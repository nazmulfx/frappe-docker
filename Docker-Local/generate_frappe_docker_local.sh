#!/bin/bash

# Color definitions
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# --- Helper Functions ---

# Check if a command exists
command_exists() {
    command -v "$1" &> /dev/null
}

# Check if a port is in use
is_port_in_use() {
    ss -ltn "sport = :$1" | grep -q LISTEN
}

# Get the process using a port
get_process_on_port() {
    ss -ltnp "sport = :$1" | grep LISTEN | awk '{print $7}'
}

# Check if Traefik is running
is_traefik_running() {
    docker ps --filter "name=traefik" --format "{{.Names}}" | grep -q "traefik"
}

# Validate a domain name (modified to allow localhost domains)
validate_domain() {
    local domain=$1
    # Allow localhost domains
    if [[ $domain =~ \.localhost$ ]]; then
        return 0
    fi
    # Standard domain validation
    if [[ ! $domain =~ ^[a-zA-Z0-9][a-zA-Z0-9-]*(\.[a-zA-Z0-9][a-zA-Z0-9-]*)*\.[a-zA-Z]{2,}$ ]]; then
        echo -e "${RED}Error: Invalid domain name format. Please use a format like 'example.com', 'subdomain.example.com', or 'mysite.localhost'.${NC}"
        return 1
    fi
    return 0
}

# Load local Traefik configuration if it exists
load_local_config() {
    if [[ -f ".traefik-local-config" ]]; then
        source .traefik-local-config
        echo -e "${BLUE}📋 Loaded local Traefik configuration${NC}"
        echo "  • HTTP Port: ${TRAEFIK_HTTP_PORT}"
        if [[ -n "$TRAEFIK_HTTPS_PORT" ]]; then
            echo "  • HTTPS Port: ${TRAEFIK_HTTPS_PORT}"
        fi
        if [[ "$USE_LOCALHOST" == "true" ]]; then
            echo "  • Using localhost domains"
        fi
        echo ""
        return 0
    fi
    return 1
}

# Function to manage hosts file entries
manage_hosts_entry() {
    local domain=$1
    local action=$2  # "add" or "remove"
    
    if [[ $domain =~ \.localhost$ ]]; then
        return 0  # .localhost domains don't need hosts file entries
    fi
    
    case $action in
        "add")
            if grep -q "$domain" /etc/hosts; then
                echo -e "${YELLOW}⚠️  Domain $domain already exists in hosts file${NC}"
                return 0
            else
                if echo "127.0.0.1 $domain" | tee -a /etc/hosts > /dev/null; then
                    echo -e "${GREEN}✅ Added $domain to hosts file${NC}"
                    return 0
                else
                    echo -e "${RED}❌ Failed to add domain to hosts file${NC}"
                    return 1
                fi
            fi
            ;;
        "remove")
            if grep -q "$domain" /etc/hosts; then
                # Create a temporary file without the domain
                sudo sed "/$domain/d" /etc/hosts > /tmp/hosts.tmp
                if sudo mv /tmp/hosts.tmp /etc/hosts; then
                    echo -e "${GREEN}✅ Removed $domain from hosts file${NC}"
                    return 0
                else
                    echo -e "${RED}❌ Failed to remove domain from hosts file${NC}"
                    return 1
                fi
            else
                echo -e "${YELLOW}⚠️  Domain $domain not found in hosts file${NC}"
                return 0
            fi
            ;;
    esac
}

# Generate the optimized docker-compose.yml file
generate_docker_compose() {
    local safe_site_name=$1
    local site_name=$2
    local compose_file="$safe_site_name/${safe_site_name}-docker-compose.yml"
    
    # Load local config to check for custom ports
    local http_entrypoint="web"
    
    if load_local_config; then
        # Use the configured entrypoint
        http_entrypoint="web"
    fi

    # Traefik labels for the main app container
    local app_labels=$(cat <<EOF
      - "traefik.enable=true"
      - "traefik.docker.network=traefik_proxy"
      - "traefik.http.services.${safe_site_name}-app.loadbalancer.server.port=8000"
      - "traefik.http.services.${safe_site_name}-app.loadbalancer.passHostHeader=true"
      - "traefik.http.routers.${safe_site_name}-app-http.rule=Host(\`${site_name}\`)"
      - "traefik.http.routers.${safe_site_name}-app-http.entrypoints=${http_entrypoint}"
      - "traefik.http.routers.${safe_site_name}-app-http.service=${safe_site_name}-app"
      - "traefik.http.services.${safe_site_name}-websocket.loadbalancer.server.port=9000"
      - "traefik.http.routers.${safe_site_name}-websocket.rule=PathPrefix(\`/socket.io\`)"
      - "traefik.http.routers.${safe_site_name}-websocket.entrypoints=${http_entrypoint}"
      - "traefik.http.routers.${safe_site_name}-websocket.service=${safe_site_name}-websocket"
EOF
)

    cat > "$compose_file" << EOF
version: "3.8"

services:
  app:
    image: frappe/erpnext:v15.63.0
    container_name: ${safe_site_name}-app
    networks:
      - frappe_network
      - traefik_proxy
    depends_on:
      - db
      - redis
    labels:
${app_labels}
    deploy:
      restart_policy:
        condition: on-failure
    volumes:
      - sites:/home/frappe/frappe-bench/sites
      - logs:/home/frappe/frappe-bench/logs
      - apps:/home/frappe/frappe-bench/apps
      - /var/www/frappe-docker/${safe_site_name}-frappe-bench/apps:/home/frappe/frappe-bench/apps
    environment:
      DB_HOST: db
      DB_PORT: "3306"
      REDIS_HOST: redis
      REDIS_PORT: "6379"
      SOCKETIO_PORT: "9000"
    entrypoint:
      - bash
      - -c
      - |
        echo "Waiting for site to be ready...";
        while [ ! -f sites/${site_name}/site_config.json ]; do
          echo "Site not ready yet, waiting...";
          sleep 5;
        done;
        echo "Site is ready, installing supervisor...";
        
        # Install supervisor using pip (works with frappe user)
        pip3 install supervisor;
        
        # Create supervisor directories in user's home
        mkdir -p /home/frappe/supervisor/conf.d /home/frappe/supervisor/logs;
        
        # Create supervisor config in user's home directory
        cat > /home/frappe/supervisor/supervisord.conf << 'SUPERVISOR_EOF'
        [unix_http_server]
        file=/home/frappe/supervisor/supervisor.sock
        chmod=0777
        chown=frappe:frappe

        [supervisord]
        logfile=/home/frappe/supervisor/logs/supervisord.log
        pidfile=/home/frappe/supervisor/supervisord.pid
        childlogdir=/home/frappe/supervisor/logs
        nodaemon=false
        user=frappe

        [rpcinterface:supervisor]
        supervisor.rpcinterface_factory = supervisor.rpcinterface:make_main_rpcinterface

        [supervisorctl]
        serverurl=unix:///home/frappe/supervisor/supervisor.sock

        [include]
        files = /home/frappe/supervisor/conf.d/*.conf
        SUPERVISOR_EOF

        # Create Frappe process configurations
        cat > /home/frappe/supervisor/conf.d/frappe.conf << 'FRAPPE_CONF_EOF'
        [group:frappe]
        programs=frappe-web,frappe-schedule,frappe-worker-short,frappe-worker-long,frappe-worker-default,frappe-websocket

        [program:frappe-web]
        command=bench serve --port 8000
        directory=/home/frappe/frappe-bench
        user=frappe
        autostart=true
        autorestart=true
        redirect_stderr=true
        stdout_logfile=/home/frappe/supervisor/logs/frappe-web.log
        stderr_logfile=/home/frappe/supervisor/logs/frappe-web-error.log

        [program:frappe-schedule]
        command=bench schedule
        directory=/home/frappe/frappe-bench
        user=frappe
        autostart=true
        autorestart=true
        redirect_stderr=true
        stdout_logfile=/home/frappe/supervisor/logs/frappe-schedule.log
        stderr_logfile=/home/frappe/supervisor/logs/frappe-schedule-error.log

        [program:frappe-worker-short]
        command=bench worker --queue short
        directory=/home/frappe/frappe-bench
        user=frappe
        autostart=true
        autorestart=true
        redirect_stderr=true
        stdout_logfile=/home/frappe/supervisor/logs/frappe-worker-short.log
        stderr_logfile=/home/frappe/supervisor/logs/frappe-worker-short-error.log

        [program:frappe-worker-long]
        command=bench worker --queue long
        directory=/home/frappe/frappe-bench
        user=frappe
        autostart=true
        autorestart=true
        redirect_stderr=true
        stdout_logfile=/home/frappe/supervisor/logs/frappe-worker-long.log
        stderr_logfile=/home/frappe/supervisor/logs/frappe-worker-long-error.log

        [program:frappe-worker-default]
        command=bench worker --queue default
        directory=/home/frappe/frappe-bench
        user=frappe
        autostart=true
        autorestart=true
        redirect_stderr=true
        stdout_logfile=/home/frappe/supervisor/logs/frappe-worker-default.log
        stderr_logfile=/home/frappe/supervisor/logs/frappe-worker-default-error.log

        [program:frappe-websocket]
        command=node /home/frappe/frappe-bench/apps/frappe/socketio.js
        directory=/home/frappe/frappe-bench
        user=frappe
        autostart=true
        autorestart=true
        redirect_stderr=true
        stdout_logfile=/home/frappe/supervisor/logs/frappe-websocket.log
        stderr_logfile=/home/frappe/supervisor/logs/frappe-websocket-error.log
        FRAPPE_CONF_EOF

        echo "Supervisor installed and configured. Starting Frappe processes...";
        
        # Start supervisor using full path
        /home/frappe/.local/bin/supervisord -c /home/frappe/supervisor/supervisord.conf;
        
        # Wait a moment for processes to start
        sleep 5;
        
        # Show status using full path
        /home/frappe/.local/bin/supervisorctl -c /home/frappe/supervisor/supervisord.conf status;
        
        # Keep container running and show logs
        tail -f /home/frappe/supervisor/logs/supervisord.log

  create-site:
    image: frappe/erpnext:v15.63.0
    container_name: ${safe_site_name}-create-site
    networks:
      - frappe_network
    deploy:
      restart_policy:
        condition: none
    volumes:
      - sites:/home/frappe/frappe-bench/sites
      - logs:/home/frappe/frappe-bench/logs
      - apps:/home/frappe/frappe-bench/apps
    entrypoint:
      - bash
      - -c
      - |
        wait-for-it -t 120 db:3306;
        wait-for-it -t 120 redis:6379;
        cd /home/frappe/frappe-bench;
        ls -1 apps > sites/apps.txt || true;
        bench set-config -g db_host db;
        bench set-config -gp db_port 3306;
        bench set-config -g redis_cache "redis://redis:6379";
        bench set-config -g redis_queue "redis://redis:6379";
        bench set-config -g redis_socketio "redis://redis:6379";
        bench set-config -gp socketio_port 9000;
        if [ ! -d sites/${site_name} ]; then
          echo "Creating new site...";
          bench new-site --mariadb-user-host-login-scope='%' --admin-password=admin --db-root-username=root --db-root-password=admin --install-app erpnext --set-default ${site_name};
          echo "${site_name}" > sites/currentsite.txt;
        else
          echo "Site ${site_name} already exists, skipping creation";
        fi

  db:
    image: mariadb:10.6
    container_name: ${safe_site_name}-db
    networks:
      - frappe_network
    healthcheck:
      test: mysqladmin ping -h localhost --password=admin
      interval: 1s
      retries: 20
    deploy:
      restart_policy:
        condition: on-failure
    command:
      - --character-set-server=utf8mb4
      - --collation-server=utf8mb4_unicode_ci
      - --skip-character-set-client-handshake
      - --skip-innodb-read-only-compressed
    environment:
      MYSQL_ROOT_PASSWORD: admin
      MARIADB_ROOT_PASSWORD: admin
    volumes:
      - db-data:/var/lib/mysql

  redis:
    image: redis:6.2-alpine
    container_name: ${safe_site_name}-redis
    networks:
      - frappe_network
    deploy:
      restart_policy:
        condition: on-failure

networks:
  frappe_network:
    driver: bridge
  traefik_proxy:
    external: true

volumes:
  sites:
  logs:
  apps:
  db-data:
EOF
}

# --- Main Script ---

# Check for Docker
if ! command_exists docker; then
    echo -e "${RED}Docker is not installed. Please install Docker and try again.${NC}"
    exit 1
fi

# Check if running with sudo (needed for hosts file management)
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}❌ This script must be run with sudo for hosts file management${NC}"
    echo -e "${YELLOW}💡 Please run: sudo ./generate_frappe_docker_local_optimized.sh${NC}"
    exit 1
fi

# Welcome message
echo -e "${GREEN}Welcome to Frappe/ERPNext Docker Setup (Optimized Edition)!${NC}"
echo "=============================================================="
echo ""
echo -e "${BLUE}🚀 Optimized for local development with minimal containers:${NC}"
echo "  • 1 app container (runs all Frappe processes via Supervisor)"
echo "  • 1 Redis container (handles cache, queue, and socketio)"
echo "  • 1 MariaDB container"
echo "  • 1 temporary create-site container"
echo ""

# For local development, we don't need SSL
echo -e "${BLUE}📍 Local Development Environment${NC}"
echo -e "${YELLOW}HTTP-only setup (no SSL certificates needed for local)${NC}"

# Check if we have a local Traefik configuration
if load_local_config; then
    echo -e "${GREEN}✅ Using existing local Traefik configuration${NC}"
fi
echo ""

# Check for port conflicts (skip if local config exists and handled)
if ! is_traefik_running && [[ ! -f ".traefik-local-config" ]]; then
    blocked_ports=""
    if is_port_in_use 80; then blocked_ports="80"; fi
    if is_port_in_use 443; then blocked_ports="$blocked_ports 443"; fi

    if [[ -n "$blocked_ports" ]]; then
        echo -e "${YELLOW}Warning: Ports $blocked_ports are in use by other processes.${NC}"
        echo "Traefik needs these ports to work properly."
        echo ""
        echo -e "${BLUE}💡 TIP: Run ./setup-traefik-local.sh first to handle port conflicts${NC}"
        echo ""
        for port in $blocked_ports; do
            echo "Port $port is being used by: $(get_process_on_port $port)"
        done
        read -p "Do you want to exit and run setup-traefik-local.sh first? (y/n): " exit_setup
        if [[ "$exit_setup" =~ ^[Yy]$ ]]; then
            echo -e "${YELLOW}Please run: ./setup-traefik-local.sh${NC}"
            exit 0
        fi
    fi
fi

# Check and create traefik_proxy network
if ! docker network ls | grep -q traefik_proxy; then
    echo "Creating traefik_proxy network..."
    docker network create traefik_proxy
fi

# Check if Traefik is running
if ! is_traefik_running; then
    echo -e "${RED}⚠️  Traefik is not running!${NC}"
    echo ""
    echo "Please run one of the following first:"
    echo "  1. ./setup-traefik-local.sh (for local environment)"
    echo "  2. Start Traefik manually"
    echo ""
    read -p "Do you want to continue anyway? (y/n): " continue_without_traefik
    if [[ ! "$continue_without_traefik" =~ ^[Yy]$ ]]; then
        exit 1
    fi
else
    echo -e "${GREEN}✅ Traefik is running${NC}"
fi

# Get site name with localhost suggestion for local env
echo ""
echo -e "${BLUE}💡 For local development, use a .localhost domain (e.g., mysite.localhost)${NC}"
echo -e "${BLUE}   Or use any domain like mysite.local (will be auto-added to hosts file)${NC}"

while true; do
    read -p "Enter site name (e.g. example.com or mysite.localhost): " site_name
    if validate_domain "$site_name"; then
        break
    fi
done

USE_LOCALHOST=false
echo -e "${BLUE}📝 Custom domain detected - will be added to hosts file${NC}"

# Sanitize site name
safe_site_name=$(echo "$site_name" | sed 's/[^a-zA-Z0-9]/_/g')

# Create site directory
mkdir -p "$safe_site_name"

# Create frappe-bench directory in /var/www/frappe-docker for VS Code development
mkdir -p "/var/www/frappe-docker/${safe_site_name}-frappe-bench"
echo -e "${GREEN}📁 Created frappe-bench directory: /var/www/frappe-docker/${safe_site_name}-frappe-bench${NC}"

# Copy Frappe apps to the mounted directory for VS Code development
echo -e "${BLUE}📦 Copying Frappe apps to mounted directory...${NC}"
sudo chown -R $USER:$USER "/var/www/frappe-docker/${safe_site_name}-frappe-bench"
docker run --rm --user root -v "/var/www/frappe-docker/${safe_site_name}-frappe-bench/apps:/apps" frappe/erpnext:v15.63.0 bash -c "cp -r /home/frappe/frappe-bench/apps/* /apps/ && chown -R 1000:1000 /apps"
echo -e "${GREEN}✅ Frappe apps copied successfully${NC}"
echo -e "${BLUE}   💡 You can now open this folder in VS Code for development${NC}"

# Create .env file
cat > "$safe_site_name/.env" << EOF
ERPNEXT_VERSION=v15.63.0
DB_PASSWORD=admin
FRAPPE_SITE_NAME_HEADER=${site_name}
SITES=${site_name}
EOF

# Generate docker-compose
generate_docker_compose "$safe_site_name" "$site_name"

# Start containers
echo -e "${GREEN}Starting your optimized Frappe/ERPNext site...${NC}"
docker compose -f "$safe_site_name/${safe_site_name}-docker-compose.yml" up -d

# Ensure Frappe apps are available in the mounted directory
echo -e "${BLUE}🔧 Ensuring Frappe apps are available for VS Code development...${NC}"
if [ ! -d "/var/www/frappe-docker/${safe_site_name}-frappe-bench/apps/frappe" ]; then
    echo -e "${YELLOW}📦 Apps not found, copying from container...${NC}"
    sudo chown -R $USER:$USER "/var/www/frappe-docker/${safe_site_name}-frappe-bench"
    docker run --rm --user root -v "/var/www/frappe-docker/${safe_site_name}-frappe-bench/apps:/apps" frappe/erpnext:v15.63.0 bash -c "cp -r /home/frappe/frappe-bench/apps/* /apps/ && chown -R 1000:1000 /apps"
    echo -e "${GREEN}✅ Frappe apps copied successfully${NC}"
else
    echo -e "${GREEN}✅ Frappe apps already available${NC}"
fi

# Show port information immediately after starting
echo ""
if [[ -f ".traefik-local-config" ]]; then
    source .traefik-local-config
    if [[ "$TRAEFIK_HTTP_PORT" != "80" ]]; then
        echo -e "${BLUE}📍 Using custom HTTP port: ${TRAEFIK_HTTP_PORT}${NC}"
        echo -e "${BLUE}   Your site will be accessible at: http://${site_name}:${TRAEFIK_HTTP_PORT}${NC}"
    else
        echo -e "${BLUE}📍 Using default HTTP port: 80${NC}"
        echo -e "${BLUE}   Your site will be accessible at: http://${site_name}${NC}"
    fi
else
    echo -e "${BLUE}📍 Using default HTTP port: 80${NC}"
    echo -e "${BLUE}   Your site will be accessible at: http://${site_name}${NC}"
fi
echo ""

# Auto-add domain to hosts file for local access
echo ""
echo -e "${BLUE}🔧 Managing hosts file for local access...${NC}"
if manage_hosts_entry "$site_name" "add"; then
    if [[ ! $site_name =~ \.localhost$ ]]; then
        # Get the correct port from local config
        local display_port=""
        if [[ -f ".traefik-local-config" ]]; then
            source .traefik-local-config
            if [[ "$TRAEFIK_HTTP_PORT" != "80" ]]; then
                display_port=":${TRAEFIK_HTTP_PORT}"
            fi
        fi
        echo -e "${BLUE}   You can now access your site at: http://$site_name${display_port}${NC}"
        echo -e "${YELLOW}   💡 To remove this domain later, run: ./manage-hosts.sh${NC}"
    fi
fi

# Final messages with port-aware URLs
echo ""
echo -e "${GREEN}🚀 Your optimized site is being prepared and will be live in approximately 5 minutes...${NC}"

# Determine the access URL based on configuration
local access_url=""
if [[ -f ".traefik-local-config" ]]; then
    source .traefik-local-config
    if [[ "$USE_LOCALHOST" == "true" ]]; then
        # For localhost domains, show the correct port
        if [[ "$TRAEFIK_HTTP_PORT" != "80" ]]; then
            access_url="http://${site_name}:${TRAEFIK_HTTP_PORT}"
        else
            access_url="http://${site_name}"
        fi
    elif [[ "$TRAEFIK_HTTP_PORT" != "80" ]]; then
        access_url="http://${site_name}:${TRAEFIK_HTTP_PORT}"
    else
        access_url="http://${site_name}"
    fi
else
    # Default to port 80 if no config
    access_url="http://${site_name}"
fi

echo -e "🌐 Your site will be accessible at: ${access_url}"

echo ""
echo "📋 Frappe Version: v15.63.0"
echo "👤 Default Username: Administrator"
echo "🔑 Default Password: admin"
echo ""
echo "💡 You can change the password after first login."
echo ""
echo "🚀 Benefits of this optimized setup:"
echo "   • Fewer containers to manage (4 vs 9)"
echo "   • Lower resource usage"
echo "   • Simpler networking"
echo "   • All Frappe processes in one container via Supervisor"
echo "   • Single Redis instance for all needs"
echo "   • Full process management and restart capabilities"
echo ""
echo "To add another domain or site, simply run this script again with a different site name."
echo ""
echo -e "${GREEN}🎯 FINAL ACCESS INFORMATION:${NC}"
if [[ -f ".traefik-local-config" ]]; then
    source .traefik-local-config
    if [[ "$TRAEFIK_HTTP_PORT" != "80" ]]; then
        echo -e "${GREEN}   🌐 Site URL: http://${site_name}:${TRAEFIK_HTTP_PORT}${NC}"
    else
        echo -e "${GREEN}   🌐 Site URL: http://${site_name}${NC}"
    fi
else
    echo -e "${GREEN}   🌐 Site URL: http://${site_name}${NC}"
fi
echo -e "${GREEN}   👤 Username: Administrator${NC}"
echo -e "${GREEN}   🔑 Password: admin${NC}"
echo ""
echo "🔧 Process Management Commands:"
echo "   • Check status: sudo docker exec ${safe_site_name}-app /home/frappe/.local/bin/supervisorctl -c /home/frappe/supervisor/supervisord.conf status"
echo "   • Restart web: sudo docker exec ${safe_site_name}-app /home/frappe/.local/bin/supervisorctl -c /home/frappe/supervisor/supervisord.conf restart frappe-web"
echo "   • Restart workers: sudo docker exec ${safe_site_name}-app /home/frappe/.local/bin/supervisorctl -c /home/frappe/supervisor/supervisord.conf restart frappe-worker-*"
echo "   • Restart all: sudo docker exec ${safe_site_name}-app /home/frappe/.local/bin/supervisorctl -c /home/frappe/supervisor/supervisord.conf restart all"
echo "   • View logs: sudo docker exec ${safe_site_name}-app tail -f /home/frappe/supervisor/logs/frappe-web.log"

echo ""
echo "📦 Custom App Management:"
echo "   • Install custom app: docker exec -it ${safe_site_name}-app bench get-app your_app_name"
echo "   • Install app on site: docker exec -it ${safe_site_name}-app bench --site ${site_name} install-app your_app_name"
echo "   • Check installed apps: docker exec -it ${safe_site_name}-app cat sites/apps.txt"
echo "   • Custom apps are now preserved on container restart!"
echo ""

# Docker Manager prompt (if needed)
read -p "Do you want to access the docker-manager? (y/n): " ACCESS_MANAGER

if [[ "$ACCESS_MANAGER" =~ ^[Yy]$ ]]; then
    echo ""
    echo "🚀 Launching Docker Manager..."
    echo ""
    
    # Try different ways to launch docker-manager
    if command -v docker-manager &> /dev/null; then
        echo "✅ Found docker-manager in PATH"
        sudo docker-manager
    elif [[ -f "./docker-manager.sh" ]]; then
        echo "✅ Found docker-manager.sh in current directory"
        sudo ./docker-manager.sh
    elif [[ -f "/var/www/html/docker2 15/docker-manager.sh" ]]; then
        echo "✅ Found docker-manager.sh in project directory"
        sudo /var/www/html/docker2\ 15/docker-manager.sh
    else
        echo "❌ docker-manager not found in common locations"
        echo ""
        echo "💡 Try these commands:"
        echo "   sudo ./docker-manager.sh"
        echo "   sudo /var/www/html/docker2\ 15/docker-manager.sh"
        echo "   sudo docker-manager (if installed globally)"
    fi
else
    echo ""
    echo "💡 You can access the docker-manager anytime by running:"
    echo "   sudo ./docker-manager.sh"
fi
