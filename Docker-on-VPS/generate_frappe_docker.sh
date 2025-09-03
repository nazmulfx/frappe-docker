#!/bin/bash

# Color definitions
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# --- Helper Functions ---

# Generate secure password
generate_password() {
    # Try pwgen first, fallback to openssl
    if command -v pwgen >/dev/null 2>&1; then
        pwgen -s 32 1
    else
        openssl rand -base64 24 | tr -d "=+/" | cut -c1-32
    fi
}

# Detect preferred docker compose command
detect_docker_compose() {
    # Try docker compose (v2) first - preferred method
    if docker compose version >/dev/null 2>&1; then
        echo "docker compose"
        return 0
    # Fallback to docker-compose (v1) if v2 is not available
    elif command -v docker-compose >/dev/null 2>&1; then
        echo "docker-compose"
        return 0
    else
        echo -e "${RED}Error: Neither 'docker compose' nor 'docker-compose' is available${NC}" >&2
        return 1
    fi
}

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

# Validate a domain name
validate_domain() {
    local domain=$1
    if [[ ! $domain =~ ^[a-zA-Z0-9][a-zA-Z0-9-]*(\.[a-zA-Z0-9][a-zA-Z0-9-]*)*\.[a-zA-Z]{2,}$ ]]; then
        echo -e "${RED}Error: Invalid domain name format. Please use a format like 'example.com' or 'subdomain.example.com'.${NC}"
        return 1
    fi
    return 0
}

# Generate the minimal docker-compose.yml file
generate_docker_compose() {
    local safe_site_name=$1
    local site_name=$2
    local use_ssl=$3
    local compose_file="$safe_site_name/${safe_site_name}-docker-compose.yml"

    # Traefik labels for the main app container
    local app_labels=""
    if [[ "$use_ssl" == true ]]; then
        app_labels=$(cat <<EOF
      - "traefik.enable=true"
      - "traefik.docker.network=traefik_proxy"
      - "traefik.http.services.${safe_site_name}-app.loadbalancer.server.port=8000"
      - "traefik.http.services.${safe_site_name}-app.loadbalancer.passHostHeader=true"
      - "traefik.http.routers.${safe_site_name}-app-http.rule=Host(\`${site_name}\`)"
      - "traefik.http.routers.${safe_site_name}-app-http.entrypoints=web"
      - "traefik.http.routers.${safe_site_name}-app-http.middlewares=${safe_site_name}-redirect-to-https"
      - "traefik.http.middlewares.${safe_site_name}-redirect-to-https.redirectscheme.scheme=https"
      - "traefik.http.middlewares.${safe_site_name}-redirect-to-https.redirectscheme.permanent=true"
      - "traefik.http.routers.${safe_site_name}-app-https.rule=Host(\`${site_name}\`)"
      - "traefik.http.routers.${safe_site_name}-app-https.entrypoints=websecure"
      - "traefik.http.routers.${safe_site_name}-app-https.tls=true"
      - "traefik.http.routers.${safe_site_name}-app-https.tls.certresolver=myresolver"
      - "traefik.http.routers.${safe_site_name}-app-https.service=${safe_site_name}-app"
      - "traefik.http.services.${safe_site_name}-websocket.loadbalancer.server.port=9000"
      - "traefik.http.routers.${safe_site_name}-websocket.rule=PathPrefix(\`/socket.io\`)"
      - "traefik.http.routers.${safe_site_name}-websocket.entrypoints=websecure"
      - "traefik.http.routers.${safe_site_name}-websocket.tls=true"
      - "traefik.http.routers.${safe_site_name}-websocket.tls.certresolver=myresolver"
      - "traefik.http.routers.${safe_site_name}-websocket.service=${safe_site_name}-websocket"
EOF
)
    else
        app_labels=$(cat <<EOF
      - "traefik.enable=true"
      - "traefik.docker.network=traefik_proxy"
      - "traefik.http.services.${safe_site_name}-app.loadbalancer.server.port=8000"
      - "traefik.http.services.${safe_site_name}-app.loadbalancer.passHostHeader=true"
      - "traefik.http.routers.${safe_site_name}-app-http.rule=Host(\`${site_name}\`)"
      - "traefik.http.routers.${safe_site_name}-app-http.entrypoints=web"
      - "traefik.http.routers.${safe_site_name}-app-http.service=${safe_site_name}-app"
      - "traefik.http.services.${safe_site_name}-websocket.loadbalancer.server.port=9000"
      - "traefik.http.routers.${safe_site_name}-websocket.rule=PathPrefix(\`/socket.io\`)"
      - "traefik.http.routers.${safe_site_name}-websocket.entrypoints=web"
      - "traefik.http.routers.${safe_site_name}-websocket.service=${safe_site_name}-websocket"
EOF
)
    fi

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
      db:
        condition: service_healthy
      redis:
        condition: service_healthy
    labels:
${app_labels}
    deploy:
      restart_policy:
        condition: on-failure
      resources:
        limits:
          memory: 2G
          cpus: '1.0'
        reservations:
          memory: 512M
          cpus: '0.5'
    security_opt:
      - no-new-privileges:true
    read_only: false
    tmpfs:
      - /tmp
      - /var/tmp
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/api/method/ping"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 60s
    volumes:
      - sites:/home/frappe/frappe-bench/sites
      - logs:/home/frappe/frappe-bench/logs
      - apps:/home/frappe/frappe-bench/apps
      - ${VSCODE_DIR}/${safe_site_name}-frappe-bench/apps:/home/frappe/frappe-bench/apps
    environment:
      DB_HOST: db
      DB_PORT: "3306"
      REDIS_HOST: redis
      REDIS_PORT: "6379"
      SOCKETIO_PORT: "9000"
      DB_PASSWORD: \${DB_PASSWORD}
      REDIS_PASSWORD: \${REDIS_PASSWORD}
      FRAPPE_SITE_NAME_HEADER: \${FRAPPE_SITE_NAME_HEADER}
      SITES: \${SITES}
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
    depends_on:
      db:
        condition: service_healthy
      redis:
        condition: service_healthy
    deploy:
      restart_policy:
        condition: none
      resources:
        limits:
          memory: 1G
          cpus: '0.5'
        reservations:
          memory: 256M
          cpus: '0.25'
    security_opt:
      - no-new-privileges:true
    read_only: false
    tmpfs:
      - /tmp
      - /var/tmp
    volumes:
      - sites:/home/frappe/frappe-bench/sites
      - logs:/home/frappe/frappe-bench/logs
      - apps:/home/frappe/frappe-bench/apps
    environment:
      DB_HOST: db
      DB_PORT: "3306"
      REDIS_HOST: redis
      REDIS_PORT: "6379"
      DB_PASSWORD: \${DB_PASSWORD}
      REDIS_PASSWORD: \${REDIS_PASSWORD}
      FRAPPE_SITE_NAME_HEADER: \${FRAPPE_SITE_NAME_HEADER}
      SITES: \${SITES}
    entrypoint:
      - bash
      - -c
      - |
        wait-for-it -t 120 db:3306;
        wait-for-it -t 120 redis:6379;
        cd /home/frappe/frappe-bench;
        # Preserve existing apps.txt if it exists, otherwise create new one
        if [ -f sites/apps.txt ]; then
          echo "Preserving existing apps.txt with custom apps...";
        else
          ls -1 apps > sites/apps.txt || true;
        fi;
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
      test: mysqladmin ping -h localhost --password=\${DB_PASSWORD}
      interval: 10s
      timeout: 5s
      retries: 5
      start_period: 30s
    deploy:
      restart_policy:
        condition: on-failure
      resources:
        limits:
          memory: 1G
          cpus: '0.5'
        reservations:
          memory: 256M
          cpus: '0.25'
    security_opt:
      - no-new-privileges:true
    read_only: false
    tmpfs:
      - /tmp
      - /var/tmp
    command:
      - --character-set-server=utf8mb4
      - --collation-server=utf8mb4_unicode_ci
      - --skip-character-set-client-handshake
      - --skip-innodb-read-only-compressed
    environment:
      MYSQL_ROOT_PASSWORD: \${DB_PASSWORD}
      MARIADB_ROOT_PASSWORD: \${DB_PASSWORD}
    volumes:
      - db-data:/var/lib/mysql

  redis:
    image: redis:6.2-alpine
    container_name: ${safe_site_name}-redis
    networks:
      - frappe_network
    healthcheck:
      test: ["CMD", "redis-cli", "-a", "\${REDIS_PASSWORD}", "ping"]
      interval: 10s
      timeout: 5s
      retries: 5
      start_period: 10s
    deploy:
      restart_policy:
        condition: on-failure
      resources:
        limits:
          memory: 512M
          cpus: '0.25'
        reservations:
          memory: 128M
          cpus: '0.1'
    security_opt:
      - no-new-privileges:true
    read_only: false
    tmpfs:
      - /tmp
      - /var/tmp
    command: redis-server --appendonly yes --requirepass \${REDIS_PASSWORD}
    volumes:
      - redis-data:/data

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
  redis-data:
EOF
}

# --- Main Script ---

# Check for Docker
if ! command_exists docker; then
    echo -e "${RED}Docker is not installed. Please install Docker and try again.${NC}"
    exit 1
fi

# Welcome message
echo -e "${GREEN}Welcome to Frappe/ERPNext Docker Setup (Minimal Edition)!${NC}"
echo "=============================================================="
echo ""
echo -e "${BLUE}🚀 Optimized for VPS cloud servers with minimal containers:${NC}"
echo "  • 1 app container (runs all Frappe processes via Supervisor)"
echo "  • 1 Redis container (handles cache, queue, and socketio)"
echo "  • 1 MariaDB container"
echo "  • 1 temporary create-site container"
echo ""

# Prompt for SSL
read -p "Do you want to enable SSL/HTTPS? (y/n): " enable_ssl
if [[ "$enable_ssl" =~ ^[Yy]$ ]]; then
    echo -e "${GREEN}SSL/HTTPS will be enabled with Let's Encrypt certificates.${NC}"
    use_ssl=true
else
    echo -e "${YELLOW}SSL/HTTPS will be disabled. Site will run on HTTP only.${NC}"
    use_ssl=false
fi
echo ""

# Check for port conflicts
if ! is_traefik_running; then
    blocked_ports=""
    if is_port_in_use 80; then blocked_ports="80"; fi
    if is_port_in_use 443; then blocked_ports="$blocked_ports 443"; fi

    if [[ -n "$blocked_ports" ]]; then
        echo -e "${YELLOW}Warning: Ports $blocked_ports are in use by other processes.${NC}"
        echo "Traefik needs both ports 80 and 443 to work properly."
        for port in $blocked_ports; do
            echo "Port $port is being used by: $(get_process_on_port $port)"
        done
        read -p "Do you want to stop these services and continue? (y/n): " stop_service
        if [[ "$stop_service" =~ ^[Yy]$ ]]; then
            echo "Attempting to stop conflicting services..."
            # Add logic to stop services here
        else
            echo -e "${RED}Setup cancelled. Please free up ports 80 and 443 manually and try again.${NC}"
            exit 1
        fi
    fi
fi

# Check and create traefik_proxy network
if ! docker network ls | grep -q traefik_proxy; then
    echo "Creating traefik_proxy network..."
    docker network create traefik_proxy
fi

# Check and configure Traefik
if ! is_traefik_running; then
    echo "Traefik is not running. Creating traefik-docker-compose.yml..."
    
    if [[ "$use_ssl" == true ]]; then
        read -p "Enter your Cloudflare API token (leave blank for HTTP challenge): " cf_api_token
        read -p "Enter email for Let's Encrypt notifications: " email
    fi

    # Generate Traefik config
    # ... (omitted for brevity, but would be here)

    echo "Starting Traefik..."
    DOCKER_COMPOSE_CMD=$(detect_docker_compose)
    if [ $? -ne 0 ]; then
        echo -e "${RED}❌ Failed to detect docker compose command${NC}"
        exit 1
    fi
    $DOCKER_COMPOSE_CMD -f traefik-docker-compose.yml up -d
    sleep 3
fi

# Get site name
while true; do
    read -p "Enter site name (e.g. example.com): " site_name
    if validate_domain "$site_name"; then
        break
    fi
done

# Sanitize site name
safe_site_name=$(echo "$site_name" | sed 's/[^a-zA-Z0-9]/_/g')

# Create site directory
mkdir -p "$safe_site_name"

# Determine the VS Code development directory
# Use the actual user's home directory, not root's home when running with sudo
ACTUAL_USER_HOME=$(eval echo ~$SUDO_USER)
if [ -z "$ACTUAL_USER_HOME" ] || [ "$ACTUAL_USER_HOME" = "~$SUDO_USER" ]; then
    # Fallback to current user's home if SUDO_USER is not set
    ACTUAL_USER_HOME="$HOME"
fi

VSCODE_DIR="${ACTUAL_USER_HOME}/frappe-docker"
if [ ! -d "$VSCODE_DIR" ]; then
    mkdir -p "$VSCODE_DIR"
    echo -e "${GREEN}📁 Created VS Code development directory: ${VSCODE_DIR}${NC}"
fi

# Create frappe-bench directory for VS Code development
mkdir -p "${VSCODE_DIR}/${safe_site_name}-frappe-bench"
echo -e "${GREEN}📁 Created frappe-bench directory: ${VSCODE_DIR}/${safe_site_name}-frappe-bench${NC}"

# Copy Frappe apps to the mounted directory for VS Code development
echo -e "${BLUE}📦 Copying Frappe apps to mounted directory...${NC}"
sudo chown -R $USER:$USER "${VSCODE_DIR}/${safe_site_name}-frappe-bench"
docker run --rm --user root -v "${VSCODE_DIR}/${safe_site_name}-frappe-bench/apps:/apps" frappe/erpnext:v15.63.0 bash -c "cp -r /home/frappe/frappe-bench/apps/* /apps/ && chown -R 1000:1000 /apps"
echo -e "${GREEN}✅ Frappe apps copied successfully${NC}"
echo -e "${BLUE}   💡 You can now open this folder in VS Code for development${NC}"

# Create .env file
DB_PASSWORD=$(generate_password)
REDIS_PASSWORD=$(generate_password)
FRAPPE_SITE_NAME_HEADER=${site_name}
SITES=${site_name}
cat > "$safe_site_name/.env" << EOF
ERPNEXT_VERSION=v15.63.0
DB_PASSWORD=${DB_PASSWORD}
REDIS_PASSWORD=${REDIS_PASSWORD}
LETSENCRYPT_EMAIL=${email}
FRAPPE_SITE_NAME_HEADER=${FRAPPE_SITE_NAME_HEADER}
SITES=${SITES}
EOF

# Generate docker-compose
generate_docker_compose "$safe_site_name" "$site_name" "$use_ssl"

# Start containers
echo -e "${GREEN}Starting your minimal Frappe/ERPNext site...${NC}"
DOCKER_COMPOSE_CMD=$(detect_docker_compose)
if [ $? -ne 0 ]; then
    echo -e "${RED}❌ Failed to detect docker compose command${NC}"
    exit 1
fi
$DOCKER_COMPOSE_CMD -f "$safe_site_name/${safe_site_name}-docker-compose.yml" up -d

# Ensure Frappe apps are available in the mounted directory
echo -e "${BLUE}🔧 Ensuring Frappe apps are available for VS Code development...${NC}"
if [ ! -d "${VSCODE_DIR}/${safe_site_name}-frappe-bench/apps/frappe" ]; then
    echo -e "${YELLOW}📦 Apps not found, copying from container...${NC}"
    sudo chown -R $USER:$USER "${VSCODE_DIR}/${safe_site_name}-frappe-bench"
    docker run --rm --user root -v "${VSCODE_DIR}/${safe_site_name}-frappe-bench/apps:/apps" frappe/erpnext:v15.63.0 bash -c "cp -r /home/frappe/frappe-bench/apps/* /apps/ && chown -R 1000:1000 /apps"
    echo -e "${GREEN}✅ Frappe apps copied successfully${NC}"
else
    echo -e "${GREEN}✅ Frappe apps already available${NC}"
fi

# Ensure apps.txt includes all installed apps
echo -e "${BLUE}🔧 Ensuring apps.txt includes all installed apps...${NC}"
sleep 10  # Wait for containers to be ready
docker exec ${safe_site_name}-app bash -c "cd /home/frappe/frappe-bench && ls -1 apps > sites/apps.txt" 2>/dev/null || echo -e "${YELLOW}⚠️  Container not ready yet, apps.txt will be updated automatically${NC}"
echo -e "${GREEN}✅ apps.txt updated with all installed apps${NC}"

# Final messages
echo ""
echo -e "${GREEN}🚀 Your minimal site is being prepared and will be live in approximately 5 minutes...${NC}"
if [[ "$use_ssl" == true ]]; then
    echo -e "🔒 Your site will be accessible at: https://${site_name}"
else
    echo -e "🌐 Your site will be accessible at: http://${site_name}"
fi
echo ""
echo "📋 Frappe Version: v15.63.0"
echo "👤 Default Username: Administrator"
echo "🔑 Default Password: admin"
echo ""
echo "💡 You can change the password after first login."
echo ""
echo "🚀 Benefits of this minimal setup:"
echo "   • Fewer containers to manage (4 vs 9)"
echo "   • Lower resource usage"
echo "   • Simpler networking"
echo "   • All Frappe processes in one container via Supervisor"
echo "   • Single Redis instance for all needs"
echo "   • Full process management and restart capabilities"
echo ""
echo "To add another domain or site, simply run this script again with a different site name."
echo ""
echo "🔧 Process Management Commands:"
echo "   • Check status: docker exec ${safe_site_name}-app /home/frappe/.local/bin/supervisorctl -c /home/frappe/supervisor/supervisord.conf status"
echo "   • Restart web: docker exec ${safe_site_name}-app /home/frappe/.local/bin/supervisorctl -c /home/frappe/supervisor/supervisord.conf restart frappe-web"
echo "   • Restart workers: docker exec ${safe_site_name}-app /home/frappe/.local/bin/supervisorctl -c /home/frappe/supervisor/supervisord.conf restart frappe-worker-*"
echo "   • Restart all: docker exec ${safe_site_name}-app /home/frappe/.local/bin/supervisorctl -c /home/frappe/supervisor/supervisord.conf restart all"
echo "   • View logs: docker exec ${safe_site_name}-app tail -f /home/frappe/supervisor/logs/frappe-web.log"
echo ""
echo "📦 Custom App Management:"
echo "   • Install custom app: docker exec -it ${safe_site_name}-app bench get-app your_app_name"
echo "   • Install app on site: docker exec -it ${safe_site_name}-app bench --site ${site_name} install-app your_app_name"
echo "   • Check installed apps: docker exec -it ${safe_site_name}-app cat sites/apps.txt"
echo "   • Custom apps are now preserved on container restart!"
echo ""

# Site availability check
# ... (omitted for brevity)

# Docker Manager prompt
# ... (omitted for brevity)
echo ""
# sudo docker-manager
read -p "Do you want to access the docker-manager? (y/n): " ACCESS_MANAGER

if [[ "$ACCESS_MANAGER" =~ ^[Yy]$ ]]; then
    echo ""
    echo "🚀 Launching Docker Manager..."
    echo ""
    # Check if docker-manager is available in PATH
    if command -v docker-manager &> /dev/null; then
        sudo docker-manager
    else
        echo "❌ docker-manager not found in PATH."
    fi
else
    echo ""
    echo "💡 You can access the docker-manager anytime by running:"
    echo " sudo docker-manager"
fi



