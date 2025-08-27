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

# Generate the docker-compose.yml file
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

    # HTTP-only labels for local development
    local frontend_labels=$(cat <<EOF
      - "traefik.enable=true"
      - "traefik.docker.network=traefik_proxy"
      - "traefik.http.services.${safe_site_name}-frontend.loadbalancer.server.port=8080"
      - "traefik.http.services.${safe_site_name}-frontend.loadbalancer.passHostHeader=true"
      - "traefik.http.routers.${safe_site_name}-frontend-http.rule=Host(\`${site_name}\`)"
      - "traefik.http.routers.${safe_site_name}-frontend-http.entrypoints=${http_entrypoint}"
      - "traefik.http.routers.${safe_site_name}-frontend-http.service=${safe_site_name}-frontend"
EOF
)

    cat > "$compose_file" << EOF
version: "3.8"

services:
  backend:
    image: frappe/erpnext:v15.63.0
    container_name: ${safe_site_name}-backend
    networks:
      - frappe_network
    deploy:
      restart_policy:
        condition: on-failure
    volumes:
      - sites:/home/frappe/frappe-bench/sites
      - logs:/home/frappe/frappe-bench/logs
    environment:
      DB_HOST: db
      DB_PORT: "3306"
      MYSQL_ROOT_PASSWORD: admin
      MARIADB_ROOT_PASSWORD: admin

  configurator:
    image: frappe/erpnext:v15.63.0
    container_name: ${safe_site_name}-configurator
    networks:
      - frappe_network
    deploy:
      restart_policy:
        condition: none
    entrypoint:
      - bash
      - -c
      - >
        ls -1 apps > sites/apps.txt;
        bench set-config -g db_host \$\$DB_HOST;
        bench set-config -gp db_port \$\$DB_PORT;
        bench set-config -g redis_cache "redis://\$\$REDIS_CACHE";
        bench set-config -g redis_queue "redis://\$\$REDIS_QUEUE";
        bench set-config -g redis_socketio "redis://\$\$REDIS_QUEUE";
        bench set-config -gp socketio_port \$\$SOCKETIO_PORT;
    environment:
      DB_HOST: db
      DB_PORT: "3306"
      REDIS_CACHE: redis-cache:6379
      REDIS_QUEUE: redis-queue:6379
      SOCKETIO_PORT: "9000"
    volumes:
      - sites:/home/frappe/frappe-bench/sites
      - logs:/home/frappe/frappe-bench/logs
    depends_on:
      - db
      - redis-cache
      - redis-queue

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
    entrypoint:
      - bash
      - -c
      - >
        wait-for-it -t 120 db:3306;
        wait-for-it -t 120 redis-cache:6379;
        wait-for-it -t 120 redis-queue:6379;
        export start=\$(date +%s);
        until [[ -n \$(grep -hs ^ sites/common_site_config.json | jq -r ".db_host // empty") ]] && \
          [[ -n \$(grep -hs ^ sites/common_site_config.json | jq -r ".redis_cache // empty") ]] && \
          [[ -n \$(grep -hs ^ sites/common_site_config.json | jq -r ".redis_queue // empty") ]];
        do
          echo "Waiting for sites/common_site_config.json to be created";
          sleep 5;
          if (( \$(date +%s)-start > 120 )); then
            echo "could not find sites/common_site_config.json with required keys";
            exit 1
          fi
        done;
        echo "sites/common_site_config.json found";
        apt-get update && apt-get install -y nano;
        bench new-site --mariadb-user-host-login-scope='%' --admin-password=admin --db-root-username=root --db-root-password=admin --install-app erpnext --set-default ${site_name};
        echo "${site_name}" > sites/currentsite.txt;
    depends_on:
      - db
      - redis-cache
      - redis-queue

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
      - --skip-innodb-read-only-compressed # Temporary fix for MariaDB 10.6
    environment:
      MYSQL_ROOT_PASSWORD: admin
      MARIADB_ROOT_PASSWORD: admin
    volumes:
      - db-data:/var/lib/mysql

  frontend:
    image: frappe/erpnext:v15.63.0
    container_name: ${safe_site_name}-frontend
    networks:
      - frappe_network
      - traefik_proxy
    depends_on:
      - backend
      - websocket
    labels:
${frontend_labels}
    deploy:
      restart_policy:
        condition: on-failure
    command:
      - nginx-entrypoint.sh
    environment:
      BACKEND: backend:8000
      FRAPPE_SITE_NAME_HEADER: ${site_name}
      SOCKETIO: websocket:9000
      UPSTREAM_REAL_IP_ADDRESS: 127.0.0.1
      UPSTREAM_REAL_IP_HEADER: X-Forwarded-For
      UPSTREAM_REAL_IP_RECURSIVE: "off"
      PROXY_READ_TIMEOUT: 120
      CLIENT_MAX_BODY_SIZE: 50m
      VIRTUAL_HOST: ${site_name}
      VIRTUAL_PORT: 8080
      NGINX_WORKER_PROCESSES: auto
      NGINX_WORKER_CONNECTIONS: 1024
      NGINX_KEEPALIVE_TIMEOUT: 65
      NGINX_CLIENT_MAX_BODY_SIZE: 50m
      NGINX_PROXY_READ_TIMEOUT: 120
      NGINX_PROXY_CONNECT_TIMEOUT: 60
      NGINX_PROXY_SEND_TIMEOUT: 60
    volumes:
      - sites:/home/frappe/frappe-bench/sites
      - logs:/home/frappe/frappe-bench/logs
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/api/method/ping"]
      interval: 30s
      timeout: 10s
      retries: 3

  queue-long:
    image: frappe/erpnext:v15.63.0
    container_name: ${safe_site_name}-queue-long
    networks:
      - frappe_network
    deploy:
      restart_policy:
        condition: on-failure
    command:
      - bench
      - worker
      - --queue
      - long,default,short
    volumes:
      - sites:/home/frappe/frappe-bench/sites
      - logs:/home/frappe/frappe-bench/logs

  queue-short:
    image: frappe/erpnext:v15.63.0
    container_name: ${safe_site_name}-queue-short
    networks:
      - frappe_network
    deploy:
      restart_policy:
        condition: on-failure
    command:
      - bench
      - worker
      - --queue
      - short,default
    volumes:
      - sites:/home/frappe/frappe-bench/sites
      - logs:/home/frappe/frappe-bench/logs

  queue-default:
    image: frappe/erpnext:v15.63.0
    container_name: ${safe_site_name}-queue-default
    networks:
      - frappe_network
    deploy:
      restart_policy:
        condition: on-failure
    command:
      - bench
      - worker
      - --queue
      - default
    volumes:
      - sites:/home/frappe/frappe-bench/sites
      - logs:/home/frappe/frappe-bench/logs

  redis-queue:
    image: redis:6.2-alpine
    container_name: ${safe_site_name}-redis-queue
    networks:
      - frappe_network
    deploy:
      restart_policy:
        condition: on-failure
    volumes:
      - redis-queue-data:/data

  redis-cache:
    image: redis:6.2-alpine
    container_name: ${safe_site_name}-redis-cache
    networks:
      - frappe_network
    deploy:
      restart_policy:
        condition: on-failure
    volumes:
      - redis-cache-data:/data

  scheduler:
    image: frappe/erpnext:v15.63.0
    container_name: ${safe_site_name}-scheduler
    networks:
      - frappe_network
    deploy:
      restart_policy:
        condition: on-failure
    command:
      - bench
      - schedule
    volumes:
      - sites:/home/frappe/frappe-bench/sites
      - logs:/home/frappe/frappe-bench/logs

  websocket:
    image: frappe/erpnext:v15.63.0
    container_name: ${safe_site_name}-websocket
    networks:
      - frappe_network
    deploy:
      restart_policy:
        condition: on-failure
    command:
      - node
      - /home/frappe/frappe-bench/apps/frappe/socketio.js
    volumes:
      - sites:/home/frappe/frappe-bench/sites
      - logs:/home/frappe/frappe-bench/logs

networks:
  frappe_network:
    driver: bridge
  traefik_proxy:
    external: true

volumes:
  sites:
  logs:
  db-data:
  redis-queue-data:
  redis-cache-data:
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
    echo -e "${YELLOW}💡 Please run: sudo ./generate_frappe_docker_local.sh${NC}"
    exit 1
fi

# Welcome message
echo -e "${GREEN}Welcome to Frappe/ERPNext Docker Setup (Local-Aware Edition)!${NC}"
echo "=============================================================="
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

# Create .env file
cat > "$safe_site_name/.env" << EOF
ERPNEXT_VERSION=v15.63.0
DB_PASSWORD=admin
FRAPPE_SITE_NAME_HEADER=${site_name}
SITES=${site_name}
EOF

# No email needed for local HTTP-only setup

# Generate docker-compose
generate_docker_compose "$safe_site_name" "$site_name"

# Start containers
echo -e "${GREEN}Starting your Frappe/ERPNext site...${NC}"
docker compose -f "$safe_site_name/${safe_site_name}-docker-compose.yml" up -d

# Auto-add domain to hosts file for local access
echo ""
echo -e "${BLUE}🔧 Managing hosts file for local access...${NC}"
if manage_hosts_entry "$site_name" "add"; then
    if [[ ! $site_name =~ \.localhost$ ]]; then
        echo -e "${BLUE}   You can now access your site at: http://$site_name${NC}"
        echo -e "${YELLOW}   💡 To remove this domain later, run: ./manage-hosts.sh${NC}"
    fi
fi

# Final messages with port-aware URLs
echo ""
echo -e "${GREEN}🚀 Your site is being prepared and will be live in approximately 5 minutes...${NC}"

# Determine the access URL based on configuration
if [[ -f ".traefik-local-config" ]]; then
    source .traefik-local-config
    if [[ "$USE_LOCALHOST" == "true" ]]; then
        # For localhost domains, show the correct port
        if [[ "$TRAEFIK_HTTP_PORT" != "80" ]]; then
            echo -e "🌐 Your site will be accessible at: http://${site_name}:${TRAEFIK_HTTP_PORT}"
        else
            echo -e "🌐 Your site will be accessible at: http://${site_name}"
        fi
    elif [[ "$TRAEFIK_HTTP_PORT" != "80" ]]; then
        echo -e "🌐 Your site will be accessible at: http://${site_name}:${TRAEFIK_HTTP_PORT}"
    else
        echo -e "🌐 Your site will be accessible at: http://${site_name}"
    fi
else
    # Default to port 80 if no config
    echo -e "🌐 Your site will be accessible at: http://${site_name}"
fi

echo ""
echo "📋 Frappe Version: v15.63.0"
echo "👤 Default Username: Administrator"
echo "🔑 Default Password: admin"
echo ""
echo "💡 You can change the password after first login."
echo ""
echo "To add another domain or site, simply run this script again with a different site name."
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
