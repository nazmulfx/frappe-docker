#!/bin/bash

# Color definitions
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
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

# Validate a domain name
validate_domain() {
    local domain=$1
    if [[ ! $domain =~ ^[a-zA-Z0-9][a-zA-Z0-9-]*(\.[a-zA-Z0-9][a-zA-Z0-9-]*)*\.[a-zA-Z]{2,}$ ]]; then
        echo -e "${RED}Error: Invalid domain name format. Please use a format like 'example.com' or 'subdomain.example.com'.${NC}"
        return 1
    fi
    return 0
}

# Generate the docker-compose.yml file
generate_docker_compose() {
    local safe_site_name=$1
    local site_name=$2
    local use_ssl=$3
    local compose_file="$safe_site_name/${safe_site_name}-docker-compose.yml"

    local frontend_labels=""
    if [[ "$use_ssl" == true ]]; then
        frontend_labels=$(cat <<EOF
      - "traefik.enable=true"
      - "traefik.docker.network=traefik_proxy"
      - "traefik.http.services.${safe_site_name}-frontend.loadbalancer.server.port=8080"
      - "traefik.http.services.${safe_site_name}-frontend.loadbalancer.passHostHeader=true"
      - "traefik.http.routers.${safe_site_name}-frontend-http.rule=Host(\`${site_name}\`)"
      - "traefik.http.routers.${safe_site_name}-frontend-http.entrypoints=web"
      - "traefik.http.routers.${safe_site_name}-frontend-http.middlewares=${safe_site_name}-redirect-to-https"
      - "traefik.http.middlewares.${safe_site_name}-redirect-to-https.redirectscheme.scheme=https"
      - "traefik.http.middlewares.${safe_site_name}-redirect-to-https.redirectscheme.permanent=true"
      - "traefik.http.routers.${safe_site_name}-frontend-https.rule=Host(\`${site_name}\`)"
      - "traefik.http.routers.${safe_site_name}-frontend-https.entrypoints=websecure"
      - "traefik.http.routers.${safe_site_name}-frontend-https.tls=true"
      - "traefik.http.routers.${safe_site_name}-frontend-https.tls.certresolver=myresolver"
      - "traefik.http.routers.${safe_site_name}-frontend-https.service=${safe_site_name}-frontend"
EOF
)
    else
        frontend_labels=$(cat <<EOF
      - "traefik.enable=true"
      - "traefik.docker.network=traefik_proxy"
      - "traefik.http.services.${safe_site_name}-frontend.loadbalancer.server.port=8080"
      - "traefik.http.services.${safe_site_name}-frontend.loadbalancer.passHostHeader=true"
      - "traefik.http.routers.${safe_site_name}-frontend-http.rule=Host(\`${site_name}\`)"
      - "traefik.http.routers.${safe_site_name}-frontend-http.entrypoints=web"
      - "traefik.http.routers.${safe_site_name}-frontend-http.service=${safe_site_name}-frontend"
EOF
)
    fi

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

# Welcome message
echo -e "${GREEN}Welcome to Frappe/ERPNext Docker Setup!${NC}"
echo "========================================="

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
    docker compose -f traefik-docker-compose.yml up -d
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

# Create .env file
cat > "$safe_site_name/.env" << EOF
ERPNEXT_VERSION=v15.63.0
DB_PASSWORD=admin
LETSENCRYPT_EMAIL=${email}
FRAPPE_SITE_NAME_HEADER=${site_name}
SITES=${site_name}
EOF

# Generate docker-compose
generate_docker_compose "$safe_site_name" "$site_name" "$use_ssl"

# Start containers
echo -e "${GREEN}Starting your Frappe/ERPNext site...${NC}"
docker compose -f "$safe_site_name/${safe_site_name}-docker-compose.yml" up -d

# Final messages
echo ""
echo -e "${GREEN}🚀 Your site is being prepared and will be live in approximately 5 minutes...${NC}"
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
echo "To add another domain or site, simply run this script again with a different site name."
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



