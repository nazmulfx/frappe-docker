#!/bin/bash

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo "Docker is not installed. Please install Docker and try again."
    exit 1
fi


# Function to check if a port is in use
check_port() {
    if ss -ltn "sport = :$1" 2>/dev/null | grep -q LISTEN; then
        return 0  # Port is in use
    else
        return 1  # Port is free
    fi
}

# Function to get process using a port
get_port_process() {
    ss -ltnp "sport = :$1" 2>/dev/null | grep LISTEN | awk '{print $7}'
}

# Function to check if traefik is running
check_traefik() {
    if docker ps | grep -q traefik; then
        return 0  # Traefik is running
    else
        return 1  # Traefik is not running
    fi
}

# Function to validate domain name
validate_domain() {
    local domain=$1
    if [[ ! $domain =~ ^[a-zA-Z0-9][a-zA-Z0-9-]*(\.[a-zA-Z0-9][a-zA-Z0-9-]*)*\.[a-zA-Z]{2,}$ ]]; then
        echo "Error: Invalid domain name format. Please use format like 'example.com' or 'subdomain.example.com'"
        exit 1
    fi
}

# Check if ports 80 and 443 are in use
if check_port 80 || check_port 443; then
    echo "Warning: Port 80 or 443 is already in use!"
    echo "This might be another web server or Traefik instance running."
    echo ""
    
    if check_port 80; then
        echo "Port 80 is being used by:"
        get_port_process 80
    fi
    if check_port 443; then
        echo "Port 443 is being used by:"
        get_port_process 443
    fi
    echo ""
    read -p "Do you want to stop the existing service? (y/n): " STOP_SERVICE
    if [[ $STOP_SERVICE == "y" ]]; then
        echo "Stopping existing services..."
        # Try to stop any existing Traefik containers
        docker compose -f traefik-docker-compose.yml down 2>/dev/null
        # If that doesn't work, try to stop the process using the ports
        if check_port 80; then
            sudo kill $(get_port_process 80 | cut -d',' -f2 | cut -d'=' -f2) 2>/dev/null
        fi
        if check_port 443; then
            sudo kill $(get_port_process 443 | cut -d',' -f2 | cut -d'=' -f2) 2>/dev/null
        fi
        sleep 2
        if check_port 80 || check_port 443; then
            echo "Error: Could not free up ports 80 and 443. Please stop the services manually and try again."
            exit 1
        fi
    else
        echo "Please stop the existing service manually and try again."
        exit 1
    fi
fi

# Check if traefik_proxy network exists, create if it doesn't
if ! docker network ls | grep -q traefik_proxy; then
    echo "Creating traefik_proxy network..."
    docker network create traefik_proxy
    if [ $? -ne 0 ]; then
        echo "Error: Failed to create traefik_proxy network"
        exit 1
    fi
    echo "traefik_proxy network created successfully"
else
    echo "traefik_proxy network already exists"
fi

# Check if Traefik is running, if not, create and start it
if ! check_traefik; then
    echo "Traefik is not running. Creating traefik-docker-compose.yml..."
    
    # Ask for Cloudflare API token (leave blank to use HTTP-01 challenge)
    read -p "Enter your Cloudflare API token (leave blank for HTTP challenge): " CF_API_TOKEN
    read  -p "Enter email for Let's Encrypt notifications: " EMAIL

    # Prepare ACME challenge options based on token presence
    if [[ -n "$CF_API_TOKEN" ]]; then
      ACME_CHALLENGE_OPTIONS=(
        "--certificatesresolvers.myresolver.acme.dnschallenge=true"
        "--certificatesresolvers.myresolver.acme.dnschallenge.provider=cloudflare"
      )
      ENV_SECTION=$(cat << EOF
    environment:
      - CF_DNS_API_TOKEN=${CF_API_TOKEN}
EOF
)
    else
      ACME_CHALLENGE_OPTIONS=(
        "--certificatesresolvers.myresolver.acme.httpchallenge=true"
        "--certificatesresolvers.myresolver.acme.httpchallenge.entrypoint=web"
      )
      ENV_SECTION=""
    fi

    cat > "traefik-docker-compose.yml" << EOF
version: "3"

services:
  traefik:
    image: traefik:v2.10
    command:
      - "--api.insecure=true"
      - "--providers.docker=true"
      - "--providers.docker.exposedbydefault=false"
      - "--entrypoints.web.address=:80"
      - "--entrypoints.web.http.redirections.entryPoint.to=websecure"
      - "--entrypoints.web.http.redirections.entryPoint.scheme=https"
      - "--entrypoints.websecure.address=:443"
      - "--entrypoints.websecure.http.tls=true"
      - "--serversTransport.insecureSkipVerify=true"
      - "--certificatesresolvers.myresolver.acme.email=${EMAIL}"
      - "--certificatesresolvers.myresolver.acme.storage=/letsencrypt/acme.json"
$(printf '      - "%s"\n' "${ACME_CHALLENGE_OPTIONS[@]}")
      - "--accesslog=true"
      - "--log.level=DEBUG"
      - "--api.dashboard=true"
    ports:
      - "80:80"
      - "443:443"
      - "8080:8080"  # dashboard
    volumes:
      - "/var/run/docker.sock:/var/run/docker.sock:ro"
      - "./traefik-letsencrypt:/letsencrypt"
    networks:
      - traefik_proxy
${ENV_SECTION}
    container_name: traefik
    restart: unless-stopped

networks:
  traefik_proxy:
    external: true
EOF

    echo "Starting Traefik..."
    docker compose -f traefik-docker-compose.yml up -d
    if [ $? -ne 0 ]; then
        echo "Error: Failed to start Traefik"
        exit 1
    fi
    echo "Traefik started successfully"
else
    echo "Traefik is already running"
fi

# Now handle the ERPNext stack creation
read -p "Enter site name (e.g. example.com): " SITE_NAME
validate_domain "$SITE_NAME"

# Generate a safe version for container naming
SAFE_SITE_NAME=$(echo "$SITE_NAME" | sed 's/[^a-zA-Z0-9]/_/g')

# Create directory for site files
mkdir -p "$SAFE_SITE_NAME"

# Create acme.json file with correct permissions
ACME_FILE_DIR="$SAFE_SITE_NAME/traefik-letsencrypt"
mkdir -p "$ACME_FILE_DIR"
touch "$ACME_FILE_DIR/acme.json"
chmod 600 "$ACME_FILE_DIR/acme.json"

# Prepare .env content
cat > "$SAFE_SITE_NAME/.env" << EOF
ERPNEXT_VERSION=v15.63.0

DB_PASSWORD=123

# Only if you use external database
DB_HOST=
DB_PORT=

# Only if you use external Redis
REDIS_CACHE=
REDIS_QUEUE=

# Only with HTTPS override
LETSENCRYPT_EMAIL=${EMAIL}

FRAPPE_SITE_NAME_HEADER=${SITE_NAME}

HTTP_PUBLISH_PORT=

UPSTREAM_REAL_IP_ADDRESS=

UPSTREAM_REAL_IP_HEADER=

UPSTREAM_REAL_IP_RECURSIVE=

PROXY_READ_TIMEOUT=

CLIENT_MAX_BODY_SIZE=

SITES=${SITE_NAME}
EOF

# Prepare docker-compose.yml content with replaced site name
cat > "$SAFE_SITE_NAME/${SAFE_SITE_NAME}-docker-compose.yml" << EOF
version: "3"

services:
  backend:
    image: frappe/erpnext:v15.63.0
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
    container_name: ${SAFE_SITE_NAME}-backend # Dynamically set container name

  configurator:
    image: frappe/erpnext:v15.63.0
    networks:
      - frappe_network
    deploy:
      restart_policy:
        condition: none
    entrypoint:
      - bash
      - -c
    command:
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
    container_name: ${SAFE_SITE_NAME}-configurator # Dynamically set container name

  create-site:
    image: frappe/erpnext:v15.63.0
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
    command:
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
        bench new-site --mariadb-user-host-login-scope='%' --admin-password=admin --db-root-username=root --db-root-password=admin --install-app erpnext --set-default ${SITE_NAME};
    depends_on:
      - db
      - redis-cache
      - redis-queue
    container_name: ${SAFE_SITE_NAME}-create-site # Dynamically set container name

  db:
    image: mariadb:10.6
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
    container_name: ${SAFE_SITE_NAME}-db # Dynamically set container name

  frontend:
    image: frappe/erpnext:v15.63.0
    networks:
      - frappe_network
      - traefik_proxy
    depends_on:
      - backend
      - websocket
    labels:
      - "traefik.enable=true"
      - "traefik.docker.network=traefik_proxy"
      - "traefik.http.services.${SAFE_SITE_NAME}-frontend.loadbalancer.server.port=8080"
      - "traefik.http.services.${SAFE_SITE_NAME}-frontend.loadbalancer.passHostHeader=true"
      - "traefik.http.routers.${SAFE_SITE_NAME}-frontend-http.rule=Host(\`${SITE_NAME}\`)"
      - "traefik.http.routers.${SAFE_SITE_NAME}-frontend-http.entrypoints=web"
      - "traefik.http.routers.${SAFE_SITE_NAME}-frontend-http.service=${SAFE_SITE_NAME}-frontend"
      - "traefik.http.routers.${SAFE_SITE_NAME}-frontend-http.middlewares=${SAFE_SITE_NAME}-redirect-to-https"
      - "traefik.http.middlewares.${SAFE_SITE_NAME}-redirect-to-https.redirectscheme.scheme=https"
      - "traefik.http.routers.${SAFE_SITE_NAME}-frontend-https.rule=Host(\`${SITE_NAME}\`)"
      - "traefik.http.routers.${SAFE_SITE_NAME}-frontend-https.entrypoints=websecure"
      - "traefik.http.routers.${SAFE_SITE_NAME}-frontend-https.tls=true"
      - "traefik.http.routers.${SAFE_SITE_NAME}-frontend-https.tls.certresolver=myresolver"
      - "traefik.http.routers.${SAFE_SITE_NAME}-frontend-https.service=${SAFE_SITE_NAME}-frontend"
      - "traefik.http.middlewares.${SAFE_SITE_NAME}-strip-prefix.stripprefix.prefixes=/"
      - "traefik.http.routers.${SAFE_SITE_NAME}-frontend-https.middlewares=${SAFE_SITE_NAME}-strip-prefix"
      - "traefik.http.routers.${SAFE_SITE_NAME}-frontend-https.priority=100"
    deploy:
      restart_policy:
        condition: on-failure
    command:
      - nginx-entrypoint.sh
    environment:
      BACKEND: backend:8000
      FRAPPE_SITE_NAME_HEADER: ${SITE_NAME}
      SOCKETIO: websocket:9000
      UPSTREAM_REAL_IP_ADDRESS: 127.0.0.1
      UPSTREAM_REAL_IP_HEADER: X-Forwarded-For
      UPSTREAM_REAL_IP_RECURSIVE: "off"
      PROXY_READ_TIMEOUT: 120
      CLIENT_MAX_BODY_SIZE: 50m
      VIRTUAL_HOST: ${SITE_NAME}
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
    container_name: ${SAFE_SITE_NAME}-frontend

  queue-long:
    image: frappe/erpnext:v15.63.0
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
    container_name: ${SAFE_SITE_NAME}-queue-long # Dynamically set container name

  queue-short:
    image: frappe/erpnext:v15.63.0
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
    container_name: ${SAFE_SITE_NAME}-queue-short # Dynamically set container name

  queue-default:
    image: frappe/erpnext:v15.63.0
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
    container_name: ${SAFE_SITE_NAME}-queue-default


  redis-queue:
    image: redis:6.2-alpine
    networks:
      - frappe_network
    deploy:
      restart_policy:
        condition: on-failure
    volumes:
      - redis-queue-data:/data
    container_name: ${SAFE_SITE_NAME}-redis-queue # Dynamically set container name

  redis-cache:
    image: redis:6.2-alpine
    networks:
      - frappe_network
    deploy:
      restart_policy:
        condition: on-failure
    volumes:
      - redis-cache-data:/data
    container_name: ${SAFE_SITE_NAME}-redis-cache # Dynamically set container name

  scheduler:
    image: frappe/erpnext:v15.63.0
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
    container_name: ${SAFE_SITE_NAME}-scheduler # Dynamically set container name

  websocket:
    image: frappe/erpnext:v15.63.0
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
    container_name: ${SAFE_SITE_NAME}-websocket # Dynamically set container name

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


sudo docker compose -f $SAFE_SITE_NAME/${SAFE_SITE_NAME}-docker-compose.yml up -d

# echo "Generated files in $SAFE_SITE_NAME/:"
# echo "  - $SAFE_SITE_NAME-docker-compose.yml"
# echo "  - .env"
# echo ""

echo ""
echo ""
echo ""

for ((i = 30; i >= 1; i--)); do
    dot_count=$(( (30 - i) % 4 ))  # Cycles through 0,1,2,3
    dots=$(printf '%*s' "$dot_count" '' | tr ' ' '.')
    printf "\rPreparing your site — it’ll be live in approximately %2d seconds%s  " "$i" "$dots"
    sleep 1
done


echo "To start your ERPNext stack:"

echo ""
echo "We're preparing your site — it’ll be live in approximately 2 minutes."
echo ""
echo "Your site will be available at: https://${SITE_NAME}"
echo ""
echo "To add another domain/site, just run this script again with a different site name."

# Ping the site until it's available (max 300 seconds wait)
echo "Checking site availability..."
echo ""

GREEN='\033[0;32m'
NC='\033[0m' # No Color

for ((i = 1; i <= 300; i++)); do
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" "https://${SITE_NAME}")
    if [[ "$STATUS" == "200" ]]; then
        echo ""
        echo -e "${GREEN}🎉 Congrats! Your site is live at: https://${SITE_NAME}${NC}"
        break
    fi

    printf "\rWaiting for site to go live... %ds" "$((i * 2))"
    sleep 2
done

echo ""