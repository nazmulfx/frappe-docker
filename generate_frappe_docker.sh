#!/bin/bash

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo "Docker is not installed. Please install Docker and try again."
    exit 1
fi

# Prompt user for SSL preference
echo "Welcome to Frappe/ERPNext Docker Setup!"
echo "========================================="
read -p "Do you want to enable SSL/HTTPS? (y/n): " ENABLE_SSL

if [[ "$ENABLE_SSL" =~ ^[Yy]$ ]]; then
    echo "SSL/HTTPS will be enabled with Let's Encrypt certificates."
    USE_SSL=true
else
    echo "SSL/HTTPS will be disabled. Site will run on HTTP only."
    USE_SSL=false
fi
echo ""


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
    local port=$1
    local process_info=$(ss -ltnp "sport = :$port" 2>/dev/null | grep LISTEN | awk '{print $7}')
    if [[ -n "$process_info" ]]; then
        echo "$process_info"
    else
        # Alternative method using netstat if ss doesn't work
        netstat -tlnp 2>/dev/null | grep ":$port " | awk '{print $7}' | head -1
    fi
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

# Check if ports 80 and 443 are in use by non-Traefik processes
if check_traefik; then
    echo "✅ Traefik is already running and managing ports 80 and 443."
    echo "   Your new site will use the existing Traefik instance."
    echo ""
else
    # Only check for port conflicts if Traefik is not running
    PORTS_BLOCKED=false
    BLOCKED_PORTS=""
    
    if check_port 80; then
        PORTS_BLOCKED=true
        BLOCKED_PORTS="80"
    fi
    if check_port 443; then
        PORTS_BLOCKED=true
        BLOCKED_PORTS="$BLOCKED_PORTS 443"
    fi
    
    if [[ "$PORTS_BLOCKED" == true ]]; then
        echo "⚠️  Warning: Ports $BLOCKED_PORTS are in use by other processes."
        echo "   Traefik needs both ports 80 and 443 to work properly."
        echo ""
        
        for port in $BLOCKED_PORTS; do
            echo "Port $port is being used by:"
            PROCESS_INFO=$(get_port_process $port)
            if [[ -n "$PROCESS_INFO" ]]; then
                echo "  $PROCESS_INFO"
            else
                echo "  Unknown process (use 'sudo netstat -tlnp | grep :$port' to check)"
            fi
        done
        
        echo ""
        read -p "Do you want to stop these services and continue? (y/n): " STOP_SERVICE
        if [[ $STOP_SERVICE == "y" ]]; then
            echo "Attempting to stop conflicting services..."
            
            # Try to stop any existing Traefik containers first
            docker compose -f traefik-docker-compose.yml down 2>/dev/null
            
            # Try to stop processes using the ports
            for port in $BLOCKED_PORTS; do
                if check_port $port; then
                    PROCESS_PID=$(get_port_process $port | cut -d'/' -f1)
                    if [[ -n "$PROCESS_PID" ]] && [[ "$PROCESS_PID" =~ ^[0-9]+$ ]]; then
                        echo "Stopping process $PROCESS_PID using port $port..."
                        sudo kill $PROCESS_PID 2>/dev/null
                    fi
                fi
            done
            
            sleep 3
            
            # Verify ports are now free
            STILL_BLOCKED=false
            for port in $BLOCKED_PORTS; do
                if check_port $port; then
                    STILL_BLOCKED=true
                    echo "❌ Port $port is still in use"
                fi
            done
            
            if [[ "$STILL_BLOCKED" == true ]]; then
                echo "Error: Could not free up required ports. Please stop the services manually and try again."
                exit 1
            else
                echo "✅ Ports are now available for Traefik"
            fi
        else
            echo "Setup cancelled. Please free up ports 80 and 443 manually and try again."
            exit 1
        fi
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

# Check if Traefik is running and what configuration it has
if check_traefik; then
    echo "Traefik is already running."
    
    # Check if current Traefik has SSL configuration by checking ports
    TRAEFIK_PORTS=$(docker ps --format "{{.Ports}}" --filter "name=traefik")
    TRAEFIK_HAS_SSL=$([[ $TRAEFIK_PORTS == *":443->443"* ]] && echo "true" || echo "false")
    
    echo "Current Traefik configuration:"
    echo "- HTTP (port 80): $([[ $TRAEFIK_PORTS == *":80->80"* ]] && echo "✅ Available" || echo "❌ Missing")"
    echo "- HTTPS (port 443): $([[ $TRAEFIK_PORTS == *":443->443"* ]] && echo "✅ Available" || echo "❌ Missing")"
    echo ""
    
    if [[ "$USE_SSL" == true ]] && [[ "$TRAEFIK_HAS_SSL" == "false" ]]; then
        echo "⚠️  Current Traefik is HTTP-only, but you want HTTPS."
        echo "   This will upgrade Traefik to support both HTTP and HTTPS."
        read -p "   Continue with upgrade? (y/n): " RECREATE_TRAEFIK
        if [[ ! "$RECREATE_TRAEFIK" =~ ^[Yy]$ ]]; then
            echo "Aborted."
            exit 1
        fi
        echo "Stopping current Traefik..."
        docker compose -f traefik-docker-compose.yml down
        sleep 2
        echo "Traefik will be recreated with HTTPS support..."
    elif [[ "$USE_SSL" == false ]] && [[ "$TRAEFIK_HAS_SSL" == "true" ]]; then
        echo "✅ Current Traefik supports HTTPS. Your HTTP-only site will work alongside HTTPS sites."
        echo "   No Traefik reconfiguration needed."
    elif [[ "$USE_SSL" == true ]] && [[ "$TRAEFIK_HAS_SSL" == "true" ]]; then
        echo "✅ Current Traefik already supports HTTPS. Perfect for your HTTPS site."
    elif [[ "$USE_SSL" == false ]] && [[ "$TRAEFIK_HAS_SSL" == "false" ]]; then
        echo "✅ Current Traefik is HTTP-only. Perfect for your HTTP-only site."
    fi
fi

# Check if Traefik is running, if not, create and start it
if ! check_traefik; then
    echo "Traefik is not running. Creating traefik-docker-compose.yml..."
    
    # SSL-specific configuration
    if [[ "$USE_SSL" == true ]]; then
        # Ask for Cloudflare API token (leave blank to use HTTP-01 challenge)
        read -p "Enter your Cloudflare API token (leave blank for HTTP challenge): " CF_API_TOKEN
        read -p "Enter email for Let's Encrypt notifications: " EMAIL

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
    else
        # No SSL configuration needed
        ACME_CHALLENGE_OPTIONS=()
        ENV_SECTION=""
        EMAIL=""
    fi

    # Always generate Traefik with both HTTP and HTTPS support
    # This allows mixing HTTP-only and HTTPS sites
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

    # Create necessary directories for SSL certificates (always needed now)
    mkdir -p "./traefik-letsencrypt"
    touch "./traefik-letsencrypt/acme.json"
    chmod 600 "./traefik-letsencrypt/acme.json"
    echo "Created SSL certificate storage directory"

    echo "Starting Traefik..."
    docker compose -f traefik-docker-compose.yml up -d
    if [ $? -ne 0 ]; then
        echo "Error: Failed to start Traefik"
        exit 1
    fi
    
    # Verify Traefik started with correct ports
    sleep 3
    TRAEFIK_PORTS=$(docker ps --format "{{.Ports}}" --filter "name=traefik")
    echo ""
    echo "Traefik started successfully with:"
    echo "- HTTP (port 80): $([[ $TRAEFIK_PORTS == *":80->80"* ]] && echo "✅ Available" || echo "❌ Missing")"
    echo "- HTTPS (port 443): $([[ $TRAEFIK_PORTS == *":443->443"* ]] && echo "✅ Available" || echo "❌ Missing")"
    echo "- Dashboard (port 8080): $([[ $TRAEFIK_PORTS == *":8080->8080"* ]] && echo "✅ Available" || echo "❌ Missing")"
    echo ""
    echo "✅ Traefik now supports both HTTP and HTTPS sites!"
    echo ""
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
if [[ "$USE_SSL" == true ]]; then
    # Generate docker-compose.yml with SSL configuration
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
        apt-get update && apt-get install -y nano;
        bench new-site --mariadb-user-host-login-scope='%' --admin-password=admin --db-root-username=root --db-root-password=admin --install-app erpnext --set-default ${SITE_NAME};
        echo "${SITE_NAME}" > sites/currentsite.txt;
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
      - "traefik.http.routers.${SAFE_SITE_NAME}-frontend-http.middlewares=${SAFE_SITE_NAME}-redirect-to-https"
      - "traefik.http.middlewares.${SAFE_SITE_NAME}-redirect-to-https.redirectscheme.scheme=https"
      - "traefik.http.middlewares.${SAFE_SITE_NAME}-redirect-to-https.redirectscheme.permanent=true"
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

else
    # Generate docker-compose.yml without SSL configuration
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
        apt-get update && apt-get install -y nano;
        bench new-site --mariadb-user-host-login-scope='%' --admin-password=admin --db-root-username=root --db-root-password=admin --install-app erpnext --set-default ${SITE_NAME};
        echo "${SITE_NAME}" > sites/currentsite.txt;
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

fi

sudo docker compose -f $SAFE_SITE_NAME/${SAFE_SITE_NAME}-docker-compose.yml up -d

echo ""
echo ""
echo ""


for ((i = 30; i >= 1; i--)); do
    dot_count=$(( (30 - i) % 4 ))  # Cycles through 0,1,2,3
    dots=$(printf '%*s' "$dot_count" '' | tr ' ' '.')
    printf "\rExecuting your commands — Please wait %2d seconds%s  " "$i" "$dots"
    sleep 1
done

echo ""
echo "🚀 Preparing your site — it will be live in approximately 5 minutes..."
if [[ "$USE_SSL" == true ]]; then
    echo "🔒 Your site will be accessible at: https://${SITE_NAME}"
else
    echo "🌐 Your site will be accessible at: http://${SITE_NAME}"
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

# Checking site availability
echo "🔍 Checking site availability..."
echo ""

sleep 10  # Wait for 10 seconds before starting checks

MAX_RETRIES=10
RETRY_INTERVAL=10

for ((i = 1; i <= MAX_RETRIES; i++)); do
    # First check without -L
    STATUS_NO_L=$(curl -s -o /dev/null -w "%{http_code}" "${SITE_URL}")

    if [[ "$STATUS_NO_L" == "200" ]]; then
        echo -e "${GREEN}🎉 Congrats! Your site is live at: ${SITE_URL}${NC}"
        break
    fi

    # Then check with -L
    STATUS_L=$(curl -s -o /dev/null -w "%{http_code}" -L "${SITE_URL}")

    if [[ "$STATUS_L" == "200" ]]; then
        echo -e "${GREEN}🎉 Congrats! Your site is live at: ${SITE_URL}${NC}"
        break
    fi

    echo "Attempt $i: Site not live yet (Status: ${STATUS_NO_L}/${STATUS_L}). Retrying in ${RETRY_INTERVAL} seconds..."
    sleep $RETRY_INTERVAL
done

# After loop ends, if not successful
if [[ "$STATUS_NO_L" != "200" && "$STATUS_L" != "200" ]]; then
    echo ""
    echo "⏳ Your site is still starting up. Please wait a few more minutes and check:"
    echo "   ${SITE_URL}"
    echo ""
    echo "💡 If you encounter issues, check the logs:"
    echo "   docker logs ${SAFE_SITE_NAME}-frontend --tail 50"
fi


# if want to check frontend logs
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



