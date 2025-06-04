#!/bin/bash

# Prompt user for inputs
read -p "Enter site name (e.g. frappe_docker_test): " SITE_NAME
read -p "Do you want to enable SSL? (yes/no): " SSL_CHOICE

EMAIL=""
if [[ "$SSL_CHOICE" == "yes" ]]; then
  read -p "Enter email for Let's Encrypt (e.g. mail@example.com): " EMAIL
fi

# Create directory for site files
mkdir -p "$SITE_NAME"

# Prepare .env content
cat > "$SITE_NAME/.env" << EOF
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

SITES=\`${SITE_NAME}\`
EOF


is_port_free() {
  ss -ltn "sport = :$1" 2>/dev/null | grep -q LISTEN && return 1 || return 0
}

# Find free ports starting from defaults
DEFAULT_HTTP_PORT=80
DEFAULT_HTTPS_PORT=443
DEFAULT_DASHBOARD_PORT=8080

HTTP_PORT=$DEFAULT_HTTP_PORT
HTTPS_PORT=$DEFAULT_HTTPS_PORT
DASHBOARD_PORT=$DEFAULT_DASHBOARD_PORT

while ! is_port_free $HTTP_PORT; do
  ((HTTP_PORT++))
done

while ! is_port_free $HTTPS_PORT; do
  ((HTTPS_PORT++))
done

while ! is_port_free $DASHBOARD_PORT; do
  ((DASHBOARD_PORT++))
done

echo "Using ports:"
echo "  HTTP (80): $HTTP_PORT"
echo "  HTTPS (443): $HTTPS_PORT"
echo "  Dashboard (8080): $DASHBOARD_PORT"

# Prepare docker-compose.yml content with replaced site name
# Here-doc with variable expansion enabled
cat > "$SITE_NAME/${SITE_NAME}-docker-compose.yml" << EOF
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
    container_name: ${SITE_NAME}-backend # Dynamically set container name

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
    container_name: ${SITE_NAME}-configurator # Dynamically set container name

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
    container_name: ${SITE_NAME}-create-site # Dynamically set container name

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
    container_name: ${SITE_NAME}-db # Dynamically set container name

  frontend:
    image: frappe/erpnext:v15.63.0
    networks:
      - frappe_network
    depends_on:
      - websocket
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.frontend.rule=Host(\`${SITE_NAME}\`)"
      - "traefik.http.routers.frontend.entrypoints=websecure"
      - "traefik.http.routers.frontend.tls.certresolver=myresolver"
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
    volumes:
      - sites:/home/frappe/frappe-bench/sites
      - logs:/home/frappe/frappe-bench/logs
    # ports:
    #   - "${HTTP_PORT}:80"
    #   - "${HTTPS_PORT}:443"
    #   - "${DASHBOARD_PORT}:8080"
    container_name: ${SITE_NAME}-frontend # Dynamically set container name

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
    container_name: ${SITE_NAME}-queue-long # Dynamically set container name

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
    container_name: ${SITE_NAME}-queue-short # Dynamically set container name

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
    container_name: ${SITE_NAME}-queue-default


  redis-queue:
    image: redis:6.2-alpine
    networks:
      - frappe_network
    deploy:
      restart_policy:
        condition: on-failure
    volumes:
      - redis-queue-data:/data
    container_name: ${SITE_NAME}-redis-queue # Dynamically set container name

  redis-cache:
    image: redis:6.2-alpine
    networks:
      - frappe_network
    deploy:
      restart_policy:
        condition: on-failure
    volumes:
      - redis-cache-data:/data
    container_name: ${SITE_NAME}-redis-cache # Dynamically set container name

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
    container_name: ${SITE_NAME}-scheduler # Dynamically set container name

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
    container_name: ${SITE_NAME}-websocket # Dynamically set container name

  traefik:
    image: traefik:v2.10
    command:
      - "--api.insecure=true"
      - "--providers.docker=true"
      - "--entrypoints.web.address=:80"
      - "--entrypoints.websecure.address=:443"
      - "--certificatesresolvers.myresolver.acme.email=${EMAIL}"
      - "--certificatesresolvers.myresolver.acme.storage=/letsencrypt/acme.json"
      - "--certificatesresolvers.myresolver.acme.tlschallenge=true"
      - "--accesslog=true"
      - "--log.level=DEBUG"
    ports:
        - "${HTTP_PORT}:80"
        - "${HTTPS_PORT}:443"
    volumes:
      - "/var/run/docker.sock:/var/run/docker.sock:ro"
      - "traefik-letsencrypt:/letsencrypt"
    networks:
      - frappe_network
    container_name: ${SITE_NAME}-traefik # Dynamically set container name

networks:
  frappe_network:
    driver: bridge

volumes:
  sites:
  logs:
  db-data:
  redis-queue-data:
  redis-cache-data:
  traefik-letsencrypt:
EOF

echo "Generated files in $SITE_NAME/:"
echo "  - $SITE_NAME-docker-compose.yml"
echo "  - .env"

docker compose -f "$SITE_NAME/${SITE_NAME}-docker-compose.yml" up
