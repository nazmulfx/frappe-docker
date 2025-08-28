#!/bin/bash

echo "Manual Traefik HTTPS Fix"
echo "========================"

read -p "Enter your email for Let's Encrypt: " EMAIL

echo "Stopping Traefik..."
docker compose -f traefik-docker-compose.yml down

echo "Backing up current configuration..."
cp traefik-docker-compose.yml traefik-docker-compose.yml.backup

echo "Creating new HTTPS-enabled configuration..."
cat > traefik-docker-compose.yml << EOF
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
      - "--certificatesresolvers.myresolver.acme.httpchallenge=true"
      - "--certificatesresolvers.myresolver.acme.httpchallenge.entrypoint=web"
      - "--accesslog=true"
      - "--log.level=DEBUG"
      - "--api.dashboard=true"
    ports:
      - "80:80"
      - "443:443"
      - "8080:8080"
    volumes:
      - "/var/run/docker.sock:/var/run/docker.sock:ro"
      - "./traefik-letsencrypt:/letsencrypt"
    networks:
      - traefik_proxy
    container_name: traefik
    restart: unless-stopped

networks:
  traefik_proxy:
    external: true
EOF

echo "Starting Traefik with HTTPS support..."
docker compose -f traefik-docker-compose.yml up -d

echo ""
echo "✅ Done! Traefik now supports both HTTP and HTTPS"
echo "Check with: docker ps --format 'table {{.Names}}\t{{.Ports}}' | grep traefik" 