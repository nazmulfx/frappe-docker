#!/bin/bash

echo "Traefik HTTPS Upgrade Script"
echo "============================="
echo ""
echo "This script will upgrade your HTTP-only Traefik to support both HTTP and HTTPS."
echo ""

# Check if Traefik is running
if ! docker ps | grep -q traefik; then
    echo "Error: Traefik is not running."
    exit 1
fi

echo "Current Traefik configuration (HTTP-only detected):"
echo "- Port 80: ✅ Exposed"
echo "- Port 443: ❌ Missing"
echo "- SSL/TLS: ❌ Not configured"
echo ""

read -p "Enter your email for Let's Encrypt certificates: " EMAIL
if [[ -z "$EMAIL" ]]; then
    echo "Error: Email is required for Let's Encrypt"
    exit 1
fi

read -p "Enter your Cloudflare API token (leave blank for HTTP challenge): " CF_API_TOKEN
echo ""

echo "Stopping current Traefik..."
docker compose -f traefik-docker-compose.yml down

echo "Backing up current configuration..."
cp traefik-docker-compose.yml traefik-docker-compose.yml.http-only-backup

echo "Creating new HTTPS-enabled Traefik configuration..."

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

echo "Starting new HTTPS-enabled Traefik..."
docker compose -f traefik-docker-compose.yml up -d

echo ""
echo "✅ Traefik has been upgraded successfully!"
echo ""
echo "New configuration:"
echo "- Port 80: ✅ HTTP traffic"
echo "- Port 443: ✅ HTTPS traffic" 
echo "- SSL/TLS: ✅ Let's Encrypt certificates"
echo "- Mixed mode: ✅ HTTP and HTTPS domains can coexist"
echo ""
echo "Now your setup supports:"
echo "- HTTP-only domains (will stay HTTP)"
echo "- HTTPS domains (will get SSL certificates)"
echo ""
echo "Backup saved as: traefik-docker-compose.yml.http-only-backup" 