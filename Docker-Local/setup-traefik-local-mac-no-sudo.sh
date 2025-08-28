#!/bin/bash

# Color definitions
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}===============================================${NC}"
echo -e "${BLUE}  Traefik Local Environment Setup Script (Mac)${NC}"
echo -e "${BLUE}===============================================${NC}"
echo -e "${BLUE}        No sudo required - Mac optimized!      ${NC}"
echo -e "${BLUE}===============================================${NC}"
echo ""

# Function to check if running on Mac
is_mac() {
    [[ "$OSTYPE" == "darwin"* ]] || [[ "$(uname)" == "Darwin" ]]
}

# Function to check if a port is in use (Mac compatible)
is_port_in_use() {
    if command -v lsof >/dev/null 2>&1; then
        lsof -i :$1 >/dev/null 2>&1
    else
        ss -ltn "sport = :$1" 2>/dev/null | grep -q LISTEN
    fi
}

# Function to get the process using a port (Mac compatible)
get_process_on_port() {
    if command -v lsof >/dev/null 2>&1; then
        lsof -i :$1 2>/dev/null | grep LISTEN | head -1 | awk '{print $1}'
    else
        lsof -i :$1 2>/dev/null | grep LISTEN | head -1 | awk '{print $1}'
    fi
}

# Check if running from correct directory
if [[ ! -f "generate_frappe_docker_local.sh" ]]; then
    echo -e "${RED}❌ Error: Please run this script from the Docker-Local directory${NC}"
    echo -e "${YELLOW}💡 Change to the Docker-Local directory first:${NC}"
    echo "cd Docker-Local"
    exit 1
fi

# Check if running on Mac
if ! is_mac; then
    echo -e "${RED}❌ This script is designed for macOS${NC}"
    echo -e "${YELLOW}💡 Use setup-traefik-local.sh for Linux${NC}"
    exit 1
fi

echo -e "${BLUE}🍎 Detected macOS - Using Mac-optimized setup${NC}"
echo ""
echo -e "${YELLOW}Mac-specific benefits:${NC}"
echo "• No sudo required for most operations"
echo "• Port 8081 by default (avoids system port conflicts)"
echo "• Native .localhost domain support"
echo "• Docker Desktop optimized"
echo ""

# Check Docker status
if ! docker info >/dev/null 2>&1; then
    echo -e "${RED}❌ Docker is not running${NC}"
    echo ""
    echo -e "${YELLOW}To start Docker Desktop:${NC}"
    echo "1. Open Docker Desktop application"
    echo "2. Wait for Docker to start (green light in menu bar)"
    echo "3. Run this script again"
    echo ""
    exit 1
fi

echo -e "${GREEN}✅ Docker is running${NC}"

# Check port availability
echo ""
echo -e "${YELLOW}Checking port availability...${NC}"

PORT_80_USED=false
PORT_8080_USED=false
PORT_8081_USED=false

if is_port_in_use 80; then
    PORT_80_USED=true
    PROCESS_80=$(get_process_on_port 80)
    echo -e "${RED}❌ Port 80 is in use by: $PROCESS_80${NC}"
    echo -e "${YELLOW}💡 This is common on macOS - system services often use port 80${NC}"
else
    echo -e "${GREEN}✅ Port 80 is available${NC}"
fi

if is_port_in_use 8080; then
    PORT_8080_USED=true
    PROCESS_8080=$(get_process_on_port 8080)
    echo -e "${YELLOW}⚠️  Port 8080 is in use by: $PROCESS_8080${NC}"
else
    echo -e "${GREEN}✅ Port 8080 is available${NC}"
fi

if is_port_in_use 8081; then
    PORT_8081_USED=true
    PROCESS_8081=$(get_process_on_port 8081)
    echo -e "${RED}❌ Port 8081 is in use by: $PROCESS_8081${NC}"
else
    echo -e "${GREEN}✅ Port 8081 is available${NC}"
fi

echo ""

# Check if Traefik is already running
if docker ps --filter "name=traefik" --format "{{.Names}}" | grep -q "traefik"; then
    echo -e "${YELLOW}Traefik is already running. Stopping it...${NC}"
    docker compose -f traefik-docker-compose.yml down 2>/dev/null || docker stop traefik 2>/dev/null
    sleep 2
fi

# Create traefik_proxy network if it doesn't exist
if ! docker network ls | grep -q traefik_proxy; then
    echo -e "${GREEN}Creating traefik_proxy network...${NC}"
    docker network create traefik_proxy
else
    echo -e "${GREEN}✅ traefik_proxy network already exists${NC}"
fi

# Create Traefik directories
mkdir -p traefik-letsencrypt
mkdir -p traefik-config/dynamic

# Initialize variables for Mac-optimized setup
USE_STANDARD_PORTS=false
USE_LOCALHOST=true
HTTP_PORT=8081

# Determine best port configuration for Mac
if [[ "$PORT_8081_USED" == true ]]; then
    echo ""
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${YELLOW}Port 8081 is in use - choosing alternative port${NC}"
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    
    # Find next available port
    for port in 8082 8083 8084 8085 8086; do
        if ! is_port_in_use $port; then
            HTTP_PORT=$port
            echo -e "${GREEN}✅ Using port $port (next available)${NC}"
            break
        fi
    done
    
    if [[ "$HTTP_PORT" == "8081" ]]; then
        echo -e "${RED}❌ No available ports found in range 8081-8086${NC}"
        echo -e "${YELLOW}💡 Please free up some ports or specify a custom port${NC}"
        read -p "Enter custom port number (e.g., 9000): " CUSTOM_PORT
        if [[ "$CUSTOM_PORT" =~ ^[0-9]+$ ]] && [ "$CUSTOM_PORT" -gt 1024 ] && [ "$CUSTOM_PORT" -lt 65536 ]; then
            HTTP_PORT=$CUSTOM_PORT
            echo -e "${GREEN}✅ Using custom port: $CUSTOM_PORT${NC}"
        else
            echo -e "${RED}❌ Invalid port number. Using port 8081${NC}"
            HTTP_PORT=8081
        fi
    fi
else
    echo -e "${GREEN}✅ Using default Mac port: 8081${NC}"
fi

# Generate Traefik configuration for Mac (no sudo required)
echo ""
echo -e "${GREEN}Creating Mac-optimized Traefik configuration...${NC}"

cat > traefik-docker-compose.yml << EOF
version: "3"

services:
  traefik:
    image: traefik:v2.10
    command:
      - "--api.insecure=true"
      - "--providers.docker=true"
      - "--providers.docker.exposedbydefault=false"
      - "--entrypoints.web.address=:${HTTP_PORT}"
      - "--serversTransport.insecureSkipVerify=true"
      - "--accesslog=true"
      - "--log.level=INFO"
      - "--api.dashboard=true"
      - "--providers.docker.network=traefik_proxy"
    ports:
      - "${HTTP_PORT}:${HTTP_PORT}"  # HTTP on Mac-optimized port
      - "8080:8080"  # Traefik dashboard
    volumes:
      - "/var/run/docker.sock:/var/run/docker.sock:ro"
    networks:
      - traefik_proxy
    container_name: traefik
    restart: unless-stopped
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.dashboard.rule=Host(\`traefik.localhost\`)"
      - "traefik.http.routers.dashboard.service=api@internal"
      - "traefik.http.routers.dashboard.entrypoints=web"

networks:
  traefik_proxy:
    external: true
EOF

# Start Traefik
echo ""
echo -e "${GREEN}Starting Traefik...${NC}"
docker compose -f traefik-docker-compose.yml up -d

# Wait for Traefik to start
sleep 3

# Check if Traefik started successfully
if docker ps --filter "name=traefik" --format "{{.Names}}" | grep -q "traefik"; then
    echo ""
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${GREEN}✅ Traefik has been successfully configured!${NC}"
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    
    echo -e "${BLUE}Configuration:${NC}"
    echo "• HTTP Port: ${HTTP_PORT}"
    echo "• Dashboard: http://localhost:8080"
    echo "• Use domains like: mysite.localhost"
    echo ""
    echo -e "${YELLOW}Mac-optimized setup:${NC}"
    echo "• Domain: yoursite.localhost"
    echo "• Access your site at: http://yoursite.localhost:${HTTP_PORT}"
    echo "• .localhost domains work natively on macOS"
    echo "• No sudo required for most operations"
    
    echo ""
    echo -e "${GREEN}Traefik Dashboard: http://localhost:8080${NC}"
    
    echo ""
    echo -e "${BLUE}🍎 Mac-specific benefits:${NC}"
    echo "• .localhost domains work natively on macOS"
    echo "• No need to modify /etc/hosts file"
    echo "• Better port conflict handling"
    echo "• Optimized for Docker Desktop on Mac"
    echo "• No sudo required for setup"
    
    echo ""
    
    # Save configuration for local development
    cat > .traefik-local-config << EOF
TRAEFIK_HTTP_PORT=${HTTP_PORT}
USE_LOCALHOST=true
EOF
    
    echo -e "${GREEN}Configuration saved to .traefik-local-config${NC}"
    
    echo ""
    echo -e "${YELLOW}🚀 Next steps for Mac users:${NC}"
    echo "1. Run: ./generate_frappe_docker_local.sh (no sudo needed!)"
    echo "2. Use domain: yoursite.localhost"
    echo "3. Access at: http://yoursite.localhost:${HTTP_PORT}"
    echo "4. Manage with: ./docker-manager-local.sh (no sudo needed!)"
    
    echo ""
    echo -e "${BLUE}💡 Mac Pro Tips:${NC}"
    echo "• .localhost domains work automatically on macOS"
    echo "• Port ${HTTP_PORT} avoids system port conflicts"
    echo "• Docker Desktop handles most permissions automatically"
    echo "• No need to edit /etc/hosts file"
    
else
    echo ""
    echo -e "${RED}❌ Failed to start Traefik${NC}"
    echo "Check the logs with: docker compose -f traefik-docker-compose.yml logs"
    
    echo ""
    echo -e "${YELLOW}Mac troubleshooting tips:${NC}"
    echo "• Ensure Docker Desktop is running"
    echo "• Check Docker Desktop resources (CPU/Memory)"
    echo "• Restart Docker Desktop if needed"
    echo "• Check port availability: lsof -i :${HTTP_PORT}"
    echo "• Ensure Docker Desktop has sufficient permissions"
    
    exit 1
fi
