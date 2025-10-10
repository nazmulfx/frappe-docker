#!/bin/bash

# Color definitions
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

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

echo -e "${BLUE}===============================================${NC}"
echo -e "${BLUE}     Traefik Local Environment Setup Script    ${NC}"
echo -e "${BLUE}===============================================${NC}"
echo ""
echo -e "${GREEN}✅ Includes automatic fix for net::ERR_NETWORK_CHANGED errors${NC}"
echo ""

# Function to check if a port is in use
is_port_in_use() {
    ss -ltn "sport = :$1" 2>/dev/null | grep -q LISTEN
}

# Function to get the process using a port
get_process_on_port() {
    sudo lsof -i :$1 2>/dev/null | grep LISTEN | head -1 | awk '{print $1}'
}

# For local development only
ENVIRONMENT="local"
echo -e "${YELLOW}🏠 Local Development Environment${NC}"

echo ""
echo -e "${YELLOW}Checking port availability...${NC}"

# Check port status for local development (HTTP only)
PORT_80_USED=false
PORT_8080_USED=false

if is_port_in_use 80; then
    PORT_80_USED=true
    PROCESS_80=$(get_process_on_port 80)
    echo -e "${RED}❌ Port 80 is in use by: $PROCESS_80${NC}"
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

echo ""

# Get the correct docker compose command
DOCKER_COMPOSE_CMD=$(detect_docker_compose)
if [ $? -ne 0 ]; then
    echo -e "${RED}❌ Docker Compose not found. Please install Docker Compose and try again.${NC}"
    exit 1
fi

# Check if Traefik is already running
if docker ps --filter "name=traefik" --format "{{.Names}}" | grep -q "traefik"; then
    echo -e "${YELLOW}Traefik is already running. Stopping it...${NC}"
    $DOCKER_COMPOSE_CMD -f traefik-docker-compose.yml down 2>/dev/null || docker stop traefik 2>/dev/null
    sleep 2
fi

# Check and create traefik_proxy network (safe for existing sites)
echo -e "${BLUE}🌐 Checking Docker network configuration...${NC}"

# Check if traefik_proxy network exists
if ! docker network ls | grep -q traefik_proxy; then
    echo -e "${GREEN}Creating traefik_proxy network...${NC}"
    docker network create traefik_proxy --driver bridge
    echo -e "${GREEN}✅ Created traefik_proxy network${NC}"
else
    # Network exists, verify it's accessible (don't remove it!)
    if docker network inspect traefik_proxy >/dev/null 2>&1; then
        echo -e "${GREEN}✅ traefik_proxy network is healthy and ready${NC}"
    else
        echo -e "${RED}⚠️  Network exists but appears corrupted${NC}"
        echo -e "${YELLOW}   This requires manual intervention to avoid breaking existing sites${NC}"
        read -p "   Remove and recreate network? This will temporarily disconnect all sites (y/n): " confirm
        if [[ "$confirm" =~ ^[Yy]$ ]]; then
            # Store running containers
            RUNNING_CONTAINERS=$(docker ps --filter "network=traefik_proxy" --format "{{.Names}}")
            
            # Disconnect and remove
            CONNECTED=$(docker network inspect traefik_proxy -f '{{range .Containers}}{{.Name}} {{end}}' 2>/dev/null)
            for container in $CONNECTED; do
                docker network disconnect -f traefik_proxy "$container" 2>/dev/null
            done
            docker network rm traefik_proxy 2>/dev/null
            
            # Recreate
            docker network create traefik_proxy --driver bridge
            
            # Reconnect
            for container in $RUNNING_CONTAINERS; do
                docker network connect traefik_proxy "$container" 2>/dev/null
            done
            echo -e "${GREEN}✅ Network fixed and containers reconnected${NC}"
        else
            echo -e "${YELLOW}   Skipping network fix. You may need to fix this manually.${NC}"
        fi
    fi
fi

# Create Traefik directories
mkdir -p traefik-letsencrypt
mkdir -p traefik-config/dynamic

# Determine Traefik configuration based on local port availability
if [[ "$PORT_80_USED" == true ]]; then
    echo ""
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${YELLOW}Local environment with port conflicts detected${NC}"
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo "Options:"
    echo "1) Stop conflicting services and use standard port 80 (RECOMMENDED)"
    echo "2) Use alternative port 8081 (keep Nginx/Apache running)"
    echo "3) Use localhost domains on port 8081 (best for local dev)"
    echo ""
    read -p "Choose an option (1-3): " OPTION
    
    case $OPTION in
        1)
            echo ""
            echo -e "${YELLOW}Stopping conflicting services...${NC}"
            if [[ "$PROCESS_80" == "nginx" ]]; then
                sudo systemctl stop nginx
                sudo systemctl disable nginx
                echo -e "${GREEN}✅ Nginx stopped and disabled${NC}"
            elif [[ "$PROCESS_80" == "apache2" ]]; then
                sudo systemctl stop apache2
                sudo systemctl disable apache2
                echo -e "${GREEN}✅ Apache stopped and disabled${NC}"
            fi
            USE_STANDARD_PORTS=true
            ;;
        2)
            USE_STANDARD_PORTS=false
            HTTP_PORT=8081
            echo -e "${YELLOW}Using alternative port: HTTP on 8081${NC}"
            ;;
        3)
            USE_STANDARD_PORTS=false
            USE_LOCALHOST=true
            HTTP_PORT=8081
            echo -e "${YELLOW}Using localhost domains on port 8081 (HTTP only)${NC}"
            ;;
    esac
else
    USE_STANDARD_PORTS=true
    USE_SSL=false  # Default to HTTP only for local
fi

# Generate Traefik configuration
echo ""
echo -e "${GREEN}Creating Traefik configuration...${NC}"

if [[ "$USE_STANDARD_PORTS" == true ]]; then
    # Standard configuration for port 80 (HTTP only for local)
    cat > traefik-docker-compose.yml << 'EOF'
version: "3"

services:
  traefik:
    image: traefik:v2.10
    command:
      - "--api.insecure=true"
      - "--providers.docker=true"
      - "--providers.docker.exposedbydefault=false"
      - "--entrypoints.web.address=:80"
      - "--accesslog=true"
      - "--log.level=INFO"
      - "--api.dashboard=true"
      - "--providers.docker.network=traefik_proxy"
    ports:
      - "80:80"
      - "8080:8080"  # Traefik dashboard
    volumes:
      - "/var/run/docker.sock:/var/run/docker.sock:ro"
    networks:
      - traefik_proxy
    container_name: traefik
    restart: unless-stopped

networks:
  traefik_proxy:
    external: true
EOF
elif [[ "$USE_LOCALHOST" == true ]]; then
    # Localhost-only configuration
    cat > traefik-docker-compose.yml << 'EOF'
version: "3"

services:
  traefik:
    image: traefik:v2.10
    command:
      - "--api.insecure=true"
      - "--providers.docker=true"
      - "--providers.docker.exposedbydefault=false"
      - "--entrypoints.web.address=:8081"
      - "--serversTransport.insecureSkipVerify=true"
      - "--accesslog=true"
      - "--log.level=INFO"
      - "--api.dashboard=true"
      - "--providers.docker.network=traefik_proxy"
    ports:
      - "8081:8081"  # HTTP on alternative port
      - "8080:8080"  # Traefik dashboard
    volumes:
      - "/var/run/docker.sock:/var/run/docker.sock:ro"
    networks:
      - traefik_proxy
    container_name: traefik
    restart: unless-stopped
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.dashboard.rule=Host(`traefik.localhost`)"
      - "traefik.http.routers.dashboard.service=api@internal"
      - "traefik.http.routers.dashboard.entrypoints=web"

networks:
  traefik_proxy:
    external: true
EOF
else
    # Alternative port configuration (HTTP only)
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
      - "--accesslog=true"
      - "--log.level=INFO"
      - "--api.dashboard=true"
      - "--providers.docker.network=traefik_proxy"
    ports:
      - "${HTTP_PORT}:${HTTP_PORT}"
      - "8080:8080"  # Traefik dashboard
    volumes:
      - "/var/run/docker.sock:/var/run/docker.sock:ro"
    networks:
      - traefik_proxy
    container_name: traefik
    restart: unless-stopped

networks:
  traefik_proxy:
    external: true
EOF
fi

# Start Traefik
echo ""
echo -e "${GREEN}Starting Traefik...${NC}"
$DOCKER_COMPOSE_CMD -f traefik-docker-compose.yml up -d

# Wait for Traefik to start
sleep 3

# Check if Traefik started successfully
if docker ps --filter "name=traefik" --format "{{.Names}}" | grep -q "traefik"; then
    echo ""
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${GREEN}✅ Traefik has been successfully configured!${NC}"
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    
    if [[ "$USE_LOCALHOST" == true ]]; then
        echo -e "${BLUE}Configuration:${NC}"
        echo "• HTTP Port: 8081"
        echo "• Dashboard: http://localhost:8080"
        echo "• Use domains like: mysite.localhost"
        echo ""
        echo -e "${YELLOW}Note: When running generate_frappe_docker_local.sh:${NC}"
        echo "• Domain: yoursite.localhost"
        echo "• Access your site at: http://yoursite.localhost:8081"
    elif [[ "$USE_STANDARD_PORTS" == true ]]; then
        echo -e "${BLUE}Configuration:${NC}"
        echo "• HTTP Port: 80"
        echo "• Dashboard: http://localhost:8080"
        echo ""
        echo -e "${YELLOW}Note: You can now run generate_frappe_docker_local.sh${NC}"
    else
        echo -e "${BLUE}Configuration:${NC}"
        echo "• HTTP Port: ${HTTP_PORT}"
        echo "• Dashboard: http://localhost:8080"
        echo ""
        echo -e "${YELLOW}Note: Access your sites on port ${HTTP_PORT}${NC}"
    fi
    
    echo ""
    echo -e "${GREEN}Traefik Dashboard: http://localhost:8080${NC}"
    echo ""
    
    # Save configuration for local development
    cat > .traefik-local-config << EOF
TRAEFIK_HTTP_PORT=${HTTP_PORT:-80}
USE_LOCALHOST=${USE_LOCALHOST:-false}
EOF
    
    echo -e "${GREEN}Configuration saved to .traefik-local-config${NC}"
    
else
    echo ""
    echo -e "${RED}❌ Failed to start Traefik${NC}"
    echo "Check the logs with: $DOCKER_COMPOSE_CMD -f traefik-docker-compose.yml logs"
    exit 1
fi
