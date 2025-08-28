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
echo ""

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
        sudo lsof -i :$1 2>/dev/null | grep LISTEN | head -1 | awk '{print $1}'
    fi
}

# Function to check if running on Mac
is_mac() {
    [[ "$OSTYPE" == "darwin"* ]] || [[ "$(uname)" == "Darwin" ]]
}

# Check if running from correct directory
if [[ ! -f "generate_frappe_docker_local.sh" ]]; then
    echo -e "${RED}❌ Error: Please run this script from the Docker-Local directory${NC}"
    echo -e "${YELLOW}💡 Change to the Docker-Local directory first:${NC}"
    echo "cd Docker-Local"
    exit 1
fi

# For local development only
ENVIRONMENT="local"
echo -e "${YELLOW}🏠 Local Development Environment (Mac Optimized)${NC}"

if is_mac; then
    echo -e "${BLUE}🍎 Detected macOS${NC}"
    echo ""
    echo -e "${YELLOW}Mac-specific notes:${NC}"
    echo "• Port 80 is often used by macOS system services"
    echo "• We'll use port 8081 by default for better compatibility"
    echo "• Localhost domains (.localhost) work great on Mac"
    echo ""
fi

echo -e "${YELLOW}Checking port availability...${NC}"

# Check port status for local development (HTTP only)
PORT_80_USED=false
PORT_8080_USED=false

if is_port_in_use 80; then
    PORT_80_USED=true
    PROCESS_80=$(get_process_on_port 80)
    echo -e "${RED}❌ Port 80 is in use by: $PROCESS_80${NC}"
    
    if is_mac; then
        echo -e "${YELLOW}💡 This is common on macOS - system services often use port 80${NC}"
        echo -e "${YELLOW}💡 We'll use port 8081 for better compatibility${NC}"
    fi
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

# Initialize variables
USE_STANDARD_PORTS=false
USE_LOCALHOST=false
HTTP_PORT=8081

# Determine Traefik configuration based on local port availability and Mac considerations
if [[ "$PORT_80_USED" == true ]] || is_mac; then
    echo ""
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    if is_mac; then
        echo -e "${YELLOW}Mac environment detected - using optimized configuration${NC}"
    else
        echo -e "${YELLOW}Local environment with port conflicts detected${NC}"
    fi
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    
    if is_mac; then
        echo "Mac-optimized options:"
        echo "1) Use port 8081 with localhost domains (RECOMMENDED for Mac)"
        echo "2) Try to free port 80 (may require system changes)"
        echo "3) Use custom port (you specify)"
        echo ""
        read -p "Choose an option (1-3): " OPTION
        
        case $OPTION in
            1)
                USE_STANDARD_PORTS=false
                USE_LOCALHOST=true
                HTTP_PORT=8081
                echo -e "${GREEN}✅ Using Mac-optimized setup: port 8081 with localhost domains${NC}"
                ;;
            2)
                echo ""
                echo -e "${YELLOW}Attempting to free port 80...${NC}"
                echo -e "${YELLOW}Note: This may require system-level changes on macOS${NC}"
                
                # Check for common Mac services using port 80
                if command -v sudo >/dev/null 2>&1; then
                    echo "Checking for services using port 80..."
                    sudo lsof -i :80 2>/dev/null | grep LISTEN || echo "No services found on port 80"
                fi
                
                echo ""
                echo "To free port 80 on Mac, you may need to:"
                echo "• Stop Apache: sudo apachectl stop"
                echo "• Stop Nginx: sudo brew services stop nginx"
                echo "• Check Activity Monitor for other services"
                echo ""
                read -p "Press Enter to continue with port 8081 setup..."
                
                USE_STANDARD_PORTS=false
                USE_LOCALHOST=true
                HTTP_PORT=8081
                echo -e "${GREEN}✅ Using port 8081 for better Mac compatibility${NC}"
                ;;
            3)
                read -p "Enter custom port number (e.g., 8081, 8082): " CUSTOM_PORT
                if [[ "$CUSTOM_PORT" =~ ^[0-9]+$ ]] && [ "$CUSTOM_PORT" -gt 1024 ] && [ "$CUSTOM_PORT" -lt 65536 ]; then
                    USE_STANDARD_PORTS=false
                    HTTP_PORT=$CUSTOM_PORT
                    echo -e "${GREEN}✅ Using custom port: $CUSTOM_PORT${NC}"
                else
                    echo -e "${RED}❌ Invalid port number. Using default port 8081${NC}"
                    USE_STANDARD_PORTS=false
                    HTTP_PORT=8081
                fi
                ;;
        esac
    else
        # Non-Mac logic (original)
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
                    if command -v systemctl >/dev/null 2>&1; then
                        sudo systemctl stop nginx
                        sudo systemctl disable nginx
                    else
                        echo -e "${YELLOW}⚠️  systemctl not available (Mac detected)${NC}"
                        echo -e "${YELLOW}💡 Try: sudo apachectl stop (if Apache)${NC}"
                    fi
                    echo -e "${GREEN}✅ Service stopped${NC}"
                elif [[ "$PROCESS_80" == "apache2" ]]; then
                    if command -v systemctl >/dev/null 2>&1; then
                        sudo systemctl stop apache2
                        sudo systemctl disable apache2
                    else
                        echo -e "${YELLOW}⚠️  systemctl not available (Mac detected)${NC}"
                        echo -e "${YELLOW}💡 Try: sudo apachectl stop (if Apache)${NC}"
                    fi
                    echo -e "${GREEN}✅ Service stopped${NC}"
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
    fi
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
    # Localhost-only configuration (Mac optimized)
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
    
    if [[ "$USE_LOCALHOST" == true ]]; then
        echo -e "${BLUE}Configuration:${NC}"
        echo "• HTTP Port: 8081"
        echo "• Dashboard: http://localhost:8080"
        echo "• Use domains like: mysite.localhost"
        echo ""
        echo -e "${YELLOW}Mac-optimized setup:${NC}"
        echo "• Domain: yoursite.localhost"
        echo "• Access your site at: http://yoursite.localhost:8081"
        echo "• .localhost domains work great on macOS"
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
    
    if is_mac; then
        echo ""
        echo -e "${BLUE}🍎 Mac-specific benefits:${NC}"
        echo "• .localhost domains work natively on macOS"
        echo "• No need to modify /etc/hosts file"
        echo "• Better port conflict handling"
        echo "• Optimized for Docker Desktop on Mac"
    fi
    
    echo ""
    
    # Save configuration for local development
    cat > .traefik-local-config << EOF
TRAEFIK_HTTP_PORT=${HTTP_PORT:-80}
USE_LOCALHOST=${USE_LOCALHOST:-false}
EOF
    
    echo -e "${GREEN}Configuration saved to .traefik-local-config${NC}"
    
    if is_mac; then
        echo ""
        echo -e "${YELLOW}🚀 Next steps for Mac users:${NC}"
        echo "1. Run: sudo ./generate_frappe_docker_local.sh"
        echo "2. Use domain: yoursite.localhost"
        echo "3. Access at: http://yoursite.localhost:8081"
        echo "4. Manage with: sudo ./docker-manager-local.sh"
    fi
    
else
    echo ""
    echo -e "${RED}❌ Failed to start Traefik${NC}"
    echo "Check the logs with: docker compose -f traefik-docker-compose.yml logs"
    
    if is_mac; then
        echo ""
        echo -e "${YELLOW}Mac troubleshooting tips:${NC}"
        echo "• Ensure Docker Desktop is running"
        echo "• Check Docker Desktop resources (CPU/Memory)"
        echo "• Restart Docker Desktop if needed"
        echo "• Check port availability: lsof -i :8081"
    fi
    
    exit 1
fi
