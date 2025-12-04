#!/bin/bash

# =====================================================================
# Web Docker Manager - VPS SSL Setup Script
# =====================================================================
# This script automates the deployment of Web Docker Manager on VPS with SSL
# Version: 1.0
# =====================================================================

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

print_header() {
    echo -e "${BLUE}╔════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║  🚀 Web Docker Manager VPS SSL Setup          ║${NC}"
    echo -e "${BLUE}╚════════════════════════════════════════════════╝${NC}"
    echo ""
}

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_info() {
    echo -e "${CYAN}💡 $1${NC}"
}

print_step() {
    echo -e "${PURPLE}🔧 $1${NC}"
}

# Check if running as root
check_root() {
    if [ "$EUID" -ne 0 ]; then 
        print_error "Please run as root or with sudo"
        exit 1
    fi
}

# Collect configuration
collect_config() {
    print_step "Configuration Setup"
    echo ""
    
    # Domain name
    read -p "Enter domain for Web Manager (e.g., manager.yourdomain.com): " DOMAIN
    if [ -z "$DOMAIN" ]; then
        print_error "Domain is required"
        exit 1
    fi
    
    # Email for Let's Encrypt
    read -p "Enter email for Let's Encrypt: " EMAIL
    if [ -z "$EMAIL" ]; then
        print_error "Email is required"
        exit 1
    fi
    
    # MySQL password
    read -s -p "Enter MySQL root password: " MYSQL_ROOT_PASS
    echo ""
    if [ -z "$MYSQL_ROOT_PASS" ]; then
        print_error "MySQL password is required"
        exit 1
    fi
    
    # Web Manager admin password
    read -s -p "Enter Web Manager admin password (min 8 chars): " ADMIN_PASSWORD
    echo ""
    if [ ${#ADMIN_PASSWORD} -lt 8 ]; then
        print_error "Admin password must be at least 8 characters"
        exit 1
    fi
    
    echo ""
    print_success "Configuration collected"
    echo "  Domain: $DOMAIN"
    echo "  Email: $EMAIL"
    echo "  SSL Method: HTTP Challenge (works with all DNS providers)"
    echo ""
}

# Install dependencies
install_dependencies() {
    print_step "Installing dependencies..."
    
    # Update package list
    apt update
    
    # Check if Docker is already installed
    if command -v docker &> /dev/null; then
        print_success "Docker is already installed"
        docker --version
    else
        print_info "Installing Docker..."
        # Install Docker using official method
        curl -fsSL https://get.docker.com -o get-docker.sh
        sh get-docker.sh
        rm get-docker.sh
        print_success "Docker installed"
    fi
    
    # Check if MySQL is already installed
    if command -v mysql &> /dev/null; then
        print_success "MySQL is already installed"
        mysql --version
        
        # Check if MySQL is running
        if systemctl is-active --quiet mysql; then
            print_success "MySQL is running"
        else
            print_warning "MySQL is installed but not running"
            
            # Check if frozen
            if [ -f "/etc/mysql/FROZEN" ]; then
                print_error "MySQL is FROZEN. Run: sudo rm /etc/mysql/FROZEN"
                read -p "Remove freeze and continue? (y/n): " REMOVE_FREEZE
                if [[ "$REMOVE_FREEZE" =~ ^[Yy]$ ]]; then
                    rm -f /etc/mysql/FROZEN
                    print_success "Freeze removed"
                else
                    print_error "Cannot continue without MySQL. Please fix MySQL first."
                    exit 1
                fi
            fi
            
            # Try to start MySQL
            print_info "Starting MySQL..."
            systemctl start mysql || {
                print_error "Failed to start MySQL. Check: sudo journalctl -xeu mysql.service"
                exit 1
            }
        fi
    else
        print_info "Installing MySQL..."
        apt install -y mysql-server
    fi
    
    # Install Python dependencies
    apt install -y python3 python3-pip python3-venv curl net-tools
    
    # Enable and start services
    systemctl enable docker
    systemctl start docker
    systemctl enable mysql
    
    print_success "Dependencies ready"
}

# Setup MySQL
setup_mysql() {
    print_step "Setting up MySQL database..."
    
    # Test MySQL connection and create database
    # Use -p flag with password
    mysql -u root -p"${MYSQL_ROOT_PASS}" <<EOF
CREATE DATABASE IF NOT EXISTS docker_manager CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER IF NOT EXISTS 'docker_mgr'@'localhost' IDENTIFIED BY '${MYSQL_ROOT_PASS}';
GRANT ALL PRIVILEGES ON docker_manager.* TO 'docker_mgr'@'localhost';
FLUSH PRIVILEGES;
EOF
    
    if [ $? -eq 0 ]; then
        print_success "MySQL database configured"
    else
        print_error "Failed to configure MySQL database"
        print_info "Please verify MySQL password is correct"
        exit 1
    fi
}

# Create Traefik network
create_network() {
    print_step "Creating Docker network..."
    
    docker network create traefik_proxy 2>/dev/null || print_info "Network already exists"
    
    print_success "Docker network ready"
}

# Setup Traefik
setup_traefik() {
    print_step "Setting up Traefik reverse proxy with HTTP Challenge..."
    
    cd "$PROJECT_ROOT"
    
    # Check if Traefik is already running
    if docker ps | grep -q traefik; then
        print_info "Traefik is already running"
        
        read -p "Do you want to reconfigure Traefik? (y/n) [n]: " RECONFIG_TRAEFIK
        RECONFIG_TRAEFIK="${RECONFIG_TRAEFIK:-n}"
        
        if [[ ! "$RECONFIG_TRAEFIK" =~ ^[Yy]$ ]]; then
            print_info "Skipping Traefik setup. Using existing Traefik configuration."
            # Just create/update the Web Manager routing
            mkdir -p traefik-config/dynamic
            cat > traefik-config/dynamic/docker-manager.yml <<EOF
http:
  routers:
    docker_manager:
      rule: "Host(\`${DOMAIN}\`)"
      entryPoints:
        - websecure
      service: docker_manager_svc
      tls:
        certResolver: myresolver
  services:
    docker_manager_svc:
      loadBalancer:
        servers:
          - url: "http://localhost:5000"
EOF
            print_success "Web Manager routing added to existing Traefik"
            return
        else
            print_warning "Stopping existing Traefik for reconfiguration..."
            
            # Backup existing dynamic config
            if [ -d "traefik-config/dynamic" ]; then
                print_info "Backing up existing routing configurations..."
                backup_dir="traefik-config-backup-$(date +%Y%m%d_%H%M%S)"
                mkdir -p "$backup_dir"
                cp -r traefik-config/dynamic "$backup_dir/"
                print_success "Backup created: $backup_dir"
            fi
            
            docker compose -f traefik-docker-compose.yml down 2>/dev/null || true
            docker stop traefik 2>/dev/null || true
            docker rm traefik 2>/dev/null || true
        fi
    fi
    
    # Create directories
    mkdir -p traefik-letsencrypt
    mkdir -p traefik-config/dynamic
    touch traefik-letsencrypt/acme.json
    chmod 600 traefik-letsencrypt/acme.json
    
    print_warning "⚠️  Important: Your existing site routing files are preserved in traefik-config/dynamic/"
    print_info "If sites are missing, check and restore from backup folder"
    
    # Create Traefik compose file with HTTP Challenge (works with all DNS providers)
    cat > traefik-docker-compose.yml <<EOF
version: '3.8'

services:
  traefik:
    image: traefik:v2.10
    container_name: traefik
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
      - "8080:8080"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - ./traefik-letsencrypt:/letsencrypt
      - ./traefik-config:/etc/traefik
    command:
      - --api.dashboard=true
      - --api.insecure=true
      - --providers.docker=true
      - --providers.docker.exposedbydefault=false
      - --providers.file.directory=/etc/traefik/dynamic
      - --providers.file.watch=true
      - --entrypoints.web.address=:80
      - --entrypoints.websecure.address=:443
      - --entrypoints.web.http.redirections.entrypoint.to=websecure
      - --entrypoints.web.http.redirections.entrypoint.scheme=https
      - --certificatesresolvers.myresolver.acme.email=${EMAIL}
      - --certificatesresolvers.myresolver.acme.storage=/letsencrypt/acme.json
      - --certificatesresolvers.myresolver.acme.httpchallenge=true
      - --certificatesresolvers.myresolver.acme.httpchallenge.entrypoint=web
      - --log.level=INFO
    networks:
      - traefik_proxy

networks:
  traefik_proxy:
    external: true
EOF
    
    # Get host IP address
    HOST_IP=$(hostname -I | awk '{print $1}')
    
    # Create Web Manager routing
    cat > traefik-config/dynamic/docker-manager.yml <<EOF
http:
  routers:
    docker_manager:
      rule: "Host(\`${DOMAIN}\`)"
      entryPoints:
        - websecure
      service: docker_manager_svc
      tls:
        certResolver: myresolver
  services:
    docker_manager_svc:
      loadBalancer:
        servers:
          - url: "http://${HOST_IP}:5000"
EOF
    
    print_info "Web Manager routing configured to connect to: http://${HOST_IP}:5000"
    
    # Start Traefik
    print_info "Starting Traefik..."
    docker compose -f traefik-docker-compose.yml up -d
    
    sleep 3
    
    # Verify Traefik is running
    if docker ps | grep -q traefik; then
        print_success "Traefik configured and started successfully"
    else
        print_error "Traefik failed to start. Check: docker logs traefik"
        exit 1
    fi
}

# Setup Web Manager
setup_webmanager() {
    print_step "Setting up Web Docker Manager..."
    
    cd "$SCRIPT_DIR"
    
    # Check if service already exists
    if systemctl list-units --full -all | grep -q web-docker-manager.service; then
        print_info "Web Docker Manager service already exists"
        
        if systemctl is-active --quiet web-docker-manager; then
            print_warning "Stopping existing Web Docker Manager service..."
            systemctl stop web-docker-manager
        fi
    fi
    
    # Create config file
    cat > .docker-manager-config <<EOF
DB_HOST="localhost"
DB_NAME="docker_manager"
DB_USER="docker_mgr"
DB_PASS="${MYSQL_ROOT_PASS}"
EOF
    chmod 600 .docker-manager-config
    
    # Run installation
    export DB_HOST=localhost
    export DB_NAME=docker_manager
    export DB_USER=docker_mgr
    export DB_PASS="${MYSQL_ROOT_PASS}"
    
    # Check for virtual environment in current or parent directory
    VENV_DIR=""
    
    # Check current directory
    if [ -d "${SCRIPT_DIR}/web-docker-manager-env" ] && [ -f "${SCRIPT_DIR}/web-docker-manager-env/bin/activate" ]; then
        VENV_DIR="${SCRIPT_DIR}/web-docker-manager-env"
        print_info "Found valid virtual environment in current directory"
    # Check parent directory
    elif [ -d "${PROJECT_ROOT}/web-docker-manager-env" ] && [ -f "${PROJECT_ROOT}/web-docker-manager-env/bin/activate" ]; then
        VENV_DIR="${PROJECT_ROOT}/web-docker-manager-env"
        print_info "Found valid virtual environment in parent directory"
    # Found corrupted venv in current directory
    elif [ -d "${SCRIPT_DIR}/web-docker-manager-env" ]; then
        print_warning "Found corrupted virtual environment. Removing..."
        rm -rf "${SCRIPT_DIR}/web-docker-manager-env"
        print_info "Creating new Python virtual environment..."
        python3 -m venv "${SCRIPT_DIR}/web-docker-manager-env"
        VENV_DIR="${SCRIPT_DIR}/web-docker-manager-env"
        
        if [ ! -f "$VENV_DIR/bin/activate" ]; then
            print_error "Failed to create virtual environment"
            print_info "Tried to create at: $VENV_DIR"
            exit 1
        fi
        print_success "Virtual environment created at: $VENV_DIR"
    # No venv exists, create new one
    else
        print_info "Creating Python virtual environment in current directory..."
        python3 -m venv "${SCRIPT_DIR}/web-docker-manager-env"
        VENV_DIR="${SCRIPT_DIR}/web-docker-manager-env"
        
        if [ ! -f "$VENV_DIR/bin/activate" ]; then
            print_error "Failed to create virtual environment"
            print_info "Tried to create at: $VENV_DIR"
            exit 1
        fi
        print_success "Virtual environment created at: $VENV_DIR"
    fi
    
    print_info "Activating virtual environment from: $VENV_DIR"
    
    source "$VENV_DIR/bin/activate"
    
    if [ $? -ne 0 ]; then
        print_error "Failed to activate virtual environment"
        exit 1
    fi
    print_success "Virtual environment activated"
    
    # Install packages
    pip install --upgrade pip
    pip install flask>=2.3.0 flask-sqlalchemy>=3.1.0 pymysql>=1.1.0 pyotp>=2.9.0 qrcode>=8.2.0 pillow>=11.0.0 werkzeug>=2.3.0 paramiko>=2.12.0
    
    # Initialize database
    python3 <<PYEOF
import sys
import os
sys.path.append('.')
os.environ['DB_HOST'] = 'localhost'
os.environ['DB_NAME'] = 'docker_manager'
os.environ['DB_USER'] = 'docker_mgr'
os.environ['DB_PASS'] = '${MYSQL_ROOT_PASS}'

from app import app, db
from models import User

with app.app_context():
    db.create_all()
    admin = User.query.filter_by(username='admin').first()
    if not admin:
        admin = User(username='admin', email='admin@localhost', is_admin=True, is_active=True, totp_enabled=False)
        admin.set_password('${ADMIN_PASSWORD}')
        admin.generate_totp_secret()
        db.session.add(admin)
        db.session.commit()
        print("✅ Admin user created")
    else:
        admin.set_password('${ADMIN_PASSWORD}')
        db.session.commit()
        print("✅ Admin password updated")
PYEOF
    
    deactivate
    
    print_success "Web Manager configured"
}

# Create systemd service
create_service() {
    print_step "Creating systemd service..."
    
    # Determine venv path (current or parent directory)
    if [ -d "${SCRIPT_DIR}/web-docker-manager-env" ]; then
        VENV_PATH="${SCRIPT_DIR}/web-docker-manager-env"
    elif [ -d "${SCRIPT_DIR}/../web-docker-manager-env" ]; then
        VENV_PATH="${SCRIPT_DIR}/../web-docker-manager-env"
    else
        print_error "Virtual environment not found"
        exit 1
    fi
    
    print_info "Using virtual environment: $VENV_PATH"
    
    cat > /etc/systemd/system/web-docker-manager.service <<EOF
[Unit]
Description=Web Docker Manager
After=network.target mysql.service docker.service

[Service]
Type=simple
User=root
WorkingDirectory=${SCRIPT_DIR}
Environment="PATH=${VENV_PATH}/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
Environment="DB_HOST=localhost"
Environment="DB_NAME=docker_manager"
Environment="DB_USER=docker_mgr"
Environment="DB_PASS=${MYSQL_ROOT_PASS}"
ExecStart=${VENV_PATH}/bin/python ${SCRIPT_DIR}/app.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    systemctl enable web-docker-manager.service
    systemctl start web-docker-manager.service
    
    print_success "Systemd service created and started"
}

# Configure firewall
setup_firewall() {
    print_step "Configuring firewall..."
    
    # Install ufw if not installed
    apt install -y ufw
    
    # Configure firewall
    ufw allow 22/tcp
    ufw allow 80/tcp
    ufw allow 443/tcp
    ufw --force enable
    
    print_success "Firewall configured"
}

# Show final information
show_info() {
    echo ""
    echo -e "${GREEN}╔════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║  ✅ Installation Complete!                     ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${CYAN}📋 Access Information:${NC}"
    echo "  URL: https://${DOMAIN}"
    echo "  Username: admin"
    echo "  Password: ${ADMIN_PASSWORD}"
    echo ""
    echo -e "${CYAN}🔧 Service Management:${NC}"
    echo "  Status:  sudo systemctl status web-docker-manager"
    echo "  Stop:    sudo systemctl stop web-docker-manager"
    echo "  Start:   sudo systemctl start web-docker-manager"
    echo "  Restart: sudo systemctl restart web-docker-manager"
    echo "  Logs:    sudo journalctl -u web-docker-manager -f"
    echo ""
    echo -e "${CYAN}📊 Traefik Dashboard:${NC}"
    echo "  URL: http://$(hostname -I | awk '{print $1}'):8080"
    echo ""
    echo -e "${CYAN}🔍 Verification:${NC}"
    echo "  Check service: sudo systemctl status web-docker-manager"
    echo "  Check Traefik: docker logs traefik"
    echo "  Test HTTPS: curl -I https://${DOMAIN}"
    echo ""
    
    print_info "Waiting 30 seconds for SSL certificate generation..."
    sleep 30
    echo ""
    
    print_step "Testing HTTPS access..."
    if curl -I -s https://${DOMAIN} | grep -q "HTTP"; then
        print_success "HTTPS is accessible!"
    else
        print_warning "HTTPS not accessible yet. This may take a few minutes."
        print_info "Check: sudo journalctl -u web-docker-manager -f"
        print_info "Check: docker logs traefik"
    fi
    
    echo ""
    print_success "Setup complete! Access your Web Manager at: https://${DOMAIN}"
}

allow_port() {
    echo ""
    echo -e "${GREEN}╔════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║   Allowing 5000 Port for docker-manager        ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════════════╝${NC}"
    echo ""

    # Allow port 5000 in UFW
    sudo ufw allow 5000/tcp
    echo -e "${GREEN}✔ UFW rule added: Allow port 5000 (TCP)${NC}"
}


# Main installation flow
main() {
    print_header
    
    # Check root
    check_root
    
    # Collect configuration
    collect_config
    
    # Install dependencies
    install_dependencies
    
    # Setup MySQL
    setup_mysql
    
    # Create network
    create_network
    
    # Setup Traefik
    setup_traefik
    
    # Setup Web Manager
    setup_webmanager
    
    # Create systemd service
    create_service
    
    # Setup firewall
    setup_firewall
    
    # Show final info
    show_info

    # Allow docker Manager 5000 Port
    allow_port
}

# Run main function
main "$@"

