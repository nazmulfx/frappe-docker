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
    
    # Cloudflare option
    read -p "Do you want to use Cloudflare DNS challenge? (y/n) [n]: " USE_CLOUDFLARE
    USE_CLOUDFLARE="${USE_CLOUDFLARE:-n}"
    
    if [[ "$USE_CLOUDFLARE" =~ ^[Yy]$ ]]; then
        read -p "Enter Cloudflare API email: " CF_EMAIL
        read -s -p "Enter Cloudflare API key: " CF_API_KEY
        echo ""
    fi
    
    echo ""
    print_success "Configuration collected"
    echo "  Domain: $DOMAIN"
    echo "  Email: $EMAIL"
    echo "  Cloudflare: ${USE_CLOUDFLARE}"
    echo ""
}

# Install dependencies
install_dependencies() {
    print_step "Installing dependencies..."
    
    apt update
    apt install -y docker.io docker-compose mysql-server python3 python3-pip python3-venv curl net-tools
    
    systemctl enable docker
    systemctl start docker
    systemctl enable mysql
    systemctl start mysql
    
    print_success "Dependencies installed"
}

# Setup MySQL
setup_mysql() {
    print_step "Setting up MySQL database..."
    
    # Secure MySQL installation (basic)
    mysql -u root <<EOF
ALTER USER 'root'@'localhost' IDENTIFIED WITH mysql_native_password BY '${MYSQL_ROOT_PASS}';
CREATE DATABASE IF NOT EXISTS docker_manager CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER IF NOT EXISTS 'docker_mgr'@'localhost' IDENTIFIED BY '${MYSQL_ROOT_PASS}';
GRANT ALL PRIVILEGES ON docker_manager.* TO 'docker_mgr'@'localhost';
FLUSH PRIVILEGES;
EOF
    
    print_success "MySQL configured"
}

# Create Traefik network
create_network() {
    print_step "Creating Docker network..."
    
    docker network create traefik_proxy 2>/dev/null || print_info "Network already exists"
    
    print_success "Docker network ready"
}

# Setup Traefik
setup_traefik() {
    print_step "Setting up Traefik reverse proxy..."
    
    cd "$PROJECT_ROOT"
    
    # Create directories
    mkdir -p traefik-letsencrypt
    mkdir -p traefik-config/dynamic
    touch traefik-letsencrypt/acme.json
    chmod 600 traefik-letsencrypt/acme.json
    
    # Create Traefik compose file
    if [[ "$USE_CLOUDFLARE" =~ ^[Yy]$ ]]; then
        # Cloudflare DNS challenge
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
    environment:
      - CF_API_EMAIL=${CF_EMAIL}
      - CF_API_KEY=${CF_API_KEY}
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
      - --certificatesresolvers.letsencrypt.acme.email=${EMAIL}
      - --certificatesresolvers.letsencrypt.acme.storage=/letsencrypt/acme.json
      - --certificatesresolvers.letsencrypt.acme.dnschallenge.provider=cloudflare
      - --certificatesresolvers.letsencrypt.acme.dnschallenge.resolvers=1.1.1.1:53,8.8.8.8:53
      - --log.level=INFO
    networks:
      - traefik_proxy

networks:
  traefik_proxy:
    external: true
EOF
    else
        # HTTP challenge
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
      - --certificatesresolvers.letsencrypt.acme.email=${EMAIL}
      - --certificatesresolvers.letsencrypt.acme.storage=/letsencrypt/acme.json
      - --certificatesresolvers.letsencrypt.acme.httpchallenge.entrypoint=web
      - --log.level=INFO
    networks:
      - traefik_proxy

networks:
  traefik_proxy:
    external: true
EOF
    fi
    
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
        certResolver: letsencrypt
  services:
    docker_manager_svc:
      loadBalancer:
        servers:
          - url: "http://localhost:5000"
EOF
    
    # Start Traefik
    docker compose -f traefik-docker-compose.yml down 2>/dev/null || true
    docker compose -f traefik-docker-compose.yml up -d
    
    print_success "Traefik configured and started"
}

# Setup Web Manager
setup_webmanager() {
    print_step "Setting up Web Docker Manager..."
    
    cd "$SCRIPT_DIR"
    
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
    
    # Create virtual environment if it doesn't exist
    if [ ! -d "web-docker-manager-env" ]; then
        python3 -m venv web-docker-manager-env
    fi
    
    source web-docker-manager-env/bin/activate
    
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
    
    cat > /etc/systemd/system/web-docker-manager.service <<EOF
[Unit]
Description=Web Docker Manager
After=network.target mysql.service docker.service

[Service]
Type=simple
User=root
WorkingDirectory=${SCRIPT_DIR}
Environment="PATH=${SCRIPT_DIR}/web-docker-manager-env/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
Environment="DB_HOST=localhost"
Environment="DB_NAME=docker_manager"
Environment="DB_USER=docker_mgr"
Environment="DB_PASS=${MYSQL_ROOT_PASS}"
ExecStart=${SCRIPT_DIR}/web-docker-manager-env/bin/python ${SCRIPT_DIR}/app.py
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
}

# Run main function
main "$@"

