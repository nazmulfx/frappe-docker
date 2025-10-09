#!/bin/bash

# =====================================================================
# Web Docker Manager - Simple Setup (No SSL/Traefik Complexity)
# =====================================================================
# Access via: http://YOUR_SERVER_IP:5000
# =====================================================================

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

print_success() { echo -e "${GREEN}✅ $1${NC}"; }
print_error() { echo -e "${RED}❌ $1${NC}"; }
print_warning() { echo -e "${YELLOW}⚠️  $1${NC}"; }
print_info() { echo -e "${CYAN}💡 $1${NC}"; }

echo -e "${BLUE}╔════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║  🚀 Web Docker Manager - Simple Setup         ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════╝${NC}"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    print_error "Please run as root or with sudo"
    exit 1
fi

# Get configuration
read -s -p "Enter MySQL root password: " MYSQL_PASS
echo ""
read -s -p "Enter Web Manager admin password (min 8 chars): " ADMIN_PASS
echo ""

if [ -z "$MYSQL_PASS" ] || [ ${#ADMIN_PASS} -lt 8 ]; then
    print_error "Invalid passwords"
    exit 1
fi

# Setup MySQL database
print_info "Setting up MySQL database..."
mysql -u root -p"${MYSQL_PASS}" <<EOF
CREATE DATABASE IF NOT EXISTS docker_manager CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER IF NOT EXISTS 'docker_mgr'@'localhost' IDENTIFIED BY '${MYSQL_PASS}';
GRANT ALL PRIVILEGES ON docker_manager.* TO 'docker_mgr'@'localhost';
FLUSH PRIVILEGES;
EOF

if [ $? -eq 0 ]; then
    print_success "MySQL database configured"
else
    print_error "Failed to configure MySQL"
    exit 1
fi

# Setup Web Manager
cd "$SCRIPT_DIR"

# Create config
cat > .docker-manager-config <<EOF
DB_HOST="localhost"
DB_NAME="docker_manager"
DB_USER="docker_mgr"
DB_PASS="${MYSQL_PASS}"
EOF
chmod 600 .docker-manager-config

# Find or create venv
VENV_DIR=""
if [ -d "web-docker-manager-env" ] && [ -f "web-docker-manager-env/bin/activate" ]; then
    VENV_DIR="web-docker-manager-env"
    print_info "Using existing virtual environment"
elif [ -d "../web-docker-manager-env" ] && [ -f "../web-docker-manager-env/bin/activate" ]; then
    VENV_DIR="../web-docker-manager-env"
    print_info "Using virtual environment from parent directory"
else
    print_info "Creating virtual environment..."
    python3 -m venv web-docker-manager-env
    VENV_DIR="web-docker-manager-env"
    print_success "Virtual environment created"
fi

# Activate and install
source "$VENV_DIR/bin/activate"
pip install --upgrade pip
pip install flask>=2.3.0 flask-sqlalchemy>=3.1.0 pymysql>=1.1.0 pyotp>=2.9.0 qrcode>=8.2.0 pillow>=11.0.0 werkzeug>=2.3.0 paramiko>=2.12.0

# Initialize database
export DB_HOST=localhost
export DB_NAME=docker_manager
export DB_USER=docker_mgr
export DB_PASS="${MYSQL_PASS}"

python3 <<PYEOF
import sys, os
sys.path.append('.')
os.environ['DB_HOST'] = 'localhost'
os.environ['DB_NAME'] = 'docker_manager'
os.environ['DB_USER'] = 'docker_mgr'
os.environ['DB_PASS'] = '${MYSQL_PASS}'

from app import app, db
from models import User

with app.app_context():
    db.create_all()
    admin = User.query.filter_by(username='admin').first()
    if not admin:
        admin = User(username='admin', email='admin@localhost', is_admin=True, is_active=True, totp_enabled=False)
        admin.set_password('${ADMIN_PASS}')
        admin.generate_totp_secret()
        db.session.add(admin)
        db.session.commit()
        print("✅ Admin user created")
    else:
        admin.set_password('${ADMIN_PASS}')
        db.session.commit()
        print("✅ Admin password updated")
PYEOF

deactivate

# Determine venv absolute path
VENV_PATH=$(cd "$VENV_DIR" && pwd)

# Create systemd service
print_info "Creating systemd service..."
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
Environment="DB_PASS=${MYSQL_PASS}"
ExecStart=${VENV_PATH}/bin/python ${SCRIPT_DIR}/app.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable web-docker-manager.service
systemctl restart web-docker-manager.service

sleep 3

# Open firewall
print_info "Opening port 5000..."
ufw allow 5000/tcp 2>/dev/null || true

echo ""
echo -e "${GREEN}╔════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║  ✅ Installation Complete!                     ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${CYAN}📋 Access Information:${NC}"
echo "  URL: http://$(hostname -I | awk '{print $1}'):5000"
echo "  Username: admin"
echo "  Password: ${ADMIN_PASS}"
echo ""
echo -e "${CYAN}🔧 Service Management:${NC}"
echo "  Status:  sudo systemctl status web-docker-manager"
echo "  Logs:    sudo journalctl -u web-docker-manager -f"
echo "  Restart: sudo systemctl restart web-docker-manager"
echo ""
echo -e "${CYAN}💡 Notes:${NC}"
echo "  • Access via IP:PORT (no domain needed)"
echo "  • Works alongside your Traefik sites"
echo "  • Port 5000 is now open in firewall"
echo "  • For SSH tunnel: ssh -L 5000:localhost:5000 ubuntu@SERVER_IP"
echo ""
print_success "Web Manager is ready!"

