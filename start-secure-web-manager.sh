#!/bin/bash

# Secure Web Docker Manager Startup Script
# Enhanced security for production VPS environments

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Security Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$SCRIPT_DIR/web-docker-manager-env"
LOG_FILE="$SCRIPT_DIR/docker-manager.log"
CREDENTIALS_FILE="$SCRIPT_DIR/.admin_credentials"

echo -e "${BLUE}🔒 SECURE WEB DOCKER MANAGER${NC}"
echo -e "${BLUE}================================${NC}"
echo ""

# Check if running as root (not recommended)
if [[ $EUID -eq 0 ]]; then
    echo -e "${RED}⚠️  WARNING: Running as root is not recommended for security!${NC}"
    echo -e "${YELLOW}   Consider creating a dedicated user for this application.${NC}"
    echo ""
fi

# Check if virtual environment exists
if [[ ! -d "$VENV_DIR" ]]; then
    echo -e "${RED}❌ Virtual environment not found.${NC}"
    echo -e "${YELLOW}📦 Please run install-web-manager.sh first.${NC}"
    exit 1
fi

# Activate virtual environment
echo -e "${CYAN}🔧 Activating virtual environment...${NC}"
source "$VENV_DIR/bin/activate"

# Check if secure manager exists
if [[ ! -f "$SCRIPT_DIR/secure-web-docker-manager.py" ]]; then
    echo -e "${RED}❌ Secure web manager not found!${NC}"
    echo -e "${YELLOW}📁 Expected: $SCRIPT_DIR/secure-web-docker-manager.py${NC}"
    exit 1
fi

# Security checks
echo -e "${PURPLE}🔍 Performing security checks...${NC}"

# Check file permissions
echo -e "${CYAN}   📋 Checking file permissions...${NC}"
chmod 600 "$SCRIPT_DIR/secure-web-docker-manager.py" 2>/dev/null || true
chmod 600 "$CREDENTIALS_FILE" 2>/dev/null || true
chmod 644 "$SCRIPT_DIR/templates/"*.html 2>/dev/null || true

# Check for existing credentials
if [[ -f "$CREDENTIALS_FILE" ]]; then
    echo -e "${GREEN}   ✅ Admin credentials file found${NC}"
    echo -e "${YELLOW}   📁 Location: $CREDENTIALS_FILE${NC}"
else
    echo -e "${YELLOW}   ⚠️  Admin credentials will be generated on first run${NC}"
fi

# Check Docker access
echo -e "${CYAN}   🐳 Checking Docker access...${NC}"
if ! sudo docker ps >/dev/null 2>&1; then
    echo -e "${RED}   ❌ Cannot access Docker. Please check Docker installation and permissions.${NC}"
    exit 1
fi
echo -e "${GREEN}   ✅ Docker access confirmed${NC}"

# Check network security
echo -e "${CYAN}   🌐 Checking network configuration...${NC}"
if netstat -tuln | grep -q ":5000 "; then
    echo -e "${YELLOW}   ⚠️  Port 5000 is already in use!${NC}"
    echo -e "${YELLOW}   🔧 The application may fail to start or use a different port.${NC}"
fi

# Security recommendations
echo ""
echo -e "${PURPLE}🔒 SECURITY RECOMMENDATIONS:${NC}"
echo -e "${CYAN}   1. 🔥 Configure firewall to restrict access to port 5000${NC}"
echo -e "${CYAN}   2. 🌐 Use reverse proxy (nginx) with SSL/HTTPS${NC}"
echo -e "${CYAN}   3. 📊 Monitor access logs regularly${NC}"
echo -e "${CYAN}   4. 🔄 Change default admin password after first login${NC}"
echo -e "${CYAN}   5. 🏠 Restrict access to trusted IP addresses only${NC}"
echo ""

# Firewall check and recommendation
if command -v ufw >/dev/null 2>&1; then
    if ufw status | grep -q "Status: active"; then
        echo -e "${GREEN}✅ UFW firewall is active${NC}"
    else
        echo -e "${YELLOW}⚠️  UFW firewall is not active. Consider enabling it:${NC}"
        echo -e "${CYAN}   sudo ufw enable${NC}"
        echo -e "${CYAN}   sudo ufw allow from YOUR_IP to any port 5000${NC}"
    fi
else
    echo -e "${YELLOW}⚠️  UFW not found. Consider installing a firewall.${NC}"
fi

echo ""

# Final confirmation
echo -e "${YELLOW}🚨 SECURITY NOTICE:${NC}"
echo -e "${RED}   This web interface provides FULL DOCKER CONTROL${NC}"
echo -e "${RED}   Ensure only authorized users have access!${NC}"
echo ""

read -p "$(echo -e ${CYAN}🔐 Start Secure Web Docker Manager? [y/N]: ${NC})" -n 1 -r
echo ""

if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo -e "${YELLOW}🛑 Startup cancelled by user.${NC}"
    exit 0
fi

echo ""
echo -e "${GREEN}🚀 Starting Secure Web Docker Manager...${NC}"
echo -e "${BLUE}📍 Access URL: http://localhost:5000${NC}"
echo -e "${PURPLE}🔐 Authentication required for access${NC}"
echo -e "${CYAN}📋 Logs: $LOG_FILE${NC}"
echo ""

# Start the secure application
cd "$SCRIPT_DIR"
python3 secure-web-docker-manager.py

# Cleanup on exit
echo ""
echo -e "${YELLOW}🛑 Secure Web Docker Manager stopped.${NC}"
echo -e "${CYAN}📋 Check logs for any issues: $LOG_FILE${NC}"
