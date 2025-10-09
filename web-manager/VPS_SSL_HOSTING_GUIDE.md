# Web Docker Manager - VPS SSL Hosting Guide

Complete guide to host the Web Docker Manager on a VPS with SSL/HTTPS support.

## 📋 Prerequisites

### Server Requirements
- **VPS/Cloud Server** (Ubuntu 20.04/22.04, Debian 11+, CentOS 8+)
- **Minimum**: 2GB RAM, 2 CPU cores, 20GB disk
- **Public IP Address**
- **Domain name** pointing to your server
- **Root or sudo access**

### Software Requirements
- Docker and Docker Compose installed
- Python 3.8+ installed
- MySQL/MariaDB server installed
- Traefik reverse proxy (for SSL)

### Ports Required
- **80** (HTTP) - For Let's Encrypt validation
- **443** (HTTPS) - For SSL traffic
- **5000** (Internal) - Web Manager app (not exposed publicly)

## 🚀 Quick Setup (Step-by-Step)

### Step 1: Setup Traefik Reverse Proxy

First, ensure Traefik is running with SSL support:

```bash
# Navigate to your project directory

# Check if Traefik is running
docker ps | grep traefik

# If not running, start Traefik
docker compose -f traefik-docker-compose.yml up -d
```

### Step 2: Configure Domain for Web Manager

Edit the Traefik dynamic configuration:

```bash
# Edit the docker-manager configuration
nano traefik-config/dynamic/docker-manager.yml
```

Update with your domain:

```yaml
http:
  routers:
    docker_manager:
      rule: "Host(`manager.yourdomain.com`)"  # Change this to your domain
      entryPoints:
        - websecure
      service: docker_manager_svc
      tls:
        certResolver: letsencrypt
  services:
    docker_manager_svc:
      loadBalancer:
        servers:
          - url: "http://localhost:5000"  # Or use host.docker.internal:5000
```

### Step 3: Update DNS Records

Add an A record in your DNS provider:

```
Type: A
Name: manager (or your subdomain)
Value: YOUR_SERVER_IP
TTL: Auto or 3600
```

**Example:**
- Domain: `manager.yourdomain.com`
- Points to: `123.45.67.89` (your VPS IP)

### Step 4: Install and Configure Web Manager

```bash
cd web-manager

# Run the installation
./docker-manager.sh install
```

**Follow the prompts:**
1. Enter MySQL host: `localhost` or `127.0.0.1`
2. Enter MySQL username: `root`
3. Enter MySQL password: (your MySQL root password)
4. Set admin password for web interface

### Step 5: Create Systemd Service (Auto-start)

Create a service file to run Web Manager automatically:

```bash
sudo nano /etc/systemd/system/web-docker-manager.service
```

Add this content:

```ini
[Unit]
Description=Web Docker Manager
After=network.target mysql.service docker.service

[Service]
Type=simple
User=root
WorkingDirectory=/var/www/html/docker2 15/web-manager
Environment="PATH=/var/www/html/docker2 15/web-manager/web-docker-manager-env/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
Environment="DB_HOST=localhost"
Environment="DB_NAME=docker_manager"
Environment="DB_USER=root"
Environment="DB_PASS=YOUR_MYSQL_PASSWORD"
ExecStart=/var/www/html/docker2 15/web-manager/web-docker-manager-env/bin/python /var/www/html/docker2 15/web-manager/app.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

**Important:** Replace `YOUR_MYSQL_PASSWORD` with your actual MySQL password.

Enable and start the service:

```bash
# Reload systemd
sudo systemctl daemon-reload

# Enable service to start on boot
sudo systemctl enable web-docker-manager.service

# Start the service
sudo systemctl start web-docker-manager.service

# Check status
sudo systemctl status web-docker-manager.service
```

### Step 6: Reload Traefik

Reload Traefik to pick up the new configuration:

```bash
# Restart Traefik to apply changes
docker restart traefik

# Wait 30 seconds for SSL certificate generation
sleep 30

# Check Traefik logs
docker logs traefik --tail 50
```

### Step 7: Test Access

```bash
# Test HTTP redirect (should redirect to HTTPS)
curl -I http://manager.yourdomain.com

# Test HTTPS access
curl -I https://manager.yourdomain.com

# Check SSL certificate
curl -vI https://manager.yourdomain.com 2>&1 | grep -i "SSL certificate"
```

### Step 8: Access Web Manager

Open your browser and go to:
```
https://manager.yourdomain.com
```

**Login with:**
- Username: `admin`
- Password: (the password you set during installation)

## 🔧 Alternative Setup Methods

### Method 1: Using Docker Container (Recommended)

Create a Dockerfile for the web-manager:

```bash
cd web-manager
nano Dockerfile
```

```dockerfile
FROM python:3.10-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    docker.io \
    mysql-client \
    sudo \
    && rm -rf /var/lib/apt/lists/*

# Create app directory
WORKDIR /app

# Copy application files
COPY . /app/

# Install Python dependencies
RUN pip install --no-cache-dir \
    flask>=2.3.0 \
    flask-sqlalchemy>=3.1.0 \
    pymysql>=1.1.0 \
    pyotp>=2.9.0 \
    qrcode>=8.2.0 \
    pillow>=11.0.0 \
    werkzeug>=2.3.0 \
    paramiko>=2.12.0

# Expose port
EXPOSE 5000

# Set environment variables
ENV PYTHONUNBUFFERED=1

# Run the application
CMD ["python", "app.py"]
```

Create docker-compose.yml:

```bash
nano docker-compose-webmanager.yml
```

```yaml
version: '3.8'

services:
  web-manager:
    build: .
    container_name: web-docker-manager
    restart: unless-stopped
    environment:
      - DB_HOST=host.docker.internal
      - DB_NAME=docker_manager
      - DB_USER=root
      - DB_PASS=${MYSQL_PASSWORD}
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
    ports:
      - "5000:5000"
    networks:
      - traefik_proxy
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.webmanager.rule=Host(`manager.yourdomain.com`)"
      - "traefik.http.routers.webmanager.entrypoints=websecure"
      - "traefik.http.routers.webmanager.tls.certresolver=letsencrypt"
      - "traefik.http.services.webmanager.loadbalancer.server.port=5000"

networks:
  traefik_proxy:
    external: true
```

Deploy:

```bash
# Create .env file
echo "MYSQL_PASSWORD=your_mysql_password" > .env

# Build and run
docker compose -f docker-compose-webmanager.yml up -d --build
```

### Method 2: Using Nginx Reverse Proxy

If you prefer Nginx over Traefik:

```bash
# Install Nginx and Certbot
sudo apt update
sudo apt install -y nginx certbot python3-certbot-nginx

# Create Nginx configuration
sudo nano /etc/nginx/sites-available/docker-manager
```

Add this configuration:

```nginx
server {
    listen 80;
    server_name manager.yourdomain.com;

    location / {
        proxy_pass http://localhost:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # WebSocket support
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
```

Enable and get SSL:

```bash
# Enable site
sudo ln -s /etc/nginx/sites-available/docker-manager /etc/nginx/sites-enabled/

# Test configuration
sudo nginx -t

# Reload Nginx
sudo systemctl reload nginx

# Get SSL certificate
sudo certbot --nginx -d manager.yourdomain.com

# Test auto-renewal
sudo certbot renew --dry-run
```

## 🔐 Security Configuration

### 1. Update Firewall

```bash
# Allow necessary ports
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw allow 22/tcp  # SSH

# Enable firewall
sudo ufw enable

# Check status
sudo ufw status
```

### 2. Secure MySQL

```bash
# Run MySQL secure installation
sudo mysql_secure_installation

# Create dedicated database user
sudo mysql -u root -p
```

```sql
CREATE DATABASE docker_manager CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'docker_mgr'@'localhost' IDENTIFIED BY 'strong_password_here';
GRANT ALL PRIVILEGES ON docker_manager.* TO 'docker_mgr'@'localhost';
FLUSH PRIVILEGES;
EXIT;
```

Update `web-manager/config.py`:

```python
DB_USER = os.environ.get('DB_USER') or 'docker_mgr'
DB_PASS = os.environ.get('DB_PASS') or 'strong_password_here'
```

### 3. Enable HTTPS Enforcement

Update `web-manager/config.py`:

```python
REQUIRE_HTTPS = True  # Set to True for production
```

### 4. Configure IP Whitelist (Optional)

Restrict access to specific IPs:

```python
ALLOWED_IPS = ['123.45.67.89', '98.76.54.32']  # Your IP addresses
```

Or allow all:

```python
ALLOWED_IPS = []  # Allow all IPs
```

### 5. Change Secret Key

```bash
# Generate a strong secret key
python3 -c "import secrets; print(secrets.token_hex(32))"
```

Update in `config.py`:

```python
SECRET_KEY = os.environ.get('SECRET_KEY') or 'your_generated_secret_key_here'
```

## 🔧 Traefik SSL Configuration

### Using HTTP Challenge (Any DNS Provider)

Your `traefik-docker-compose.yml` should have:

```yaml
command:
  - --certificatesresolvers.letsencrypt.acme.email=your-email@example.com
  - --certificatesresolvers.letsencrypt.acme.storage=/letsencrypt/acme.json
  - --certificatesresolvers.letsencrypt.acme.httpchallenge.entrypoint=web
```

### Using Cloudflare DNS Challenge

For Cloudflare, update `traefik-docker-compose.yml`:

```yaml
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
      - CF_API_EMAIL=your-cloudflare-email@example.com
      - CF_API_KEY=your_cloudflare_api_key
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
      - --certificatesresolvers.letsencrypt.acme.email=your-email@example.com
      - --certificatesresolvers.letsencrypt.acme.storage=/letsencrypt/acme.json
      - --certificatesresolvers.letsencrypt.acme.dnschallenge.provider=cloudflare
      - --certificatesresolvers.letsencrypt.acme.dnschallenge.resolvers=1.1.1.1:53,8.8.8.8:53
      - --log.level=INFO
    networks:
      - traefik_proxy
    labels:
      - "traefik.enable=true"

networks:
  traefik_proxy:
    external: true
```

## 📝 Complete Installation Script

Here's a complete automated setup script:

```bash
#!/bin/bash

# Web Docker Manager VPS SSL Setup Script
# Run as root or with sudo

set -e

echo "🚀 Web Docker Manager VPS SSL Setup"
echo "===================================="
echo ""

# Variables (UPDATE THESE)
DOMAIN="manager.yourdomain.com"
EMAIL="your-email@example.com"
MYSQL_PASSWORD="your_mysql_password"
ADMIN_PASSWORD="your_admin_password"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

print_success() { echo -e "${GREEN}✅ $1${NC}"; }
print_info() { echo -e "${YELLOW}ℹ️  $1${NC}"; }
print_error() { echo -e "${RED}❌ $1${NC}"; }

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    print_error "Please run as root or with sudo"
    exit 1
fi

# Step 1: Update system
print_info "Updating system packages..."
apt update && apt upgrade -y
print_success "System updated"

# Step 2: Install dependencies
print_info "Installing dependencies..."
apt install -y docker.io docker-compose mysql-server python3 python3-pip python3-venv git curl
systemctl enable docker
systemctl start docker
print_success "Dependencies installed"

# Step 3: Setup MySQL
print_info "Configuring MySQL..."
systemctl start mysql
systemctl enable mysql

# Create database and user
mysql -u root <<EOF
CREATE DATABASE IF NOT EXISTS docker_manager CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER IF NOT EXISTS 'docker_mgr'@'localhost' IDENTIFIED BY '${MYSQL_PASSWORD}';
GRANT ALL PRIVILEGES ON docker_manager.* TO 'docker_mgr'@'localhost';
FLUSH PRIVILEGES;
EOF
print_success "MySQL configured"

# Step 4: Create Traefik network
print_info "Creating Traefik network..."
docker network create traefik_proxy 2>/dev/null || print_info "Network already exists"
print_success "Traefik network ready"

# Step 5: Create SSL certificate directory
print_info "Creating SSL directories..."
mkdir -p traefik-letsencrypt
mkdir -p traefik-config/dynamic
touch traefik-letsencrypt/acme.json
chmod 600 traefik-letsencrypt/acme.json
print_success "SSL directories created"

# Step 6: Create Traefik configuration
print_info "Creating Traefik configuration..."
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
print_success "Traefik configuration created"

# Step 7: Create Web Manager Traefik routing
print_info "Creating Web Manager routing..."
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
print_success "Routing configuration created"

# Step 8: Start Traefik
print_info "Starting Traefik..."
docker compose -f traefik-docker-compose.yml up -d
sleep 5
print_success "Traefik started"

# Step 9: Setup Web Manager
print_info "Setting up Web Docker Manager..."
cd web-manager

# Create config file
cat > .docker-manager-config <<EOF
DB_HOST="localhost"
DB_NAME="docker_manager"
DB_USER="docker_mgr"
DB_PASS="${MYSQL_PASSWORD}"
EOF
chmod 600 .docker-manager-config

# Create virtual environment
python3 -m venv web-docker-manager-env
source web-docker-manager-env/bin/activate

# Install packages
pip install --upgrade pip
pip install flask>=2.3.0 flask-sqlalchemy>=3.1.0 pymysql>=1.1.0 pyotp>=2.9.0 qrcode>=8.2.0 pillow>=11.0.0 werkzeug>=2.3.0 paramiko>=2.12.0

# Update config.py
export DB_HOST=localhost
export DB_NAME=docker_manager
export DB_USER=docker_mgr
export DB_PASS="${MYSQL_PASSWORD}"

# Run migration
python3 <<PYEOF
import sys
sys.path.append('.')
from app import app, db
from models import User

with app.app_context():
    db.create_all()
    admin = User.query.filter_by(username='admin').first()
    if not admin:
        admin = User(username='admin', email='admin@localhost', is_admin=True, is_active=True)
        admin.set_password('${ADMIN_PASSWORD}')
        admin.generate_totp_secret()
        db.session.add(admin)
        db.session.commit()
    print("✅ Database initialized")
PYEOF

deactivate
cd ..
print_success "Web Manager configured"

# Step 10: Create systemd service
print_info "Creating systemd service..."
cat > /etc/systemd/system/web-docker-manager.service <<EOF
[Unit]
Description=Web Docker Manager
After=network.target mysql.service docker.service

[Service]
Type=simple
User=root
WorkingDirectory=$(pwd)/web-manager
Environment="PATH=$(pwd)/web-manager/web-docker-manager-env/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
Environment="DB_HOST=localhost"
Environment="DB_NAME=docker_manager"
Environment="DB_USER=docker_mgr"
Environment="DB_PASS=${MYSQL_PASSWORD}"
ExecStart=$(pwd)/web-manager/web-docker-manager-env/bin/python $(pwd)/web-manager/app.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable web-docker-manager.service
systemctl start web-docker-manager.service
print_success "Systemd service created and started"

# Step 11: Configure firewall
print_info "Configuring firewall..."
ufw allow 22/tcp
ufw allow 80/tcp
ufw allow 443/tcp
ufw --force enable
print_success "Firewall configured"

# Final checks
echo ""
echo "================================================"
print_success "Installation Complete!"
echo "================================================"
echo ""
echo "📋 Access Information:"
echo "  URL: https://${DOMAIN}"
echo "  Username: admin"
echo "  Password: ${ADMIN_PASSWORD}"
echo ""
echo "🔧 Service Management:"
echo "  Status:  sudo systemctl status web-docker-manager"
echo "  Stop:    sudo systemctl stop web-docker-manager"
echo "  Start:   sudo systemctl start web-docker-manager"
echo "  Restart: sudo systemctl restart web-docker-manager"
echo "  Logs:    sudo journalctl -u web-docker-manager -f"
echo ""
echo "📊 Traefik Dashboard:"
echo "  URL: http://YOUR_SERVER_IP:8080"
echo ""
print_info "Waiting 30 seconds for SSL certificate generation..."
sleep 30
echo ""
print_info "Testing HTTPS access..."
curl -I https://${DOMAIN} || print_error "HTTPS not accessible yet. Wait a few minutes and try again."
echo ""
print_success "Setup complete! Access your Web Manager at: https://${DOMAIN}"
```

## 🛠️ Troubleshooting

### Check Service Status

```bash
# Check if service is running
sudo systemctl status web-docker-manager

# View logs
sudo journalctl -u web-docker-manager -f

# Restart service
sudo systemctl restart web-docker-manager
```

### Check Traefik

```bash
# Check Traefik status
docker ps | grep traefik

# View Traefik logs
docker logs traefik --tail 100

# Access Traefik dashboard
# http://YOUR_SERVER_IP:8080
```

### SSL Certificate Issues

```bash
# Check certificate status
docker exec traefik cat /letsencrypt/acme.json | grep -A 5 "manager.yourdomain.com"

# Force certificate renewal
docker exec traefik traefik version
docker restart traefik

# Wait 2 minutes and check again
```

### MySQL Connection Issues

```bash
# Test MySQL connection
mysql -h localhost -u docker_mgr -p docker_manager

# Check MySQL service
sudo systemctl status mysql

# View MySQL error logs
sudo tail -f /var/log/mysql/error.log
```

### Port Conflicts

```bash
# Check what's using port 5000
sudo netstat -tlnp | grep :5000
sudo lsof -i :5000

# Kill process if needed
sudo kill -9 <PID>
```

## 📊 Monitoring

### System Monitoring

```bash
# Monitor system resources
htop

# Check disk space
df -h

# Monitor Docker
docker stats
```

### Application Monitoring

```bash
# View application logs
sudo journalctl -u web-docker-manager -f --lines 100

# Check database connections
mysql -u docker_mgr -p -e "SHOW PROCESSLIST;"

# Monitor Traefik
docker logs traefik -f
```

## 🔄 Maintenance

### Regular Updates

```bash
# Update system packages
sudo apt update && sudo apt upgrade -y

# Update Docker images
docker compose -f traefik-docker-compose.yml pull
docker compose -f traefik-docker-compose.yml up -d

# Update Web Manager dependencies
cd web-manager
source web-docker-manager-env/bin/activate
pip install --upgrade flask flask-sqlalchemy pymysql pyotp qrcode pillow werkzeug paramiko
deactivate

# Restart service
sudo systemctl restart web-docker-manager
```

### Backup Configuration

```bash
# Backup Web Manager
tar -czf web-manager-backup-$(date +%Y%m%d).tar.gz web-manager/

# Backup database
mysqldump -u docker_mgr -p docker_manager > docker_manager_backup_$(date +%Y%m%d).sql

# Backup Traefik configuration
tar -czf traefik-backup-$(date +%Y%m%d).tar.gz traefik-config/ traefik-letsencrypt/
```

## 🎯 Quick Setup Summary

1. ✅ **Install dependencies** (Docker, MySQL, Python)
2. ✅ **Setup Traefik** with SSL support
3. ✅ **Configure DNS** (A record pointing to server)
4. ✅ **Create Traefik routing** for web-manager
5. ✅ **Install Web Manager** (run docker-manager.sh install)
6. ✅ **Create systemd service** for auto-start
7. ✅ **Configure firewall** (ports 80, 443, 22)
8. ✅ **Test access** at https://manager.yourdomain.com

## 📞 Support

If you encounter issues:
1. Check systemd logs: `sudo journalctl -u web-docker-manager -f`
2. Check Traefik logs: `docker logs traefik`
3. Verify DNS: `nslookup manager.yourdomain.com`
4. Test ports: `telnet yourdomain.com 80` and `443`
5. Check firewall: `sudo ufw status`

Your Web Docker Manager will be accessible at: **https://manager.yourdomain.com** with automatic SSL certificate renewal!
