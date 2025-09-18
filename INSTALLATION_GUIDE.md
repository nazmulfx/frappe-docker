# 🚀 Secure Docker Manager - Complete Installation Guide

A comprehensive guide for installing, configuring, and troubleshooting the Secure Docker Manager web application.

## 📋 Table of Contents

1. [System Requirements](#system-requirements)
2. [Dependencies](#dependencies)
3. [Installation Methods](#installation-methods)
4. [Configuration](#configuration)
5. [Database Setup](#database-setup)
6. [Security Configuration](#security-configuration)
7. [Troubleshooting](#troubleshooting)
8. [Maintenance](#maintenance)
9. [Advanced Configuration](#advanced-configuration)

---

## 🖥️ System Requirements

### Minimum Requirements
- **Operating System**: Linux (Ubuntu 18.04+, CentOS 7+, Debian 9+)
- **RAM**: 2GB minimum, 4GB recommended
- **Storage**: 5GB free space
- **CPU**: 2 cores minimum
- **Network**: Internet connection for package installation

### Required Software
- **Python**: 3.8 or higher
- **MySQL/MariaDB**: 5.7+ or 10.3+
- **Docker**: 20.10+ (for container management)
- **Git**: For cloning the repository

---

## 📦 Dependencies

### System Dependencies

#### Ubuntu/Debian
```bash
# Update package list
sudo apt update

# Install required packages
sudo apt install -y python3 python3-pip python3-venv mysql-server mysql-client git curl wget

# Install Docker (if not already installed)
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo usermod -aG docker $USER
```

#### CentOS/RHEL/Fedora
```bash
# Install required packages
sudo yum install -y python3 python3-pip mysql-server mysql git curl wget

# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo usermod -aG docker $USER
```

### Python Dependencies

The application requires the following Python packages (automatically installed):

| Package | Version | Purpose |
|---------|---------|---------|
| `flask` | >=2.3.0 | Web framework |
| `flask-sqlalchemy` | >=3.1.0 | Database ORM |
| `pymysql` | >=1.1.0 | MySQL connector |
| `pyotp` | >=2.9.0 | Two-factor authentication |
| `qrcode` | >=8.2.0 | QR code generation |
| `pillow` | >=11.0.0 | Image processing |
| `werkzeug` | >=2.3.0 | WSGI utilities |
| `paramiko` | >=2.12.0 | SSH connections |

---

## 🚀 Installation Methods

### Method 1: Automated Installation (Recommended)

The easiest way to install the Secure Docker Manager:

```bash
# Navigate to the web-manager directory
cd /var/www/html/docker2\ 15/web-manager

# Make the script executable
chmod +x docker-manager.sh

# Run the installation
./docker-manager.sh install
```

This will:
- ✅ Create a Python virtual environment
- ✅ Install all required Python packages
- ✅ Set up the MySQL database
- ✅ Create the admin user
- ✅ Configure the application

### Method 2: Manual Installation

If you prefer manual control over the installation process:

#### Step 1: Create Virtual Environment
```bash
cd /var/www/html/docker2\ 15/web-manager
python3 -m venv web-docker-manager-env
source web-docker-manager-env/bin/activate
```

#### Step 2: Install Python Packages
```bash
pip install --upgrade pip
pip install flask>=2.3.0 flask-sqlalchemy>=3.1.0 pymysql>=1.1.0 pyotp>=2.9.0 qrcode>=8.2.0 pillow>=11.0.0 werkzeug>=2.3.0 paramiko>=2.12.0
```

#### Step 3: Database Setup
```bash
# Start MySQL service
sudo systemctl start mysql
sudo systemctl enable mysql

# Create database and user
sudo mysql -u root -p << 'EOF'
CREATE DATABASE IF NOT EXISTS docker_manager CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER IF NOT EXISTS 'docker_user'@'localhost' IDENTIFIED BY 'docker_password';
GRANT ALL PRIVILEGES ON docker_manager.* TO 'docker_user'@'localhost';
FLUSH PRIVILEGES;
EOF
```

#### Step 4: Run Migration
```bash
./docker-manager.sh migrate
```

---

## ⚙️ Configuration

### Database Configuration

The database configuration is located in `config.py`:

```python
# Database settings
SQLALCHEMY_DATABASE_URI = 'mysql+pymysql://docker_user:docker_password@localhost/docker_manager'
SQLALCHEMY_TRACK_MODIFICATIONS = False
SQLALCHEMY_ENGINE_OPTIONS = {
    'pool_recycle': 300,
    'pool_pre_ping': True,
    'pool_size': 10,
    'max_overflow': 20
}
```

### Security Configuration

```python
# Security settings
SECRET_KEY = 'your-secret-key-here'  # Change in production!
MAX_LOGIN_ATTEMPTS = 300
LOCKOUT_DURATION = 300  # 5 minutes
SESSION_TIMEOUT = 3600  # 1 hour
ALLOWED_IPS = ['127.0.0.1', '::1']  # Add your IPs
REQUIRE_HTTPS = False  # Set to True for production
ENABLE_AUDIT_LOG = True
```

### Custom Configuration

To customize the configuration:

1. **Copy the config file**:
   ```bash
   cp config.py config_local.py
   ```

2. **Edit your settings**:
   ```bash
   nano config_local.py
   ```

3. **Update the application** to use your config:
   ```python
   # In app.py, change:
   app.config.from_object(Config)
   # To:
   app.config.from_object('config_local.Config')
   ```

---

## 🗄️ Database Setup

### Initial Database Setup

The application uses MySQL/MariaDB with the following structure:

#### Users Table
```sql
CREATE TABLE users (
    id INT PRIMARY KEY AUTO_INCREMENT,
    username VARCHAR(80) UNIQUE NOT NULL,
    email VARCHAR(120) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    totp_secret VARCHAR(32),
    totp_enabled BOOLEAN DEFAULT FALSE,
    is_active BOOLEAN DEFAULT TRUE,
    is_admin BOOLEAN DEFAULT FALSE,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_login DATETIME,
    failed_login_count INT DEFAULT 0,
    locked_until DATETIME
);
```

#### Audit Logs Table
```sql
CREATE TABLE audit_logs (
    id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT,
    username VARCHAR(80) NOT NULL,
    ip_address VARCHAR(45) NOT NULL,
    event_type VARCHAR(50) NOT NULL,
    message TEXT NOT NULL,
    status VARCHAR(20) DEFAULT 'success',
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);
```

### Database Migration

Run the migration to create tables and default admin user:

```bash
# Using the script
./docker-manager.sh migrate

# Or manually
source web-docker-manager-env/bin/activate
python3 -c "
from app import app, db
from models import User, AuditLog
with app.app_context():
    db.create_all()
    admin = User(username='admin', email='admin@localhost', is_admin=True)
    admin.set_password('admin123')
    db.session.add(admin)
    db.session.commit()
    print('Database setup complete!')
"
```

---

## 🔒 Security Configuration

### Production Security Checklist

#### 1. Change Default Credentials
```bash
# Access the web interface and change admin password
# Default: admin / admin123
```

#### 2. Configure IP Whitelisting
```python
# In config.py
ALLOWED_IPS = ['192.168.1.100', '10.0.0.50']  # Your trusted IPs
```

#### 3. Enable HTTPS
```python
# In config.py
REQUIRE_HTTPS = True
```

#### 4. Set Strong Secret Key
```python
# Generate a strong secret key
import secrets
print(secrets.token_hex(32))

# Use in config.py
SECRET_KEY = 'your-generated-secret-key'
```

#### 5. Database Security
```sql
-- Create a dedicated database user with limited privileges
CREATE USER 'docker_manager'@'localhost' IDENTIFIED BY 'strong_password';
GRANT SELECT, INSERT, UPDATE, DELETE ON docker_manager.* TO 'docker_manager'@'localhost';
FLUSH PRIVILEGES;
```

### Two-Factor Authentication Setup

1. **Enable 2FA for admin user**:
   - Login to the web interface
   - Go to User Profile
   - Enable Two-Factor Authentication
   - Scan QR code with authenticator app

2. **Configure TOTP settings**:
   ```python
   # In config.py
   TOTP_ISSUER = 'Your Company Name'
   TOTP_WINDOW = 1  # Allow 1 time step tolerance
   ```

---

## 🛠️ Troubleshooting

### Common Issues and Solutions

#### 1. Database Connection Errors

**Error**: `(2003, "Can't connect to MySQL server")`

**Solutions**:
```bash
# Check MySQL service status
sudo systemctl status mysql

# Start MySQL if stopped
sudo systemctl start mysql

# Check MySQL configuration
sudo nano /etc/mysql/mysql.conf.d/mysqld.cnf

# Verify bind-address (should be 127.0.0.1 or 0.0.0.0)
bind-address = 127.0.0.1
```

#### 2. Permission Denied Errors

**Error**: `Permission denied` when accessing Docker

**Solutions**:
```bash
# Add user to docker group
sudo usermod -aG docker $USER

# Logout and login again, or use:
newgrp docker

# Verify docker access
docker ps
```

#### 3. Port Already in Use

**Error**: `Address already in use: Port 5000`

**Solutions**:
```bash
# Find process using port 5000
sudo ss -tlnp | grep :5000

# Kill the process
sudo kill -9 <PID>

# Or change port in app.py
app.run(host='0.0.0.0', port=5001, debug=False)
```

#### 4. Python Module Not Found

**Error**: `ModuleNotFoundError: No module named 'flask'`

**Solutions**:
```bash
# Activate virtual environment
source web-docker-manager-env/bin/activate

# Reinstall packages
pip install -r requirements.txt

# Or install manually
pip install flask flask-sqlalchemy pymysql
```

#### 5. Database Access Denied

**Error**: `(1045, "Access denied for user 'docker_user'@'localhost'")`

**Solutions**:
```bash
# Reset MySQL password
sudo mysql -u root -p
ALTER USER 'docker_user'@'localhost' IDENTIFIED BY 'docker_password';
FLUSH PRIVILEGES;

# Or recreate user
DROP USER 'docker_user'@'localhost';
CREATE USER 'docker_user'@'localhost' IDENTIFIED BY 'docker_password';
GRANT ALL PRIVILEGES ON docker_manager.* TO 'docker_user'@'localhost';
FLUSH PRIVILEGES;
```

### Debug Mode

Enable debug mode for detailed error messages:

```python
# In app.py
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
```

### Log Files

Check application logs for errors:

```bash
# Application logs
tail -f docker-manager.log

# MySQL logs
sudo tail -f /var/log/mysql/error.log

# System logs
journalctl -u mysql -f
```

---

## 🔧 Maintenance

### Regular Maintenance Tasks

#### Daily Tasks
- **Monitor logs**: Check for errors and security events
- **Backup database**: Create daily backups
- **Check disk space**: Monitor storage usage

#### Weekly Tasks
- **Update packages**: Keep dependencies current
- **Review audit logs**: Check for suspicious activity
- **Clean up logs**: Rotate log files

#### Monthly Tasks
- **Security audit**: Review access logs and user accounts
- **Performance review**: Check database performance
- **Backup verification**: Test restore procedures

### Backup Procedures

#### Database Backup
```bash
# Create backup
mysqldump -u docker_user -p docker_manager > backup_$(date +%Y%m%d).sql

# Compress backup
gzip backup_$(date +%Y%m%d).sql

# Automated backup script
#!/bin/bash
BACKUP_DIR="/backups/docker_manager"
DATE=$(date +%Y%m%d_%H%M%S)
mkdir -p $BACKUP_DIR
mysqldump -u docker_user -p docker_manager | gzip > $BACKUP_DIR/backup_$DATE.sql.gz
find $BACKUP_DIR -name "backup_*.sql.gz" -mtime +30 -delete
```

#### Application Backup
```bash
# Backup application files
tar -czf docker_manager_app_$(date +%Y%m%d).tar.gz \
    --exclude='web-docker-manager-env' \
    --exclude='*.log' \
    /var/www/html/docker2\ 15/web-manager/
```

### Performance Optimization

#### Database Optimization
```sql
-- Add indexes for better performance
CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_audit_logs_timestamp ON audit_logs(timestamp);
CREATE INDEX idx_audit_logs_event_type ON audit_logs(event_type);
```

#### Application Optimization
```python
# In config.py - optimize database connections
SQLALCHEMY_ENGINE_OPTIONS = {
    'pool_recycle': 300,
    'pool_pre_ping': True,
    'pool_size': 20,  # Increase for high traffic
    'max_overflow': 30
}
```

---

## 🚀 Advanced Configuration

### Production Deployment

#### Using Gunicorn
```bash
# Install Gunicorn
pip install gunicorn

# Create Gunicorn configuration
cat > gunicorn.conf.py << 'EOF'
bind = "0.0.0.0:5000"
workers = 4
worker_class = "sync"
worker_connections = 1000
timeout = 30
keepalive = 2
max_requests = 1000
max_requests_jitter = 100
preload_app = True
EOF

# Start with Gunicorn
gunicorn -c gunicorn.conf.py app:app
```

#### Using Systemd Service
```bash
# Create systemd service file
sudo nano /etc/systemd/system/docker-manager.service
```

```ini
[Unit]
Description=Secure Docker Manager
After=network.target mysql.service

[Service]
Type=simple
User=www-data
Group=www-data
WorkingDirectory=/var/www/html/docker2 15/web-manager
Environment=PATH=/var/www/html/docker2 15/web-manager/web-docker-manager-env/bin
ExecStart=/var/www/html/docker2 15/web-manager/web-docker-manager-env/bin/gunicorn -c gunicorn.conf.py app:app
Restart=always

[Install]
WantedBy=multi-user.target
```

```bash
# Enable and start service
sudo systemctl daemon-reload
sudo systemctl enable docker-manager
sudo systemctl start docker-manager
```

### Reverse Proxy with Nginx

```nginx
# /etc/nginx/sites-available/docker-manager
server {
    listen 80;
    server_name your-domain.com;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### SSL Configuration

```bash
# Install Certbot
sudo apt install certbot python3-certbot-nginx

# Get SSL certificate
sudo certbot --nginx -d your-domain.com

# Auto-renewal
sudo crontab -e
# Add: 0 12 * * * /usr/bin/certbot renew --quiet
```

### Monitoring and Logging

#### Application Monitoring
```python
# Add monitoring endpoints
@app.route('/health')
def health_check():
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.utcnow().isoformat(),
        'database': check_database_connection()
    })
```

#### Log Aggregation
```bash
# Install ELK Stack for log aggregation
# Or use simple log rotation
sudo nano /etc/logrotate.d/docker-manager
```

```
/var/www/html/docker2 15/web-manager/docker-manager.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 644 www-data www-data
}
```

---

## 📞 Support and Resources

### Getting Help

1. **Check Logs**: Always check application and system logs first
2. **Documentation**: Review this guide and related documentation
3. **Community**: Check GitHub issues and discussions
4. **Professional Support**: Contact the development team

### Useful Commands

```bash
# Check application status
./docker-manager.sh status

# View real-time logs
tail -f docker-manager.log

# Check database status
mysql -u docker_user -p -e "SHOW PROCESSLIST;" docker_manager

# Monitor system resources
htop
df -h
free -h

# Check Docker status
docker system df
docker system prune -f
```

### Version Information

- **Application Version**: 3.1
- **Python Version**: 3.8+
- **Flask Version**: 2.3.0+
- **Database**: MySQL 5.7+ / MariaDB 10.3+

---

## 🎯 Quick Reference

### Installation Commands
```bash
# Quick install
./docker-manager.sh install

# Start application
./docker-manager.sh start

# Check status
./docker-manager.sh status

# Run migration
./docker-manager.sh migrate
```

### Default Credentials
- **Username**: admin
- **Password**: admin123
- **URL**: http://localhost:5000

### Important Files
- **Main Script**: `docker-manager.sh`
- **Application**: `app.py`
- **Configuration**: `config.py`
- **Database Models**: `models.py`
- **Logs**: `docker-manager.log`

---

**📝 Last Updated**: January 2025  
**🔧 Version**: 1.0  
**👥 Maintainer**: Secure Docker Manager Team

---

*This guide covers the complete installation and setup process for the Secure Docker Manager. For additional help or advanced configurations, please refer to the specific documentation files or contact the support team.*
