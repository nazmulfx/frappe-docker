# 🔒 PRODUCTION SECURITY GUIDE
## Secure Web Docker Manager for VPS/Server Deployment

### ⚠️ CRITICAL SECURITY NOTICE
This guide is **MANDATORY** for production VPS deployment. Failure to follow these steps will leave your server vulnerable to attacks.

---

## 🛡️ SECURITY FEATURES IMPLEMENTED

### ✅ **Authentication & Authorization**
- **Secure Login System** - Username/password authentication required
- **Session Management** - Automatic timeout and secure session handling
- **CSRF Protection** - Prevents cross-site request forgery attacks
- **Admin Credentials** - Auto-generated secure passwords

### ✅ **Input Security**
- **Command Sanitization** - All user inputs are sanitized
- **Command Validation** - Only whitelisted commands allowed
- **Container Name Validation** - Prevents injection attacks
- **Length Limits** - Prevents buffer overflow attempts

### ✅ **Network Security**
- **IP Whitelisting** - Restrict access to specific IPs
- **Rate Limiting** - Prevents brute force attacks
- **Security Headers** - XSS, clickjacking, and MIME-type protection
- **HTTPS Ready** - SSL/TLS encryption support

### ✅ **Operational Security**
- **Audit Logging** - All actions are logged
- **Failed Login Tracking** - Automatic IP blocking
- **Command Timeout** - Prevents resource exhaustion
- **Secure File Permissions** - Restricted access to sensitive files

---

## 🚀 QUICK START (SECURE)

### 1. **Install Dependencies**
```bash
./install-web-manager.sh
```

### 2. **Start Secure Manager**
```bash
./start-secure-web-manager.sh
```

### 3. **First Login**
- Check `.admin_credentials` file for generated password
- Login at: http://localhost:5000
- **IMMEDIATELY change the default password**

---

## 🔥 PRODUCTION HARDENING (MANDATORY)

### 1. **Firewall Configuration**
```bash
# Enable UFW firewall
sudo ufw enable

# Allow SSH (replace 22 with your SSH port)
sudo ufw allow 22/tcp

# Allow only your IP to access the web manager
sudo ufw allow from YOUR_IP_ADDRESS to any port 5000

# Deny all other access to port 5000
sudo ufw deny 5000

# Check status
sudo ufw status verbose
```

### 2. **Nginx Reverse Proxy with SSL**
```nginx
# /etc/nginx/sites-available/docker-manager
server {
    listen 443 ssl http2;
    server_name your-domain.com;

    ssl_certificate /path/to/your/certificate.crt;
    ssl_certificate_key /path/to/your/private.key;
    
    # Security headers
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains";

    # Rate limiting
    limit_req_zone $binary_remote_addr zone=docker_manager:10m rate=10r/m;
    limit_req zone=docker_manager burst=5 nodelay;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}

# Redirect HTTP to HTTPS
server {
    listen 80;
    server_name your-domain.com;
    return 301 https://$server_name$request_uri;
}
```

### 3. **IP Whitelisting Configuration**
Edit `secure-web-docker-manager.py`:
```python
SECURITY_CONFIG = {
    'ALLOWED_IPS': ['YOUR_IP_1', 'YOUR_IP_2'],  # Add your IPs
    'REQUIRE_HTTPS': True,  # Enable in production
    # ... other settings
}
```

### 4. **System User (Recommended)**
```bash
# Create dedicated user
sudo useradd -m -s /bin/bash dockermgr
sudo usermod -aG docker dockermgr

# Move application to user directory
sudo cp -r /var/www/html/docker2\ 15 /home/dockermgr/docker-manager
sudo chown -R dockermgr:dockermgr /home/dockermgr/docker-manager

# Run as dedicated user
sudo -u dockermgr /home/dockermgr/docker-manager/start-secure-web-manager.sh
```

### 5. **Systemd Service (Auto-start)**
```ini
# /etc/systemd/system/docker-manager.service
[Unit]
Description=Secure Docker Manager Web Interface
After=network.target docker.service

[Service]
Type=simple
User=dockermgr
Group=dockermgr
WorkingDirectory=/home/dockermgr/docker-manager
ExecStart=/home/dockermgr/docker-manager/web-docker-manager-env/bin/python3 secure-web-docker-manager.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Enable service:
```bash
sudo systemctl daemon-reload
sudo systemctl enable docker-manager
sudo systemctl start docker-manager
```

---

## 🔍 SECURITY MONITORING

### 1. **Log Monitoring**
```bash
# Monitor access logs
tail -f docker-manager.log

# Check for failed login attempts
grep "Failed login" docker-manager.log

# Monitor blocked IPs
grep "blocked" docker-manager.log
```

### 2. **System Monitoring**
```bash
# Check active connections
netstat -tuln | grep :5000

# Monitor system resources
htop

# Check Docker events
sudo docker events
```

### 3. **Regular Security Checks**
```bash
# Check file permissions
ls -la .admin_credentials
ls -la secure-web-docker-manager.py

# Verify firewall status
sudo ufw status verbose

# Check for suspicious processes
ps aux | grep python
```

---

## 🚨 INCIDENT RESPONSE

### If Compromised:
1. **Immediate Actions:**
   ```bash
   # Stop the service
   sudo systemctl stop docker-manager
   
   # Block all access
   sudo ufw deny 5000
   
   # Check for unauthorized containers
   sudo docker ps -a
   
   # Review logs
   grep -i "error\|failed\|unauthorized" docker-manager.log
   ```

2. **Recovery Steps:**
   - Change all passwords
   - Review and remove unauthorized containers
   - Update IP whitelist
   - Restart with new credentials

---

## 📋 SECURITY CHECKLIST

### Before Going Live:
- [ ] Firewall configured and active
- [ ] IP whitelist configured
- [ ] SSL/HTTPS enabled
- [ ] Default passwords changed
- [ ] Nginx reverse proxy configured
- [ ] Rate limiting enabled
- [ ] Logging enabled and monitored
- [ ] Dedicated user account created
- [ ] Systemd service configured
- [ ] Regular backup strategy in place

### Regular Maintenance:
- [ ] Review access logs weekly
- [ ] Update IP whitelist as needed
- [ ] Monitor for failed login attempts
- [ ] Check for unauthorized containers
- [ ] Update system packages monthly
- [ ] Rotate passwords quarterly

---

## 🆘 SUPPORT & TROUBLESHOOTING

### Common Issues:

1. **Cannot Access Web Interface**
   - Check firewall rules
   - Verify IP whitelist
   - Check if port 5000 is available

2. **Authentication Fails**
   - Check `.admin_credentials` file
   - Verify file permissions
   - Clear browser cache

3. **Commands Not Working**
   - Check Docker permissions
   - Verify container names
   - Review command sanitization logs

### Emergency Access:
If locked out, you can reset by:
```bash
# Stop service
sudo systemctl stop docker-manager

# Remove credentials file
rm .admin_credentials

# Restart service (new password will be generated)
sudo systemctl start docker-manager
```

---

## ⚖️ LEGAL & COMPLIANCE

- **Audit Trail**: All actions are logged for compliance
- **Access Control**: Role-based access implemented
- **Data Protection**: No sensitive data stored in plain text
- **Incident Response**: Comprehensive logging for forensics

---

**🔒 Remember: Security is not a one-time setup but an ongoing process. Regularly review and update your security measures.**
