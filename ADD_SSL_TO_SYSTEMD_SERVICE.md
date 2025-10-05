# Adding SSL/HTTPS to a Systemd Service via Traefik

This guide explains how to add SSL certificate (Let's Encrypt) to a systemd service using Traefik reverse proxy with dynamic configuration.

## Prerequisites

- A systemd service running on a specific port (e.g., port 5000)
- Traefik v2.10+ installed and running
- A domain name pointing to your server
- Docker and Docker Compose installed

## Overview

This setup allows you to:
- Run your application as a systemd service (not in Docker)
- Use Traefik to handle SSL/HTTPS termination
- Get automatic Let's Encrypt certificates
- Add security headers for production

## Step-by-Step Guide

### Step 1: Identify Your Running Traefik Instance

First, find where your Traefik container is running from:

```bash
docker ps --format "table {{.Names}}\t{{.Labels}}" | grep traefik | grep "working_dir"
```

This will show you the `working_dir` which tells you where the Traefik compose file is located.

**Example output:**
```
traefik  com.docker.compose.project.working_dir=/home/ubuntu/frappe-docker/Docker-on-VPS
```

### Step 2: Check Your Traefik Certificate Resolver Name

View your Traefik configuration to find the certificate resolver name:

```bash
cat /home/ubuntu/frappe-docker/Docker-on-VPS/traefik-docker-compose.yml | grep certificatesresolvers
```

**Example output:**
```
- "--certificatesresolvers.myresolver.acme.email=developer@example.com"
```

Note: The resolver name here is `myresolver`. Yours might be different (e.g., `letsencrypt`).

### Step 3: Find Your Docker Network Gateway IP

Get the gateway IP of your Traefik network:

```bash
docker network inspect traefik_proxy --format '{{range .IPAM.Config}}{{.Gateway}}{{end}}'
```

**Example output:**
```
172.18.0.1
```

### Step 4: Update Traefik to Support File Provider

Add file provider configuration to your Traefik docker-compose file:

```bash
sudo nano /home/ubuntu/frappe-docker/Docker-on-VPS/traefik-docker-compose.yml
```

Add these command lines:

```yaml
version: "3"

services:
  traefik:
    image: traefik:v2.10
    command:
      - "--api.insecure=true"
      - "--providers.docker=true"
      - "--providers.docker.exposedbydefault=false"
      - "--providers.file.directory=/etc/traefik/dynamic"  # ADD THIS
      - "--providers.file.watch=true"                      # ADD THIS
      - "--entrypoints.web.address=:80"
      - "--entrypoints.websecure.address=:443"
      - "--entrypoints.websecure.http.tls=true"
      - "--serversTransport.insecureSkipVerify=true"
      - "--certificatesresolvers.myresolver.acme.email=developer@example.com"
      - "--certificatesresolvers.myresolver.acme.storage=/letsencrypt/acme.json"
      - "--certificatesresolvers.myresolver.acme.httpchallenge=true"
      - "--certificatesresolvers.myresolver.acme.httpchallenge.entrypoint=web"
      - "--accesslog=true"
      - "--log.level=INFO"
      - "--api.dashboard=true"
    ports:
      - "80:80"
      - "443:443"
      - "8080:8080"
    volumes:
      - "/var/run/docker.sock:/var/run/docker.sock:ro"
      - "./traefik-letsencrypt:/letsencrypt"
      - "/home/ubuntu/frappe-docker/traefik-config:/etc/traefik"  # ADD THIS
    networks:
      - traefik_proxy
    container_name: traefik
    restart: unless-stopped

networks:
  traefik_proxy:
    external: true
```

### Step 5: Create Dynamic Configuration Directory

Create the directory structure for dynamic configurations:

```bash
sudo mkdir -p /home/ubuntu/frappe-docker/traefik-config/dynamic
```

### Step 6: Create Dynamic Configuration File

Create a configuration file for your service (replace `your-service` with your actual service name):

```bash
sudo nano /home/ubuntu/frappe-docker/traefik-config/dynamic/your-service.yml
```

Add the following configuration:

```yaml
http:
  routers:
    your_service:
      rule: "Host(`your-domain.com`)"
      entryPoints:
        - websecure
      service: your_service_svc
      tls:
        certResolver: myresolver  # Use the same name from Step 2
      middlewares:
        - your_service_headers
  
  middlewares:
    your_service_headers:
      headers:
        forceSTSHeader: true
        sslRedirect: true
        stsSeconds: 31536000
        stsIncludeSubdomains: true
        stsPreload: true
        frameDeny: true
        contentTypeNosniff: true
        browserXssFilter: true
        referrerPolicy: "strict-origin-when-cross-origin"
  
  services:
    your_service_svc:
      loadBalancer:
        servers:
          - url: "http://172.18.0.1:5000"  # Use gateway IP from Step 3
```

**Configuration explained:**

- `rule: "Host(\`your-domain.com\`)"` - Your domain name
- `entryPoints: websecure` - Use HTTPS (port 443)
- `certResolver: myresolver` - Must match your Traefik certificate resolver name
- `url: "http://172.18.0.1:5000"` - Gateway IP + your service port

### Step 7: Remove Conflicting Docker Containers

If you have a Docker container running the same service, remove it to avoid conflicts:

```bash
docker ps -a | grep your-service
docker stop your-service-container
docker rm your-service-container
```

### Step 8: Restart Traefik

Apply the new configuration by restarting Traefik:

```bash
cd /home/ubuntu/frappe-docker/Docker-on-VPS
docker compose -f traefik-docker-compose.yml down
docker compose -f traefik-docker-compose.yml up -d
```

### Step 9: Verify SSL Certificate

Check if the SSL certificate is properly issued:

```bash
# Method 1: Using curl
curl -I https://your-domain.com

# Method 2: Using openssl
echo | openssl s_client -connect your-domain.com:443 -servername your-domain.com 2>/dev/null | openssl x509 -noout -issuer -dates
```

**Expected output:**
```
issuer=C = US, O = Let's Encrypt, CN = R13
notBefore=Oct  3 06:07:53 2025 GMT
notAfter=Jan  1 06:07:52 2026 GMT
```

### Step 10: Check Traefik Logs

Monitor Traefik logs for any errors:

```bash
docker logs traefik --tail 50 -f
```

Look for:
- ✅ ACME challenge requests (Let's Encrypt verification)
- ✅ Certificate generation messages
- ✅ Router and service detection
- ❌ Any error messages

## Example: Creating Web Docker Manager Service

Here's a complete example for setting up a docker-manager service with SSL.

### Part A: Creating the Systemd Service

**Step 1: Create the systemd service file**

```bash
sudo nano /etc/systemd/system/web-docker-manager.service
```

**Step 2: Add the service configuration**

```ini
[Unit]
Description=Web Docker Manager
After=network.target mysql.service

[Service]
Type=simple
User=ubuntu
Group=ubuntu
WorkingDirectory=/home/ubuntu/frappe-docker/web-manager
ExecStart=/home/ubuntu/frappe-docker/web-manager/web-docker-manager-env/bin/python app.py
Environment=DB_HOST=localhost
Environment=DB_NAME=docker_manager
Environment=DB_USER=root
Environment=DB_PASS=your_secure_password_here
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

**Configuration explained:**

- `Description` - Service name and description
- `After` - Start after network and MySQL are ready
- `Type=simple` - Standard service type
- `User/Group` - Run as specific user (not root)
- `WorkingDirectory` - Application directory
- `ExecStart` - Command to start the application
- `Environment` - Environment variables for database connection
- `Restart=always` - Auto-restart on failure
- `RestartSec=10` - Wait 10 seconds before restart
- `StandardOutput/Error=journal` - Log to systemd journal
- `WantedBy=multi-user.target` - Start at boot

**Step 3: Reload systemd and start the service**

```bash
# Reload systemd to recognize the new service
sudo systemctl daemon-reload

# Enable the service to start on boot
sudo systemctl enable web-docker-manager.service

# Start the service
sudo systemctl start web-docker-manager.service

# Check service status
sudo systemctl status web-docker-manager.service
```

**Step 4: Verify the service is running**

```bash
# Check if the service is listening on port 5000
sudo netstat -tlnp | grep :5000

# Or using ss
sudo ss -tlnp | grep :5000

# Check service logs
sudo journalctl -u web-docker-manager.service -f
```

**Expected output:**
```
tcp        0      0 0.0.0.0:5000            0.0.0.0:*               LISTEN      12345/python
```

### Part B: Setting Up SSL for Docker Manager

**Service details:**
- Domain: `your-domain.com`
- Port: `5000`
- Systemd service: `web-docker-manager.service`

**Step 1: Create dynamic config file**

```bash
sudo nano /home/ubuntu/frappe-docker/traefik-config/dynamic/docker-manager.yml
```

**Step 2: Add the configuration**

```yaml
http:
  routers:
    docker_manager:
      rule: "Host(`your-domain.com`)"
      entryPoints:
        - websecure
      service: docker_manager_svc
      tls:
        certResolver: myresolver
      middlewares:
        - docker_manager_headers
  
  middlewares:
    docker_manager_headers:
      headers:
        forceSTSHeader: true
        sslRedirect: true
        stsSeconds: 31536000
        stsIncludeSubdomains: true
        stsPreload: true
        frameDeny: true
        contentTypeNosniff: true
        browserXssFilter: true
        referrerPolicy: "strict-origin-when-cross-origin"
  
  services:
    docker_manager_svc:
      loadBalancer:
        servers:
          - url: "http://172.18.0.1:5000"
```

**Step 3: Restart Traefik to apply changes**

```bash
cd /home/ubuntu/frappe-docker/Docker-on-VPS
docker compose -f traefik-docker-compose.yml restart
```

**Step 4: Test the setup**

```bash
# Test HTTPS access
curl -I https://your-domain.com

# Verify certificate
echo | openssl s_client -connect your-domain.com:443 -servername your-domain.com 2>/dev/null | openssl x509 -noout -issuer -dates
```

### Part C: Useful Systemd Commands

```bash
# View service status
sudo systemctl status web-docker-manager.service

# Start the service
sudo systemctl start web-docker-manager.service

# Stop the service
sudo systemctl stop web-docker-manager.service

# Restart the service
sudo systemctl restart web-docker-manager.service

# Enable service on boot
sudo systemctl enable web-docker-manager.service

# Disable service on boot
sudo systemctl disable web-docker-manager.service

# View service logs (last 50 lines)
sudo journalctl -u web-docker-manager.service -n 50

# View service logs (follow/live)
sudo journalctl -u web-docker-manager.service -f

# View service logs (since last boot)
sudo journalctl -u web-docker-manager.service -b

# Check if service is enabled
sudo systemctl is-enabled web-docker-manager.service

# Check if service is active
sudo systemctl is-active web-docker-manager.service
```

### Part D: Testing Before Adding SSL

Before setting up SSL, test that your service works correctly:

```bash
# Test local access
curl http://localhost:5000

# Test via gateway IP
curl http://172.18.0.1:5000

# If you get a response, the service is working correctly
# Example response:
# <html>...login page...</html>
```

### Part E: Common Service Issues

**Issue 1: Service fails to start**

```bash
# Check detailed error logs
sudo journalctl -u web-docker-manager.service -n 100 --no-pager

# Common causes:
# 1. Python environment not found
# 2. Database connection failed
# 3. Port already in use
# 4. Permission issues
```

**Issue 2: Port already in use**

```bash
# Find what's using port 5000
sudo lsof -i :5000

# Kill the process if needed
sudo kill -9 <PID>

# Restart the service
sudo systemctl restart web-docker-manager.service
```

**Issue 3: Database connection error**

```bash
# Test database connection
mysql -u root -p -h localhost docker_manager

# If it fails, check:
# 1. Database exists: CREATE DATABASE IF NOT EXISTS docker_manager;
# 2. User has permissions: GRANT ALL PRIVILEGES ON docker_manager.* TO 'root'@'localhost';
# 3. Password is correct in service file
```

**Issue 4: Permission denied**

```bash
# Fix ownership of application directory
sudo chown -R ubuntu:ubuntu /home/ubuntu/frappe-docker/web-manager

# Make Python virtual environment executable
chmod +x /home/ubuntu/frappe-docker/web-manager/web-docker-manager-env/bin/python

# Check Python path exists
ls -la /home/ubuntu/frappe-docker/web-manager/web-docker-manager-env/bin/python
```

**Issue 5: Service starts but immediately stops**

```bash
# Check if the application itself has errors
cd /home/ubuntu/frappe-docker/web-manager
./web-docker-manager-env/bin/python app.py

# This will show Python errors directly
# Fix any missing dependencies or configuration issues
```


## Troubleshooting

### Issue 1: Self-signed Certificate

**Symptom:**
```
curl: (60) SSL certificate problem: self-signed certificate
```

**Solutions:**

1. **Check certificate resolver name** - Must match between Traefik config and dynamic config
   ```bash
   # In Traefik compose file
   grep certificatesresolvers traefik-docker-compose.yml
   
   # In dynamic config
   grep certResolver traefik-config/dynamic/your-service.yml
   ```

2. **Ensure Let's Encrypt storage exists:**
   ```bash
   mkdir -p /home/ubuntu/frappe-docker/Docker-on-VPS/traefik-letsencrypt
   touch /home/ubuntu/frappe-docker/Docker-on-VPS/traefik-letsencrypt/acme.json
   chmod 600 /home/ubuntu/frappe-docker/Docker-on-VPS/traefik-letsencrypt/acme.json
   ```

3. **Check domain is accessible from internet:**
   ```bash
   nslookup your-domain.com
   curl http://your-domain.com
   ```

### Issue 2: Router Not Found

**Symptom:**
```
level=error msg="the router your_service@file uses a non-existent resolver"
```

**Solution:**
Update the `certResolver` name in your dynamic config to match Traefik's resolver name.

### Issue 3: Cannot Connect to Service

**Symptom:**
```
level=error msg="service error: unable to find the IP address"
```

**Solutions:**

1. **Verify gateway IP is correct:**
   ```bash
   docker network inspect traefik_proxy --format '{{range .IPAM.Config}}{{.Gateway}}{{end}}'
   ```

2. **Verify service is listening on the port:**
   ```bash
   sudo netstat -tlnp | grep :5000
   ```

3. **Test service directly:**
   ```bash
   curl http://172.18.0.1:5000
   ```

### Issue 4: HTTP Challenge Fails

**Symptom:**
```
level=error msg="Unable to obtain ACME certificate for domains"
```

**Solutions:**

1. **Ensure port 80 is open and accessible:**
   ```bash
   sudo ufw status
   curl http://your-domain.com/.well-known/acme-challenge/test
   ```

2. **Check DNS is pointing to your server:**
   ```bash
   dig your-domain.com
   ```

## Security Headers Explained

The middleware adds these security headers:

| Header | Purpose |
|--------|---------|
| `forceSTSHeader` | Force HTTP Strict Transport Security |
| `sslRedirect` | Redirect HTTP to HTTPS (deprecated, use entrypoint redirect) |
| `stsSeconds` | HSTS max-age (1 year) |
| `stsIncludeSubdomains` | Apply HSTS to all subdomains |
| `stsPreload` | Allow inclusion in browser HSTS preload lists |
| `frameDeny` | Prevent clickjacking attacks |
| `contentTypeNosniff` | Prevent MIME type sniffing |
| `browserXssFilter` | Enable browser XSS protection |
| `referrerPolicy` | Control referrer information |

## Certificate Renewal

Let's Encrypt certificates are valid for 90 days. Traefik automatically:
- Checks for renewal every 24 hours
- Renews certificates 30 days before expiry
- No manual intervention needed

To check certificate expiry:
```bash
echo | openssl s_client -connect your-domain.com:443 2>/dev/null | openssl x509 -noout -dates
```

## Adding Multiple Services

To add another service with SSL, simply create a new dynamic config file:

```bash
sudo nano /home/ubuntu/frappe-docker/traefik-config/dynamic/another-service.yml
```

Use the same structure, just change:
- Router name
- Domain name
- Service port
- Middleware name

Traefik will automatically detect and apply the new configuration.

## Best Practices

1. **Use unique router names** - Avoid conflicts by using descriptive names
2. **Use specific middleware names** - One per service for clarity
3. **Keep certificates organized** - One ACME storage per Traefik instance
4. **Monitor logs regularly** - Check for certificate renewal issues
5. **Test in staging first** - Use Let's Encrypt staging environment for testing
6. **Enable HSTS** - But only after confirming HTTPS works correctly
7. **Regular backups** - Backup `acme.json` file containing certificates

## File Structure Summary

```
/home/ubuntu/frappe-docker/
├── Docker-on-VPS/
│   ├── traefik-docker-compose.yml          # Main Traefik configuration
│   └── traefik-letsencrypt/
│       └── acme.json                        # Let's Encrypt certificates
└── traefik-config/
    └── dynamic/
        ├── docker-manager.yml               # Service 1 config
        ├── another-service.yml              # Service 2 config
        └── ...                              # More services
```

## Useful Commands

```bash
# View all Traefik routers
docker exec traefik cat /etc/traefik/dynamic/*.yml

# Check certificate expiry for all domains
for domain in domain1.com domain2.com; do
  echo "=== $domain ==="
  echo | openssl s_client -connect $domain:443 -servername $domain 2>/dev/null | openssl x509 -noout -dates
done

# Force certificate renewal (for testing)
docker exec traefik rm /letsencrypt/acme.json
docker restart traefik

# View Traefik dashboard
# Access: http://your-server-ip:8080/dashboard/
```

## References

- [Traefik Documentation](https://doc.traefik.io/traefik/)
- [Let's Encrypt Documentation](https://letsencrypt.org/docs/)
- [Traefik File Provider](https://doc.traefik.io/traefik/providers/file/)
- [Traefik ACME](https://doc.traefik.io/traefik/https/acme/)

## Support

If you encounter issues:
1. Check Traefik logs: `docker logs traefik --tail 100`
2. Verify DNS: `nslookup your-domain.com`
3. Test HTTP access: `curl -v http://your-domain.com`
4. Check firewall: `sudo ufw status`
5. Review this guide's troubleshooting section

---

**Created:** October 3, 2025  
**Last Updated:** October 3, 2025  
**Version:** 1.0

