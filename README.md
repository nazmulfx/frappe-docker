# Frappe/ERPNext Docker Setup Scripts

A comprehensive collection of scripts to automatically deploy Frappe/ERPNext with Docker, supporting both HTTP and HTTPS configurations with Cloudflare integration and automatic SSL certificate management.

## 📁 Available Scripts

### Main Deployment Script
- **`generate_frappe_docker.sh`** - Complete ERPNext deployment script with Cloudflare support

### Management & Fix Scripts  
- **`manual_fix_traefik.sh`** - Quick manual upgrade of Traefik to HTTPS support
- **`fix_traefik_https.sh`** - Comprehensive Traefik upgrade with Cloudflare DNS challenge
- **`test_mixed_setup.sh`** - Test and verify mixed HTTP/HTTPS configurations

### Docker Compose Templates
- **`demo.yaml`** - Example Docker Compose configuration for ERPNext
- **`pwd.yml`** - Template with environment variable substitution

## 🚀 Features

- ✅ **SSL/HTTPS Choice**: Choose between HTTP-only or HTTPS with Let's Encrypt
- ✅ **Cloudflare Integration**: DNS challenge support with Cloudflare API
- ✅ **Traefik Integration**: Automatic reverse proxy setup with Traefik
- ✅ **Mixed Deployments**: Run both HTTP and HTTPS sites on the same server
- ✅ **Port Management**: Intelligent port conflict detection and resolution
- ✅ **Auto SSL Certificates**: Automatic Let's Encrypt certificate generation and renewal
- ✅ **Auto-restart**: Containers automatically restart on failure
- ✅ **Multiple Sites**: Deploy multiple ERPNext instances on one server

## 📋 Prerequisites

- Docker and Docker Compose installed
- Domain name pointing to your server IP address
- Ports 80 and 443 accessible from the internet (for SSL certificates)
- Root or sudo access for port management
- (Optional) Cloudflare account with API token for DNS challenge

## 🎯 Quick Start

### Standard Setup
```bash
# Make script executable
chmod +x generate_frappe_docker.sh

# Run the setup
./generate_frappe_docker.sh
```

## 📖 Usage Guide

### Step-by-Step Setup

#### 1. SSL/HTTPS Choice
```
Do you want to enable SSL/HTTPS? (y/n): 
```
- **Choose 'y'** for production sites with SSL certificates
- **Choose 'n'** for development or HTTP-only sites

#### 2. Domain Configuration
```
Enter site name (e.g. example.com): your-domain.com
```
- Enter your fully qualified domain name
- Domain must be properly formatted (e.g., `example.com` or `subdomain.example.com`)
- Domain must point to your server's IP address

#### 3. SSL Configuration (HTTPS only)
```
Enter your Cloudflare API token (leave blank for HTTP challenge): 
Enter email for Let's Encrypt notifications: your-email@example.com
```
- **Cloudflare API Token**: For DNS challenge (recommended for wildcard certs)
- **Leave blank**: For HTTP challenge (standard method)
- **Email**: Required for Let's Encrypt certificate notifications

### Configuration Options

#### HTTP-Only Setup
- Perfect for development environments
- No SSL certificate required
- Accessible via `http://your-domain.com`
- No email or Cloudflare token required

#### HTTPS Setup with HTTP Challenge
- Standard SSL setup using HTTP-01 challenge
- Automatic certificate generation and renewal
- Accessible via `https://your-domain.com`
- HTTP automatically redirects to HTTPS
- Requires valid email address

#### HTTPS Setup with Cloudflare DNS Challenge
- Advanced SSL setup using DNS-01 challenge
- Supports wildcard certificates
- Works behind Cloudflare proxy
- Requires Cloudflare API token
- More reliable for complex setups

## 📂 File Structure

After running the script, you'll have:

```
your-domain-com/
├── .env                                    # Environment variables
├── your-domain-com-docker-compose.yml     # Docker Compose configuration
└── traefik-letsencrypt/                   # SSL certificates (if HTTPS)
    └── acme.json

traefik-docker-compose.yml                 # Traefik reverse proxy
```

## 🔧 Managing Your Site

### Start/Stop Containers
```bash
cd your-domain-com

# Stop all containers
docker compose -f your-domain-com-docker-compose.yml down

# Start all containers
docker compose -f your-domain-com-docker-compose.yml up -d

# View container status
docker compose -f your-domain-com-docker-compose.yml ps
```

### View Logs
```bash
# View all container logs
docker compose -f your-domain-com-docker-compose.yml logs

# View specific container logs
docker logs your-domain-com-frontend
docker logs your-domain-com-backend
docker logs your-domain-com-db
```

### Access Your Site
- **HTTP**: `http://your-domain.com`
- **HTTPS**: `https://your-domain.com`
- **Admin Login**: 
  - Username: `Administrator`
  - Password: `admin`

## 🛠 Troubleshooting

### Common Issues

#### 1. Frontend Container Keeps Restarting
**Symptoms**: Frontend container status shows "Restarting"
```bash
docker logs your-domain-com-frontend --tail 20
```

**Common Causes**:
- Nginx configuration errors
- Missing environment variables
- Domain not pointing to server
- Cloudflare proxy configuration issues

**Solution**: Check logs and verify domain DNS configuration

#### 2. SSL Certificate Issues
**Symptoms**: SSL certificate not generating

**For HTTP Challenge**:
- Verify domain points to your server
- Ensure ports 80 and 443 are accessible from the internet
- Check if domain is reachable via HTTP first
- Verify email address is valid

**For Cloudflare DNS Challenge**:
- Verify Cloudflare API token is correct
- Check token permissions (Zone:Zone:Read, Zone:DNS:Edit)
- Ensure domain is managed by Cloudflare

#### 3. Port Conflicts
**Symptoms**: "Port already in use" errors
```bash
# Check what's using ports 80/443
sudo netstat -tlnp | grep :80
sudo netstat -tlnp | grep :443
```

**Solution**: The script automatically handles port conflicts with Traefik

#### 4. Mixed HTTP/HTTPS Issues
**Symptoms**: Some sites work, others don't

**Use the test script**:
```bash
chmod +x test_mixed_setup.sh
./test_mixed_setup.sh
```

**Fix Traefik for HTTPS (comprehensive)**:
```bash
chmod +x fix_traefik_https.sh
./fix_traefik_https.sh
```

**Manual Traefik fix (quick)**:
```bash
chmod +x manual_fix_traefik.sh
./manual_fix_traefik.sh
```

### Advanced Troubleshooting

#### Check Container Health
```bash
# View all containers
docker ps -a

# Check specific container health
docker inspect your-domain-com-frontend | grep Health -A 10
```

#### Database Issues
```bash
# Access database container
docker exec -it your-domain-com-db mysql -u root -padmin

# View database logs
docker logs your-domain-com-db
```

#### Reset Site (Nuclear Option)
```bash
cd your-domain-com
docker compose -f your-domain-com-docker-compose.yml down -v
docker compose -f your-domain-com-docker-compose.yml up -d
```

#### Check Traefik Dashboard
```bash
# Access Traefik dashboard at: http://your-server-ip:8080
# View routing rules and certificate status
```

## 🌐 Multiple Sites

You can run multiple ERPNext sites on the same server:

1. Run the script multiple times with different domain names
2. Each site gets its own directory and containers
3. All sites share the same Traefik instance
4. Mix HTTP and HTTPS sites as needed

Example:
```bash
./generate_frappe_docker.sh  # First site (e.g., site1.com)
./generate_frappe_docker.sh  # Second site (e.g., site2.com)
./generate_frappe_docker.sh  # Third site (e.g., site3.com)
```

## ⚙️ Environment Variables

Key environment variables in `.env` file:

```bash
ERPNEXT_VERSION=v15.63.0                    # ERPNext version
FRAPPE_SITE_NAME_HEADER=your-domain.com     # Your domain
LETSENCRYPT_EMAIL=your-email@example.com    # Email for SSL certificates
PROXY_READ_TIMEOUT=120                      # Nginx timeout
CLIENT_MAX_BODY_SIZE=50m                    # Max upload size
SITES=your-domain.com                       # Site name
```

## ☁️ Cloudflare Integration

### Getting Cloudflare API Token

1. **Login to Cloudflare Dashboard**
2. **Go to**: My Profile → API Tokens
3. **Create Token** with permissions:
   - Zone: Zone: Read
   - Zone: DNS: Edit
4. **Zone Resources**: Include → Specific zone → your-domain.com

### Benefits of Cloudflare DNS Challenge

- ✅ **Wildcard Certificates**: Support for `*.your-domain.com`
- ✅ **Behind Proxy**: Works when domain is proxied through Cloudflare
- ✅ **Rate Limits**: Avoids Let's Encrypt HTTP challenge rate limits
- ✅ **Private Networks**: Works on servers not directly accessible from internet

### Cloudflare Proxy Configuration

If using Cloudflare proxy (orange cloud):

1. **SSL/TLS Mode**: Set to "Full" or "Full (strict)"
2. **Always Use HTTPS**: Enable this setting
3. **HSTS**: Consider enabling for security
4. **Real IP**: Script automatically configures real IP detection

## 🔧 Management Scripts

### Test Mixed Setup
```bash
# Check if HTTP and HTTPS can coexist
chmod +x test_mixed_setup.sh
./test_mixed_setup.sh
```

**What it checks**:
- Traefik port configuration
- HTTP/HTTPS entrypoints
- Global redirect conflicts
- Running container status

### Fix Traefik for HTTPS (Comprehensive)
```bash
# Upgrade HTTP-only Traefik to support HTTPS with Cloudflare
chmod +x fix_traefik_https.sh
./fix_traefik_https.sh
```

**Features**:
- Backup current configuration
- Cloudflare DNS challenge support
- HTTP challenge fallback
- Mixed HTTP/HTTPS support

### Manual Traefik Fix (Quick)
```bash
# Simple manual fix for Traefik HTTPS
chmod +x manual_fix_traefik.sh
./manual_fix_traefik.sh
```

**Features**:
- Quick HTTPS upgrade
- HTTP challenge only
- Backup creation
- Simple configuration

## 📊 Using Docker Compose Templates

### Using demo.yaml
```bash
# Copy and customize the demo template
cp demo.yaml my-site-docker-compose.yml
# Edit the file to change domain names and settings
docker compose -f my-site-docker-compose.yml up -d
```

### Using pwd.yml with Environment Variables
```bash
# Create .env file with your settings
echo "FRAPPE_SITE_NAME_HEADER=mysite.com" > .env
# Use the template
docker compose -f pwd.yml up -d
```

## 🔐 Security Considerations

### Production Deployment
1. **Change default passwords**:
   - ERPNext admin password (default: `admin`)
   - Database password (in `.env` file)

2. **Firewall Configuration**:
   ```bash
   # Allow only necessary ports
   sudo ufw allow 80/tcp
   sudo ufw allow 443/tcp
   sudo ufw allow 22/tcp
   sudo ufw enable
   ```

3. **Cloudflare Security**:
   - Use "Full (strict)" SSL mode for maximum security
   - Enable "Always Use HTTPS"
   - Consider enabling "HSTS" headers
   - Use Cloudflare's security features (firewall, rate limiting)

4. **API Token Security**:
   - Store Cloudflare API tokens securely
   - Use minimum required permissions
   - Rotate tokens regularly

## ⚡ Performance Optimization

### Resource Allocation
```bash
# Monitor resource usage
docker stats

# Adjust container resources in docker-compose.yml if needed
```

### Database Optimization
- Regular database maintenance
- Monitor disk space
- Consider database backups

### Nginx Optimization
- Adjust worker processes based on CPU cores
- Configure appropriate timeouts
- Set proper file upload limits

## 💾 Backup and Recovery

### Backup Site Data
```bash
# Backup volumes
docker run --rm -v your-domain-com_sites:/data -v $(pwd):/backup alpine tar czf /backup/sites-backup.tar.gz /data

# Backup database
docker exec your-domain-com-db mysqldump -u root -padmin --all-databases > backup.sql
```

### Restore Site Data
```bash
# Restore volumes
docker run --rm -v your-domain-com_sites:/data -v $(pwd):/backup alpine tar xzf /backup/sites-backup.tar.gz -C /

# Restore database
docker exec -i your-domain-com-db mysql -u root -padmin < backup.sql
```

### Automated Backups
```bash
# Create backup script
#!/bin/bash
DATE=$(date +%Y%m%d_%H%M%S)
docker exec your-domain-com-db mysqldump -u root -padmin --all-databases > backup_$DATE.sql
docker run --rm -v your-domain-com_sites:/data -v $(pwd):/backup alpine tar czf /backup/sites_backup_$DATE.tar.gz /data

# Schedule with cron
# 0 2 * * * /path/to/backup-script.sh
```

## 🌍 DNS Configuration

### Required DNS Records
For your domain to work properly, ensure these DNS records are set:

```
# A Record (required)
your-domain.com     A       YOUR_SERVER_IP

# CNAME for www (optional)
www.your-domain.com CNAME   your-domain.com
```

### Verify DNS Configuration
```bash
# Check if domain resolves to your server
nslookup your-domain.com

# Test connectivity
ping your-domain.com

# Check if ports are accessible
telnet your-domain.com 80
telnet your-domain.com 443
```

## 📞 Support

### Getting Help
1. Check the troubleshooting section above
2. Review container logs for specific error messages
3. Use the test scripts to diagnose issues
4. Verify DNS configuration
5. Check Cloudflare settings if using Cloudflare integration

### Useful Commands
```bash
# View all Docker containers
docker ps -a

# View Docker networks
docker network ls

# Clean up unused Docker resources
docker system prune

# View Traefik dashboard
# Access http://your-server-ip:8080

# Check system resources
htop
df -h
free -h
```

### Log Locations
```bash
# Container logs
docker logs container-name

# System logs
sudo journalctl -u docker

# Nginx access logs (inside container)
docker exec container-name tail -f /var/log/nginx/access.log
```

## 🤝 Contributing

Feel free to submit issues, feature requests, or pull requests to improve these scripts and documentation.

## 📄 License

This project is open source and available under the MIT License.

## 📝 Script Descriptions

### generate_frappe_docker.sh
- **Purpose**: Complete ERPNext deployment script with Cloudflare integration
- **Features**: 
  - SSL choice (HTTP/HTTPS)
  - Cloudflare DNS challenge support
  - HTTP challenge fallback
  - Port conflict management
  - Traefik auto-configuration
  - Mixed HTTP/HTTPS support
  - Domain validation
  - Container deployment
- **Best for**: New deployments, production sites, Cloudflare users

### manual_fix_traefik.sh
- **Purpose**: Quick manual fix for Traefik HTTPS issues
- **Features**: 
  - Simple HTTPS upgrade
  - HTTP challenge only
  - Configuration backup
  - Basic Traefik setup
- **Best for**: Quick fixes, emergency repairs, simple setups

### fix_traefik_https.sh
- **Purpose**: Comprehensive Traefik upgrade to mixed HTTP/HTTPS
- **Features**: 
  - Full configuration upgrade
  - Cloudflare DNS challenge support
  - HTTP challenge fallback
  - Configuration backup
  - Mixed mode support
- **Best for**: Upgrading existing HTTP-only setups, advanced configurations

### test_mixed_setup.sh
- **Purpose**: Diagnostic tool for mixed HTTP/HTTPS configurations
- **Features**: 
  - Port checking
  - Configuration validation
  - Problem detection
  - Status reporting
- **Best for**: Troubleshooting, verification, diagnostics

### demo.yaml
- **Purpose**: Example Docker Compose configuration
- **Features**: 
  - Complete ERPNext stack
  - Hardcoded values
  - Reference implementation
- **Best for**: Learning, reference, quick testing

### pwd.yml
- **Purpose**: Template with environment variable substitution
- **Features**: 
  - Dynamic configuration via .env file
  - Variable substitution
  - Flexible deployment
- **Best for**: Templating, multiple similar deployments


