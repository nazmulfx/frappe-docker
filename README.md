# 🚀 Frappe/ERPNext Docker Setup - Complete Guide

A comprehensive collection of Docker tools for deploying Frappe/ERPNext, supporting both **local development** and **VPS/cloud server** environments with automatic SSL certificate management and Cloudflare integration.

## 🎯 Choose Your Environment

### 🌐 **VPS/Cloud Server** (Production Websites)
- **SSL/HTTPS Support**: Full Let's Encrypt certificates
- **Cloudflare Integration**: DNS challenge support
- **Internet Accessible**: Public domain deployment
- **Production Ready**: Optimized for live websites

### 🏠 **Local Development** (Development & Testing)
- **Optimized Architecture**: 4 containers with faster startup
- **Custom Ports**: Smart port detection (e.g., 8081)
- **Localhost Support**: .localhost domains
- **Development Focus**: Lower resource usage, faster iteration

---

## 📁 Available Tools

### 🌐 **VPS/Cloud Server Tools** (Production)
- **`generate_frappe_docker.sh`** - Production deployment with SSL/HTTPS
- **`docker-manager.sh`** - Production container management (11 menu options)
- **`fix_traefik_https.sh`** - Comprehensive HTTPS upgrade
- **`manual_fix_traefik.sh`** - Quick HTTPS fix
- **`test_mixed_setup.sh`** - Mixed HTTP/HTTPS testing

### 🏠 **Local Development Tools** (Docker-Local Folder)
- **`Docker-Local/generate_frappe_docker_local.sh`** - Local development setup
- **`Docker-Local/docker-manager-local.sh`** - Local container management (11 menu options)
- **`Docker-Local/setup-traefik-local.sh`** - Local Traefik configuration

### 📚 **Documentation & Templates**
- **`Docker-Local/README.md`** - Complete local development guide
- **`Docker-Local/QUICK_REFERENCE.md`** - Local development commands
- **`Docker-on-VPS/README.md`** - Complete VPS deployment guide
- **`Docker-on-VPS/DOCKER_MANAGER.md`** - VPS container management guide
- **`demo.yaml`** & **`pwd.yml`** - Docker Compose templates

---

## 🚀 Quick Start Guide

### 🌐 **VPS/Cloud Server Setup** (Production)
```bash
# 1. Make script executable
chmod +x generate_frappe_docker.sh

# 2. Run the setup
./generate_frappe_docker.sh

# 3. Choose SSL/HTTPS when prompted
# 4. Enter your domain (e.g., example.com)
# 5. Provide Cloudflare API token (optional)
# 6. Wait for automatic setup (5 minutes)

# 7. Manage your site
./docker-manager.sh
```

**What You Get**:
- ✅ **4-Container Setup**: app, db, redis, create-site
- ✅ **SSL/HTTPS**: Automatic Let's Encrypt certificates
- ✅ **Traefik Integration**: Reverse proxy with SSL termination
- ✅ **Production Ready**: Internet accessible with domain validation

### 🏠 **Local Development Setup** (Development)
```bash
# 1. Setup local Traefik (first time only)
sudo ./Docker-Local/setup-traefik-local.sh

# 2. Generate new local site
sudo ./Docker-Local/generate_frappe_docker_local.sh

# 3. Enter site name (e.g., demo.localhost)
# 4. Wait for automatic setup (5 minutes)

# 5. Manage local containers
sudo ./Docker-Local/docker-manager-local.sh
```

**What You Get**:
- ✅ **4-Container Setup**: Optimized for local development
- ✅ **Custom Ports**: Automatically detected (e.g., 8081)
- ✅ **Localhost Domains**: .localhost support with hosts file management
- ✅ **Fast Startup**: Lower resource usage, faster iteration

---

## 📊 Environment Comparison

| Feature | VPS/Cloud Server | Local Development |
|---------|------------------|-------------------|
| **Purpose** | Production websites | Development & testing |
| **Containers** | 4 containers (minimal) | 4 containers (optimized) |
| **SSL** | Full HTTPS with Let's Encrypt | HTTP only (local) |
| **Ports** | Standard 80/443 | Custom ports (e.g., 8081) |
| **Access** | Internet accessible | Local network only |
| **Domains** | Real domains (example.com) | Localhost domains (demo.localhost) |
| **Resource Usage** | Medium (production) | Lower (development) |
| **Startup Time** | Medium | Faster |
| **Use Case** | Live websites, clients | Learning, testing, development |

---

## 🏗️ Architecture Overview

### 🌐 **VPS/Cloud Server Architecture**
```
Site Container Structure:
├── site-name-app/          # Main application (Supervisor + all Frappe processes)
│   ├── Frappe Web          # Web server (port 8000)
│   ├── Frappe Workers      # Background workers (short, long, default)
│   ├── Frappe Schedule     # Background scheduler
│   └── Frappe WebSocket    # WebSocket server (port 9000)
├── site-name-db/           # MariaDB 10.6 database
├── site-name-redis/        # Redis 6.2 (cache, queue, socketio)
└── site-name-create-site/  # Temporary setup container

Traefik Integration:
├── SSL termination
├── Automatic redirects (HTTP → HTTPS)
├── Load balancing
└── Certificate management
```

### 🏠 **Local Development Architecture**
```
Site Container Structure:
├── site-name-app/          # Main application (Supervisor + all Frappe processes)
│   ├── Frappe Web          # Web server (port 8000)
│   ├── Frappe Workers      # Background workers
│   ├── Frappe Schedule     # Background scheduler
│   └── Frappe WebSocket    # WebSocket server (port 9000)
├── site-name-db/           # MariaDB 10.6 database
├── site-name-redis/        # Redis 6.2 (cache, queue, socketio)
└── site-name-create-site/  # Temporary setup container

Local Traefik Integration:
├── Custom port support (e.g., 8081)
├── Localhost domain handling
├── Hosts file management
└── Development-optimized routing
```

---

## 📖 Complete Usage Guides

### 🌐 **VPS/Cloud Server Guide**
📚 **[Complete VPS Guide](Docker-on-VPS/README.md)** - Full production deployment documentation

**Key Features**:
- SSL/HTTPS with Let's Encrypt
- Cloudflare DNS challenge support
- Traefik reverse proxy setup
- Mixed HTTP/HTTPS deployments
- Production security considerations

### 🏠 **Local Development Guide**
📚 **[Complete Local Guide](Docker-Local/README.md)** - Full local development documentation

**Key Features**:
- Optimized 4-container setup
- Smart port detection
- Localhost domain support
- Hosts file management
- Development-focused tooling

---

## 🛠️ Container Management

### 🌐 **VPS Container Management**
```bash
# Access the VPS Docker Manager
./docker-manager.sh

# Available Menu Options:
1. Show running containers
2. Access container shell (normal user)
3. Access container shell (root user)
4. Manage Frappe processes
5. View logs
6. Manage containers
7. Show site information
8. Access specific container as root
9. File Transfer
10. Install Packages
11. Exit
```

📚 **[VPS Manager Documentation](Docker-on-VPS/DOCKER_MANAGER.md)**

### 🏠 **Local Container Management**
```bash
# Access the Local Docker Manager
sudo ./Docker-Local/docker-manager-local.sh

# Available Menu Options:
1. Show running containers
2. Access container shell (normal user)
3. Access container shell (root user)
4. Manage Frappe processes
5. View logs
6. Manage containers
7. Show site information
8. Access specific container as root
9. File Transfer
10. Install Packages
11. Exit
```

📚 **[Local Manager Documentation](Docker-Local/README.md)**

---

## 🔧 Process Management

### **Supervisor Commands** (Both Environments)
```bash
# Check process status
docker exec SITE_NAME-app /home/frappe/.local/bin/supervisorctl -c /home/frappe/supervisor/supervisord.conf status

# Restart specific process
docker exec SITE_NAME-app /home/frappe/.local/bin/supervisorctl -c /home/frappe/supervisor/supervisord.conf restart frappe-web

# Restart all processes
docker exec SITE_NAME-app /home/frappe/.local/bin/supervisorctl -c /home/frappe/supervisor/supervisord.conf restart all

# View specific logs
docker exec SITE_NAME-app tail -f /home/frappe/supervisor/logs/frappe-web.log
```

**Available Processes**:
- `frappe-web` - Web server
- `frappe-schedule` - Background scheduler
- `frappe-worker-short` - Short queue worker
- `frappe-worker-long` - Long queue worker
- `frappe-worker-default` - Default queue worker
- `frappe-websocket` - WebSocket server

---

## 📸 Screenshots & Visual Guides

### 🏠 **Local Development Screenshots**
Located in `Docker-Local/helper-screenshot/`:

- **Site Generation**: `run_generate_frappe_docker_local.png` - Complete setup process
- **Docker Manager**: `access_the_docker-manager.png` - Main menu interface
- **Container Access**: `view_and_access_containers.png` - Container management
- **Package Installation**: `install_nano_package_on_container.png` - Software installation

### 🌐 **VPS/Cloud Server Screenshots**
Production deployment screenshots available in the VPS documentation.

---

## 🚨 Troubleshooting

### **Common Issues & Solutions**

#### 1. **Container Won't Start**
```bash
# Check container logs
docker logs SITE_NAME-app

# Check container status
docker ps -a

# Restart container
docker restart SITE_NAME-app
```

#### 2. **Process Management Issues**
```bash
# Access container and check Supervisor
docker exec -it SITE_NAME-app bash

# Check Supervisor status
/home/frappe/.local/bin/supervisorctl -c /home/frappe/supervisor/supervisord.conf status

# Restart all processes
/home/frappe/.local/bin/supervisorctl -c /home/frappe/supervisor/supervisord.conf restart all
```

#### 3. **Port Conflicts (Local)**
```bash
# Check what's using ports
sudo ss -ltn "sport = :80"
sudo ss -ltn "sport = :443"

# Setup local Traefik
sudo ./Docker-Local/setup-traefik-local.sh
```

#### 4. **SSL Issues (VPS)**
```bash
# Check Traefik logs
docker logs traefik

# Verify domain DNS
nslookup your-domain.com

# Test Traefik configuration
./test_mixed_setup.sh
```

---

## 🔐 Security & Best Practices

### **VPS/Cloud Server Security**
- ✅ **SSL/HTTPS**: Always use for production
- ✅ **Firewall**: Configure UFW with minimal open ports
- ✅ **Cloudflare**: Use "Full (strict)" SSL mode
- ✅ **Passwords**: Change default passwords immediately
- ✅ **Updates**: Keep containers and system updated

### **Local Development Security**
- ✅ **Local Network**: Only accessible from local machine
- ✅ **Custom Ports**: Use non-standard ports for development
- ✅ **Hosts File**: Automatic domain management
- ✅ **Isolation**: Separate from production environments

---

## 💾 Backup & Recovery

### **Backup Commands**
```bash
# Backup database
docker exec SITE_NAME-db mysqldump -u root -padmin --all-databases > backup.sql

# Backup volumes
docker run --rm -v SITE_NAME_sites:/data -v $(pwd):/backup alpine tar czf /backup/sites-backup.tar.gz /data

# Backup entire site
tar czf site-backup-$(date +%Y%m%d).tar.gz SITE_NAME/ backup.sql
```

### **Restore Commands**
```bash
# Restore database
docker exec -i SITE_NAME-db mysql -u root -padmin < backup.sql

# Restore volumes
docker run --rm -v SITE_NAME_sites:/data -v $(pwd):/backup alpine tar xzf /backup/sites-backup.tar.gz -C /
```

---

## 🌐 Multiple Sites

### **VPS Multiple Sites**
```bash
# Deploy multiple production sites
./generate_frappe_docker.sh  # site1.com
./generate_frappe_docker.sh  # site2.com
./generate_frappe_docker.sh  # site3.com
```

### **Local Multiple Sites**
```bash
# Deploy multiple local sites
sudo ./Docker-Local/generate_frappe_docker_local.sh  # demo.localhost
sudo ./Docker-Local/generate_frappe_docker_local.sh  # test.localhost
sudo ./Docker-Local/generate_frappe_docker_local.sh  # dev.localhost
```

---

## 🎯 Environment Selection Guide

### **🌐 Choose VPS/Cloud Server When**:
- ✅ Deploying production websites
- ✅ Need SSL/HTTPS certificates
- ✅ Want public internet access
- ✅ Using Cloudflare integration
- ✅ Need domain validation
- ✅ Running on cloud servers/VPS
- ✅ Client-facing applications

### **🏠 Choose Local Development When**:
- ✅ Developing locally
- ✅ Testing applications
- ✅ Learning Frappe/ERPNext
- ✅ Working offline
- ✅ Need faster startup times
- ✅ Want lower resource usage
- ✅ Using custom ports
- ✅ Development iterations

---

## 📞 Support & Resources

### **Getting Help**
1. **Check Documentation**: Start with the appropriate README
2. **Review Logs**: Use container management tools
3. **Verify Setup**: Ensure proper configuration
4. **Test Scripts**: Use diagnostic tools

### **Useful Commands**
```bash
# View all containers
docker ps -a

# Check container resources
docker stats

# View Docker networks
docker network ls

# Clean up unused resources
docker system prune
```

### **Documentation Links**
- **🏠 Local Development**: [Docker-Local/README.md](Docker-Local/README.md)
- **🌐 VPS/Cloud Server**: [Docker-on-VPS/README.md](Docker-on-VPS/README.md)
- **🛠️ VPS Manager**: [Docker-on-VPS/DOCKER_MANAGER.md](Docker-on-VPS/DOCKER_MANAGER.md)
- **📚 Local Quick Reference**: [Docker-Local/QUICK_REFERENCE.md](Docker-Local/QUICK_REFERENCE.md)

---

## 🤝 Contributing

Feel free to submit issues, feature requests, or pull requests to improve these tools and documentation.

### **Development Guidelines**
1. Test changes in both environments
2. Update relevant documentation
3. Maintain backward compatibility
4. Follow existing code patterns

---

## 📄 License

This project is open source and available under the MIT License.

---

## 🚀 Quick Reference

### **VPS Production Setup**
```bash
chmod +x generate_frappe_docker.sh
./generate_frappe_docker.sh
./docker-manager.sh
```

### **Local Development Setup**
```bash
sudo ./Docker-Local/setup-traefik-local.sh
sudo ./Docker-Local/generate_frappe_docker_local.sh
sudo ./Docker-Local/docker-manager-local.sh
```

### **Process Management**
```bash
# Check status
docker exec SITE_NAME-app /home/frappe/.local/bin/supervisorctl -c /home/frappe/supervisor/supervisord.conf status

# Restart all
docker exec SITE_NAME-app /home/frappe/.local/bin/supervisorctl -c /home/frappe/supervisor/supervisord.conf restart all
```

---

**💡 Pro Tip**: Bookmark the appropriate README for your environment - [Local Development](Docker-Local/README.md) or [VPS/Cloud Server](Docker-on-VPS/README.md)!

**🎯 Ready to Deploy?** Choose your environment and follow the complete guide! 🚀


