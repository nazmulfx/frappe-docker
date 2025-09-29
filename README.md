# 🚀 Frappe/ERPNext Docker Manager

A powerful web-based Docker management tool for deploying and managing Frappe/ERPNext applications with both **local development** and **production** environments.

## 🎯 Quick Start

### 🌐 **Production Setup** (VPS/Cloud)
```bash
# 1. Generate production site
chmod +x generate_frappe_docker.sh
./generate_frappe_docker.sh

# 2. Manage containers
./docker-manager.sh
```

### 🏠 **Local Development**
```bash
# Mac (Recommended - No sudo)
./Docker-Local/setup-traefik-local-mac-no-sudo.sh
./Docker-Local/generate_frappe_docker_local.sh

# Linux
sudo ./Docker-Local/setup-traefik-local.sh
sudo ./Docker-Local/generate_frappe_docker_local.sh

# Web Interface (Both VPS and Local)
sudo ./web-manager/docker-manager.sh
```

## 🖥️ Web Docker Manager

The **Web Docker Manager** is a powerful web interface for managing Frappe/ERPNext Docker containers.

### Features
- **App Management**: Install, uninstall, and update Frappe apps
- **Site Management**: Create and manage multiple sites
- **Terminal Access**: Integrated SSH terminal
- **Real-time Logs**: Operation logs with auto-scroll
- **Container Management**: Start, stop, restart containers
- **Process Control**: Manage Frappe processes (web, workers, scheduler)

### Access
- **Web Interface**: `http://your-server:5000`
- **Login**: Use your system credentials

## 📸 Screenshots

### 1. Frappe Docker Local Installation Process
![Frappe Docker Local Installation Process](screenshots/01-docker-manager-dashboard.png)
Complete setup process for generating and installing Frappe sites locally.

### 2. Container Management Interface
![Container Management Interface](screenshots/02-container-selection.png)
Command-line interface for managing Docker containers with 13 menu options including container access, process management, log viewing, and system cleanup.

### 3. App Installation Interface
![App Installation Interface](screenshots/03-app-installation-interface.png)
Complete Frappe/ERPNext app installation and management interface with real-time operation logs, terminal access, and SSH integration.

### 4. Terminal Access Tab
![Terminal Access Tab](screenshots/04-terminal-access.png)
Integrated terminal for direct container access within the web interface.

### 5. SSH Access Tab
![SSH Access Tab](screenshots/05-ssh-access.png)
Secure SSH connection management with session persistence and authentication.

### 6. Powerful Docker Manager
![Powerful Docker Manager](screenshots/06-powerful-docker-manager.png)
Comprehensive Docker management interface - **Super powerful tool for end-to-end Docker management**.

## 🏗️ Architecture

### Production (VPS/Cloud)
```
├── site-app/          # Main application (Supervisor + all Frappe processes)
├── site-db/           # MariaDB 10.6 database
├── site-redis/        # Redis 6.2 (cache, queue, socketio)
└── site-create-site/  # Temporary setup container
```

### Local Development
```
├── site-app/          # Main application (optimized for development)
├── site-db/           # MariaDB 10.6 database
├── site-redis/        # Redis 6.2 (cache, queue, socketio)
└── site-create-site/  # Temporary setup container
```

## 🛠️ Container Management

### Command Line Tools (`./docker-manager.sh`)
Powerful command-line interface with 13 menu options:

**Main Menu Options:**
1. **Show running containers** - Display all Frappe containers and their status
2. **Access container shell (normal user)** - Enter container as frappe user
3. **Access container shell (root user)** - Enter container as root user
4. **Manage Frappe processes** - Control Supervisor processes (web, workers, scheduler, websocket)
5. **View logs** - Access various log types (web, worker, schedule, websocket, supervisor, container, create-site)
6. **Manage containers** - Start, stop, restart, rebuild containers with custom apps preservation
7. **Show site information** - Display detailed site and container information
8. **Access specific container as root** - Root access to any container
9. **File Transfer** - Copy files to/from containers
10. **Install Packages** - Smart package installation with common development tools
11. **View Create-Site logs** - Monitor site creation process
12. **Fix Restart Policies** - Auto-start containers after reboot
13. **Exit** - Close the manager

**Advanced Features:**
- **Process Management**: Start, stop, restart individual or all Frappe processes
- **Log Viewing**: Real-time logs for web, workers, scheduler, websocket, supervisor
- **Container Operations**: Rebuild with custom apps preservation, complete cleanup
- **File Transfer**: Bidirectional file copying between host and containers
- **Package Installation**: Smart installation of development tools (nano, vim, curl, wget, git, htop, tree, net-tools)
- **System Cleanup**: Docker space management and unused resource cleanup
- **Complete Site Removal**: Remove containers, folders, and hosts file entries

### Web Interface (`sudo ./web-manager/docker-manager.sh`)
Access the Web Docker Manager at `http://your-server:5000` for:
- Visual container management
- App installation interface
- Terminal access
- Real-time monitoring

## 🔧 Process Management

```bash
# Check process status
docker exec SITE_NAME-app /home/frappe/.local/bin/supervisorctl -c /home/frappe/supervisor/supervisord.conf status

# Restart all processes
docker exec SITE_NAME-app /home/frappe/.local/bin/supervisorctl -c /home/frappe/supervisor/supervisord.conf restart all
```

**Available Processes**:
- `frappe-web` - Web server
- `frappe-schedule` - Background scheduler
- `frappe-worker-short` - Short queue worker
- `frappe-worker-long` - Long queue worker
- `frappe-worker-default` - Default queue worker
- `frappe-websocket` - WebSocket server

## 🚨 Troubleshooting

### Container Issues
```bash
# Check container logs
docker logs SITE_NAME-app

# Restart container
docker restart SITE_NAME-app
```

### Process Issues
```bash
# Access container
docker exec -it SITE_NAME-app bash

# Check Supervisor status
/home/frappe/.local/bin/supervisorctl -c /home/frappe/supervisor/supervisord.conf status
```

## 📚 Documentation

- **Local Development**: [Docker-Local/README.md](Docker-Local/README.md)
- **VPS/Production**: [Docker-on-VPS/README.md](Docker-on-VPS/README.md)
- **VPS Manager**: [Docker-on-VPS/DOCKER_MANAGER.md](Docker-on-VPS/DOCKER_MANAGER.md)

## 🍎 Mac Users

**Recommended Setup** (No sudo required):
```bash
./Docker-Local/setup-traefik-local-mac-no-sudo.sh
./Docker-Local/generate_frappe_docker_local.sh
```

**Benefits**:
- Native .localhost support
- Port 8081 default (avoids system conflicts)
- Docker Desktop optimized
- No hosts file editing required

## 💾 Backup & Recovery

```bash
# Backup database
docker exec SITE_NAME-db mysqldump -u root -padmin --all-databases > backup.sql

# Backup volumes
docker run --rm -v SITE_NAME_sites:/data -v $(pwd):/backup alpine tar czf /backup/sites-backup.tar.gz /data
```

## 🌐 Multiple Sites

```bash
# Production
./generate_frappe_docker.sh  # site1.com
./generate_frappe_docker.sh  # site2.com

# Local
sudo ./Docker-Local/generate_frappe_docker_local.sh  # demo.localhost
sudo ./Docker-Local/generate_frappe_docker_local.sh  # test.localhost
```

## 🔐 Security

### Production
- ✅ SSL/HTTPS with Let's Encrypt
- ✅ Cloudflare integration
- ✅ Firewall configuration
- ✅ Regular updates

### Local Development
- ✅ Local network only
- ✅ Custom ports
- ✅ Isolated environment

---

## 🚀 Quick Reference

### Production Setup
```bash
chmod +x generate_frappe_docker.sh
./generate_frappe_docker.sh
./docker-manager.sh
```

### Local Development
```bash
# Mac (recommended)
./Docker-Local/setup-traefik-local-mac-no-sudo.sh
./Docker-Local/generate_frappe_docker_local.sh

# Linux
sudo ./Docker-Local/setup-traefik-local.sh
sudo ./Docker-Local/generate_frappe_docker_local.sh

# Web Interface (Both VPS and Local)
sudo ./web-manager/docker-manager.sh
```

### Web Interface
- **URL**: `http://your-server:5000`
- **Features**: App management, terminal access, real-time logs

---

**💡 Pro Tip**: Use the **Web Docker Manager** for the best experience - it's a super powerful tool for managing your Frappe/ERPNext Docker containers!

**🎯 Ready to Deploy?** Choose your environment and get started! 🚀