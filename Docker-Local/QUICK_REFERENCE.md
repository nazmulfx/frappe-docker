# Quick Reference Guide - Docker-Local

## 🚀 Essential Commands

### Setup & Generation
```bash
# Setup local Traefik (first time)
cd ../
sudo ./setup-traefik-local.sh

# Generate new Frappe site
sudo ./generate_frappe_docker_local.sh

# Manage containers
sudo ./docker-manager-local.sh
```

### Container Management
```bash
# View all containers
sudo docker ps -a

# View running containers
sudo docker ps

# Stop all containers
sudo docker stop $(sudo docker ps -q)

# Remove all containers
sudo docker rm $(sudo docker ps -aq)
```

### Docker Manager Menu Options
```bash
sudo ./docker-manager-local.sh

# Available options:
# 1. Show running containers
# 2. Access container shell (normal user)
# 3. Access container shell (root user)
# 4. Manage Frappe processes
# 5. View logs
# 6. Manage containers
# 7. Show site information
# 8. Access specific container as root
# 9. File Transfer
# 10. Install Packages
# 11. Exit
```

### Site-Specific Operations
```bash
# Replace SITE_NAME with your actual site name (e.g., demo_local)

# Access app container
sudo docker exec -it SITE_NAME-app bash

# Access as root
sudo docker exec -it --user root SITE_NAME-app bash

# View logs
sudo docker logs SITE_NAME-app

# Follow logs
sudo docker logs -f SITE_NAME-app
```

## 🔧 Supervisor Commands (Inside Container)

```bash
# Check process status
/home/frappe/.local/bin/supervisorctl -c /home/frappe/supervisor/supervisord.conf status

# Restart specific process
/home/frappe/.local/bin/supervisorctl -c /home/frappe/supervisor/supervisord.conf restart frappe-web

# Restart all processes
/home/frappe/.local/bin/supervisorctl -c /home/frappe/supervisor/supervisord.conf restart all

# Stop all processes
/home/frappe/.local/bin/supervisorctl -c /home/frappe/supervisor/supervisord.conf stop all

# Start all processes
/home/frappe/.local/bin/supervisorctl -c /home/frappe/supervisor/supervisord.conf start all
```

## 🌐 Access Information

### Default Credentials
- **Username**: `Administrator`
- **Password**: `admin`

### Access URLs
- **Custom Port**: `http://yourdomain.local:8081`
- **Default Port**: `http://yourdomain.local`

### Port Detection
```bash
# Check current Traefik configuration
cat .traefik-local-config

# Expected output:
# TRAEFIK_HTTP_PORT=8081
# USE_LOCALHOST=true
```

## 📊 Container Architecture

```
SITE_NAME-app      # Main app container (Supervisor + all Frappe processes)
SITE_NAME-db       # MariaDB database
SITE_NAME-redis    # Redis cache/queue
SITE_NAME-create-site  # Temporary setup container
```

## 🚨 Troubleshooting

### Common Issues

#### Port Already in Use
```bash
# Check what's using port 80/443
sudo ss -ltn "sport = :80"
sudo ss -ltn "sport = :443"

# Setup local Traefik to handle conflicts
cd ../
sudo ./setup-traefik-local.sh
```

#### Container Won't Start
```bash
# Check container logs
sudo docker logs SITE_NAME-app

# Check container status
sudo docker ps -a

# Restart container
sudo docker restart SITE_NAME-app
```

#### Can't Access Site
```bash
# Check hosts file
cat /etc/hosts

# Check if Traefik is running
sudo docker ps | grep traefik

# Check Traefik logs
sudo docker logs traefik
```

#### Process Issues
```bash
# Access container
sudo docker exec -it SITE_NAME-app bash

# Check Supervisor status
/home/frappe/.local/bin/supervisorctl -c /home/frappe/supervisor/supervisord.conf status

# Restart processes
/home/frappe/.local/bin/supervisorctl -c /home/frappe/supervisor/supervisord.conf restart all
```

### Reset Everything
```bash
# Stop and remove all containers
sudo docker stop $(sudo docker ps -q)
sudo docker rm $(sudo docker ps -aq)

# Remove all volumes
sudo docker volume rm $(sudo docker volume ls -q)

# Remove all networks (except default)
sudo docker network rm $(sudo docker network ls -q | grep -v bridge)

# Start fresh
sudo ./generate_frappe_docker_local.sh
```

## 📝 Log Locations

### Container Logs
```bash
# App container logs
sudo docker logs SITE_NAME-app

# Database logs
sudo docker logs SITE_NAME-db

# Redis logs
sudo docker logs SITE_NAME-redis
```

### Application Logs (Inside Container)
```bash
# Supervisor logs
tail -f /home/frappe/supervisor/logs/supervisord.log

# Frappe web logs
tail -f /home/frappe/supervisor/logs/frappe-web.log

# Worker logs
tail -f /home/frappe/supervisor/logs/frappe-worker-default.log
```

## 🔒 Security Commands

### Check Container Security
```bash
# View container details
sudo docker inspect SITE_NAME-app

# Check container processes
sudo docker top SITE_NAME-app

# Check container resources
sudo docker stats SITE_NAME-app
```

### Network Security
```bash
# View networks
sudo docker network ls

# Inspect network
sudo docker network inspect traefik_proxy

# Check network connectivity
sudo docker exec SITE_NAME-app ping db
sudo docker exec SITE_NAME-app ping redis
```

## 💡 Pro Tips

1. **Use docker-manager-local.sh** for most operations - it's user-friendly
2. **Check logs first** when troubleshooting
3. **Use Supervisor commands** to manage Frappe processes
4. **Monitor resource usage** with `docker stats`
5. **Keep Traefik running** - it handles routing for all sites
6. **Use .localhost domains** for automatic hosts file management

## 📞 Getting Help

1. Check this quick reference first
2. Read the main README.md
3. Check container logs for error messages
4. Use docker-manager-local.sh for interactive help
5. Verify Traefik configuration and status
