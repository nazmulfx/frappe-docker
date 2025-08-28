# 🔧 Traefik Local Machine Fix Guide

## Problem Summary
When running `generate_frappe_docker.sh` on your local machine, Traefik fails to work because:
- **Port 80 is occupied by Nginx** (or Apache) on your local machine
- Traefik cannot bind to port 80, preventing it from routing traffic
- The original script doesn't handle local development environments with port conflicts

## Solution Overview
I've created two scripts to solve this issue:

1. **`setup-traefik-local.sh`** - Sets up Traefik for local environment with port conflict handling
2. **`generate_frappe_docker_local.sh`** - Modified version that works with local Traefik setup

## 📝 Step-by-Step Instructions

### Step 1: Setup Traefik for Local Environment

```bash
# Make the script executable (if not already done)
chmod +x setup-traefik-local.sh

# Run the Traefik setup script
./setup-traefik-local.sh
```

When you run this script, you'll see three options:

#### Option 1: Stop Nginx and Use Standard Port 80 (RECOMMENDED)
- Stops and disables Nginx
- Traefik uses port 80
- Your sites work with standard URLs (http://mysite.com)

#### Option 2: Use Alternative Port 8081
- Keeps Nginx running on port 80
- Traefik uses port 8081
- Access sites with port: http://mysite.com:8081

#### Option 3: Use Localhost Domains (BEST FOR LOCAL DEV)
- Perfect for local development
- Uses `.localhost` domains (e.g., `mysite.localhost`)
- No DNS configuration needed
- Access sites at: http://mysite.localhost:8081

### Step 2: Run Frappe Docker Setup

After setting up Traefik, use the local-aware script:

```bash
# Make the script executable
chmod +x generate_frappe_docker_local.sh

# Run the Frappe setup
./generate_frappe_docker_local.sh
```

#### For Localhost Development (Option 3):
- Enter domain: `mysite.localhost`
- Access at: http://mysite.localhost:8081

#### For Standard Ports (Option 1):
- Enter domain: Your actual domain or local IP
- Access at: http://yourdomain.com

#### For Alternative Ports (Option 2):
- Enter domain: Your domain
- Access at: http://yourdomain.com:8081

## 🎯 Quick Fix Commands

If you just want to get it working quickly:

```bash
# Quick setup for local development with localhost domains
./setup-traefik-local.sh
# Choose option 3 (localhost domains)

# Then create your Frappe site
./generate_frappe_docker_local.sh
# Enter: mysite.localhost
```

Your site will be available at: **http://mysite.localhost:8081**

## 🔍 Troubleshooting

### Check if Traefik is Running
```bash
docker ps | grep traefik
```

### View Traefik Logs
```bash
docker logs traefik
```

### Check Port Usage
```bash
# See what's using port 80
sudo lsof -i :80

# See what's using port 8081
sudo lsof -i :8081
```

### Manage Hosts File Entries
```bash
# View current custom domain entries
./manage-hosts.sh
# Choose option 1

# Add a domain manually
./manage-hosts.sh
# Choose option 2

# Remove a domain
./manage-hosts.sh
# Choose option 3

# Clean up all custom entries
./manage-hosts.sh
# Choose option 4
```

### Restart Traefik
```bash
docker compose -f traefik-docker-compose.yml restart
```

### Access Traefik Dashboard
- URL: http://localhost:8080
- Shows all registered routes and services

## 🌟 Benefits of This Solution

1. **Works with existing Nginx/Apache** - No need to uninstall your web server
2. **Flexible port configuration** - Choose what works for your setup
3. **Local development friendly** - Use `.localhost` domains without DNS setup
4. **Preserves VPS compatibility** - Scripts detect environment automatically
5. **No SSL/HTTPS complexity** - HTTP-only for simple local development
6. **No certificate management** - No Let's Encrypt or SSL certificates needed
7. **Automatic hosts file management** - Domains are automatically added to hosts file
8. **Easy cleanup** - Built-in tools to manage and clean up hosts file entries

## 📌 Important Notes

1. **For Production/VPS**: Use the original `generate_frappe_docker.sh` script
2. **For Local Development**: Use `generate_frappe_docker_local.sh`
3. **Port in URL**: If using alternative ports, always include the port in URLs
4. **Multiple Sites**: You can run multiple Frappe sites with different domains

## 💡 Pro Tips

1. **Use localhost domains for development**
   - No DNS configuration needed
   - Works immediately
   - Example: `erp.localhost`, `test.localhost`

2. **Stop services cleanly**
   ```bash
   # Stop all Frappe containers for a site
   docker compose -f mysite_localhost/mysite_localhost-docker-compose.yml down
   
   # Stop Traefik
   docker compose -f traefik-docker-compose.yml down
   ```

3. **Reset everything**
   ```bash
   # Remove all containers and start fresh
   docker stop $(docker ps -aq)
   docker system prune -a
   ```

## 🚀 Example Full Setup

```bash
# 1. Setup Traefik for local development
./setup-traefik-local.sh
# Choose option 3 (localhost domains)

# 2. Create an ERPNext site
./generate_frappe_docker_local.sh
# Enter: erp.localhost

# 3. Wait 5 minutes for site to initialize

# 4. Access your site
# Browser: http://erp.localhost:8081
# Username: Administrator
# Password: admin
```

## 🔧 Hosts File Management

The script automatically adds custom domains to your hosts file. To manage these entries:

```bash
# Interactive hosts file management
./manage-hosts.sh

# Quick commands
echo "127.0.0.1 mysite.local" | sudo tee -a /etc/hosts  # Add domain
sudo sed -i '/mysite.local/d' /etc/hosts                 # Remove domain
```

## 📞 Need Help?

If you encounter issues:

1. Check Traefik is running: `docker ps | grep traefik`
2. Check logs: `docker logs traefik`
3. Verify network exists: `docker network ls | grep traefik_proxy`
4. Ensure ports are free or correctly configured
5. Try restarting Docker: `sudo systemctl restart docker`

## 🔄 Switching Between Local and VPS

The scripts automatically detect your environment:
- **Local**: When Nginx/Apache is running locally
- **VPS**: When no local web server is detected

The configuration is saved in `.traefik-local-config` file.

---

**Created to solve**: Traefik not working on local machine due to port conflicts with Nginx
**Solution by**: Local-aware Traefik setup with flexible port configuration
