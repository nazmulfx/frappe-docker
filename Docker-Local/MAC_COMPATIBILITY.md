# 🍎 Mac Compatibility Guide

This guide covers using the Docker-Local tools on macOS systems.

## ✅ **What Works Great on Mac**

### **Native .localhost Support**
- `.localhost` domains work natively on macOS without editing `/etc/hosts`
- No need for manual domain configuration
- Automatic DNS resolution for local development

### **Docker Desktop Integration**
- Optimized for Docker Desktop on macOS
- Better resource management
- Native macOS performance

### **Smart Port Handling**
- Automatically detects port 80 conflicts with macOS system services
- Uses port 8081 by default for better compatibility
- Handles common macOS port usage patterns

## 🚀 **Mac-Optimized Setup**

### **1. Setup Local Traefik (Mac Version)**
```bash
# Option 1: No sudo required (RECOMMENDED for Mac)
./setup-traefik-local-mac-no-sudo.sh

# Option 2: With sudo (if you prefer)
sudo ./setup-traefik-local-mac.sh
```

**What it does**:
- Detects macOS automatically
- Uses port 8081 by default (avoids system port conflicts)
- Provides Mac-specific options and guidance
- Optimized configuration for Docker Desktop
- **No sudo required** for most operations (Option 1)

### **2. Generate Local Site**
```bash
sudo ./generate_frappe_docker_local.sh
```

**Mac-specific behavior**:
- Automatically detects port 8081 from Traefik config
- Uses .localhost domains for better Mac compatibility
- No hosts file modification required

### **3. Manage Containers**
```bash
sudo ./docker-manager-local.sh
```

**Same functionality as Linux**:
- All 11 menu options work identically
- Container management and process control
- Log viewing and troubleshooting

## 🌐 **Mac Access URLs**

### **Site Access**
- **Your Site**: `http://yoursite.localhost:8081`
- **Example**: `http://demo.localhost:8081`
- **No port 80 conflicts**: Uses 8081 by default

### **Traefik Dashboard**
- **Dashboard**: `http://localhost:8080`
- **Localhost Access**: `http://traefik.localhost:8081`

### **Container Management**
- **Direct Container Access**: `http://localhost:8081` (if using standard ports)
- **Custom Ports**: `http://localhost:YOUR_PORT`

## 🔧 **Mac-Specific Configuration**

### **Port 8081 Default**
The Mac script automatically uses port 8081 because:
- Port 80 is often used by macOS system services
- Apache, Nginx, or other services may be running
- Port 8081 provides better compatibility
- No need to stop system services

### **.localhost Domains**
- Work natively on macOS
- No `/etc/hosts` editing required
- Automatic DNS resolution
- Perfect for local development

### **Docker Desktop Resources**
- Ensure Docker Desktop has sufficient resources
- Recommended: 4GB RAM, 2 CPU cores minimum
- Adjust in Docker Desktop preferences if needed

## 🚨 **Mac Troubleshooting**

### **Common Issues**

#### **Port Already in Use**
```bash
# Check what's using port 8081
lsof -i :8081

# Check what's using port 80
lsof -i :80
```

#### **Docker Desktop Issues**
```bash
# Restart Docker Desktop
# Check Docker Desktop resources
# Ensure Docker Desktop is running
```

#### **Permission Issues**
```bash
# Option 1: No sudo required (RECOMMENDED)
./setup-traefik-local-mac-no-sudo.sh
./generate_frappe_docker_local.sh

# Option 2: With sudo (if you prefer)
sudo ./setup-traefik-local-mac.sh
sudo ./generate_frappe_docker_local.sh
```

### **Mac-Specific Solutions**

#### **Port 80 Conflicts**
If you want to use port 80:
```bash
# Stop Apache (if running)
sudo apachectl stop

# Stop Nginx (if installed via Homebrew)
sudo brew services stop nginx

# Check Activity Monitor for other services
```

#### **Docker Desktop Resources**
1. Open Docker Desktop
2. Go to Settings → Resources
3. Increase Memory to 4GB+
4. Increase CPU to 2+
5. Apply & Restart

## 📱 **Mac Development Workflow**

### **Daily Development**
```bash
# 1. Start Docker Desktop
# 2. Start Traefik (if not running)
# Option 1: No sudo required (RECOMMENDED)
./setup-traefik-local-mac-no-sudo.sh

# Option 2: With sudo (if you prefer)
sudo ./setup-traefik-local-mac.sh

# 3. Generate new site (if needed)
./generate_frappe_docker_local.sh

# 4. Manage containers
./docker-manager-local.sh

# 5. Access your site
# Open: http://yoursite.localhost:8081
```

### **Multiple Sites**
```bash
# Site 1
sudo ./generate_frappe_docker_local.sh  # demo.localhost

# Site 2  
sudo ./generate_frappe_docker_local.sh  # test.localhost

# Site 3
sudo ./generate_frappe_docker_local.sh  # dev.localhost

# All accessible on port 8081
# http://demo.localhost:8081
# http://test.localhost:8081
# http://dev.localhost:8081
```

## 🎯 **Mac vs Linux Differences**

| Feature | Mac | Linux |
|---------|-----|-------|
| **Port 80** | Often used by system | Usually available |
| **Default Port** | 8081 | 80 (if available) |
| **.localhost Domains** | Native support | Requires /etc/hosts |
| **System Services** | Apache, Nginx common | systemctl services |
| **Port Detection** | lsof + ss fallback | ss command |
| **Docker Integration** | Docker Desktop | Docker Engine |

## 🚀 **Quick Mac Start**

### **One-Command Setup**
```bash
# Complete Mac setup in one go (no sudo required)
./setup-traefik-local-mac-no-sudo.sh && \
./generate_frappe_docker_local.sh && \
echo "✅ Mac setup complete! Access at: http://yoursite.localhost:8081"
```

### **Mac-Optimized Commands**
```bash
# Option 1: No sudo required (RECOMMENDED)
./setup-traefik-local-mac-no-sudo.sh
./generate_frappe_docker_local.sh
./docker-manager-local.sh

# Option 2: With sudo (if you prefer)
sudo ./setup-traefik-local-mac.sh
sudo ./generate_frappe_docker_local.sh
sudo ./docker-manager-local.sh
```

## 💡 **Mac Pro Tips**

1. **Use .localhost domains**: They work natively on macOS
2. **Port 8081 is your friend**: Avoids system port conflicts
3. **Docker Desktop resources**: Allocate sufficient RAM/CPU
4. **sudo required**: Mac scripts need sudo for port binding
5. **No hosts file editing**: .localhost domains work automatically

## 🔗 **Related Documentation**

- **[Main README](../README.md)** - Complete project overview
- **[Local Development Guide](README.md)** - Detailed local setup
- **[Quick Reference](QUICK_REFERENCE.md)** - Command reference
- **[VPS Guide](../Docker-on-VPS/README.md)** - Production deployment

---

**🍎 Ready to develop on Mac?** Use `setup-traefik-local-mac-no-sudo.sh` for the best experience with no sudo required! 🚀
