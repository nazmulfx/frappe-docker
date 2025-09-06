# Docker Manager Script Documentation

A comprehensive Docker container management tool specifically designed for Frappe/ERPNext minimal setup deployments, providing an interactive menu-driven interface for managing Docker containers with ease.

## 🚀 Overview

The Docker Manager script (`docker-manager.sh`) is designed for **VPS/Cloud Server** Frappe/ERPNext deployments. It automatically detects your Docker projects and provides quick access to common operations like accessing containers, viewing logs, transferring files, and managing container lifecycle.

## ✨ Features

- 🔍 **Auto-Discovery**: Automatically detects available Frappe/ERPNext sites from running containers
- 🐚 **Shell Access**: Quick access to container shells (both frappe user and root)
- 📋 **Log Inspection**: View container and application logs with comprehensive options
- 🔄 **Container Management**: Start, stop, restart, rebuild, and remove containers
- 📁 **File Transfer**: Copy files between host and containers
- 🛡️ **Safety Features**: Confirmation prompts for destructive operations
- 🎨 **User-Friendly**: Color-coded output and clear feedback messages
- ⚡ **Bulk Operations**: Manage all containers for a project simultaneously
- 🔧 **Process Management**: Control Frappe processes via Supervisor
- 📦 **Package Installation**: Install software packages in containers

## 📋 Prerequisites

- Docker and Docker Compose installed
- Sudo privileges for Docker operations
- Bash shell environment
- Frappe/ERPNext containers created by `generate_frappe_docker.sh`
- Containers following the naming convention: `{site-name}-{service}` (e.g., `mysite-app`, `mysite-db`, `mysite-redis`)

## 🎯 Quick Start

### Make Script Executable
```bash
chmod +x docker-manager.sh
```

### Run the Script
```bash
./docker-manager.sh
```

## 📖 Usage Guide

### 1. Automatic Site Detection
When you run the script, it will:
- Automatically detect all Frappe/ERPNext sites from running containers
- Display the number of sites found
- List all available sites
- Provide a comprehensive menu for management

```
✅ Found 2 Frappe site(s):
   • mysite
   • example-com
```

### 2. Main Menu Options

The script provides **11 main menu options**:

#### 📋 **Option 1: Show running containers**
- Displays all running Frappe containers with status and port information
- Shows containers grouped by site

#### 🐚 **Option 2: Access container shell (normal user)**
- Opens bash shell as frappe user (recommended for most operations)
- If multiple sites exist, prompts for site selection
- Automatically handles single vs. multiple site scenarios

#### 🔧 **Option 3: Access container shell (root user)**
- Opens bash shell as root user (for system-level changes)
- Useful for installing packages or making system modifications
- If multiple sites exist, prompts for site selection

#### 🔄 **Option 4: Manage Frappe processes**
- Opens submenu for Supervisor process management
- Control all Frappe processes (web, workers, scheduler, websocket)
- Start, stop, restart individual or all processes

#### 📋 **Option 5: View logs**
- Opens submenu for comprehensive log viewing
- Access Frappe web, worker, schedule, websocket, and supervisor logs
- View container logs and application logs

#### 🐳 **Option 6: Manage containers**
- Opens submenu for container lifecycle management
- Start, stop, restart, rebuild containers
- Remove containers with safety confirmations
- Docker system cleanup and space management

#### 🏠 **Option 7: Show site information**
- Displays detailed information about all Frappe sites
- Shows container status and running state
- Provides overview of site configuration

#### 🔧 **Option 8: Access specific container as root**
- Provides root access to any specific container by name
- Useful for debugging or system-level operations
- If multiple sites exist, prompts for site selection

#### 📁 **Option 9: File Transfer**
- Copy files between host system and containers
- Bidirectional file transfer capabilities
- Automatic destination path handling

#### 📦 **Option 10: Install Packages**
- Install software packages in containers
- Useful for adding development tools or utilities
- If multiple sites exist, prompts for site selection

#### 🚪 **Option 11: Exit**
- Safely exits the docker manager

## 🔧 Detailed Feature Guide

### Shell Access
```bash
# Access app container as frappe user (recommended)
./docker-manager.sh
> Select option 2

# Access app container as root user
./docker-manager.sh  
> Select option 3
```

### Frappe Process Management (Option 4)
Submenu with 6 options:
1. **Show process status** - Display all Supervisor process states
2. **Restart all processes** - Restart all Frappe processes simultaneously
3. **Restart specific process** - Restart individual processes (web, worker, etc.)
4. **Stop all processes** - Stop all Frappe processes
5. **Start all processes** - Start all Frappe processes
6. **Back to main menu** - Return to main menu

**Available Processes**:
- `frappe-web` - Web server process
- `frappe-schedule` - Background scheduler
- `frappe-worker-short` - Short queue worker
- `frappe-worker-long` - Long queue worker
- `frappe-worker-default` - Default queue worker
- `frappe-websocket` - WebSocket server

### Log Viewing (Option 5)
Submenu with 7 options:
1. **Frappe Web logs** - Web server application logs
2. **Frappe Worker logs** - Background worker logs
3. **Frappe Schedule logs** - Scheduler logs
4. **Frappe WebSocket logs** - WebSocket server logs
5. **Supervisor logs** - Process manager logs
6. **Container logs** - Docker container logs
7. **Back to main menu** - Return to main menu

### Container Management (Option 6)
Submenu with 10 options:
1. **Start containers** - Start all containers for a site
2. **Stop containers** - Stop all containers for a site
3. **Restart containers** - Restart all containers for a site
4. **Rebuild containers** - Rebuild containers from images
5. **Show container logs** - Display container logs
6. **Show container status** - Show container health and status
7. **Remove all containers** - Remove all containers with space cleanup
8. **Remove specific container** - Remove individual containers
9. **Docker system cleanup** - Free disk space and clean up Docker
10. **Back to main menu** - Return to main menu

### File Transfer (Option 9)
Bidirectional file transfer between host and containers:
- **Copy TO container**: Upload files from host to container
- **Copy FROM container**: Download files from container to host
- Automatic path handling for common destinations
- File validation and error checking

### Package Installation (Option 10)
Install software packages in containers:
- Uses container's package manager
- Supports both apt (Debian/Ubuntu) and yum (CentOS/RHEL)
- Interactive package selection and installation

## 🛡️ Safety Features

### Confirmation Prompts
- **Container Removal**: Requires confirmation before deleting containers
- **Bulk Operations**: Double confirmation for destructive operations
- **Process Management**: Confirmation for stopping critical processes
- **Non-destructive Operations**: No confirmation needed for access, logs, or status checks

### Error Handling
- **Docker Status Check**: Verifies Docker is running before operations
- **Container Existence**: Validates containers exist before operations
- **Site Detection**: Automatically finds and validates Frappe sites
- **Graceful Failures**: Clear error messages with suggested actions

## 🎨 User Interface

### Color Coding
- 🟢 **Green**: Success messages and confirmations
- 🔴 **Red**: Error messages and warnings  
- 🟡 **Yellow**: Information and prompts
- 🔵 **Blue**: Headers and site information
- 🔷 **Cyan**: Menu options and submenus
- ⚪ **White**: Standard output

### Feedback Messages
- ✅ Success indicators
- ❌ Error indicators
- ⚠️ Warning indicators
- 📋 Information indicators
- 🔧 Action indicators
- 🏠 Site indicators

## 📂 Project Structure Support

The script works with Frappe/ERPNext minimal setup naming conventions:

```
site-name/
├── docker-compose.yml
└── containers:
    ├── site-name-app      # Main application container
    ├── site-name-db       # MariaDB database
    ├── site-name-redis    # Redis cache/queue
    └── site-name-create-site  # Temporary setup container
```

## 🔍 Troubleshooting

### Common Issues

#### 1. "Docker is not running"
```bash
# Start Docker service
sudo systemctl start docker
# Or restart Docker Desktop on Windows/Mac
```

#### 2. "No Frappe sites found"
- Verify your containers are running: `docker ps`
- Check container naming follows convention: `{site}-{service}`
- Ensure containers were created by `generate_frappe_docker.sh`
- Start containers first: `docker compose up -d`

#### 3. "Cannot access container"
- Container might be stopped - check status first
- Try accessing as root user instead
- Verify container has bash shell available
- Check container logs for errors

#### 4. "Process management failed"
- Verify Supervisor is running in container
- Check if Frappe processes are properly configured
- Access container and check Supervisor status manually

### Debug Commands
```bash
# List all containers
docker ps -a

# Check container logs
docker logs container-name

# Inspect container details
docker inspect container-name

# Check Docker service status
sudo systemctl status docker

# Verify site containers
docker ps --filter "name=site-name-"
```

## 🔄 Recent Updates

### Current Version Features
- ✅ **11 Main Menu Options**: Comprehensive container and process management
- ✅ **Automatic Site Detection**: Finds Frappe sites from running containers
- ✅ **Supervisor Integration**: Full Frappe process management via Supervisor
- ✅ **Submenu System**: Organized submenus for different management areas
- ✅ **Multi-Site Support**: Handles single and multiple site scenarios
- ✅ **File Transfer**: Bidirectional file transfer capabilities
- ✅ **Package Installation**: Software package management in containers
- ✅ **Safety Features**: Confirmation prompts and error handling

### Architecture
- **Minimal Setup**: Designed for 4-container Frappe/ERPNext deployments
- **Supervisor Management**: All Frappe processes managed in single container
- **Container Lifecycle**: Complete container management capabilities
- **Log Management**: Comprehensive logging and monitoring

## 🤝 Contributing

### Making Changes
1. Test changes with various Frappe/ERPNext configurations
2. Ensure backward compatibility with existing minimal setups
3. Update documentation for new features
4. Follow existing code style and error handling patterns

### Testing
```bash
# Test with different site configurations
./docker-manager.sh

# Test process management
./docker-manager.sh > Select option 4

# Test container management
./docker-manager.sh > Select option 6

# Test file transfer
./docker-manager.sh > Select option 9
```

## 📞 Support

### Getting Help
1. **Check Logs**: Use the log inspection features (option 5)
2. **Verify Setup**: Ensure Docker and containers are properly configured
3. **Test Manually**: Try Docker commands manually to isolate issues
4. **Check Documentation**: Review this guide and the main README.md

### Related Scripts
- `generate_frappe_docker.sh` - Initial VPS deployment setup
- `fix_traefik_https.sh` - HTTPS configuration fixes
- `test_mixed_setup.sh` - Testing mixed HTTP/HTTPS configurations

### Local Development Alternative
For local development, use the Docker-Local folder tools:
- `Docker-Local/generate_frappe_docker_local.sh` - Local site generation
- `Docker-Local/docker-manager-local.sh` - Local container management

---

**💡 Pro Tip**: This script is specifically designed for **VPS/Cloud Server** Frappe/ERPNext deployments. For local development, use the Docker-Local folder tools instead.

**🚀 Quick Access**: Keep this script in your project root directory for easy access. You can create an alias for quick execution:

```bash
# Add to your ~/.bashrc or ~/.zshrc
alias dm='./docker-manager.sh'
```

Then just run `dm` to launch the Docker Manager! 🚀 