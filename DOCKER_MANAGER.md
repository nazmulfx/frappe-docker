# Docker Manager Script Documentation

A comprehensive Docker container management tool that simplifies day-to-day operations for Docker Compose-based projects, specifically designed for Frappe/ERPNext deployments.

## 🚀 Overview

The Docker Manager script (`docker-manager.sh`) provides an interactive menu-driven interface to manage your Docker containers with ease. It automatically detects your Docker projects and provides quick access to common operations like accessing containers, viewing logs, transferring files, and managing container lifecycle.

## ✨ Features

- 🔍 **Auto-Discovery**: Automatically lists available Docker Compose projects
- 🐚 **Shell Access**: Quick access to container shells (both frappe user and root)
- 📋 **Log Inspection**: View container logs with tail functionality
- 🔄 **Container Management**: Start, stop, restart, and remove containers
- 📁 **File Transfer**: Copy files between host and containers
- 🛡️ **Safety Features**: Confirmation prompts for destructive operations
- 🎨 **User-Friendly**: Color-coded output and clear feedback messages
- ⚡ **Bulk Operations**: Restart or remove all containers for a project

## 📋 Prerequisites

- Docker and Docker Compose installed
- Sudo privileges for Docker operations
- Bash shell environment
- Containers following the naming convention: `{project-name}-{service}` (e.g., `mysite-backend`, `mysite-frontend`, `mysite-db`)

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

### 1. Project Selection
When you run the script, it will:
- Display all available Docker projects detected on your system
- Prompt you to enter your project name (e.g., `mysite`, `example-com`)

```
🔍 Enter your Docker Compose project name: mysite
```

### 2. Menu Options

The script provides 16 different operations:

#### Container Access
- **Option 1**: Access Backend (as frappe user)
- **Option 2**: Access Frontend (as frappe user) 
- **Option 3**: Access DB (as frappe user)
- **Option 12**: Access Backend as Root
- **Option 13**: Access Frontend as Root

#### Log Inspection
- **Option 4**: Backend Logs
- **Option 5**: Frontend Logs
- **Option 6**: DB Logs

#### Container Management
- **Option 7**: Start a Container
- **Option 8**: Stop a Container
- **Option 9**: Restart All Containers
- **Option 10**: Remove a Container
- **Option 11**: Remove All Containers

#### System Operations
- **Option 14**: Check Running Containers
- **Option 15**: File Transfer
- **Option 16**: Exit

## 🔧 Detailed Feature Guide

### Shell Access
```bash
# Access backend container as frappe user
./docker-manager.sh
> Select option 1

# Access backend container as root user
./docker-manager.sh  
> Select option 12
```

### Log Inspection
View the last 50 lines of container logs:
```bash
./docker-manager.sh
> Select option 4 (for backend logs)
```

### File Transfer Operations

#### Copy File TO Container
Perfect for uploading backup files, configurations, or data:

```bash
./docker-manager.sh
> Select option 15
> Select option 1 (Copy TO container)
> Enter source file path: /path/to/your/backup.tar
> Enter target container: mysite-backend
# Files are automatically copied to /home/frappe/frappe-bench/
```

**Example Use Case**: 
```bash
# Upload a Frappe backup file
Source file: 20250602_190012-frappe_cloud-private-files.tar
Target: mysite-backend
Destination: /home/frappe/frappe-bench/
```

#### Copy File FROM Container
Extract files, logs, or configurations from containers:

```bash
./docker-manager.sh
> Select option 15
> Select option 2 (Copy FROM container)
> Enter source container: mysite-backend
> Enter source file path: /home/frappe/frappe-bench/sites/site1.local/private/backups/
> Enter destination on host: ./backups/
```

### Bulk Operations

#### Restart All Containers
Restart all containers for a specific project:
```bash
./docker-manager.sh
> Select option 9
```

This will:
- List all containers for your project
- Show current status
- Restart all containers simultaneously
- Provide success/failure feedback

#### Remove All Containers
**⚠️ DANGEROUS OPERATION** - Permanently removes all containers for a project:
```bash
./docker-manager.sh
> Select option 11
```

Safety features:
- Shows all containers that will be affected
- Requires double confirmation
- Final confirmation requires typing "DELETE"

## 🛡️ Safety Features

### Confirmation Prompts
- **Single Container Removal**: Requires "y" confirmation and typing "DELETE"
- **Bulk Container Removal**: Double confirmation with "DELETE" keyword
- **Non-destructive Operations**: No confirmation needed for access, logs, or status checks

### Error Handling
- **Docker Status Check**: Verifies Docker is running before operations
- **Container Existence**: Validates containers exist before operations
- **File Validation**: Checks source files exist before transfer
- **Graceful Failures**: Clear error messages with suggested actions

## 🎨 User Interface

### Color Coding
- 🟢 **Green**: Success messages and confirmations
- 🔴 **Red**: Error messages and warnings  
- 🟡 **Yellow**: Information and prompts
- ⚪ **White**: Standard output

### Feedback Messages
- ✅ Success indicators
- ❌ Error indicators
- ⚠️ Warning indicators
- 📋 Information indicators
- 🔧 Action indicators

## 📂 Project Structure Support

The script works with standard Docker Compose naming conventions:

```
project-name/
├── docker-compose.yml
└── containers:
    ├── project-name-backend
    ├── project-name-frontend
    ├── project-name-db
    └── project-name-redis (if applicable)
```

## 🔍 Troubleshooting

### Common Issues

#### 1. "Docker is not running"
```bash
# Start Docker service
sudo systemctl start docker
# Or restart Docker Desktop on Windows/Mac
```

#### 2. "No containers found"
- Verify your project name matches the container prefix
- Check containers exist: `docker ps -a`
- Ensure containers follow naming convention: `{project}-{service}`

#### 3. "Cannot access container"
- Container might be stopped - check status first
- Try accessing as root user instead
- Verify container has bash shell available

#### 4. "File transfer failed"
- Check file paths are correct
- Ensure container is running
- Verify sufficient disk space
- Check file permissions

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
```

## 🔄 Recent Updates

### Latest Changes (Based on Git History)
- ✅ **File Transfer Feature**: Added comprehensive file transfer functionality
- ✅ **Enhanced Logging**: Improved log display and formatting
- ✅ **Better UX**: Streamlined prompts and user feedback
- ✅ **Safety Improvements**: Enhanced confirmation dialogs
- ✅ **Auto-Detection**: Improved project container discovery

### File Transfer Updates
- **Fixed Destination Path**: Automatically sets destination to `/home/frappe/frappe-bench/` for TO container operations
- **Bidirectional Transfer**: Supports both upload and download operations
- **File Validation**: Checks source file existence before transfer
- **Clear Feedback**: Shows source and destination paths during transfer

## 🤝 Contributing

### Making Changes
1. Test changes with various container configurations
2. Ensure backward compatibility with existing projects
3. Update documentation for new features
4. Follow existing code style and error handling patterns

### Testing
```bash
# Test with different project names
./docker-manager.sh

# Test file transfers
./docker-manager.sh > Select option 15

# Test bulk operations
./docker-manager.sh > Select option 9 or 11
```

## 📞 Support

### Getting Help
1. **Check Logs**: Use the log inspection features (options 4-6)
2. **Verify Setup**: Ensure Docker and containers are properly configured
3. **Test Manually**: Try Docker commands manually to isolate issues
4. **Check Documentation**: Review this guide and the main README.md

### Related Scripts
- `generate_frappe_docker.sh` - Initial deployment setup
- `fix_traefik_https.sh` - HTTPS configuration fixes
- `test_mixed_setup.sh` - Testing mixed configurations

---

**💡 Pro Tip**: Keep this script in your project root directory for easy access. You can create an alias for quick execution:

```bash
# Add to your ~/.bashrc or ~/.zshrc
alias dm='./docker-manager.sh'
```

Then just run `dm` to launch the Docker Manager! 🚀 