# 🌐 Web Docker Manager

A modern web interface for managing Docker containers, replacing the command-line `docker-manager.sh` with a beautiful, user-friendly web dashboard.

## ✨ Features

### 🎯 **Dashboard**
- **Real-time container status** with color-coded indicators
- **System statistics** (running/stopped containers, projects, space usage)
- **Quick actions** (start, stop, restart, remove containers)
- **Container logs** viewer with modal popup
- **Project organization** - group containers by project name

### 🗂️ **Project Management**
- **Project overview** with container grouping
- **Bulk operations** (restart all, remove all containers for a project)
- **Volume and network management** per project
- **Resource statistics** per project

### 🧹 **System Cleanup**
- **Safe cleanup options** (containers, images, networks)
- **Destructive cleanup** with warnings (volumes, complete cleanup)
- **Space usage visualization**
- **Before/after cleanup statistics**

### 🔍 **Container Details**
- **Detailed container information** (image, status, ports, etc.)
- **Live log streaming** with auto-refresh
- **Container actions** (start, stop, restart, remove)
- **Resource usage information**

## 🚀 Quick Start

### 1. **Install the Web Manager**
```bash
./install-web-manager.sh
```

### 2. **Start the Web Server**
```bash
./start-web-manager.sh
```

### 3. **Access the Web Interface**
- **Local access:** http://localhost:5000
- **Remote access:** http://YOUR_SERVER_IP:5000

## 📋 Installation Details

The installation script will:
1. ✅ Check and install Python3 and pip if needed
2. ✅ Create a virtual environment
3. ✅ Install Flask and dependencies
4. ✅ Set up all necessary files and permissions

## 🎨 Web Interface Screenshots

### Dashboard
- 📊 **Statistics cards** showing running/stopped containers
- 📋 **Container list** with status indicators
- 🎯 **Quick actions** for each container
- 📁 **Project navigation** in sidebar

### Project View
- 📦 **Container grouping** by project
- 📊 **Project statistics** (containers, volumes, networks)
- 🔄 **Bulk operations** (restart all, remove all)
- 💾 **Volume and network management**

### Cleanup Page
- 🟢 **Safe cleanup options** (recommended)
- 🔴 **Destructive options** with warnings
- 📊 **Space usage before/after**
- 💡 **Cleanup tips and best practices**

## 🔧 Advanced Usage

### **Run in Background (Production)**
```bash
# Start in background
nohup python3 web-docker-manager.py > web-manager.log 2>&1 &

# Check if running
ps aux | grep web-docker-manager

# Stop background process
pkill -f web-docker-manager.py
```

### **Custom Port**
Edit `web-docker-manager.py` and change:
```python
app.run(host='0.0.0.0', port=5000, debug=True)
```

### **Enable HTTPS**
For production, use a reverse proxy like nginx or add SSL to Flask.

## 🛡️ Security Features

- ✅ **Safe by default** - destructive actions require confirmation
- ✅ **Double confirmation** for dangerous operations
- ✅ **Visual warnings** for data-destructive actions
- ✅ **Read-only operations** don't require special permissions
- ✅ **Sudo integration** for Docker commands

## 🆚 Comparison: CLI vs Web

| Feature | CLI (`docker-manager.sh`) | Web Interface |
|---------|---------------------------|---------------|
| **Ease of Use** | Command-line knowledge required | Point-and-click interface |
| **Visual Feedback** | Text-based | Rich graphics and colors |
| **Multi-tasking** | One operation at a time | Multiple tabs/windows |
| **Remote Access** | SSH required | Any web browser |
| **Mobile Friendly** | No | Yes (responsive design) |
| **Log Viewing** | Terminal output | Formatted, searchable |
| **Bulk Operations** | Manual scripting | Built-in bulk actions |
| **System Overview** | Text tables | Visual dashboards |

## 🔍 API Endpoints

The web manager also provides REST API endpoints:

- `GET /api/system/info` - System information
- `POST /api/container/{name}/action` - Container actions
- `GET /api/container/{name}/logs` - Container logs
- `POST /api/cleanup` - System cleanup

## 🐛 Troubleshooting

### **Port 5000 already in use**
```bash
# Find what's using port 5000
sudo ss -tlnp | grep :5000

# Kill the process or change port in web-docker-manager.py
```

### **Permission denied errors**
```bash
# Make sure user is in docker group
sudo usermod -aG docker $USER

# Logout and login again, or use:
newgrp docker
```

### **Flask not found**
```bash
# Activate virtual environment
source web-docker-manager-env/bin/activate

# Reinstall requirements
pip install -r requirements.txt
```

## 🎯 Perfect For

- ✅ **System administrators** managing multiple Docker projects
- ✅ **Development teams** needing easy container management
- ✅ **Remote server management** via web browser
- ✅ **Non-technical users** who need Docker access
- ✅ **Mobile device management** of Docker containers
- ✅ **Training environments** for Docker learning

## 🚀 Future Enhancements

- 📊 **Real-time metrics** and monitoring
- 🔔 **Notifications** for container status changes
- 👥 **User authentication** and role-based access
- 📈 **Historical data** and analytics
- 🔄 **Auto-refresh** capabilities
- 📱 **Progressive Web App** (PWA) support

---

**🎉 Enjoy your new Web Docker Manager!** 

No more command-line complexity - manage your Docker containers with style! 🐳✨
