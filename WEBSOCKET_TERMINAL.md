# WebSocket Terminal for Frappe Docker

This document explains how to set up the WebSocket terminal for Frappe Docker, which provides a full-featured terminal experience in the browser.

## Features

- Full terminal emulation with xterm.js
- Real-time bidirectional communication via WebSockets
- Support for all terminal commands and features
- Automatic reconnection and fallback to HTTP API
- Proper handling of terminal sizing and resizing
- Support for UTF-8, colors, and copy-paste

## Prerequisites

- Python 3.6+
- pip
- sudo access
- Docker

## Installation

1. Install required Python packages:

```bash
pip install websockets aiohttp ptyprocess
```

2. Make the startup script executable:

```bash
chmod +x /var/www/html/frappe-docker/start-terminal-ws.sh
```

3. Install the systemd service:

```bash
sudo cp /var/www/html/frappe-docker/terminal-ws.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable terminal-ws
sudo systemctl start terminal-ws
```

4. Check the service status:

```bash
sudo systemctl status terminal-ws
```

## Manual Start

If you don't want to use systemd, you can start the WebSocket server manually:

```bash
cd /var/www/html/frappe-docker
./start-terminal-ws.sh
```

## Usage

1. Access the web interface at `http://your-server/app-installation`
2. Click on the "Terminal Access" tab
3. Select a container from the dropdown
4. The terminal will connect automatically

## Troubleshooting

### WebSocket Connection Error

If you see "WebSocket error: Unknown error", check the following:

1. Make sure the WebSocket server is running:

```bash
sudo systemctl status terminal-ws
```

2. Check if port 8765 is open:

```bash
sudo netstat -tuln | grep 8765
```

3. Check the logs:

```bash
tail -f /var/www/html/frappe-docker/web-manager/terminal_ws.log
```

4. If the WebSocket server is not accessible, the terminal will automatically fall back to HTTP API mode with limited functionality.

### Permission Issues

If you encounter permission issues, make sure:

1. The WebSocket server is running as root or has sudo access
2. The Docker socket is accessible to the user running the WebSocket server

## Advanced Configuration

You can modify the WebSocket port and other settings in the `xterm-ws.js` file:

```javascript
// Default options
this.options = {
    // ...
    wsPort: 8765,  // WebSocket port
    fallbackToHttp: true,  // Whether to fall back to HTTP API if WebSocket fails
    // ...
};
```

## Security Considerations

- The WebSocket server requires authentication to access the terminal
- All commands are executed within Docker containers, providing isolation
- The server validates container names before connecting
- All terminal sessions are logged for audit purposes 