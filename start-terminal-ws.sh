#!/bin/bash
# Start the WebSocket terminal server

# Navigate to the web-manager directory
cd "$(dirname "$0")/web-manager"

# Activate virtual environment if it exists
if [ -d "web-docker-manager-env" ]; then
    source web-docker-manager-env/bin/activate
fi

# Start the WebSocket server
echo "Starting WebSocket terminal server..."
python3 terminal_ws.py &

# Save the PID
echo $! > terminal_ws.pid
echo "WebSocket terminal server started with PID: $!"
echo "Access the terminal at http://localhost:5000/app-installation" 