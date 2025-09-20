#!/bin/bash

echo "🚀 Starting Secure Web Docker Manager with User Management..."
echo "============================================================"
echo "NOTE: Web manager files are in web-manager directory"
echo ""

# Navigate to web-manager directory
cd web-manager

# Check if the startup script exists
if [ ! -f "start-user-manager.sh" ]; then
    echo "❌ start-user-manager.sh not found in web-manager directory"
    exit 1
fi

# Run the actual startup script
echo "🔧 Running web-manager/start-user-manager.sh..."
./start-user-manager.sh
