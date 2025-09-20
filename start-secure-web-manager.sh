#!/bin/bash

echo "🔒 Starting Secure Web Docker Manager..."
echo "NOTE: Web manager files have been moved to web-manager directory"
 
# Change to the web-manager directory and execute the secure script there
cd web-manager && ./start-secure-web-manager.sh 