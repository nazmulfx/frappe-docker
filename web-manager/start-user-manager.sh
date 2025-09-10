#!/bin/bash

echo "🚀 Starting Secure Docker Manager with User Management..."
echo "========================================================"

# Check if virtual environment exists
if [ ! -d "web-docker-manager-env" ]; then
    echo "❌ Virtual environment not found. Please run install-web-manager.sh first."
    exit 1
fi

# Activate virtual environment
source web-docker-manager-env/bin/activate

# Check if MySQL is running
if ! systemctl is-active --quiet mysql && ! systemctl is-active --quiet mariadb; then
    echo "⚠️  MySQL/MariaDB is not running. Please start it first:"
    echo "   sudo systemctl start mysql"
    echo "   or"
    echo "   sudo systemctl start mariadb"
    exit 1
fi

# Setup database if needed
echo "🔧 Setting up database..."
python3 setup_database.py

if [ $? -ne 0 ]; then
    echo "❌ Database setup failed. Please check MySQL configuration."
    exit 1
fi

echo "🌐 Starting web server on http://localhost:5000"
echo "🛑 Press Ctrl+C to stop the server"
echo ""

# Start the web manager
python3 app.py
