#!/bin/bash

echo "🚀 Starting Web Docker Manager..."

# Check if virtual environment exists
if [ ! -d "web-docker-manager-env" ]; then
    echo "❌ Virtual environment not found. Please run install-web-manager.sh first."
    exit 1
fi

# Activate virtual environment
source web-docker-manager-env/bin/activate

# Check if Flask is installed
if ! python3 -c "import flask" 2>/dev/null; then
    echo "❌ Flask not found. Installing requirements..."
    pip install -r requirements.txt
fi

echo "🌐 Starting web server on http://localhost:5000"
echo "🛑 Press Ctrl+C to stop the server"
echo ""

# Start the web manager
python3 web-docker-manager.py
