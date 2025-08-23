#!/bin/bash

echo "🚀 Installing Web Docker Manager..."
echo "=================================="

# Check if Python3 is installed
if ! command -v python3 &> /dev/null; then
    echo "❌ Python3 is not installed. Installing..."
    sudo apt update
    sudo apt install -y python3 python3-pip python3-venv
fi

# Check if pip is installed
if ! command -v pip3 &> /dev/null; then
    echo "❌ pip3 is not installed. Installing..."
    sudo apt install -y python3-pip
fi

# Create virtual environment
echo "📦 Creating virtual environment..."
python3 -m venv web-docker-manager-env

# Activate virtual environment
echo "🔧 Activating virtual environment..."
source web-docker-manager-env/bin/activate

# Install requirements
echo "📥 Installing Python dependencies..."
pip install -r requirements.txt

# Make the script executable
chmod +x web-docker-manager.py

echo ""
echo "✅ Installation completed successfully!"
echo ""
echo "🚀 To start the Web Docker Manager:"
echo "   1. Activate the virtual environment:"
echo "      source web-docker-manager-env/bin/activate"
echo ""
echo "   2. Start the web server:"
echo "      python3 web-docker-manager.py"
echo ""
echo "   3. Open your browser and go to:"
echo "      http://localhost:5000"
echo ""
echo "   4. Or access from another machine:"
echo "      http://YOUR_SERVER_IP:5000"
echo ""
echo "💡 To stop the server, press Ctrl+C"
echo ""
echo "🔧 To run in background (production):"
echo "   nohup python3 web-docker-manager.py > web-manager.log 2>&1 &"
