#!/bin/bash

echo "🔒 Setting up SSL for Secure Docker Manager"
echo "==========================================="

# Check if OpenSSL is installed
if ! command -v openssl &> /dev/null; then
    echo "❌ OpenSSL not found. Installing..."
    
    # Try apt-get (Debian/Ubuntu)
    if command -v apt-get &> /dev/null; then
        sudo apt-get update
        sudo apt-get install -y openssl
    # Try yum (CentOS/RHEL)
    elif command -v yum &> /dev/null; then
        sudo yum install -y openssl
    # Try dnf (Fedora)
    elif command -v dnf &> /dev/null; then
        sudo dnf install -y openssl
    # Try apk (Alpine)
    elif command -v apk &> /dev/null; then
        apk add --no-cache openssl
    # Try pacman (Arch)
    elif command -v pacman &> /dev/null; then
        sudo pacman -S --noconfirm openssl
    else
        echo "❌ Could not determine package manager. Please install OpenSSL manually."
        exit 1
    fi
fi

# Verify installation
if command -v openssl &> /dev/null; then
    echo "✅ OpenSSL is installed: $(openssl version)"
else
    echo "❌ Failed to install OpenSSL"
    exit 1
fi

# Generate self-signed certificate
CERT_FILE="server.crt"
KEY_FILE="server.key"

if [ -f "$CERT_FILE" ] && [ -f "$KEY_FILE" ]; then
    echo "✅ SSL certificate already exists"
    exit 0
fi

echo "🔑 Generating self-signed SSL certificate..."
openssl req -x509 -newkey rsa:4096 -nodes -out "$CERT_FILE" -keyout "$KEY_FILE" -days 365 -subj '/CN=localhost' -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"

if [ $? -eq 0 ]; then
    echo "✅ SSL certificate generated successfully!"
    echo "📁 Certificate: $CERT_FILE"
    echo "📁 Private key: $KEY_FILE"
    chmod 600 "$KEY_FILE"  # Secure the private key
else
    echo "❌ Failed to generate SSL certificate"
    exit 1
fi

echo ""
echo "🌐 You can now start the secure web manager with HTTPS support"
echo "🚀 Run ./start-secure-web-manager.sh to start the server" 