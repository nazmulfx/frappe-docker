#!/bin/bash

# MySQL Auto-Fix Script
# This script automatically fixes common MySQL connection issues

echo "🔧 MySQL Auto-Fix Script"
echo "======================="
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_info() {
    echo -e "${BLUE}💡 $1${NC}"
}

# Detect OS
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    if command -v apt &> /dev/null; then
        OS="ubuntu"
    elif command -v yum &> /dev/null; then
        OS="centos"
    elif command -v dnf &> /dev/null; then
        OS="centos"
    else
        OS="linux"
    fi
elif [[ "$OSTYPE" == "darwin"* ]]; then
    OS="macos"
elif [[ "$OSTYPE" == "msys" ]] || [[ "$OSTYPE" == "cygwin" ]]; then
    OS="windows"
else
    OS="unknown"
fi

echo "Detected OS: $OS"
echo ""

# Check if MySQL is installed
if ! command -v mysql &> /dev/null; then
    print_error "MySQL client is not installed"
    echo ""
    print_info "Installing MySQL client..."
    
    case $OS in
        "ubuntu")
            sudo apt update
            sudo apt install -y mysql-client mysql-server
            ;;
        "centos")
            if command -v dnf &> /dev/null; then
                sudo dnf install -y mysql mysql-server
            else
                sudo yum install -y mysql mysql-server
            fi
            ;;
        "macos")
            if command -v brew &> /dev/null; then
                brew install mysql
            else
                print_error "Please install Homebrew first: https://brew.sh"
                exit 1
            fi
            ;;
        *)
            print_error "Please install MySQL manually for your OS"
            exit 1
            ;;
    esac
fi

# Start MySQL service
print_info "Starting MySQL service..."
case $OS in
    "ubuntu")
        sudo systemctl start mysql
        sudo systemctl enable mysql
        ;;
    "centos")
        sudo systemctl start mysqld
        sudo systemctl enable mysqld
        ;;
    "macos")
        brew services start mysql
        ;;
    "windows")
        net start mysql
        ;;
esac

# Wait for MySQL to start
sleep 3

# Test connection methods
print_info "Testing MySQL connection methods..."

# Method 1: Try with sudo (auth_socket)
if sudo mysql -u root -e "SELECT 1;" &>/dev/null; then
    print_success "MySQL works with sudo (auth_socket)"
    echo ""
    print_info "Setting up password authentication..."
    
    # Get password from user
    read -s -p "Enter new password for root user: " root_password
    echo ""
    
    # Set password
    sudo mysql -u root << EOF
ALTER USER 'root'@'localhost' IDENTIFIED WITH mysql_native_password BY '$root_password';
FLUSH PRIVILEGES;
EOF
    
    if [ $? -eq 0 ]; then
        print_success "Password authentication enabled"
        echo ""
        print_info "You can now use:"
        echo "  Username: root"
        echo "  Password: $root_password"
    else
        print_error "Failed to set password"
    fi

# Method 2: Try with password
elif mysql -u root -p -e "SELECT 1;" &>/dev/null; then
    print_success "MySQL works with password authentication"
    echo ""
    print_info "Your MySQL is already configured correctly"

# Method 3: Try to connect and fix
else
    print_warning "Cannot connect to MySQL. Attempting to fix..."
    echo ""
    
    # Try to start MySQL in safe mode and reset password
    case $OS in
        "ubuntu")
            sudo systemctl stop mysql
            sudo mysqld_safe --skip-grant-tables --skip-networking &
            sleep 5
            
            mysql -u root << EOF
USE mysql;
UPDATE user SET authentication_string=PASSWORD('newpassword') WHERE User='root';
UPDATE user SET plugin='mysql_native_password' WHERE User='root';
FLUSH PRIVILEGES;
EXIT;
EOF
            
            sudo pkill mysqld
            sudo systemctl start mysql
            ;;
        "centos")
            sudo systemctl stop mysqld
            sudo mysqld_safe --skip-grant-tables --skip-networking &
            sleep 5
            
            mysql -u root << EOF
USE mysql;
UPDATE user SET authentication_string=PASSWORD('newpassword') WHERE User='root';
UPDATE user SET plugin='mysql_native_password' WHERE User='root';
FLUSH PRIVILEGES;
EXIT;
EOF
            
            sudo pkill mysqld
            sudo systemctl start mysqld
            ;;
    esac
    
    print_info "Default password set to: newpassword"
    print_warning "Please change this password after setup!"
fi

# Test final connection
print_info "Testing final connection..."
if mysql -u root -p -e "SELECT 1;" &>/dev/null; then
    print_success "MySQL connection successful!"
    echo ""
    print_info "You can now run the Docker Manager setup:"
    echo "  cd /var/www/html/docker2\\ 15/web-manager"
    echo "  ./docker-manager.sh install"
    echo ""
    print_info "When prompted for MySQL credentials:"
    echo "  Host: localhost"
    echo "  Username: root"
    echo "  Password: [the password you set]"
else
    print_error "MySQL connection still failing"
    echo ""
    print_info "Manual troubleshooting steps:"
    echo "1. Check MySQL service: sudo systemctl status mysql"
    echo "2. Check MySQL logs: sudo tail -f /var/log/mysql/error.log"
    echo "3. Try connecting manually: mysql -u root -p"
    echo "4. Run the test script: ./docker-manager.sh test"
fi

echo ""
print_info "MySQL Auto-Fix completed!"
