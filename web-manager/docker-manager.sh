#!/bin/bash

# =====================================================================
# SECURE DOCKER MANAGER - UNIFIED STARTUP SCRIPT
# =====================================================================
# This script handles installation, setup, and startup of the Secure Docker Manager
# Version: 3.1
# Author: Secure Docker Manager Team
# =====================================================================

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$SCRIPT_DIR/web-docker-manager-env"
APP_FILE="$SCRIPT_DIR/app.py"
CONFIG_FILE="$SCRIPT_DIR/.docker-manager-config"

# Database config - will be prompted for
DB_HOST=""
DB_NAME="docker_manager"
DB_USER=""
DB_PASS=""

# Functions
print_header() {
    echo -e "${BLUE}🚀 SECURE DOCKER MANAGER${NC}"
    echo -e "${BLUE}========================${NC}"
    echo ""
}

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
    echo -e "${CYAN}💡 $1${NC}"
}

print_step() {
    echo -e "${PURPLE}🔧 $1${NC}"
}

print_prompt() {
    echo -e "${YELLOW}❓ $1${NC}"
}

# Load configuration from file
load_config() {
    if [[ -f "$CONFIG_FILE" ]]; then
        source "$CONFIG_FILE"
        return 0
    fi
    return 1
}

# Save configuration to file
save_config() {
    cat > "$CONFIG_FILE" << EOF
# Docker Manager Configuration
# Generated on $(date)

DB_HOST="$DB_HOST"
DB_NAME="$DB_NAME"
DB_USER="$DB_USER"
DB_PASS="$DB_PASS"
EOF
    chmod 600 "$CONFIG_FILE"
    print_success "Configuration saved to $CONFIG_FILE"
}

# Prompt for MySQL credentials
prompt_mysql_credentials() {
    echo ""
    print_step "MySQL Database Configuration"
    echo ""
    
    # MySQL Host
    read -p "Enter MySQL host [localhost]: " input_host
    DB_HOST="${input_host:-localhost}"
    
    # MySQL Username
    read -p "Enter MySQL username [root]: " input_user
    DB_USER="${input_user:-root}"
    
    # MySQL Password
    while true; do
        read -s -p "Enter MySQL password: " input_pass
        echo ""
        if [ -n "$input_pass" ]; then
            DB_PASS="$input_pass"
            break
        else
            print_error "Password cannot be empty"
        fi
    done
    
    print_success "MySQL credentials configured"
    echo "  Host: $DB_HOST"
    echo "  Username: $DB_USER"
    echo "  Database: $DB_NAME"
    
    # Save configuration
    save_config
}

# Prompt for admin password
prompt_admin_password() {
    echo ""
    print_prompt "Do you want to set a custom admin password? (y/n)"
    read -p "Enter choice [n]: " set_password
    
    if [[ "$set_password" =~ ^[Yy]$ ]]; then
        while true; do
            read -s -p "Enter new admin password (min 8 chars): " admin_password
            echo ""
            if [ ${#admin_password} -ge 8 ]; then
                read -s -p "Confirm admin password: " confirm_password
                echo ""
                if [ "$admin_password" = "$confirm_password" ]; then
                    ADMIN_PASSWORD="$admin_password"
                    print_success "Admin password set successfully"
                    break
                else
                    print_error "Passwords don't match. Try again."
                fi
            else
                print_error "Password must be at least 8 characters long"
            fi
        done
    else
        ADMIN_PASSWORD="admin123"
        print_info "Using default admin password: admin123"
    fi
}

# Check if MySQL client is installed
check_mysql_client() {
    if ! command -v mysql &> /dev/null; then
        print_error "MySQL client is not installed"
        echo ""
        print_info "To install MySQL client on Ubuntu/Debian:"
        echo "  sudo apt update && sudo apt install mysql-client"
        echo ""
        print_info "To install MySQL client on CentOS/RHEL:"
        echo "  sudo yum install mysql"
        echo ""
        return 1
    fi
    return 0
}

# Check database connection
check_database_connection() {
    if ! check_mysql_client; then
        return 1
    fi
    
    if mysql -h "$DB_HOST" -u "$DB_USER" -p"$DB_PASS" -e "SELECT 1;" &>/dev/null; then
        return 0
    else
        return 1
    fi
}

# Check if database exists
check_database_exists() {
    if mysql -h "$DB_HOST" -u "$DB_USER" -p"$DB_PASS" -e "USE $DB_NAME;" &>/dev/null; then
        return 0
    else
        return 1
    fi
}

# Create database
create_database() {
    print_step "Setting up database..."
    
    echo ""
    print_prompt "Database '$DB_NAME' not found. Do you want to create it? (y/n)"
    read -p "Enter choice [y]: " create_db
    
    if [[ "$create_db" =~ ^[Nn]$ ]]; then
        print_error "Database setup cancelled"
        exit 1
    fi
    
    print_info "Creating database and user..."
    
    mysql -h "$DB_HOST" -u "$DB_USER" -p"$DB_PASS" << MYSQL_EOF
CREATE DATABASE IF NOT EXISTS ${DB_NAME} CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER IF NOT EXISTS '${DB_USER}'@'${DB_HOST}' IDENTIFIED BY '${DB_PASS}';
GRANT ALL PRIVILEGES ON ${DB_NAME}.* TO '${DB_USER}'@'${DB_HOST}';
FLUSH PRIVILEGES;
MYSQL_EOF
    
    if [ $? -eq 0 ]; then
        print_success "Database and user created successfully"
    else
        print_error "Failed to create database"
        exit 1
    fi
}

# Check if tables exist
check_tables_exist() {
    local table_count=$(mysql -h "$DB_HOST" -u "$DB_USER" -p"$DB_PASS" -D "$DB_NAME" -e "SHOW TABLES;" 2>/dev/null | wc -l)
    if [ "$table_count" -gt 1 ]; then
        return 0
    else
        return 1
    fi
}

# Run migration
run_migration() {
    print_step "Running database migration..."
    
    # Create migration script
    # Create migration script with variable substitution
    cat > "$SCRIPT_DIR/temp_migration.py" << EOF
#!/usr/bin/env python3
import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app import app, db
from models import User, AuditLog

def migrate():
    with app.app_context():
        print("🔄 Running database migration...")
        
        # Create all tables
        db.create_all()
        print("✅ Tables created/updated")
        
        # Get admin password from command line argument
        admin_password = sys.argv[1] if len(sys.argv) > 1 else "admin123"
        
        # Check if admin user exists
        admin_user = User.query.filter_by(username="admin").first()
        if not admin_user:
            print("👤 Creating admin user...")
            admin_user = User(
                username="admin",
                email="admin@localhost",
                is_admin=True,
                is_active=True,
                totp_enabled=False
            )
            admin_user.set_password(admin_password)
            admin_user.generate_totp_secret()
            db.session.add(admin_user)
            db.session.commit()
            print("✅ Admin user created")
        else:
            print("👤 Admin user already exists")
            # Always update password to ensure it is correct
            admin_user.set_password(admin_password)
            db.session.commit()
            print("✅ Admin password updated")
        
        print("🎉 Migration completed successfully!")

if __name__ == "__main__":
    migrate()
EOF
    
    # Ensure virtual environment is activated and run migration
    source "$VENV_DIR/bin/activate"
    cd "$SCRIPT_DIR"
    python3 temp_migration.py "${ADMIN_PASSWORD}"
    local migration_result=$?
    
    # Clean up
    rm -f "$SCRIPT_DIR/temp_migration.py"
    
    if [ $migration_result -eq 0 ]; then
        print_success "Migration completed successfully"
        return 0
    else
        print_error "Migration failed"
        return 1
    fi
}

# Install packages
install_packages() {
    print_step "Installing Python packages..."
    
    # Ensure virtual environment is activated
    if [[ -f "$VENV_DIR/bin/activate" ]]; then
        source "$VENV_DIR/bin/activate"
    else
        print_error "Virtual environment not found at $VENV_DIR"
        return 1
    fi
    
    # Upgrade pip first
    print_info "Upgrading pip..."
    pip install --upgrade pip --force-reinstall
    
    local packages=(
        "flask>=2.3.0"
        "flask-sqlalchemy>=3.1.0"
        "pymysql>=1.1.0"
        "pyotp>=2.9.0"
        "qrcode>=8.2.0"
        "pillow>=11.0.0"
        "werkzeug>=2.3.0"
        "paramiko>=2.12.0"
    )
    
    for package in "${packages[@]}"; do
        print_info "Installing $package..."
        # Use --ignore-installed to avoid conflicts with system packages
        pip install "$package" --ignore-installed --force-reinstall
    done
    
    print_success "All packages installed"
}

# Check if Python3 is installed
check_python3() {
    if ! command -v python3 &> /dev/null; then
        print_error "Python3 is not installed"
        echo ""
        print_info "To install Python3 on Ubuntu/Debian:"
        echo "  sudo apt update && sudo apt install python3 python3-pip python3-venv"
        echo ""
        print_info "To install Python3 on CentOS/RHEL:"
        echo "  sudo yum install python3 python3-pip"
        echo ""
        return 1
    fi
    return 0
}

# Create virtual environment
create_venv() {
    print_step "Setting up virtual environment..."
    
    if ! check_python3; then
        exit 1
    fi
    
    # Remove existing venv if it's corrupted
    if [ -d "$VENV_DIR" ] && [ ! -f "$VENV_DIR/bin/activate" ]; then
        print_warning "Corrupted virtual environment found, removing..."
        rm -rf "$VENV_DIR"
    fi
    
    if [ -d "$VENV_DIR" ] && [ -f "$VENV_DIR/bin/activate" ]; then
        print_info "Virtual environment already exists"
    else
        print_info "Creating virtual environment..."
        python3 -m venv "$VENV_DIR"
        if [ $? -eq 0 ]; then
            print_success "Virtual environment created"
        else
            print_error "Failed to create virtual environment"
            exit 1
        fi
    fi
    
    # Verify activation script exists
    if [[ -f "$VENV_DIR/bin/activate" ]]; then
        source "$VENV_DIR/bin/activate"
        print_success "Virtual environment activated"
    else
        print_error "Virtual environment activation script not found"
        exit 1
    fi
}

# Start application
start_app() {
    print_step "Starting Secure Docker Web Manager..."
    
    if [ ! -f "$APP_FILE" ]; then
        print_error "Application file not found: $APP_FILE"
        exit 1
    fi
    
    # Ensure virtual environment is activated
    if [[ -f "$VENV_DIR/bin/activate" ]]; then
        source "$VENV_DIR/bin/activate"
        print_info "Virtual environment activated"
    else
        print_error "Virtual environment not found. Please run install first."
        exit 1
    fi
    
    print_info "Starting web server on http://localhost:5000"
    print_info "Press Ctrl+C to stop the server"
    echo ""
    
    # Use the python from the virtual environment
    "$VENV_DIR/bin/python" "$APP_FILE"
}

# Show help
show_help() {
    echo "Usage: $0 [OPTION]"
    echo ""
    echo "Options:"
    echo "  install    Install dependencies and setup environment"
    echo "  start      Start the application (default)"
    echo "  migrate    Run database migration only"
    echo "  status     Show application status"
    echo "  clean      Remove virtual environment and config files"
    echo "  help       Show this help message"
    echo ""
}

# Show status
show_status() {
    print_step "Application Status"
    echo ""
    
    if [ -d "$VENV_DIR" ]; then
        print_success "Virtual environment: $VENV_DIR"
    else
        print_error "Virtual environment: Not found"
    fi
    
    if [ -f "$APP_FILE" ]; then
        print_success "Application file: $APP_FILE"
    else
        print_error "Application file: Not found"
    fi
    
    if check_database_connection; then
        if check_database_exists; then
            print_success "Database: Connected and exists"
            if check_tables_exist; then
                print_success "Tables: Present"
            else
                print_warning "Tables: Missing (run migration)"
            fi
        else
            print_warning "Database: Connected but database doesn't exist"
        fi
    else
        print_error "Database: Not connected"
    fi
    
    if pgrep -f "python3.*app.py" > /dev/null; then
        print_success "Server status: Running"
        print_info "Access: http://localhost:5000"
    else
        print_warning "Server status: Not running"
    fi
    
    echo ""
}

# Main function
main() {
    print_header
    
    # Try to load existing configuration
    if load_config; then
        print_info "Loaded existing configuration"
    fi
    
    case "${1:-start}" in
        "install")
            prompt_mysql_credentials
            prompt_admin_password
            create_venv
            install_packages
            
            if ! check_database_connection; then
                print_error "Cannot connect to database. Please check MySQL service and credentials."
                exit 1
            fi
            
            if ! check_database_exists; then
                create_database
            fi
            
            run_migration
            print_success "Installation completed successfully!"
            ;;
        "start")
            # Check if credentials are already set (from config file or previous run)
            if [[ -z "$DB_HOST" || -z "$DB_USER" || -z "$DB_PASS" ]]; then
                prompt_mysql_credentials
            fi
            
            create_venv
            install_packages
            
            if ! check_database_connection; then
                print_error "Cannot connect to database. Please check MySQL service and credentials."
                exit 1
            fi
            
            if ! check_database_exists; then
                create_database
            fi
            
            if ! check_tables_exist; then
                prompt_admin_password
                run_migration
            fi
            
            start_app
            ;;
        "migrate")
            if [[ -z "$DB_HOST" || -z "$DB_USER" || -z "$DB_PASS" ]]; then
                prompt_mysql_credentials
            fi
            
            create_venv
            install_packages
            
            if ! check_database_connection; then
                print_error "Cannot connect to database"
                exit 1
            fi
            
            if ! check_database_exists; then
                create_database
            fi
            
            prompt_admin_password
            run_migration
            print_success "Migration completed!"
            ;;
        "status")
            show_status
            ;;
        "clean")
            print_step "Cleaning virtual environment..."
            if [ -d "$VENV_DIR" ]; then
                rm -rf "$VENV_DIR"
                print_success "Virtual environment removed"
            else
                print_info "No virtual environment found"
            fi
            if [ -f "$CONFIG_FILE" ]; then
                rm -f "$CONFIG_FILE"
                print_success "Configuration file removed"
            else
                print_info "No configuration file found"
            fi
            print_success "Clean completed"
            ;;
        "help"|"-h"|"--help")
            show_help
            ;;
        *)
            print_error "Unknown option: $1"
            show_help
            exit 1
            ;;
    esac
}

# Run main function
main "$@"
