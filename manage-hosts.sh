#!/bin/bash

# Color definitions
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}===============================================${NC}"
echo -e "${BLUE}        Hosts File Management Script         ${NC}"
echo -e "${BLUE}===============================================${NC}"
echo ""

# Check if running with sudo (needed for hosts file management)
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}❌ This script must be run with sudo for hosts file management${NC}"
    echo -e "${YELLOW}💡 Please run: sudo ./manage-hosts.sh${NC}"
    exit 1
fi

# Function to show current hosts file entries
show_hosts_entries() {
    echo -e "${BLUE}📋 Current hosts file entries:${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    # Show custom entries (excluding localhost and system entries)
    grep -E "^127\.0\.0\.1\s+[a-zA-Z0-9.-]+" /etc/hosts | while read -r line; do
        echo -e "${GREEN}✅ $line${NC}"
    done
    
    # Show if no custom entries found
    if ! grep -q -E "^127\.0\.0\.1\s+[a-zA-Z0-9.-]+" /etc/hosts; then
        echo -e "${YELLOW}No custom domain entries found in hosts file${NC}"
    fi
    echo ""
}

# Function to add a domain
add_domain() {
    local domain=$1
    if [[ -z "$domain" ]]; then
        read -p "Enter domain to add: " domain
    fi
    
    if [[ -z "$domain" ]]; then
        echo -e "${RED}❌ No domain specified${NC}"
        return 1
    fi
    
    # Check if domain already exists
    if grep -q "$domain" /etc/hosts; then
        echo -e "${YELLOW}⚠️  Domain $domain already exists in hosts file${NC}"
        return 0
    fi
    
    # Add domain to hosts file
            if echo "127.0.0.1 $domain" | tee -a /etc/hosts > /dev/null; then
        echo -e "${GREEN}✅ Added $domain to hosts file${NC}"
        echo -e "${BLUE}   You can now access: http://$domain${NC}"
    else
        echo -e "${RED}❌ Failed to add domain to hosts file${NC}"
        return 1
    fi
}

# Function to remove a domain
remove_domain() {
    local domain=$1
    if [[ -z "$domain" ]]; then
        read -p "Enter domain to remove: " domain
    fi
    
    if [[ -z "$domain" ]]; then
        echo -e "${RED}❌ No domain specified${NC}"
        return 1
    fi
    
    # Check if domain exists
    if ! grep -q "$domain" /etc/hosts; then
        echo -e "${YELLOW}⚠️  Domain $domain not found in hosts file${NC}"
        return 0
    fi
    
            # Remove domain from hosts file
        sed "/$domain/d" /etc/hosts > /tmp/hosts.tmp
        if mv /tmp/hosts.tmp /etc/hosts; then
        echo -e "${GREEN}✅ Removed $domain from hosts file${NC}"
    else
        echo -e "${RED}❌ Failed to remove domain from hosts file${NC}"
        return 1
    fi
}

# Function to clean up all custom entries
cleanup_all() {
    echo -e "${YELLOW}⚠️  This will remove ALL custom domain entries from hosts file${NC}"
    read -p "Are you sure? (y/n): " confirm
    
    if [[ "$confirm" =~ ^[Yy]$ ]]; then
        # Create backup
        cp /etc/hosts /etc/hosts.backup.$(date +%Y%m%d_%H%M%S)
        echo -e "${BLUE}📋 Backup created: /etc/hosts.backup.$(date +%Y%m%d_%H%M%S)${NC}"
        
        # Remove all custom entries (keep system entries)
        sed '/^127\.0\.0\.1\s+[a-zA-Z0-9.-]\+$/d' /etc/hosts > /tmp/hosts.tmp
        if mv /tmp/hosts.tmp /etc/hosts; then
            echo -e "${GREEN}✅ Cleaned up all custom domain entries${NC}"
        else
            echo -e "${RED}❌ Failed to clean up hosts file${NC}"
            return 1
        fi
    else
        echo -e "${YELLOW}Cleanup cancelled${NC}"
    fi
}

# Function to restore backup
restore_backup() {
    echo -e "${BLUE}📋 Available backups:${NC}"
    ls -la /etc/hosts.backup.* 2>/dev/null | while read -r line; do
        echo "  $line"
    done
    
    if ! ls /etc/hosts.backup.* >/dev/null 2>&1; then
        echo -e "${YELLOW}No backups found${NC}"
        return 1
    fi
    
    read -p "Enter backup filename to restore: " backup_file
    if [[ -f "$backup_file" ]]; then
        if cp "$backup_file" /etc/hosts; then
            echo -e "${GREEN}✅ Restored hosts file from backup${NC}"
        else
            echo -e "${RED}❌ Failed to restore hosts file${NC}"
        fi
    else
        echo -e "${RED}❌ Backup file not found${NC}"
    fi
}

# Main menu
while true; do
    echo ""
    echo -e "${BLUE}Choose an option:${NC}"
    echo "1) Show current hosts file entries"
    echo "2) Add a domain"
    echo "3) Remove a domain"
    echo "4) Clean up all custom entries"
    echo "5) Restore from backup"
    echo "6) Exit"
    echo ""
    read -p "Enter your choice (1-6): " choice
    
    case $choice in
        1)
            show_hosts_entries
            ;;
        2)
            add_domain
            ;;
        3)
            remove_domain
            ;;
        4)
            cleanup_all
            ;;
        5)
            restore_backup
            ;;
        6)
            echo -e "${GREEN}Goodbye!${NC}"
            exit 0
            ;;
        *)
            echo -e "${RED}Invalid choice. Please enter 1-6.${NC}"
            ;;
    esac
done
