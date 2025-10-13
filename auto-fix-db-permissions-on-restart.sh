#!/bin/bash

# Auto-fix database permissions on container restart
# This script should be run after containers restart to handle IP changes

# Color definitions
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}🔧 Auto-fixing database permissions for all running sites...${NC}"
echo "=========================================================="

# Find all running app containers
APP_CONTAINERS=$(docker ps --filter "name=-app" --format "{{.Names}}" | grep -E "_local-app$|_vps-app$")

if [ -z "$APP_CONTAINERS" ]; then
    echo -e "${YELLOW}⚠️  No app containers found${NC}"
    exit 0
fi

# Fix permissions for each container
for container in $APP_CONTAINERS; do
    echo ""
    echo -e "${BLUE}📍 Processing: $container${NC}"
    
    # Run the fix script
    /var/www/html/frappe-docker/fix-db-permissions.sh "$container" 2>/dev/null
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✅ Fixed permissions for $container${NC}"
    else
        echo -e "${YELLOW}⚠️  Could not fix permissions for $container${NC}"
    fi
done

echo ""
echo -e "${GREEN}🎉 Auto-fix completed for all sites!${NC}"
echo ""
echo -e "${BLUE}💡 To run this automatically on system boot, add this to crontab:${NC}"
echo "   @reboot sleep 60 && /var/www/html/frappe-docker/auto-fix-db-permissions-on-restart.sh"

