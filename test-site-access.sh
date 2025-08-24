#!/bin/bash

# Color definitions
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}===============================================${NC}"
echo -e "${BLUE}        Site Accessibility Test Script        ${NC}"
echo -e "${BLUE}===============================================${NC}"
echo ""

# Check if Traefik is running
if docker ps --filter "name=traefik" --format "{{.Names}}" | grep -q "traefik"; then
    echo -e "${GREEN}✅ Traefik is running${NC}"
else
    echo -e "${RED}❌ Traefik is not running${NC}"
    exit 1
fi

echo ""

# Get all running Frappe sites
echo -e "${BLUE}🔍 Checking running Frappe sites...${NC}"
docker ps --filter "name=frontend" --format "{{.Names}}" | grep -E ".*-frontend$" | while read -r container; do
    # Extract site name from container name
    site_name=$(echo "$container" | sed 's/-frontend$//' | sed 's/.*_//')
    
    # Get the actual domain from Traefik labels
    domain=$(docker inspect "$container" | grep -o 'Host(`[^`]*`)' | sed 's/Host(`//' | sed 's/`)//')
    
    if [[ -n "$domain" ]]; then
        echo -e "${BLUE}📋 Testing: $domain${NC}"
        
        # Test site accessibility
        if curl -s -I "http://$domain" | grep -q "HTTP/1.1 200"; then
            echo -e "  ${GREEN}✅ Accessible at: http://$domain${NC}"
        else
            echo -e "  ${RED}❌ Not accessible at: http://$domain${NC}"
        fi
        
        # Check if domain is in hosts file (for non-localhost domains)
        if [[ ! $domain =~ \.localhost$ ]]; then
            if grep -q "$domain" /etc/hosts; then
                echo -e "  ${GREEN}✅ Domain found in hosts file${NC}"
            else
                echo -e "  ${RED}❌ Domain NOT in hosts file${NC}"
            fi
        else
            echo -e "  ${GREEN}✅ Localhost domain - no hosts file needed${NC}"
        fi
        
        echo ""
    fi
done

echo -e "${BLUE}===============================================${NC}"
echo -e "${BLUE}           Test Complete!                     ${NC}"
echo -e "${BLUE}===============================================${NC}"
echo ""
echo -e "${GREEN}💡 To manage hosts file entries: ./manage-hosts.sh${NC}"
echo -e "${GREEN}💡 To create new sites: ./generate_frappe_docker_local.sh${NC}"
