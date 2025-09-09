#!/bin/bash

# Script to set Docker container restart policies
# This ensures containers automatically start after system reboot

# Color definitions
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Detect preferred docker compose command
detect_docker_compose() {
    # Try docker compose (v2) first - preferred method
    if docker compose version >/dev/null 2>&1; then
        echo "docker compose"
        return 0
    # Fallback to docker-compose (v1) if v2 is not available
    elif command -v docker-compose >/dev/null 2>&1; then
        echo "docker-compose"
        return 0
    else
        echo -e "${RED}Error: Neither 'docker compose' nor 'docker-compose' is available${NC}" >&2
        return 1
    fi
}

# Function to find Frappe sites by running containers
find_frappe_sites() {
    local sites=()
    # Use docker ps to find containers and extract project names
    local project_names=$(docker ps -a --format '{{.Names}}' | awk -F'-' '{print $1}' | sort | uniq)
    
    for project in $project_names; do
        # Check if this project has Frappe-related containers
        if docker ps -a --format '{{.Names}}' | grep -q "^${project}-"; then
            sites+=("$project")
        fi
    done
    
    echo "${sites[@]}"
}

# Function to set restart policy for all containers of a site
set_container_restart_policy() {
    local site_name=$1
    
    echo -e "${BLUE}🔄 Setting restart policy for $site_name containers...${NC}"
    
    # Get all containers for this site
    local containers=$(docker ps -a --filter "name=^${site_name}-" --format "{{.Names}}")
    
    if [[ -z "$containers" ]]; then
        echo -e "${YELLOW}⚠️  No containers found for $site_name${NC}"
        return 1
    fi
    
    # For each container, set restart policy to 'always'
    for container in $containers; do
        echo -e "${GREEN}📌 Setting restart policy for $container to 'always'${NC}"
        if docker update --restart=always "$container"; then
            echo -e "${GREEN}✅ Successfully set restart policy for $container${NC}"
        else
            echo -e "${RED}❌ Failed to set restart policy for $container${NC}"
        fi
    done
    
    # If there's a docker-compose file, update it too for future rebuilds
    local compose_file="${site_name}-docker-compose.yml"
    local compose_file_in_dir="${site_name}/${site_name}-docker-compose.yml"
    
    if [[ -f "$compose_file" ]]; then
        echo -e "${BLUE}📝 Updating docker-compose file: $compose_file${NC}"
        sed -i 's/\(^\s*\)\(container_name:\)/\1restart: always\n\1\2/g' "$compose_file"
        echo -e "${GREEN}✅ Updated $compose_file with restart policy${NC}"
    elif [[ -f "$compose_file_in_dir" ]]; then
        echo -e "${BLUE}📝 Updating docker-compose file: $compose_file_in_dir${NC}"
        sed -i 's/\(^\s*\)\(container_name:\)/\1restart: always\n\1\2/g' "$compose_file_in_dir"
        echo -e "${GREEN}✅ Updated $compose_file_in_dir with restart policy${NC}"
    else
        echo -e "${YELLOW}ℹ️  No docker-compose file found for $site_name${NC}"
        echo -e "${YELLOW}ℹ️  Containers will restart automatically, but restart policy won't be preserved in rebuilds${NC}"
    fi
    
    echo -e "${GREEN}✅ All $site_name containers now set to restart automatically after system reboot${NC}"
}

# Main function
main() {
    echo -e "${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║           Docker Container Restart Policy Setter            ║${NC}"
    echo -e "${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    # Check if Docker is running
    if ! docker info >/dev/null 2>&1; then
        echo -e "${RED}❌ Docker is not running or you don't have permission to access it${NC}"
        echo "Please start Docker and try again."
        exit 1
    fi
    
    # Find Frappe sites
    local sites=($(find_frappe_sites))
    if [[ ${#sites[@]} -eq 0 ]]; then
        echo -e "${YELLOW}⚠️  No Frappe sites found in containers${NC}"
        echo "No containers to update."
        exit 1
    fi
    
    echo -e "${GREEN}✅ Found ${#sites[@]} Frappe site(s):${NC}"
    for ((i=0; i<${#sites[@]}; i++)); do
        echo -e "${GREEN}$((i+1)).${NC} ${sites[$i]}"
    done
    echo ""
    
    echo -e "${CYAN}Options:${NC}"
    echo "1. Update restart policy for all sites"
    echo "2. Select a specific site to update"
    read -p "Enter your choice (1-2): " choice
    
    case $choice in
        1)
            echo -e "${GREEN}🔄 Setting restart policy for ALL sites...${NC}"
            for site in "${sites[@]}"; do
                set_container_restart_policy "$site"
                echo ""
            done
            echo -e "${GREEN}🎉 All sites updated successfully!${NC}"
            ;;
        2)
            echo -e "${CYAN}Select a site to update:${NC}"
            select site in "${sites[@]}"; do
                if [[ -n "$site" ]]; then
                    set_container_restart_policy "$site"
                    echo -e "${GREEN}🎉 Site $site updated successfully!${NC}"
                    break
                fi
            done
            ;;
        *)
            echo -e "${RED}❌ Invalid option. Exiting.${NC}"
            exit 1
            ;;
    esac
    
    echo ""
    echo -e "${GREEN}✅ Done! Your containers should now start automatically after system reboot.${NC}"
}

# Run main function
main




