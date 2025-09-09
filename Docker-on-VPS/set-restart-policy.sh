#!/bin/bash

# Auto-Restart Policy Setter for Docker on VPS
# This script adds "restart: always" policy to all containers in docker-compose files

# Color definitions
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m' # No Color

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Function to print header
print_header() {
    echo -e "${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║              Auto-Restart Policy Setter v1.0                ║${NC}"
    echo -e "${BLUE}║         For Frappe/ERPNext Production Setup on VPS         ║${NC}"
    echo -e "${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

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

# Function to add restart policy to a single docker-compose file
add_restart_policy() {
    local compose_file=$1
    local temp_file="${compose_file}.temp"
    
    echo -e "${BLUE}📝 Adding auto-restart policy to containers in ${compose_file}...${NC}"
    
    # Check if file exists
    if [[ ! -f "$compose_file" ]]; then
        echo -e "${RED}❌ File not found: $compose_file${NC}"
        return 1
    fi
    
    # Check if the file already contains restart policies
    if grep -q "restart:" "$compose_file"; then
        echo -e "${YELLOW}⚠️  File already contains restart policies. Checking for missing entries...${NC}"
        
        # Count services without restart policy
        local services_without_restart=$(grep -A1 "container_name:" "$compose_file" | grep -v "restart:" | grep -c "container_name:")
        
        if [ "$services_without_restart" -eq 0 ]; then
            echo -e "${GREEN}✅ All services already have restart policies. No changes needed.${NC}"
            return 0
        else
            echo -e "${BLUE}🔄 Found $services_without_restart service(s) without restart policy. Adding them...${NC}"
        fi
    fi
    
    # Add restart policy before each container_name line that doesn't have one
    sed 's/\(^\s*\)\(container_name:\)/\1restart: always\n\1\2/g' "$compose_file" > "$temp_file"
    
    # Count the number of restart policies added
    local added_policies=$(grep -c "restart: always" "$temp_file")
    local original_policies=$(grep -c "restart: always" "$compose_file")
    local new_policies=$((added_policies - original_policies))
    
    # Replace original file with the modified one
    mv "$temp_file" "$compose_file"
    
    echo -e "${GREEN}✅ Added restart policies to $new_policies container(s) in $compose_file${NC}"
    
    return 0
}

# Function to apply changes and restart containers
apply_and_restart() {
    local site_name=$1
    local compose_file="${site_name}/${site_name}-docker-compose.yml"
    
    echo -e "${CYAN}🔄 Applying changes and restarting containers for $site_name...${NC}"
    
    # Check if file exists
    if [[ ! -f "$compose_file" ]]; then
        echo -e "${RED}❌ Docker compose file not found: $compose_file${NC}"
        return 1
    fi
    
    # Get docker compose command
    DOCKER_COMPOSE_CMD=$(detect_docker_compose)
    if [ $? -ne 0 ]; then
        echo -e "${RED}❌ Failed to detect docker compose command${NC}"
        return 1
    fi
    
    # Apply changes
    echo -e "${BLUE}🔄 Restarting services to apply restart policies...${NC}"
    $DOCKER_COMPOSE_CMD -f "$compose_file" up -d
    
    echo -e "${GREEN}✅ Successfully applied restart policies to $site_name containers${NC}"
    
    return 0
}

# Function to process all sites
process_all_sites() {
    local sites=($(find_frappe_sites))
    if [[ ${#sites[@]} -eq 0 ]]; then
        echo -e "${YELLOW}⚠️  No Frappe sites found in running containers${NC}"
        return 1
    fi
    
    echo -e "${GREEN}✅ Found ${#sites[@]} Frappe site(s):${NC}"
    for site in "${sites[@]}"; do
        echo -e "   • ${site}"
    done
    echo ""
    
    local success_count=0
    
    for site in "${sites[@]}"; do
        echo -e "${BLUE}🔧 Processing site: $site${NC}"
        
        # Path to docker-compose file
        local compose_file="${site}/${site}-docker-compose.yml"
        
        # Check if docker-compose file exists
        if [[ ! -f "$compose_file" ]]; then
            echo -e "${YELLOW}⚠️  Docker compose file not found for $site: $compose_file${NC}"
            continue
        fi
        
        # Add restart policy
        add_restart_policy "$compose_file"
        if [ $? -eq 0 ]; then
            # Apply changes
            apply_and_restart "$site"
            if [ $? -eq 0 ]; then
                ((success_count++))
            fi
        fi
        
        echo ""
    done
    
    echo -e "${GREEN}✅ Successfully processed $success_count out of ${#sites[@]} sites${NC}"
    
    return 0
}

# Function to process a single site
process_single_site() {
    local site_name=$1
    
    echo -e "${BLUE}🔧 Processing site: $site_name${NC}"
    
    # Path to docker-compose file
    local compose_file="${site_name}/${site_name}-docker-compose.yml"
    
    # Check if docker-compose file exists
    if [[ ! -f "$compose_file" ]]; then
        echo -e "${RED}❌ Docker compose file not found: $compose_file${NC}"
        return 1
    fi
    
    # Add restart policy
    add_restart_policy "$compose_file"
    if [ $? -eq 0 ]; then
        # Apply changes
        apply_and_restart "$site_name"
        return $?
    else
        return 1
    fi
}

# Main function
main() {
    print_header
    
    # Check if Docker is running
    if ! docker info >/dev/null 2>&1; then
        echo -e "${RED}❌ Docker is not running or you don't have permission to access it${NC}"
        echo "Please start Docker and try again."
        exit 1
    fi
    
    # Check if a site name was provided
    if [ $# -eq 1 ]; then
        # Process specific site
        site_name=$1
        process_single_site "$site_name"
    else
        # Process all sites
        process_all_sites
    fi
    
    echo -e "${GREEN}🎉 Auto-restart policy configuration completed!${NC}"
    echo -e "${BLUE}💡 Your containers will now automatically restart on system reboot.${NC}"
}

# If script is being executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
