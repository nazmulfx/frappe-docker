#!/bin/bash

# Docker Manager Local - For Frappe/ERPNext Local Optimized Setup
# This script manages containers created by generate_frappe_docker_local_optimized.sh

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

# Function to print header
print_header() {
    echo -e "${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║                Docker Manager Local v1.0                    ║${NC}"
    echo -e "${BLUE}║         Frappe/ERPNext Local Optimized Setup                ║${NC}"
    echo -e "${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

# Function to check if Docker is running
check_docker() {
    if ! docker info >/dev/null 2>&1; then
        echo -e "${RED}❌ Docker is not running or you don't have permission to access it${NC}"
        echo "Please start Docker and try again."
        exit 1
    fi
}

# Function to find Frappe sites by running containers (like docker-manager.sh)
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

# Function to show running containers
show_running_containers() {
    echo -e "${CYAN}📋 Currently Running Frappe Containers:${NC}"
    echo ""
    
    local sites=($(find_frappe_sites))
    if [[ ${#sites[@]} -eq 0 ]]; then
        echo -e "${YELLOW}No Frappe sites found in running containers${NC}"
        return
    fi
    
    for site in "${sites[@]}"; do
        echo -e "${BLUE}🏠 Site: ${site}${NC}"
        
        # Show containers for this site
        local site_containers=$(docker ps --filter "name=^${site}-" --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}")
        if [[ -n "$site_containers" ]]; then
            echo "$site_containers" | grep -v "NAME"
        else
            echo -e "${YELLOW}  No containers running${NC}"
        fi
        echo ""
    done
}

# Function to access container shell
access_container() {
    local site_name=$1
    local access_type=$2
    
    case $access_type in
        "normal")
            echo -e "${GREEN}🔧 Accessing $site_name-app container as frappe user...${NC}"
            docker exec -it "$site_name-app" bash
            ;;
        "root")
            echo -e "${GREEN}🔧 Accessing $site_name-app container as root user...${NC}"
            docker exec -it --user root "$site_name-app" bash
            ;;
        *)
            echo -e "${RED}❌ Invalid access type${NC}"
            return 1
            ;;
    esac
}

# Function to manage Frappe processes via Supervisor
manage_frappe_processes() {
    local site_name=$1
    local action=$2
    local process=$3
    
    case $action in
        "status")
            echo -e "${CYAN}📊 Frappe Process Status for $site_name:${NC}"
            docker exec "$site_name-app" /home/frappe/.local/bin/supervisorctl -c /home/frappe/supervisor/supervisord.conf status
            ;;
        "restart")
            if [[ -n "$process" ]]; then
                echo -e "${GREEN}🔄 Restarting $process process in $site_name...${NC}"
                docker exec "$site_name-app" /home/frappe/.local/bin/supervisorctl -c /home/frappe/supervisor/supervisord.conf restart "$process"
            else
                echo -e "${GREEN}🔄 Restarting all Frappe processes in $site_name...${NC}"
                docker exec "$site_name-app" /home/frappe/.local/bin/supervisorctl -c /home/frappe/supervisor/supervisord.conf restart all
            fi
            ;;
        "stop")
            if [[ -n "$process" ]]; then
                echo -e "${YELLOW}⏹️  Stopping $process process in $site_name...${NC}"
                docker exec "$site_name-app" /home/frappe/.local/bin/supervisorctl -c /home/frappe/supervisor/supervisord.conf stop "$process"
            else
                echo -e "${YELLOW}⏹️  Stopping all Frappe processes in $site_name...${NC}"
                docker exec "$site_name-app" /home/frappe/.local/bin/supervisorctl -c /home/frappe/supervisor/supervisord.conf stop all
            fi
            ;;
        "start")
            if [[ -n "$process" ]]; then
                echo -e "${GREEN}▶️  Starting $process process in $site_name...${NC}"
                docker exec "$site_name-app" /home/frappe/.local/bin/supervisorctl -c /home/frappe/supervisor/supervisord.conf start "$process"
            else
                echo -e "${GREEN}▶️  Starting all Frappe processes in $site_name...${NC}"
                docker exec "$site_name-app" /home/frappe/.local/bin/supervisorctl -c /home/frappe/supervisor/supervisord.conf start all
            fi
            ;;
        *)
            echo -e "${RED}❌ Invalid action${NC}"
            return 1
            ;;
    esac
}

# Function to view logs
view_logs() {
    local site_name=$1
    local log_type=$2
    
    case $log_type in
        "web")
            echo -e "${CYAN}📋 Viewing Frappe Web logs for $site_name...${NC}"
            docker exec "$site_name-app" tail -f /home/frappe/supervisor/logs/frappe-web.log
            ;;
        "worker")
            echo -e "${CYAN}📋 Viewing Frappe Worker logs for $site_name...${NC}"
            docker exec "$site_name-app" tail -f /home/frappe/supervisor/logs/frappe-worker-default.log
            ;;
        "schedule")
            echo -e "${CYAN}📋 Viewing Frappe Schedule logs for $site_name...${NC}"
            docker exec "$site_name-app" tail -f /home/frappe/supervisor/logs/frappe-schedule.log
            ;;
        "websocket")
            echo -e "${CYAN}📋 Viewing Frappe WebSocket logs for $site_name...${NC}"
            docker exec "$site_name-app" tail -f /home/frappe/supervisor/logs/frappe-websocket.log
            ;;
        "supervisor")
            echo -e "${CYAN}📋 Viewing Supervisor logs for $site_name...${NC}"
            docker exec "$site_name-app" tail -f /home/frappe/supervisor/logs/supervisord.log
            ;;
        "container")
            echo -e "${CYAN}📋 Viewing container logs for $site_name...${NC}"
            docker logs -f "$site_name-app"
            ;;
        "create-site")
            echo -e "${CYAN}📋 Viewing Create-Site logs for $site_name...${NC}"
            docker logs -f "$site_name-create-site"
            ;;
        *)
            echo -e "${RED}❌ Invalid log type${NC}"
            return 1
            ;;
    esac
}

# Function to manage containers
manage_containers() {
    local site_name=$1
    local action=$2
    
    case $action in
        "start")
            echo -e "${GREEN}🚀 Starting containers for $site_name...${NC}"
            docker start $(docker ps -a --filter "name=^${site_name}-" --format "{{.Names}}")
            ;;
        "stop")
            echo -e "${YELLOW}⏹️  Stopping containers for $site_name...${NC}"
            docker stop $(docker ps --filter "name=^${site_name}-" --format "{{.Names}}")
            ;;
        "restart")
            echo -e "${GREEN}🔄 Restarting containers for $site_name...${NC}"
            docker restart $(docker ps --filter "name=^${site_name}-" --format "{{.Names}}")
            ;;
        "rebuild")
            echo -e "${CYAN}🔨 Rebuilding containers for $site_name...${NC}"
            # Find docker-compose file if it exists
            if [[ -f "${site_name}-docker-compose.yml" ]]; then
                DOCKER_COMPOSE_CMD=$(detect_docker_compose)
                if [ $? -ne 0 ]; then
                    echo -e "${RED}❌ Failed to detect docker compose command${NC}"
                    return 1
                fi
                $DOCKER_COMPOSE_CMD -f "${site_name}-docker-compose.yml" down
                
                # Update docker-compose file to add restart policy
                echo -e "${BLUE}📝 Adding auto-restart policy to containers...${NC}"
                sed -i 's/\(^\s*\)\(container_name:\)/\1restart: always\n\1\2/g' "${site_name}-docker-compose.yml"
                
                $DOCKER_COMPOSE_CMD -f "${site_name}-docker-compose.yml" up -d --build
            else
                echo -e "${YELLOW}⚠️  No docker-compose file found for $site_name${NC}"
                echo "Containers will be restarted instead."
                docker restart $(docker ps --filter "name=^${site_name}-" --format "{{.Names}}")
            fi
            ;;
        "rebuild-with-apps")
            echo -e "${CYAN}🔨 Rebuilding containers with custom apps preservation for $site_name...${NC}"
            rebuild_with_custom_apps "$site_name"
            ;;
        "logs")
            echo -e "${CYAN}📋 Showing logs for $site_name...${NC}"
            docker logs $(docker ps --filter "name=^${site_name}-" --format "{{.Names}}")
            ;;
        "status")
            echo -e "${CYAN}📊 Container status for $site_name:${NC}"
            docker ps --filter "name=^${site_name}-"
            ;;
        *)
            echo -e "${RED}❌ Invalid action${NC}"
            return 1
            ;;
    esac
}

# Function to remove all containers for a site
remove_all_containers() {
    local site_name=$1
    
    echo -e "${RED}⚠️  WARNING: This will remove ALL containers for site: $site_name${NC}"
    echo -e "${YELLOW}This action cannot be undone!${NC}"
    echo ""
    
    # Show what will be removed
    echo -e "${CYAN}Containers that will be removed:${NC}"
    docker ps -a --filter "name=^${site_name}-" --format "table {{.Names}}\t{{.Status}}"
    echo ""
    
    # Show folders that will be removed
    echo -e "${CYAN}Folders that will be removed:${NC}"
    local site_folder="${site_name}"
    local vscode_folder=""
    
    # Determine VS Code folder path
    ACTUAL_USER_HOME=$(eval echo ~$SUDO_USER)
    if [ -z "$ACTUAL_USER_HOME" ] || [ "$ACTUAL_USER_HOME" = "~$SUDO_USER" ]; then
        ACTUAL_USER_HOME="$HOME"
    fi
    vscode_folder="${ACTUAL_USER_HOME}/frappe-docker/${site_name}-frappe-bench"
    
    if [[ -d "$site_folder" ]]; then
        echo -e "   📁 Site folder: ${site_folder}"
    fi
    if [[ -d "$vscode_folder" ]]; then
        echo -e "   💻 VS Code folder: ${vscode_folder}"
    fi
    echo ""
    
    read -p "⚠️  Are you absolutely sure you want to remove ALL containers? (y/n): " confirm1
    if [[ ! "$confirm1" =~ ^[Yy]$ ]]; then
        echo -e "${YELLOW}Operation cancelled.${NC}"
        return 0
    fi
    
    read -p "⚠️  FINAL CONFIRMATION: Type 'DELETE' to confirm removal: " confirm2
    if [[ "$confirm2" != "DELETE" ]]; then
        echo -e "${YELLOW}Removal cancelled - incorrect confirmation.${NC}"
        return 0
    fi
    
    echo -e "${RED}🗑️  Removing all containers for $site_name...${NC}"
    
    # Stop and remove containers
    docker stop $(docker ps --filter "name=^${site_name}-" --format "{{.Names}}") 2>/dev/null
    docker rm $(docker ps -a --filter "name=^${site_name}-" --format "{{.Names}}") 2>/dev/null
    
    echo -e "${GREEN}✅ All containers removed successfully!${NC}"
    
    # Remove site folder
    if [[ -d "$site_folder" ]]; then
        echo -e "${BLUE}🗑️  Removing site folder: $site_folder${NC}"
        rm -rf "$site_folder"
        echo -e "${GREEN}✅ Site folder removed successfully!${NC}"
    fi
    
    # Remove VS Code development folder
    if [[ -d "$vscode_folder" ]]; then
        echo -e "${BLUE}🗑️  Removing VS Code folder: $vscode_folder${NC}"
        rm -rf "$vscode_folder"
        echo -e "${GREEN}✅ VS Code folder removed successfully!${NC}"
    fi
    
    # Remove from hosts file if it exists
    local site_domain="${site_name//_/.}"
    if grep -q "$site_domain" /etc/hosts 2>/dev/null; then
        echo -e "${BLUE}🗑️  Removing $site_domain from hosts file${NC}"
        sudo sed -i "/$site_domain/d" /etc/hosts
        echo -e "${GREEN}✅ Hosts file entry removed successfully!${NC}"
    fi
    
    echo -e "${GREEN}🎉 Complete cleanup completed for $site_name!${NC}"
    
    # Offer cleanup
    read -p "🧹 Do you want to clean up unused Docker resources? (y/n): " cleanup_choice
    if [[ "$cleanup_choice" =~ ^[Yy]$ ]]; then
        cleanup_docker_space
    fi
}

# Function to remove specific container
remove_specific_container() {
    local site_name=$1
    
    echo -e "${CYAN}📋 Available containers for $site_name:${NC}"
    docker ps -a --filter "name=^${site_name}-" --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
    echo ""
    
    read -p "Enter container name to remove: " container_name
    if [[ -z "$container_name" ]]; then
        echo -e "${YELLOW}No container name provided.${NC}"
        return 1
    fi
    
    # Check if container exists
    if ! docker ps -a --format "{{.Names}}" | grep -q "^${container_name}$"; then
        echo -e "${RED}❌ Container $container_name not found.${NC}"
        return 1
    fi
    
    echo -e "${RED}⚠️  WARNING: This will permanently remove container: $container_name${NC}"
    read -p "⚠️  Are you sure you want to remove $container_name? (y/n): " confirm1
    if [[ ! "$confirm1" =~ ^[Yy]$ ]]; then
        echo -e "${YELLOW}Removal cancelled.${NC}"
        return 0
    fi
    
    read -p "⚠️  FINAL CONFIRMATION: Type 'REMOVE' to confirm: " confirm2
    if [[ "$confirm2" != "REMOVE" ]]; then
        echo -e "${YELLOW}Removal cancelled - incorrect confirmation.${NC}"
        return 0
    fi
    
    echo -e "${RED}🗑️  Removing container $container_name...${NC}"
    
    if docker rm -f "$container_name"; then
        echo -e "${GREEN}✅ Container $container_name removed successfully!${NC}"
    else
        echo -e "${RED}❌ Failed to remove container $container_name.${NC}"
        return 1
    fi
}

# Function to cleanup Docker space
cleanup_docker_space() {
    echo -e "${CYAN}🧹 Docker System Cleanup${NC}"
    echo ""
    
    # Show current space usage
    echo -e "${YELLOW}📊 Current Docker Space Usage:${NC}"
    docker system df
    echo ""
    
    echo "What would you like to clean up?"
    echo "1. Clean unused containers, networks, and dangling images (safe)"
    echo "2. Clean everything unused including volumes (removes data!)"
    echo "3. Clean only dangling images"
    echo "4. Clean only stopped containers"
    echo "5. Clean only unused volumes (removes data!)"
    echo "6. Clean only unused networks"
    echo "7. Cancel"
    
    read -p "Select cleanup option (1-7): " cleanup_option
    
    case $cleanup_option in
        1)
            echo -e "${GREEN}🧹 Cleaning containers, networks, and dangling images...${NC}"
            docker system prune -f
            ;;
        2)
            echo -e "${RED}⚠️  WARNING: This will remove ALL unused volumes and may delete important data!${NC}"
            read -p "⚠️  Are you sure you want to remove volumes? (y/n): " confirm_volumes
            if [[ "$confirm_volumes" == "y" ]]; then
                echo -e "${GREEN}🧹 Cleaning everything including volumes...${NC}"
                docker system prune -a --volumes -f
            else
                echo -e "${YELLOW}Volume cleanup cancelled.${NC}"
            fi
            ;;
        3)
            echo -e "${GREEN}🖼️  Cleaning dangling images...${NC}"
            docker image prune -f
            ;;
        4)
            echo -e "${GREEN}📦 Cleaning stopped containers...${NC}"
            docker container prune -f
            ;;
        5)
            echo -e "${RED}⚠️  WARNING: This will remove unused volumes and may delete data!${NC}"
            read -p "⚠️  Are you sure you want to remove unused volumes? (y/n): " confirm_vol
            if [[ "$confirm_vol" == "y" ]]; then
                echo -e "${GREEN}💾 Cleaning unused volumes...${NC}"
                docker volume prune -f
            else
                echo -e "${YELLOW}Volume cleanup cancelled.${NC}"
            fi
            ;;
        6)
            echo -e "${GREEN}🌐 Cleaning unused networks...${NC}"
            docker network prune -f
            ;;
        7)
            echo -e "${YELLOW}Cleanup cancelled.${NC}"
            return
            ;;
        *)
            echo -e "${RED}❌ Invalid option.${NC}"
            return
            ;;
    esac
    
    echo ""
    echo -e "${GREEN}✅ Cleanup completed!${NC}"
    echo -e "${GREEN}📊 Updated Docker Space Usage:${NC}"
    docker system df
}

# Function to access specific container as root
access_specific_container_root() {
    local site_name=$1
    
    echo -e "${CYAN}📋 Available containers for $site_name:${NC}"
    docker ps --filter "name=^${site_name}-" --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
    echo ""
    
    read -p "Enter container name to access as root: " container_name
    if [[ -z "$container_name" ]]; then
        echo -e "${YELLOW}No container name provided.${NC}"
        return 1
    fi
    
    # Check if container exists and is running
    if ! docker ps --format "{{.Names}}" | grep -q "^${container_name}$"; then
        echo -e "${RED}❌ Container $container_name not found or not running.${NC}"
        return 1
    fi
    
    echo -e "${GREEN}🔧 Accessing $container_name as root user...${NC}"
    docker exec -it --user root "$container_name" bash
}

# Function to transfer files
transfer_files() {
    local site_name=$1
    
    echo -e "${YELLOW}📁 File Transfer Options:${NC}"
    echo "1. Copy file TO container"
    echo "2. Copy file FROM container"
    read -p "Select transfer direction (1-2): " direction
    
    case $direction in
        1)
            # Copy TO container
            read -p "Enter source file path (on host): " source_path
            if [[ ! -f "$source_path" ]]; then
                echo -e "${RED}❌ Source file does not exist: $source_path${NC}"
                return 1
            fi
            
            echo -e "${CYAN}📋 Available containers for $site_name:${NC}"
            docker ps --filter "name=^${site_name}-" --format "table {{.Names}}\t{{.Status}}"
            read -p "Enter target container name: " container_name
            dest_path="/home/frappe/frappe-bench/"
            
            echo -e "${GREEN}📤 Copying file TO container...${NC}"
            echo "Source: $source_path"
            echo "Destination: $container_name:$dest_path"
            
            if docker cp "$source_path" "$container_name:$dest_path"; then
                echo -e "${GREEN}✅ File copied successfully!${NC}"
            else
                echo -e "${RED}❌ Failed to copy file to container.${NC}"
            fi
            ;;
        2)
            # Copy FROM container
            echo -e "${CYAN}📋 Available containers for $site_name:${NC}"
            docker ps --filter "name=^${site_name}-" --format "table {{.Names}}\t{{.Status}}"
            read -p "Enter source container name: " container_name
            read -p "Enter source file path in container: " source_path
            read -p "Enter destination path on host: " dest_path
            
            echo -e "${GREEN}📥 Copying file FROM container...${NC}"
            echo "Source: $container_name:$source_path"
            echo "Destination: $dest_path"
            
            if docker cp "$container_name:$source_path" "$dest_path"; then
                echo -e "${GREEN}✅ File copied successfully!${NC}"
            else
                echo -e "${RED}❌ Failed to copy file from container.${NC}"
            fi
            ;;
        *)
            echo -e "${RED}❌ Invalid option. Please choose 1 or 2.${NC}"
            ;;
    esac
}

# Function to install packages
install_packages() {
    local site_name=$1
    
    echo -e "${CYAN}📦 Smart Package Installation for $site_name${NC}"
    echo ""
    
    # Show available containers
    echo -e "${YELLOW}📋 Available containers:${NC}"
    docker ps --filter "name=^${site_name}-" --format "table {{.Names}}\t{{.Status}}"
    echo ""
    
    # Select container
    read -p "Enter container name to install packages in: " container_name
    if [[ -z "$container_name" ]]; then
        echo -e "${YELLOW}No container name provided.${NC}"
        return 1
    fi
    
    # Check if container exists and is running
    if ! docker ps --format "{{.Names}}" | grep -q "^${container_name}$"; then
        echo -e "${RED}❌ Container $container_name not found or not running.${NC}"
        return 1
    fi
    
    echo ""
    echo -e "${GREEN}🎯 Installing packages in: $container_name${NC}"
    echo ""
    
    # Smart package installation
    echo -e "${CYAN}📦 Smart Package Installation${NC}"
    echo ""
    echo -e "${BLUE}💡 Enter packages to install (space-separated)${NC}"
    echo -e "${BLUE}   Examples: nano, nano vim curl, or press Enter for common tools${NC}"
    echo ""
    
    read -p "Enter packages (or press Enter for common tools): " packages
    
    if [[ -z "$packages" ]]; then
        # Install common development tools
        echo -e "${GREEN}📦 Installing common development tools...${NC}"
        echo "Installing: nano vim curl wget git htop tree net-tools"
        docker exec -it --user root "$container_name" bash -c "apt-get update && apt-get install nano vim curl wget git htop tree net-tools -y"
        echo -e "${GREEN}✅ Development tools installation completed!${NC}"
    else
        # Install user-specified packages
        echo -e "${GREEN}📦 Installing packages: $packages${NC}"
        docker exec -it --user root "$container_name" bash -c "apt-get update && apt-get install $packages -y"
        echo -e "${GREEN}✅ Package installation completed!${NC}"
    fi
    
    echo ""
    echo -e "${GREEN}🎉 Package installation process completed!${NC}"
    echo -e "${BLUE}💡 You can now use the installed packages in your container.${NC}"
}

# Function to show main menu
show_main_menu() {
    echo -e "${CYAN}📋 Available Actions:${NC}"
    echo ""
    echo -e "${GREEN}1.${NC} Show running containers"
    echo -e "${GREEN}2.${NC} Access container shell (normal user)"
    echo -e "${GREEN}3.${NC} Access container shell (root user)"
    echo -e "${GREEN}4.${NC} Manage Frappe processes"
    echo -e "${GREEN}5.${NC} View logs"
    echo -e "${GREEN}6.${NC} Manage containers"
    echo -e "${GREEN}7.${NC} Show site information"
    echo -e "${GREEN}8.${NC} Access specific container as root"
    echo -e "${GREEN}9.${NC} File Transfer"
    echo -e "${GREEN}10.${NC} Install Packages"
    echo -e "${GREEN}11.${NC} View Create-Site logs"
    echo -e "${GREEN}12.${NC} Exit"
    echo ""
}

# Function to show Frappe process management menu
show_process_menu() {
    echo -e "${CYAN}🔄 Frappe Process Management:${NC}"
    echo ""
    echo -e "${GREEN}1.${NC} Show process status"
    echo -e "${GREEN}2.${NC} Restart all processes"
    echo -e "${GREEN}3.${NC} Restart specific process"
    echo -e "${GREEN}4.${NC} Stop all processes"
    echo -e "${GREEN}5.${NC} Start all processes"
    echo -e "${GREEN}6.${NC} Back to main menu"
    echo ""
}

# Function to show log menu
show_log_menu() {
    echo -e "${CYAN}📋 Log Viewing Options:${NC}"
    echo ""
    echo -e "${GREEN}1.${NC} Frappe Web logs"
    echo -e "${GREEN}2.${NC} Frappe Worker logs"
    echo -e "${GREEN}3.${NC} Frappe Schedule logs"
    echo -e "${GREEN}4.${NC} Frappe WebSocket logs"
    echo -e "${GREEN}5.${NC} Supervisor logs"
    echo -e "${GREEN}6.${NC} Container logs"
    echo -e "${GREEN}7.${NC} Create-Site logs"
    echo -e "${GREEN}8.${NC} Back to main menu"
    echo ""
}

# Function to show container management menu
show_container_menu() {
    echo -e "${CYAN}🐳 Container Management:${NC}"
    echo ""
    echo -e "${GREEN}1.${NC} Start containers"
    echo -e "${GREEN}2.${NC} Stop containers"
    echo -e "${GREEN}3.${NC} Restart containers"
    echo -e "${GREEN}4.${NC} Rebuild containers"
    echo -e "${GREEN}5.${NC} Rebuild with custom apps preservation"
    echo -e "${GREEN}6.${NC} Show container logs"
    echo -e "${GREEN}7.${NC} Show container status"
    echo -e "${GREEN}8.${NC} Remove all containers (with space cleanup)"
    echo -e "${GREEN}9.${NC} Remove specific container"
    echo -e "${GREEN}10.${NC} Docker system cleanup (free space)"
    echo -e "${GREEN}11.${NC} Complete site removal (containers + folders + hosts)"
    echo -e "${GREEN}12.${NC} Back to main menu"
    echo ""
}

# Function to show site information
show_site_info() {
    local sites=($(find_frappe_sites))
    if [[ ${#sites[@]} -eq 0 ]]; then
        echo -e "${YELLOW}No Frappe sites found in running containers${NC}"
        return
    fi
    
    echo -e "${CYAN}🏠 Frappe Sites Information:${NC}"
    echo ""
    
    for site in "${sites[@]}"; do
        echo -e "${BLUE}📁 Site: ${site}${NC}"
        
        # Check if containers are running
        local running=$(docker ps --filter "name=^${site}-" --format "{{.Names}}" | wc -l)
        if [[ $running -gt 0 ]]; then
            echo -e "   🟢 Status: ${GREEN}Running ($running containers)${NC}"
        else
            echo -e "   🔴 Status: ${RED}Stopped${NC}"
        fi
        
        # Show container details
        echo -e "   📋 Containers:"
        docker ps --filter "name=^${site}-" --format "   {{.Names}} - {{.Status}}"
        
        echo ""
    done
}

# Main function
main() {
    print_header
    
    # Check if Docker is running
    check_docker
    
    # Check if we have any Frappe sites running
    local sites=($(find_frappe_sites))
    if [[ ${#sites[@]} -eq 0 ]]; then
        echo -e "${YELLOW}⚠️  No Frappe sites found in running containers${NC}"
        echo "Please start your Frappe containers first."
        echo "Or run generate_frappe_docker_local_optimized.sh to create a site."
        exit 1
    fi
    
    echo -e "${GREEN}✅ Found ${#sites[@]} Frappe site(s):${NC}"
    for site in "${sites[@]}"; do
        echo -e "   • ${site}"
    done
    echo ""
    
    while true; do
        show_main_menu
        
        read -p "Select an option (1-12): " choice
        
        case $choice in
            1)
                show_running_containers
                ;;
            2)
                if [[ ${#sites[@]} -eq 1 ]]; then
                    access_container "${sites[0]}" "normal"
                else
                    echo -e "${CYAN}Select a site:${NC}"
                    select site in "${sites[@]}"; do
                        if [[ -n "$site" ]]; then
                            access_container "$site" "normal"
                            break
                        fi
                    done
                fi
                ;;
            3)
                if [[ ${#sites[@]} -eq 1 ]]; then
                    access_container "${sites[0]}" "root"
                else
                    echo -e "${CYAN}Select a site:${NC}"
                    select site in "${sites[@]}"; do
                        if [[ -n "$site" ]]; then
                            access_container "$site" "root"
                            break
                        fi
                    done
                fi
                ;;
            4)
                if [[ ${#sites[@]} -eq 1 ]]; then
                    manage_frappe_processes_menu "${sites[0]}"
                else
                    echo -e "${CYAN}Select a site:${NC}"
                    select site in "${sites[@]}"; do
                        if [[ -n "$site" ]]; then
                            manage_frappe_processes_menu "$site"
                            break
                        fi
                    done
                fi
                ;;
            5)
                if [[ ${#sites[@]} -eq 1 ]]; then
                    view_logs_menu "${sites[0]}"
                else
                    echo -e "${CYAN}Select a site:${NC}"
                    select site in "${sites[@]}"; do
                        if [[ -n "$site" ]]; then
                            view_logs_menu "$site"
                            break
                        fi
                    done
                fi
                ;;
            6)
                if [[ ${#sites[@]} -eq 1 ]]; then
                    manage_containers_menu "${sites[0]}"
                else
                    echo -e "${CYAN}Select a site:${NC}"
                    select site in "${sites[@]}"; do
                        if [[ -n "$site" ]]; then
                            manage_containers_menu "$site"
                            break
                        fi
                    done
                fi
                ;;
            7)
                show_site_info
                ;;
            8)
                if [[ ${#sites[@]} -eq 1 ]]; then
                    access_specific_container_root "${sites[0]}"
                else
                    echo -e "${CYAN}Select a site:${NC}"
                    select site in "${sites[@]}"; do
                        if [[ -n "$site" ]]; then
                            access_specific_container_root "$site"
                            break
                        fi
                    done
                fi
                ;;
            9)
                if [[ ${#sites[@]} -eq 1 ]]; then
                    transfer_files "${sites[0]}"
                else
                    echo -e "${CYAN}Select a site:${NC}"
                    select site in "${sites[@]}"; do
                        if [[ -n "$site" ]]; then
                            transfer_files "$site"
                            break
                        fi
                    done
                fi
                ;;
            10)
                if [[ ${#sites[@]} -eq 1 ]]; then
                    install_packages "${sites[0]}"
                else
                    echo -e "${CYAN}Select a site:${NC}"
                    select site in "${sites[@]}"; do
                        if [[ -n "$site" ]]; then
                            install_packages "$site"
                            break
                        fi
                    done
                fi
                ;;
            11)
                if [[ ${#sites[@]} -eq 1 ]]; then
                    view_logs "${sites[0]}" "create-site"
                else
                    echo -e "${CYAN}Select a site:${NC}"
                    select site in "${sites[@]}"; do
                        if [[ -n "$site" ]]; then
                            view_logs "$site" "create-site"
                            break
                        fi
                    done
                fi
                ;;
            12)
                echo -e "${GREEN}👋 Goodbye!${NC}"
                exit 0
                ;;
            *)
                echo -e "${RED}❌ Invalid option. Please try again.${NC}"
                ;;
        esac
        
        echo ""
        read -p "Press Enter to continue..."
        echo ""
    done
}

# Function to handle Frappe process management menu
manage_frappe_processes_menu() {
    local site_name=$1
    
    while true; do
        show_process_menu
        
        read -p "Select an option (1-6): " choice
        
        case $choice in
            1)
                manage_frappe_processes "$site_name" "status"
                ;;
            2)
                manage_frappe_processes "$site_name" "restart"
                ;;
            3)
                echo -e "${CYAN}Available processes:${NC}"
                echo "frappe-web, frappe-schedule, frappe-worker-short, frappe-worker-long, frappe-worker-default, frappe-websocket"
                read -p "Enter process name: " process_name
                if [[ -n "$process_name" ]]; then
                    manage_frappe_processes "$site_name" "restart" "$process_name"
                fi
                ;;
            4)
                manage_frappe_processes "$site_name" "stop"
                ;;
            5)
                manage_frappe_processes "$site_name" "start"
                ;;
            6)
                break
                ;;
            *)
                echo -e "${RED}❌ Invalid option. Please try again.${NC}"
                ;;
        esac
        
        echo ""
        read -p "Press Enter to continue..."
        echo ""
    done
}

# Function to rebuild with custom apps preservation
rebuild_with_custom_apps() {
    local site_name=$1
    local container_name="${site_name}-app"
    
    echo -e "${BLUE}📦 Backing up custom apps for ${site_name}...${NC}"
    
    # Check if container exists and is running
    if ! docker ps | grep -q "${container_name}"; then
        echo -e "${YELLOW}⚠️  Container ${container_name} is not running. Cannot backup custom apps.${NC}"
        return 1
    fi
    
    # Create backup directory
    local backup_dir="/tmp/frappe_custom_apps_backup_${site_name}"
    mkdir -p "$backup_dir"
    
    # Extract custom apps (excluding frappe and erpnext)
    local custom_apps=$(docker exec "${container_name}" bash -c "cd /home/frappe/frappe-bench && cat sites/apps.json | jq -r 'keys[]' | grep -v '^frappe$' | grep -v '^erpnext$'" 2>/dev/null)
    
    if [ -n "$custom_apps" ]; then
        echo "$custom_apps" > "${backup_dir}/custom_apps.txt"
        echo -e "${GREEN}✅ Custom apps backed up: $(echo "$custom_apps" | tr '\n' ' ')${NC}"
    else
        echo -e "${YELLOW}ℹ️  No custom apps found to backup${NC}"
        rm -rf "$backup_dir"
        return 0
    fi
    
    # Stop containers
    echo -e "${BLUE}🛑 Stopping containers...${NC}"
    DOCKER_COMPOSE_CMD=$(detect_docker_compose)
    if [ $? -ne 0 ]; then
        echo -e "${RED}❌ Failed to detect docker compose command${NC}"
        return 1
    fi
    $DOCKER_COMPOSE_CMD -f "${site_name}/${site_name}-docker-compose.yml" down
    
    # Update docker-compose file to add restart policy
    echo -e "${BLUE}📝 Adding auto-restart policy to containers...${NC}"
    sed -i 's/\(^\s*\)\(container_name:\)/\1restart: always\n\1\2/g' "${site_name}/${site_name}-docker-compose.yml"
    
    # Start containers (without regenerating docker-compose)
    echo -e "${BLUE}🔄 Starting containers...${NC}"
    $DOCKER_COMPOSE_CMD -f "${site_name}/${site_name}-docker-compose.yml" up -d
    
    # Wait for containers to be ready
    echo -e "${BLUE}⏳ Waiting for containers to be ready...${NC}"
    local max_attempts=30
    local attempt=0
    
    while [ $attempt -lt $max_attempts ]; do
        if docker exec "${container_name}" bash -c "cd /home/frappe/frappe-bench && bench --version" >/dev/null 2>&1; then
            break
        fi
        echo -e "${YELLOW}   Attempt $((attempt + 1))/$max_attempts - Container not ready yet...${NC}"
        sleep 10
        ((attempt++))
    done
    
    if [ $attempt -eq $max_attempts ]; then
        echo -e "${RED}❌ Container ${container_name} did not become ready in time${NC}"
        return 1
    fi
    
    echo -e "${GREEN}✅ Container is ready!${NC}"
    
    # Reinstall custom apps
    local custom_apps=$(cat "${backup_dir}/custom_apps.txt")
    for app in $custom_apps; do
        echo -e "${BLUE}📦 Reinstalling ${app}...${NC}"
        
        # Get app from git repository
        docker exec "${container_name}" bash -c "cd /home/frappe/frappe-bench && bench get-app ${app}" 2>/dev/null
        
        if [ $? -eq 0 ]; then
            echo -e "${GREEN}✅ ${app} downloaded successfully${NC}"
            
            # Install app on the site
            docker exec "${container_name}" bash -c "cd /home/frappe/frappe-bench && bench --site ${site_name}.local install-app ${app}" 2>/dev/null
            
            if [ $? -eq 0 ]; then
                echo -e "${GREEN}✅ ${app} installed on site successfully${NC}"
            else
                echo -e "${YELLOW}⚠️  ${app} installation on site failed (may already be installed)${NC}"
            fi
        else
            echo -e "${YELLOW}⚠️  ${app} download failed (may already exist)${NC}"
        fi
    done
    
    # Update apps.txt
    docker exec "${container_name}" bash -c "cd /home/frappe/frappe-bench && ls -1 apps > sites/apps.txt"
    echo -e "${GREEN}✅ apps.txt updated with all installed apps${NC}"
    
    # Clean up backup
    rm -rf "$backup_dir"
    echo -e "${GREEN}✅ Backup cleaned up${NC}"
    echo -e "${GREEN}🎉 Rebuild with custom apps preservation completed!${NC}"
}

# Function to handle log viewing menu
view_logs_menu() {
    local site_name=$1
    
    while true; do
        show_log_menu
        
        read -p "Select an option (1-8): " choice
        
        case $choice in
            1)
                view_logs "$site_name" "web"
                ;;
            2)
                view_logs "$site_name" "worker"
                ;;
            3)
                view_logs "$site_name" "schedule"
                ;;
            4)
                view_logs "$site_name" "websocket"
                ;;
            5)
                view_logs "$site_name" "supervisor"
                ;;
            6)
                view_logs "$site_name" "container"
                ;;
            7)
                view_logs "$site_name" "create-site"
                ;;
            8)
                break
                ;;
            *)
                echo -e "${RED}❌ Invalid option. Please try again.${NC}"
                ;;
        esac
        
        echo ""
        read -p "Press Enter to continue..."
        echo ""
    done
}

# Function to handle container management menu
manage_containers_menu() {
    local site_name=$1
    
    while true; do
        show_container_menu
        
        read -p "Select an option (1-12): " choice
        
        case $choice in
            1)
                manage_containers "$site_name" "start"
                ;;
            2)
                manage_containers "$site_name" "stop"
                ;;
            3)
                manage_containers "$site_name" "restart"
                ;;
            4)
                manage_containers "$site_name" "rebuild"
                ;;
            5)
                manage_containers "$site_name" "rebuild-with-apps"
                ;;
            6)
                manage_containers "$site_name" "logs"
                ;;
            7)
                manage_containers "$site_name" "status"
                ;;
            8)
                remove_all_containers "$site_name"
                ;;
            9)
                remove_specific_container "$site_name"
                ;;
            10)
                cleanup_docker_space
                ;;
            11)
                remove_all_containers "$site_name"
                ;;
            12)
                break
                ;;
            *)
                echo -e "${RED}❌ Invalid option. Please try again.${NC}"
                ;;
        esac
        
        echo ""
        read -p "Press Enter to continue..."
        echo ""
    done
}

# Check if script is run directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main
fi
