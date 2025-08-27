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

# Function to find Frappe sites
find_frappe_sites() {
    local sites=()
    for dir in */; do
        if [[ -d "$dir" ]]; then
            local site_name=$(basename "$dir")
            if [[ -f "$dir/${site_name}-docker-compose.yml" ]]; then
                sites+=("$site_name")
            fi
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
        echo -e "${YELLOW}No Frappe sites found in current directory${NC}"
        return
    fi
    
    for site in "${sites[@]}"; do
        echo -e "${BLUE}🏠 Site: ${site}${NC}"
        
        # Check if containers are running
        local compose_file="$site/${site}-docker-compose.yml"
        if [[ -f "$compose_file" ]]; then
            local running_containers=$(docker compose -f "$compose_file" ps --format "table {{.Name}}\t{{.Status}}\t{{.Ports}}")
            if [[ -n "$running_containers" ]]; then
                echo "$running_containers" | grep -v "NAME"
            else
                echo -e "${YELLOW}  No containers running${NC}"
            fi
        fi
        echo ""
    done
}

# Function to access container shell
access_container() {
    local site_name=$1
    local access_type=$2
    
    local compose_file="$site_name/${site_name}-docker-compose.yml"
    if [[ ! -f "$compose_file" ]]; then
        echo -e "${RED}❌ Site $site_name not found or invalid${NC}"
        return 1
    fi
    
    case $access_type in
        "normal")
            echo -e "${GREEN}🔧 Accessing $site_name-app container as frappe user...${NC}"
            docker compose -f "$compose_file" exec app bash
            ;;
        "root")
            echo -e "${GREEN}🔧 Accessing $site_name-app container as root user...${NC}"
            docker compose -f "$compose_file" exec -u root app bash
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
    
    local compose_file="$site_name/${site_name}-docker-compose.yml"
    if [[ ! -f "$compose_file" ]]; then
        echo -e "${RED}❌ Site $site_name not found or invalid${NC}"
        return 1
    fi
    
    case $action in
        "status")
            echo -e "${CYAN}📊 Frappe Process Status for $site_name:${NC}"
            docker compose -f "$compose_file" exec app /home/frappe/.local/bin/supervisorctl -c /home/frappe/supervisor/supervisord.conf status
            ;;
        "restart")
            if [[ -n "$process" ]]; then
                echo -e "${GREEN}🔄 Restarting $process process in $site_name...${NC}"
                docker compose -f "$compose_file" exec app /home/frappe/.local/bin/supervisorctl -c /home/frappe/supervisor/supervisord.conf restart "$process"
            else
                echo -e "${GREEN}🔄 Restarting all Frappe processes in $site_name...${NC}"
                docker compose -f "$compose_file" exec app /home/frappe/.local/bin/supervisorctl -c /home/frappe/supervisor/supervisord.conf restart all
            fi
            ;;
        "stop")
            if [[ -n "$process" ]]; then
                echo -e "${YELLOW}⏹️  Stopping $process process in $site_name...${NC}"
                docker compose -f "$compose_file" exec app /home/frappe/.local/bin/supervisorctl -c /home/frappe/supervisor/supervisord.conf stop "$process"
            else
                echo -e "${YELLOW}⏹️  Stopping all Frappe processes in $site_name...${NC}"
                docker compose -f "$compose_file" exec app /home/frappe/.local/bin/supervisorctl -c /home/frappe/supervisor/supervisord.conf stop all
            fi
            ;;
        "start")
            if [[ -n "$process" ]]; then
                echo -e "${GREEN}▶️  Starting $process process in $site_name...${NC}"
                docker compose -f "$compose_file" exec app /home/frappe/.local/bin/supervisorctl -c /home/frappe/supervisor/supervisord.conf start "$process"
            else
                echo -e "${GREEN}▶️  Starting all Frappe processes in $site_name...${NC}"
                docker compose -f "$compose_file" exec app /home/frappe/.local/bin/supervisorctl -c /home/frappe/supervisor/supervisord.conf start all
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
    
    local compose_file="$site_name/${site_name}-docker-compose.yml"
    if [[ ! -f "$compose_file" ]]; then
        echo -e "${RED}❌ Site $site_name not found or invalid${NC}"
        return 1
    fi
    
    case $log_type in
        "web")
            echo -e "${CYAN}📋 Viewing Frappe Web logs for $site_name...${NC}"
            docker compose -f "$compose_file" exec app tail -f /home/frappe/supervisor/logs/frappe-web.log
            ;;
        "worker")
            echo -e "${CYAN}📋 Viewing Frappe Worker logs for $site_name...${NC}"
            docker compose -f "$compose_file" exec app tail -f /home/frappe/supervisor/logs/frappe-worker-default.log
            ;;
        "schedule")
            echo -e "${CYAN}📋 Viewing Frappe Schedule logs for $site_name...${NC}"
            docker compose -f "$compose_file" exec app tail -f /home/frappe/supervisor/logs/frappe-schedule.log
            ;;
        "websocket")
            echo -e "${CYAN}📋 Viewing Frappe WebSocket logs for $site_name...${NC}"
            docker compose -f "$compose_file" exec app tail -f /home/frappe/supervisor/logs/frappe-websocket.log
            ;;
        "supervisor")
            echo -e "${CYAN}📋 Viewing Supervisor logs for $site_name...${NC}"
            docker compose -f "$compose_file" exec app tail -f /home/frappe/supervisor/logs/supervisord.log
            ;;
        "container")
            echo -e "${CYAN}📋 Viewing container logs for $site_name...${NC}"
            docker compose -f "$compose_file" logs -f app
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
    
    local compose_file="$site_name/${site_name}-docker-compose.yml"
    if [[ ! -f "$compose_file" ]]; then
        echo -e "${RED}❌ Site $site_name not found or invalid${NC}"
        return 1
    fi
    
    case $action in
        "start")
            echo -e "${GREEN}🚀 Starting containers for $site_name...${NC}"
            docker compose -f "$compose_file" up -d
            ;;
        "stop")
            echo -e "${YELLOW}⏹️  Stopping containers for $site_name...${NC}"
            docker compose -f "$compose_file" down
            ;;
        "restart")
            echo -e "${GREEN}🔄 Restarting containers for $site_name...${NC}"
            docker compose -f "$compose_file" restart
            ;;
        "rebuild")
            echo -e "${CYAN}🔨 Rebuilding containers for $site_name...${NC}"
            docker compose -f "$compose_file" down
            docker compose -f "$compose_file" up -d --build
            ;;
        "logs")
            echo -e "${CYAN}📋 Showing logs for $site_name...${NC}"
            docker compose -f "$compose_file" logs
            ;;
        "status")
            echo -e "${CYAN}📊 Container status for $site_name:${NC}"
            docker compose -f "$compose_file" ps
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
    
    local compose_file="$site_name/${site_name}-docker-compose.yml"
    if [[ ! -f "$compose_file" ]]; then
        echo -e "${RED}❌ Site $site_name not found or invalid${NC}"
        return 1
    fi
    
    echo -e "${RED}⚠️  WARNING: This will remove ALL containers for site: $site_name${NC}"
    echo -e "${YELLOW}This action cannot be undone!${NC}"
    echo ""
    
    # Show what will be removed
    echo -e "${CYAN}Containers that will be removed:${NC}"
    docker compose -f "$compose_file" ps --format "table {{.Names}}\t{{.Status}}"
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
    docker compose -f "$compose_file" down -v
    
    echo -e "${GREEN}✅ All containers removed successfully!${NC}"
    
    # Offer cleanup
    read -p "🧹 Do you want to clean up unused Docker resources? (y/n): " cleanup_choice
    if [[ "$cleanup_choice" =~ ^[Yy]$ ]]; then
        cleanup_docker_space
    fi
}

# Function to remove specific container
remove_specific_container() {
    local site_name=$1
    
    local compose_file="$site_name/${site_name}-docker-compose.yml"
    if [[ ! -f "$compose_file" ]]; then
        echo -e "${RED}❌ Site $site_name not found or invalid${NC}"
        return 1
    fi
    
    echo -e "${CYAN}📋 Available containers for $site_name:${NC}"
    docker compose -f "$compose_file" ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
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
    
    local compose_file="$site_name/${site_name}-docker-compose.yml"
    if [[ ! -f "$compose_file" ]]; then
        echo -e "${RED}❌ Site $site_name not found or invalid${NC}"
        return 1
    fi
    
    echo -e "${CYAN}📋 Available containers for $site_name:${NC}"
    docker compose -f "$compose_file" ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
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
    
    local compose_file="$site_name/${site_name}-docker-compose.yml"
    if [[ ! -f "$compose_file" ]]; then
        echo -e "${RED}❌ Site $site_name not found or invalid${NC}"
        return 1
    fi
    
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
            docker compose -f "$compose_file" ps --format "table {{.Names}}\t{{.Status}}"
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
            docker compose -f "$compose_file" ps --format "table {{.Names}}\t{{.Status}}"
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
    
    local compose_file="$site_name/${site_name}-docker-compose.yml"
    if [[ ! -f "$compose_file" ]]; then
        echo -e "${RED}❌ Site $site_name not found or invalid${NC}"
        return 1
    fi
    
    echo -e "${CYAN}📦 Package Installation for $site_name${NC}"
    echo ""
    
    # Show available containers
    echo -e "${YELLOW}📋 Available containers:${NC}"
    docker compose -f "$compose_file" ps --format "table {{.Names}}\t{{.Status}}"
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
    echo -e "${GREEN}11.${NC} Exit"
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
    echo -e "${GREEN}7.${NC} Back to main menu"
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
    echo -e "${GREEN}5.${NC} Show container logs"
    echo -e "${GREEN}6.${NC} Show container status"
    echo -e "${GREEN}7.${NC} Remove all containers (with space cleanup)"
    echo -e "${GREEN}8.${NC} Remove specific container"
    echo -e "${GREEN}9.${NC} Docker system cleanup (free space)"
    echo -e "${GREEN}10.${NC} Back to main menu"
    echo ""
}

# Function to show site information
show_site_info() {
    local sites=($(find_frappe_sites))
    if [[ ${#sites[@]} -eq 0 ]]; then
        echo -e "${YELLOW}No Frappe sites found in current directory${NC}"
        return
    fi
    
    echo -e "${CYAN}🏠 Frappe Sites Information:${NC}"
    echo ""
    
    for site in "${sites[@]}"; do
        echo -e "${BLUE}📁 Site: ${site}${NC}"
        
        if [[ -f "$site/.env" ]]; then
            echo -e "   📄 Environment file: ${GREEN}✓${NC}"
            source "$site/.env"
            echo -e "   🌐 Site URL: ${CYAN}${SITES}${NC}"
            echo -e "   📊 Frappe Version: ${CYAN}${ERPNEXT_VERSION}${NC}"
        else
            echo -e "   📄 Environment file: ${YELLOW}Not found${NC}"
        fi
        
        if [[ -f "$site/${site}-docker-compose.yml" ]]; then
            echo -e "   🐳 Docker Compose: ${GREEN}✓${NC}"
        fi
        
        # Check if containers are running
        if [[ -d "$site" ]]; then
            local compose_file="$site/${site}-docker-compose.yml"
            if [[ -f "$compose_file" ]]; then
                local running=$(docker compose -f "$compose_file" ps -q 2>/dev/null | wc -l)
                if [[ $running -gt 0 ]]; then
                    echo -e "   🟢 Status: ${GREEN}Running ($running containers)${NC}"
                else
                    echo -e "   🔴 Status: ${RED}Stopped${NC}"
                fi
            fi
        fi
        
        echo ""
    done
}

# Main function
main() {
    print_header
    
    # Check if Docker is running
    check_docker
    
    # Check if we're in a directory with Frappe sites
    local sites=($(find_frappe_sites))
    if [[ ${#sites[@]} -eq 0 ]]; then
        echo -e "${YELLOW}⚠️  No Frappe sites found in current directory${NC}"
        echo "Please run this script from the directory containing your Frappe sites."
        echo "Or run generate_frappe_docker_local_optimized.sh first to create a site."
        exit 1
    fi
    
    echo -e "${GREEN}✅ Found ${#sites[@]} Frappe site(s):${NC}"
    for site in "${sites[@]}"; do
        echo -e "   • ${site}"
    done
    echo ""
    
    while true; do
        show_main_menu
        
        read -p "Select an option (1-11): " choice
        
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

# Function to handle log viewing menu
view_logs_menu() {
    local site_name=$1
    
    while true; do
        show_log_menu
        
        read -p "Select an option (1-7): " choice
        
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
        
        read -p "Select an option (1-10): " choice
        
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
                manage_containers "$site_name" "logs"
                ;;
            6)
                manage_containers "$site_name" "status"
                ;;
            7)
                remove_all_containers "$site_name"
                ;;
            8)
                remove_specific_container "$site_name"
                ;;
            9)
                cleanup_docker_space
                ;;
            10)
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
