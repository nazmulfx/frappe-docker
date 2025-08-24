#!/bin/bash

# Docker Helper Script (Enhanced Version)
# Simplifies managing Docker Compose-based project containers

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Header
print_header() {
    echo -e "${YELLOW}🚀 Welcome to Docker Helper Script${NC}"
    echo "---------------------------------------------"
}

# Check Docker status
check_docker_running() {
    if ! sudo docker info > /dev/null 2>&1; then
        echo -e "${RED}❌ Docker is not running. Please start Docker and try again.${NC}"
        exit 1
    fi
}

# Function: Logs
inspect_container_logs() {
    [[ -z "$1" ]] && { echo -e "${RED}❌ No container specified.${NC}"; return 1; }
    echo -e "${GREEN}📋 Showing logs for: $1${NC}"
    sudo docker logs "$1" --tail 50 || echo -e "${RED}⚠️ Failed to get logs.${NC}"
}

# Function: Access Shell
access_container() {
    local container_name=$1
    local user=${2:-"frappe"}
    [[ -z "$container_name" ]] && { echo -e "${RED}❌ No container specified.${NC}"; return 1; }
    echo -e "${GREEN}🔧 Opening shell for: $container_name as $user${NC}"
    sudo docker exec -it --user "$user" "$container_name" bash || echo -e "${RED}⚠️ Cannot access container.${NC}"
}

# Function: Start / Stop / Remove
container_action() {
    local action=$1
    local name=$2
    [[ -z "$name" ]] && { echo -e "${RED}❌ No container specified.${NC}"; return 1; }

    case $action in
        start)
            sudo docker start "$name" && echo -e "${GREEN}✅ Started: $name${NC}" || echo -e "${RED}⚠️ Failed to start.${NC}"
            ;;
        stop)
            sudo docker stop "$name" && echo -e "${GREEN}🛑 Stopped: $name${NC}" || echo -e "${RED}⚠️ Failed to stop.${NC}"
            ;;
        remove)
            sudo docker rm "$name" && echo -e "${GREEN}🗑️ Removed: $name${NC}" || echo -e "${RED}⚠️ Failed to remove.${NC}"
            ;;
    esac
}

# Function: Running containers
check_running_processes() {
    echo -e "${GREEN}📦 Running Containers:${NC}"
    sudo docker ps
}

# Function: List all project containers
list_project_containers() {
    echo -e "${YELLOW}🧱 Project Containers:${NC}"
    sudo docker ps -a --format '{{.Names}}' | grep "^${SAFE_SITE_NAME}-"
}

# Optional: Fuzzy select (requires fzf)
fuzzy_select_container() {
    command -v fzf >/dev/null 2>&1 || { echo -e "${RED}fzf not installed. Falling back to manual entry.${NC}"; return 1; }
    selected=$(sudo docker ps -a --format '{{.Names}}' | grep "^${SAFE_SITE_NAME}-" | fzf --prompt="Select container: ")
    echo "$selected"
}

# Function: Restart all containers by site name
restart_all_containers() {
    [[ -z "$1" ]] && { echo -e "${RED}❌ No site name specified.${NC}"; return 1; }
    echo -e "${GREEN}🔄 Restarting all containers for: $1${NC}"
    
    # Get all containers (running and stopped) for the site
    containers=$(sudo docker ps -a -q --filter "name=$1-")
    
    if [[ -z "$containers" ]]; then
        echo -e "${YELLOW}⚠️ No containers found for site: $1${NC}"
        return 1
    fi
    
    echo "Found containers:"
    sudo docker ps -a --filter "name=$1-" --format "table {{.Names}}\t{{.Status}}"
    echo ""
    echo "Please wait while we restart the containers..."
    
    # Restart all containers
    echo "$containers" | xargs -r sudo docker restart
    
    if [[ $? -eq 0 ]]; then
        echo -e "${GREEN}✅ Successfully restarted all containers for: $1${NC}"
    else
        echo -e "${RED}⚠️ Some containers failed to restart.${NC}"
    fi
}

# Function: Remove all containers by site name with space cleanup
remove_all_containers() {
    [[ -z "$1" ]] && { echo -e "${RED}❌ No site name specified.${NC}"; return 1; }
    
    # Get all containers (running and stopped) for the site
    containers=$(sudo docker ps -a -q --filter "name=$1-")
    
    if [[ -z "$containers" ]]; then
        echo -e "${YELLOW}⚠️ No containers found for site: $1${NC}"
        return 1
    fi
    
    echo "Found containers for site: $1"
    sudo docker ps -a --filter "name=$1-" --format "table {{.Names}}\t{{.Status}}\t{{.Size}}"
    echo ""
    
    # Show space usage before cleanup
    echo -e "${YELLOW}📊 Current Docker Space Usage:${NC}"
    sudo docker system df
    echo ""
    
    # Check for associated volumes and networks
    echo "Checking for associated resources..."
    volumes=$(sudo docker volume ls -q | grep "$1" 2>/dev/null)
    networks=$(sudo docker network ls --filter "name=$1" --format "{{.Name}}" | grep -v "bridge\|host\|none")
    
    if [[ -n "$volumes" ]]; then
        echo -e "${YELLOW}📂 Associated volumes found:${NC}"
        echo "$volumes" | sed 's/^/  - /'
    fi
    
    if [[ -n "$networks" ]]; then
        echo -e "${YELLOW}🌐 Associated networks found:${NC}"
        echo "$networks" | sed 's/^/  - /'
    fi
    echo ""
    
    echo -e "${RED}⚠️ WARNING: This will permanently remove ALL containers, volumes, and networks for site: $1${NC}"
    echo -e "${RED}💾 This will FREE UP DISK SPACE by removing all associated data!${NC}"
    read -p "⚠️ Are you absolutely sure you want to remove ALL resources? (y/n): " confirm1
    if [[ $confirm1 == "y" ]]; then
        read -p "⚠️ FINAL CONFIRMATION: Type 'DELETE' to confirm complete removal: " confirm2
        if [[ $confirm2 == "DELETE" ]]; then
            echo -e "${GREEN}🗑️ Removing all resources for: $1${NC}"
            echo "Please wait while we clean up everything..."
            
            # Step 1: Stop containers first
            echo "1. Stopping containers..."
            echo "$containers" | xargs -r sudo docker stop 2>/dev/null
            
            # Step 2: Remove containers
            echo "2. Removing containers..."
            echo "$containers" | xargs -r sudo docker rm
            
            # Step 3: Remove volumes
            if [[ -n "$volumes" ]]; then
                echo "3. Removing volumes..."
                echo "$volumes" | xargs -r sudo docker volume rm 2>/dev/null
            fi
            
            # Step 4: Remove networks (exclude default networks)
            if [[ -n "$networks" ]]; then
                echo "4. Removing custom networks..."
                echo "$networks" | xargs -r sudo docker network rm 2>/dev/null
            fi
            
            # Step 5: Clean up orphaned resources
            echo "5. Cleaning up orphaned resources..."
            sudo docker system prune -f >/dev/null 2>&1
            
            echo ""
            echo -e "${GREEN}✅ Successfully removed all resources for: $1${NC}"
            
            # Show space freed up
            echo -e "${GREEN}💾 Updated Docker Space Usage:${NC}"
            sudo docker system df
            echo ""
            echo -e "${GREEN}🎉 Cleanup complete! Disk space has been freed up.${NC}"
            
        else
            echo -e "${YELLOW}Removal cancelled - incorrect confirmation.${NC}"
        fi
    else
        echo -e "${YELLOW}Removal cancelled.${NC}"
    fi
}

# Function: Clean up Docker system and free space
cleanup_docker_space() {
    echo -e "${YELLOW}🧹 Docker System Cleanup${NC}"
    echo "This will clean up unused Docker resources to free disk space."
    echo ""
    
    # Show current space usage
    echo -e "${YELLOW}📊 Current Docker Space Usage:${NC}"
    sudo docker system df
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
            sudo docker system prune -f
            ;;
        2)
            echo -e "${RED}⚠️ WARNING: This will remove ALL unused volumes and may delete important data!${NC}"
            read -p "⚠️ Are you sure you want to remove volumes? (y/n): " confirm_volumes
            if [[ $confirm_volumes == "y" ]]; then
                echo -e "${GREEN}🧹 Cleaning everything including volumes...${NC}"
                sudo docker system prune -a --volumes -f
            else
                echo -e "${YELLOW}Volume cleanup cancelled.${NC}"
            fi
            ;;
        3)
            echo -e "${GREEN}🖼️ Cleaning dangling images...${NC}"
            sudo docker image prune -f
            ;;
        4)
            echo -e "${GREEN}📦 Cleaning stopped containers...${NC}"
            sudo docker container prune -f
            ;;
        5)
            echo -e "${RED}⚠️ WARNING: This will remove unused volumes and may delete data!${NC}"
            read -p "⚠️ Are you sure you want to remove unused volumes? (y/n): " confirm_vol
            if [[ $confirm_vol == "y" ]]; then
                echo -e "${GREEN}💾 Cleaning unused volumes...${NC}"
                sudo docker volume prune -f
            else
                echo -e "${YELLOW}Volume cleanup cancelled.${NC}"
            fi
            ;;
        6)
            echo -e "${GREEN}🌐 Cleaning unused networks...${NC}"
            sudo docker network prune -f
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
    sudo docker system df
}

# Function: File transfer
transfer_files() {
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
            
            list_project_containers
            read -p "Enter target container name: " container_name
            dest_path="/home/frappe/frappe-bench/"
            
            echo -e "${GREEN}📤 Copying file TO container...${NC}"
            echo "Source: $source_path"
            echo "Destination: $container_name:$dest_path"
            
            if sudo docker cp "$source_path" "$container_name:$dest_path"; then
                echo -e "${GREEN}✅ File copied successfully!${NC}"
            else
                echo -e "${RED}❌ Failed to copy file to container.${NC}"
            fi
            ;;
        2)
            # Copy FROM container
            list_project_containers
            read -p "Enter source container name: " container_name
            read -p "Enter source file path in container: " source_path
            read -p "Enter destination path on host: " dest_path
            
            echo -e "${GREEN}📥 Copying file FROM container...${NC}"
            echo "Source: $container_name:$source_path"
            echo "Destination: $dest_path"
            
            if sudo docker cp "$container_name:$source_path" "$dest_path"; then
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

# --- Script Start ---

print_header
check_docker_running

# Show available Compose projects
echo -e "${YELLOW}📋 Available Projects:${NC}"
sudo docker ps -a --format '{{.Names}}' | awk -F'-' '{print $1}' | sort | uniq
echo ""

read -p "🔍 Enter your Docker Compose project name: " SAFE_SITE_NAME
echo ""

# Menu
echo "What would you like to do?"
PS3="Select an option (1-17): "
options=(
    "Access: Backend"
    "Access: Frontend"
    "Access: DB"
    "Logs: Backend"
    "Logs: Frontend"
    "Logs: DB"
    "Start a Container"
    "Stop a Container"
    "Restart All Containers"
    "Remove a Container"
    "Remove All Containers (with space cleanup)"
    "Access: Backend as Root"
    "Access: Frontend as Root"
    "Check Running Containers"
    "Docker System Cleanup (free space)"
    "File Transfer"
    "Exit"
)

select opt in "${options[@]}"; do
    echo ""
    case $REPLY in
        1)  access_container "${SAFE_SITE_NAME}-backend" ;;
        2)  access_container "${SAFE_SITE_NAME}-frontend" ;;
        3)  access_container "${SAFE_SITE_NAME}-db" ;;
        4)  inspect_container_logs "${SAFE_SITE_NAME}-backend" ;;
        5)  inspect_container_logs "${SAFE_SITE_NAME}-frontend" ;;
        6)  inspect_container_logs "${SAFE_SITE_NAME}-db" ;;
        7)
            list_project_containers
            read -p "Enter container name to start: " cname
            container_action start "$cname"
            ;;
        8)
            list_project_containers
            read -p "Enter container name to stop: " cname
            container_action stop "$cname"
            ;;
        9)  restart_all_containers "$SAFE_SITE_NAME" ;;
        10)
            list_project_containers
            read -p "Enter container name to remove: " cname
            echo -e "${RED}⚠️ WARNING: This will permanently remove the container!${NC}"
            read -p "⚠️ Are you absolutely sure you want to remove $cname? (y/n): " confirm1
            if [[ $confirm1 == "y" ]]; then
                read -p "⚠️ FINAL CONFIRMATION: Type 'DELETE' to confirm removal: " confirm2
                if [[ $confirm2 == "DELETE" ]]; then
                    container_action remove "$cname"
                else
                    echo -e "${YELLOW}Removal cancelled - incorrect confirmation.${NC}"
                fi
            else
                echo -e "${YELLOW}Removal cancelled.${NC}"
            fi
            ;;
        11)  remove_all_containers "$SAFE_SITE_NAME" ;;
        12)  access_container "${SAFE_SITE_NAME}-backend" "root" ;;
        13)  access_container "${SAFE_SITE_NAME}-frontend" "root" ;;
        14)  check_running_processes ;;
        15)  cleanup_docker_space ;;
        16)  transfer_files ;;
        17)  echo -e "${GREEN}👋 Exiting. Goodbye!${NC}"
            break
            ;;
        *) echo -e "${RED}❌ Invalid option. Please choose 1–17.${NC}" ;;
    esac
    echo ""
done
