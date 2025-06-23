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

# Function: Remove all containers by site name
remove_all_containers() {
    [[ -z "$1" ]] && { echo -e "${RED}❌ No site name specified.${NC}"; return 1; }
    
    # Get all containers (running and stopped) for the site
    containers=$(sudo docker ps -a -q --filter "name=$1-")
    
    if [[ -z "$containers" ]]; then
        echo -e "${YELLOW}⚠️ No containers found for site: $1${NC}"
        return 1
    fi
    
    echo "Found containers for site: $1"
    sudo docker ps -a --filter "name=$1-" --format "table {{.Names}}\t{{.Status}}"
    echo ""
    echo -e "${RED}⚠️ WARNING: This will permanently remove ALL containers for site: $1${NC}"
    read -p "⚠️ Are you absolutely sure you want to remove ALL containers? (y/n): " confirm1
    if [[ $confirm1 == "y" ]]; then
        read -p "⚠️ FINAL CONFIRMATION: Type 'DELETE' to confirm removal: " confirm2
        if [[ $confirm2 == "DELETE" ]]; then
            echo -e "${GREEN}🗑️ Removing all containers for: $1${NC}"
            echo "Please wait while we remove the containers..."
            
            # Stop containers first, then remove them
            echo "$containers" | xargs -r sudo docker stop 2>/dev/null
            echo "$containers" | xargs -r sudo docker rm
            
            if [[ $? -eq 0 ]]; then
                echo -e "${GREEN}✅ Successfully removed all containers for: $1${NC}"
            else
                echo -e "${RED}⚠️ Some containers failed to remove.${NC}"
            fi
        else
            echo -e "${YELLOW}Removal cancelled - incorrect confirmation.${NC}"
        fi
    else
        echo -e "${YELLOW}Removal cancelled.${NC}"
    fi
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
PS3="Select an option (1-16): "
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
    "Remove All Containers"
    "Access: Backend as Root"
    "Access: Frontend as Root"
    "Check Running Containers"
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
        15)  transfer_files ;;
        16)  echo -e "${GREEN}👋 Exiting. Goodbye!${NC}"
            break
            ;;
        *) echo -e "${RED}❌ Invalid option. Please choose 1–16.${NC}" ;;
    esac
    echo ""
done
