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
    [[ -z "$1" ]] && { echo -e "${RED}❌ No container specified.${NC}"; return 1; }
    echo -e "${GREEN}🔧 Opening shell for: $1${NC}"
    sudo docker exec -it "$1" bash || echo -e "${RED}⚠️ Cannot access container.${NC}"
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
PS3="Select an option (1-11): "
options=(
    "Logs: Frontend"
    "Logs: Backend"
    "Logs: DB"
    "Access: Frontend"
    "Access: Backend"
    "Access: DB"
    "Check Running Containers"
    "Start a Container"
    "Stop a Container"
    "Remove a Container"
    "Exit"
)

select opt in "${options[@]}"; do
    echo ""
    case $REPLY in
        1)  inspect_container_logs "${SAFE_SITE_NAME}-frontend" ;;
        2)  inspect_container_logs "${SAFE_SITE_NAME}-backend" ;;
        3)  inspect_container_logs "${SAFE_SITE_NAME}-db" ;;
        4)  access_container "${SAFE_SITE_NAME}-frontend" ;;
        5)  access_container "${SAFE_SITE_NAME}-backend" ;;
        6)  access_container "${SAFE_SITE_NAME}-db" ;;
        7)  check_running_processes ;;
        8)
            list_project_containers
            read -p "Enter container name to start: " cname
            container_action start "$cname"
            ;;
        9)
            list_project_containers
            read -p "Enter container name to stop: " cname
            container_action stop "$cname"
            ;;
        10)
            list_project_containers
            read -p "Enter container name to remove: " cname
            read -p "⚠️ Are you sure you want to remove $cname? (y/n): " confirm
            [[ $confirm == "y" ]] && container_action remove "$cname" || echo -e "${YELLOW}Cancelled.${NC}"
            ;;
        11)
            echo -e "${GREEN}👋 Exiting. Goodbye!${NC}"
            break
            ;;
        *) echo -e "${RED}❌ Invalid option. Please choose 1–11.${NC}" ;;
    esac
    echo ""
done
