#!/bin/bash

# Docker Security Tools Installation & Setup
# Comprehensive security toolkit for Docker environments

echo "🛡️  Installing Docker Security Tools..."

# Install Trivy (Vulnerability Scanner)
install_trivy() {
    echo "📦 Installing Trivy vulnerability scanner..."
    curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin
    echo "✅ Trivy installed successfully"
}

# Install Docker Bench Security
install_docker_bench() {
    echo "📦 Installing Docker Bench Security..."
    git clone https://github.com/docker/docker-bench-security.git
    cd docker-bench-security
    sudo ./docker-bench-security.sh
    cd ..
    echo "✅ Docker Bench Security completed"
}

# Install and configure Falco (Runtime Security)
install_falco() {
    echo "📦 Installing Falco runtime security..."
    curl -s https://falco.org/repo/falcosecurity-packages.asc | sudo apt-key add -
    echo "deb https://download.falco.org/packages/deb stable main" | sudo tee -a /etc/apt/sources.list.d/falcosecurity.list
    sudo apt-get update -qq
    sudo apt-get install -y falco
    
    # Configure Falco for Docker
    sudo tee /etc/falco/falco_rules.local.yaml << EOF
- rule: Container With Unexpected Shell
  desc: Detect container with unexpected interactive shell
  condition: >
    spawned_process and container and
    (proc.name in (shell_binaries) or
     proc.name in (bash, sh, zsh, dash, ash))
  output: >
    Container with unexpected shell spawned
    (user=%user.name command=%proc.cmdline container_id=%container.id image=%container.image.repository)
  priority: WARNING

- rule: Container Privilege Escalation
  desc: Detect container attempting privilege escalation
  condition: >
    spawned_process and container and
    proc.name in (sudo, su, doas)
  output: >
    Container attempting privilege escalation
    (user=%user.name command=%proc.cmdline container_id=%container.id image=%container.image.repository)
  priority: HIGH
EOF
    
    sudo systemctl enable falco
    sudo systemctl start falco
    echo "✅ Falco installed and configured"
}

# Security monitoring function
monitor_docker_security() {
    echo "🔍 Running Docker Security Audit..."
    
    # Check for running privileged containers
    echo "Checking for privileged containers..."
    PRIVILEGED=$(docker ps --filter "label=privileged=true" --format "table {{.Names}}\t{{.Image}}\t{{.Status}}")
    if [[ -n "$PRIVILEGED" ]]; then
        echo "⚠️  Privileged containers found:"
        echo "$PRIVILEGED"
    else
        echo "✅ No privileged containers found"
    fi
    
    # Check for containers running as root
    echo "Checking for containers running as root..."
    for container in $(docker ps -q); do
        ROOT_USER=$(docker exec "$container" id -u 2>/dev/null)
        if [[ "$ROOT_USER" == "0" ]]; then
            CONTAINER_NAME=$(docker inspect --format '{{.Name}}' "$container" | sed 's/^.//')
            CONTAINER_IMAGE=$(docker inspect --format '{{.Config.Image}}' "$container")
            echo "⚠️  Container $CONTAINER_NAME ($CONTAINER_IMAGE) running as root"
        fi
    done
    
    # Check for exposed Docker daemon
    echo "Checking Docker daemon exposure..."
    if netstat -ln | grep -q ":2375.*LISTEN"; then
        echo "🚨 CRITICAL: Docker daemon exposed on port 2375!"
    elif netstat -ln | grep -q ":2376.*LISTEN"; then
        echo "✅ Docker daemon secured on port 2376 (TLS)"
    else
        echo "✅ Docker daemon not exposed"
    fi
    
    # Check for containers with excessive capabilities
    echo "Checking container capabilities..."
    for container in $(docker ps -q); do
        CAPS=$(docker inspect --format '{{.HostConfig.CapAdd}}' "$container")
        if [[ "$CAPS" != "<no value>" ]] && [[ "$CAPS" != "[]" ]]; then
            CONTAINER_NAME=$(docker inspect --format '{{.Name}}' "$container" | sed 's/^.//')
            echo "⚠️  Container $CONTAINER_NAME has additional capabilities: $CAPS"
        fi
    done
}

# Vulnerability scanning function
scan_images() {
    echo "🔍 Scanning Docker images for vulnerabilities..."
    
    # Get all images
    IMAGES=$(docker images --format "{{.Repository}}:{{.Tag}}" | grep -v "<none>")
    
    for image in $IMAGES; do
        echo "Scanning $image..."
        if command -v trivy &> /dev/null; then
            trivy image --severity HIGH,CRITICAL --quiet "$image"
        else
            echo "⚠️  Trivy not installed. Run: curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin"
        fi
    done
}

# Docker daemon hardening
harden_docker_daemon() {
    echo "🔧 Hardening Docker daemon..."
    
    DAEMON_CONFIG="/etc/docker/daemon.json"
    
    # Backup existing config
    if [[ -f "$DAEMON_CONFIG" ]]; then
        sudo cp "$DAEMON_CONFIG" "$DAEMON_CONFIG.backup"
    fi
    
    # Create secure daemon.json
    sudo tee "$DAEMON_CONFIG" << EOF
{
  "icc": false,
  "userns-remap": "default",
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3"
  },
  "live-restore": true,
  "userland-proxy": false,
  "no-new-privileges": true,
  "seccomp-profile": "/etc/docker/seccomp.json",
  "default-ulimits": {
    "nofile": {
      "Hard": 64000,
      "Name": "nofile",
      "Soft": 64000
    }
  }
}
EOF
    
    echo "✅ Docker daemon configuration hardened"
    echo "⚠️  Restart Docker daemon to apply changes: sudo systemctl restart docker"
}

# Create security monitoring cron job
setup_security_monitoring() {
    echo "⏰ Setting up automated security monitoring..."
    
    # Create monitoring script
    sudo tee /usr/local/bin/docker-security-monitor.sh << 'EOF'
#!/bin/bash
LOG_FILE="/var/log/docker-security.log"
DATE=$(date '+%Y-%m-%d %H:%M:%S')

echo "[$DATE] Docker Security Scan Started" >> "$LOG_FILE"

# Check for new privileged containers
PRIVILEGED=$(docker ps --filter "label=privileged=true" --format "{{.Names}}")
if [[ -n "$PRIVILEGED" ]]; then
    echo "[$DATE] WARNING: Privileged containers: $PRIVILEGED" >> "$LOG_FILE"
fi

# Check for containers running as root
for container in $(docker ps -q); do
    ROOT_USER=$(docker exec "$container" id -u 2>/dev/null)
    if [[ "$ROOT_USER" == "0" ]]; then
        CONTAINER_NAME=$(docker inspect --format '{{.Name}}' "$container" | sed 's/^.//')
        echo "[$DATE] WARNING: Container $CONTAINER_NAME running as root" >> "$LOG_FILE"
    fi
done

echo "[$DATE] Docker Security Scan Completed" >> "$LOG_FILE"
EOF
    
    sudo chmod +x /usr/local/bin/docker-security-monitor.sh
    
    # Add to cron (run every hour)
    (crontab -l 2>/dev/null; echo "0 * * * * /usr/local/bin/docker-security-monitor.sh") | crontab -
    
    echo "✅ Security monitoring scheduled (hourly)"
}

# Main menu
show_menu() {
    echo ""
    echo "🛡️  Docker Security Toolkit"
    echo "=========================="
    echo "1. Install Security Tools"
    echo "2. Run Security Audit"
    echo "3. Scan Images for Vulnerabilities"
    echo "4. Harden Docker Daemon"
    echo "5. Setup Security Monitoring"
    echo "6. View Security Logs"
    echo "7. Exit"
    echo ""
}

# Main execution
while true; do
    show_menu
    read -p "Select option (1-7): " choice
    
    case $choice in
        1)
            install_trivy
            install_docker_bench
            install_falco
            ;;
        2)
            monitor_docker_security
            ;;
        3)
            scan_images
            ;;
        4)
            harden_docker_daemon
            ;;
        5)
            setup_security_monitoring
            ;;
        6)
            if [[ -f "/var/log/docker-security.log" ]]; then
                tail -50 /var/log/docker-security.log
            else
                echo "No security logs found"
            fi
            ;;
        7)
            echo "Goodbye!"
            exit 0
            ;;
        *)
            echo "Invalid option"
            ;;
    esac
    
    echo ""
    read -p "Press Enter to continue..."
done 