# Docker Security Scripts Documentation

This document provides instructions on how to use the `docker-security-tools.sh` and `secure-docker-setup.sh` scripts to enhance the security of your Dockerized Frappe/ERPNext environment.

## 1. `docker-security-tools.sh` - Docker Security Toolkit

This script provides a comprehensive toolkit for installing, configuring, and running various Docker security tools. It helps you perform security audits, scan for vulnerabilities, and harden your Docker environment.

### How to Use

1.  **Make the script executable:**
    ```bash
    chmod +x docker-security-tools.sh
    ```

2.  **Run the script:**
    ```bash
    sudo ./docker-security-tools.sh
    ```

The script will present you with a menu of options to choose from.

### Menu Options

*   **1. Install Security Tools:**
    *   Installs essential security tools:
        *   **Trivy:** A powerful vulnerability scanner for container images.
        *   **Docker Bench Security:** A script that checks for dozens of common best-practices around deploying Docker containers in production.
        *   **Falco:** A runtime security tool that detects and alerts on anomalous activity in your containers.

*   **2. Run Security Audit:**
    *   Performs a security audit of your Docker environment, checking for:
        *   Containers running with the `--privileged` flag.
        *   Containers running as the `root` user.
        *   Exposure of the Docker daemon socket.
        *   Containers with excessive capabilities.

*   **3. Scan Images for Vulnerabilities:**
    *   Uses Trivy to scan all your local Docker images for known vulnerabilities (CVEs).

*   **4. Harden Docker Daemon:**
    *   Applies security best practices to the Docker daemon by creating a secure `/etc/docker/daemon.json` configuration file.
    *   **Note:** You will need to restart the Docker daemon for the changes to take effect (`sudo systemctl restart docker`).

*   **5. Setup Security Monitoring:**
    *   Creates a cron job that runs a security scan every hour and logs the results to `/var/log/docker-security.log`.

*   **6. View Security Logs:**
    *   Displays the last 50 lines of the security log file.

*   **7. Exit:**
    *   Exits the script.

## 2. `secure-docker-setup.sh` - Secure Frappe/ERPNext Setup

This script is a security-hardened version of the `generate_frappe_docker.sh` script. It creates a `docker-compose.yml` file with numerous security enhancements to protect your Frappe/ERPNext installation.

### How to Use

1.  **Make the script executable:**
    ```bash
    chmod +x secure-docker-setup.sh
    ```

2.  **Run the script:**
    ```bash
    ./secure-docker-setup.sh
    ```

The script will guide you through the process of creating a secure `docker-compose.yml` file for your Frappe/ERPNext site.

### Security Features

*   **Non-Root Containers:** Configures containers to run as non-root users, reducing the risk of privilege escalation.
*   **Resource Limits:** Sets CPU and memory limits for containers to prevent resource exhaustion.
*   **Read-Only Filesystems:** Mounts container filesystems as read-only where possible, preventing unauthorized modifications.
*   **Capability Dropping:** Removes unnecessary Linux capabilities from containers to reduce their attack surface.
*   **Network Isolation:** Creates separate Docker networks for the application and the database to restrict communication.
*   **Secure Password Generation:** Automatically generates strong, random passwords for the database and administrator accounts.
*   **Docker Secrets:** Uses Docker secrets to manage passwords securely, avoiding the need to store them in environment variables.
*   **Security Headers:** Adds important security headers (e.g., HSTS, X-Frame-Options) to the Traefik configuration to protect against common web vulnerabilities.

### Output

The script will create a new directory for your site, which will contain the following:

*   `secure-<site-name>-docker-compose.yml`: The security-hardened `docker-compose.yml` file.
*   `.env`: An environment file with secure defaults.
*   `secrets/`: A directory containing the generated passwords for the database and administrator accounts.

**IMPORTANT:** Make sure to save the generated passwords in a secure location. You will need them to access your Frappe/ERPNext site and manage the database.
