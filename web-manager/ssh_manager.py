#!/usr/bin/env python3
"""
SSH Connection Manager for Docker Containers
Comprehensive SSH server setup and port forwarding management
"""

import subprocess
import json
import os
import time
import logging
import socket
import uuid
import re
from datetime import datetime, timedelta
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

# Setup logging
logger = logging.getLogger(__name__)

class SSHManager:
    """Comprehensive SSH connection management for Docker containers"""
    
    def __init__(self):
        self.ssh_connections = {}
        self.sessions_dir = "ssh_sessions"
        self._ensure_sessions_dir()
    
    def _ensure_sessions_dir(self):
        """Ensure SSH sessions directory exists"""
        if not os.path.exists(self.sessions_dir):
            os.makedirs(self.sessions_dir)
    
    def setup_ssh_server_in_container(self, container, username, public_key, port=22):
        """
        FIXED: Setup SSH server in Docker container with proper verification
        
        Args:
            container: Docker container name
            username: SSH user to create
            public_key: SSH public key for authentication
            port: Port for external access (SSH always runs on 22 internally)
        
        Returns:
            dict: {'success': bool, 'error': str}
        """
        logger.info(f"Setting up SSH server for {username} in container {container}")
        
        try:
            # 1. Install SSH server if not present
            install_result = self._install_ssh_server(container)
            if not install_result['success']:
                return install_result
            
            # 2. Create user if doesn't exist
            user_result = self._create_ssh_user(container, username)
            if not user_result['success']:
                return user_result
            
            # 3. Setup SSH keys and permissions
            keys_result = self._setup_ssh_keys(container, username, public_key)
            if not keys_result['success']:
                return keys_result
            
            # 4. Configure SSH server (FIXED: SSH runs on port 22, not custom port)
            config_result = self._configure_ssh_server(container)
            if not config_result['success']:
                return config_result
            
            # 5. Generate SSH host keys
            hostkeys_result = self._generate_host_keys(container)
            if not hostkeys_result['success']:
                return hostkeys_result
            
            # 6. Start SSH server (FIXED: Use proper method for containers)
            start_result = self._start_ssh_server(container)
            if not start_result['success']:
                return start_result
            
            # 7. CRITICAL: Verify SSH is actually running
            verify_result = self._verify_ssh_running(container)
            if not verify_result['success']:
                return verify_result
            
            logger.info(f"SSH server successfully configured in {container}")
            return {'success': True, 'message': f'SSH server running on port 22 in {container}'}
            
        except Exception as e:
            logger.error(f"SSH setup error: {str(e)}")
            return {'success': False, 'error': str(e)}
    
    def _install_ssh_server(self, container):
        """Install SSH server in container"""
        cmd = ["sudo", "docker", "exec", "-u", "root", container, "bash", "-c", 
               "which sshd || (apt-get update && apt-get install -y openssh-server)"]
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode != 0:
            logger.error(f"SSH server installation failed: {result.stderr}")
            return {'success': False, 'error': f'SSH installation failed: {result.stderr}'}
        
        return {'success': True}
    
    def _create_ssh_user(self, container, username):
        """Create SSH user if doesn't exist"""
        cmd = ["sudo", "docker", "exec", "-u", "root", container, "bash", "-c", 
               f"id {username} || useradd -m -s /bin/bash {username}"]
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode != 0 and "already exists" not in result.stderr.lower():
            logger.error(f"User creation failed: {result.stderr}")
            return {'success': False, 'error': f'User creation failed: {result.stderr}'}
        
        return {'success': True}
    
    def _setup_ssh_keys(self, container, username, public_key):
        """Setup SSH keys and permissions"""
        commands = [
            f"mkdir -p /home/{username}/.ssh",
            f"echo '{public_key}' > /home/{username}/.ssh/authorized_keys",
            f"chown -R {username}:{username} /home/{username}/.ssh",
            f"chmod 700 /home/{username}/.ssh",
            f"chmod 600 /home/{username}/.ssh/authorized_keys"
        ]
        
        for cmd_str in commands:
            cmd = ["sudo", "docker", "exec", "-u", "root", container, "bash", "-c", cmd_str]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode != 0:
                logger.error(f"SSH key setup failed: {cmd_str} - {result.stderr}")
                return {'success': False, 'error': f'SSH key setup failed: {result.stderr}'}
        
        return {'success': True}
    
    def _configure_ssh_server(self, container):
        """Configure SSH server (FIXED: SSH runs on port 22)"""
        ssh_config = """Port 22
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
StrictModes no
UsePAM yes
X11Forwarding no
PrintMotd no"""
        
        cmd = ["sudo", "docker", "exec", "-u", "root", container, "bash", "-c", 
               f"cat > /etc/ssh/sshd_config << 'EOF'\n{ssh_config}\nEOF"]
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode != 0:
            logger.error(f"SSH config failed: {result.stderr}")
            return {'success': False, 'error': f'SSH configuration failed: {result.stderr}'}
        
        return {'success': True}
    
    def _generate_host_keys(self, container):
        """Generate SSH host keys"""
        cmd = ["sudo", "docker", "exec", "-u", "root", container, "bash", "-c", 
               "ssh-keygen -A && mkdir -p /var/run/sshd"]
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode != 0:
            logger.warning(f"Host key generation warning: {result.stderr}")
            # Don't fail on host key generation issues
        
        return {'success': True}
    
    def _start_ssh_server(self, container):
        """Start SSH server (FIXED: Use service command for containers)"""
        # Try multiple methods to start SSH
        start_methods = [
            "service ssh start",
            "systemctl start ssh",
            "/usr/sbin/sshd -D &"
        ]
        
        for method in start_methods:
            cmd = ["sudo", "docker", "exec", "-u", "root", container, "bash", "-c", method]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                logger.info(f"SSH started using: {method}")
                time.sleep(2)  # Give SSH time to start
                return {'success': True}
            else:
                logger.warning(f"SSH start method failed: {method} - {result.stderr}")
        
        return {'success': False, 'error': 'All SSH start methods failed'}
    
    def _verify_ssh_running(self, container):
        """Verify SSH server is actually running on port 22"""
        cmd = ["sudo", "docker", "exec", container, "ss", "-tlnp"]
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode != 0:
            return {'success': False, 'error': 'Cannot check SSH status'}
        
        if ":22" not in result.stdout:
            logger.error("SSH server not listening on port 22")
            return {'success': False, 'error': 'SSH server not listening on port 22'}
        
        logger.info("SSH server verified running on port 22")
        return {'success': True}
    
    def expose_ssh_port(self, container, external_port):
        """
        FIXED: Expose SSH port using socat (forwards to port 22, not custom port)
        
        Args:
            container: Docker container name
            external_port: External port to expose SSH on
        
        Returns:
            dict: {'success': bool, 'error': str, 'pid': int}
        """
        try:
            logger.info(f"Exposing SSH port {external_port} for container {container}")
            
            # 1. Kill existing socat processes on this port
            self._kill_existing_socat(external_port)
            
            # 2. Get container IP
            container_ip = self._get_container_ip(container)
            if not container_ip:
                return {'success': False, 'error': 'Could not get container IP'}
            
            # 3. Verify SSH is running in container
            if not self._verify_ssh_running(container)['success']:
                return {'success': False, 'error': 'SSH server not running in container'}
            
            # 4. Start socat port forwarding (FIXED: Forward to port 22)
            socat_result = self._start_socat_forwarding(container_ip, external_port)
            if not socat_result['success']:
                return socat_result
            
            # 5. Verify socat is running
            verify_result = self._verify_socat_running(external_port)
            if not verify_result['success']:
                return verify_result
            
            logger.info(f"Port forwarding established: {external_port} -> {container_ip}:22")
            return {
                'success': True, 
                'message': f'Port forwarding: {external_port} -> {container_ip}:22',
                'pid': socat_result.get('pid')
            }
            
        except Exception as e:
            logger.error(f"Port exposure error: {str(e)}")
            return {'success': False, 'error': str(e)}
    
    def _kill_existing_socat(self, port):
        """Kill existing socat processes on port"""
        cmd = ["sudo", "-n", "pkill", "-f", f"socat.*{port}"]
        subprocess.run(cmd, capture_output=True, text=True)
        
        # Also kill any process using the port
        cmd = ["sudo", "fuser", "-k", f"{port}/tcp"]
        subprocess.run(cmd, capture_output=True, text=True)
    
    def _get_container_ip(self, container):
        """Get container IP address with proper validation"""
        cmd = ["sudo", "docker", "inspect", container, 
               "--format", "{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}"]
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode != 0:
            logger.error(f"Container IP lookup failed: {result.stderr}")
            return None
        
        # Extract valid IP addresses
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        ips = re.findall(ip_pattern, result.stdout.strip())
        
        # Filter out invalid IPs
        valid_ips = []
        for ip in ips:
            parts = ip.split('.')
            if all(0 <= int(part) <= 255 for part in parts):
                valid_ips.append(ip)
        
        if not valid_ips:
            logger.error(f"No valid IP found for container {container}")
            return None
        
        # Prefer Frappe network IPs (172.22.x.x) if available
        frappe_ips = [ip for ip in valid_ips if ip.startswith('172.22.')]
        container_ip = frappe_ips[0] if frappe_ips else valid_ips[0]
        
        logger.info(f"Container {container} IP: {container_ip}")
        return container_ip
    
    def _start_socat_forwarding(self, container_ip, external_port):
        """Start socat port forwarding with proper process management"""
        # Check if socat is available (should be installed by docker-manager.sh)
        result = subprocess.run(['which', 'socat'], capture_output=True, text=True)
        if result.returncode != 0:
            raise Exception("socat is not installed. Please run the docker-manager.sh script first or install socat manually: sudo apt install socat")
        
        # FIXED: Forward to port 22 (SSH port), not custom port
        # Try socat without sudo first, then with sudo if needed
        socat_cmd = [
            "socat",
            f"TCP-LISTEN:{external_port},bind=0.0.0.0,fork,reuseaddr",
            f"TCP:{container_ip}:22"  # FIXED: Always forward to port 22
        ]
        
        log_file = f"ssh_sessions/socat_{external_port}.log"
        
        try:
            # Start socat with proper process management
            with open(log_file, "w") as log_f:
                process = subprocess.Popen(
                    socat_cmd,
                    stdout=log_f,
                    stderr=subprocess.STDOUT,
                    preexec_fn=os.setsid  # Create new session
                )
            
            # Check if socat started successfully, if not try with sudo
            time.sleep(1)
            check_cmd = ["pgrep", "-f", f"socat.*{external_port}"]
            check_result = subprocess.run(check_cmd, capture_output=True, text=True)
            
            if check_result.returncode != 0:
                # Socat failed, try with sudo
                logger.info("Socat failed without sudo, trying with sudo...")
                socat_cmd_sudo = ["sudo", "-n", "socat"] + socat_cmd[1:]
                
                # Kill the failed process
                process.terminate()
                
                # Start with sudo
                process = subprocess.Popen(
                    socat_cmd_sudo,
                    stdout=log_f,
                    stderr=subprocess.STDOUT,
                    preexec_fn=os.setsid
                )
            
            # Give socat time to start
            time.sleep(2)
            
            # Check if process is still running
            if process.poll() is not None:
                # Process died, check log
                try:
                    with open(log_file, 'r') as f:
                        error_log = f.read()
                    logger.error(f"Socat failed to start. Log: {error_log}")
                    return {'success': False, 'error': f'Socat failed: {error_log}'}
                except:
                    return {'success': False, 'error': 'Socat failed to start'}
            
            logger.info(f"Socat started: PID {process.pid}")
            return {'success': True, 'pid': process.pid}
            
        except Exception as e:
            logger.error(f"Socat start error: {str(e)}")
            return {'success': False, 'error': str(e)}
    
    def _verify_socat_running(self, port):
        """Verify socat is running and listening"""
        # Check with pgrep
        cmd = ["sudo", "-n", "pgrep", "-f", f"socat.*{port}"]
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode != 0:
            return {'success': False, 'error': 'Socat process not found'}
        
        # Check with ss
        cmd = ["sudo", "ss", "-tlnp"]
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if f":{port}" not in result.stdout:
            return {'success': False, 'error': f'Port {port} not listening'}
        
        return {'success': True}
    
    def generate_ssh_key_pair(self):
        """Generate SSH key pair using cryptography library"""
        try:
            # Generate private key
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
            )
            
            # Get private key in PEM format
            private_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ).decode('utf-8')
            
            # Get public key in OpenSSH format
            public_key = private_key.public_key()
            public_ssh = public_key.public_bytes(
                encoding=serialization.Encoding.OpenSSH,
                format=serialization.PublicFormat.OpenSSH
            ).decode('utf-8')
            
            logger.info("SSH key pair generated successfully")
            return private_pem, public_ssh
            
        except Exception as e:
            logger.error(f"SSH key generation failed: {str(e)}")
            # Fallback to ssh-keygen
            return self._generate_ssh_key_fallback()
    
    def _generate_ssh_key_fallback(self):
        """Fallback SSH key generation using ssh-keygen"""
        import tempfile
        
        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                key_path = os.path.join(temp_dir, 'temp_key')
                
                # Generate key using ssh-keygen
                cmd = ['ssh-keygen', '-t', 'rsa', '-b', '2048', '-f', key_path, '-N', '', '-C', 'temp_ssh_key']
                result = subprocess.run(cmd, capture_output=True, text=True)
                
                if result.returncode != 0:
                    raise Exception(f"ssh-keygen failed: {result.stderr}")
                
                # Read private key
                with open(key_path, 'r') as f:
                    private_pem = f.read()
                
                # Read public key
                with open(f"{key_path}.pub", 'r') as f:
                    public_ssh = f.read().strip()
                
                logger.info("SSH key pair generated using ssh-keygen fallback")
                return private_pem, public_ssh
                
        except Exception as e:
            logger.error(f"Fallback SSH key generation failed: {str(e)}")
            raise Exception(f"SSH key generation failed: {str(e)}")
    
    def create_ssh_session(self, container, username='frappe', duration=24, port=None, description='', access_type='public'):
        """
        Create temporary SSH session with proper setup and verification
        
        Args:
            container: Docker container name
            username: SSH username (default: frappe)
            duration: Session duration in hours (default: 24)
            port: External port (auto-assigned if None)
            description: Session description
            access_type: 'public' or 'private' - determines IP type to use (default: 'public')
        
        Returns:
            dict: Session information or error
        """
        try:
            logger.info(f"Creating SSH session for {container}")
            
            # Generate session ID and key name
            session_id = str(uuid.uuid4())
            key_name = f"temp_ssh_{session_id[:8]}"
            
            # Generate SSH key pair
            try:
                private_key, public_key = self.generate_ssh_key_pair()
                logger.info("SSH key pair generated successfully")
            except Exception as e:
                logger.error(f"Key generation failed: {str(e)}")
                return {'success': False, 'error': f'Key generation failed: {str(e)}'}
            
            # Find available port if not specified
            if not port:
                port = self._find_available_port(2222, 2299)
                if not port:
                    return {'success': False, 'error': 'No available ports'}
            
            # Setup SSH server in container
            setup_result = self.setup_ssh_server_in_container(container, username, public_key, port)
            if not setup_result['success']:
                return setup_result
            
            # Expose SSH port
            expose_result = self.expose_ssh_port(container, port)
            if not expose_result['success']:
                return expose_result
            
            # Create session info
            expires_at = datetime.now() + timedelta(hours=duration)
            server_ip = self._get_server_ip(access_type)
            
            session_info = {
                'session_id': session_id,
                'container': container,
                'username': username,
                'port': port,
                'key_name': key_name,
                'private_key': private_key,
                'public_key': public_key,
                'host': server_ip,
                'created_at': datetime.now(),
                'expires_at': expires_at,
                'description': description,
                'access_type': access_type,
                'status': 'active'
            }
            
            # Store session
            self.ssh_connections[session_id] = session_info
            self._save_session_to_file(session_info)
            
            logger.info(f"SSH session created successfully: {session_id}")
            
            return {
                'success': True,
                'session': {
                    'session_id': session_id,
                    'container': container,
                    'username': username,
                    'port': port,
                    'key_name': key_name,
                    'host': server_ip,
                    'created_at': session_info['created_at'].isoformat(),
                    'expires_at': session_info['expires_at'].isoformat(),
                    'description': description,
                    'status': 'active'
                },
                'connection_details': {
                    'host': server_ip,
                    'port': port,
                    'username': username,
                    'key_name': key_name
                },
                'message': f'SSH session created for {container}'
            }
            
        except Exception as e:
            logger.error(f"SSH session creation error: {str(e)}")
            return {'success': False, 'error': str(e)}
    
    def _find_available_port(self, start_port, end_port):
        """Find available port in range"""
        for port in range(start_port, end_port + 1):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            result = sock.connect_ex(('localhost', port))
            sock.close()
            if result != 0:
                return port
        return None
    
    def _is_vps_environment(self):
        """Detect if running on VPS or local environment"""
        try:
            # Check for VPS indicators
            vps_indicators = [
                # Check if we have a public IP (not private range)
                self._has_public_ip(),
                # Check for cloud provider indicators
                self._is_cloud_instance(),
                # Check if external services are accessible
                self._can_access_external_services()
            ]
            
            # If majority of indicators suggest VPS, return True
            vps_score = sum(vps_indicators)
            is_vps = vps_score >= 2
            
            logger.info(f"Environment detection: VPS={is_vps} (score: {vps_score}/3)")
            return is_vps
            
        except Exception as e:
            logger.warning(f"Environment detection failed: {str(e)}")
            # Default to local if detection fails
            return False
    
    def _has_public_ip(self):
        """Check if server has a public IP address"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            
            # Check if IP is in private ranges
            private_ranges = [
                ("10.0.0.0", "10.255.255.255"),
                ("172.16.0.0", "172.31.255.255"),
                ("192.168.0.0", "192.168.255.255"),
                ("127.0.0.0", "127.255.255.255")
            ]
            
            for start, end in private_ranges:
                if self._ip_in_range(local_ip, start, end):
                    return False  # Private IP, likely local
            
            return True  # Public IP, likely VPS
            
        except:
            return False
    
    def _is_cloud_instance(self):
        """Check if running on cloud instance"""
        try:
            # Check for cloud provider metadata services
            cloud_indicators = [
                # AWS EC2
                self._check_url("http://169.254.169.254/latest/meta-data/", timeout=2),
                # Google Cloud
                self._check_url("http://metadata.google.internal/computeMetadata/v1/", timeout=2),
                # Azure
                self._check_url("http://169.254.169.254/metadata/instance", timeout=2)
            ]
            return any(cloud_indicators)
        except:
            return False
    
    def _can_access_external_services(self):
        """Check if external services are accessible"""
        try:
            import urllib.request
            with urllib.request.urlopen('http://ifconfig.me', timeout=3) as response:
                return response.getcode() == 200
        except:
            return False
    
    def _check_url(self, url, timeout=2):
        """Check if URL is accessible"""
        try:
            import urllib.request
            with urllib.request.urlopen(url, timeout=timeout) as response:
                return response.getcode() == 200
        except:
            return False
    
    def _ip_in_range(self, ip, start, end):
        """Check if IP is in given range"""
        try:
            ip_int = int(''.join([f"{int(x):03d}" for x in ip.split('.')]))
            start_int = int(''.join([f"{int(x):03d}" for x in start.split('.')]))
            end_int = int(''.join([f"{int(x):03d}" for x in end.split('.')]))
            return start_int <= ip_int <= end_int
        except:
            return False

    def _get_server_ip(self, access_type='public'):
        """Get server IP address based on access type - SIMPLIFIED
        
        Args:
            access_type: 'public' or 'private'
                - 'public': Get real public IP from external service
                - 'private': Get local/private IP
        
        Returns:
            str: IP address (public or private based on access_type)
        """
        if access_type == 'private':
            # User wants private/local IP
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect(("8.8.8.8", 80))
                ip = s.getsockname()[0]
                s.close()
                logger.info(f"Private IP selected - Using local IP: {ip}")
                return ip
            except Exception as e:
                logger.warning(f"Could not get local IP: {str(e)}")
                return "localhost"
        else:
            # User wants public IP - always try to get real public IP
            try:
                import urllib.request
                # Try multiple public IP services
                services = [
                    'http://ifconfig.me',
                    'http://api.ipify.org',
                    'http://icanhazip.com'
                ]
                
                for service in services:
                    try:
                        with urllib.request.urlopen(service, timeout=5) as response:
                            public_ip = response.read().decode('utf-8').strip()
                            if public_ip and self._is_valid_ip(public_ip):
                                logger.info(f"Public IP selected - Using real IP: {public_ip}")
                                return public_ip
                    except:
                        continue
                
                # If all public IP services fail, fallback to local IP
                logger.warning("Could not get public IP from any service, using local IP as fallback")
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect(("8.8.8.8", 80))
                ip = s.getsockname()[0]
                s.close()
                logger.info(f"Fallback to local IP: {ip}")
                return ip
                
            except Exception as e:
                logger.error(f"Error getting IP: {str(e)}")
                return "localhost"
    
    def _is_valid_ip(self, ip):
        """Validate IP address format"""
        try:
            socket.inet_aton(ip)
            return True
        except socket.error:
            return False
    
    def _save_session_to_file(self, session_info):
        """Save session to persistent file storage"""
        try:
            session_file = os.path.join(self.sessions_dir, f"{session_info['session_id']}.json")
            
            # Convert datetime objects for JSON serialization
            session_data = session_info.copy()
            session_data['created_at'] = session_data['created_at'].isoformat()
            session_data['expires_at'] = session_data['expires_at'].isoformat()
            
            with open(session_file, 'w') as f:
                json.dump(session_data, f, indent=2)
            
            logger.info(f"Session saved to {session_file}")
            
        except Exception as e:
            logger.error(f"Failed to save session: {str(e)}")
    
    def get_ssh_sessions(self):
        """Get all active SSH sessions"""
        active_sessions = []
        for session_id, session in self.ssh_connections.items():
            if session['status'] == 'active' and session['expires_at'] > datetime.now():
                active_sessions.append({
                    'session_id': session_id,
                    'container': session['container'],
                    'username': session['username'],
                    'port': session['port'],
                    'created_at': session['created_at'].isoformat(),
                    'expires_at': session['expires_at'].isoformat(),
                    'status': session['status'],
                    'description': session['description']
                })
        
        return active_sessions
    
    def revoke_ssh_session(self, session_id):
        """Revoke SSH session and cleanup"""
        try:
            if session_id not in self.ssh_connections:
                return {'success': False, 'error': 'Session not found'}
            
            session = self.ssh_connections[session_id]
            
            # Stop SSH server and port forwarding
            self._cleanup_session(session)
            
            # Remove session
            del self.ssh_connections[session_id]
            
            # Remove session file
            session_file = os.path.join(self.sessions_dir, f"{session_id}.json")
            if os.path.exists(session_file):
                os.remove(session_file)
            
            logger.info(f"SSH session revoked: {session_id}")
            return {'success': True, 'message': 'SSH session revoked'}
            
        except Exception as e:
            logger.error(f"Session revocation error: {str(e)}")
            return {'success': False, 'error': str(e)}
    
    def _has_other_active_sessions(self, container, username):
        """Check if there are other active SSH sessions for the same user in the same container"""
        try:
            for session_id, session in self.ssh_connections.items():
                if (session['container'] == container and 
                    session['username'] == username and 
                    session['status'] == 'active' and 
                    session['expires_at'] > datetime.now()):
                    return True
            return False
        except Exception as e:
            logger.error(f"Error checking active sessions: {str(e)}")
            return True  # Conservative approach - don't remove if we can't check

    def _remove_ssh_keys_from_container(self, container, username, remove_user=False):
        """Remove SSH keys from Docker container
        
        Args:
            container: Docker container name
            username: SSH username to clean up
            remove_user: If True, remove the entire user account
        """
        try:
            logger.info(f"Removing SSH keys for {username} from {container}")
            
            # Remove authorized_keys file
            cmd = ["sudo", "docker", "exec", "-u", "root", container, "bash", "-c", 
                   f"rm -f /home/{username}/.ssh/authorized_keys"]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode != 0:
                logger.warning(f"Failed to remove authorized_keys: {result.stderr}")
            
            # Remove .ssh directory if empty
            cmd = ["sudo", "docker", "exec", "-u", "root", container, "bash", "-c", 
                   f"rmdir /home/{username}/.ssh 2>/dev/null || true"]
            subprocess.run(cmd, capture_output=True, text=True)
            
            # Optionally remove the entire user account
            if remove_user:
                logger.info(f"Removing user {username} from {container}")
                cmd = ["sudo", "docker", "exec", "-u", "root", container, "bash", "-c", 
                       f"userdel -r {username} 2>/dev/null || true"]
                result = subprocess.run(cmd, capture_output=True, text=True)
                
                if result.returncode == 0:
                    logger.info(f"User {username} removed from {container}")
                else:
                    logger.warning(f"Failed to remove user {username}: {result.stderr}")
            
            logger.info(f"SSH keys removed for {username} from {container}")
            
        except Exception as e:
            logger.error(f"SSH key removal error: {str(e)}")

    def _cleanup_session(self, session):
        """Cleanup SSH session resources"""
        try:
            container = session['container']
            port = session['port']
            username = session['username']
            
            # Kill socat process
            subprocess.run(['sudo', 'pkill', '-f', f'socat.*{port}'], 
                         capture_output=True, text=True)
            
            # Remove socat log file
            log_file = f"ssh_sessions/socat_{port}.log"
            if os.path.exists(log_file):
                try:
                    os.remove(log_file)
                    logger.info(f"Removed socat log file: {log_file}")
                except Exception as e:
                    logger.warning(f"Failed to remove log file {log_file}: {str(e)}")
            
            # Remove SSH keys from container
            # Only remove user if no other active sessions exist for this user
            remove_user = not self._has_other_active_sessions(container, username)
            self._remove_ssh_keys_from_container(container, username, remove_user)
            
            # Stop SSH server (optional - may be used by other sessions)
            # subprocess.run(['sudo', 'docker', 'exec', container, 'service', 'ssh', 'stop'],
            #              capture_output=True, text=True)
            
            logger.info(f"Cleaned up session for {container}:{port}")
            
        except Exception as e:
            logger.error(f"Session cleanup error: {str(e)}")
    

    def cleanup_orphaned_log_files(self):
        """Clean up orphaned socat log files that don't have active sessions"""
        try:
            if not os.path.exists(self.sessions_dir):
                return
            
            # Get all active session ports
            active_ports = set()
            for session in self.ssh_connections.values():
                if session['status'] == 'active':
                    active_ports.add(session['port'])
            
            # Find all socat log files
            for filename in os.listdir(self.sessions_dir):
                if filename.startswith('socat_') and filename.endswith('.log'):
                    # Extract port from filename (socat_2222.log -> 2222)
                    try:
                        port_str = filename.replace('socat_', '').replace('.log', '')
                        port = int(port_str)
                        
                        # If port is not in active sessions, remove the log file
                        if port not in active_ports:
                            log_file = os.path.join(self.sessions_dir, filename)
                            os.remove(log_file)
                            logger.info(f"Removed orphaned log file: {filename}")
                    except ValueError:
                        # Skip files that don't match the expected pattern
                        continue
            
        except Exception as e:
            logger.error(f"Orphaned log cleanup error: {str(e)}")
    
    def cleanup_orphaned_ssh_users(self):
        """Clean up orphaned SSH users from containers that no longer have active sessions"""
        try:
            # Get list of all containers
            cmd = ["sudo", "docker", "ps", "--format", "{{.Names}}"]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode != 0:
                logger.error(f"Failed to list containers: {result.stderr}")
                return
            
            containers = result.stdout.strip().split('\n')
            containers = [c for c in containers if c]  # Filter empty strings
            
            # Get all active sessions grouped by container and username
            active_users = {}
            for session in self.ssh_connections.values():
                if session['status'] == 'active' and session['expires_at'] > datetime.now():
                    container = session['container']
                    username = session['username']
                    
                    if container not in active_users:
                        active_users[container] = set()
                    active_users[container].add(username)
            
            # Check each container for orphaned SSH users
            cleaned_count = 0
            for container in containers:
                try:
                    # List users with SSH directories
                    cmd = ["sudo", "docker", "exec", "-u", "root", container, "bash", "-c",
                           "find /home -maxdepth 2 -type d -name '.ssh' 2>/dev/null | sed 's|/home/||; s|/.ssh||'"]
                    result = subprocess.run(cmd, capture_output=True, text=True)
                    
                    if result.returncode != 0:
                        continue
                    
                    ssh_users = result.stdout.strip().split('\n')
                    ssh_users = [u for u in ssh_users if u and u != 'frappe']  # Keep frappe user
                    
                    # Remove users that don't have active sessions
                    for username in ssh_users:
                        if container not in active_users or username not in active_users[container]:
                            # Check if user has temp_ssh pattern (our temporary users)
                            if 'temp' in username.lower() or username.startswith('ssh_'):
                                logger.info(f"Removing orphaned SSH user {username} from {container}")
                                self._remove_ssh_keys_from_container(container, username, remove_user=True)
                                cleaned_count += 1
                
                except Exception as e:
                    logger.warning(f"Error checking container {container}: {str(e)}")
                    continue
            
            if cleaned_count > 0:
                logger.info(f"Cleaned up {cleaned_count} orphaned SSH users")
            else:
                logger.info("No orphaned SSH users found")
            
        except Exception as e:
            logger.error(f"Orphaned SSH user cleanup error: {str(e)}")
    

    def cleanup_expired_sessions(self):
        """Clean up expired SSH sessions"""
        try:
            current_time = datetime.now()
            expired_sessions = []
            
            for session_id, session in self.ssh_connections.items():
                if session['expires_at'] <= current_time:
                    expired_sessions.append(session_id)
            
            for session_id in expired_sessions:
                self.revoke_ssh_session(session_id)
            
            if expired_sessions:
                logger.info(f"Cleaned up {len(expired_sessions)} expired sessions")
            
            # Also clean up orphaned log files
            self.cleanup_orphaned_log_files()
            
        except Exception as e:
            logger.error(f"Expired session cleanup error: {str(e)}")
    
    def get_session_private_key(self, session_id):
        """Get private key for SSH session"""
        if session_id not in self.ssh_connections:
            return None
        
        return self.ssh_connections[session_id]['private_key']


# Create global SSH manager instance
ssh_manager = SSHManager()

# Convenience functions for backward compatibility
def setup_ssh_server_in_container(container, username, public_key, port=22):
    """Backward compatibility wrapper"""
    return ssh_manager.setup_ssh_server_in_container(container, username, public_key, port)

def expose_ssh_port_docker(container, port):
    """Backward compatibility wrapper"""
    return ssh_manager.expose_ssh_port(container, port)

def generate_ssh_key_pair():
    """Backward compatibility wrapper"""
    return ssh_manager.generate_ssh_key_pair()

def create_temp_ssh_session(container, username='frappe', duration=24, port=None, description='', access_type='public'):
    """Backward compatibility wrapper"""
    return ssh_manager.create_ssh_session(container, username, duration, port, description, access_type)

def get_ssh_sessions():
    """Backward compatibility wrapper"""
    return ssh_manager.get_ssh_sessions()

def revoke_ssh_session(session_id):
    """Backward compatibility wrapper"""
    return ssh_manager.revoke_ssh_session(session_id)

def cleanup_expired_sessions():
    """Backward compatibility wrapper"""
    return ssh_manager.cleanup_expired_sessions()

def get_session_private_key(session_id):
    """Backward compatibility wrapper"""
    return ssh_manager.get_session_private_key(session_id)

def cleanup_orphaned_log_files():
    """Backward compatibility wrapper"""
    return ssh_manager.cleanup_orphaned_log_files()

def cleanup_orphaned_ssh_users():
    """Backward compatibility wrapper"""
    return ssh_manager.cleanup_orphaned_ssh_users()
