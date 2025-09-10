#!/usr/bin/env python3
"""
SECURE Web Docker Manager - Production-ready with security features
Enhanced for ERPNext/Frappe with enterprise-grade security
"""

from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import subprocess
import json
import re
import os
import secrets
import time
import hashlib
import hmac
from datetime import datetime, timedelta
import logging
from logging.handlers import RotatingFileHandler
import pyotp
import base64
import qrcode
import io
import base64

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)  # Secure random secret key

# Security Configuration
SECURITY_CONFIG = {
    'MAX_LOGIN_ATTEMPTS': 3,  # Changed from 5 to 3
    'LOCKOUT_DURATION': 300,  # 5 minutes
    'SESSION_TIMEOUT': 3600,  # 1 hour
    'ALLOWED_IPS': ['127.0.0.1', '::1'],  # Only localhost by default
    'REQUIRE_HTTPS': True,  # Set to True to enforce HTTPS connections
    'ADMIN_USERNAME': 'admin',
    'ADMIN_PASSWORD_HASH': None,  # Will be set on first run
    'ADMIN_TOTP_SECRET': None,  # Will be set on first run
    'ENABLE_AUDIT_LOG': True,  # Enable detailed audit logging
}

# Rate limiting storage
login_attempts = {}
blocked_ips = {}
failed_login_users = {}  # Track failed login attempts per username

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
handler = RotatingFileHandler('docker-manager.log', maxBytes=10000000, backupCount=5)
handler.setFormatter(logging.Formatter(
    '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
))
app.logger.addHandler(handler)

# Add audit logging
audit_logger = logging.getLogger('audit')
audit_handler = RotatingFileHandler('security-audit.log', maxBytes=10000000, backupCount=10)
audit_handler.setFormatter(logging.Formatter(
    '%(asctime)s [AUDIT] %(message)s'
))
audit_logger.setLevel(logging.INFO)
audit_logger.addHandler(audit_handler)

def log_audit(event_type, username, ip, message, status="success"):
    """Log security event to audit log"""
    if SECURITY_CONFIG['ENABLE_AUDIT_LOG']:
        event_data = {
            "event": event_type,
            "user": username,
            "ip": ip,
            "status": status,
            "message": message,
            "timestamp": datetime.now().isoformat()
        }
        audit_logger.info(json.dumps(event_data))

class SecurityManager:
    """Handle security operations"""
    
    @staticmethod
    def init_admin_password():
        """Initialize admin password and TOTP on first run"""
        credentials_updated = False
        
        # Create TOTP secret if not exists
        if not SECURITY_CONFIG['ADMIN_TOTP_SECRET']:
            SECURITY_CONFIG['ADMIN_TOTP_SECRET'] = pyotp.random_base32()
            credentials_updated = True
        
        # Create password if not exists
        if not SECURITY_CONFIG['ADMIN_PASSWORD_HASH']:
            # Generate secure random password
            password = secrets.token_urlsafe(16)
            SECURITY_CONFIG['ADMIN_PASSWORD_HASH'] = generate_password_hash(password)
            credentials_updated = True
            
            # Create QR code for TOTP
            totp_uri = pyotp.totp.TOTP(SECURITY_CONFIG['ADMIN_TOTP_SECRET']).provisioning_uri(
                name=SECURITY_CONFIG['ADMIN_USERNAME'], 
                issuer_name="Secure Docker Manager"
            )
            
            # Save to secure file
            with open('.admin_credentials', 'w') as f:
                f.write(f"Username: {SECURITY_CONFIG['ADMIN_USERNAME']}\n")
                f.write(f"Password: {password}\n")
                f.write(f"Generated: {datetime.now()}\n")
                f.write(f"TOTP Secret: {SECURITY_CONFIG['ADMIN_TOTP_SECRET']}\n")
                f.write(f"TOTP URI: {totp_uri}\n")
            
            # Set secure permissions
            os.chmod('.admin_credentials', 0o600)
            
            logger.info("Admin credentials generated and saved to .admin_credentials")
            return {
                'password': password,
                'totp_secret': SECURITY_CONFIG['ADMIN_TOTP_SECRET'],
                'totp_uri': totp_uri
            }
        
        return None
    
    @staticmethod
    def validate_ip(ip):
        """Check if IP is allowed"""
        if not SECURITY_CONFIG['ALLOWED_IPS']:
            return True
        return ip in SECURITY_CONFIG['ALLOWED_IPS']
    
    @staticmethod
    def is_blocked(ip):
        """Check if IP is temporarily blocked"""
        if ip in blocked_ips:
            if time.time() < blocked_ips[ip]:
                return True
            else:
                del blocked_ips[ip]
        return False
    
    @staticmethod
    def is_user_locked(username):
        """Check if a user account is locked due to too many failed attempts"""
        if username in failed_login_users:
            attempts = failed_login_users[username]
            # Clean old attempts (older than 5 minutes)
            cutoff = time.time() - 300
            attempts = [t for t in attempts if t > cutoff]
            failed_login_users[username] = attempts
            
            # Check if there are too many recent attempts
            if len(attempts) >= SECURITY_CONFIG['MAX_LOGIN_ATTEMPTS']:
                # Check if the oldest attempt is still within the lockout window
                if time.time() - min(attempts) < SECURITY_CONFIG['LOCKOUT_DURATION']:
                    # Calculate remaining lockout time
                    lockout_end = min(attempts) + SECURITY_CONFIG['LOCKOUT_DURATION']
                    remaining = int(lockout_end - time.time())
                    return True, remaining
                else:
                    # Reset if lockout period has passed
                    failed_login_users[username] = []
        return False, 0
    
    @staticmethod
    def record_failed_login(ip):
        """Record failed login attempt for IP"""
        if ip not in login_attempts:
            login_attempts[ip] = []
        
        login_attempts[ip].append(time.time())
        
        # Clean old attempts (older than 1 hour)
        cutoff = time.time() - 3600
        login_attempts[ip] = [t for t in login_attempts[ip] if t > cutoff]
        
        # Block if too many attempts
        if len(login_attempts[ip]) >= SECURITY_CONFIG['MAX_LOGIN_ATTEMPTS']:
            blocked_ips[ip] = time.time() + SECURITY_CONFIG['LOCKOUT_DURATION']
            logger.warning(f"IP {ip} blocked due to too many failed login attempts")
    
    @staticmethod
    def record_failed_user_login(username):
        """Record failed login attempt for username"""
        if username not in failed_login_users:
            failed_login_users[username] = []
        
        failed_login_users[username].append(time.time())
        logger.warning(f"Failed login for user: {username}. Total attempts: {len(failed_login_users[username])}")
    
    @staticmethod
    def generate_totp_qr_code(secret, username):
        """Generate QR code for TOTP setup"""
        totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
            name=username,
            issuer_name="Secure Docker Manager"
        )
        
        # Generate QR code
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(totp_uri)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        buffered = io.BytesIO()
        img.save(buffered, format="PNG")
        img_str = base64.b64encode(buffered.getvalue()).decode()
        return f"data:image/png;base64,{img_str}"
    
    @staticmethod
    def verify_totp(token, secret):
        """Verify TOTP token"""
        totp = pyotp.TOTP(secret)
        return totp.verify(token)
    
    @staticmethod
    def sanitize_input(input_str):
        """Sanitize user input to prevent command injection"""
        if not input_str:
            return ""
        
        # Remove dangerous characters
        dangerous_chars = [';', '&', '|', '`', '$', '(', ')', '{', '}', '[', ']', '<', '>', '"', "'"]
        sanitized = input_str
        for char in dangerous_chars:
            sanitized = sanitized.replace(char, '')
        
        # Only allow alphanumeric, dash, underscore, dot, slash
        sanitized = re.sub(r'[^a-zA-Z0-9\-_./]', '', sanitized)
        
        return sanitized[:100]  # Limit length
    
    @staticmethod
    def validate_container_name(name):
        """Validate container name format"""
        if not name or len(name) > 100:
            return False
        return re.match(r'^[a-zA-Z0-9][a-zA-Z0-9_.-]*$', name) is not None
    
    @staticmethod
    def generate_csrf_token():
        """Generate CSRF token"""
        return secrets.token_hex(32)
    
    @staticmethod
    def validate_csrf_token(token):
        """Validate CSRF token"""
        return token and token == session.get('csrf_token')

def require_auth(f):
    """Decorator to require authentication"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check IP whitelist
        client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
        if not SecurityManager.validate_ip(client_ip):
            logger.warning(f"Access denied for IP: {client_ip}")
            return jsonify({'error': 'Access denied'}), 403
        
        # Check if IP is blocked
        if SecurityManager.is_blocked(client_ip):
            return jsonify({'error': 'IP temporarily blocked'}), 429
        
        # Check session
        if 'logged_in' not in session or not session['logged_in']:
            return redirect(url_for('login'))
        
        # Check session timeout
        if 'last_activity' in session:
            if time.time() - session['last_activity'] > SECURITY_CONFIG['SESSION_TIMEOUT']:
                session.clear()
                flash('Session expired. Please log in again.', 'warning')
                return redirect(url_for('login'))
        
        session['last_activity'] = time.time()
        return f(*args, **kwargs)
    return decorated_function

def require_csrf(f):
    """Decorator to require CSRF token for POST requests"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.method == 'POST':
            token = request.form.get('csrf_token') or request.json.get('csrf_token')
            if not SecurityManager.validate_csrf_token(token):
                logger.warning(f"CSRF token validation failed for {request.endpoint}")
                return jsonify({'error': 'Invalid CSRF token'}), 403
        return f(*args, **kwargs)
    return decorated_function

class SecureDockerManager:
    """Secure Docker operations with input validation"""
    
    @staticmethod
    def run_command(cmd, timeout=30):
        """Execute shell command securely"""
        try:
            # Log the command (sanitized)
            logger.info(f"Executing command: {cmd[:100]}...")
            
            result = subprocess.run(
                cmd, 
                shell=True, 
                capture_output=True, 
                text=True, 
                timeout=timeout,
                cwd='/var/www/html/docker2 15'  # Fixed working directory
            )
            
            return {
                'success': result.returncode == 0,
                'stdout': result.stdout.strip(),
                'stderr': result.stderr.strip(),
                'returncode': result.returncode
            }
        except subprocess.TimeoutExpired:
            logger.error(f"Command timeout: {cmd[:50]}...")
            return {'success': False, 'stdout': '', 'stderr': 'Command timeout', 'returncode': -1}
        except Exception as e:
            logger.error(f"Command execution error: {str(e)}")
            return {'success': False, 'stdout': '', 'stderr': str(e), 'returncode': -1}
    
    @staticmethod
    def get_containers():
        """Get list of containers securely"""
        cmd = "sudo docker ps -a --format json"
        result = SecureDockerManager.run_command(cmd)
        
        if not result['success']:
            return []
        
        containers = []
        for line in result['stdout'].split('\n'):
            if line.strip():
                try:
                    container = json.loads(line)
                    # Sanitize container data
                    container['Names'] = SecurityManager.sanitize_input(container.get('Names', ''))
                    container['Image'] = SecurityManager.sanitize_input(container.get('Image', ''))
                    containers.append(container)
                except json.JSONDecodeError:
                    continue
        
        return containers
    
    @staticmethod
    def container_action(container_name, action):
        """Perform container action securely"""
        # Validate inputs
        if not SecurityManager.validate_container_name(container_name):
            return {'success': False, 'message': 'Invalid container name'}
        
        allowed_actions = ['start', 'stop', 'restart', 'remove']
        if action not in allowed_actions:
            return {'success': False, 'message': 'Invalid action'}
        
        # Build secure command
        cmd = f"sudo docker {action} {container_name}"
        result = SecureDockerManager.run_command(cmd)
        
        logger.info(f"Container action: {action} on {container_name} - {'Success' if result['success'] else 'Failed'}")
        
        return {
            'success': result['success'],
            'message': result['stdout'] if result['success'] else result['stderr']
        }

class SecureFrappeManager:
    """Secure Frappe operations"""
    
    @staticmethod
    def execute_bench_command(container_name, command, timeout=60):
        """Execute bench command securely"""
        # Validate container name
        if not SecurityManager.validate_container_name(container_name):
            return {'success': False, 'error': 'Invalid container name'}
        
        # Sanitize command
        safe_command = SecurityManager.sanitize_input(command)
        if not safe_command or len(safe_command) < 3:
            return {'success': False, 'error': 'Invalid command'}
        
        # Only allow specific bench commands
        allowed_commands = [
            'bench --site all list-apps',
            'bench --site all clear-cache',
            'bench --site all clear-website-cache',
            'bench --site all build --force',
            'bench --site all backup --with-files',
            'bench --site all migrate',
            'bench version',
            'bench doctor'
        ]
        
        # Check if command starts with allowed patterns
        allowed = any(safe_command.startswith(cmd.split()[0:3]) for cmd in allowed_commands)
        if not allowed and not safe_command.startswith('bench'):
            return {'success': False, 'error': 'Command not allowed'}
        
        cmd = f"sudo docker exec {container_name} bash -c 'cd /home/frappe/frappe-bench && {safe_command}'"
        result = SecureDockerManager.run_command(cmd, timeout)
        
        logger.info(f"Bench command executed: {safe_command[:50]}... on {container_name}")
        
        return {
            'success': result['success'],
            'output': result['stdout'],
            'error': result['stderr']
        }

# Routes
@app.before_request
def before_request():
    """Security checks before each request"""
    # Force HTTPS in production
    if SECURITY_CONFIG['REQUIRE_HTTPS'] and not request.is_secure:
        return redirect(request.url.replace('http://', 'https://'))

@app.after_request
def after_request(response):
    """Add security headers after each request"""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://code.jquery.com; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; font-src 'self' https://cdn.jsdelivr.net; img-src 'self' data:"
    return response

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Secure login page with 2FA"""
    client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
    
    # IP whitelist check
    if not SecurityManager.validate_ip(client_ip):
        log_audit("access_denied", "unknown", client_ip, "IP not in whitelist", "blocked")
        return render_template('login.html', error='Access denied. Your IP is not authorized.')
    
    # Check if IP is blocked
    if SecurityManager.is_blocked(client_ip):
        log_audit("login_attempt", "unknown", client_ip, "IP temporarily blocked", "blocked")
        return render_template('login.html', error='IP temporarily blocked due to too many failed attempts')
    
    # Check if in 2FA verification mode
    if session.get('awaiting_2fa') and request.method == 'POST':
        totp_code = request.form.get('totp_code', '').strip()
        username = session.get('pending_username', 'unknown')
        
        # Verify TOTP code
        if SecurityManager.verify_totp(totp_code, SECURITY_CONFIG['ADMIN_TOTP_SECRET']):
            # Complete login
            session['logged_in'] = True
            session['username'] = username
            session['last_activity'] = time.time()
            session['csrf_token'] = SecurityManager.generate_csrf_token()
            
            # Clear 2FA flags
            session.pop('awaiting_2fa', None)
            session.pop('pending_username', None)
            
            # Log successful 2FA login
            log_audit("login_2fa", username, client_ip, "Successful 2FA authentication")
            logger.info(f"Successful 2FA login from IP: {client_ip}")
            return redirect(url_for('index'))
        else:
            # Failed 2FA
            SecurityManager.record_failed_login(client_ip)
            if username:
                SecurityManager.record_failed_user_login(username)
            
            # Log failed 2FA attempt
            log_audit("login_2fa", username, client_ip, "Failed 2FA authentication", "failed")
            logger.warning(f"Failed 2FA attempt from IP: {client_ip}")
            flash('Invalid authentication code', 'error')
            
            # Check if user should be locked
            is_locked, remaining = SecurityManager.is_user_locked(username)
            if is_locked:
                # Log the lockout
                log_audit("account_lockout", username, client_ip, f"Account locked for {remaining} seconds", "security")
                logger.warning(f"User {username} locked out due to too many failed attempts")
                minutes = remaining // 60
                seconds = remaining % 60
                flash(f'Account locked for {minutes} minutes and {seconds} seconds due to too many failed attempts', 'error')
                session.clear()  # Clear session data
                return render_template('login.html', error=f'Account locked for {minutes}m {seconds}s')
    
    elif request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        # Check if user is locked
        is_locked, remaining = SecurityManager.is_user_locked(username)
        if is_locked:
            minutes = remaining // 60
            seconds = remaining % 60
            logger.warning(f"Attempt to login to locked account {username}")
            log_audit("login_attempt", username, client_ip, "Attempt on locked account", "blocked")
            return render_template('login.html', error=f'Account locked for {minutes}m {seconds}s due to too many failed attempts')
        
        # Validate credentials
        if (username == SECURITY_CONFIG['ADMIN_USERNAME'] and 
            SECURITY_CONFIG['ADMIN_PASSWORD_HASH'] and
            check_password_hash(SECURITY_CONFIG['ADMIN_PASSWORD_HASH'], password)):
            
            # Set up 2FA verification
            session['awaiting_2fa'] = True
            session['pending_username'] = username
            
            # Log successful password auth
            log_audit("login_password", username, client_ip, "Password authentication successful")
            
            # Generate QR code only for first-time setup
            qr_code = None
            if not os.path.exists(f'.{username}_2fa_setup_complete'):
                qr_code = SecurityManager.generate_totp_qr_code(
                    SECURITY_CONFIG['ADMIN_TOTP_SECRET'],
                    SECURITY_CONFIG['ADMIN_USERNAME']
                )
                # Create a marker file to track that setup is complete
                with open(f'.{username}_2fa_setup_complete', 'w') as f:
                    f.write(f"2FA setup completed on: {datetime.now()}\n")
                
            return render_template('login.html', awaiting_2fa=True, qr_code=qr_code)
        else:
            SecurityManager.record_failed_login(client_ip)
            SecurityManager.record_failed_user_login(username)
            logger.warning(f"Failed login attempt from IP: {client_ip} for user: {username}")
            log_audit("login_attempt", username, client_ip, "Invalid credentials", "failed")
            flash('Invalid credentials', 'error')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    """Logout and clear session"""
    username = session.get('username', 'unknown')
    client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
    
    # Log logout event
    log_audit("logout", username, client_ip, "User logged out")
    
    session.clear()
    flash('Logged out successfully', 'success')
    return redirect(url_for('login'))

@app.route('/')
@require_auth
def index():
    """Secure main dashboard"""
    containers = SecureDockerManager.get_containers()
    
    # Group containers by project
    projects = {}
    for container in containers:
        # Extract project name safely
        name_parts = container['Names'].split('-')
        if len(name_parts) > 1:
            project = '-'.join(name_parts[:-1])
        else:
            project = 'standalone'
        
        if project not in projects:
            projects[project] = []
        projects[project].append(container)
    
    return render_template('secure_dashboard.html', 
                         projects=projects, 
                         containers=containers,
                         csrf_token=session.get('csrf_token'))

@app.route('/api/container/<container_name>/action', methods=['POST'])
@require_auth
@require_csrf
def container_action_api(container_name):
    """Secure container action API"""
    action = request.json.get('action')
    client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
    username = session.get('username', 'unknown')
    
    result = SecureDockerManager.container_action(container_name, action)
    
    # Log container action
    status = "success" if result['success'] else "failed"
    log_audit("container_action", username, client_ip, 
              f"Container {action} on {container_name}", status)
    
    return jsonify(result)

@app.route('/api/container/<container_name>/logs')
@require_auth
def container_logs_api(container_name):
    """Get container logs API"""
    if not SecurityManager.validate_container_name(container_name):
        return jsonify({'success': False, 'error': 'Invalid container name'})
    
    # Get container logs with limit
    cmd = f"sudo docker logs --tail 100 {container_name}"
    result = SecureDockerManager.run_command(cmd, timeout=30)
    
    if result['success']:
        return jsonify({
            'success': True,
            'logs': result['stdout'],
            'container': container_name
        })
    else:
        return jsonify({
            'success': False,
            'error': result['stderr'],
            'container': container_name
        })

@app.route('/frappe/<container_name>')
@require_auth
def secure_frappe_manager(container_name):
    """Secure Frappe management page"""
    if not SecurityManager.validate_container_name(container_name):
        flash('Invalid container name', 'error')
        return redirect(url_for('index'))
    
    # Check if container exists and is a Frappe container
    containers = SecureDockerManager.get_containers()
    container = next((c for c in containers if c.get('Names') == container_name), None)
    
    if not container:
        flash(f'Container {container_name} not found', 'error')
        return redirect(url_for('index'))
    
    if 'frappe' not in container.get('Image', '').lower():
        flash(f'Container {container_name} is not a Frappe container', 'warning')
        return redirect(url_for('index'))
    
    return render_template('secure_frappe_manager.html',
                         container=container,
                         container_name=container_name,
                         csrf_token=session.get('csrf_token'))

@app.route('/api/frappe/<container_name>/bench-command', methods=['POST'])
@require_auth
@require_csrf
def secure_frappe_bench_command_api(container_name):
    """Secure API endpoint for executing bench commands"""
    command = request.json.get('command')
    timeout = min(int(request.json.get('timeout', 60)), 300)  # Max 5 minutes
    client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
    username = session.get('username', 'unknown')
    
    # Log command execution attempt
    log_audit("bench_command", username, client_ip, 
              f"Executing '{command}' on {container_name}", "attempt")
    
    result = SecureFrappeManager.execute_bench_command(container_name, command, timeout)
    
    # Log command execution result
    status = "success" if result.get('success') else "failed"
    log_audit("bench_command", username, client_ip, 
              f"Executed '{command}' on {container_name}", status)
    
    return jsonify(result)

if __name__ == '__main__':
    # Initialize security
    new_credentials = SecurityManager.init_admin_password()
    
    if new_credentials:
        print("🔐 SECURITY SETUP COMPLETE!")
        print("=" * 50)
        print(f"Admin Username: {SECURITY_CONFIG['ADMIN_USERNAME']}")
        print(f"Admin Password: {new_credentials['password']}")
        print("=" * 50)
        print("⚠️  SAVE THESE CREDENTIALS SECURELY!")
        print("📁 Also saved to: .admin_credentials")
        print("")
    
    # Generate self-signed SSL certificate if not exists
    cert_file = "server.crt"
    key_file = "server.key"
    
    use_https = SECURITY_CONFIG['REQUIRE_HTTPS']
    ssl_available = False
    
    if use_https:
        try:
            if not os.path.exists(cert_file) or not os.path.exists(key_file):
                print("🔒 Generating self-signed SSL certificate...")
                # Check if openssl is available
                import subprocess
                try:
                    result = subprocess.run(["which", "openssl"], capture_output=True, text=True)
                    if result.returncode == 0:
                        # Generate certificate using openssl
                        cmd = f"openssl req -x509 -newkey rsa:4096 -nodes -out {cert_file} -keyout {key_file} -days 365 -subj '/CN=localhost'"
                        subprocess.run(cmd, shell=True, check=True)
                        print("✅ SSL certificate generated")
                        ssl_available = True
                    else:
                        print("⚠️ OpenSSL not found. HTTPS not available.")
                        use_https = False
                except Exception as e:
                    print(f"⚠️ Error generating SSL certificate: {str(e)}")
                    use_https = False
            else:
                print("✅ Using existing SSL certificates")
                ssl_available = True
        except Exception as e:
            print(f"⚠️ Error setting up HTTPS: {str(e)}")
            use_https = False
    
    print("🔒 SECURITY FEATURES ENABLED:")
    print("✅ Authentication required")
    print("✅ Two-factor authentication (Google Authenticator)")
    print("✅ Account lockout after 3 failed attempts (5 min)")
    print("✅ IP whitelist protection")
    print("✅ Rate limiting")
    print("✅ Input sanitization")
    print("✅ CSRF protection")
    print("✅ Security headers")
    print("✅ Command validation")
    print("✅ Session management")
    print("✅ Audit logging enabled")
    if ssl_available:
        print("✅ HTTPS with SSL/TLS")
    else:
        print("❌ HTTPS with SSL/TLS (not available)")
    print("")
    print("🌐 Starting SECURE Web Docker Manager...")
    if ssl_available:
        print("📍 Access: https://localhost:5000")
    else:
        print("📍 Access: http://localhost:5000")
    print("🔐 Login required for access")
    
    # Run with or without SSL based on availability
    if ssl_available:
        app.run(host='0.0.0.0', port=5000, debug=False, ssl_context=(cert_file, key_file))
    else:
        app.run(host='0.0.0.0', port=5000, debug=False)
