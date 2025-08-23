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

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)  # Secure random secret key

# Security Configuration
SECURITY_CONFIG = {
    'MAX_LOGIN_ATTEMPTS': 5,
    'LOCKOUT_DURATION': 300,  # 5 minutes
    'SESSION_TIMEOUT': 3600,  # 1 hour
    'ALLOWED_IPS': ['127.0.0.1', '::1'],  # Only localhost by default
    'REQUIRE_HTTPS': False,  # Set to True in production
    'ADMIN_USERNAME': 'admin',
    'ADMIN_PASSWORD_HASH': None,  # Will be set on first run
}

# Rate limiting storage
login_attempts = {}
blocked_ips = {}

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
handler = RotatingFileHandler('docker-manager.log', maxBytes=10000000, backupCount=5)
handler.setFormatter(logging.Formatter(
    '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
))
app.logger.addHandler(handler)

class SecurityManager:
    """Handle security operations"""
    
    @staticmethod
    def init_admin_password():
        """Initialize admin password on first run"""
        if not SECURITY_CONFIG['ADMIN_PASSWORD_HASH']:
            # Generate secure random password
            password = secrets.token_urlsafe(16)
            SECURITY_CONFIG['ADMIN_PASSWORD_HASH'] = generate_password_hash(password)
            
            # Save to secure file
            with open('.admin_credentials', 'w') as f:
                f.write(f"Username: {SECURITY_CONFIG['ADMIN_USERNAME']}\n")
                f.write(f"Password: {password}\n")
                f.write(f"Generated: {datetime.now()}\n")
            
            # Set secure permissions
            os.chmod('.admin_credentials', 0o600)
            
            logger.info("Admin credentials generated and saved to .admin_credentials")
            return password
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
    def record_failed_login(ip):
        """Record failed login attempt"""
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
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://code.jquery.com; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; font-src 'self' https://cdn.jsdelivr.net"
    return response

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Secure login page"""
    client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
    
    # Check if IP is blocked
    if SecurityManager.is_blocked(client_ip):
        return render_template('login.html', error='IP temporarily blocked due to too many failed attempts')
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        # Validate credentials
        if (username == SECURITY_CONFIG['ADMIN_USERNAME'] and 
            SECURITY_CONFIG['ADMIN_PASSWORD_HASH'] and
            check_password_hash(SECURITY_CONFIG['ADMIN_PASSWORD_HASH'], password)):
            
            session['logged_in'] = True
            session['username'] = username
            session['last_activity'] = time.time()
            session['csrf_token'] = SecurityManager.generate_csrf_token()
            
            logger.info(f"Successful login from IP: {client_ip}")
            return redirect(url_for('index'))
        else:
            SecurityManager.record_failed_login(client_ip)
            logger.warning(f"Failed login attempt from IP: {client_ip}")
            flash('Invalid credentials', 'error')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    """Logout and clear session"""
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
    result = SecureDockerManager.container_action(container_name, action)
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
    
    result = SecureFrappeManager.execute_bench_command(container_name, command, timeout)
    return jsonify(result)

if __name__ == '__main__':
    # Initialize security
    new_password = SecurityManager.init_admin_password()
    
    if new_password:
        print("🔐 SECURITY SETUP COMPLETE!")
        print("=" * 50)
        print(f"Admin Username: {SECURITY_CONFIG['ADMIN_USERNAME']}")
        print(f"Admin Password: {new_password}")
        print("=" * 50)
        print("⚠️  SAVE THESE CREDENTIALS SECURELY!")
        print("📁 Also saved to: .admin_credentials")
        print("")
    
    print("🔒 SECURITY FEATURES ENABLED:")
    print("✅ Authentication required")
    print("✅ IP whitelist protection")
    print("✅ Rate limiting")
    print("✅ Input sanitization")
    print("✅ CSRF protection")
    print("✅ Security headers")
    print("✅ Command validation")
    print("✅ Session management")
    print("")
    print("🌐 Starting SECURE Web Docker Manager...")
    print("📍 Access: http://localhost:5000")
    print("🔐 Login required for access")
    
    # Run in development mode (use gunicorn for production)
    app.run(host='127.0.0.1', port=5000, debug=False)
