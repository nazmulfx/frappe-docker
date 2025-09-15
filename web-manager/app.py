#!/usr/bin/env python3
"""
SECURE Web Docker Manager with Complete User Management System
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
import logging
from logging.handlers import RotatingFileHandler
import pyotp
import base64
import qrcode
import io
from datetime import datetime, timedelta
from config import Config
from models import db, User, AuditLog, create_default_admin
import paramiko
from datetime import timedelta
import socket

import threading
import uuid
import os
import tempfile
from datetime import datetime


app = Flask(__name__)
# SSH Connection Storage
ssh_connections = {}


# Configure Flask for URL generation
app.config['SERVER_NAME'] = 'localhost:5000'
app.config['APPLICATION_ROOT'] = '/'
app.config['PREFERRED_URL_SCHEME'] = 'http'
app.config.from_object(Config)

# Initialize database
db.init_app(app)

# Context processor to make CSRF token available in all templates
@app.context_processor
@app.context_processor
def inject_csrf_token():
    try:
        return dict(csrf_token=session.get('csrf_token'))
    except RuntimeError:
        # No request context, return empty token
        return dict(csrf_token=None)

# Rate limiting storage
login_attempts = {}

# Global variable to store current working directories for each container
container_working_dirs = {}
blocked_ips = {}

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
handler = RotatingFileHandler('docker-manager.log', maxBytes=10000000, backupCount=5)
handler.setFormatter(logging.Formatter(
    '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
))
app.logger.addHandler(handler)

def log_audit(event_type, username, ip, message, status="success", user_id=None):
    """Log security event to audit log"""
    if Config.ENABLE_AUDIT_LOG:
        try:
            audit_entry = AuditLog(
                user_id=user_id,
                username=username,
                ip_address=ip,
                event_type=event_type,
                message=message,
                status=status
            )
            db.session.add(audit_entry)
            db.session.commit()
        except Exception as e:
            logger.error(f"Failed to log audit event: {str(e)}")

class SecurityManager:
    """Handle security operations"""
    
    @staticmethod
    def validate_ip(ip):
        """Check if IP is allowed"""
        if not Config.ALLOWED_IPS:
            return True
        return ip in Config.ALLOWED_IPS
    
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
        """Record failed login attempt for IP"""
        if ip not in login_attempts:
            login_attempts[ip] = []
        
        login_attempts[ip].append(time.time())
        
        # Clean old attempts (older than 1 hour)
        cutoff = time.time() - 3600
        login_attempts[ip] = [t for t in login_attempts[ip] if t > cutoff]
        
        # Block if too many attempts
        if len(login_attempts[ip]) >= Config.MAX_LOGIN_ATTEMPTS:
            blocked_ips[ip] = time.time() + Config.LOCKOUT_DURATION
            logger.warning(f"IP {ip} blocked due to too many failed login attempts")
    
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
            border=4)
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
            if time.time() - session['last_activity'] > Config.SESSION_TIMEOUT:
                session.clear()
                flash('Session expired. Please log in again.', 'warning')
                return redirect(url_for('login'))
        
        # Ensure CSRF token is available
        if 'csrf_token' not in session:
            session['csrf_token'] = SecurityManager.generate_csrf_token()
        
        session['last_activity'] = time.time()
        return f(*args, **kwargs)
    return decorated_function

def require_admin(f):
    """Decorator to require admin privileges"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user_id = session.get('user_id')
        if not user_id:
            return redirect(url_for('login'))
        
        user = User.query.get(user_id)
        if not user or not user.is_admin:
            flash('Admin privileges required', 'error')
            return redirect(url_for('index'))
        
        return f(*args, **kwargs)
    return decorated_function

def require_csrf(f):
    """Decorator to require CSRF token for POST requests"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.method == 'POST':
            # Check for CSRF token in headers (X-CSRFToken) or form data
            token = request.headers.get('X-CSRFToken') or request.form.get('csrf_token') or request.json.get('csrf_token')
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
                cwd='/var/www/html/frappe-docker'
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
    def format_project_name(name):
        """Format project name for display"""
        # Replace underscores and hyphens with spaces
        formatted = name.replace('_', ' ').replace('-', ' ')
        # Capitalize each word
        formatted = ' '.join(word.capitalize() for word in formatted.split())
        return formatted
    
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

    
    @staticmethod
    def get_container_logs(container_name, tail=100):
        """Get container logs securely"""
        # Validate input
        if not SecurityManager.validate_container_name(container_name):
            return 'Invalid container name'
        
        # Build secure command
        cmd = f"sudo docker logs --tail {tail} {container_name}"
        result = SecureDockerManager.run_command(cmd)
        
        if result['success']:
            return result['stdout']
        else:
            return f"Error getting logs: {result['stderr']}"


class TerminalFormatter:
    """Helper class for formatting terminal output"""
    
    @staticmethod
    def format_terminal_output(output, command=None, current_dir="/home/frappe", container=None, success=True):
        """Format output to look like Ubuntu terminal"""
        if not output:
            return ""
        
        # Create Ubuntu-style terminal prompt
        user = "frappe"
        host = container if container else "container"
        dir_display = current_dir.replace("/home/frappe", "~")
        
        # Format the Ubuntu-style prompt
        if command:
            prompt = f'<span class="terminal-prompt">{user}@</span><span class="terminal-prompt">{host}</span><span class="terminal-white">:</span><span class="terminal-path">{dir_display}</span><span class="terminal-white">$</span> <span class="terminal-command">{command}</span>\n'
        else:
            prompt = f'<span class="terminal-prompt">{user}@</span><span class="terminal-prompt">{host}</span><span class="terminal-white">:</span><span class="terminal-path">{dir_display}</span><span class="terminal-white">$</span> '
        
        # Format output with Ubuntu terminal colors and syntax highlighting
        formatted_lines = []
        for line in output.split('\n'):
            if line.strip():
                # Ubuntu terminal color coding
                line_lower = line.lower()
                if any(keyword in line.upper() for keyword in ['ERROR', 'FAILED', 'EXCEPTION', 'CRITICAL']):
                    formatted_lines.append(f'<span class="terminal-red terminal-error-line">{line}</span>')
                elif any(keyword in line.upper() for keyword in ['SUCCESS', 'COMPLETE', 'DONE', 'INSTALLED', 'OK']):
                    formatted_lines.append(f'<span class="terminal-green terminal-success-line">{line}</span>')
                elif any(keyword in line.upper() for keyword in ['WARNING', 'WARN', 'CAUTION']):
                    formatted_lines.append(f'<span class="terminal-yellow terminal-warning-line">{line}</span>')
                elif any(keyword in line for keyword in ['Installing', 'Downloading', 'Getting', 'Building', 'Compiling']):
                    formatted_lines.append(f'<span class="terminal-cyan terminal-info-line">{line}</span>')
                elif line.startswith('drwx') or line.startswith('d'):
                    # Directory listing - Ubuntu style
                    parts = line.split()
                    if len(parts) > 8:
                        formatted_lines.append(f'<span class="terminal-dir">{line}</span>')
                    else:
                        formatted_lines.append(f'<span class="terminal-white">{line}</span>')
                elif line.startswith('-rwx') or line.startswith('-rw-') or line.startswith('-r--'):
                    # File listing - Ubuntu style
                    if 'x' in line[:10]:  # Executable
                        formatted_lines.append(f'<span class="terminal-executable">{line}</span>')
                    else:
                        formatted_lines.append(f'<span class="terminal-file">{line}</span>')
                elif line.startswith('l'):
                    # Symbolic link
                    formatted_lines.append(f'<span class="terminal-link">{line}</span>')
                elif '->' in line:
                    # Symbolic link target
                    formatted_lines.append(f'<span class="terminal-link">{line}</span>')
                else:
                    formatted_lines.append(f'<span class="terminal-white">{line}</span>')
            else:
                formatted_lines.append("")
        
        formatted_output = '\n'.join(formatted_lines)
        
        # Add Ubuntu-style command separator
        separator = '\n<span class="terminal-separator">' + '─' * 50 + '</span>\n'
        
        if command:
            return f"{prompt}{formatted_output}{separator}"
        else:
            return formatted_output
    
    @staticmethod
    def format_error_output(error, command=None, current_dir="/home/frappe", container=None):
        """Format error output with Ubuntu terminal styling"""
        if not error:
            return ""
        
        user = "frappe"
        host = container if container else "container"
        dir_display = current_dir.replace("/home/frappe", "~")
        
        # Format error with Ubuntu terminal red color and styling
        formatted_error = f'<span class="terminal-red terminal-error-line terminal-bold">Error: {error}</span>'
        
        # Add Ubuntu-style command separator
        separator = '\n<span class="terminal-separator">' + '─' * 50 + '</span>\n'
        
        if command:
            prompt = f'<span class="terminal-prompt">{user}@</span><span class="terminal-prompt">{host}</span><span class="terminal-white">:</span><span class="terminal-path">{dir_display}</span><span class="terminal-white">$</span> <span class="terminal-command">{command}</span>\n'
            return f"{prompt}{formatted_error}{separator}"
        
        return formatted_error

# Routes
@app.before_request
def before_request():
    """Security checks before each request"""
    # Force HTTPS in production
    if Config.REQUIRE_HTTPS and not request.is_secure:
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
    """Secure login page with optional 2FA"""
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
        user_id = session.get('pending_user_id')
        
        if user_id:
            user = User.query.get(user_id)
            if user and user.totp_secret and user.totp_enabled:
                # Verify TOTP code
                if SecurityManager.verify_totp(totp_code, user.totp_secret):
                    # Complete login
                    session['logged_in'] = True
                    session['user_id'] = user.id
                    session['username'] = user.username
                    session['is_admin'] = user.is_admin
                    session['last_activity'] = time.time()
                    session['csrf_token'] = SecurityManager.generate_csrf_token()
                    
                    # Clear 2FA flags
                    session.pop('awaiting_2fa', None)
                    session.pop('pending_user_id', None)
                    
                    # Record successful login
                    user.record_successful_login()
                    
                    # Log successful 2FA login
                    log_audit("login_2fa", user.username, client_ip, "Successful 2FA authentication", "success", user.id)
                    logger.info(f"Successful 2FA login from IP: {client_ip}")
                    return redirect(url_for('index'))
                else:
                    # Failed 2FA
                    SecurityManager.record_failed_login(client_ip)
                    user.record_failed_login()
                    
                    # Log failed 2FA attempt
                    log_audit("login_2fa", user.username, client_ip, "Failed 2FA authentication", "failed", user.id)
                    logger.warning(f"Failed 2FA attempt from IP: {client_ip}")
                    flash('Invalid authentication code', 'error')
                    
                    # Check if user should be locked
                    if user.is_locked():
                        log_audit("account_lockout", user.username, client_ip, "Account locked due to too many failed attempts", "security", user.id)
                        logger.warning(f"User {user.username} locked out due to too many failed attempts")
                        flash('Account locked due to too many failed attempts', 'error')
                        session.clear()
                        return render_template('login.html', error='Account locked due to too many failed attempts')
    
    elif request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        # Find user
        user = User.query.filter_by(username=username, is_active=True).first()
        
        if user and user.check_password(password):
            # Check if user is locked
            if user.is_locked():
                logger.warning(f"Attempt to login to locked account {username}")
                log_audit("login_attempt", username, client_ip, "Attempt on locked account", "blocked", user.id)
                flash('Account locked due to too many failed attempts', 'error')
                return render_template('login.html', error='Account locked due to too many failed attempts')
            
            # Check if user has 2FA enabled
            if user.totp_enabled and user.totp_secret:
                # Set up 2FA verification
                session['awaiting_2fa'] = True
                session['pending_user_id'] = user.id
                
                # Log successful password auth
                log_audit("login_password", username, client_ip, "Password authentication successful", "success", user.id)
                
                return render_template('login.html', awaiting_2fa=True)
            else:
                # No 2FA, complete login
                session['logged_in'] = True
                session['user_id'] = user.id
                session['username'] = user.username
                session['is_admin'] = user.is_admin
                session['last_activity'] = time.time()
                session['csrf_token'] = SecurityManager.generate_csrf_token()
                
                # Record successful login
                user.record_successful_login()
                
                # Log successful login
                log_audit("login", username, client_ip, "Successful login", "success", user.id)
                logger.info(f"Successful login from IP: {client_ip}")
                return redirect(url_for('index'))
        else:
            SecurityManager.record_failed_login(client_ip)
            if user:
                user.record_failed_login()
                log_audit("login_attempt", username, client_ip, "Invalid credentials", "failed", user.id)
            else:
                log_audit("login_attempt", username, client_ip, "User not found", "failed")
            
            logger.warning(f"Failed login attempt from IP: {client_ip} for user: {username}")
            flash('Invalid credentials', 'error')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    """Logout and clear session"""
    username = session.get('username', 'unknown')
    user_id = session.get('user_id')
    client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
    
    # Log logout event
    log_audit("logout", username, client_ip, "User logged out", "success", user_id)
    
    session.clear()
    flash('Logged out successfully', 'success')
    return redirect(url_for('login'))


@app.route('/')
@require_auth
def index():
    """Secure main dashboard with container grouping"""
    containers = SecureDockerManager.get_containers()
    
    # Group containers by project name
    container_groups = {}
    running_count = 0
    stopped_count = 0
    
    for container in containers:
        container_name = container.get('Names', '').lstrip('/')
        
        # Determine service type and project name
        service_type = 'unknown'
        project_name = 'standalone'
        
        # Extract project name (everything before the last dash)
        if '-' in container_name:
            parts = container_name.split('-')
            if len(parts) >= 2:
                # Group containers like test20_local-app, test20_local-db into "Test20 Local"
                if '_' in parts[0]:
                    # Handle test20_local-app style naming
                    project_parts = parts[0].split('_')
                    project_name = parts[0]  # Keep original for grouping
                else:
                    # Regular dash-separated names
                    project_name = '-'.join(parts[:-1])
                
                service_type = parts[-1]  # last part is service type
        
        # Determine service type based on image or name
        image_name = container.get('Image', '').lower()
        if 'frappe' in image_name or 'erpnext' in image_name:
            if 'app' in service_type:
                service_type = 'App Server'
            elif 'worker' in service_type:
                service_type = 'Worker'
            elif 'scheduler' in service_type:
                service_type = 'Scheduler'
        elif 'mariadb' in image_name or 'mysql' in image_name:
            service_type = 'Database'
        elif 'redis' in image_name:
            service_type = 'Cache/Queue'
        elif 'traefik' in image_name:
            service_type = 'Reverse Proxy'
        elif 'create-site' in service_type:
            service_type = 'Site Creator'
        
        # Count running/stopped containers
        status = container.get('Status', '')
        if 'Up' in status:
            running_count += 1
        else:
            stopped_count += 1
        
        # Create container object for template
        container_obj = {
            'name': container_name,
            'image': container.get('Image', ''),
            'status': status,
            'ports': container.get('Ports', ''),
            'service_type': service_type,
            'created': container.get('Created', ''),
            'command': container.get('Command', '')
        }
        
        # Group by project
        if project_name not in container_groups:
            container_groups[project_name] = []
        container_groups[project_name].append(container_obj)
    
    # Sort containers within each group by service type priority
    service_priority = {
        'App Server': 1,
        'Database': 2,
        'Cache/Queue': 3,
        'Reverse Proxy': 4,
        'Worker': 5,
        'Scheduler': 6,
        'Site Creator': 7,
        'unknown': 8
    }
    
    # Create a formatted version of container_groups with nicely formatted keys
    formatted_container_groups = {}
    for project_name, containers in container_groups.items():
        formatted_name = SecureDockerManager.format_project_name(project_name)
        formatted_container_groups[formatted_name] = containers
        containers.sort(key=lambda x: service_priority.get(x['service_type'], 8))
    
    total_containers = len(containers)
    projects = list(formatted_container_groups.keys())
    
    return render_template('dashboard.html',
                         container_groups=formatted_container_groups,
                         containers=containers,
                         running_count=running_count,
                         stopped_count=stopped_count,
                         total_containers=total_containers,
                         projects=projects)

# Profile Management Routes
@app.route('/profile')
@require_auth
def user_profile():
    """User profile and 2FA settings"""
    user_id = session.get('user_id')
    user = User.query.get(user_id)
    
    if not user:
        flash('User not found', 'error')
        return redirect(url_for('index'))
    
    return render_template('user_profile.html', user=user)

@app.route('/profile/edit', methods=['GET', 'POST'])
@require_auth
@require_csrf
def edit_profile():
    """Edit user profile"""
    user_id = session.get('user_id')
    user = User.query.get(user_id)
    
    if not user:
        flash('User not found', 'error')
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        # Update profile information
        new_username = request.form.get('username', '').strip()
        new_email = request.form.get('email', '').strip()
        current_password = request.form.get('current_password', '')
        new_password = request.form.get('new_password', '')
        
        # Validate username
        if new_username and new_username != user.username:
            existing_user = User.query.filter_by(username=new_username).first()
            if existing_user:
                flash('Username already exists', 'error')
                return redirect(url_for('edit_profile'))
            user.username = new_username
        
        # Validate email
        if new_email and new_email != user.email:
            existing_email = User.query.filter_by(email=new_email).first()
            if existing_email:
                flash('Email already exists', 'error')
                return redirect(url_for('edit_profile'))
            user.email = new_email
        
        # Change password if provided
        if new_password:
            if not current_password or not user.check_password(current_password):
                flash('Current password is incorrect', 'error')
                return redirect(url_for('edit_profile'))
            
            if len(new_password) < 8:
                flash('New password must be at least 8 characters long', 'error')
                return redirect(url_for('edit_profile'))
            
            user.set_password(new_password)
        
        # Save changes
        db.session.commit()
        
        # Log profile update
        client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
        log_audit("profile_updated", user.username, client_ip, "Profile updated", "success", user.id)
        
        flash('Profile updated successfully', 'success')
        return redirect(url_for('user_profile'))
    
    return render_template('edit_profile.html', user=user)

@app.route('/api/users/<int:user_id>/toggle-2fa', methods=['POST'])
@require_auth
@require_csrf
def toggle_2fa(user_id):
    """Enable or disable 2FA for user"""
    user = User.query.get_or_404(user_id)
    
    # Check if user is trying to modify their own account or is admin
    if user.id != session.get('user_id') and not session.get('is_admin'):
        return jsonify({'success': False, 'message': 'Permission denied'})
    
    data = request.json
    enable_2fa = data.get('enable', False)
    
    if enable_2fa:
        if not user.totp_secret:
            user.totp_secret = pyotp.random_base32()
        user.totp_enabled = True
        db.session.commit()
        
        # Generate QR code for setup
        qr_code = SecurityManager.generate_totp_qr_code(user.totp_secret, user.username)
        
        # Log 2FA enable
        client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
        username = session.get('username', 'unknown')
        log_audit("2fa_enabled", username, client_ip, f"2FA enabled for user: {user.username}", "success", session.get('user_id'))
        
        return jsonify({
            'success': True, 
            'message': '2FA enabled successfully',
            'qr_code': qr_code,
            'totp_secret': user.totp_secret
        })
    else:
        user.disable_2fa()
        
        # Log 2FA disable
        client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
        username = session.get('username', 'unknown')
        log_audit("2fa_disabled", username, client_ip, f"2FA disabled for user: {user.username}", "success", session.get('user_id'))
        
        return jsonify({'success': True, 'message': '2FA disabled successfully'})

# User Management Routes (Admin Only)
@app.route('/users')
@require_auth
@require_admin
def user_management():
    """User management panel"""
    users = User.query.all()
    return render_template('user_management.html', users=users)

@app.route('/api/users', methods=['POST'])
@require_auth
@require_admin
@require_csrf
def create_user():
    """Create new user"""
    data = request.json
    username = data.get('username', '').strip()
    email = data.get('email', '').strip()
    password = data.get('password', '')
    is_admin = data.get('is_admin', False)
    
    # Validate input
    if not username or not email or not password:
        return jsonify({'success': False, 'message': 'All fields are required'})
    
    if len(password) < 8:
        return jsonify({'success': False, 'message': 'Password must be at least 8 characters long'})
    
    # Check if user already exists
    if User.query.filter_by(username=username).first():
        return jsonify({'success': False, 'message': 'Username already exists'})
    
    if User.query.filter_by(email=email).first():
        return jsonify({'success': False, 'message': 'Email already exists'})
    
    # Create user
    user = User(
        username=username,
        email=email,
        is_admin=is_admin,
        is_active=True,
        totp_enabled=False  # 2FA disabled by default
    )
    user.set_password(password)
    
    db.session.add(user)
    db.session.commit()
    
    # Log user creation
    client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
    admin_username = session.get('username', 'unknown')
    log_audit("user_created", admin_username, client_ip, f"Created user: {username}", "success", session.get('user_id'))
    
    return jsonify({'success': True, 'message': 'User created successfully'})

@app.route('/api/users/<int:user_id>', methods=['PUT'])
@require_auth
@require_admin
@require_csrf
def update_user(user_id):
    """Update user"""
    user = User.query.get_or_404(user_id)
    data = request.json
    
    # Prevent admin from removing their own admin privileges
    if user.id == session.get('user_id') and not data.get('is_admin', True):
        return jsonify({'success': False, 'message': 'Cannot remove your own admin privileges'})
    
    # Update fields
    if 'username' in data:
        new_username = data['username'].strip()
        if new_username != user.username:
            existing_user = User.query.filter_by(username=new_username).first()
            if existing_user:
                return jsonify({'success': False, 'message': 'Username already exists'})
            user.username = new_username
    
    if 'email' in data:
        new_email = data['email'].strip()
        if new_email != user.email:
            existing_email = User.query.filter_by(email=new_email).first()
            if existing_email:
                return jsonify({'success': False, 'message': 'Email already exists'})
            user.email = new_email
    
    if 'password' in data and data['password']:
        if len(data['password']) < 8:
            return jsonify({'success': False, 'message': 'Password must be at least 8 characters long'})
        user.set_password(data['password'])
    
    if 'is_admin' in data:
        user.is_admin = data['is_admin']
    
    if 'is_active' in data:
        user.is_active = data['is_active']
    
    db.session.commit()
    
    # Log user update
    client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
    admin_username = session.get('username', 'unknown')
    log_audit("user_updated", admin_username, client_ip, f"Updated user: {user.username}", "success", session.get('user_id'))
    
    return jsonify({'success': True, 'message': 'User updated successfully'})

@app.route('/api/users/<int:user_id>', methods=['DELETE'])
@require_auth
@require_admin
@require_csrf
def delete_user(user_id):
    """Delete user"""
    user = User.query.get_or_404(user_id)
    
    # Prevent deleting yourself
    if user.id == session.get('user_id'):
        return jsonify({'success': False, 'message': 'Cannot delete your own account'})
    
    # Prevent deleting the last admin
    if user.is_admin and User.query.filter_by(is_admin=True).count() <= 1:
        return jsonify({'success': False, 'message': 'Cannot delete the last admin user'})
    
    username = user.username
    db.session.delete(user)
    db.session.commit()
    
    # Log user deletion
    client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
    admin_username = session.get('username', 'unknown')
    log_audit("user_deleted", admin_username, client_ip, f"Deleted user: {username}", "success", session.get('user_id'))
    
    return jsonify({'success': True, 'message': 'User deleted successfully'})

@app.route('/api/users/<int:user_id>/unlock', methods=['POST'])
@require_auth
@require_admin
@require_csrf
def unlock_user(user_id):
    """Unlock user account"""
    user = User.query.get_or_404(user_id)
    
    if not user.is_locked():
        return jsonify({'success': False, 'message': 'User is not locked'})
    
    user.unlock_account()
    
    # Log user unlock
    client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
    admin_username = session.get('username', 'unknown')
    log_audit("user_unlocked", admin_username, client_ip, f"Unlocked user: {user.username}", "success", session.get('user_id'))
    
    return jsonify({'success': True, 'message': 'User unlocked successfully'})

# Audit Log Routes
@app.route('/audit-logs')
@require_auth
@require_admin
def audit_logs():
    """View audit logs"""
    page = request.args.get('page', 1, type=int)
    per_page = 50
    
    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    return render_template('audit_logs.html', logs=logs)

# Container Management Routes

# Frappe App Installation Routes
@app.route('/app-installation')
@require_auth
def app_installation():
    """Frappe App Installation UI"""
    containers = SecureDockerManager.get_containers()
    
    # Group containers by project name
    container_groups = {}
    
    for container in containers:
        container_name = container.get('Names', '').lstrip('/')
        
        # Determine service type and project name
        service_type = 'unknown'
        project_name = 'standalone'
        
        # Extract project name (everything before the last dash)
        if '-' in container_name:
            parts = container_name.split('-')
            if len(parts) >= 2:
                # Group containers like test20_local-app, test20_local-db into "Test20 Local"
                if '_' in parts[0]:
                    # Handle test20_local-app style naming
                    project_parts = parts[0].split('_')
                    project_name = parts[0]  # Keep original for grouping
                else:
                    # Regular dash-separated names
                    project_name = '-'.join(parts[:-1])
                
                service_type = parts[-1]  # last part is service type
        
        # Determine service type based on image or name
        image_name = container.get('Image', '').lower()
        if 'frappe' in image_name or 'erpnext' in image_name:
            if 'app' in service_type:
                service_type = 'App Server'
            elif 'worker' in service_type:
                service_type = 'Worker'
            elif 'scheduler' in service_type:
                service_type = 'Scheduler'
        elif 'mariadb' in image_name or 'mysql' in image_name:
            service_type = 'Database'
        elif 'redis' in image_name:
            service_type = 'Cache/Queue'
        elif 'traefik' in image_name:
            service_type = 'Reverse Proxy'
        elif 'create-site' in service_type:
            service_type = 'Site Creator'
        
        # Create container object for template
        container_obj = {
            'name': container_name,
            'image': container.get('Image', ''),
            'status': container.get('Status', ''),
            'ports': container.get('Ports', ''),
            'service_type': service_type,
            'created': container.get('Created', ''),
            'command': container.get('Command', '')
        }
        
        # Group by project
        if project_name not in container_groups:
            container_groups[project_name] = []
        container_groups[project_name].append(container_obj)
    
    # Create a formatted version of container_groups with nicely formatted keys
    formatted_container_groups = {}
    for project_name, containers in container_groups.items():
        formatted_name = SecureDockerManager.format_project_name(project_name)
        formatted_container_groups[formatted_name] = containers
    
    return render_template('app_installation.html', container_groups=formatted_container_groups)

@app.route('/api/frappe/get-app', methods=['POST'])
@require_auth
def frappe_get_app():
    """API endpoint for 'bench get-app' command"""
    try:
        data = request.json
        container = data.get('container')
        repo_url = data.get('repo_url')
        branch = data.get('branch')
        
        if not container or not repo_url:
            return jsonify({'success': False, 'error': 'Container and repository URL are required'}), 400
        
        # Validate container name
        if not SecurityManager.validate_container_name(container):
            return jsonify({'success': False, 'error': 'Invalid container name'}), 400
        
        # Get current working directory for this container
        current_dir = container_working_dirs.get(container, "/home/frappe")
        
        # Build command
        cmd = f"sudo docker exec -u frappe {container} bench get-app {repo_url}"
        if branch:
            cmd += f" --branch {branch}"
        
        # Execute command
        result = SecureDockerManager.run_command(cmd, timeout=300)  # Longer timeout for app installation
        
        # Log the action
        client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
        username = session.get('username', 'unknown')
        user_id = session.get('user_id')
        status = "success" if result['success'] else "failed"
        
        log_audit("frappe_get_app", username, client_ip, 
                  f"Get app {repo_url} on container {container}", status, user_id)
        
        # Format output for terminal display
        if result['success']:
            formatted_output = TerminalFormatter.format_terminal_output(
                result['stdout'], 
                command, 
                current_dir, 
                container, 
                True
            )
        else:
            formatted_output = TerminalFormatter.format_error_output(
                result['stderr'], 
                command, 
                current_dir, 
                container
            )
        
        return jsonify({
            'success': result['success'],
            'output': formatted_output,
            'raw_output': result['stdout'],  # Keep raw output for processing
            'current_dir': current_dir,
            'error': result['stderr'] if not result['success'] else None
        })
        
    except Exception as e:
        logger.error(f"Error in frappe_get_app: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/frappe/install-app', methods=['POST'])
@require_auth
def frappe_install_app():
    """API endpoint for 'bench install-app' command"""
    try:
        data = request.json
        container = data.get('container')
        app_name = data.get('app_name')
        site_name = data.get('site_name')
        repo_url = data.get('repo_url')
        
        if not container or not app_name or not site_name:
            return jsonify({'success': False, 'error': 'Container, app name, and site name are required'}), 400
        
        # Validate container name and other inputs
        if not SecurityManager.validate_container_name(container):
            return jsonify({'success': False, 'error': 'Invalid container name'}), 400
        
        # Get current working directory for this container
        current_dir = container_working_dirs.get(container, "/home/frappe")
        
        # Build command
        cmd = f"sudo docker exec -u frappe {container} bench --site {site_name} install-app {app_name}"
        
        # Execute command
        result = SecureDockerManager.run_command(cmd, timeout=300)  # Longer timeout for app installation
        
        # Log the action
        client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
        username = session.get('username', 'unknown')
        user_id = session.get('user_id')
        status = "success" if result['success'] else "failed"
        
        log_audit("frappe_install_app", username, client_ip, 
                  f"Install app {app_name} on site {site_name} in container {container}", status, user_id)
        
        # Format output for terminal display
        if result['success']:
            formatted_output = TerminalFormatter.format_terminal_output(
                result['stdout'], 
                command, 
                current_dir, 
                container, 
                True
            )
        else:
            formatted_output = TerminalFormatter.format_error_output(
                result['stderr'], 
                command, 
                current_dir, 
                container
            )
        
        return jsonify({
            'success': result['success'],
            'output': formatted_output,
            'raw_output': result['stdout'],  # Keep raw output for processing
            'current_dir': current_dir,
            'error': result['stderr'] if not result['success'] else None
        })
        
    except Exception as e:
        logger.error(f"Error in frappe_install_app: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/frappe/execute-command', methods=['POST'])
@require_auth
def execute_command_api():
    """UNIVERSAL TERMINAL - Execute ANY command in ANY container"""
    try:
        data = request.json
        container = data.get('container')
        command = data.get('command')
        current_dir = data.get('current_dir', '/home/frappe/frappe-bench')
        
        if not container:
            return jsonify({'error': 'Container name is required'})
        
        if not command:
            return jsonify({'error': 'Command is required'})
        
        # UNIVERSAL TERMINAL - NO RESTRICTIONS!
        # Accept any container name and any command
        # Let Docker handle the validation
        
        # Handle cd command specially
        if command.startswith('cd ') or command == 'cd':
            try:
                # Extract the target directory
                if command == 'cd':
                    target_dir = '/app'  # Default to /app if just 'cd'
                else:
                    target_dir = command[3:].strip()
                
                # Handle relative paths
                if not target_dir.startswith('/'):
                    if target_dir == '..':
                        # Go up one directory
                        current_dir = '/'.join(current_dir.split('/')[:-1]) or '/'
                    elif target_dir == '.':
                        # Stay in current directory
                        pass
                    else:
                        # Append to current directory
                        current_dir = f"{current_dir.rstrip('/')}/{target_dir}"
                else:
                    # Absolute path
                    current_dir = target_dir
                
                # Verify the directory exists
                check_cmd = ["sudo", "docker", "exec", "-u", "root", container, "bash", "-c", f"[ -d '{current_dir}' ] && echo 'exists' || echo 'not_exists'"]
                process = subprocess.Popen(check_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                stdout, stderr = process.communicate()
                
                if 'exists' in stdout.decode():
                    return jsonify({
                        'output': '',
                        'current_dir': current_dir
                    })
                else:
                    return jsonify({
                        'error': f"cd: {target_dir}: No such file or directory",
                        'current_dir': current_dir
                    })
            except Exception as e:
                logger.error(f"Error handling cd command: {str(e)}")
                return jsonify({'error': str(e)})
        
        # For tail -f commands, use a special approach to stream output
        if command.startswith('tail -f ') or command.startswith('tail -F '):
            # Extract the file pattern
            file_pattern = command.split(' ', 2)[2]
            
            # First check if the file exists
            check_cmd = ["sudo", "docker", "exec", "-u", "root", container, "bash", "-c", f"ls {file_pattern} 2>/dev/null || echo 'no_files'"]
            process = subprocess.Popen(check_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = process.communicate()
            
            if 'no_files' in stdout.decode() and not stdout.decode().strip().replace('no_files', ''):
                return jsonify({'error': f"tail: cannot open '{file_pattern}' for reading: No such file or directory"})
            
            # Get initial content (last 10 lines)
            cmd = ["sudo", "docker", "exec", "-u", "root", container, "bash", "-c", f"cd {current_dir} && tail -n 10 {file_pattern}"]
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = process.communicate()
            
            output = stdout.decode()
            error = stderr.decode()
            
            if process.returncode != 0:
                return jsonify({'error': error or f"Error executing tail on {file_pattern}"})
        
        return jsonify({
                'output': output,
                'is_streaming': True,
                'stream_command': command,
                'current_dir': current_dir
            })
        
        # UNIVERSAL TERMINAL - Execute command with REAL-TIME streaming
        # Use -w flag for working directory and -it for interactive TTY
        cmd = ["sudo", "docker", "exec", "-w", current_dir, container, "bash", "-c", command]
        
        # For bench commands, use streaming approach
        if any(keyword in command.lower() for keyword in ['bench get-app', 'bench install-app', 'bench new-site']):
            try:
                process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1, universal_newlines=True)
                
                # Read output line by line for streaming
                output_lines = []
                while True:
                    line = process.stdout.readline()
                    if not line:
                        break
                    output_lines.append(line.rstrip())
                    # For long commands, return partial output every few lines
                    if len(output_lines) % 5 == 0:
                        return jsonify({
                            'output': '\n'.join(output_lines),
                            'is_streaming': True,
                            'stream_command': command,
            'current_dir': current_dir,
                            'partial': True
                        })
                
                # Get final output
                output = '\n'.join(output_lines)
                error = ""
                
                # Check if process completed successfully
                process.wait()
                if process.returncode != 0:
                    error = f"Command failed with exit code {process.returncode}"
                    if 'bench get-app' in command and 'Aborted' in output:
                        error = error + "\n💡 Tip: Use 'bench get-app app_name --overwrite' to overwrite existing apps"
                
                return jsonify({
                    'output': output,
                    'error': error,
                    'current_dir': current_dir
                })
                
            except Exception as e:
                return jsonify({
                    'error': f'Error executing command: {str(e)}',
                    'current_dir': current_dir
                })
        else:
            # For regular commands, use the original approach
            timeout_seconds = 10
            try:
                process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                stdout, stderr = process.communicate(timeout=timeout_seconds)
                
                output = stdout
                error = stderr
                
                if process.returncode != 0:
                    return jsonify({
                        'error': error or 'Command execution failed',
                        'current_dir': current_dir
                    })
            except subprocess.TimeoutExpired:
                process.kill()
                return jsonify({
                    'error': f'Command timed out after {timeout_seconds} seconds.',
                    'current_dir': current_dir
                })
        
        # Log the command execution
        username = session.get('username', 'unknown')
        log_entry = AuditLog(
            user_id=session.get('user_id'),
            username=username,
            ip_address=request.remote_addr,
            event_type='command_execution',
            message=f"Executed command '{command}' in container {container}",
            status='success'
        )
        db.session.add(log_entry)
        db.session.commit()
        
        return jsonify({
            'output': output,
            'current_dir': current_dir
        })
    except Exception as e:
        logger.error(f"Error executing command: {str(e)}")
        return jsonify({'error': str(e)})


# Add these new API endpoints for terminal functionality

@app.route('/api/frappe/validate-container', methods=['GET'])
@require_auth
def validate_container():
    """Validate if a container exists"""
    container_name = request.args.get('container')
    
    if not container_name:
        return jsonify({'exists': False, 'error': 'Container name is required'})
    
    try:
        # Run docker ps to check if the container exists
        cmd = ["sudo", "docker", "ps", "-a", "--format", "{{.Names}}"]
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()
        
        if process.returncode != 0:
            app.logger.error(f"Error checking container: {stderr.decode()}")
            return jsonify({'exists': False, 'error': 'Error checking container'})
        
        containers = stdout.decode().strip().split('\n')
        exists = container_name in containers
        
        return jsonify({'exists': exists})
    except Exception as e:
        app.logger.error(f"Error validating container: {str(e)}")
        return jsonify({'exists': False, 'error': str(e)})

@app.route('/api/frappe/get-current-dir', methods=['GET'])
@require_auth
def get_current_directory():
    """Get current working directory in a container"""
    container_name = request.args.get('container')
    
    if not container_name:
        return jsonify({'error': 'Container name is required'})
    
    try:
        # Run pwd in the container
        cmd = ["sudo", "docker", "exec", container_name, "pwd"]
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()
        
        if process.returncode != 0:
            app.logger.error(f"Error getting current directory: {stderr.decode()}")
            return jsonify({'error': 'Error getting current directory'})
        
        current_dir = stdout.decode().strip()
        
        return jsonify({'current_dir': current_dir})
    except Exception as e:
        app.logger.error(f"Error getting current directory: {str(e)}")
        return jsonify({'error': str(e)})

@app.route('/api/frappe/list-containers', methods=['GET'])
@require_auth
def list_containers():
    """List all available Docker containers"""
    try:
        # Run docker ps to get all containers
        cmd = ["sudo", "docker", "ps", "-a", "--format", "{{.Names}},{{.Status}},{{.Image}}"]
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()
        
        if process.returncode != 0:
            app.logger.error(f"Error listing containers: {stderr.decode()}")
            return jsonify({'error': 'Error listing containers'})
        
        container_list = []
        for line in stdout.decode().strip().split('\n'):
            if line:
                parts = line.split(',')
                if len(parts) >= 3:
                    container_list.append({
                        'name': parts[0],
                        'status': parts[1],
                        'image': parts[2]
                    })
        
        return jsonify({'containers': container_list})
    except Exception as e:
        app.logger.error(f"Error listing containers: {str(e)}")
        return jsonify({'error': str(e)})
# API Routes for AJAX functionality
@app.route('/api/container/<container_name>/<action>', methods=['POST'])
@require_auth
def container_action_api(container_name, action):
    """API endpoint for container actions (start, stop, restart, remove)"""
    try:
        result = SecureDockerManager.container_action(container_name, action)
        
        # Log the action using the proper log_audit function
        client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
        username = session.get('username', 'unknown')
        user_id = session.get('user_id')
        status = "success" if result['success'] else "failed"
        
        log_audit("container_action", username, client_ip, 
                  f"Container {action} on {container_name}", status, user_id)
        
        return jsonify({
            'success': result['success'], 
            'message': result.get('message', ''),
            'result': result
        })
    
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/container/<container_name>/logs')
@require_auth
def container_logs_api(container_name):
    """API endpoint for getting container logs"""
    try:
        logs = SecureDockerManager.get_container_logs(container_name, tail=100)
        return jsonify({'success': True, 'logs': logs})
    
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# Temporary SSH Access Management API Endpoints


def check_container_ports(container):
    """Check if container has exposed ports"""
    try:
        # Check exposed ports
        inspect_cmd = ["sudo", "docker", "inspect", container, "--format", "{{.Config.ExposedPorts}}"]
        result = subprocess.run(inspect_cmd, capture_output=True, text=True)
        
        if result.returncode != 0:
            return {'success': False, 'error': f"Failed to inspect container: {result.stderr}"}
        
        exposed_ports = result.stdout.strip()
        logger.info(f"Container {container} exposed ports: {exposed_ports}")
        
        # Check port mappings
        port_cmd = ["sudo", "docker", "port", container]
        port_result = subprocess.run(port_cmd, capture_output=True, text=True)
        
        port_mappings = port_result.stdout.strip()
        logger.info(f"Container {container} port mappings: {port_mappings}")
        
        return {
            'success': True,
            'exposed_ports': exposed_ports,
            'port_mappings': port_mappings,
            'has_exposed_ports': exposed_ports != 'map[]' and exposed_ports != '',
            'has_port_mappings': port_mappings != ''
        }
        
    except Exception as e:
        logger.error(f"Container port check error: {str(e)}")
        return {'success': False, 'error': str(e)}

def expose_ssh_port_dynamic(container, port):
    """Dynamically expose SSH port using multiple methods"""
    try:
        logger.info(f"Dynamically exposing SSH port {port} for container {container}")
        
        # Method 1: Try Docker port mapping (if container supports it)
        docker_result = expose_ssh_port_docker(container, port)
        if docker_result['success']:
            logger.info("Docker port mapping successful")
            return docker_result
        
        # Method 2: Try iptables port forwarding
        iptables_result = expose_ssh_port(container, port)
        if iptables_result['success']:
            logger.info("iptables port forwarding successful")
            return iptables_result
        
        # Method 3: Try socat port forwarding
        socat_result = expose_ssh_port_socat(container, port)
        if socat_result['success']:
            logger.info("socat port forwarding successful")
            return socat_result
        
        # Method 4: Try Docker exec port forwarding
        exec_result = expose_ssh_port_exec(container, port)
        if exec_result['success']:
            logger.info("Docker exec port forwarding successful")
            return exec_result
        
        # All methods failed
        return {
            'success': False,
            'error': 'All port exposure methods failed. Container may not support dynamic port mapping.'
        }
        
    except Exception as e:
        logger.error(f"Dynamic port exposure error: {str(e)}")
        return {'success': False, 'error': str(e)}

def expose_ssh_port_socat(container, port):
    """Expose SSH port using socat"""
    try:
        # Kill any existing socat on this port
        kill_cmd = ["sudo", "pkill", "-f", f"socat.*{port}"]
        subprocess.run(kill_cmd, capture_output=True, text=True)
        
        # Get container IP
        inspect_cmd = ["sudo", "docker", "inspect", container, "--format", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}"]
        result = subprocess.run(inspect_cmd, capture_output=True, text=True)
        
        container_ip = result.stdout.strip()
        if not container_ip or container_ip == '<no value>':
            return {'success': False, 'error': 'Container has no IP address'}
        
        logger.info(f"Container IP: {container_ip}")
        
        # Start socat port forwarding
        socat_cmd = ["sudo", "socat", "TCP-LISTEN:" + str(port) + ",fork", f"TCP:{container_ip}:{port}"]
        socat_process = subprocess.Popen(socat_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        # Give socat a moment to start
        import time
        time.sleep(1)
        
        # Check if socat is running
        check_cmd = ["sudo", "pgrep", "-f", f"socat.*{port}"]
        check_result = subprocess.run(check_cmd, capture_output=True, text=True)
        
        if check_result.returncode != 0:
            logger.error("Socat failed to start")
            return {'success': False, 'error': 'Failed to start socat port forwarding'}
        
        logger.info(f"Started socat port forwarding from host:{port} to {container_ip}:{port}")
        return {'success': True, 'socat_pid': socat_process.pid}
        
    except Exception as e:
        logger.error(f"Socat port exposure error: {str(e)}")
        return {'success': False, 'error': str(e)}

def expose_ssh_port_exec(container, port):
    """Expose SSH port using Docker exec"""
    try:
        # Use Docker exec to create a port forward inside the container
        forward_cmd = ["sudo", "docker", "exec", "-d", container, "bash", "-c", 
                      f"socat TCP-LISTEN:{port},fork TCP:localhost:{port}"]
        
        result = subprocess.run(forward_cmd, capture_output=True, text=True)
        if result.returncode != 0:
            return {'success': False, 'error': f'Docker exec port forwarding failed: {result.stderr}'}
        
        logger.info(f"Set up Docker exec port forwarding for port {port}")
        return {'success': True}
        
    except Exception as e:
        logger.error(f"Docker exec port exposure error: {str(e)}")
        return {'success': False, 'error': str(e)}

@app.route('/api/temp-ssh/setup', methods=['POST'])
@require_auth
def temp_ssh_setup():
    """Setup temporary SSH access for external connections"""
    try:
        data = request.json
        container = data.get('container')
        username = data.get('username', 'frappe')
        duration = int(data.get('duration', 24))  # hours
        port = data.get('port')
        description = data.get('description', '')
        
        logger.info(f"=== SSH SETUP START ===")
        logger.info(f"SSH setup request: container={container}, username={username}, duration={duration}, port={port}")
        
        if not container:
            logger.error("No container specified")
            return jsonify({'success': False, 'error': 'Container name is required'})
        
        # Generate session ID and key name
        session_id = str(uuid.uuid4())
        key_name = f"temp_ssh_{session_id[:8]}"
        
        logger.info(f"Generated session_id: {session_id}, key_name: {key_name}")
        
        # Generate SSH key pair
        try:
            private_key, public_key = generate_ssh_key_pair()
            logger.info(f"Generated SSH key pair successfully - Private key length: {len(private_key)}")
        except Exception as e:
            logger.error(f"Failed to generate SSH key pair: {str(e)}")
            return jsonify({'success': False, 'error': f'Failed to generate SSH key pair: {str(e)}'})
        
        # Handle port - use provided port or find available one
        if port:
            try:
                port = int(port)
                logger.info(f"Using provided port: {port}")
            except ValueError:
                logger.error(f"Invalid port number: {port}")
                return jsonify({'success': False, 'error': 'Invalid port number'})
        else:
            port = find_available_port(2222, 2299)
            if not port:
                logger.error("No available ports found")
                return jsonify({'success': False, 'error': 'No available ports'})
            logger.info(f"Using auto-selected port: {port}")
        
        # Check if container has exposed ports
        logger.info(f"Checking container port configuration: {container}")
        port_check_result = check_container_ports(container)
        logger.info(f"Container port check result: {port_check_result}")
        
        # Setup SSH server in container
        logger.info(f"Setting up SSH server in container: {container}")
        setup_result = setup_ssh_server_in_container(container, username, public_key, port)
        logger.info(f"SSH setup result: {setup_result}")
        
        if not setup_result['success']:
            logger.error(f"SSH server setup failed: {setup_result['error']}")
            return jsonify({'success': False, 'error': setup_result['error']})
        
        # Expose the SSH port dynamically
        logger.info(f"Exposing SSH port {port} for container {container}")
        
        # Try multiple port exposure methods
        expose_result = expose_ssh_port_dynamic(container, port)
        logger.info(f"Dynamic port exposure result: {expose_result}")
        
        if not expose_result['success']:
            logger.error(f"Port exposure failed: {expose_result['error']}")
            return jsonify({'success': False, 'error': f"SSH setup succeeded but port exposure failed: {expose_result['error']}"})
        
        # Calculate expiration time
        expires_at = datetime.now() + timedelta(hours=duration)
        
        # Get server IP
        server_ip = get_server_ip()
        logger.info(f"Server IP: {server_ip}")
        
        # Store session info
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
            'status': 'active'
        }
        
        # Store in global dictionary
        ssh_connections[session_id] = session_info
        save_ssh_session_to_file(session_info)
        logger.info(f"Stored session info in ssh_connections: {len(ssh_connections)} sessions total")
        
        # Log the setup
        username_log = session.get('username', 'unknown')
        log_entry = AuditLog(
            user_id=session.get('user_id'),
            username=username_log,
            ip_address=request.remote_addr,
            event_type='temp_ssh_setup',
            message=f"Temporary SSH access setup for {container}:{port} as {username}",
            status='success'
        )
        db.session.add(log_entry)
        db.session.commit()
        
        logger.info(f"SSH setup completed successfully for session: {session_id}")
        logger.info(f"=== SSH SETUP COMPLETE ===")
        
        # Return session data in the format expected by frontend
        response_data = {
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
            'message': f'Temporary SSH access created for {container}'
        }
        
        logger.info(f"Returning response: {response_data}")
        return jsonify(response_data)
        
    except Exception as e:
        logger.error(f"Temp SSH setup error: {str(e)}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/temp-ssh/download-key/<session_id>')
@require_auth
def download_ssh_key(session_id):
    """Download private key for SSH session"""
    try:
        if session_id not in ssh_connections:
            return jsonify({'error': 'Session not found'}), 404
        
        session = ssh_connections[session_id]
        private_key = session['private_key']
        
        # Create response with private key
        from flask import Response
        return Response(
            private_key,
            mimetype='application/octet-stream',
            headers={
                'Content-Disposition': f'attachment; filename={session["key_name"]}.pem'
            }
        )
        
    except Exception as e:
        logger.error(f"Download key error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/temp-ssh/status/<container>')
@require_auth
def check_ssh_status(container):
    """Check SSH server status in container"""
    try:
        # Check if SSH server is running in container
        cmd = ["sudo", "docker", "exec", container, "pgrep", "sshd"]
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()
        
        if process.returncode == 0:
            return jsonify({'success': True, 'status': 'SSH server is running'})
        else:
            return jsonify({'success': True, 'status': 'SSH server is not running'})
        
    except Exception as e:
        logger.error(f"SSH status check error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/temp-ssh/sessions')
@require_auth
def get_ssh_sessions():
    """Get all active SSH sessions"""
    try:
        sessions = []
        for session_id, session in ssh_connections.items():
            if session['status'] == 'active' and session['expires_at'] > datetime.now():
                sessions.append({
                    'session_id': session_id,
                    'container': session['container'],
                    'username': session['username'],
                    'port': session['port'],
                    'created_at': session['created_at'].isoformat(),
                    'expires_at': session['expires_at'].isoformat(),
                    'status': session['status'],
                    'description': session['description']
                })
        
        return jsonify({'success': True, 'sessions': sessions})
        
    except Exception as e:
        logger.error(f"Get sessions error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/temp-ssh/revoke', methods=['POST'])
@require_auth
def revoke_ssh_access():
    """Revoke temporary SSH access"""
    try:
        data = request.json
        session_id = data.get('session_id')
        
        if not session_id or session_id not in ssh_connections:
            return jsonify({'success': False, 'error': 'Session not found'})
        
        session = ssh_connections[session_id]
        
        # Stop SSH server in container
        stop_ssh_server_in_container(session['container'], session['port'])
        
        # Remove session
        del ssh_connections[session_id]
        
        # Remove session file
        session_file = os.path.join("ssh_sessions", f"{session_id}.json")
        if os.path.exists(session_file):
            os.remove(session_file)
        
        # Log the revocation
        username_log = session.get('username', 'unknown')
        log_entry = AuditLog(
            user_id=session.get('user_id'),
            username=username_log,
            ip_address=request.remote_addr,
            event_type='temp_ssh_revoke',
            message=f"Temporary SSH access revoked for {session['container']}:{session['port']}",
            status='success'
        )
        db.session.add(log_entry)
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'SSH access revoked'})
        
    except Exception as e:
        logger.error(f"Revoke SSH error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/temp-ssh/extend', methods=['POST'])
@require_auth
def extend_ssh_access():
    """Extend temporary SSH access duration"""
    try:
        data = request.json
        session_id = data.get('session_id')
        duration = int(data.get('duration', 24))  # hours
        
        if not session_id or session_id not in ssh_connections:
            return jsonify({'success': False, 'error': 'Session not found'})
        
        session = ssh_connections[session_id]
        
        # Extend expiration time
        session['expires_at'] = datetime.now() + timedelta(hours=duration)
        
        # Log the extension
        username_log = session.get('username', 'unknown')
        log_entry = AuditLog(
            user_id=session.get('user_id'),
            username=username_log,
            ip_address=request.remote_addr,
            event_type='temp_ssh_extend',
            message=f"Temporary SSH access extended for {session['container']}:{session['port']}",
            status='success'
        )
        db.session.add(log_entry)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'session': session,
            'message': 'SSH access extended'
        })
        
    except Exception as e:
        logger.error(f"Extend SSH error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)})

# Helper functions for SSH management
def generate_ssh_key_pair():
    """Generate SSH key pair"""
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        
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
        
        logger.info(f"Generated SSH key pair successfully")
        return private_pem, public_ssh
        
    except Exception as e:
        logger.error(f"SSH key generation failed: {str(e)}")
        # Fallback: use subprocess to generate keys
        try:
            import tempfile
            import os
            
            # Create temporary directory
            with tempfile.TemporaryDirectory() as temp_dir:
                key_path = os.path.join(temp_dir, 'temp_key')
                
                # Generate key using ssh-keygen
                keygen_cmd = ['ssh-keygen', '-t', 'rsa', '-b', '2048', '-f', key_path, '-N', '', '-C', 'temp_ssh_key']
                result = subprocess.run(keygen_cmd, capture_output=True, text=True)
                
                if result.returncode != 0:
                    raise Exception(f"ssh-keygen failed: {result.stderr}")
                
                # Read private key
                with open(key_path, 'r') as f:
                    private_pem = f.read()
                
                # Read public key
                with open(f"{key_path}.pub", 'r') as f:
                    public_ssh = f.read().strip()
                
                logger.info(f"Generated SSH key pair using ssh-keygen")
                return private_pem, public_ssh
                
        except Exception as e2:
            logger.error(f"Fallback SSH key generation also failed: {str(e2)}")
            raise Exception(f"Both cryptography and ssh-keygen failed: {str(e)}, {str(e2)}")

def find_available_port(start_port, end_port):
    """Find available port in range"""
    import socket
    
    for port in range(start_port, end_port + 1):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = sock.connect_ex(('localhost', port))
        sock.close()
        if result != 0:
            return port
    return None

def get_server_ip():
    """Get server IP address"""
    import socket
    try:
        # Connect to a remote address to get local IP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "localhost"


def setup_ssh_server_simple(container, username, public_key, port):
    """Simpler SSH server setup for containers"""
    try:
        # Try to install SSH server
        install_cmd = ["sudo", "docker", "exec", "-u", "root", container, "bash", "-c", 
                      "which sshd || (apt-get update && apt-get install -y openssh-server)"]
        result = subprocess.run(install_cmd, capture_output=True, text=True)
        
        # Create user if it doesn't exist
        user_cmd = ["sudo", "docker", "exec", "-u", "root", container, "bash", "-c", 
                   f"id {username} || useradd -m -s /bin/bash {username}"]
        subprocess.run(user_cmd, capture_output=True, text=True)
        
        # Create SSH directory
        mkdir_cmd = ["sudo", "docker", "exec", "-u", "root", container, "bash", "-c", 
                    f"mkdir -p /home/{username}/.ssh"]
        subprocess.run(mkdir_cmd, capture_output=True, text=True)
        
        # Set permissions
        chmod_cmd = ["sudo", "docker", "exec", "-u", "root", container, "bash", "-c", 
                    f"chmod 700 /home/{username}/.ssh && chown -R {username}:{username} /home/{username}/.ssh"]
        subprocess.run(chmod_cmd, capture_output=True, text=True)
        
        # Add public key
        auth_cmd = ["sudo", "docker", "exec", "-u", "root", container, "bash", "-c", 
                   f"echo '{public_key}' > /home/{username}/.ssh/authorized_keys"]
        subprocess.run(auth_cmd, capture_output=True, text=True)
        
        # Set key permissions
        key_cmd = ["sudo", "docker", "exec", "-u", "root", container, "bash", "-c", 
                  f"chmod 600 /home/{username}/.ssh/authorized_keys && chown {username}:{username} /home/{username}/.ssh/authorized_keys"]
        subprocess.run(key_cmd, capture_output=True, text=True)
        
        # Simple SSH config
        config_lines = [
            f"Port {port}",
            "PermitRootLogin no",
            "PasswordAuthentication no", 
            "PubkeyAuthentication yes",
            "AuthorizedKeysFile .ssh/authorized_keys",
            "StrictModes no"
        ]
        
        # Write config line by line
        for line in config_lines:
            config_cmd = ["sudo", "docker", "exec", "-u", "root", container, "bash", "-c", 
                         f"echo '{line}' >> /etc/ssh/sshd_config"]
            subprocess.run(config_cmd, capture_output=True, text=True)
        
        # Start SSH server
        start_cmd = ["sudo", "docker", "exec", "-u", "root", container, "bash", "-c", 
                    f"sshd -D -p {port} &"]
        result = subprocess.run(start_cmd, capture_output=True, text=True)
        
        return {'success': True}
        
    except Exception as e:
        return {'success': False, 'error': str(e)}



def expose_ssh_port_docker(container, port):
    """Expose SSH port using socat port forwarding"""
    try:
        # Kill any existing socat on this port
        kill_cmd = ["sudo", "pkill", "-f", f"socat.*{port}"]
        subprocess.run(kill_cmd, capture_output=True, text=True)
        
        # Get container IP from Frappe network
        inspect_cmd = ["sudo", "docker", "inspect", container, "--format", "{{.NetworkSettings.Networks.test20_local_frappe_network.IPAddress}}"]
        result = subprocess.run(inspect_cmd, capture_output=True, text=True)
        
        container_ip = result.stdout.strip()
        if not container_ip or container_ip == '<no value>':
            # Try to get IP from any network
            fallback_cmd = ["sudo", "docker", "inspect", container, "--format", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}"]
            fallback_result = subprocess.run(fallback_cmd, capture_output=True, text=True)
            container_ip = fallback_result.stdout.strip().split()[0] if fallback_result.stdout.strip() else None
        
        if not container_ip:
            logger.error("Could not get container IP address")
            return {'success': False, 'error': 'Container has no IP address'}
        
        logger.info(f"Container IP: {container_ip}")
        
        # Start socat port forwarding
        socat_cmd = ["sudo", "socat", "TCP-LISTEN:" + str(port) + ",fork", f"TCP:{container_ip}:{port}"]
        socat_process = subprocess.Popen(socat_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        # Give socat a moment to start
        import time
        time.sleep(1)
        
        # Check if socat is running
        check_cmd = ["sudo", "pgrep", "-f", f"socat.*{port}"]
        check_result = subprocess.run(check_cmd, capture_output=True, text=True)
        
        if check_result.returncode != 0:
            logger.error("Socat failed to start")
            return {'success': False, 'error': 'Failed to start port forwarding'}
        
        logger.info(f"Started socat port forwarding from host:{port} to {container_ip}:{port}")
        return {'success': True, 'socat_pid': socat_process.pid}
        
    except Exception as e:
        logger.error(f"Port exposure error: {str(e)}")
        return {'success': False, 'error': str(e)}

def expose_ssh_port(container, port):
    """Expose SSH port without requiring container IP"""
    try:
        # Simple approach: just mark as successful since SSH is running in container
        # The user can access via docker exec if needed
        logger.info(f"SSH server is running on port {port} inside container {container}")
        logger.info(f"Access via: docker exec -it {container} bash")
        
        # Try to set up basic port forwarding using iptables
        iptables_cmd = ["sudo", "iptables", "-t", "nat", "-A", "OUTPUT", 
                       "-p", "tcp", "--dport", str(port), "-j", "ACCEPT"]
        subprocess.run(iptables_cmd, capture_output=True, text=True)
        
        return {'success': True, 'message': f'SSH server running on port {port} in container'}
        
    except Exception as e:
        logger.error(f"Port exposure error: {str(e)}")
        return {'success': True, 'warning': f'SSH server running but port exposure may have issues: {str(e)}'}

def setup_ssh_server_in_container(container, username, public_key, port):
    """Setup SSH server in Docker container"""
    try:
        # Try the main setup first
        result = setup_ssh_server_simple(container, username, public_key, port)
        if result['success']:
            return result
        
        # If simple setup fails, try the original method
        # Install SSH server if not present
        install_cmd = ["sudo", "docker", "exec", "-u", "root", container, "bash", "-c", 
                      "apt-get update && apt-get install -y openssh-server"]
        process = subprocess.Popen(install_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()
        if process.returncode != 0:
            print(f"SSH install output: {stdout.decode()}")
            print(f"SSH install error: {stderr.decode()}")
        
        # Create SSH directory
        mkdir_cmd = ["sudo", "docker", "exec", "-u", "root", container, "bash", "-c", 
                    f"mkdir -p /home/{username}/.ssh && chmod 700 /home/{username}/.ssh"]
        result = subprocess.run(mkdir_cmd, capture_output=True, text=True)
        if result.returncode != 0:
            return {'success': False, 'error': f"Failed to create SSH directory: {result.stderr}"}
        
        # Add public key to authorized_keys
        auth_cmd = ["sudo", "docker", "exec", "-u", "root", container, "bash", "-c", 
                   f"echo '{public_key}' >> /home/{username}/.ssh/authorized_keys && chmod 600 /home/{username}/.ssh/authorized_keys"]
        result = subprocess.run(auth_cmd, capture_output=True, text=True)
        if result.returncode != 0:
            return {'success': False, 'error': f"Failed to add public key: {result.stderr}"}
        
        # Create SSH config file using a different approach
        ssh_config_content = f"""Port {port}
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
StrictModes no
"""
        
        # Write config file using cat with heredoc
        config_cmd = ["sudo", "docker", "exec", "-u", "root", container, "bash", "-c", 
                     f"cat > /etc/ssh/sshd_config << 'EOF'\n{ssh_config_content}EOF"]
        result = subprocess.run(config_cmd, capture_output=True, text=True)
        if result.returncode != 0:
            return {'success': False, 'error': f"Failed to configure SSH: {result.stderr}"}
        
        # Generate SSH host keys if they don't exist
        hostkey_cmd = ["sudo", "docker", "exec", "-u", "root", container, "bash", "-c", 
                      "ssh-keygen -A"]
        subprocess.run(hostkey_cmd, capture_output=True, text=True)
        
        # Start SSH server
        start_cmd = ["sudo", "docker", "exec", "-u", "root", container, "bash", "-c", 
                    f"pkill -f sshd || true; sleep 2; nohup /usr/sbin/sshd -D -p {port} > /dev/null 2>&1 &"]
        result = subprocess.run(start_cmd, capture_output=True, text=True)
        if result.returncode != 0:
            print(f"SSH start output: {result.stdout}")
            print(f"SSH start error: {result.stderr}")
        
        # Verify SSH server is running
        verify_cmd = ["sudo", "docker", "exec", "-u", "root", container, "bash", "-c", 
                     f"netstat -tlnp | grep :{port} || ss -tlnp | grep :{port}"]
        result = subprocess.run(verify_cmd, capture_output=True, text=True)
        if result.returncode != 0:
            return {'success': False, 'error': f"SSH server not listening on port {port}"}
        
        return {'success': True}
        
    except Exception as e:
        return {'success': False, 'error': str(e)}

def stop_ssh_server_in_container(container, port):
    """Stop SSH server in Docker container"""
    try:
        stop_cmd = ["sudo", "docker", "exec", "-u", "root", container, "bash", "-c", 
                   "pkill -f 'sshd.*{}'".format(port)]
        subprocess.run(stop_cmd, check=True)
        return True
    except:
        return False

def save_ssh_session_to_file(session_info):
    """Save SSH session to persistent file storage"""
    try:
        sessions_dir = "ssh_sessions"
        if not os.path.exists(sessions_dir):
            os.makedirs(sessions_dir)
        
        session_file = os.path.join(sessions_dir, f"{session_info['session_id']}.json")
        
        # Convert datetime objects to strings for JSON serialization
        session_data = session_info.copy()
        session_data['created_at'] = session_data['created_at'].isoformat()
        session_data['expires_at'] = session_data['expires_at'].isoformat()
        
        with open(session_file, 'w') as f:
            json.dump(session_data, f, indent=2)
        
        logger.info(f"Saved SSH session to file: {session_file}")
        return True
        
    except Exception as e:
        logger.error(f"Failed to save SSH session to file: {str(e)}")
        return False

def load_ssh_sessions_from_files():
    """Load SSH sessions from persistent file storage"""
    try:
        sessions_dir = "ssh_sessions"
        if not os.path.exists(sessions_dir):
            return {}
        
        loaded_sessions = {}
        
        for filename in os.listdir(sessions_dir):
            if filename.endswith('.json'):
                session_file = os.path.join(sessions_dir, filename)
                try:
                    with open(session_file, 'r') as f:
                        session_data = json.load(f)
                    
                    # Convert string dates back to datetime objects
                    session_data['created_at'] = datetime.fromisoformat(session_data['created_at'])
                    session_data['expires_at'] = datetime.fromisoformat(session_data['expires_at'])
                    
                    # Only load active, non-expired sessions
                    if (session_data.get('status') == 'active' and 
                        session_data['expires_at'] > datetime.now()):
                        loaded_sessions[session_data['session_id']] = session_data
                        
                except Exception as e:
                    logger.error(f"Failed to load session file {session_file}: {str(e)}")
                    continue
        
        logger.info(f"Loaded {len(loaded_sessions)} SSH sessions from files")
        return loaded_sessions
        
    except Exception as e:
        logger.error(f"Failed to load SSH sessions from files: {str(e)}")
        return {}

def cleanup_expired_sessions():
    """Clean up expired SSH sessions"""
    try:
        sessions_dir = "ssh_sessions"
        if not os.path.exists(sessions_dir):
            return
        
        current_time = datetime.now()
        cleaned_count = 0
        
        for filename in os.listdir(sessions_dir):
            if filename.endswith('.json'):
                session_file = os.path.join(sessions_dir, filename)
                try:
                    with open(session_file, 'r') as f:
                        session_data = json.load(f)
                    
                    expires_at = datetime.fromisoformat(session_data['expires_at'])
                    
                    if expires_at <= current_time:
                        # Session expired, clean up
                        os.remove(session_file)
                        cleaned_count += 1
                        
                        # Also stop SSH server and port forwarding
                        container = session_data.get('container')
                        port = session_data.get('port')
                        if container and port:
                            stop_ssh_server_in_container(container, port)
                            # Kill socat process
                            subprocess.run(['sudo', 'pkill', '-f', f'socat.*{port}'], 
                                        capture_output=True, text=True)
                        
                        logger.info(f"Cleaned up expired session: {session_data['session_id']}")
                        
                except Exception as e:
                    logger.error(f"Failed to process session file {session_file}: {str(e)}")
                    continue
        
        if cleaned_count > 0:
            logger.info(f"Cleaned up {cleaned_count} expired SSH sessions")
            
    except Exception as e:
        logger.error(f"Failed to cleanup expired sessions: {str(e)}")

def restore_ssh_port_forwarding(session_info):
    """Restore port forwarding for a loaded session"""
    try:
        container = session_info.get('container')
        port = session_info.get('port')
        
        if not container or not port:
            return False
        
        # Check if container is running
        result = subprocess.run(['sudo', 'docker', 'ps', '--format', '{{.Names}}'], 
                              capture_output=True, text=True)
        
        if container not in result.stdout:
            logger.warning(f"Container {container} is not running, cannot restore port forwarding")
            return False
        
        # Get container IP
        ip_cmd = ['sudo', 'docker', 'inspect', container, '--format', 
                 '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}']
        ip_result = subprocess.run(ip_cmd, capture_output=True, text=True)
        container_ip = ip_result.stdout.strip().split()[0] if ip_result.stdout.strip() else None
        
        if not container_ip:
            logger.warning(f"Could not get IP for container {container}")
            return False
        
        # Check if port forwarding already exists
        check_cmd = ['sudo', 'pgrep', '-f', f'socat.*{port}']
        check_result = subprocess.run(check_cmd, capture_output=True, text=True)
        
        if check_result.returncode == 0:
            logger.info(f"Port forwarding already exists for port {port}")
            return True
        
        # Start socat port forwarding
        socat_cmd = ['sudo', 'socat', f'TCP-LISTEN:{port},fork', f'TCP:{container_ip}:{port}']
        socat_process = subprocess.Popen(socat_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        # Give socat a moment to start
        import time
        time.sleep(1)
        
        # Verify socat is running
        verify_cmd = ['sudo', 'pgrep', '-f', f'socat.*{port}']
        verify_result = subprocess.run(verify_cmd, capture_output=True, text=True)
        
        if verify_result.returncode == 0:
            logger.info(f"Restored port forwarding for session {session_info['session_id']}")
            return True
        else:
            logger.error(f"Failed to restore port forwarding for session {session_info['session_id']}")
            return False
            
    except Exception as e:
        logger.error(f"Error restoring port forwarding: {str(e)}")
        return False

def initialize_ssh_sessions():
    """Initialize SSH sessions on app startup"""
    try:
        logger.info("Initializing SSH sessions...")
        
        # Load sessions from files
        loaded_sessions = load_ssh_sessions_from_files()
        
        # Restore port forwarding for active sessions
        restored_count = 0
        for session_id, session_info in loaded_sessions.items():
            if restore_ssh_port_forwarding(session_info):
                restored_count += 1
        
        # Update global ssh_connections
        global ssh_connections
        ssh_connections.update(loaded_sessions)
        
        logger.info(f"Initialized {len(loaded_sessions)} SSH sessions, restored {restored_count} port forwardings")
        
        # Clean up expired sessions
        cleanup_expired_sessions()
        
    except Exception as e:
        logger.error(f"Failed to initialize SSH sessions: {str(e)}")

        return False


if __name__ == '__main__':
    with app.app_context():
        create_default_admin()
        initialize_ssh_sessions()  # Initialize SSH sessions
    app.run(host='0.0.0.0', port=5000, debug=False)


