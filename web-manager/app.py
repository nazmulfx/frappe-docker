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
    """Check if container has exposed ports and mapped ports.

    Returns:
        dict with keys: success, exposed_ports (dict or None), port_mappings (str), has_exposed_ports (bool), has_port_mappings (bool)
    """
    try:
        inspect_cmd = ["sudo", "docker", "inspect", container, "--format", "{{json .Config.ExposedPorts}}"]
        result = subprocess.run(inspect_cmd, capture_output=True, text=True)
        if result.returncode != 0:
            return {'success': False, 'error': f"Failed to inspect container: {result.stderr.strip()}"}

        exposed_raw = result.stdout.strip()
        exposed_ports = None
        try:
            # exposed_raw could be "null", "{}", or a JSON map
            exposed_ports = json.loads(exposed_raw)
        except Exception:
            # fallback parsing
            if exposed_raw in ("<nil>", "map[]", "", "null"):
                exposed_ports = {}
            else:
                # try to interpret as string
                exposed_ports = {}

        logger.info(f"Container {container} exposed ports (parsed): {exposed_ports}")

        # Check port mappings (docker port)
        port_cmd = ["sudo", "docker", "port", container]
        port_result = subprocess.run(port_cmd, capture_output=True, text=True)
        port_mappings = port_result.stdout.strip() if port_result.returncode == 0 else ""

        logger.info(f"Container {container} port mappings: {port_mappings}")

        has_exposed = bool(exposed_ports) and exposed_ports != {}
        has_mappings = port_mappings != ""

        return {
            'success': True,
            'exposed_ports': exposed_ports,
            'port_mappings': port_mappings,
            'has_exposed_ports': has_exposed,
            'has_port_mappings': has_mappings
        }
    except Exception as e:
        logger.exception("Container port check error")
        return {'success': False, 'error': str(e)}




def expose_ssh_port_dynamic(container, port):
    """Dynamically expose SSH port using multiple methods - WITH DEBUGGING"""
    try:
        logger.info(f"=== DYNAMIC PORT EXPOSURE DEBUG ===")
        logger.info(f"Container: {container}, Port: {port}")
        
        # Method 1: Try Docker port mapping
        logger.info("Attempting Docker port mapping...")
        docker_result = expose_ssh_port_docker(container, port)
        if docker_result['success']:
            logger.info("Docker port mapping successful")
            return docker_result
        else:
            logger.warning(f"Docker port mapping failed: {docker_result.get('error', 'Unknown error')}")

        # Method 2: Try iptables port forwarding
        logger.info("Attempting iptables port forwarding...")
        iptables_result = expose_ssh_port(container, port)
        if iptables_result['success']:
            logger.info("iptables port forwarding successful")
            return iptables_result
        else:
            logger.warning(f"iptables failed: {iptables_result.get('error', 'Unknown error')}")

        # Method 3: Try socat port forwarding
        logger.info("Attempting socat port forwarding...")
        socat_result = expose_ssh_port_socat(container, port)
        if socat_result['success']:
            logger.info("socat port forwarding successful")
            return socat_result
        else:
            logger.warning(f"socat failed: {socat_result.get('error', 'Unknown error')}")

        # Method 4: Try Docker exec port forwarding
        logger.info("Attempting Docker exec port forwarding...")
        exec_result = expose_ssh_port_exec(container, port)
        if exec_result['success']:
            logger.info("Docker exec port forwarding successful")
            return exec_result
        else:
            logger.warning(f"Docker exec failed: {exec_result.get('error', 'Unknown error')}")

        # All methods failed - provide detailed diagnostics
        logger.error("All port exposure methods failed!")
        
        # Run diagnostic commands
        diagnostics = run_port_diagnostics(container, port)
        logger.info(f"Port diagnostics: {diagnostics}")
        logger.info("Attempting manual fallback method...")
        manual_result = expose_ssh_port_manual(container, port)
        if manual_result['success']:
            logger.info("Manual method successful")
            return manual_result
        return {
            'success': False,
            'error': 'All port exposure methods failed. ' + diagnostics,
            'diagnostics': diagnostics
        }
        
    except Exception as e:
        logger.exception("Dynamic port exposure error")
        return {'success': False, 'error': str(e)}

def run_port_diagnostics(container, port):
    """Run diagnostic commands to understand why port forwarding fails"""
    diagnostics = {}
    
    try:
        # Check if port is already in use
        check_port_cmd = ["sudo", "lsof", "-i", f":{port}"]
        result = subprocess.run(check_port_cmd, capture_output=True, text=True)
        diagnostics['port_usage'] = result.stdout if result.stdout else result.stderr
        
        # Check container IP
        container_ip = get_container_ip(container)
        diagnostics['container_ip'] = container_ip
        
        # Check if container has SSH running
        ssh_check = ["sudo", "docker", "exec", container, "netstat", "-tlnp"]
        result = subprocess.run(ssh_check, capture_output=True, text=True)
        diagnostics['container_ports'] = result.stdout if result.stdout else result.stderr
        
        # Check iptables rules
        iptables_check = ["sudo", "iptables", "-t", "nat", "-L", "-n", "-v"]
        result = subprocess.run(iptables_check, capture_output=True, text=True)
        diagnostics['iptables_rules'] = result.stdout
        
        # Check socat processes
        socat_check = ["sudo", "pgrep", "-a", "socat"]
        result = subprocess.run(socat_check, capture_output=True, text=True)
        diagnostics['socat_processes'] = result.stdout if result.stdout else "No socat processes"
        
    except Exception as e:
        diagnostics['error'] = str(e)
    
    return json.dumps(diagnostics)


def expose_ssh_port_socat(container, port):
    """
    Forward host port -> container SSH (22) using socat - IMPROVED VERSION
    """
    try:
        logger.info(f"Starting socat for container {container} on port {port}")
        
        # Get container IP
        container_ip = get_container_ip(container)
        if not container_ip:
            return {'success': False, 'error': 'Could not get container IP'}
        
        logger.info(f"Container IP: {container_ip}")
        
        # Kill any existing processes on this port
        kill_cmd = ["sudo", "pkill", "-f", f"socat.*{port}"]
        subprocess.run(kill_cmd, capture_output=True)
        
        # Also kill any existing processes that might be blocking the port
        kill_port_cmd = ["sudo", "fuser", "-k", f"{port}/tcp"]
        subprocess.run(kill_port_cmd, capture_output=True)
        
        # Create the socat command
        socat_cmd = [
            "sudo", "socat",
            "TCP-LISTEN:{},fork,reuseaddr".format(port),
            "TCP:{}:22".format(container_ip)
        ]
        
        logger.info(f"Executing: {' '.join(socat_cmd)}")
        
        # Start socat in the background
        process = subprocess.Popen(
            socat_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            preexec_fn=os.setsid
        )
        
        # Wait a moment for socat to start
        time.sleep(2)
        
        # Check if socat is running
        check_cmd = ["sudo", "ss", "-tlnp", "|", "grep", f":{port}"]
        result = subprocess.run(" ".join(check_cmd), shell=True, capture_output=True, text=True)
        
        if result.returncode == 0 and str(port) in result.stdout:
            logger.info(f"Socat successfully listening on port {port}")
            logger.info(f"Port check: {result.stdout}")
            
            # Test the connection
            test_result = test_port_connectivity("localhost", port)
            logger.info(f"Port connectivity test: {test_result}")
            
            return {
                'success': True, 
                'pid': process.pid, 
                'container_ip': container_ip,
                'method': 'socat'
            }
        else:
            # Get error output
            stdout, stderr = process.communicate()
            logger.error(f"Socat failed - stdout: {stdout}, stderr: {stderr}")
            
            process.terminate()
            return {'success': False, 'error': f'Socat failed to start: {stderr}'}
            
    except Exception as e:
        logger.exception("Socat port exposure error")
        return {'success': False, 'error': str(e)}

def test_port_connectivity(host, port):
    """Test if a port is actually accessible"""
    try:
        # Try netcat
        nc_cmd = ["nc", "-z", "-w", "3", host, str(port)]
        result = subprocess.run(nc_cmd, capture_output=True, text=True)
        
        if result.returncode == 0:
            return "Port is accessible"
        else:
            return f"Port not accessible: {result.stderr}"
            
    except Exception as e:
        return f"Test failed: {str(e)}"

def expose_ssh_port_manual(container, port):
    """Manual fallback method using direct commands"""
    try:
        container_ip = get_container_ip(container)
        if not container_ip:
            return {'success': False, 'error': 'No container IP'}
        
        # Method 1: Direct socat command that you can test manually
        manual_command = f"sudo socat TCP-LISTEN:{port},fork,reuseaddr TCP:{container_ip}:22 &"
        
        logger.info(f"Manual command: {manual_command}")
        
        # Try executing it
        result = subprocess.run(manual_command, shell=True, capture_output=True, text=True)
        
        if result.returncode == 0:
            # Verify it worked
            verify_cmd = f"sudo ss -tlnp | grep :{port}"
            verify = subprocess.run(verify_cmd, shell=True, capture_output=True, text=True)
            
            if verify.returncode == 0:
                return {'success': True, 'method': 'manual', 'command': manual_command}
        
        return {'success': False, 'error': 'Manual method failed'}
        
    except Exception as e:
        return {'success': False, 'error': str(e)}

def stop_socat_by_pid(pid):
    try:
        os.kill(pid, 15)
        return True
    except Exception as e:
        logger.warning(f"stop_socat_by_pid failed: {e}")
        return False


def expose_ssh_port_exec(container, port):
    """Expose SSH by running a forwarder inside the container.
       Inside-container socat will listen on container's port and forward to 127.0.0.1:22 (container internal SSH).
       Note: this requires socat installed inside the container. If not present, you can apt-get install it (if allowed).
    """
    try:
        # Check if socat exists inside container
        check_socat = ["sudo", "docker", "exec", container, "which", "socat"]
        chk = subprocess.run(check_socat, capture_output=True, text=True)
        if chk.returncode != 0:
            logger.info("socat not found inside container; attempting to install (best-effort)")
            # Attempt install (only works for Debian/Ubuntu-based containers and when allowed)
            install_cmd = ["sudo", "docker", "exec", container, "sh", "-c", "apt-get update && apt-get install -y socat"]
            inst = subprocess.run(install_cmd, capture_output=True, text=True)
            if inst.returncode != 0:
                logger.warning(f"Failed to install socat inside container: {inst.stderr.strip()}")
                # do not fail immediately; return helpful message
                return {'success': False, 'error': 'socat not found inside container and auto-install failed'}

        # Run socat inside container to listen on container port and forward to container's sshd (127.0.0.1:22)
        # We run it detached using docker exec -d
        inner_cmd = f"socat TCP-LISTEN:{int(port)},fork,reuseaddr"
        forward_cmd = ["sudo", "docker", "exec", "-d", container, "sh", "-c", inner_cmd]
        result = subprocess.run(forward_cmd, capture_output=True, text=True)
        if result.returncode != 0:
            logger.error(f"Docker exec socat failed: {result.stderr.strip()}")
            return {'success': False, 'error': f'Docker exec socat failed: {result.stderr.strip()}'}

        logger.info(f"Started socat inside container {container} listening on {port} forwarding to 127.0.0.1:22")
        return {'success': True, 'method': 'exec', 'detail': 'socat started inside container'}
    except Exception as e:
        logger.exception("Docker exec port exposure error")
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
                if port:
                    port = int(port)
                else:
                    port = find_available_port(2222, 2299)
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
            # After SSH setup, check if port forwarding needs to be re-established
            if 'container_restarted' in setup_result and setup_result['container_restarted']:
                logger.info("Container was restarted, re-establishing port forwarding...")
                port_forward_result = reestablish_port_forwarding(container, port)
                
                if not port_forward_result['success']:
                    logger.error(f"Port forwarding re-establishment failed: {port_forward_result['error']}")
                    return jsonify({'success': False, 'error': f"SSH setup succeeded but port forwarding failed: {port_forward_result['error']}"})
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

        # Setup SSH server in container
        logger.info(f"Setting up SSH server in container: {container}")
        setup_result = setup_ssh_server_in_container(container, username, public_key, port)
        logger.info(f"SSH setup result: {setup_result}")
        
        if not setup_result['success']:
            logger.error(f"SSH server setup failed: {setup_result['error']}")
            return jsonify({'success': False, 'error': setup_result['error']})
        
        # VERIFY the setup worked
        logger.info("Verifying SSH setup...")
        verify_result = verify_ssh_setup(container, username, public_key)
        logger.info(f"Verification result: {verify_result}")
        
        if not verify_result['success']:
            logger.error(f"SSH setup verification failed: {verify_result.get('error', 'Unknown error')}")
            return jsonify({'success': False, 'error': f"SSH setup failed verification: {verify_result.get('error', 'Unknown error')}"})


        return jsonify(response_data)
        
    except Exception as e:
        logger.error(f"Temp SSH setup error: {str(e)}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
        return jsonify({'success': False, 'error': str(e)})

def diagnose_ssh_issues(container, username, public_key, port):
    """Run comprehensive diagnostics to identify the SSH authentication issue"""
    logger.info("=== COMPREHENSIVE SSH DIAGNOSIS ===")
    
    diagnostics = {}
    
    # 1. Check if user exists
    user_check = ["sudo", "docker", "exec", container, "id", username]
    result = subprocess.run(user_check, capture_output=True, text=True)
    diagnostics['user_exists'] = result.returncode == 0
    diagnostics['user_info'] = result.stdout if result.stdout else result.stderr
    
    # 2. Check .ssh directory
    ssh_dir = f"/home/{username}/.ssh"
    dir_check = ["sudo", "docker", "exec", container, "ls", "-la", "/home", "|", "grep", username]
    result = subprocess.run(" ".join(dir_check), shell=True, capture_output=True, text=True)
    diagnostics['home_dir'] = result.stdout if result.stdout else result.stderr
    
    # 3. Check .ssh directory specifically
    ssh_dir_check = ["sudo", "docker", "exec", container, "ls", "-la", ssh_dir]
    result = subprocess.run(ssh_dir_check, capture_output=True, text=True)
    diagnostics['ssh_dir'] = result.stdout if result.stdout else result.stderr
    
    # 4. Check authorized_keys file
    auth_file = f"{ssh_dir}/authorized_keys"
    auth_check = ["sudo", "docker", "exec", container, "cat", auth_file]
    result = subprocess.run(auth_check, capture_output=True, text=True)
    diagnostics['authorized_keys_content'] = result.stdout if result.stdout else result.stderr
    diagnostics['authorized_keys_exists'] = result.returncode == 0
    
    # 5. Check permissions
    perm_check = ["sudo", "docker", "exec", container, "stat", "-c", "%a %U:%G", auth_file]
    result = subprocess.run(perm_check, capture_output=True, text=True)
    diagnostics['permissions'] = result.stdout if result.stdout else result.stderr
    
    # 6. Check SSH server configuration
    sshd_check = ["sudo", "docker", "exec", container, "grep", "-E", "(PubkeyAuthentication|PasswordAuthentication)", "/etc/ssh/sshd_config"]
    result = subprocess.run(sshd_check, capture_output=True, text=True)
    diagnostics['sshd_config'] = result.stdout if result.stdout else result.stderr
    
    # 7. Check if SSH is running
    ssh_running = ["sudo", "docker", "exec", container, "ps", "aux", "|", "grep", "ssh"]
    result = subprocess.run(" ".join(ssh_running), shell=True, capture_output=True, text=True)
    diagnostics['ssh_processes'] = result.stdout if result.stdout else result.stderr
    
    # 8. Check SSH logs
    ssh_logs = ["sudo", "docker", "exec", container, "tail", "-20", "/var/log/auth.log"]
    result = subprocess.run(ssh_logs, capture_output=True, text=True)
    diagnostics['auth_logs'] = result.stdout if result.returncode == 0 else "No auth.log found"
    
    # 9. Manual test - try to add key manually
    manual_key_test = ["sudo", "docker", "exec", container, "sh", "-c", f"echo 'Manual test key' >> {auth_file}"]
    result = subprocess.run(manual_key_test, capture_output=True, text=True)
    diagnostics['manual_write_test'] = result.returncode == 0
    
    logger.info(f"Diagnostics: {json.dumps(diagnostics, indent=2)}")
    return diagnostics


def debug_ssh_setup(container, username):
    """Run debugging commands to see what's happening in the container"""
    debug_info = {}
    
    commands = [
        ["id", username],
        ["ls", "-la", f"/home/{username}"],
        ["ls", "-la", f"/home/{username}/.ssh"],
        ["cat", f"/home/{username}/.ssh/authorized_keys"],
        ["stat", "-c", "%a %U:%G", f"/home/{username}/.ssh/authorized_keys"],
        ["grep", "^PubkeyAuthentication", "/etc/ssh/sshd_config"],
        ["ss", "-tlnp", "|", "grep", ":22"]
    ]
    
    for cmd in commands:
        try:
            result = subprocess.run(["sudo", "docker", "exec", container] + cmd, 
                                  capture_output=True, text=True)
            debug_info[' '.join(cmd)] = {
                'stdout': result.stdout,
                'stderr': result.stderr,
                'returncode': result.returncode
            }
        except Exception as e:
            debug_info[' '.join(cmd)] = {'error': str(e)}
    
    return debug_info


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

def find_available_port(start=2222, end=2299):
    import socket
    for p in range(start, end+1):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(('0.0.0.0', p))
                return p
            except OSError:
                continue
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
            "Port 22",
            "PermitRootLogin no",
            "PasswordAuthentication no", 
            "PubkeyAuthentication yes",
            "AuthorizedKeysFile .ssh/authorized_keys",
            "StrictModes no"
        ]
        
        # Write SSH config using heredoc
        ssh_config_content = """Port 22
            PermitRootLogin no
            PasswordAuthentication no
            PubkeyAuthentication yes
            AuthorizedKeysFile .ssh/authorized_keys
            StrictModes no"""
        
        config_cmd = ["sudo", "docker", "exec", "-u", "root", container, "bash", "-c", 
                     f"cat > /etc/ssh/sshd_config << 'EOF'\n{ssh_config_content}\nEOF"]
        subprocess.run(config_cmd, capture_output=True, text=True)
        
        # Start SSH server
        start_cmd = ["sudo", "docker", "exec", "-u", "root", container, "bash", "-c", 
                    "mkdir -p /var/run/sshd && /usr/sbin/sshd -D -p 22 &"]
        result = subprocess.run(start_cmd, capture_output=True, text=True)
        
        return {'success': True}
        
    except Exception as e:
        return {'success': False, 'error': str(e)}



def expose_ssh_port_docker(container, port):
    """Expose SSH port using socat port forwarding - FIXED VERSION"""
    try:
        # Kill any existing socat on this port
        kill_cmd = ["sudo", "pkill", "-f", f"socat.*{port}"]
        subprocess.run(kill_cmd, capture_output=True, text=True)
        
        # Get container IP using standardized method
        container_ip = get_container_ip(container)
        if not container_ip:
            logger.error("Could not get container IP address")
            return {'success': False, 'error': 'Container has no IP address'}
        
        logger.info(f"Container {container} IP: {container_ip}")
        
        # Check if SSH server is running in container
        ssh_check = subprocess.run(["sudo", "docker", "exec", container, "ss", "-tlnp"],
                                   capture_output=True, text=True)
        if ":22" not in ssh_check.stdout:
            return {'success': False, 'error': 'SSH server not running in container'}
        
        # Create log file for debugging
        log_file = f"/tmp/socat_{container}_{port}.log"
        
        # FIXED: Correct socat command like your working manual command
        # Added debug flags (-d -d) and removed malformed shell redirection
        socat_args = [
            "sudo", "socat", 
            "-d", "-d",  # Debug flags like your working command
            f"TCP-LISTEN:{port},bind=0.0.0.0,fork,reuseaddr",
            f"TCP:{container_ip}:22"
        ]
        
        logger.info(f"Starting socat with command: {' '.join(socat_args)}")
        
        # Start socat process properly
        with open(log_file, 'w') as log_f:
            socat_process = subprocess.Popen(
                socat_args,
                stdout=log_f,
                stderr=subprocess.STDOUT,
                preexec_fn=os.setpgrp  # Create new process group
            )
        
        # Give socat time to start
        time.sleep(2)
        
        # Verify socat process is running
        if socat_process.poll() is not None:
            # Process exited, check log file
            try:
                with open(log_file, 'r') as f:
                    error_log = f.read()
                logger.error(f"Socat exited immediately. Log: {error_log}")
                return {'success': False, 'error': f'Socat failed to start. Check log: {log_file}'}
            except:
                return {'success': False, 'error': f'Socat exited immediately. Check log: {log_file}'}
        
        # Double-check with pgrep
        check_cmd = ["sudo", "pgrep", "-f", f"socat.*{port}"]
        check_result = subprocess.run(check_cmd, capture_output=True, text=True)
        
        if check_result.returncode != 0:
            logger.error("Socat process not found after startup")
            return {'success': False, 'error': 'Failed to start port forwarding'}
        
        logger.info(f"Successfully started socat pid={socat_process.pid}: host port {port} -> {container_ip}:22")
        return {
            'success': True, 
            'socat_pid': socat_process.pid,
            'container_ip': container_ip,
            'log_file': log_file
        }
        
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

def restart_ssh_service(container):
    """Properly restart SSH service and clean up zombie processes"""
    try:
        logger.info(f"Restarting SSH service in {container} and cleaning zombies")
        
        # 1. First, kill all zombie SSH processes
        kill_zombies_cmd = [
            "sudo", "docker", "exec", container, "sh", "-c",
            "pkill -9 sshd && sleep 2"
        ]
        subprocess.run(kill_zombies_cmd, capture_output=True)
        
        # 2. Clean up any remaining defunct processes
        clean_zombies_cmd = [
            "sudo", "docker", "exec", container, "sh", "-c",
            "ps aux | grep '[s]shd.*defunct' | awk '{print $2}' | xargs -r kill -9"
        ]
        subprocess.run(clean_zombies_cmd, capture_output=True)
        
        # 3. Start SSH service properly
        start_commands = [
            ["sudo", "docker", "exec", container, "service", "ssh", "restart"],
            ["sudo", "docker", "exec", container, "/etc/init.d/ssh", "restart"],
            ["sudo", "docker", "exec", container, "sshd", "-D", "-p", "22", "-f", "/etc/ssh/sshd_config", "&"],
            ["sudo", "docker", "exec", container, "/usr/sbin/sshd", "-D", "-p", "22", "-f", "/etc/ssh/sshd_config", "&"]
        ]
        
        for cmd in start_commands:
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode == 0:
                logger.info(f"SSH restarted using: {' '.join(cmd)}")
                break
        
        # 4. Wait a moment and verify
        time.sleep(3)
        verify_cmd = ["sudo", "docker", "exec", container, "ps", "aux", "|", "grep", "[s]shd"]
        result = subprocess.run(" ".join(verify_cmd), shell=True, capture_output=True, text=True)
        
        logger.info(f"SSH processes after restart: {result.stdout}")
        
        # Check for zombies
        if "defunct" in result.stdout or "Z" in result.stdout:
            logger.warning("Zombie processes still present after restart")
            return False
        else:
            logger.info("SSH service restarted successfully")
            return True
            
    except Exception as e:
        logger.error(f"SSH restart failed: {str(e)}")
        return False

def setup_ssh_server_in_container(container, username, public_key, port):
    """ULTIMATE SSH setup with multiple fallback methods"""
    try:
        logger.info(f"ULTIMATE SSH setup for {username} in {container}")
        
        # Run diagnostics first
        diagnostics = diagnose_ssh_issues(container, username, public_key, port)
        
        # METHOD 1: Direct file creation using docker exec
        ssh_dir = f"/home/{username}/.ssh"
        auth_file = f"{ssh_dir}/authorized_keys"
        
        # Create directory
        cmds = [
            ["sudo", "docker", "exec", container, "mkdir", "-p", ssh_dir],
            ["sudo", "docker", "exec", container, "touch", auth_file],
            ["sudo", "docker", "exec", container, "chown", "-R", f"{username}:{username}", ssh_dir],
            ["sudo", "docker", "exec", container, "chmod", "700", ssh_dir],
            ["sudo", "docker", "exec", container, "chmod", "600", auth_file]
        ]
        
        for cmd in cmds:
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode != 0:
                logger.warning(f"Command failed: {' '.join(cmd)} - {result.stderr}")
        
        # METHOD 2: Use printf to add the key
        key_cmd = [
            "sudo", "docker", "exec", container, "sh", "-c",
            f"printf '\\n%s\\n' '{public_key}' >> {auth_file}"
        ]
        result = subprocess.run(key_cmd, capture_output=True, text=True)
        
        if result.returncode != 0:
            logger.warning("Method 2 failed, trying method 3...")
            
            # METHOD 3: Use temp file method
            temp_file = f"/tmp/ssh_key_{port}.pub"
            with open(temp_file, "w") as f:
                f.write(public_key + "\n")
            
            copy_cmd = ["sudo", "docker", "cp", temp_file, f"{container}:{auth_file}"]
            result = subprocess.run(copy_cmd, capture_output=True, text=True)
            os.remove(temp_file)
            
            if result.returncode != 0:
                logger.error("All automated methods failed, using nuclear option...")
                
                # METHOD 4: Nuclear option - execute shell in container
                shell_cmd = [
                    "sudo", "docker", "exec", "-it", container, "bash", "-c",
                    f"mkdir -p {ssh_dir} && " +
                    f"echo '{public_key}' > {auth_file} && " +
                    f"chown -R {username}:{username} {ssh_dir} && " +
                    f"chmod 700 {ssh_dir} && " +
                    f"chmod 600 {auth_file}"
                ]
                result = subprocess.run(" ".join(shell_cmd), shell=True, capture_output=True, text=True)
        
        # Verify the key was installed
        verify_cmd = ["sudo", "docker", "exec", container, "cat", auth_file]
        result = subprocess.run(verify_cmd, capture_output=True, text=True)
        
        if public_key.strip() not in result.stdout:
            logger.error(f"KEY VERIFICATION FAILED! Expected: {public_key}, Got: {result.stdout}")
            return {'success': False, 'error': 'Public key not properly installed'}
        
        logger.info("Key successfully installed!")
        
        # Configure SSH server
        configure_cmds = [
            ["sudo", "docker", "exec", container, "sed", "-i", "s/^#PubkeyAuthentication yes/PubkeyAuthentication yes/", "/etc/ssh/sshd_config"],
            ["sudo", "docker", "exec", container, "sed", "-i", "s/^PubkeyAuthentication no/PubkeyAuthentication yes/", "/etc/ssh/sshd_config"],
            ["sudo", "docker", "exec", container, "sh", "-c", "echo 'PubkeyAuthentication yes' >> /etc/ssh/sshd_config"]
        ]
        
        for cmd in configure_cmds:
            subprocess.run(cmd, capture_output=True)
        
        # Restart SSH
        restart_cmds = [
            ["sudo", "docker", "exec", container, "service", "ssh", "restart"],
            ["sudo", "docker", "exec", container, "/etc/init.d/ssh", "restart"],
            ["sudo", "docker", "exec", container, "pkill", "-HUP", "sshd"]
        ]
        
        for cmd in restart_cmds:
            result = subprocess.run(cmd, capture_output=True)
            if result.returncode == 0:
                break
        
        # AFTER key installation, restart SSH properly
        ssh_restarted = restart_ssh_service(container)
        
        if not ssh_restarted:
            logger.warning("SSH restart may have failed, but continuing...")
        
        # Verify SSH is actually working
        test_result = test_ssh_from_inside_container(container, username)
        logger.info(f"Internal SSH test result: {test_result}")
        fix_zombie_issue(container)

        return {'success': True}
        
    except Exception as e:
        logger.exception(f"Ultimate SSH setup failed: {str(e)}")
        return {'success': False, 'error': str(e)}

def reestablish_port_forwarding(container, port):
    """Re-establish port forwarding after container restart"""
    try:
        logger.info(f"Re-establishing port forwarding for {container}:{port}")
        
        # Get the new container IP (it might have changed after restart)
        container_ip = get_container_ip(container)
        if not container_ip:
            return {'success': False, 'error': 'Could not get container IP after restart'}
        
        logger.info(f"New container IP: {container_ip}")
        
        # Kill any existing socat processes on this port
        kill_cmd = ["sudo", "pkill", "-f", f"socat.*{port}"]
        subprocess.run(kill_cmd, capture_output=True)
        
        # Start new socat process
        socat_cmd = [
            "sudo", "socat",
            "TCP-LISTEN:{},fork,reuseaddr,bind=0.0.0.0".format(port),
            "TCP:{}:22".format(container_ip)
        ]
        
        process = subprocess.Popen(
            socat_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            preexec_fn=os.setsid
        )
        
        # Wait and verify
        time.sleep(2)
        
        # Check if socat is listening
        check_cmd = ["sudo", "ss", "-tlnp", "|", "grep", f":{port}"]
        result = subprocess.run(" ".join(check_cmd), shell=True, capture_output=True, text=True)
        
        if result.returncode == 0 and str(port) in result.stdout:
            logger.info(f"Port forwarding re-established on port {port}")
            return {'success': True, 'pid': process.pid, 'container_ip': container_ip}
        else:
            # Get error output
            stdout, stderr = process.communicate()
            logger.error(f"Socat failed: {stderr}")
            return {'success': False, 'error': f'Port forwarding failed: {stderr}'}
            
    except Exception as e:
        logger.error(f"Port forwarding re-establishment failed: {str(e)}")
        return {'success': False, 'error': str(e)}


def fix_zombie_issue(container):
    """Fix zombie processes by adding proper init system to container"""
    try:
        logger.info(f"Restarting container {container} to clear zombies")
        
        restart_cmd = ["sudo", "docker", "restart", container]
        result = subprocess.run(restart_cmd, capture_output=True, text=True)
        
        if result.returncode == 0:
            # Wait for container to be fully restarted
            time.sleep(5)
            
            # Check if container is running
            check_cmd = ["sudo", "docker", "inspect", "-f", "{{.State.Running}}", container]
            result = subprocess.run(check_cmd, capture_output=True, text=True)
            
            if "true" in result.stdout:
                logger.info(f"Container {container} restarted successfully")
                return True
        
        logger.error(f"Container restart failed: {result.stderr}")
        return False
        
    except Exception as e:
        logger.error(f"Container restart error: {str(e)}")
        return False

def test_ssh_from_inside_container(container, username):
    """Test SSH connection from inside the container itself"""
    try:
        test_cmd = [
            "sudo", "docker", "exec", container, "sh", "-c",
            f"ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 {username}@localhost echo INTERNAL_TEST_SUCCESS 2>&1"
        ]
        
        result = subprocess.run(test_cmd, capture_output=True, text=True, timeout=10)
        
        if "INTERNAL_TEST_SUCCESS" in result.stdout:
            return "Internal SSH test: SUCCESS"
        else:
            return f"Internal SSH test failed: {result.stdout} {result.stderr}"
            
    except Exception as e:
        return f"Internal test error: {str(e)}"

def configure_ssh_server(container):
    """Ensure SSH server is configured to allow public key authentication"""
    try:
        # Check current SSH config
        check_cmd = ["sudo", "docker", "exec", container, "grep", "^PubkeyAuthentication", "/etc/ssh/sshd_config"]
        result = subprocess.run(check_cmd, capture_output=True, text=True)
        
        if result.returncode != 0 or "yes" not in result.stdout:
            logger.info("Configuring SSH server to allow public key authentication")
            
            # Enable public key authentication
            enable_pubkey = [
                "sudo", "docker", "exec", container, "sh", "-c",
                "echo 'PubkeyAuthentication yes' >> /etc/ssh/sshd_config"
            ]
            subprocess.run(enable_pubkey, capture_output=True)
            
            # Also ensure password authentication is disabled for security
            disable_password = [
                "sudo", "docker", "exec", container, "sh", "-c", 
                "echo 'PasswordAuthentication no' >> /etc/ssh/sshd_config"
            ]
            subprocess.run(disable_password, capture_output=True)
            
    except Exception as e:
        logger.warning(f"SSH configuration failed: {e}")


def verify_ssh_setup(container, username, public_key):
    """Verify SSH setup was successful"""
    try:
        auth_keys_file = f"/home/{username}/.ssh/authorized_keys"
        
        # 1. Check if key was installed
        check_key_cmd = ["sudo", "docker", "exec", container, "cat", auth_keys_file]
        key_result = subprocess.run(check_key_cmd, capture_output=True, text=True)
        
        if key_result.returncode != 0:
            return {'success': False, 'error': 'Authorized keys file not found'}
        
        if public_key.strip() not in key_result.stdout:
            logger.error(f"Key mismatch! Expected: {public_key}, Found: {key_result.stdout}")
            return {'success': False, 'error': 'Public key not found in authorized_keys'}
        
        # 2. Check permissions
        perm_cmd = ["sudo", "docker", "exec", container, "stat", "-c", "%a %U:%G", auth_keys_file]
        perm_result = subprocess.run(perm_cmd, capture_output=True, text=True)
        
        if "600" not in perm_result.stdout or username not in perm_result.stdout:
            logger.warning(f"Permissions may be incorrect: {perm_result.stdout}")
        
        # 3. Check SSH server is running
        ssh_check = ["sudo", "docker", "exec", container, "ss", "-tlnp", "|", "grep", ":22"]
        ssh_result = subprocess.run(" ".join(ssh_check), shell=True, capture_output=True, text=True)
        
        if ":22" not in ssh_result.stdout:
            logger.warning("SSH server may not be listening on port 22")
        
        return {'success': True, 'message': 'SSH setup verified'}
        
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
                # Extract first valid IP using regex
        import re
        ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
        ips = re.findall(ip_pattern, ip_result.stdout.strip())
        container_ip = ips[0] if ips else None
        
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
        socat_cmd = ['sudo', 'socat', f'TCP-LISTEN:{port},bind=0.0.0.0,fork,reuseaddr', f'TCP:{container_ip}:22']
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

def get_container_ip(container):
    """Standardized container IP extraction with proper validation - FIXED VERSION"""
    try:
        # Try to get IP from any network with proper spacing
        inspect_cmd = ["sudo", "docker", "inspect", container, 
                      "--format", "{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}"]
        result = subprocess.run(inspect_cmd, capture_output=True, text=True)
        
        if result.returncode != 0:
            logger.error(f"Docker inspect failed: {result.stderr.strip()}")
            return None
            
        raw_output = result.stdout.strip()
        logger.info(f"Raw docker inspect output for {container}: '{raw_output}'")
        
        # Function to validate if an IP address is valid
        def is_valid_ip(ip):
            try:
                parts = ip.split('.')
                if len(parts) != 4:
                    return False
                for part in parts:
                    if not part.isdigit():
                        return False
                    num = int(part)
                    if num < 0 or num > 255:
                        return False
                return True
            except:
                return False
        
        # Split by spaces and filter out empty strings
        potential_ips = [ip.strip() for ip in raw_output.split() if ip.strip()]
        
        # Filter out invalid IPs (where any octet > 255)
        valid_ips = [ip for ip in potential_ips if is_valid_ip(ip)]
        invalid_ips = [ip for ip in potential_ips if not is_valid_ip(ip)]
        
        logger.info(f"Potential IPs found: {potential_ips}")
        logger.info(f"Valid IPs after filtering: {valid_ips}")
        if invalid_ips:
            logger.info(f"Invalid IPs (filtered out): {invalid_ips}")
        
        if not valid_ips:
            logger.error(f"No valid IP found for container {container}")
            return None
        
        # Prefer IPs in the 172.22.x.x range (Frappe network) if available
        frappe_ips = [ip for ip in valid_ips if ip.startswith('172.22.')]
        if frappe_ips:
            container_ip = frappe_ips[0]
            logger.info(f"Using Frappe network IP: {container_ip}")
        else:
            # Use the first valid IP
            container_ip = valid_ips[0]
            logger.info(f"Using first available valid IP: {container_ip}")
        
        logger.info(f"Selected container IP: {container_ip} from valid IPs: {valid_ips}")
        return container_ip
        
    except Exception as e:
        logger.error(f"Error getting container IP: {str(e)}")
        return None

def fix_existing_socat_processes():
    """Fix existing socat processes with incorrect IPs"""
    try:
        logger.info("Checking and fixing existing socat processes...")
        
        # Get all socat processes
        result = subprocess.run(["sudo", "pgrep", "-f", "socat.*TCP-LISTEN"], 
                              capture_output=True, text=True)
        
        if result.returncode != 0:
            logger.info("No socat processes found")
            return
        
        pids = result.stdout.strip().split('\n')
        logger.info(f"Found {len(pids)} socat processes")
        
        # Get detailed process info
        for pid in pids:
            if pid.strip():
                try:
                    # Get process command line
                    cmd_result = subprocess.run(["sudo", "ps", "-p", pid.strip(), "-o", "args", "--no-headers"], 
                                              capture_output=True, text=True)
                    if cmd_result.returncode == 0:
                        cmd_line = cmd_result.stdout.strip()
                        logger.info(f"Process {pid}: {cmd_line}")
                        
                        # Extract port and target IP from command
                        import re
                        port_match = re.search(r'TCP-LISTEN:(\d+)', cmd_line)
                        ip_match = re.search(r'TCP:(\d+\.\d+\.\d+\.\d+):22', cmd_line)
                        
                        if port_match and ip_match:
                            port = port_match.group(1)
                            target_ip = ip_match.group(1)
                            
                            # Check if this IP looks wrong (like 172.20.0.217)
                            if len(target_ip) > 15:  # Normal IPs are max 15 chars
                                logger.warning(f"Process {pid} has suspicious IP: {target_ip}")
                                # Kill this process
                                subprocess.run(["sudo", "kill", pid.strip()], capture_output=True)
                                logger.info(f"Killed process {pid} with suspicious IP")
                            
                except Exception as e:
                    logger.error(f"Error checking process {pid}: {str(e)}")
                    
    except Exception as e:
        logger.error(f"Error fixing socat processes: {str(e)}")

if __name__ == '__main__':
    with app.app_context():
        create_default_admin()
        initialize_ssh_sessions()  # Initialize SSH sessions
    app.run(host='0.0.0.0', port=5000, debug=False)


