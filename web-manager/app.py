#!/usr/bin/env python3
"""
SECURE Web Docker Manager with Complete User Management System
"""

from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, session, Response
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import subprocess
import json
import re
import secrets
import time
import logging
from logging.handlers import RotatingFileHandler
import pyotp
import base64
import qrcode
import io
import os
import threading
import uuid
from datetime import datetime, timedelta
from config import Config
from models import db, User, AuditLog, create_default_admin




# SSH Manager imports
from ssh_routes import ssh_bp
from ssh_pages import ssh_pages_bp

app = Flask(__name__)

# Configure Flask for URL generation
app.config['SERVER_NAME'] = 'localhost:5000'
app.config['APPLICATION_ROOT'] = '/'
app.config['PREFERRED_URL_SCHEME'] = 'http'
app.config.from_object(Config)

# Initialize database
db.init_app(app)

# Register SSH blueprints
app.register_blueprint(ssh_bp)
app.register_blueprint(ssh_pages_bp)


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

# Global dictionary to store site creation tasks status
site_creation_tasks = {}

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
handler = RotatingFileHandler('docker-manager.log', maxBytes=10000000, backupCount=5)
handler.setFormatter(logging.Formatter(
    '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
))
app.logger.addHandler(handler)

def format_command_output(output, error="", command_type="general"):
    """
    Universal function to format command output in a professional and pretty way
    
    Args:
        output (str): The command output
        error (str): Any error messages
        command_type (str): Type of command (bench, docker, general, etc.)
    
    Returns:
        dict: Formatted output with professional styling
    """
    
    def format_ls_output(text):
        """Format ls command output with beautiful styling"""
        lines = text.split('\n')
        formatted_lines = []
        
        for line in lines:
            line = line.strip()
            if not line:
                formatted_lines.append("")
                continue
            
            # Handle total line
            if line.startswith('total '):
                formatted_lines.append(f"📊 <strong style='color: #6c757d;'>{line}</strong>")
                formatted_lines.append("")  # Add blank line after total
            
            # Handle directory entries (lines with permissions)
            elif len(line) > 10 and line[0] in 'd' and line[1:10].replace('-', '').replace('r', '').replace('w', '').replace('x', '') == '':
                parts = line.split()
                if len(parts) >= 9:
                    permissions = parts[0]
                    links = parts[1]
                    owner = parts[2]
                    group = parts[3]
                    size = parts[4]
                    date_parts = parts[5:8]
                    name = ' '.join(parts[8:])
                    
                    # Format permissions with colors
                    perm_colors = ""
                    if permissions.startswith('d'):
                        perm_colors = "color: #007bff;"  # Blue for directories
                        icon = "📁"
                    elif permissions.startswith('l'):
                        perm_colors = "color: #28a745;"  # Green for links
                        icon = "🔗"
                    elif permissions[3] == 'x' or permissions[6] == 'x' or permissions[9] == 'x':
                        perm_colors = "color: #dc3545;"  # Red for executables
                        icon = "⚡"
                    else:
                        perm_colors = "color: #6c757d;"  # Gray for files
                        icon = "📄"
                    
                    # Format date
                    date_str = ' '.join(date_parts)
                    
                    # Create formatted line
                    formatted_line = f"{icon} <span style='{perm_colors}'>{permissions}</span> {links:>3} {owner:<8} {group:<8} {size:>8} {date_str} <strong>{name}</strong>"
                    formatted_lines.append(formatted_line)
                else:
                    formatted_lines.append(line)
            
            # Handle other lines
            else:
                formatted_lines.append(line)
        
        return '\n'.join(formatted_lines)
    
    def format_help_text(text):
        """Format help text with proper indentation and styling"""
        lines = text.split('\n')
        formatted_lines = []
        
        for line in lines:
            line = line.strip()
            if not line:
                formatted_lines.append("")
                continue
                
            # Format usage lines
            if line.startswith('Usage:'):
                formatted_lines.append(f"📋 <strong>{line}</strong>")
            
            # Format error lines
            elif line.startswith('Error:'):
                formatted_lines.append(f"❌ <span style='color: #dc3545;'>{line}</span>")
            
            # Format warning lines
            elif line.startswith('Warning:') or line.startswith('WARNING:'):
                formatted_lines.append(f"⚠️ <span style='color: #ffc107;'>{line}</span>")
            
            # Format success lines
            elif line.startswith('Success:') or line.startswith('SUCCESS:'):
                formatted_lines.append(f"✅ <span style='color: #28a745;'>{line}</span>")
            
            # Format info lines
            elif line.startswith('Info:') or line.startswith('INFO:'):
                formatted_lines.append(f"ℹ️ <span style='color: #17a2b8;'>{line}</span>")
            
            # Format command options (lines starting with spaces or dashes)
            elif line.startswith('  ') or line.startswith('-') or line.startswith('--'):
                formatted_lines.append(f"<span style='color: #6c757d; font-family: monospace;'>{line}</span>")
            
            # Format section headers (lines in caps or with colons)
            elif line.isupper() or line.endswith(':'):
                formatted_lines.append(f"<strong style='color: #495057;'>{line}</strong>")
            
            # Format regular lines
            else:
                formatted_lines.append(line)
        
        return '\n'.join(formatted_lines)
    
    def format_bench_output(text):
        """Format bench command output specifically"""
        lines = text.split('\n')
        formatted_lines = []
        
        for line in lines:
            line = line.strip()
            if not line:
                formatted_lines.append("")
                continue
            
            # Format site information
            if 'site:' in line.lower() or 'sites:' in line.lower():
                formatted_lines.append(f"🏢 {line}")
            
            # Format app information
            elif 'app:' in line.lower() or 'apps:' in line.lower():
                formatted_lines.append(f"📦 {line}")
            
            # Format status information
            elif 'status:' in line.lower() or 'running' in line.lower():
                formatted_lines.append(f"🔄 {line}")
            
            # Format version information
            elif 'version:' in line.lower():
                formatted_lines.append(f"🔢 {line}")
            
            # Format path information
            elif 'path:' in line.lower() or 'directory:' in line.lower():
                formatted_lines.append(f"📁 {line}")
            
            # Format error messages
            elif 'error:' in line.lower() or 'failed' in line.lower():
                formatted_lines.append(f"❌ <span style='color: #dc3545;'>{line}</span>")
            
            # Format success messages
            elif 'success' in line.lower() or 'completed' in line.lower():
                formatted_lines.append(f"✅ <span style='color: #28a745;'>{line}</span>")
            
            # Format regular lines
            else:
                formatted_lines.append(line)
        
        return '\n'.join(formatted_lines)
    
    def format_docker_output(text):
        """Format docker command output specifically"""
        lines = text.split('\n')
        formatted_lines = []
        
        for line in lines:
            line = line.strip()
            if not line:
                formatted_lines.append("")
                continue
            
            # Format container information
            if 'container' in line.lower() and ('running' in line.lower() or 'stopped' in line.lower()):
                formatted_lines.append(f"🐳 {line}")
            
            # Format image information
            elif 'image' in line.lower():
                formatted_lines.append(f"📦 {line}")
            
            # Format network information
            elif 'network' in line.lower():
                formatted_lines.append(f"🌐 {line}")
            
            # Format volume information
            elif 'volume' in line.lower():
                formatted_lines.append(f"💾 {line}")
            
            # Format regular lines
            else:
                formatted_lines.append(line)
        
        return '\n'.join(formatted_lines)
    
    def format_filesystem_output(text):
        """Format filesystem commands (ls, find, etc.) with beautiful styling"""
        lines = text.split('\n')
        formatted_lines = []
        
        for line in lines:
            line = line.strip()
            if not line:
                formatted_lines.append("")
                continue
            
            # Handle total line
            if line.startswith('total '):
                formatted_lines.append(f"📊 <strong style='color: #6c757d;'>{line}</strong>")
                formatted_lines.append("")  # Add blank line after total
            
            # Handle directory entries (lines with permissions)
            elif len(line) > 10 and line[0] in 'd' and line[1:10].replace('-', '').replace('r', '').replace('w', '').replace('x', '') == '':
                parts = line.split()
                if len(parts) >= 9:
                    permissions = parts[0]
                    links = parts[1]
                    owner = parts[2]
                    group = parts[3]
                    size = parts[4]
                    date_parts = parts[5:8]
                    name = ' '.join(parts[8:])
                    
                    # Format permissions with colors
                    perm_colors = ""
                    if permissions.startswith('d'):
                        perm_colors = "color: #007bff;"  # Blue for directories
                        icon = "📁"
                    elif permissions.startswith('l'):
                        perm_colors = "color: #28a745;"  # Green for links
                        icon = "🔗"
                    elif permissions[3] == 'x' or permissions[6] == 'x' or permissions[9] == 'x':
                        perm_colors = "color: #dc3545;"  # Red for executables
                        icon = "⚡"
                    else:
                        perm_colors = "color: #6c757d;"  # Gray for files
                        icon = "📄"
                    
                    # Format date
                    date_str = ' '.join(date_parts)
                    
                    # Create formatted line with proper spacing
                    formatted_line = f"{icon} <span style='{perm_colors}'>{permissions}</span> {links:>3} {owner:<8} {group:<8} {size:>8} {date_str} <strong>{name}</strong>"
                    formatted_lines.append(formatted_line)
                else:
                    formatted_lines.append(line)
            
            # Handle other lines
            else:
                formatted_lines.append(line)
        
        return '\n'.join(formatted_lines)
    
    # Format the output based on command type
    if command_type.lower() == 'bench':
        formatted_output = format_bench_output(output)
    elif command_type.lower() == 'docker':
        formatted_output = format_docker_output(output)
    elif command_type.lower() in ['ls', 'filesystem', 'find']:
        formatted_output = format_filesystem_output(output)
    else:
        formatted_output = format_help_text(output)
    
    # Format error messages
    formatted_error = ""
    if error:
        formatted_error = format_help_text(error)
    
    # Create the final formatted response
    result = {
        'formatted_output': formatted_output,
        'formatted_error': formatted_error,
        'raw_output': output,
        'raw_error': error,
        'command_type': command_type
    }
    
    return result

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

def check_database_connectivity(container):
    """Check if database is accessible for bench commands"""
    try:
        # Try to connect to database using TCP connection test
        cmd = ["sudo", "docker", "exec", container, "bash", "-c", "timeout 5 bash -c '</dev/tcp/db/3306' && echo 'connected' || echo 'failed'"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        return "connected" in result.stdout
    except:
        return False
    
def log_command_execution(command, container, success, error_message=None):
    """Helper function to log command execution"""
    username = session.get('username', 'unknown')
    status = 'success' if success else 'failed'
    message = f"Executed command '{command}' in container {container}"
    if error_message:
        message += f" - Error: {error_message}"
    
    log_entry = AuditLog(
        user_id=session.get('user_id'),
        username=username,
        ip_address=request.remote_addr,
        event_type='command_execution',
        message=message,
        status=status
    )
    db.session.add(log_entry)
    db.session.commit()


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
            
            # Get the current working directory dynamically
            current_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            
            result = subprocess.run(
                cmd, 
                shell=True, 
                capture_output=True, 
                text=True, 
                timeout=timeout,
                cwd=current_dir
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
        result = SecureDockerManager.run_command(cmd, timeout=60)
        
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
        result = SecureDockerManager.run_command(cmd, timeout=60)
        
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
        result = SecureDockerManager.run_command(cmd, timeout=60)
        
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

@require_auth
@app.route('/api/frappe/execute-command', methods=['POST'])
@require_auth
def execute_command_api():
    """UNIVERSAL TERMINAL - Execute ANY command in ANY container"""
    try:
        # Initialize variables
        output = ''
        error = ''
        
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
                    if target_dir == '..' or target_dir == '../':
                        # Go up one directory - improved logic
                        parts = current_dir.rstrip('/').split('/')
                        if len(parts) > 1:
                            current_dir = '/'.join(parts[:-1]) or '/'
                        else:
                            current_dir = '/'
                    elif target_dir == '.' or target_dir == './':
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
            
            # First check if the file exists (improved logic)
            check_cmd = ["sudo", "docker", "exec", "-u", "root", container, "bash", "-c", f"cd {current_dir} && ls {file_pattern} 2>/dev/null"]
            process = subprocess.Popen(check_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = process.communicate()
            
            # If ls command failed or returned empty, file doesn't exist
            if process.returncode != 0 or not stdout.decode().strip():
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
        if command.lower().startswith('bench '):
            try:
                process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1, universal_newlines=True)
                
                # Set timeout for bench commands
                timeout_seconds = 60
                
                # Special handling for bench migrate command
                if command.lower().strip() == 'bench migrate':
                    output_lines = []
                    current_app = None
                    last_progress = 0
                    
                    while True:
                        line = process.stdout.readline()
                        if not line:
                            break
                        
                        line = line.rstrip()
                        
                        # Extract meaningful information from migrate output
                        if 'Migrating' in line and 'local' in line:
                            # Extract site name
                            site_name = line.split('Migrating ')[1].split('\n')[0]
                            output_lines.append(f"🔄 Starting migration for site: {site_name}")
                        
                        elif 'Updating DocTypes for' in line and '%' in line:
                            # Extract app name and progress
                            parts = line.split('Updating DocTypes for ')
                            if len(parts) > 1:
                                app_part = parts[1].split(' : ')[0]
                                progress_part = parts[1].split(' : ')[1] if ' : ' in parts[1] else ''
                                
                                # Extract percentage
                                if '%' in progress_part:
                                    percent = progress_part.split('%')[0].split()[-1]
                                    try:
                                        percent_int = int(percent)
                                        # Only show progress every 10% to reduce noise
                                        if percent_int >= last_progress + 10:
                                            output_lines.append(f"📊 Updating DocTypes for {app_part}: {percent_int}%")
                                            last_progress = percent_int
                                    except ValueError:
                                        pass
                        
                        elif 'Updating Dashboard for' in line:
                            app_name = line.split('Updating Dashboard for ')[1]
                            output_lines.append(f"📈 Updating Dashboard for {app_name}")
                        
                        elif 'Updating customizations for' in line:
                            doctype = line.split('Updating customizations for ')[1]
                            output_lines.append(f"🔧 Updating customizations for {doctype}")
                        
                        elif 'Executing `after_migrate` hooks' in line:
                            output_lines.append("⚡ Executing post-migration hooks...")
                        
                        elif 'Queued rebuilding of search index' in line:
                            site_name = line.split('Queued rebuilding of search index for ')[1]
                            output_lines.append(f"🔍 Queued search index rebuild for {site_name}")
                        
                        elif line.strip() and not any(x in line for x in ['[', ']', '=']):
                            # Include other important lines that aren't progress bars
                            output_lines.append(line)
                    
                    # Get final output
                    output = '\n'.join(output_lines)
                    error = ""
                    
                    # Check if process completed successfully
                    process.wait()
                    if process.returncode != 0:
                        error = f"Migration failed with exit code {process.returncode}"
                    else:
                        # Add success message
                        output += "\n\n✅ Migration completed successfully!"
                
                else:
                    # For other bench commands, use the original approach
                    output_lines = []
                    while True:
                        line = process.stdout.readline()
                        if not line:
                            break
                        output_lines.append(line.rstrip())
                    
                    # Get final output
                    output = '\n'.join(output_lines)
                    error = ""
                    
                    # Check if process completed successfully
                    process.wait()
                    if process.returncode != 0:
                        error = f"Command failed with exit code {process.returncode}"
                        if 'bench get-app' in command and 'Aborted' in output:
                            error = error + "\n💡 Tip: Use 'bench get-app app_name --overwrite' to overwrite existing apps"
                
                # Log command execution
                log_command_execution(command, container, process.returncode == 0, error if process.returncode != 0 else None)
                
                # Detect command type for better formatting
                command_type = "general"
                if command.lower().startswith('bench '):
                    command_type = "bench"
                elif command.lower().startswith('docker '):
                    command_type = "docker"
                elif command.lower().startswith('ls ') or command.lower() == 'ls' or command.lower().startswith('find '):
                    command_type = "filesystem"
                
                formatted_output = format_command_output(output, error, command_type)
                
                return jsonify({
                    'output': formatted_output['formatted_output'],
                    'error': formatted_output['formatted_error'],
                    'current_dir': current_dir,
                    'is_streaming': True,
                    'stream_command': command
                })
                
            except Exception as e:
                return jsonify({
                    'error': f'Error executing command: {str(e)}',
                    'current_dir': current_dir
                })
        else:
            # For regular commands, use the original approach
            timeout_seconds = 30
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
        log_command_execution(command, container, True, None)
        
        # Detect command type for better formatting
        command_type = "general"
        if command.lower().startswith('bench '):
            command_type = "bench"
        elif command.lower().startswith('docker '):
            command_type = "docker"
        elif command.lower().startswith('ls ') or command.lower() == 'ls' or command.lower().startswith('find '):
            command_type = "filesystem"
        
        formatted_output = format_command_output(output, error, command_type)
        
        return jsonify({
            'output': formatted_output['formatted_output'],
            'current_dir': current_dir
        })
    except Exception as e:
        logger.error(f"Error executing command: {str(e)}")
        return jsonify({'error': str(e)})



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



# Backward compatibility routes for old SSH endpoints
@app.route('/api/temp-ssh/setup', methods=['POST'])
@require_auth
def temp_ssh_setup_compat():
    """Backward compatibility for /api/temp-ssh/setup"""
    from ssh_manager import ssh_manager
    data = request.json
    container = data.get('container')
    username = data.get('username', 'frappe')
    duration = int(data.get('duration', 24))
    port = data.get('port')
    description = data.get('description', '')
    
    result = ssh_manager.create_ssh_session(container, username, duration, port, description)
    return jsonify(result)

@app.route('/api/temp-ssh/sessions')
@require_auth
def temp_ssh_sessions_compat():
    """Backward compatibility for /api/temp-ssh/sessions"""
    from ssh_manager import ssh_manager
    sessions = ssh_manager.get_ssh_sessions()
    return jsonify({'success': True, 'sessions': sessions})

@app.route('/api/temp-ssh/download-key/<session_id>')
@require_auth
def temp_ssh_download_key_compat(session_id):
    """Backward compatibility for /api/temp-ssh/download-key/<session_id>"""
    from ssh_manager import ssh_manager
    private_key = ssh_manager.get_session_private_key(session_id)
    if not private_key:
        return jsonify({'error': 'Session not found'}), 404
    
    return Response(private_key, mimetype='application/octet-stream',
                   headers={'Content-Disposition': f'attachment; filename=ssh_key_{session_id[:8]}.pem'})

@app.route('/api/temp-ssh/status/<container>')
@require_auth
def temp_ssh_status_compat(container):
    """Backward compatibility for /api/temp-ssh/status/<container>"""
    import subprocess
    cmd = ["sudo", "docker", "exec", container, "pgrep", "sshd"]
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()
    
    if process.returncode == 0:
        status = 'SSH server is running'
    else:
        status = 'SSH server is not running'
    
    return jsonify({'success': True, 'status': status})

@app.route('/api/temp-ssh/revoke', methods=['POST'])
@require_auth
def temp_ssh_revoke_compat():
    """Backward compatibility for /api/temp-ssh/revoke"""
    from ssh_manager import ssh_manager
    data = request.json
    session_id = data.get('session_id')
    result = ssh_manager.revoke_ssh_session(session_id)
    return jsonify(result)

@app.route('/api/temp-ssh/extend', methods=['POST'])
@require_auth
def temp_ssh_extend_compat():
    """Backward compatibility for /api/temp-ssh/extend"""
    from ssh_manager import ssh_manager
    data = request.json
    session_id = data.get('session_id')
    duration = int(data.get('duration', 24))
    
    # Get session and create new one with extended duration
    sessions = ssh_manager.get_ssh_sessions()
    session_info = next((s for s in sessions if s['session_id'] == session_id), None)
    
    if not session_info:
        return jsonify({'success': False, 'error': 'Session not found'}), 404
    
    # Create new session with extended duration
    result = ssh_manager.create_ssh_session(
        session_info['container'], session_info['username'], duration, 
        session_info['port'], f"{session_info['description']} (Extended)"
    )
    
    # Revoke old session
    ssh_manager.revoke_ssh_session(session_id)
    
    return jsonify(result)


# Terminal Logs API endpoints
@app.route('/api/frappe/terminal-logs', methods=['GET'])
@require_auth
def get_terminal_logs():
    """Get terminal error logs from audit logs"""
    try:
        # Get terminal error logs from audit logs
        logs = AuditLog.query.filter(
            AuditLog.event_type == 'command_execution',
            AuditLog.status == 'failed'
        ).order_by(AuditLog.timestamp.desc()).limit(100).all()
        
        # Format logs for frontend
        formatted_logs = []
        for log in logs:
            # Parse the message to extract command and container
            message = log.message or ''
            command = 'Unknown'
            container = 'Unknown'
            
            # Extract command and container from message
            if 'Executed command' in message and 'in container' in message:
                try:
                    # Format: "Executed command 'command' in container container_name" or "Executed command "command" in container container_name"
                    parts = message.split("'")
                    if len(parts) >= 2:
                        command = parts[1]
                    container_part = message.split("in container ")[-1].split(" - Error:")[0] if "in container " in message else "Unknown"
                    container = container_part.strip()
                except:
                    pass
            
            formatted_logs.append({
                'id': log.id,
                'timestamp': log.timestamp.isoformat() if log.timestamp else None,
                'container': container,
                'command': command,
                'error': log.message or 'Command execution failed',
                'exit_code': 1,  # Default for failed commands
                'username': log.username or 'Unknown',
                'ip_address': log.ip_address or 'Unknown',
                'full_error': log.message or ''  # Full error message for Terminal Logs
            })
        
        return jsonify({
            'success': True,
            'logs': formatted_logs,
            'count': len(formatted_logs)
        })
        
    except Exception as e:
        logger.error(f"Error getting terminal logs: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e),
            'logs': [],
            'count': 0
        })

@app.route('/api/frappe/clear-terminal-logs', methods=['POST'])
@require_auth
def clear_terminal_logs():
    """Clear terminal error logs"""
    try:
        # Delete terminal error logs from audit logs
        deleted_count = AuditLog.query.filter(
            AuditLog.event_type == 'command_execution',
            AuditLog.status == 'failed'
        ).delete()
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': f'Cleared {deleted_count} terminal error logs',
            'deleted_count': deleted_count
        })
        
    except Exception as e:
        logger.error(f"Error clearing terminal logs: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        })

# Backup and Restore API Endpoints
@app.route('/api/frappe/backup/create', methods=['POST'])
@require_auth
def create_backup():
    """Create a backup of a Frappe site"""
    try:
        data = request.json
        container = data.get('container')
        site_name = data.get('site_name')
        include_files = data.get('include_files', True)
        include_private_files = data.get('include_private_files', True)
        include_public_files = data.get('include_public_files', True)
        
        if not container or not site_name:
            return jsonify({'error': 'Container and site_name are required'}), 400
        
        # Build the bench backup command
        backup_command = f"bench --site {site_name} backup"
        
        if include_files:
            if include_private_files and include_public_files:
                backup_command += " --with-files"
            elif include_private_files:
                backup_command += " --with-private-files"
            elif include_public_files:
                backup_command += " --with-public-files"
        
        # Execute the backup command
        cmd = ["sudo", "docker", "exec", container, "bash", "-c", backup_command]
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        
        output_lines = []
        while True:
            line = process.stdout.readline()
            if not line:
                break
            output_lines.append(line.rstrip())
        
        process.wait()
        output = '\n'.join(output_lines)
        
        if process.returncode == 0:
            # Get the backup file paths from output
            backup_info = {
                'database': None,
                'private_files': None,
                'public_files': None
            }
            
            for line in output_lines:
                if 'database' in line.lower() and ('.sql' in line or '.gz' in line):
                    # Extract backup file path
                    import re
                    path_match = re.search(r'/home/frappe/frappe-bench/sites/[^\s]+\.(sql\.gz|sql)', line)
                    if path_match:
                        backup_info['database'] = path_match.group(0)
                elif 'private' in line.lower() and '.tar' in line:
                    path_match = re.search(r'/home/frappe/frappe-bench/sites/[^\s]+\.tar', line)
                    if path_match:
                        backup_info['private_files'] = path_match.group(0)
                elif 'public' in line.lower() and '.tar' in line:
                    path_match = re.search(r'/home/frappe/frappe-bench/sites/[^\s]+\.tar', line)
                    if path_match:
                        backup_info['public_files'] = path_match.group(0)
            
            log_command_execution(backup_command, container, True, None)
            
            return jsonify({
                'success': True,
                'output': output,
                'backup_info': backup_info,
                'message': 'Backup created successfully'
            })
        else:
            log_command_execution(backup_command, container, False, output)
            return jsonify({
                'error': output or 'Backup failed',
                'success': False
            }), 500
            
    except Exception as e:
        logger.error(f"Error creating backup: {str(e)}")
        return jsonify({'error': str(e), 'success': False}), 500

@app.route('/api/frappe/backup/list', methods=['POST'])
@require_auth
def list_backups():
    """List all available backups for a site"""
    try:
        data = request.json
        container = data.get('container')
        site_name = data.get('site_name')
        
        if not container or not site_name:
            return jsonify({'error': 'Container and site_name are required'}), 400
        
        # List backups in the site's backup directory
        backup_dir = f"/home/frappe/frappe-bench/sites/{site_name}/private/backups"
        cmd = ["sudo", "docker", "exec", container, "bash", "-c", 
               f"ls -lth {backup_dir} | grep -E '(database|files|private-files|public-files)' || echo 'No backups found'"]
        
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, stderr = process.communicate()
        
        if process.returncode == 0:
            # Parse the backup list
            backups = []
            for line in stdout.strip().split('\n'):
                if line and not line.startswith('total') and 'No backups found' not in line:
                    parts = line.split()
                    if len(parts) >= 9:
                        filename = parts[-1]
                        size = parts[4]
                        date = ' '.join(parts[5:8])
                        
                        backup_type = 'database' if 'database' in filename else \
                                    'private_files' if 'private' in filename else \
                                    'public_files' if 'public' in filename else \
                                    'files' if 'files' in filename else 'unknown'
                        
                        backups.append({
                            'filename': filename,
                            'size': size,
                            'date': date,
                            'type': backup_type,
                            'path': f"{backup_dir}/{filename}"
                        })
            
            return jsonify({
                'success': True,
                'backups': backups,
                'count': len(backups)
            })
        else:
            return jsonify({
                'error': stderr or 'Failed to list backups',
                'success': False
            }), 500
            
    except Exception as e:
        logger.error(f"Error listing backups: {str(e)}")
        return jsonify({'error': str(e), 'success': False}), 500

@app.route('/api/frappe/backup/restore', methods=['POST'])
@require_auth
def restore_backup():
    """Restore a backup for a Frappe site"""
    try:
        data = request.json
        container = data.get('container')
        site_name = data.get('site_name')
        backup_path = data.get('backup_path')  # Path to database backup
        private_files_path = data.get('private_files_path')
        public_files_path = data.get('public_files_path')
        mysql_root_password = data.get('mysql_root_password')
        admin_password = data.get('admin_password')
        
        if not container or not site_name or not backup_path:
            return jsonify({'error': 'Container, site_name, and backup_path are required'}), 400
        
        if not mysql_root_password:
            return jsonify({'error': 'MySQL root password is required'}), 400
        
        # Escape single quotes in password for shell safety
        escaped_password = mysql_root_password.replace("'", "'\\''")
        
        # Create a temporary MySQL config file with password to avoid prompts
        mysql_config_content = f"""[client]
user=root
password={escaped_password}
host=db
"""
        
        # Create the config file in the container
        create_config_cmd = f"cat > /tmp/mysql_restore.cnf << 'EOFMYSQL'\n{mysql_config_content}\nEOFMYSQL"
        cmd_create = ["sudo", "docker", "exec", container, "bash", "-c", create_config_cmd]
        subprocess.run(cmd_create, capture_output=True)
        
        # Build the restore command using the config file
        # Use --defaults-file to specify MySQL config with password
        restore_command = f"bench --site {site_name} --force restore {backup_path} --mariadb-root-password '{escaped_password}'"
        
        # Add file restore options
        restore_options = []
        if private_files_path:
            restore_options.append(f"--with-private-files {private_files_path}")
        if public_files_path:
            restore_options.append(f"--with-public-files {public_files_path}")
        
        if restore_options:
            restore_command += " " + " ".join(restore_options)
        
        # Add admin password option if provided
        if admin_password:
            escaped_admin_password = admin_password.replace("'", "'\\''")
            restore_command += f" --admin-password '{escaped_admin_password}'"
        
        # Execute the restore command
        cmd = ["sudo", "docker", "exec", container, "bash", "-c", restore_command]
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        
        output_lines = []
        while True:
            line = process.stdout.readline()
            if not line:
                break
            output_lines.append(line.rstrip())
        
        process.wait()
        output = '\n'.join(output_lines)
        
        # Clean up the temporary config file
        cleanup_cmd = ["sudo", "docker", "exec", container, "bash", "-c", "rm -f /tmp/mysql_restore.cnf"]
        subprocess.run(cleanup_cmd, capture_output=True)
        
        if process.returncode == 0:
            log_command_execution(f"bench restore (site: {site_name})", container, True, None)
            
            return jsonify({
                'success': True,
                'output': output,
                'message': 'Backup restored successfully'
            })
        else:
            log_command_execution(f"bench restore (site: {site_name})", container, False, output)
            return jsonify({
                'error': output or 'Restore failed',
                'success': False
            }), 500
            
    except Exception as e:
        logger.error(f"Error restoring backup: {str(e)}")
        return jsonify({'error': str(e), 'success': False}), 500

@app.route('/api/frappe/backup/download/<path:filename>', methods=['GET'])
@require_auth
def download_backup_file(filename):
    """Download a backup file directly"""
    try:
        # Security check - ensure filename doesn't contain path traversal
        if '..' in filename or '/' in filename:
            return jsonify({'error': 'Invalid filename'}), 400
        
        temp_path = f"/tmp/{filename}"
        
        if not os.path.exists(temp_path):
            return jsonify({'error': 'File not found'}), 404
        
        # Send file for download
        from flask import send_file
        return send_file(
            temp_path,
            as_attachment=True,
            download_name=filename,
            mimetype='application/octet-stream'
        )
            
    except Exception as e:
        logger.error(f"Error downloading backup file: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/frappe/backup/prepare-download', methods=['POST'])
@require_auth
def prepare_backup_download():
    """Prepare a backup file for download by copying from container to host"""
    try:
        data = request.json
        container = data.get('container')
        backup_path = data.get('backup_path')
        
        if not container or not backup_path:
            return jsonify({'error': 'Container and backup_path are required'}), 400
        
        # Get the backup file from container
        filename = os.path.basename(backup_path)
        temp_path = f"/tmp/{filename}"
        
        # Copy file from container to host
        cmd = ["sudo", "docker", "cp", f"{container}:{backup_path}", temp_path]
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()
        
        if process.returncode == 0:
            # Get file size
            file_size = os.path.getsize(temp_path)
            
            # Return the download URL
            return jsonify({
                'success': True,
                'download_url': f'/api/frappe/backup/download/{filename}',
                'filename': filename,
                'size': file_size,
                'message': 'Backup file ready for download'
            })
        else:
            return jsonify({
                'error': stderr.decode() or 'Failed to copy backup file',
                'success': False
            }), 500
            
    except Exception as e:
        logger.error(f"Error preparing backup download: {str(e)}")
        return jsonify({'error': str(e), 'success': False}), 500

@app.route('/api/frappe/backup/upload', methods=['POST'])
@require_auth
def upload_backup():
    """Upload a backup file from external source"""
    try:
        container = request.form.get('container')
        site_name = request.form.get('site_name')
        backup_type = request.form.get('backup_type')  # database, private_files, public_files
        
        if not container or not site_name or not backup_type:
            return jsonify({'error': 'Container, site_name, and backup_type are required'}), 400
        
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        # Validate file extension based on backup type
        allowed_extensions = {
            'database': ['.sql', '.sql.gz'],
            'private_files': ['.tar', '.tar.gz'],
            'public_files': ['.tar', '.tar.gz']
        }
        
        file_ext = os.path.splitext(file.filename)[1].lower()
        if backup_type == 'database' and not any(file.filename.endswith(ext) for ext in allowed_extensions['database']):
            return jsonify({'error': 'Invalid file type for database backup. Expected .sql or .sql.gz'}), 400
        elif backup_type in ['private_files', 'public_files'] and not any(file.filename.endswith(ext) for ext in allowed_extensions[backup_type]):
            return jsonify({'error': f'Invalid file type for {backup_type}. Expected .tar or .tar.gz'}), 400
        
        # Save file temporarily
        temp_filename = f"{secrets.token_hex(8)}_{file.filename}"
        temp_path = f"/tmp/{temp_filename}"
        file.save(temp_path)
        
        # Copy file to container's backup directory
        backup_dir = f"/home/frappe/frappe-bench/sites/{site_name}/private/backups"
        container_path = f"{backup_dir}/{file.filename}"
        
        # Create backup directory if it doesn't exist
        cmd_mkdir = ["sudo", "docker", "exec", container, "bash", "-c", f"mkdir -p {backup_dir}"]
        subprocess.run(cmd_mkdir, capture_output=True)
        
        # Copy file to container
        cmd_copy = ["sudo", "docker", "cp", temp_path, f"{container}:{container_path}"]
        process = subprocess.Popen(cmd_copy, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()
        
        # Clean up temp file
        os.remove(temp_path)
        
        if process.returncode == 0:
            log_command_execution(f"Uploaded backup {file.filename}", container, True, None)
            
            return jsonify({
                'success': True,
                'filename': file.filename,
                'container_path': container_path,
                'message': f'Backup file uploaded successfully to {site_name}'
            })
        else:
            log_command_execution(f"Failed to upload backup {file.filename}", container, False, stderr.decode())
            return jsonify({
                'error': stderr.decode() or 'Failed to copy file to container',
                'success': False
            }), 500
            
    except Exception as e:
        logger.error(f"Error uploading backup: {str(e)}")
        return jsonify({'error': str(e), 'success': False}), 500

@app.route('/api/frappe/backup/delete', methods=['POST'])
@require_auth
def delete_backup():
    """Delete a backup file"""
    try:
        data = request.json
        container = data.get('container')
        backup_path = data.get('backup_path')
        
        if not container or not backup_path:
            return jsonify({'error': 'Container and backup_path are required'}), 400
        
        # Delete the backup file
        cmd = ["sudo", "docker", "exec", container, "bash", "-c", f"rm -f {backup_path}"]
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()
        
        if process.returncode == 0:
            log_command_execution(f"rm -f {backup_path}", container, True, None)
            
            return jsonify({
                'success': True,
                'message': 'Backup deleted successfully'
            })
        else:
            log_command_execution(f"rm -f {backup_path}", container, False, stderr.decode())
            return jsonify({
                'error': stderr.decode() or 'Failed to delete backup',
                'success': False
            }), 500
            
    except Exception as e:
        logger.error(f"Error deleting backup: {str(e)}")
        return jsonify({'error': str(e), 'success': False}), 500

@app.route('/api/frappe/get-erpnext-versions', methods=['GET'])
@require_auth
def get_erpnext_versions():
    """Fetch available ERPNext versions from Docker Hub"""
    try:
        # Use curl to fetch versions from Docker Hub API
        cmd = [
            "curl", "-s", "--connect-timeout", "10", "--max-time", "30",
            "https://registry.hub.docker.com/v2/repositories/frappe/erpnext/tags?page_size=100"
        ]
        
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate(timeout=35)
        
        if process.returncode == 0:
            data = json.loads(stdout.decode())
            # Extract version tags that match pattern v[0-9]+.[0-9]+.[0-9]+
            versions = []
            for result in data.get('results', []):
                tag_name = result.get('name', '')
                if re.match(r'^v\d+\.\d+\.\d+$', tag_name):
                    versions.append(tag_name)
            
            # Sort versions in reverse order (newest first)
            versions.sort(reverse=True, key=lambda x: [int(n) for n in x[1:].split('.')])
            
            # Limit to top 50 versions
            versions = versions[:50]
            
            if versions:
                return jsonify({
                    'success': True,
                    'versions': versions,
                    'count': len(versions)
                })
            else:
                # Return fallback versions if API fails
                return jsonify({
                    'success': True,
                    'versions': [
                        'v15.80.1', 'v15.80.0', 'v15.79.2', 'v15.79.1', 'v15.79.0',
                        'v15.78.1', 'v15.78.0', 'v15.77.0', 'v15.76.0', 'v15.75.1',
                        'v14.73.0', 'v14.72.0', 'v14.71.0', 'v13.54.0'
                    ],
                    'count': 14,
                    'fallback': True
                })
        else:
            # Return fallback versions
            return jsonify({
                'success': True,
                'versions': [
                    'v15.80.1', 'v15.80.0', 'v15.79.2', 'v15.79.1', 'v15.79.0',
                    'v15.78.1', 'v15.78.0', 'v15.77.0', 'v15.76.0', 'v15.75.1',
                    'v14.73.0', 'v14.72.0', 'v14.71.0', 'v13.54.0'
                ],
                'count': 14,
                'fallback': True
            })
            
    except Exception as e:
        logger.error(f"Error fetching ERPNext versions: {str(e)}")
        # Return fallback versions on error
        return jsonify({
            'success': True,
            'versions': [
                'v15.80.1', 'v15.80.0', 'v15.79.2', 'v15.79.1', 'v15.79.0',
                'v15.78.1', 'v15.78.0', 'v15.77.0', 'v15.76.0', 'v15.75.1',
                'v14.73.0', 'v14.72.0', 'v14.71.0', 'v13.54.0'
            ],
            'count': 14,
            'fallback': True,
            'error': str(e)
        })

def clean_ansi_codes(text):
    """Remove all ANSI escape sequences and clean terminal output"""
    if not text:
        return text
    
    import re
    
    # Remove ANSI escape sequences
    text = re.sub(r'\x1b\[[0-9;]*m', '', text)  # Standard ANSI codes
    text = re.sub(r'\x1b\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]', '', text)  # Extended ANSI
    text = re.sub(r'\[[0-9;]*m', '', text)  # Bracket-only codes
    text = re.sub(r'\[0m', '', text)  # Reset codes
    text = re.sub(r'\[0;[0-9]+m', '', text)  # Color codes
    text = re.sub(r'\\033\[[0-9;]*m', '', text)  # Octal ANSI
    text = re.sub(r'\[([0-9]{1,2}(;[0-9]{1,2})?)m', '', text)  # Generic color
    text = re.sub(r'\[\d+[ABCD]', '', text)  # Cursor movement
    text = re.sub(r'\[2K', '', text)  # Clear line
    text = re.sub(r'\[1A', '', text)  # Move cursor up
    text = re.sub(r'\[2A', '', text)  # Move cursor up 2
    text = re.sub(r'\[1B', '', text)  # Move cursor down
    text = re.sub(r'\[2B', '', text)  # Move cursor down 2
    
    # Remove carriage returns and normalize line endings
    text = text.replace('\r\n', '\n').replace('\r', '')
    
    return text

def run_site_creation_task(task_id, domain_name, erpnext_version, environment, script_path, base_dir):
    """Background task to create a site"""
    try:
        # Extract site name from domain
        site_name = domain_name.split('.')[0]
        
        # Update task status
        site_creation_tasks[task_id]['status'] = 'running'
        site_creation_tasks[task_id]['progress'] = 10
        site_creation_tasks[task_id]['message'] = 'Starting site creation...'
        
        # Log the site creation attempt
        logger.info(f"Creating new site: {site_name} ({domain_name}) with ERPNext {erpnext_version} in {environment} environment")
        
        # Update progress
        site_creation_tasks[task_id]['progress'] = 20
        site_creation_tasks[task_id]['message'] = 'Creating expect automation script...'
        site_creation_tasks[task_id]['output'] = ''  # Initialize output
        
        # Create expect script to automate the interactive bash script
        expect_script = f"""#!/usr/bin/expect -f
set timeout 1800

# Enable output logging
log_user 1

spawn bash {script_path}

# Wait for version selection
expect "Select ERPNext version"
send "1\\r"

# Wait for Traefik setup question (local only)
expect {{
    "Choose an option" {{
        send "3\\r"
        exp_continue
    }}
    "Do you want to continue anyway?" {{
        send "y\\r"
        exp_continue
    }}
    "Enter site name" {{
        send "{domain_name}\\r"
    }}
}}

# Wait for docker manager question
expect "Do you want to access the docker-manager?"
send "n\\r"

expect eof
"""
        
        # Write expect script to temporary file
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', suffix='.exp', delete=False) as f:
            expect_file = f.name
            f.write(expect_script)
        
        try:
            # Make expect script executable
            os.chmod(expect_file, 0o755)
            
            # Update progress
            site_creation_tasks[task_id]['progress'] = 30
            site_creation_tasks[task_id]['message'] = 'Running site generation script...'
            
            # Execute expect script with real-time output capture
            cmd = ['expect', expect_file]
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,  # Merge stderr into stdout
                cwd=base_dir,
                text=True,
                bufsize=1,  # Line buffered
                universal_newlines=True
            )
            
            # Update progress while running
            site_creation_tasks[task_id]['progress'] = 50
            site_creation_tasks[task_id]['message'] = 'Installing Frappe/ERPNext... This may take 5-15 minutes...'
            
            # Read output line by line in real-time
            output_lines = []
            for line in iter(process.stdout.readline, ''):
                if line:
                    cleaned_line = clean_ansi_codes(line.rstrip())
                    output_lines.append(cleaned_line)
                    # Update task with latest output (keep last 100 lines for performance)
                    site_creation_tasks[task_id]['output'] = '\n'.join(output_lines[-100:])
                    
                    # Update progress based on output keywords
                    if 'Pulling' in line or 'Downloading' in line:
                        site_creation_tasks[task_id]['progress'] = 40
                        site_creation_tasks[task_id]['message'] = 'Downloading Docker images...'
                    elif 'Building' in line or 'Creating' in line:
                        site_creation_tasks[task_id]['progress'] = 60
                        site_creation_tasks[task_id]['message'] = 'Creating containers...'
                    elif 'Starting' in line or 'Started' in line:
                        site_creation_tasks[task_id]['progress'] = 75
                        site_creation_tasks[task_id]['message'] = 'Starting containers...'
            
            # Wait for process to complete
            process.wait()
            stdout = '\n'.join(output_lines)
            stderr = ''
            
            # Clean up expect script
            os.unlink(expect_file)
            
            # Update progress
            site_creation_tasks[task_id]['progress'] = 80
            site_creation_tasks[task_id]['message'] = 'Configuring containers...'
            
            # Construct the docker-compose directory path and access URL
            if environment == 'local':
                compose_dir = f"{base_dir}/{site_name}_local"
                # Extract port from output - look for various patterns
                port_match = re.search(r'(?:HTTP|http|Port|port).*?:?\s*(\d{4,5})', stdout)
                if not port_match:
                    # Try to extract from "localhost:" or ".local:" patterns
                    port_match = re.search(r'(?:localhost|\.local):(\d{4,5})', stdout)
                
                if port_match:
                    port = port_match.group(1)
                else:
                    port = '8080'  # Default fallback
                
                # Log the port detection for debugging
                logger.info(f"Detected port: {port} for site {site_name}")
                
                access_url = f"http://{domain_name}:{port}"
            else:
                compose_dir = f"{base_dir}/{site_name}"
                access_url = f"https://{domain_name}"
            
            # Check if directory was created
            if os.path.exists(compose_dir):
                # Extract essential credentials from script output
                credentials_dict = {
                    'username': None,
                    'password': None,
                    'mysql': None,
                    'redis': None
                }
                
                for line in stdout.split('\n'):
                    cleaned_line = clean_ansi_codes(line.strip())
                    if cleaned_line:
                        # Extract username
                        if ('username' in cleaned_line.lower() or 'default username' in cleaned_line.lower()) and not credentials_dict['username']:
                            match = re.search(r'(?:Username|username).*?:\s*(\w+)', cleaned_line)
                            if match:
                                credentials_dict['username'] = match.group(1)
                        
                        # Extract admin password
                        if ('password' in cleaned_line.lower() and 'mysql' not in cleaned_line.lower() and 'redis' not in cleaned_line.lower() and 'database' not in cleaned_line.lower()) and not credentials_dict['password']:
                            match = re.search(r'(?:Password|password).*?:\s*(\S+)', cleaned_line)
                            if match:
                                credentials_dict['password'] = match.group(1)
                        
                        # Extract MySQL password
                        if 'mysql' in cleaned_line.lower() and 'password' in cleaned_line.lower() and not credentials_dict['mysql']:
                            match = re.search(r':\s*([A-Za-z0-9]{20,})', cleaned_line)
                            if match:
                                credentials_dict['mysql'] = match.group(1)
                        
                        # Extract Redis password
                        if 'redis' in cleaned_line.lower() and 'password' in cleaned_line.lower() and not credentials_dict['redis']:
                            match = re.search(r':\s*([A-Za-z0-9]{20,})', cleaned_line)
                            if match:
                                credentials_dict['redis'] = match.group(1)
                
                # Build clean credentials info
                cred_parts = []
                if credentials_dict['username']:
                    cred_parts.append(f"👤 Username: {credentials_dict['username']}")
                if credentials_dict['password']:
                    cred_parts.append(f"🔑 Password: {credentials_dict['password']}")
                if credentials_dict['mysql']:
                    cred_parts.append(f"💾 MySQL Password: {credentials_dict['mysql']}")
                if credentials_dict['redis']:
                    cred_parts.append(f"💾 Redis Password: {credentials_dict['redis']}")
                
                credentials_info = '\n'.join(cred_parts) if cred_parts else f"""Site: {domain_name}
Access URL: {access_url}
Container Directory: {compose_dir}

Note: Check the output log below for generated passwords and credentials."""
                
                # Update task as completed
                site_creation_tasks[task_id]['status'] = 'completed'
                site_creation_tasks[task_id]['progress'] = 100
                site_creation_tasks[task_id]['message'] = 'Site created successfully!'
                site_creation_tasks[task_id]['result'] = {
                    'success': True,
                    'site_name': site_name,
                    'domain_name': domain_name,
                    'access_url': access_url,
                    'credentials': credentials_info,
                    'compose_directory': compose_dir,
                    'output': stdout
                }
            else:
                # Update task as failed
                site_creation_tasks[task_id]['status'] = 'failed'
                site_creation_tasks[task_id]['message'] = 'Site directory not created'
                site_creation_tasks[task_id]['result'] = {
                    'success': False,
                    'error': 'Site directory not created. Check output below.',
                    'output': stdout,
                    'stderr': stderr
                }
                
        except Exception as e:
            # Update task as failed
            site_creation_tasks[task_id]['status'] = 'failed'
            site_creation_tasks[task_id]['message'] = f'Error: {str(e)}'
            site_creation_tasks[task_id]['result'] = {
                'success': False,
                'error': str(e)
            }
        finally:
            # Ensure expect script is cleaned up
            if 'expect_file' in locals() and os.path.exists(expect_file):
                os.unlink(expect_file)
            
    except Exception as e:
        logger.error(f"Error in site creation task: {str(e)}")
        site_creation_tasks[task_id]['status'] = 'failed'
        site_creation_tasks[task_id]['message'] = f'Error: {str(e)}'
        site_creation_tasks[task_id]['result'] = {
            'success': False,
            'error': str(e)
        }

@app.route('/api/frappe/create-site', methods=['POST'])
@require_auth
def create_site():
    """Start site creation as a background task"""
    try:
        data = request.json
        domain_name = data.get('domain_name')
        erpnext_version = data.get('erpnext_version')
        environment = data.get('environment', 'local')
        
        # Validate required fields
        if not domain_name or not erpnext_version:
            return jsonify({'error': 'Domain name and ERPNext version are required', 'success': False}), 400
        
        # Extract site name from domain
        site_name = domain_name.split('.')[0]
        
        # Validate extracted site name format
        if not re.match(r'^[a-z0-9_-]+$', site_name):
            return jsonify({
                'error': f'Invalid domain name. Extracted site name "{site_name}" must contain only lowercase letters, numbers, underscores, and hyphens',
                'success': False
            }), 400
        
        # Determine script path based on environment (dynamic)
        # Get the project root (parent directory of web-manager)
        web_manager_dir = os.path.dirname(os.path.abspath(__file__))
        project_root = os.path.dirname(web_manager_dir)
        
        if environment == 'local':
            script_path = os.path.join(project_root, 'Docker-Local', 'generate_frappe_docker_local.sh')
            base_dir = os.path.join(project_root, 'Docker-Local')
        else:
            script_path = os.path.join(project_root, 'Docker-on-VPS', 'generate_frappe_docker.sh')
            base_dir = os.path.join(project_root, 'Docker-on-VPS')
        
        # Check if script exists
        if not os.path.exists(script_path):
            return jsonify({
                'error': f'Generation script not found: {script_path}',
                'success': False
            }), 404
        
        # Generate unique task ID
        task_id = str(uuid.uuid4())
        
        # Initialize task status
        site_creation_tasks[task_id] = {
            'status': 'pending',
            'progress': 0,
            'message': 'Task queued...',
            'site_name': site_name,
            'domain_name': domain_name,
            'environment': environment,
            'created_at': datetime.now().isoformat(),
            'result': None
        }
        
        # Start background thread
        thread = threading.Thread(
            target=run_site_creation_task,
            args=(task_id, domain_name, erpnext_version, environment, script_path, base_dir)
        )
        thread.daemon = True
        thread.start()
        
        # Return task ID immediately
        return jsonify({
            'success': True,
            'task_id': task_id,
            'message': 'Site creation started in background',
            'site_name': site_name,
            'domain_name': domain_name
        })
        
    except Exception as e:
        logger.error(f"Error starting site creation: {str(e)}")
        return jsonify({'error': str(e), 'success': False}), 500

@app.route('/api/frappe/create-site/status/<task_id>', methods=['GET'])
@require_auth
def get_site_creation_status(task_id):
    """Get the status of a site creation task"""
    if task_id not in site_creation_tasks:
        return jsonify({'error': 'Task not found', 'success': False}), 404
    
    return jsonify({
        'success': True,
        'task': site_creation_tasks[task_id]
    })

if __name__ == '__main__':
    with app.app_context():
        create_default_admin()
    app.run(host='0.0.0.0', port=5000, debug=False)





# Additional API endpoints for enhanced app management
def format_terminal_response(output, error="", command=""):
    """
    Format terminal response for web display with professional styling
    
    Args:
        output (str): Command output
        error (str): Error messages
        command (str): The command that was executed
    
    Returns:
        str: HTML formatted response
    """
    
    # Determine command type for better formatting
    command_type = "general"
    if command.lower().startswith('bench '):
        command_type = "bench"
    elif command.lower().startswith('docker '):
        command_type = "docker"
    
    # Get formatted output
    formatted = format_command_output(output, error, command_type)
    
    # Create HTML response
    html_response = f"""
    <div class="terminal-response">
        <div class="command-executed">
            <span class="prompt">$</span> <span class="command">{command}</span>
        </div>
    """
    
    if formatted['formatted_output']:
        html_response += f"""
        <div class="output-section">
            <pre class="output">{formatted['formatted_output']}</pre>
        </div>
        """
    
    if formatted['formatted_error']:
        html_response += f"""
        <div class="error-section">
            <pre class="error">{formatted['formatted_error']}</pre>
        </div>
        """
    
    html_response += "</div>"
    
    return html_response

