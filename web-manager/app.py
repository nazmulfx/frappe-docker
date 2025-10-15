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
import shlex
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
from models import db, User, AuditLog, Role, Permission, create_default_admin, init_rbac_system
from permissions import require_permission, require_any_permission, require_role, get_current_user, check_permission
from middleware import init_middleware




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

# Initialize RBAC Middleware - filters all requests through permission checking
init_middleware(app)

# Context processor to make CSRF token and user info available in all templates
@app.context_processor
def inject_csrf_token():
    try:
        return dict(csrf_token=session.get('csrf_token'))
    except RuntimeError:
        # No request context, return empty token
        return dict(csrf_token=None)

@app.context_processor
def inject_user_permissions():
    """Make current user and their permissions available in all templates"""
    try:
        current_user = get_current_user()
        if current_user:
            return {
                'current_user': current_user,
                'has_permission': lambda perm: current_user.has_permission(perm)
            }
        return {'current_user': None, 'has_permission': lambda perm: False}
    except:
        return {'current_user': None, 'has_permission': lambda perm: False}

# Rate limiting storage
login_attempts = {}

# Global variable to store current working directories for each container
container_working_dirs = {}
blocked_ips = {}

# Global dictionary to store site creation tasks status
site_creation_tasks = {}

# Global dictionary to store background tasks (backup, restore, migrate, etc.)
background_tasks = {}

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
    """Helper function to log command execution (thread-safe)"""
    from flask import has_request_context
    
    try:
        # Check if we're in a request context (not in background thread)
        if has_request_context():
            username = session.get('username', 'system')
            user_id = session.get('user_id')
            ip_address = request.remote_addr
        else:
            # Background thread - use system defaults
            username = 'system'
            user_id = None
            ip_address = '127.0.0.1'
        
        status = 'success' if success else 'failed'
        message = f"Executed command '{command}' in container {container}"
        if error_message:
            message += f" - Error: {error_message}"
        
        log_entry = AuditLog(
            user_id=user_id,
            username=username,
            ip_address=ip_address,
            event_type='command_execution',
            message=message,
            status=status
        )
        db.session.add(log_entry)
        db.session.commit()
    except Exception as e:
        # Don't fail the main operation if logging fails
        logger.error(f"Failed to log command execution: {str(e)}")


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
@require_permission('view_users')
def user_management():
    """User management panel"""
    users = User.query.all()
    roles = Role.query.all()
    permissions = Permission.query.all()
    
    # Check if current user can manage roles
    current_user = get_current_user()
    can_manage_roles = current_user.has_permission('manage_roles') if current_user else False
    
    return render_template('user_management.html', 
                         users=users, 
                         roles=roles, 
                         permissions=permissions,
                         can_manage_roles=can_manage_roles)

@app.route('/roles')
@require_auth
@require_permission('manage_roles')
def role_management():
    """Role and permission management panel"""
    roles = Role.query.all()
    permissions_objs = Permission.query.all()
    
    # Group permissions by category
    permissions = {}
    for perm in permissions_objs:
        category = perm.category or 'other'
        if category not in permissions:
            permissions[category] = []
        permissions[category].append(perm.to_dict())
    
    return render_template('role_management.html', 
                         roles=roles, 
                         permissions=permissions,
                         permissions_objs=permissions_objs)

@app.route('/api/users', methods=['POST'])
@require_auth
@require_permission('create_users')
@require_csrf
def create_user():
    """Create new user"""
    data = request.json
    username = data.get('username', '').strip()
    email = data.get('email', '').strip()
    password = data.get('password', '')
    is_admin = data.get('is_admin', False)
    role_ids = data.get('role_ids', [])
    
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
        is_active=data.get('is_active', True),  # Default to True if not specified
        totp_enabled=False  # 2FA disabled by default
    )
    user.set_password(password)
    
    db.session.add(user)
    db.session.flush()  # Flush to get user ID
    
    # Assign roles
    if role_ids:
        for role_id in role_ids:
            role = Role.query.get(role_id)
            if role:
                user.roles.append(role)
    else:
        # If no roles assigned and not admin, assign viewer role by default
        if not is_admin:
            viewer_role = Role.query.filter_by(name='viewer').first()
            if viewer_role:
                user.roles.append(viewer_role)
    
    # If user is admin, ensure they have admin role
    if is_admin:
        admin_role = Role.query.filter_by(name='admin').first()
        if admin_role and admin_role not in user.roles:
            user.roles.append(admin_role)
    
    db.session.commit()
    
    # Log user creation
    client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
    admin_username = session.get('username', 'unknown')
    role_names = [r.display_name for r in user.roles]
    log_audit("user_created", admin_username, client_ip, 
              f"Created user: {username} with roles: {', '.join(role_names) if role_names else 'None'}", 
              "success", session.get('user_id'))
    
    return jsonify({
        'success': True, 
        'message': 'User created successfully',
        'user': user.to_dict()
    })

@app.route('/api/users/<int:user_id>', methods=['PUT'])
@require_auth
@require_permission('edit_users')
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
    
    # Handle password update
    if 'password' in data and data['password']:
        new_password = data['password'].strip() if isinstance(data['password'], str) else data['password']
        if new_password:  # Only update if not empty after stripping
            if len(new_password) < 8:
                return jsonify({'success': False, 'message': 'Password must be at least 8 characters long'})
            user.set_password(new_password)
            logger.info(f"Password updated for user: {user.username}")
            # Log password change
            log_audit("password_changed", session.get('username', 'unknown'), 
                     request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr),
                     f"Password changed for user: {user.username}", "success", session.get('user_id'))
    
    if 'is_admin' in data:
        user.is_admin = data['is_admin']
    
    if 'is_active' in data:
        user.is_active = data['is_active']
    
    if 'totp_enabled' in data:
        user.totp_enabled = data['totp_enabled']
        # If disabling 2FA, clear the TOTP secret
        if not data['totp_enabled']:
            user.totp_secret = None
    
    db.session.commit()
    
    # Log user update
    client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
    admin_username = session.get('username', 'unknown')
    log_audit("user_updated", admin_username, client_ip, f"Updated user: {user.username}", "success", session.get('user_id'))
    
    return jsonify({'success': True, 'message': 'User updated successfully'})

@app.route('/api/users/<int:user_id>', methods=['DELETE'])
@require_auth
@require_permission('delete_users')
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
@require_permission('edit_users')
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

# Role Management Routes
@app.route('/api/roles', methods=['GET'])
@require_auth
@require_permission('manage_roles')
def get_roles():
    """Get all roles"""
    roles = Role.query.all()
    return jsonify({
        'success': True,
        'roles': [role.to_dict() for role in roles]
    })

@app.route('/api/permissions', methods=['GET'])
@require_auth
@require_permission('manage_roles')
def get_permissions():
    """Get all permissions"""
    permissions = Permission.query.all()
    # Group permissions by category
    grouped = {}
    for perm in permissions:
        category = perm.category or 'other'
        if category not in grouped:
            grouped[category] = []
        grouped[category].append(perm.to_dict())
    
    return jsonify({
        'success': True,
        'permissions': grouped
    })

@app.route('/api/users/<int:user_id>/roles', methods=['GET'])
@require_auth
@require_permission('view_users')
def get_user_roles(user_id):
    """Get user's roles and status"""
    user = User.query.get_or_404(user_id)
    return jsonify({
        'success': True,
        'roles': [role.to_dict() for role in user.roles],
        'permissions': [p.name for p in user.get_all_permissions()],
        'user': {
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'is_active': user.is_active,
            'totp_enabled': user.totp_enabled,
            'is_admin': user.is_admin
        }
    })

@app.route('/api/users/<int:user_id>/roles', methods=['POST'])
@require_auth
@require_permission('manage_roles')
@require_csrf
def assign_user_roles(user_id):
    """Assign roles to user"""
    user = User.query.get_or_404(user_id)
    data = request.json
    role_ids = data.get('role_ids', [])
    
    # Clear existing roles
    user.roles.clear()
    
    # Assign new roles
    for role_id in role_ids:
        role = Role.query.get(role_id)
        if role:
            user.roles.append(role)
    
    db.session.commit()
    
    # Log role assignment
    client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
    admin_username = session.get('username', 'unknown')
    role_names = [role.display_name for role in user.roles]
    log_audit("roles_assigned", admin_username, client_ip, 
              f"Assigned roles to {user.username}: {', '.join(role_names)}", 
              "success", session.get('user_id'))
    
    return jsonify({
        'success': True,
        'message': 'Roles assigned successfully',
        'roles': [role.to_dict() for role in user.roles]
    })

@app.route('/api/roles/<int:role_id>/permissions', methods=['POST'])
@require_auth
@require_permission('manage_roles')
@require_csrf
def update_role_permissions(role_id):
    """Update permissions for a role"""
    role = Role.query.get_or_404(role_id)
    
    # Prevent modifying system roles
    if role.is_system:
        return jsonify({
            'success': False,
            'message': 'Cannot modify system roles. Create a custom role instead.'
        }), 403
    
    data = request.json
    permission_ids = data.get('permission_ids', [])
    
    # Clear existing permissions
    role.permissions.clear()
    
    # Assign new permissions
    for perm_id in permission_ids:
        permission = Permission.query.get(perm_id)
        if permission:
            role.permissions.append(permission)
    
    db.session.commit()
    
    # Log permission update
    client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
    admin_username = session.get('username', 'unknown')
    log_audit("role_permissions_updated", admin_username, client_ip, 
              f"Updated permissions for role: {role.display_name}", 
              "success", session.get('user_id'))
    
    return jsonify({
        'success': True,
        'message': 'Role permissions updated successfully',
        'role': role.to_dict()
    })

@app.route('/api/roles', methods=['POST'])
@require_auth
@require_permission('manage_roles')
@require_csrf
def create_role():
    """Create a new custom role"""
    data = request.json
    name = data.get('name', '').strip().lower().replace(' ', '_')
    display_name = data.get('display_name', '').strip()
    description = data.get('description', '').strip()
    permission_ids = data.get('permission_ids', [])
    
    if not name or not display_name:
        return jsonify({
            'success': False,
            'message': 'Name and display name are required'
        }), 400
    
    # Check if role already exists
    if Role.query.filter_by(name=name).first():
        return jsonify({
            'success': False,
            'message': 'Role with this name already exists'
        }), 400
    
    # Create role
    role = Role(
        name=name,
        display_name=display_name,
        description=description,
        is_system=False
    )
    
    # Add permissions
    for perm_id in permission_ids:
        permission = Permission.query.get(perm_id)
        if permission:
            role.permissions.append(permission)
    
    db.session.add(role)
    db.session.commit()
    
    # Log role creation
    client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
    admin_username = session.get('username', 'unknown')
    log_audit("role_created", admin_username, client_ip, 
              f"Created role: {role.display_name}", 
              "success", session.get('user_id'))
    
    return jsonify({
        'success': True,
        'message': 'Role created successfully',
        'role': role.to_dict()
    })

@app.route('/api/roles/<int:role_id>', methods=['DELETE'])
@require_auth
@require_permission('manage_roles')
@require_csrf
def delete_role(role_id):
    """Delete a custom role"""
    role = Role.query.get_or_404(role_id)
    
    # Prevent deleting system roles
    if role.is_system:
        return jsonify({
            'success': False,
            'message': 'Cannot delete system roles'
        }), 403
    
    role_name = role.display_name
    db.session.delete(role)
    db.session.commit()
    
    # Log role deletion
    client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
    admin_username = session.get('username', 'unknown')
    log_audit("role_deleted", admin_username, client_ip, 
              f"Deleted role: {role_name}", 
              "success", session.get('user_id'))
    
    return jsonify({
        'success': True,
        'message': 'Role deleted successfully'
    })

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
    
    # Get base directory dynamically (parent of web-manager directory)
    import os
    web_manager_dir = os.path.dirname(os.path.abspath(__file__))
    base_dir = os.path.dirname(web_manager_dir)
    
    return render_template('app_installation.html', 
                         container_groups=formatted_container_groups,
                         base_dir=base_dir)

@require_auth
@app.route('/api/frappe/execute-command', methods=['POST'])
@require_auth
def execute_command_api():
    """
    SECURE TERMINAL - Execute validated commands with comprehensive security checks
    
    Security Features:
    - RBAC permission checking
    - Command whitelist/blacklist validation
    - Input sanitization
    - Container name validation
    - Path traversal protection
    - Audit logging
    - Rate limiting
    """
    try:
        from command_security import validate_command_security, command_validator
        from models import AuditLog, User, db
        
        # Initialize variables
        output = ''
        error = ''
        
        data = request.json
        container = data.get('container')
        command = data.get('command')
        current_dir = data.get('current_dir', '/home/frappe/frappe-bench')
        
        # Get current user info for audit
        user_id = session.get('user_id')
        username = session.get('username', 'unknown')
        client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
        
        # Basic input validation
        if not container:
            return jsonify({'error': 'Container name is required'}), 400
        
        if not command:
            return jsonify({'error': 'Command is required'}), 400
        
        # Get user object for permission checking
        user = User.query.get(user_id) if user_id else None
        if not user:
            logger.error(f"User not found for command execution: {user_id}")
            return jsonify({'error': 'User not found'}), 401
        
        # Check if user has execute_commands permission
        has_execute_permission = user.has_permission('execute_commands')
        has_privileged_permission = user.has_permission('execute_privileged_commands')
        
        if not has_execute_permission:
            # Log unauthorized attempt
            try:
                audit_log = AuditLog(
                    user_id=user_id,
                    username=username,
                    ip_address=client_ip,
                    event_type='command_execution_denied',
                    message=f'Unauthorized command execution attempt: {command[:100]}',
                    status='blocked'
                )
                db.session.add(audit_log)
                db.session.commit()
            except Exception as e:
                logger.error(f"Failed to log unauthorized attempt: {str(e)}")
            
            return jsonify({
                'error': 'Permission Denied',
                'message': 'You do not have permission to execute commands. Contact your administrator.',
                'required_permission': 'execute_commands'
            }), 403
        
        # Comprehensive security validation
        is_valid, error_msg, security_info = validate_command_security(
            command=command,
            container=container,
            current_dir=current_dir,
            allow_privileged=has_privileged_permission
        )
        
        if not is_valid:
            # Log blocked command
            try:
                audit_log = AuditLog(
                    user_id=user_id,
                    username=username,
                    ip_address=client_ip,
                    event_type='command_blocked',
                    message=f'Blocked command: {command[:200]} | Reason: {error_msg} | Risk: {security_info.get("risk_level")}',
                    status='blocked'
                )
                db.session.add(audit_log)
                db.session.commit()
            except Exception as e:
                logger.error(f"Failed to log blocked command: {str(e)}")
            
            logger.warning(f"Command blocked for user {username}: {command} - {error_msg}")
            return jsonify({
                'error': 'Command Blocked',
                'message': error_msg,
                'security_info': {
                    'risk_level': security_info.get('risk_level'),
                    'risk_score': security_info.get('risk_score')
                }
            }), 403
        
        # Validate container exists
        try:
            check_container_cmd = ["sudo", "docker", "inspect", container, "--format", "{{.State.Running}}"]
            result = subprocess.run(check_container_cmd, capture_output=True, text=True, timeout=5)
            if result.returncode != 0:
                return jsonify({'error': f'Container "{container}" not found or not accessible'}), 404
        except Exception as e:
            logger.error(f"Container validation failed: {str(e)}")
            return jsonify({'error': 'Failed to validate container'}), 500
        
        # Log command execution attempt
        try:
            audit_log = AuditLog(
                user_id=user_id,
                username=username,
                ip_address=client_ip,
                event_type='command_executed',
                message=f'Executing command in {container}: {command[:200]} | Risk: {security_info.get("risk_level")}',
                status='success'
            )
            db.session.add(audit_log)
            db.session.commit()
        except Exception as e:
            logger.error(f"Failed to log command execution: {str(e)}")
        
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
                # SECURITY FIX: Use shlex.quote() to prevent command injection
                escaped_dir = shlex.quote(current_dir)
                check_cmd = ["sudo", "docker", "exec", "-u", "root", container, "bash", "-c", f"[ -d {escaped_dir} ] && echo 'exists' || echo 'not_exists'"]
                process = subprocess.Popen(check_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
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
            
            # SECURITY FIX: Use shlex.quote() to prevent command injection
            escaped_dir = shlex.quote(current_dir)
            escaped_pattern = shlex.quote(file_pattern)
            
            # First check if the file exists (improved logic)
            check_cmd = ["sudo", "docker", "exec", "-u", "root", container, "bash", "-c", f"cd {escaped_dir} && ls {escaped_pattern} 2>/dev/null"]
            process = subprocess.Popen(check_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
            try:
                stdout, stderr = process.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                return jsonify({'error': 'Command timed out'}), 408
            
            # If ls command failed or returned empty, file doesn't exist
            if process.returncode != 0 or not stdout.decode().strip():
                return jsonify({'error': f"tail: cannot open '{file_pattern}' for reading: No such file or directory"})
            
            # Get initial content (last 10 lines)
            cmd = ["sudo", "docker", "exec", "-u", "root", container, "bash", "-c", f"cd {escaped_dir} && tail -n 10 {escaped_pattern}"]
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                stdout, stderr = process.communicate(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                return jsonify({'error': 'Tail command timed out'}), 408
            
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
        
        # Detect heavy commands that should run in background
        heavy_commands = ['bench migrate', 'bench get-app', 'bench install-app', 'bench build', 'bench update', 'bench backup', 'bench restore']
        
        # Check for exact matches and also patterns like "bench --site site_name install-app"
        is_heavy_command = any(command.lower().strip().startswith(hc) for hc in heavy_commands)
        
        # Also check for bench commands with --site parameter that contain heavy operations
        if not is_heavy_command and command.lower().strip().startswith('bench --site') and any(op in command.lower() for op in ['install-app', 'migrate', 'build', 'update', 'backup', 'restore']):
            is_heavy_command = True
        
        # For heavy commands, use threading for background execution
        if is_heavy_command:
            # Generate unique task ID
            task_id = str(uuid.uuid4())
            
            # Initialize task in background_tasks
            background_tasks[task_id] = {
                'type': 'command',
                'status': 'pending',
                'progress': 0,
                'message': f'Initializing command: {command}',
                'output': '',
                'error': None,
                'container': container,
                'command': command,
                'current_dir': current_dir,
                'created_at': datetime.now().isoformat(),
                'result': None
            }
            
            # Start background thread
            thread = threading.Thread(
                target=run_heavy_command_task,
                args=(task_id, container, command, current_dir)
            )
            thread.daemon = True
            thread.start()
            
            # Return task ID immediately
            return jsonify({
                'success': True,
                'task_id': task_id,
                'message': f'Heavy command started in background. Use /api/tasks/status/{task_id} to check progress.',
                'current_dir': current_dir,
                'is_background_task': True
            })
        
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
        
        # Log successful command completion
        try:
            audit_log = AuditLog(
                user_id=user_id,
                username=username,
                ip_address=client_ip,
                event_type='command_completed',
                message=f'Command completed in {container}: {command[:100]}',
                status='success'
            )
            db.session.add(audit_log)
            db.session.commit()
        except Exception as e:
            logger.error(f"Failed to log command completion: {str(e)}")
        
        return jsonify({
            'output': formatted_output['formatted_output'],
            'current_dir': current_dir,
            'security_validated': True
        })
    except Exception as e:
        # Log command execution failure
        try:
            user_id = session.get('user_id')
            username = session.get('username', 'unknown')
            client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
            command = request.json.get('command', 'unknown') if request.json else 'unknown'
            
            audit_log = AuditLog(
                user_id=user_id,
                username=username,
                ip_address=client_ip,
                event_type='command_failed',
                message=f'Command execution error: {command[:100]} | Error: {str(e)[:200]}',
                status='error'
            )
            db.session.add(audit_log)
            db.session.commit()
        except Exception as log_error:
            logger.error(f"Failed to log command failure: {str(log_error)}")
        
        logger.error(f"Error executing command: {str(e)}")
        return jsonify({'error': str(e), 'security_validated': False}), 500



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
        return jsonify({'success': False, 'message': str(e), 'error': str(e)}), 500

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
    """Create a backup of a Frappe site (using threading for background processing)"""
    try:
        data = request.json
        container = data.get('container')
        site_name = data.get('site_name')
        include_files = data.get('include_files', True)
        include_private_files = data.get('include_private_files', True)
        include_public_files = data.get('include_public_files', True)
        
        if not container or not site_name:
            return jsonify({'error': 'Container and site_name are required'}), 400
        
        # Generate unique task ID
        task_id = str(uuid.uuid4())
        
        # Initialize task in background_tasks
        background_tasks[task_id] = {
            'type': 'backup',
            'status': 'pending',
            'progress': 0,
            'message': 'Initializing backup task...',
            'output': '',
            'error': None,
            'container': container,
            'site_name': site_name,
            'created_at': datetime.now().isoformat(),
            'result': None
        }
        
        # Start background thread
        thread = threading.Thread(
            target=run_backup_task,
            args=(task_id, container, site_name, include_files, include_private_files, include_public_files)
        )
        thread.daemon = True
        thread.start()
        
        # Return task ID immediately
        return jsonify({
            'success': True,
            'task_id': task_id,
            'message': 'Backup task started. Use /api/tasks/status/<task_id> to check progress.'
        })
            
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
                        
                        # Determine backup type based on Frappe naming convention
                        if 'database' in filename and ('.sql' in filename or '.gz' in filename):
                            backup_type = 'database'
                        elif 'private-files' in filename or 'private_files' in filename:
                            backup_type = 'private_files'
                        elif 'files' in filename and 'private' not in filename:
                            # Public files are named *-files.tar (without 'private')
                            backup_type = 'public_files'
                        elif 'site_config_backup' in filename:
                            backup_type = 'config'
                        else:
                            backup_type = 'unknown'
                        
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
    """Restore a backup for a Frappe site (using threading for background processing)"""
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
        
        # Generate unique task ID
        task_id = str(uuid.uuid4())
        
        # Initialize task in background_tasks
        background_tasks[task_id] = {
            'type': 'restore',
            'status': 'pending',
            'progress': 0,
            'message': 'Initializing restore task...',
            'output': '',
            'error': None,
            'container': container,
            'site_name': site_name,
            'created_at': datetime.now().isoformat(),
            'result': None
        }
        
        # Start background thread
        thread = threading.Thread(
            target=run_restore_task,
            args=(task_id, container, site_name, backup_path, private_files_path, public_files_path, mysql_root_password, admin_password)
        )
        thread.daemon = True
        thread.start()
        
        # Return task ID immediately
        return jsonify({
            'success': True,
            'task_id': task_id,
            'message': 'Restore task started. Use /api/tasks/status/<task_id> to check progress.'
        })
            
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


# ============================================================================
# BACKGROUND TASK STATUS API ENDPOINTS
# ============================================================================

@app.route('/api/tasks/status/<task_id>', methods=['GET'])
@require_auth
def get_task_status(task_id):
    """Get the status of a background task"""
    try:
        # Check both background_tasks and site_creation_tasks
        if task_id in background_tasks:
            task = background_tasks[task_id]
            return jsonify({
                'success': True,
                'task': task
            })
        elif task_id in site_creation_tasks:
            task = site_creation_tasks[task_id]
            return jsonify({
                'success': True,
                'task': task
            })
        else:
            return jsonify({
                'success': False,
                'error': 'Task not found'
            }), 404
            
    except Exception as e:
        logger.error(f"Error getting task status: {str(e)}")
        return jsonify({'error': str(e), 'success': False}), 500


@app.route('/api/tasks/list', methods=['GET'])
@require_auth
def list_tasks():
    """List all background tasks"""
    try:
        # Get task type filter from query params
        task_type = request.args.get('type')
        status = request.args.get('status')
        
        # Combine all tasks
        all_tasks = {}
        
        # Add background_tasks
        for task_id, task in background_tasks.items():
            if task_type and task.get('type') != task_type:
                continue
            if status and task.get('status') != status:
                continue
            all_tasks[task_id] = task
        
        # Add site_creation_tasks
        for task_id, task in site_creation_tasks.items():
            if task_type and task_type != 'site_creation':
                continue
            if status and task.get('status') != status:
                continue
            # Add type for consistency
            task_copy = task.copy()
            task_copy['type'] = 'site_creation'
            all_tasks[task_id] = task_copy
        
        return jsonify({
            'success': True,
            'tasks': all_tasks,
            'count': len(all_tasks)
        })
            
    except Exception as e:
        logger.error(f"Error listing tasks: {str(e)}")
        return jsonify({'error': str(e), 'success': False}), 500


@app.route('/api/tasks/delete/<task_id>', methods=['DELETE'])
@require_auth
def delete_task(task_id):
    """Delete a completed or failed task from the list"""
    try:
        # Check both background_tasks and site_creation_tasks
        if task_id in background_tasks:
            task = background_tasks[task_id]
            # Only allow deletion of completed or failed tasks
            if task.get('status') not in ['completed', 'failed', 'cancelled']:
                return jsonify({
                    'success': False,
                    'error': 'Cannot delete running tasks'
                }), 400
            
            del background_tasks[task_id]
            return jsonify({
                'success': True,
                'message': 'Task deleted successfully'
            })
        elif task_id in site_creation_tasks:
            task = site_creation_tasks[task_id]
            # Only allow deletion of completed or failed tasks
            if task.get('status') not in ['completed', 'failed', 'cancelled']:
                return jsonify({
                    'success': False,
                    'error': 'Cannot delete running tasks'
                }), 400
            
            del site_creation_tasks[task_id]
            return jsonify({
                'success': True,
                'message': 'Task deleted successfully'
            })
        else:
            return jsonify({
                'success': False,
                'error': 'Task not found'
            }), 404
            
    except Exception as e:
        logger.error(f"Error deleting task: {str(e)}")
        return jsonify({'error': str(e), 'success': False}), 500


@app.route('/api/tasks/clear', methods=['POST'])
@require_auth
def clear_completed_tasks():
    """Clear all completed and failed tasks"""
    try:
        # Clear from background_tasks
        tasks_to_delete = [
            task_id for task_id, task in background_tasks.items()
            if task.get('status') in ['completed', 'failed', 'cancelled']
        ]
        
        for task_id in tasks_to_delete:
            del background_tasks[task_id]
        
        # Clear from site_creation_tasks
        site_tasks_to_delete = [
            task_id for task_id, task in site_creation_tasks.items()
            if task.get('status') in ['completed', 'failed', 'cancelled']
        ]
        
        for task_id in site_tasks_to_delete:
            del site_creation_tasks[task_id]
        
        total_cleared = len(tasks_to_delete) + len(site_tasks_to_delete)
        
        return jsonify({
            'success': True,
            'message': f'Cleared {total_cleared} completed/failed tasks',
            'count': total_cleared
        })
            
    except Exception as e:
        logger.error(f"Error clearing tasks: {str(e)}")
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

# ============================================================================
# BACKGROUND TASK FUNCTIONS FOR HEAVY OPERATIONS
# ============================================================================

def run_backup_task(task_id, container, site_name, include_files, include_private_files, include_public_files):
    """Background task to create a backup"""
    try:
        # Update task status
        background_tasks[task_id]['status'] = 'running'
        background_tasks[task_id]['progress'] = 10
        background_tasks[task_id]['message'] = 'Starting backup process...'
        
        # Build the bench backup command
        backup_command = f"bench --site {site_name} backup"
        
        if include_files:
            if include_private_files and include_public_files:
                backup_command += " --with-files"
            elif include_private_files:
                backup_command += " --with-private-files"
            elif include_public_files:
                backup_command += " --with-public-files"
        
        background_tasks[task_id]['progress'] = 20
        background_tasks[task_id]['message'] = 'Executing backup command...'
        
        # Execute the backup command
        cmd = ["sudo", "docker", "exec", container, "bash", "-c", backup_command]
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        
        output_lines = []
        while True:
            line = process.stdout.readline()
            if not line:
                break
            output_lines.append(line.rstrip())
            # Update output in real-time
            background_tasks[task_id]['output'] = '\n'.join(output_lines)
            
            # Update progress based on output
            if 'Backing up' in line or 'backup' in line.lower():
                if background_tasks[task_id]['progress'] < 60:
                    background_tasks[task_id]['progress'] = 50
                    background_tasks[task_id]['message'] = 'Creating database backup...'
            elif 'files' in line.lower():
                if background_tasks[task_id]['progress'] < 80:
                    background_tasks[task_id]['progress'] = 70
                    background_tasks[task_id]['message'] = 'Backing up files...'
        
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
            
            background_tasks[task_id]['status'] = 'completed'
            background_tasks[task_id]['progress'] = 100
            background_tasks[task_id]['message'] = 'Backup created successfully!'
            background_tasks[task_id]['result'] = {
                'success': True,
                'output': output,
                'backup_info': backup_info
            }
        else:
            log_command_execution(backup_command, container, False, output)
            background_tasks[task_id]['status'] = 'failed'
            background_tasks[task_id]['error'] = output or 'Backup failed'
            background_tasks[task_id]['result'] = {
                'success': False,
                'error': output or 'Backup failed'
            }
            
    except Exception as e:
        logger.error(f"Error in backup task {task_id}: {str(e)}")
        background_tasks[task_id]['status'] = 'failed'
        background_tasks[task_id]['error'] = str(e)
        background_tasks[task_id]['result'] = {
            'success': False,
            'error': str(e)
        }


def run_restore_task(task_id, container, site_name, backup_path, private_files_path, public_files_path, mysql_root_password, admin_password):
    """Background task to restore a backup"""
    try:
        # Update task status
        background_tasks[task_id]['status'] = 'running'
        background_tasks[task_id]['progress'] = 10
        background_tasks[task_id]['message'] = 'Starting restore process...'
        
        # Escape single quotes in password for shell safety
        escaped_password = mysql_root_password.replace("'", "'\\''")
        
        # Create a temporary MySQL config file with password to avoid prompts
        mysql_config_content = f"""[client]
user=root
password={escaped_password}
host=db
"""
        
        background_tasks[task_id]['progress'] = 20
        background_tasks[task_id]['message'] = 'Creating MySQL configuration...'
        
        # Create the config file in the container
        create_config_cmd = f"cat > /tmp/mysql_restore.cnf << 'EOFMYSQL'\n{mysql_config_content}\nEOFMYSQL"
        cmd_create = ["sudo", "docker", "exec", container, "bash", "-c", create_config_cmd]
        subprocess.run(cmd_create, capture_output=True)
        
        # Build the restore command
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
        
        background_tasks[task_id]['progress'] = 30
        background_tasks[task_id]['message'] = 'Executing restore command...'
        
        # Execute the restore command
        cmd = ["sudo", "docker", "exec", container, "bash", "-c", restore_command]
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        
        output_lines = []
        while True:
            line = process.stdout.readline()
            if not line:
                break
            output_lines.append(line.rstrip())
            # Update output in real-time
            background_tasks[task_id]['output'] = '\n'.join(output_lines)
            
            # Update progress based on output
            if 'database' in line.lower() or 'restoring' in line.lower():
                if background_tasks[task_id]['progress'] < 70:
                    background_tasks[task_id]['progress'] = 50
                    background_tasks[task_id]['message'] = 'Restoring database...'
            elif 'files' in line.lower():
                if background_tasks[task_id]['progress'] < 90:
                    background_tasks[task_id]['progress'] = 80
                    background_tasks[task_id]['message'] = 'Restoring files...'
        
        process.wait()
        output = '\n'.join(output_lines)
        
        # Clean up the temporary config file
        cleanup_cmd = ["sudo", "docker", "exec", container, "bash", "-c", "rm -f /tmp/mysql_restore.cnf"]
        subprocess.run(cleanup_cmd, capture_output=True)
        
        if process.returncode == 0:
            log_command_execution(f"bench restore (site: {site_name})", container, True, None)
            
            background_tasks[task_id]['status'] = 'completed'
            background_tasks[task_id]['progress'] = 100
            background_tasks[task_id]['message'] = 'Backup restored successfully!'
            background_tasks[task_id]['result'] = {
                'success': True,
                'output': output
            }
        else:
            log_command_execution(f"bench restore (site: {site_name})", container, False, output)
            background_tasks[task_id]['status'] = 'failed'
            background_tasks[task_id]['error'] = output or 'Restore failed'
            background_tasks[task_id]['result'] = {
                'success': False,
                'error': output or 'Restore failed'
            }
            
    except Exception as e:
        logger.error(f"Error in restore task {task_id}: {str(e)}")
        background_tasks[task_id]['status'] = 'failed'
        background_tasks[task_id]['error'] = str(e)
        background_tasks[task_id]['result'] = {
            'success': False,
            'error': str(e)
        }


def run_heavy_command_task(task_id, container, command, current_dir):
    """Background task for heavy commands like bench migrate"""
    try:
        # Update task status
        background_tasks[task_id]['status'] = 'running'
        background_tasks[task_id]['progress'] = 10
        background_tasks[task_id]['message'] = f'Executing: {command}'
        
        # Execute command
        cmd = ["sudo", "docker", "exec", "-w", current_dir, container, "bash", "-c", command]
        
        background_tasks[task_id]['progress'] = 20
        background_tasks[task_id]['message'] = 'Processing command...'
        
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1, universal_newlines=True)
        
        output_lines = []
        
        # Special handling for bench migrate command
        if command.lower().strip() == 'bench migrate':
            current_app = None
            last_progress = 0
            
            while True:
                line = process.stdout.readline()
                if not line:
                    break
                
                line = line.rstrip()
                
                # Extract meaningful information from migrate output
                if 'Migrating' in line and 'local' in line:
                    site_name = line.split('Migrating ')[1].split('\n')[0]
                    output_lines.append(f"🔄 Starting migration for site: {site_name}")
                    background_tasks[task_id]['progress'] = 30
                    background_tasks[task_id]['message'] = f'Migrating site: {site_name}'
                
                elif 'Updating DocTypes for' in line and '%' in line:
                    parts = line.split('Updating DocTypes for ')
                    if len(parts) > 1:
                        app_part = parts[1].split(' : ')[0]
                        progress_part = parts[1].split(' : ')[1] if ' : ' in parts[1] else ''
                        
                        if '%' in progress_part:
                            percent = progress_part.split('%')[0].split()[-1]
                            try:
                                percent_int = int(percent)
                                if percent_int >= last_progress + 10:
                                    output_lines.append(f"📊 Updating DocTypes for {app_part}: {percent_int}%")
                                    last_progress = percent_int
                                    # Map progress to 40-80 range
                                    background_tasks[task_id]['progress'] = min(40 + int(percent_int * 0.4), 80)
                                    background_tasks[task_id]['message'] = f'Updating DocTypes: {percent_int}%'
                            except ValueError:
                                pass
                
                elif 'Updating Dashboard for' in line:
                    app_name = line.split('Updating Dashboard for ')[1]
                    output_lines.append(f"📈 Updating Dashboard for {app_name}")
                    background_tasks[task_id]['progress'] = 85
                    background_tasks[task_id]['message'] = 'Updating dashboards...'
                
                elif 'Updating customizations for' in line:
                    doctype = line.split('Updating customizations for ')[1]
                    output_lines.append(f"🔧 Updating customizations for {doctype}")
                
                elif 'Executing `after_migrate` hooks' in line:
                    output_lines.append("⚡ Executing post-migration hooks...")
                    background_tasks[task_id]['progress'] = 90
                    background_tasks[task_id]['message'] = 'Executing post-migration hooks...'
                
                elif 'Queued rebuilding of search index' in line:
                    site_name = line.split('Queued rebuilding of search index for ')[1]
                    output_lines.append(f"🔍 Queued search index rebuild for {site_name}")
                
                elif line.strip() and not any(x in line for x in ['[', ']', '=']):
                    output_lines.append(line)
                
                # Update output in real-time
                background_tasks[task_id]['output'] = '\n'.join(output_lines)
            
            # Get final output
            output = '\n'.join(output_lines)
            
            # Check if process completed successfully
            process.wait()
            if process.returncode != 0:
                background_tasks[task_id]['status'] = 'failed'
                background_tasks[task_id]['error'] = f"Migration failed with exit code {process.returncode}"
                background_tasks[task_id]['result'] = {
                    'success': False,
                    'error': f"Migration failed with exit code {process.returncode}"
                }
            else:
                output += "\n\n✅ Migration completed successfully!"
                background_tasks[task_id]['status'] = 'completed'
                background_tasks[task_id]['progress'] = 100
                background_tasks[task_id]['message'] = 'Migration completed successfully!'
                background_tasks[task_id]['output'] = output
                background_tasks[task_id]['result'] = {
                    'success': True,
                    'output': output
                }
        
        # Special handling for bench install-app command
        elif command.lower().strip().startswith('bench --site') and 'install-app' in command.lower():
            app_name = None
            site_name = None
            last_progress = 0
            
            while True:
                line = process.stdout.readline()
                if not line:
                    break
                
                line = line.rstrip()
                
                # Extract app and site names from command
                if app_name is None or site_name is None:
                    if '--site' in command:
                        parts = command.split('--site')
                        if len(parts) > 1:
                            site_part = parts[1].strip().split()[0]
                            site_name = site_part
                    if 'install-app' in command:
                        parts = command.split('install-app')
                        if len(parts) > 1:
                            app_part = parts[1].strip().split()[0]
                            app_name = app_part
                
                # Parse install-app specific output
                if 'Installing' in line and 'app' in line.lower():
                    output_lines.append(f"🚀 Starting installation of {app_name or 'app'} on site {site_name or 'site'}")
                    background_tasks[task_id]['progress'] = 20
                    background_tasks[task_id]['message'] = f'Installing {app_name or "app"} on {site_name or "site"}'
                
                elif 'Installing app' in line:
                    output_lines.append(f"📦 {line}")
                    background_tasks[task_id]['progress'] = 30
                    background_tasks[task_id]['message'] = 'Installing application files...'
                
                elif 'Building' in line or 'Compiling' in line:
                    output_lines.append(f"🔨 {line}")
                    background_tasks[task_id]['progress'] = 40
                    background_tasks[task_id]['message'] = 'Building application...'
                
                elif 'Installing dependencies' in line or 'pip install' in line.lower():
                    output_lines.append(f"📚 {line}")
                    background_tasks[task_id]['progress'] = 50
                    background_tasks[task_id]['message'] = 'Installing dependencies...'
                
                elif 'Creating' in line and 'doctype' in line.lower():
                    output_lines.append(f"📋 {line}")
                    background_tasks[task_id]['progress'] = 60
                    background_tasks[task_id]['message'] = 'Creating database tables...'
                
                elif 'Migrating' in line and 'local' in line:
                    output_lines.append(f"🔄 {line}")
                    background_tasks[task_id]['progress'] = 70
                    background_tasks[task_id]['message'] = 'Running database migrations...'
                
                elif 'Updating DocTypes' in line:
                    output_lines.append(f"📊 {line}")
                    background_tasks[task_id]['progress'] = 80
                    background_tasks[task_id]['message'] = 'Updating DocTypes...'
                
                elif 'Building assets' in line or 'Compiling assets' in line:
                    output_lines.append(f"🎨 {line}")
                    background_tasks[task_id]['progress'] = 85
                    background_tasks[task_id]['message'] = 'Building frontend assets...'
                
                elif 'Successfully installed' in line or 'Installation completed' in line:
                    output_lines.append(f"✅ {line}")
                    background_tasks[task_id]['progress'] = 95
                    background_tasks[task_id]['message'] = 'Installation completed!'
                
                elif line.strip() and not any(x in line for x in ['[', ']', '=', 'INFO', 'DEBUG']):
                    # Include important lines but filter out noise
                    if any(keyword in line.lower() for keyword in ['error', 'warning', 'success', 'installing', 'creating', 'building', 'migrating']):
                        output_lines.append(line)
                
                # Update output in real-time
                background_tasks[task_id]['output'] = '\n'.join(output_lines)
            
            # Get final output
            output = '\n'.join(output_lines)
            
            # Check if process completed successfully
            process.wait()
            if process.returncode != 0:
                background_tasks[task_id]['status'] = 'failed'
                background_tasks[task_id]['error'] = f"App installation failed with exit code {process.returncode}"
                background_tasks[task_id]['result'] = {
                    'success': False,
                    'error': f"App installation failed with exit code {process.returncode}",
                    'output': output
                }
            else:
                output += f"\n\n✅ App '{app_name or 'application'}' installed successfully on site '{site_name or 'site'}'!"
                background_tasks[task_id]['status'] = 'completed'
                background_tasks[task_id]['progress'] = 100
                background_tasks[task_id]['message'] = f'App {app_name or "application"} installed successfully!'
                background_tasks[task_id]['output'] = output
                background_tasks[task_id]['result'] = {
                    'success': True,
                    'output': output
                }
        
        else:
            # For other commands, use standard approach
            while True:
                line = process.stdout.readline()
                if not line:
                    break
                output_lines.append(line.rstrip())
                # Update output in real-time
                background_tasks[task_id]['output'] = '\n'.join(output_lines)
                
                # Update progress gradually
                current_progress = background_tasks[task_id]['progress']
                if current_progress < 90:
                    background_tasks[task_id]['progress'] = min(current_progress + 5, 90)
            
            # Get final output
            output = '\n'.join(output_lines)
            
            # Check if process completed successfully
            process.wait()
            if process.returncode != 0:
                background_tasks[task_id]['status'] = 'failed'
                background_tasks[task_id]['error'] = f"Command failed with exit code {process.returncode}"
                background_tasks[task_id]['result'] = {
                    'success': False,
                    'output': output,
                    'error': f"Command failed with exit code {process.returncode}"
                }
            else:
                background_tasks[task_id]['status'] = 'completed'
                background_tasks[task_id]['progress'] = 100
                background_tasks[task_id]['message'] = 'Command completed successfully!'
                background_tasks[task_id]['output'] = output
                background_tasks[task_id]['result'] = {
                    'success': True,
                    'output': output
                }
            
    except Exception as e:
        logger.error(f"Error in command task {task_id}: {str(e)}")
        background_tasks[task_id]['status'] = 'failed'
        background_tasks[task_id]['error'] = str(e)
        background_tasks[task_id]['result'] = {
            'success': False,
            'error': str(e)
        }


def run_site_creation_task(task_id, domain_name, erpnext_version, environment, script_path, base_dir):
    """Background task to create a site"""
    try:
        # Extract site name from domain
        site_name = domain_name.split('.')[0]
        
        # Update task status
        site_creation_tasks[task_id]['status'] = 'running'
        site_creation_tasks[task_id]['progress'] = 2
        site_creation_tasks[task_id]['message'] = 'Starting site creation...'
        
        # Log the site creation attempt
        logger.info(f"Creating new site: {site_name} ({domain_name}) with ERPNext {erpnext_version} in {environment} environment")
        
        # Update progress
        site_creation_tasks[task_id]['progress'] = 5
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
            site_creation_tasks[task_id]['progress'] = 20
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
            site_creation_tasks[task_id]['progress'] = 25
            site_creation_tasks[task_id]['message'] = 'Installing Frappe/ERPNext... This may take 5 minutes...'
            
            # Read output line by line in real-time
            output_lines = []
            for line in iter(process.stdout.readline, ''):
                if line:
                    cleaned_line = clean_ansi_codes(line.rstrip())
                    output_lines.append(cleaned_line)
                    # Update task with latest output (keep last 100 lines for performance)
                    site_creation_tasks[task_id]['output'] = '\n'.join(output_lines[-100:])
                    
                    # Get current progress to ensure it never goes backward
                    current_progress = site_creation_tasks[task_id]['progress']
                    
                    # Update progress based on output keywords (only increase, never decrease)
                    if ('Pulling' in line or 'Downloading' in line or 'Download' in line) and current_progress < 45:
                        site_creation_tasks[task_id]['progress'] = 35
                        site_creation_tasks[task_id]['message'] = 'Downloading Docker images...'
                    elif ('Building' in line or 'Built' in line) and current_progress < 55:
                        site_creation_tasks[task_id]['progress'] = 40
                        site_creation_tasks[task_id]['message'] = 'Building Docker images...'
                    elif ('Creating' in line and 'container' in line.lower()) and current_progress < 65:
                        site_creation_tasks[task_id]['progress'] = 50
                        site_creation_tasks[task_id]['message'] = 'Creating containers...'
                    elif ('Starting' in line or 'Started' in line) and current_progress < 75:
                        site_creation_tasks[task_id]['progress'] = 55
                        site_creation_tasks[task_id]['message'] = 'Starting containers...'
                    elif ('done' in line.lower() or 'complete' in line.lower()) and current_progress < 85:
                        site_creation_tasks[task_id]['progress'] = 65
                        site_creation_tasks[task_id]['message'] = 'Finalizing setup...'
            
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

# ==================== REBUILD OPERATIONS WITH THREADING ====================
# Store rebuild tasks (similar to site_creation_tasks)
rebuild_tasks = {}

def run_rebuild_task(task_id, site_name, base_dir):
    """Background task to rebuild containers with apps preservation"""
    try:
        rebuild_tasks[task_id]['status'] = 'running'
        rebuild_tasks[task_id]['progress'] = 5
        rebuild_tasks[task_id]['output'] = ''
        
        def append_output(msg):
            rebuild_tasks[task_id]['output'] += msg + '\n'
        
        append_output(f'🔄 Starting rebuild for {site_name}...')
        append_output(f'📍 Base directory: {base_dir}')
        
        # Detect docker compose command
        try:
            subprocess.run(['docker', 'compose', 'version'], capture_output=True, check=True)
            docker_compose_cmd = 'docker compose'
        except:
            docker_compose_cmd = 'docker-compose'
        
        append_output(f'✅ Using: {docker_compose_cmd}')
        rebuild_tasks[task_id]['progress'] = 10
        
        # Find compose file
        compose_file_local = f"{base_dir}/Docker-Local/{site_name}/{site_name}-docker-compose.yml"
        compose_file_vps = f"{base_dir}/Docker-on-VPS/{site_name}/{site_name}-docker-compose.yml"
        
        compose_file = None
        work_dir = None
        
        if os.path.exists(compose_file_local):
            compose_file = compose_file_local
            work_dir = f"{base_dir}/Docker-Local/{site_name}"
            append_output(f'📁 Found in: Docker-Local/{site_name}/')
        elif os.path.exists(compose_file_vps):
            compose_file = compose_file_vps
            work_dir = f"{base_dir}/Docker-on-VPS/{site_name}"
            append_output(f'📁 Found in: Docker-on-VPS/{site_name}/')
        else:
            rebuild_tasks[task_id]['status'] = 'failed'
            rebuild_tasks[task_id]['error'] = f'Docker compose file not found for {site_name}'
            return
        
        container_name = f"{site_name}-app"
        rebuild_tasks[task_id]['progress'] = 20
        
        # Backup apps list
        append_output('\n💾 Backing up apps list...')
        try:
            backup_cmd = f'docker exec {container_name} bash -c "cd /home/frappe/frappe-bench && cat sites/apps.txt"'
            result = subprocess.run(backup_cmd, shell=True, capture_output=True, text=True, timeout=30)
            apps_backup = result.stdout
            if apps_backup:
                append_output('✅ Apps backed up')
        except Exception as e:
            apps_backup = None
            append_output(f'⚠️  Could not backup apps: {str(e)}')
        
        rebuild_tasks[task_id]['progress'] = 30
        
        # Stop containers
        append_output('\n⏹️  Stopping containers...')
        stop_cmd = f'{docker_compose_cmd} -f "{compose_file}" down'
        result = subprocess.run(stop_cmd, shell=True, cwd=work_dir, capture_output=True, text=True, timeout=120)
        append_output(result.stdout)
        if result.stderr:
            append_output(result.stderr)
        
        rebuild_tasks[task_id]['progress'] = 50
        
        # Rebuild and start
        append_output('\n🔨 Rebuilding containers...')
        rebuild_cmd = f'{docker_compose_cmd} -f "{compose_file}" up -d --build'
        process = subprocess.Popen(rebuild_cmd, shell=True, cwd=work_dir, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
        
        for line in process.stdout:
            append_output(line.rstrip())
            
        process.wait()
        rebuild_tasks[task_id]['progress'] = 80
        
        # Wait for container to be ready
        append_output('\n⏳ Waiting for container to be ready...')
        max_attempts = 30
        for attempt in range(max_attempts):
            check_cmd = f'docker exec {container_name} bash -c "cd /home/frappe/frappe-bench && bench --version"'
            result = subprocess.run(check_cmd, shell=True, capture_output=True, timeout=10)
            if result.returncode == 0:
                append_output('✅ Container is ready!')
                break
            append_output(f'   Attempt {attempt + 1}/{max_attempts} - Waiting...')
            time.sleep(10)
            rebuild_tasks[task_id]['progress'] = 80 + (attempt * 0.5)
        else:
            rebuild_tasks[task_id]['status'] = 'failed'
            rebuild_tasks[task_id]['error'] = 'Container did not become ready in time'
            return
        
        # Restore apps list
        if apps_backup:
            append_output('\n📋 Restoring apps list...')
            restore_cmd = f'echo "{apps_backup}" | docker exec -i {container_name} bash -c "cat > /home/frappe/frappe-bench/sites/apps.txt"'
            subprocess.run(restore_cmd, shell=True, timeout=30)
            append_output('✅ Apps list restored')
        
        rebuild_tasks[task_id]['progress'] = 100
        rebuild_tasks[task_id]['status'] = 'completed'
        append_output('\n🎉 Rebuild completed successfully!')
        
    except Exception as e:
        logger.error(f"Error in rebuild task: {str(e)}")
        rebuild_tasks[task_id]['status'] = 'failed'
        rebuild_tasks[task_id]['error'] = str(e)
        rebuild_tasks[task_id]['output'] += f'\n❌ Error: {str(e)}'

@app.route('/api/frappe/rebuild-with-apps', methods=['POST'])
@require_auth
def rebuild_with_apps():
    """Start rebuild task as a background thread"""
    try:
        data = request.json
        site_name = data.get('site_name')
        
        if not site_name:
            return jsonify({'error': 'Site name is required', 'success': False}), 400
        
        # Get base directory
        web_manager_dir = os.path.dirname(os.path.abspath(__file__))
        base_dir = os.path.dirname(web_manager_dir)
        
        # Generate unique task ID
        task_id = str(uuid.uuid4())
        
        # Initialize task status
        rebuild_tasks[task_id] = {
            'status': 'pending',
            'progress': 0,
            'message': 'Task queued...',
            'site_name': site_name,
            'created_at': datetime.now().isoformat(),
            'output': '',
            'error': None
        }
        
        # Start background thread
        thread = threading.Thread(
            target=run_rebuild_task,
            args=(task_id, site_name, base_dir)
        )
        thread.daemon = True
        thread.start()
        
        # Return task ID immediately
        return jsonify({
            'success': True,
            'task_id': task_id,
            'message': 'Rebuild started in background',
            'site_name': site_name
        })
        
    except Exception as e:
        logger.error(f"Error starting rebuild: {str(e)}")
        return jsonify({'error': str(e), 'success': False}), 500

@app.route('/api/frappe/rebuild-with-apps/status/<task_id>', methods=['GET'])
@require_auth
def get_rebuild_status(task_id):
    """Get status of rebuild task"""
    if task_id not in rebuild_tasks:
        return jsonify({'error': 'Task not found', 'success': False}), 404
    
    return jsonify({
        'success': True,
        'task': rebuild_tasks[task_id]
    })

# ==================== FIX RESTART POLICIES WITH THREADING ====================
restart_policy_tasks = {}

def run_fix_restart_policies_task(task_id):
    """Background task to fix restart policies for all containers"""
    try:
        restart_policy_tasks[task_id]['status'] = 'running'
        restart_policy_tasks[task_id]['progress'] = 10
        restart_policy_tasks[task_id]['output'] = ''
        
        def append_output(msg):
            restart_policy_tasks[task_id]['output'] += msg + '\n'
        
        append_output('🔧 Starting restart policy fix for all containers...')
        append_output('')
        
        # Get all unique site names
        cmd = "docker ps -a --format '{{.Names}}' | grep -E '.*-(db|redis|app)$' | sed 's/-(db|redis|app)$//' | sort -u"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
        
        if result.returncode != 0:
            restart_policy_tasks[task_id]['status'] = 'failed'
            restart_policy_tasks[task_id]['error'] = 'Failed to get container list'
            return
        
        sites = result.stdout.strip().split('\n') if result.stdout.strip() else []
        
        if not sites:
            append_output('ℹ️  No Frappe containers found')
            restart_policy_tasks[task_id]['status'] = 'completed'
            restart_policy_tasks[task_id]['progress'] = 100
            return
        
        total_sites = len(sites)
        append_output(f'📋 Found {total_sites} site(s) to process')
        append_output('')
        
        for idx, site in enumerate(sites):
            if not site:
                continue
                
            append_output(f'🔄 Processing {site}...')
            progress = 10 + (idx * 80 // total_sites)
            restart_policy_tasks[task_id]['progress'] = progress
            
            for container in [f'{site}-db', f'{site}-redis', f'{site}-app']:
                # Check if container exists
                check_cmd = f"docker ps -a --format '{{{{.Names}}}}' | grep -q '^{container}$'"
                check_result = subprocess.run(check_cmd, shell=True, capture_output=True, timeout=10)
                
                if check_result.returncode != 0:
                    continue
                
                # Get current policy
                policy_cmd = f'docker inspect {container} --format="{{{{.HostConfig.RestartPolicy.Name}}}}"'
                policy_result = subprocess.run(policy_cmd, shell=True, capture_output=True, text=True, timeout=10)
                current_policy = policy_result.stdout.strip() if policy_result.returncode == 0 else 'unknown'
                
                # Update if not already unless-stopped
                if current_policy != 'unless-stopped':
                    append_output(f'  ✏️  Updating {container} restart policy...')
                    update_cmd = f'docker update --restart=unless-stopped {container}'
                    subprocess.run(update_cmd, shell=True, capture_output=True, timeout=30)
                
                # Check if stopped and start it
                status_cmd = f'docker inspect {container} --format="{{{{.State.Status}}}}"'
                status_result = subprocess.run(status_cmd, shell=True, capture_output=True, text=True, timeout=10)
                status = status_result.stdout.strip() if status_result.returncode == 0 else ''
                
                if status != 'running':
                    append_output(f'  ▶️  Starting {container}...')
                    start_cmd = f'docker start {container}'
                    subprocess.run(start_cmd, shell=True, capture_output=True, timeout=30)
            
            append_output(f'  ✅ {site} done')
            append_output('')
        
        restart_policy_tasks[task_id]['progress'] = 100
        restart_policy_tasks[task_id]['status'] = 'completed'
        append_output('🎉 All restart policies fixed!')
        append_output('✅ Containers will now start automatically after system restart')
        
    except Exception as e:
        logger.error(f"Error in fix restart policies task: {str(e)}")
        restart_policy_tasks[task_id]['status'] = 'failed'
        restart_policy_tasks[task_id]['error'] = str(e)
        restart_policy_tasks[task_id]['output'] += f'\n❌ Error: {str(e)}'

@app.route('/api/frappe/fix-restart-policies', methods=['POST'])
@require_auth
def fix_restart_policies():
    """Start fix restart policies task as a background thread"""
    try:
        # Generate unique task ID
        task_id = str(uuid.uuid4())
        
        # Initialize task status
        restart_policy_tasks[task_id] = {
            'status': 'pending',
            'progress': 0,
            'message': 'Task queued...',
            'created_at': datetime.now().isoformat(),
            'output': '',
            'error': None
        }
        
        # Start background thread
        thread = threading.Thread(
            target=run_fix_restart_policies_task,
            args=(task_id,)
        )
        thread.daemon = True
        thread.start()
        
        # Return task ID immediately
        return jsonify({
            'success': True,
            'task_id': task_id,
            'message': 'Restart policy fix started in background'
        })
        
    except Exception as e:
        logger.error(f"Error starting restart policy fix: {str(e)}")
        return jsonify({'error': str(e), 'success': False}), 500

@app.route('/api/frappe/fix-restart-policies/status/<task_id>', methods=['GET'])
@require_auth
def get_restart_policy_status(task_id):
    """Get status of restart policy fix task"""
    if task_id not in restart_policy_tasks:
        return jsonify({'error': 'Task not found', 'success': False}), 404
    
    return jsonify({
        'success': True,
        'task': restart_policy_tasks[task_id]
    })

# ==================== COMPLETE SITE REMOVAL WITH THREADING ====================
site_removal_tasks = {}

def run_site_removal_task(task_id, site_name, base_dir):
    """Background task to completely remove a site"""
    try:
        site_removal_tasks[task_id]['status'] = 'running'
        site_removal_tasks[task_id]['progress'] = 5
        site_removal_tasks[task_id]['output'] = ''
        
        def append_output(msg):
            site_removal_tasks[task_id]['output'] += msg + '\n'
        
        append_output(f'🗑️  Starting complete removal of {site_name}...')
        append_output(f'📍 Base directory: {base_dir}')
        append_output('')
        
        # Show preview of what will be removed
        append_output('=' * 60)
        append_output('📋 PREVIEW: Resources to be removed')
        append_output('=' * 60)
        
        # Preview containers
        containers_cmd = f'docker ps -a --filter "name=^{site_name}-" --format "{{{{.Names}}}}"'
        containers_result = subprocess.run(containers_cmd, shell=True, capture_output=True, text=True, timeout=30)
        if containers_result.stdout.strip():
            append_output('🐳 Containers:')
            for container in containers_result.stdout.strip().split('\n'):
                if container:
                    append_output(f'   • {container}')
        else:
            append_output('🐳 Containers: None found')
        
        # Preview volumes
        volumes_cmd = f'docker volume ls --filter "name={site_name}" --format "{{{{.Name}}}}"'
        volumes_result = subprocess.run(volumes_cmd, shell=True, capture_output=True, text=True, timeout=30)
        if volumes_result.stdout.strip():
            append_output('📦 Volumes:')
            for volume in volumes_result.stdout.strip().split('\n'):
                if volume:
                    append_output(f'   • {volume}')
        else:
            append_output('📦 Volumes: None found')
        
        # Preview networks
        networks_cmd = f'docker network ls --filter "name={site_name}" --format "{{{{.Name}}}}"'
        networks_result = subprocess.run(networks_cmd, shell=True, capture_output=True, text=True, timeout=30)
        if networks_result.stdout.strip():
            append_output('🌐 Networks:')
            for network in networks_result.stdout.strip().split('\n'):
                if network and network not in ['bridge', 'host', 'none']:
                    append_output(f'   • {network}')
        else:
            append_output('🌐 Networks: None found')
        
        # Preview folders
        append_output('📁 Folders:')
        site_folder_local = f"{base_dir}/Docker-Local/{site_name}"
        site_folder_vps = f"{base_dir}/Docker-on-VPS/{site_name}"
        if os.path.exists(site_folder_local):
            append_output(f'   • {site_folder_local}')
        if os.path.exists(site_folder_vps):
            append_output(f'   • {site_folder_vps}')
        
        # Preview dev folder
        if os.environ.get('SUDO_USER'):
            preview_home_dir = os.path.expanduser(f"~{os.environ['SUDO_USER']}")
        else:
            preview_home_dir = os.path.expanduser("~")
        preview_dev_folder = f"{preview_home_dir}/frappe-docker/{site_name}-frappe-bench"
        if os.path.exists(preview_dev_folder):
            append_output(f'   • {preview_dev_folder}')
        
        # Preview hosts entry
        site_domain = site_name.replace('_', '.')
        check_hosts_cmd = f'grep "{site_domain}" /etc/hosts 2>/dev/null'
        check_result = subprocess.run(check_hosts_cmd, shell=True, capture_output=True)
        if check_result.returncode == 0:
            append_output(f'🌍 Hosts entry: {site_domain}')
        
        append_output('=' * 60)
        append_output('')
        
        # Stop and remove containers (with force)
        append_output('⏹️  Stopping containers...')
        stop_cmd = f'docker stop $(docker ps -q --filter "name=^{site_name}-") 2>/dev/null || true'
        subprocess.run(stop_cmd, shell=True, capture_output=True, timeout=120)
        site_removal_tasks[task_id]['progress'] = 15
        
        append_output('🗑️  Force removing containers (app, db, redis)...')
        # Force remove with -f flag to ensure removal even if running
        rm_cmd = f'docker rm -f $(docker ps -aq --filter "name=^{site_name}-") 2>/dev/null || true'
        rm_result = subprocess.run(rm_cmd, shell=True, capture_output=True, text=True, timeout=60)
        
        # Also try individual container removal to be thorough
        for container_type in ['app', 'db', 'redis', 'socketio', 'scheduler', 'worker']:
            container_name = f'{site_name}-{container_type}'
            rm_individual = f'docker rm -f {container_name} 2>/dev/null || true'
            subprocess.run(rm_individual, shell=True, capture_output=True, timeout=30)
        
        append_output('✅ All containers forcefully removed')
        site_removal_tasks[task_id]['progress'] = 25
        
        # Remove Docker volumes (force removal)
        append_output('')
        append_output('📦 Removing Docker volumes (all data)...')
        
        # Get list of volumes for this site (multiple patterns)
        volume_patterns = [
            f'docker volume ls -q --filter "name={site_name}"',
            f'docker volume ls -q | grep {site_name}',
        ]
        
        volumes_found = set()
        for pattern_cmd in volume_patterns:
            try:
                result = subprocess.run(pattern_cmd, shell=True, capture_output=True, text=True, timeout=30)
                if result.stdout.strip():
                    for vol in result.stdout.strip().split('\n'):
                        if vol and site_name in vol:
                            volumes_found.add(vol)
            except:
                pass
        
        if volumes_found:
            for volume in volumes_found:
                append_output(f'  🗑️  Force removing volume: {volume}')
                # Force remove with -f flag
                rm_vol_cmd = f'docker volume rm -f {volume} 2>/dev/null || true'
                subprocess.run(rm_vol_cmd, shell=True, capture_output=True, timeout=30)
            append_output(f'✅ Removed {len(volumes_found)} Docker volume(s)')
        else:
            append_output('  ℹ️  No volumes found')
        
        # Also try to remove common volume patterns
        common_volumes = [
            f'{site_name}_db-data',
            f'{site_name}_redis-data',
            f'{site_name}_sites',
            f'{site_name}-db-data',
            f'{site_name}-redis-data',
            f'{site_name}-sites',
        ]
        for vol in common_volumes:
            subprocess.run(f'docker volume rm -f {vol} 2>/dev/null', shell=True, capture_output=True, timeout=10)
        
        site_removal_tasks[task_id]['progress'] = 35
        
        # Remove Docker networks (force removal)
        append_output('')
        append_output('🌐 Removing Docker networks...')
        
        # Get list of networks for this site (multiple methods)
        network_patterns = [
            f'docker network ls -q --filter "name={site_name}"',
            f'docker network ls -q | grep {site_name}',
        ]
        
        networks_found = set()
        for pattern_cmd in network_patterns:
            try:
                result = subprocess.run(pattern_cmd, shell=True, capture_output=True, text=True, timeout=30)
                if result.stdout.strip():
                    for net in result.stdout.strip().split('\n'):
                        if net and site_name in net:
                            networks_found.add(net)
            except:
                pass
        
        # Exclude system networks
        system_networks = {'bridge', 'host', 'none', 'traefik-net', 'traefik-public'}
        networks_to_remove = networks_found - system_networks
        
        if networks_to_remove:
            for network in networks_to_remove:
                append_output(f'  🗑️  Removing network: {network}')
                rm_net_cmd = f'docker network rm {network} 2>/dev/null || true'
                subprocess.run(rm_net_cmd, shell=True, capture_output=True, timeout=30)
            append_output(f'✅ Removed {len(networks_to_remove)} Docker network(s)')
        else:
            append_output('  ℹ️  No custom networks found')
        
        # Also try common network patterns
        common_networks = [
            f'{site_name}_default',
            f'{site_name}-network',
            f'{site_name}_network',
        ]
        for net in common_networks:
            subprocess.run(f'docker network rm {net} 2>/dev/null', shell=True, capture_output=True, timeout=10)
        
        site_removal_tasks[task_id]['progress'] = 40
        
        # Remove Docker images related to this site
        append_output('')
        append_output('🖼️  Removing Docker images...')
        
        # Find images tagged with site name
        images_cmd = f'docker images --format "{{{{.Repository}}}}:{{{{.Tag}}}}" | grep {site_name}'
        images_result = subprocess.run(images_cmd, shell=True, capture_output=True, text=True, timeout=30)
        
        if images_result.stdout.strip():
            images = images_result.stdout.strip().split('\n')
            images_removed = 0
            for image in images:
                if image and site_name in image:
                    append_output(f'  🗑️  Removing image: {image}')
                    rm_img_cmd = f'docker rmi -f {image} 2>/dev/null || true'
                    subprocess.run(rm_img_cmd, shell=True, capture_output=True, timeout=30)
                    images_removed += 1
            if images_removed > 0:
                append_output(f'✅ Removed {images_removed} Docker image(s)')
        else:
            append_output('  ℹ️  No custom images found')
        
        site_removal_tasks[task_id]['progress'] = 50
        
        # Remove site folders and configuration files
        append_output('')
        append_output('📁 Removing site folders and configurations...')
        
        folders_removed = 0
        
        # Remove Docker-Local folder
        site_folder_local = f"{base_dir}/Docker-Local/{site_name}"
        if os.path.exists(site_folder_local):
            append_output(f'  🗑️  Removing: {site_folder_local}')
            rm_local_cmd = f'sudo rm -rf "{site_folder_local}"'
            subprocess.run(rm_local_cmd, shell=True, timeout=60)
            append_output('  ✅ Docker-Local folder removed')
            folders_removed += 1
        
        # Remove Docker-on-VPS folder
        site_folder_vps = f"{base_dir}/Docker-on-VPS/{site_name}"
        if os.path.exists(site_folder_vps):
            append_output(f'  🗑️  Removing: {site_folder_vps}')
            rm_vps_cmd = f'sudo rm -rf "{site_folder_vps}"'
            subprocess.run(rm_vps_cmd, shell=True, timeout=60)
            append_output('  ✅ Docker-on-VPS folder removed')
            folders_removed += 1
        
        # Remove any docker-compose files in root
        compose_files = [
            f"{base_dir}/{site_name}-docker-compose.yml",
            f"{base_dir}/{site_name}_local/{site_name}_local-docker-compose.yml",
            f"{base_dir}/erp{site_name}/{site_name}-docker-compose.yml",
        ]
        for compose_file in compose_files:
            if os.path.exists(compose_file):
                append_output(f'  🗑️  Removing compose file: {compose_file}')
                subprocess.run(f'sudo rm -f "{compose_file}"', shell=True, timeout=10)
        
        if folders_removed == 0:
            append_output('  ℹ️  No site folders found')
        
        site_removal_tasks[task_id]['progress'] = 65
        
        # Remove development folder
        append_output('')
        append_output('💻 Removing development folder...')
        
        # Detect actual user home directory (same logic as docker-manager.sh)
        if os.environ.get('SUDO_USER'):
            home_dir = os.path.expanduser(f"~{os.environ['SUDO_USER']}")
        else:
            home_dir = os.path.expanduser("~")
        
        dev_folder = f"{home_dir}/frappe-docker/{site_name}-frappe-bench"
        
        if os.path.exists(dev_folder):
            append_output(f'  🗑️  Removing: {dev_folder}')
            rm_dev_cmd = f'sudo rm -rf "{dev_folder}"'
            subprocess.run(rm_dev_cmd, shell=True, timeout=60)
            append_output('  ✅ Development folder removed')
        else:
            append_output(f'  ℹ️  Development folder not found: {dev_folder}')
        
        site_removal_tasks[task_id]['progress'] = 85
        
        # Update hosts file
        append_output('')
        append_output('📝 Updating hosts file...')
        site_domain = site_name.replace('_', '.')
        
        # Check if entry exists
        check_hosts_cmd = f'grep "{site_domain}" /etc/hosts 2>/dev/null'
        check_result = subprocess.run(check_hosts_cmd, shell=True, capture_output=True)
        
        if check_result.returncode == 0:
            append_output(f'  🗑️  Removing hosts entry for {site_domain}')
            sed_cmd = f'sudo sed -i "/{site_domain}/d" /etc/hosts'
            subprocess.run(sed_cmd, shell=True, timeout=30)
            append_output('  ✅ Hosts file updated')
        else:
            append_output('  ℹ️  No hosts entry found')
        
        site_removal_tasks[task_id]['progress'] = 90
        
        # Docker system cleanup
        append_output('')
        append_output('🧹 Cleaning up unused Docker resources...')
        cleanup_cmd = 'docker system prune -a --volumes -f'
        cleanup_result = subprocess.run(cleanup_cmd, shell=True, capture_output=True, text=True, timeout=300)
        if cleanup_result.returncode == 0:
            append_output('  ✅ Docker cleanup completed')
        
        # Show final disk usage
        append_output('')
        append_output('📊 Updated Docker Space Usage:')
        df_cmd = 'docker system df'
        df_result = subprocess.run(df_cmd, shell=True, capture_output=True, text=True, timeout=30)
        if df_result.stdout:
            for line in df_result.stdout.strip().split('\n'):
                append_output(f'  {line}')
        
        site_removal_tasks[task_id]['progress'] = 100
        site_removal_tasks[task_id]['status'] = 'completed'
        append_output('')
        append_output('=' * 60)
        append_output('🎉 COMPLETE CLEANUP FINISHED!')
        append_output('=' * 60)
        append_output(f'✅ All traces of {site_name} have been removed from the system')
        append_output('')
        append_output('✅ Successfully removed:')
        append_output('  ✔ Docker containers (app, db, redis, worker, scheduler, socketio)')
        append_output('  ✔ Docker volumes (all persistent data)')
        append_output('  ✔ Docker networks (custom networks)')
        append_output('  ✔ Docker images (site-specific images)')
        append_output('  ✔ Site folders (Docker-Local, Docker-on-VPS)')
        append_output('  ✔ Configuration files (docker-compose.yml)')
        append_output('  ✔ Development folders (frappe-bench)')
        append_output('  ✔ Hosts file entries')
        append_output('  ✔ Unused Docker resources (system prune)')
        append_output('')
        append_output('✨ Complete site removal finished successfully!')
        append_output(f'💾 Disk space has been reclaimed')
        append_output('')
        append_output('⚠️  Note: You may need to refresh the page to see updated container list')
        
    except Exception as e:
        logger.error(f"Error in site removal task: {str(e)}")
        site_removal_tasks[task_id]['status'] = 'failed'
        site_removal_tasks[task_id]['error'] = str(e)
        site_removal_tasks[task_id]['output'] += f'\n❌ Error: {str(e)}'

@app.route('/api/frappe/remove-site', methods=['POST'])
@require_auth
def remove_site_completely():
    """Start complete site removal task as a background thread"""
    try:
        data = request.json
        site_name = data.get('site_name')
        
        if not site_name:
            return jsonify({'error': 'Site name is required', 'success': False}), 400
        
        # Get base directory
        web_manager_dir = os.path.dirname(os.path.abspath(__file__))
        base_dir = os.path.dirname(web_manager_dir)
        
        # Generate unique task ID
        task_id = str(uuid.uuid4())
        
        # Initialize task status
        site_removal_tasks[task_id] = {
            'status': 'pending',
            'progress': 0,
            'message': 'Task queued...',
            'site_name': site_name,
            'created_at': datetime.now().isoformat(),
            'output': '',
            'error': None
        }
        
        # Start background thread
        thread = threading.Thread(
            target=run_site_removal_task,
            args=(task_id, site_name, base_dir)
        )
        thread.daemon = True
        thread.start()
        
        # Return task ID immediately
        return jsonify({
            'success': True,
            'task_id': task_id,
            'message': 'Site removal started in background',
            'site_name': site_name
        })
        
    except Exception as e:
        logger.error(f"Error starting site removal: {str(e)}")
        return jsonify({'error': str(e), 'success': False}), 500

@app.route('/api/frappe/remove-site/status/<task_id>', methods=['GET'])
@require_auth
def get_site_removal_status(task_id):
    """Get status of site removal task"""
    if task_id not in site_removal_tasks:
        return jsonify({'error': 'Task not found', 'success': False}), 404
    
    return jsonify({
        'success': True,
        'task': site_removal_tasks[task_id]
    })

if __name__ == '__main__':
    with app.app_context():
        # Initialize database and RBAC system
        db.create_all()
        init_rbac_system()
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

