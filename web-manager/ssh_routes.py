#!/usr/bin/env python3
"""
SSH Management API Routes
Clean API endpoints for SSH connection management
"""

from flask import Blueprint, request, jsonify, Response, session
from functools import wraps
import logging
from datetime import datetime, timedelta
from ssh_manager import ssh_manager
from models import AuditLog, db

# Setup logging
logger = logging.getLogger(__name__)

# Create SSH blueprint
ssh_bp = Blueprint('ssh', __name__, url_prefix='/api/ssh')

def require_auth(f):
    """Decorator to require authentication"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session or not session['logged_in']:
            return jsonify({'error': 'Authentication required'}), 401
        return f(*args, **kwargs)
    return decorated_function

def log_audit(event_type, username, ip, message, status="success", user_id=None):
    """Log security event to audit log"""
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

@ssh_bp.route('/sessions', methods=['GET'])
@require_auth
def get_ssh_sessions():
    """Get all active SSH sessions"""
    try:
        sessions = ssh_manager.get_ssh_sessions()
        
        # Log the action
        client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
        username = session.get('username', 'unknown')
        user_id = session.get('user_id')
        
        log_audit("ssh_sessions_viewed", username, client_ip, 
                  "Viewed SSH sessions", "success", user_id)
        
        return jsonify({
            'success': True,
            'sessions': sessions,
            'count': len(sessions)
        })
        
    except Exception as e:
        logger.error(f"Get SSH sessions error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

@ssh_bp.route('/create', methods=['POST'])
@require_auth
def create_ssh_session():
    """Create new SSH session"""
    try:
        data = request.json
        container = data.get('container')
        username = data.get('username', 'frappe')
        duration = int(data.get('duration', 24))  # hours
        port = data.get('port')
        description = data.get('description', '')
        
        if not container:
            return jsonify({'success': False, 'error': 'Container name is required'}), 400
        
        logger.info(f"Creating SSH session for container: {container}")
        
        # Create SSH session using the manager
        result = ssh_manager.create_ssh_session(
            container=container,
            username=username,
            duration=duration,
            port=port,
            description=description
        )
        
        # Log the action
        client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
        username_log = session.get('username', 'unknown')
        user_id = session.get('user_id')
        status = "success" if result['success'] else "failed"
        
        log_audit("ssh_session_created", username_log, client_ip, 
                  f"Created SSH session for {container}:{port or 'auto'} as {username}", 
                  status, user_id)
        
        if result['success']:
            logger.info(f"SSH session created successfully: {result['session']['session_id']}")
        else:
            logger.error(f"SSH session creation failed: {result['error']}")
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Create SSH session error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

@ssh_bp.route('/revoke', methods=['POST'])
@require_auth
def revoke_ssh_session():
    """Revoke SSH session"""
    try:
        data = request.json
        session_id = data.get('session_id')
        
        if not session_id:
            return jsonify({'success': False, 'error': 'Session ID is required'}), 400
        
        logger.info(f"Revoking SSH session: {session_id}")
        
        # Revoke SSH session using the manager
        result = ssh_manager.revoke_ssh_session(session_id)
        
        # Log the action
        client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
        username = session.get('username', 'unknown')
        user_id = session.get('user_id')
        status = "success" if result['success'] else "failed"
        
        log_audit("ssh_session_revoked", username, client_ip, 
                  f"Revoked SSH session {session_id}", status, user_id)
        
        if result['success']:
            logger.info(f"SSH session revoked successfully: {session_id}")
        else:
            logger.error(f"SSH session revocation failed: {result['error']}")
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Revoke SSH session error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

@ssh_bp.route('/download-key/<session_id>')
@require_auth
def download_ssh_key(session_id):
    """Download private key for SSH session"""
    try:
        logger.info(f"Downloading SSH key for session: {session_id}")
        
        # Get private key from SSH manager
        private_key = ssh_manager.get_session_private_key(session_id)
        
        if not private_key:
            return jsonify({'error': 'Session not found or expired'}), 404
        
        # Get session info for filename
        sessions = ssh_manager.get_ssh_sessions()
        session_info = next((s for s in sessions if s['session_id'] == session_id), None)
        
        if not session_info:
            return jsonify({'error': 'Session not found'}), 404
        
        key_name = f"ssh_key_{session_id[:8]}"
        
        # Log the action
        client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
        username = session.get('username', 'unknown')
        user_id = session.get('user_id')
        
        log_audit("ssh_key_downloaded", username, client_ip, 
                  f"Downloaded SSH key for session {session_id}", "success", user_id)
        
        # Create response with private key
        return Response(
            private_key,
            mimetype='application/octet-stream',
            headers={
                'Content-Disposition': f'attachment; filename={key_name}.pem'
            }
        )
        
    except Exception as e:
        logger.error(f"Download SSH key error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@ssh_bp.route('/status/<container>')
@require_auth
def check_ssh_status(container):
    """Check SSH server status in container"""
    try:
        logger.info(f"Checking SSH status for container: {container}")
        
        # Check if SSH server is running in container
        import subprocess
        cmd = ["sudo", "docker", "exec", container, "pgrep", "sshd"]
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()
        
        if process.returncode == 0:
            status = 'SSH server is running'
        else:
            status = 'SSH server is not running'
        
        # Log the action
        client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
        username = session.get('username', 'unknown')
        user_id = session.get('user_id')
        
        log_audit("ssh_status_checked", username, client_ip, 
                  f"Checked SSH status for {container}: {status}", "success", user_id)
        
        return jsonify({
            'success': True, 
            'status': status,
            'container': container
        })
        
    except Exception as e:
        logger.error(f"SSH status check error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

@ssh_bp.route('/extend', methods=['POST'])
@require_auth
def extend_ssh_session():
    """Extend SSH session duration"""
    try:
        data = request.json
        session_id = data.get('session_id')
        duration = int(data.get('duration', 24))  # hours
        
        if not session_id:
            return jsonify({'success': False, 'error': 'Session ID is required'}), 400
        
        logger.info(f"Extending SSH session: {session_id} by {duration} hours")
        
        # Get session from SSH manager
        sessions = ssh_manager.get_ssh_sessions()
        session_info = next((s for s in sessions if s['session_id'] == session_id), None)
        
        if not session_info:
            return jsonify({'success': False, 'error': 'Session not found'}), 404
        
        # Extend session (this would need to be implemented in ssh_manager)
        # For now, we'll create a new session with extended duration
        result = ssh_manager.create_ssh_session(
            container=session_info['container'],
            username=session_info['username'],
            duration=duration,
            port=session_info['port'],
            description=f"{session_info['description']} (Extended)"
        )
        
        # Revoke old session
        ssh_manager.revoke_ssh_session(session_id)
        
        # Log the action
        client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
        username = session.get('username', 'unknown')
        user_id = session.get('user_id')
        status = "success" if result['success'] else "failed"
        
        log_audit("ssh_session_extended", username, client_ip, 
                  f"Extended SSH session {session_id} by {duration} hours", status, user_id)
        
        if result['success']:
            logger.info(f"SSH session extended successfully: {session_id}")
        else:
            logger.error(f"SSH session extension failed: {result['error']}")
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Extend SSH session error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

@ssh_bp.route('/cleanup', methods=['POST'])
@require_auth
def cleanup_expired_sessions():
    """Clean up expired SSH sessions"""
    try:
        logger.info("Cleaning up expired SSH sessions")
        
        # Clean up expired sessions
        ssh_manager.cleanup_expired_sessions()
        
        # Log the action
        client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
        username = session.get('username', 'unknown')
        user_id = session.get('user_id')
        
        log_audit("ssh_sessions_cleaned", username, client_ip, 
                  "Cleaned up expired SSH sessions", "success", user_id)
        
        return jsonify({
            'success': True,
            'message': 'Expired sessions cleaned up successfully'
        })
        
    except Exception as e:
        logger.error(f"Cleanup SSH sessions error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500


@ssh_bp.route('/cleanup-orphaned', methods=['POST'])
@require_auth
def cleanup_orphaned_files():
    """Clean up orphaned log files"""
    try:
        username = session.get('username', 'unknown')
        ip = request.remote_addr
        
        # Run orphaned cleanup
        ssh_manager.cleanup_orphaned_log_files()
        
        # Log the action
        log_audit('ssh_cleanup', username, ip, 'Cleaned up orphaned SSH log files')
        
        return jsonify({
            'success': True,
            'message': 'Orphaned files cleaned up successfully'
        })
        
    except Exception as e:
        logger.error(f"Orphaned cleanup error: {str(e)}")
        log_audit('ssh_cleanup', session.get('username', 'unknown'), request.remote_addr, 
                 f'Orphaned cleanup failed: {str(e)}', 'error')
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@ssh_bp.route('/cleanup-orphaned-users', methods=['POST'])
@require_auth
def cleanup_orphaned_ssh_users():
    """Clean up orphaned SSH users from containers"""
    try:
        username = session.get('username', 'unknown')
        ip = request.remote_addr
        
        # Run orphaned SSH user cleanup
        ssh_manager.cleanup_orphaned_ssh_users()
        
        # Log the action
        log_audit('ssh_cleanup_users', username, ip, 'Cleaned up orphaned SSH users from containers')
        
        return jsonify({
            'success': True,
            'message': 'Orphaned SSH users cleaned up successfully'
        })
        
    except Exception as e:
        logger.error(f"Orphaned SSH user cleanup error: {str(e)}")
        log_audit('ssh_cleanup_users', session.get('username', 'unknown'), request.remote_addr, 
                 f'Orphaned SSH user cleanup failed: {str(e)}', 'error')
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500
@ssh_bp.route('/containers')
@require_auth
def get_containers():
    """Get list of available containers for SSH setup"""
    try:
        from app import SecureDockerManager
        
        containers = SecureDockerManager.get_containers()
        
        # Filter running containers
        running_containers = []
        for container in containers:
            if 'Up' in container.get('Status', ''):
                running_containers.append({
                    'name': container.get('Names', '').lstrip('/'),
                    'image': container.get('Image', ''),
                    'status': container.get('Status', ''),
                    'ports': container.get('Ports', '')
                })
        
        return jsonify({
            'success': True,
            'containers': running_containers,
            'count': len(running_containers)
        })
        
    except Exception as e:
        logger.error(f"Get containers error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

