"""
Role-Based Access Control (RBAC) decorators and utilities
"""

from functools import wraps
from flask import session, flash, redirect, url_for, jsonify, request
from models import User

def require_permission(permission_name):
    """Decorator to require a specific permission"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            user_id = session.get('user_id')
            if not user_id:
                if request.is_json or request.path.startswith('/api/'):
                    return jsonify({'success': False, 'error': 'Authentication required'}), 401
                flash('Please log in to access this page', 'error')
                return redirect(url_for('login'))
            
            user = User.query.get(user_id)
            if not user:
                if request.is_json or request.path.startswith('/api/'):
                    return jsonify({'success': False, 'error': 'User not found'}), 401
                session.clear()
                return redirect(url_for('login'))
            
            # Check if user has the required permission
            if not user.has_permission(permission_name):
                # Create user-friendly permission names
                permission_display_names = {
                    'view_containers': 'View Containers',
                    'start_containers': 'Start Containers',
                    'stop_containers': 'Stop Containers',
                    'restart_containers': 'Restart Containers',
                    'remove_containers': 'Remove Containers',
                    'view_logs': 'View Container Logs',
                    'exec_commands': 'Execute Commands',
                    'install_apps': 'Install Applications',
                    'uninstall_apps': 'Uninstall Applications',
                    'create_sites': 'Create/Remove Sites',
                    'backup_sites': 'Backup Sites',
                    'restore_sites': 'Restore Sites',
                    'migrate_sites': 'Migrate Sites',
                    'view_users': 'View Users',
                    'create_users': 'Create Users',
                    'edit_users': 'Edit Users',
                    'delete_users': 'Delete Users',
                    'manage_roles': 'Manage Roles & Permissions',
                    'ssh_access': 'SSH Access',
                    'view_audit_logs': 'View Audit Logs',
                    'view_dashboard': 'View Dashboard'
                }
                perm_display = permission_display_names.get(permission_name, permission_name)
                
                if request.is_json or request.path.startswith('/api/'):
                    return jsonify({
                        'success': False,
                        'error': f'Permission denied: {perm_display}',
                        'message': f'You need the "{perm_display}" permission to perform this action.',
                        'code': 'PERMISSION_DENIED',
                        'required_permission': permission_name,
                        'help': 'Contact your administrator to request access.'
                    }), 403
                user_roles = ', '.join([r.display_name for r in user.roles]) if user.roles else 'No roles assigned'
                flash(
                    f'<strong>Access Denied!</strong><br>'
                    f'You need the <strong>"{perm_display}"</strong> permission to access this page.<br>'
                    f'<small class="d-block mt-2">Your current roles: {user_roles}</small>'
                    f'<small class="d-block mt-1 text-muted">Contact your administrator to request access.</small>',
                    'permission_denied'
                )
                return redirect(url_for('index'))
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def require_any_permission(*permission_names):
    """Decorator to require any one of the specified permissions"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            user_id = session.get('user_id')
            if not user_id:
                if request.is_json or request.path.startswith('/api/'):
                    return jsonify({'success': False, 'error': 'Authentication required'}), 401
                flash('Please log in to access this page', 'error')
                return redirect(url_for('login'))
            
            user = User.query.get(user_id)
            if not user:
                if request.is_json or request.path.startswith('/api/'):
                    return jsonify({'success': False, 'error': 'User not found'}), 401
                session.clear()
                return redirect(url_for('login'))
            
            # Check if user has any of the required permissions
            has_permission = any(user.has_permission(perm) for perm in permission_names)
            if not has_permission:
                if request.is_json or request.path.startswith('/api/'):
                    return jsonify({
                        'success': False,
                        'error': 'Permission denied',
                        'message': f'You need at least one of these permissions: {", ".join(permission_names)}',
                        'code': 'PERMISSION_DENIED',
                        'required_permissions': list(permission_names),
                        'help': 'Contact your administrator to request access.'
                    }), 403
                user_roles = ', '.join([r.display_name for r in user.roles]) if user.roles else 'No roles assigned'
                flash(
                    f'<strong>Access Denied!</strong><br>'
                    f'You need at least one of the required permissions to access this page.<br>'
                    f'<small class="d-block mt-2">Your current roles: {user_roles}</small>'
                    f'<small class="d-block mt-1 text-muted">Contact your administrator to request access.</small>',
                    'permission_denied'
                )
                return redirect(url_for('index'))
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def require_all_permissions(*permission_names):
    """Decorator to require all of the specified permissions"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            user_id = session.get('user_id')
            if not user_id:
                if request.is_json or request.path.startswith('/api/'):
                    return jsonify({'success': False, 'error': 'Authentication required'}), 401
                flash('Please log in to access this page', 'error')
                return redirect(url_for('login'))
            
            user = User.query.get(user_id)
            if not user:
                if request.is_json or request.path.startswith('/api/'):
                    return jsonify({'success': False, 'error': 'User not found'}), 401
                session.clear()
                return redirect(url_for('login'))
            
            # Check if user has all required permissions
            has_all = all(user.has_permission(perm) for perm in permission_names)
            if not has_all:
                missing_perms = [p for p in permission_names if not user.has_permission(p)]
                if request.is_json or request.path.startswith('/api/'):
                    return jsonify({
                        'success': False,
                        'error': 'Permission denied',
                        'message': f'You need all of these permissions: {", ".join(permission_names)}',
                        'code': 'PERMISSION_DENIED',
                        'required_permissions': list(permission_names),
                        'missing_permissions': missing_perms,
                        'help': 'Contact your administrator to request access.'
                    }), 403
                user_roles = ', '.join([r.display_name for r in user.roles]) if user.roles else 'No roles assigned'
                flash(
                    f'<strong>Access Denied!</strong><br>'
                    f'You need all of the required permissions to access this page.<br>'
                    f'<small class="d-block mt-2">Your current roles: {user_roles}</small>'
                    f'<small class="d-block mt-1 text-muted">Contact your administrator to request access.</small>',
                    'permission_denied'
                )
                return redirect(url_for('index'))
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def require_role(role_name):
    """Decorator to require a specific role"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            user_id = session.get('user_id')
            if not user_id:
                if request.is_json or request.path.startswith('/api/'):
                    return jsonify({'success': False, 'error': 'Authentication required'}), 401
                flash('Please log in to access this page', 'error')
                return redirect(url_for('login'))
            
            user = User.query.get(user_id)
            if not user:
                if request.is_json or request.path.startswith('/api/'):
                    return jsonify({'success': False, 'error': 'User not found'}), 401
                session.clear()
                return redirect(url_for('login'))
            
            # Check if user has the required role
            if not user.has_role(role_name) and not user.is_admin:
                if request.is_json or request.path.startswith('/api/'):
                    return jsonify({
                        'success': False,
                        'error': f'Access denied: {role_name} role required',
                        'message': f'You need the "{role_name}" role to perform this action.',
                        'code': 'ROLE_REQUIRED',
                        'required_role': role_name,
                        'help': 'Contact your administrator to request the required role.'
                    }), 403
                user_roles = ', '.join([r.display_name for r in user.roles]) if user.roles else 'No roles assigned'
                flash(
                    f'<strong>Access Denied!</strong><br>'
                    f'You need the <strong>"{role_name}"</strong> role to access this page.<br>'
                    f'<small class="d-block mt-2">Your current roles: {user_roles}</small>'
                    f'<small class="d-block mt-1 text-muted">Contact your administrator to request the required role.</small>',
                    'permission_denied'
                )
                return redirect(url_for('index'))
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def get_current_user():
    """Helper function to get current logged-in user"""
    user_id = session.get('user_id')
    if user_id:
        return User.query.get(user_id)
    return None

def check_permission(permission_name):
    """Helper function to check if current user has a permission"""
    user = get_current_user()
    if user:
        return user.has_permission(permission_name)
    return False


