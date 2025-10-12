"""
RBAC Middleware - Request filtering and permission checking
Intercepts all requests and validates user permissions before reaching route handlers
"""

from flask import request, session, redirect, url_for, jsonify, g
from functools import wraps
import re
from models import User

class RBACMiddleware:
    """
    Role-Based Access Control Middleware
    Filters all requests through permission checking
    """
    
    def __init__(self, app=None):
        self.app = app
        self.route_permissions = {}
        self.public_routes = set()
        self.route_patterns = []
        
        if app:
            self.init_app(app)
    
    def init_app(self, app):
        """Initialize middleware with Flask app"""
        self.app = app
        
        # Register before_request handler
        app.before_request(self.check_permissions)
        
        # Define public routes (no authentication required)
        self.public_routes = {
            '/login',
            '/logout',
            '/static/<path:filename>',
            '/_debug_toolbar/<path:filename>',  # Flask debug toolbar
        }
        
        # Define route-permission mappings
        self.define_route_permissions()
    
    def define_route_permissions(self):
        """
        Define which permissions are required for each route
        Routes not listed here will require authentication but no specific permission
        """
        
        # Dashboard and main routes
        self.route_permissions['/'] = 'view_dashboard'
        self.route_permissions['/dashboard'] = 'view_dashboard'
        
        # Container management routes
        self.add_pattern_permission(r'^/api/container/[^/]+/action$', 'start_containers')  # Will be refined per action
        self.add_pattern_permission(r'^/api/container/[^/]+/logs$', 'view_logs')
        self.add_pattern_permission(r'^/api/container/[^/]+/exec$', 'exec_commands')
        self.route_permissions['/api/containers/list'] = 'view_containers'
        
        # User management routes
        self.route_permissions['/users'] = 'view_users'
        self.route_permissions['/api/users'] = 'view_users'  # GET
        self.add_pattern_permission(r'^/api/users/\d+$', 'view_users')  # GET single user
        self.add_pattern_permission(r'^/api/users/\d+/roles$', 'manage_roles')  # GET/POST roles
        self.add_pattern_permission(r'^/api/users/\d+/unlock$', 'edit_users')  # Unlock user
        
        # Role management routes
        self.route_permissions['/roles'] = 'manage_roles'
        self.route_permissions['/api/roles'] = 'manage_roles'
        self.route_permissions['/api/permissions'] = 'manage_roles'
        self.add_pattern_permission(r'^/api/roles/\d+$', 'manage_roles')
        self.add_pattern_permission(r'^/api/roles/\d+/permissions$', 'manage_roles')
        
        # Application/Site management routes
        self.add_pattern_permission(r'^/api/frappe/.*install.*$', 'install_apps')
        self.add_pattern_permission(r'^/api/frappe/.*uninstall.*$', 'uninstall_apps')
        self.add_pattern_permission(r'^/api/frappe/create-site.*$', 'create_sites')
        self.add_pattern_permission(r'^/api/frappe/remove-site.*$', 'create_sites')  # Requires same permission
        self.add_pattern_permission(r'^/api/frappe/backup.*$', 'backup_sites')
        self.add_pattern_permission(r'^/api/frappe/restore.*$', 'restore_sites')
        self.add_pattern_permission(r'^/api/frappe/migrate.*$', 'migrate_sites')
        self.add_pattern_permission(r'^/api/frappe/rebuild-with-apps.*$', 'install_apps')
        self.add_pattern_permission(r'^/api/frappe/fix-restart-policies.*$', 'start_containers')
        
        # Frappe command execution routes (SECURITY: execute_commands permission required)
        self.route_permissions['/api/frappe/execute-command'] = 'execute_commands'
        self.route_permissions['/api/frappe/validate-container'] = 'view_containers'
        self.route_permissions['/api/frappe/get-current-dir'] = 'view_containers'
        self.route_permissions['/api/frappe/list-containers'] = 'view_containers'
        self.route_permissions['/api/frappe/terminal-logs'] = 'view_logs'
        self.route_permissions['/api/frappe/clear-terminal-logs'] = 'view_logs'
        self.route_permissions['/api/frappe/get-erpnext-versions'] = 'view_dashboard'
        self.route_permissions['/app-installation'] = 'install_apps'
        
        # Task management routes
        self.add_pattern_permission(r'^/api/tasks/.*$', 'view_dashboard')
        
        # SSH routes - both web and API
        self.route_permissions['/ssh-manager'] = 'ssh_access'
        self.route_permissions['/ssh-sessions'] = 'ssh_access'
        self.add_pattern_permission(r'^/api/ssh/.*$', 'ssh_access')
        self.add_pattern_permission(r'^/api/temp-ssh/.*$', 'ssh_access')
        
        # Audit logs
        self.route_permissions['/audit-logs'] = 'view_audit_logs'
        self.route_permissions['/api/audit-logs'] = 'view_audit_logs'
        
        # Profile routes (any authenticated user)
        self.route_permissions['/profile'] = None  # Any authenticated user
        self.route_permissions['/profile/edit'] = None
        self.route_permissions['/user-profile'] = None
        self.route_permissions['/api/profile'] = None
        self.add_pattern_permission(r'^/api/users/\d+/toggle-2fa$', None)  # Users can toggle their own 2FA
    
    def add_pattern_permission(self, pattern, permission):
        """Add a regex pattern with required permission"""
        self.route_patterns.append({
            'pattern': re.compile(pattern),
            'permission': permission
        })
    
    def is_public_route(self, path):
        """Check if route is public (no authentication required)"""
        # Exact match
        if path in self.public_routes:
            return True
        
        # Static files
        if path.startswith('/static/'):
            return True
        
        # Favicon and common public assets
        if path in ['/favicon.ico', '/robots.txt']:
            return True
        
        return False
    
    def get_required_permission(self, path, method):
        """
        Get required permission for a route
        Returns None if no specific permission required (but authentication still needed)
        Returns False if route is public
        """
        # Check if public route
        if self.is_public_route(path):
            return False
        
        # Check exact match
        if path in self.route_permissions:
            return self.route_permissions[path]
        
        # Check pattern match
        for pattern_info in self.route_patterns:
            if pattern_info['pattern'].match(path):
                return pattern_info['permission']
        
        # Special handling for different HTTP methods
        permission = None
        
        # API routes with specific method requirements
        if path.startswith('/api/users') and method == 'POST':
            if '/api/users/' in path and path.endswith('/unlock'):
                permission = 'edit_users'
            else:
                permission = 'create_users'
        
        elif path.startswith('/api/users/') and method == 'PUT':
            permission = 'edit_users'
        
        elif path.startswith('/api/users/') and method == 'DELETE':
            permission = 'delete_users'
        
        elif path.startswith('/api/container/') and '/action' in path and method == 'POST':
            # Will check action type in check_permissions
            permission = 'start_containers'  # Base permission, refined later
        
        return permission
    
    def get_current_user(self):
        """Get current logged-in user"""
        user_id = session.get('user_id')
        if user_id:
            return User.query.get(user_id)
        return None
    
    def check_permissions(self):
        """
        Main middleware function - checks permissions before each request
        Called automatically by Flask before_request
        """
        # Store request start time
        g.request_start_time = __import__('time').time()
        
        path = request.path
        method = request.method
        
        # Get required permission for this route
        required_permission = self.get_required_permission(path, method)
        
        # Public route - allow access
        if required_permission is False:
            return None
        
        # Check if user is authenticated
        if 'logged_in' not in session or not session.get('logged_in'):
            # Not authenticated
            if request.is_json or path.startswith('/api/'):
                return jsonify({
                    'success': False,
                    'error': 'Authentication required',
                    'code': 'AUTH_REQUIRED'
                }), 401
            else:
                return redirect(url_for('login'))
        
        # Get current user
        user = self.get_current_user()
        if not user:
            session.clear()
            if request.is_json or path.startswith('/api/'):
                return jsonify({
                    'success': False,
                    'error': 'Invalid session',
                    'code': 'INVALID_SESSION'
                }), 401
            else:
                return redirect(url_for('login'))
        
        # Store user in g for easy access in route handlers
        g.current_user = user
        
        # Check if user is active
        if not user.is_active:
            session.clear()
            if request.is_json or path.startswith('/api/'):
                return jsonify({
                    'success': False,
                    'error': 'Account is inactive',
                    'code': 'ACCOUNT_INACTIVE'
                }), 403
            else:
                return redirect(url_for('login'))
        
        # Check if user is locked
        if user.is_locked():
            if request.is_json or path.startswith('/api/'):
                return jsonify({
                    'success': False,
                    'error': 'Account is locked',
                    'code': 'ACCOUNT_LOCKED'
                }), 403
            else:
                return redirect(url_for('login'))
        
        # No specific permission required - authenticated user is enough
        if required_permission is None:
            return None
        
        # Refine permission based on action for container operations
        if path.startswith('/api/container/') and '/action' in path:
            action = request.json.get('action') if request.is_json else None
            if action == 'start':
                required_permission = 'start_containers'
            elif action == 'stop':
                required_permission = 'stop_containers'
            elif action == 'restart':
                required_permission = 'restart_containers'
            elif action == 'remove':
                required_permission = 'remove_containers'
        
        # Check if user has required permission
        if not user.has_permission(required_permission):
            # Permission denied - create helpful message
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
                'view_dashboard': 'View Dashboard',
                'system_settings': 'System Settings'
            }
            
            perm_display = permission_display_names.get(required_permission, required_permission)
            
            if request.is_json or path.startswith('/api/'):
                return jsonify({
                    'success': False,
                    'error': f'Permission denied: {perm_display}',
                    'message': f'You need the "{perm_display}" permission to perform this action.',
                    'code': 'PERMISSION_DENIED',
                    'required_permission': required_permission,
                    'help': 'Contact your administrator to request access.'
                }), 403
            else:
                from flask import flash
                user_roles = ', '.join([r.display_name for r in user.roles]) if user.roles else 'No roles assigned'
                flash(
                    f'<strong>Access Denied!</strong><br>'
                    f'You need the <strong>"{perm_display}"</strong> permission to access this page.<br>'
                    f'<small class="d-block mt-2">Your current roles: {user_roles}</small>'
                    f'<small class="d-block mt-1 text-muted">Contact your administrator to request access.</small>',
                    'permission_denied'
                )
                return redirect(url_for('index'))
        
        # All checks passed - allow request
        return None
    
    def after_request(self, response):
        """
        After request handler - can add headers, log requests, etc.
        """
        # Add security headers
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        
        # Add custom permission header for debugging (in development only)
        if self.app.debug and hasattr(g, 'current_user'):
            if g.current_user:
                response.headers['X-User-Roles'] = ','.join([r.name for r in g.current_user.roles])
        
        return response


# Global middleware instance
rbac_middleware = RBACMiddleware()


def init_middleware(app):
    """
    Initialize RBAC middleware with Flask app
    Call this in your app.py after creating the Flask app
    """
    rbac_middleware.init_app(app)
    
    # Register after_request handler
    app.after_request(rbac_middleware.after_request)
    
    print("✅ RBAC Middleware initialized")
    print(f"   - Route permissions: {len(rbac_middleware.route_permissions)}")
    print(f"   - Pattern permissions: {len(rbac_middleware.route_patterns)}")
    print(f"   - Public routes: {len(rbac_middleware.public_routes)}")
    
    return rbac_middleware


