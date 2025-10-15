from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import pyotp

db = SQLAlchemy()

# Association tables for many-to-many relationships
user_roles = db.Table('user_roles',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
    db.Column('role_id', db.Integer, db.ForeignKey('role.id'), primary_key=True)
)

role_permissions = db.Table('role_permissions',
    db.Column('role_id', db.Integer, db.ForeignKey('role.id'), primary_key=True),
    db.Column('permission_id', db.Integer, db.ForeignKey('permission.id'), primary_key=True)
)

class Permission(db.Model):
    """Permission model - defines granular permissions"""
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)  # e.g., 'view_containers'
    display_name = db.Column(db.String(100), nullable=False)  # e.g., 'View Containers'
    description = db.Column(db.String(255))
    category = db.Column(db.String(50))  # e.g., 'containers', 'users', 'ssh', 'apps'
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'display_name': self.display_name,
            'description': self.description,
            'category': self.category
        }

class Role(db.Model):
    """Role model - defines user roles"""
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)  # e.g., 'admin', 'developer'
    display_name = db.Column(db.String(100), nullable=False)  # e.g., 'Administrator'
    description = db.Column(db.String(255))
    is_system = db.Column(db.Boolean, default=False)  # System roles can't be deleted
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    permissions = db.relationship('Permission', secondary=role_permissions, backref='roles')
    
    def has_permission(self, permission_name):
        """Check if role has a specific permission"""
        return any(p.name == permission_name for p in self.permissions)
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'display_name': self.display_name,
            'description': self.description,
            'is_system': self.is_system,
            'permissions': [p.name for p in self.permissions]
        }

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    totp_secret = db.Column(db.String(32), nullable=True)
    totp_enabled = db.Column(db.Boolean, default=False)  # New field for 2FA status
    is_active = db.Column(db.Boolean, default=True)
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime, nullable=True)
    failed_login_count = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime, nullable=True)
    
    # Relationships
    roles = db.relationship('Role', secondary=user_roles, backref='users')
    
    def has_role(self, role_name):
        """Check if user has a specific role"""
        return any(r.name == role_name for r in self.roles)
    
    def has_permission(self, permission_name):
        """Check if user has a specific permission through any of their roles"""
        # Admin role has all permissions
        if self.is_admin or self.has_role('admin'):
            return True
        
        for role in self.roles:
            if role.has_permission(permission_name):
                return True
        return False
    
    def get_all_permissions(self):
        """Get all permissions user has across all roles"""
        if self.is_admin or self.has_role('admin'):
            return Permission.query.all()
        
        permissions = set()
        for role in self.roles:
            permissions.update(role.permissions)
        return list(permissions)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def is_locked(self):
        if self.locked_until:
            return datetime.utcnow() < self.locked_until
        return False
    
    def lock_account(self, duration_minutes=5):
        self.locked_until = datetime.utcnow() + timedelta(minutes=duration_minutes)
        db.session.commit()
    
    def unlock_account(self):
        self.locked_until = None
        self.failed_login_count = 0
        db.session.commit()
    
    def record_failed_login(self):
        self.failed_login_count += 1
        if self.failed_login_count >= 3:  # MAX_LOGIN_ATTEMPTS
            self.lock_account()
        db.session.commit()
    
    def record_successful_login(self):
        self.failed_login_count = 0
        self.last_login = datetime.utcnow()
        self.locked_until = None
        db.session.commit()
    
    def generate_totp_secret(self):
        """Generate TOTP secret for user"""
        if not self.totp_secret:
            self.totp_secret = pyotp.random_base32()
        return self.totp_secret
    
    def get_totp_uri(self):
        """Get TOTP URI for QR code generation"""
        if self.totp_secret:
            return pyotp.totp.TOTP(self.totp_secret).provisioning_uri(
                name=self.username,
                issuer_name="Secure Docker Manager"
            )
        return None
    
    def verify_totp(self, token):
        """Verify TOTP token"""
        if self.totp_secret:
            totp = pyotp.TOTP(self.totp_secret)
            return totp.verify(token)
        return False
    
    def enable_2fa(self):
        """Enable 2FA for user"""
        if not self.totp_secret:
            self.totp_secret = pyotp.random_base32()
        self.totp_enabled = True
        db.session.commit()
    
    def disable_2fa(self):
        """Disable 2FA for user"""
        self.totp_enabled = False
        self.totp_secret = None
        db.session.commit()
    
    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'is_active': self.is_active,
            'is_admin': self.is_admin,
            'totp_enabled': self.totp_enabled,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'last_login': self.last_login.isoformat() if self.last_login else None,
            'failed_login_count': self.failed_login_count,
            'is_locked': self.is_locked(),
            'roles': [r.to_dict() for r in self.roles],
            'permissions': [p.name for p in self.get_all_permissions()]
        }

class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    username = db.Column(db.String(80), nullable=False)
    ip_address = db.Column(db.String(45), nullable=False)
    event_type = db.Column(db.String(50), nullable=False)
    message = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), default='success')
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'ip_address': self.ip_address,
            'event_type': self.event_type,
            'message': self.message,
            'status': self.status,
            'timestamp': self.timestamp.isoformat()
        }

def init_permissions():
    """Initialize default permissions"""
    permissions_data = [
        # Container permissions
        ('view_containers', 'View Containers', 'View Docker containers and their status', 'containers'),
        ('start_containers', 'Start Containers', 'Start Docker containers', 'containers'),
        ('stop_containers', 'Stop Containers', 'Stop Docker containers', 'containers'),
        ('restart_containers', 'Restart Containers', 'Restart Docker containers', 'containers'),
        ('remove_containers', 'Remove Containers', 'Remove Docker containers', 'containers'),
        ('view_logs', 'View Container Logs', 'View Docker container logs', 'containers'),
        ('exec_commands', 'Execute Commands', 'Execute commands in containers', 'containers'),
        
        # Application permissions
        ('install_apps', 'Install Apps', 'Install Frappe applications', 'apps'),
        ('uninstall_apps', 'Uninstall Apps', 'Uninstall Frappe applications', 'apps'),
        ('create_sites', 'Create Sites', 'Create new Frappe sites', 'apps'),
        ('backup_sites', 'Backup Sites', 'Backup Frappe sites', 'apps'),
        ('restore_sites', 'Restore Sites', 'Restore Frappe sites', 'apps'),
        ('migrate_sites', 'Migrate Sites', 'Migrate Frappe sites', 'apps'),
        
        # User management permissions
        ('view_users', 'View Users', 'View user accounts', 'users'),
        ('create_users', 'Create Users', 'Create new user accounts', 'users'),
        ('edit_users', 'Edit Users', 'Edit user accounts', 'users'),
        ('delete_users', 'Delete Users', 'Delete user accounts', 'users'),
        ('manage_roles', 'Manage Roles', 'Manage user roles and permissions', 'users'),
        
        # SSH permissions
        ('ssh_access', 'SSH Access', 'Access SSH terminals', 'ssh'),
        ('view_ssh_sessions', 'View SSH Sessions', 'View SSH sessions', 'ssh'),
        
        # Audit permissions
        ('view_audit_logs', 'View Audit Logs', 'View system audit logs', 'audit'),
        
        # System permissions
        ('view_dashboard', 'View Dashboard', 'Access main dashboard', 'system'),
        ('system_settings', 'System Settings', 'Modify system settings', 'system'),
    ]
    
    for name, display_name, description, category in permissions_data:
        if not Permission.query.filter_by(name=name).first():
            permission = Permission(
                name=name,
                display_name=display_name,
                description=description,
                category=category
            )
            db.session.add(permission)
    
    db.session.commit()
    print("✅ Permissions initialized")

def init_roles():
    """Initialize default roles with permissions"""
    # Get all permissions
    all_permissions = Permission.query.all()
    
    # Define roles with their permissions
    roles_data = [
        {
            'name': 'admin',
            'display_name': 'Administrator',
            'description': 'Full system access with all permissions',
            'is_system': True,
            'permissions': [p.name for p in all_permissions]  # Admin gets all permissions
        },
        {
            'name': 'manager',
            'display_name': 'Manager',
            'description': 'Can manage containers, apps, and view users',
            'is_system': True,
            'permissions': [
                'view_dashboard', 'view_containers', 'start_containers', 'stop_containers',
                'restart_containers', 'view_logs', 'install_apps', 'uninstall_apps',
                'create_sites', 'backup_sites', 'restore_sites', 'migrate_sites',
                'view_users', 'ssh_access', 'view_ssh_sessions', 'view_audit_logs'
            ]
        },
        {
            'name': 'developer',
            'display_name': 'Developer',
            'description': 'Can manage containers and applications',
            'is_system': True,
            'permissions': [
                'view_dashboard', 'view_containers', 'start_containers', 'stop_containers',
                'restart_containers', 'view_logs', 'exec_commands', 'install_apps',
                'create_sites', 'backup_sites', 'migrate_sites', 'ssh_access'
            ]
        },
        {
            'name': 'operator',
            'display_name': 'Operator',
            'description': 'Can start/stop containers and view logs',
            'is_system': True,
            'permissions': [
                'view_dashboard', 'view_containers', 'start_containers', 'stop_containers',
                'restart_containers', 'view_logs', 'backup_sites'
            ]
        },
        {
            'name': 'viewer',
            'display_name': 'Viewer',
            'description': 'Read-only access to view containers and logs',
            'is_system': True,
            'permissions': [
                'view_dashboard', 'view_containers', 'view_logs', 'view_audit_logs'
            ]
        }
    ]
    
    for role_data in roles_data:
        role = Role.query.filter_by(name=role_data['name']).first()
        if not role:
            role = Role(
                name=role_data['name'],
                display_name=role_data['display_name'],
                description=role_data['description'],
                is_system=role_data['is_system']
            )
            db.session.add(role)
            db.session.flush()  # Get the role ID
        
        # Add permissions to role
        role.permissions.clear()
        for perm_name in role_data['permissions']:
            permission = Permission.query.filter_by(name=perm_name).first()
            if permission and permission not in role.permissions:
                role.permissions.append(permission)
    
    db.session.commit()
    print("✅ Roles initialized")

def create_default_admin():
    """Create default admin user if no users exist"""
    if User.query.count() == 0:
        admin_user = User(
            username='admin',
            email='admin@localhost',
            is_admin=True,
            is_active=True,
            totp_enabled=False  # 2FA disabled by default
        )
        admin_user.set_password('admin123')
        
        db.session.add(admin_user)
        db.session.flush()  # Get user ID
        
        # Assign admin role
        admin_role = Role.query.filter_by(name='admin').first()
        if admin_role:
            admin_user.roles.append(admin_role)
        
        db.session.commit()
        
        print("🔐 DEFAULT ADMIN USER CREATED!")
        print("=" * 50)
        print("Username: admin")
        print("Password: admin123")
        print("Role: Administrator (Full Access)")
        print("2FA Status: DISABLED (can be enabled in user settings)")
        print("=" * 50)
        print("⚠️  CHANGE THESE CREDENTIALS IMMEDIATELY!")
        print("📁 Access the user management panel to update")
        print("")
        return True
    return False

def init_rbac_system():
    """Initialize the complete RBAC system (permissions, roles, default admin)"""
    try:
        init_permissions()
        init_roles()
        create_default_admin()
        print("✅ RBAC System initialized successfully")
        return True
    except Exception as e:
        print(f"❌ Error initializing RBAC system: {e}")
        db.session.rollback()
        return False
