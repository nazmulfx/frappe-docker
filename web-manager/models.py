from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import pyotp

db = SQLAlchemy()

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
            'is_locked': self.is_locked()
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
        # Don't generate TOTP secret until user enables 2FA
        
        db.session.add(admin_user)
        db.session.commit()
        
        print("🔐 DEFAULT ADMIN USER CREATED!")
        print("=" * 50)
        print("Username: admin")
        print("Password: admin123")
        print("2FA Status: DISABLED (can be enabled in user settings)")
        print("=" * 50)
        print("⚠️  CHANGE THESE CREDENTIALS IMMEDIATELY!")
        print("📁 Access the user management panel to update")
        print("")
        return True
    return False
