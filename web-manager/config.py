import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key-change-in-production'
    SQLALCHEMY_DATABASE_URI = 'mysql+pymysql://docker_user:docker_password@localhost/docker_manager'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_recycle': 300,
        'pool_pre_ping': True,
        'pool_size': 10,
        'max_overflow': 20
    }
    
    # Security Configuration
    MAX_LOGIN_ATTEMPTS = 300
    LOCKOUT_DURATION = 300  # 5 minutes
    SESSION_TIMEOUT = 3600  # 1 hour
    ALLOWED_IPS = ['127.0.0.1', '::1']
    REQUIRE_HTTPS = False  # Set to True for production
    ENABLE_AUDIT_LOG = True
