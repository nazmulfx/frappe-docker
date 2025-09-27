import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key-change-in-production'
    
    # Database configuration with multiple fallback options
    DB_HOST = os.environ.get('DB_HOST') or 'localhost'
    DB_NAME = os.environ.get('DB_NAME') or 'docker_manager'
    DB_USER = os.environ.get('DB_USER') or 'root'
    DB_PASS = os.environ.get('DB_PASS') or ''
    
    # Try different connection methods
    @staticmethod
    def get_database_uri():
        """
        Generate database URI with multiple fallback options for different MySQL configurations
        """
        # Method 1: Try with password if provided
        if Config.DB_PASS:
            return f'mysql+pymysql://{Config.DB_USER}:{Config.DB_PASS}@{Config.DB_HOST}/{Config.DB_NAME}'
        
        # Method 2: Try without password (for systems with auth_socket plugin)
        return f'mysql+pymysql://{Config.DB_USER}@{Config.DB_HOST}/{Config.DB_NAME}'
    
    # Generate database URI after class definition
    SQLALCHEMY_DATABASE_URI = None
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_recycle': 300,
        'pool_pre_ping': True,
        'pool_size': 10,
        'max_overflow': 20,
        'connect_args': {
            'charset': 'utf8mb4',
            'autocommit': True,
            'init_command': "SET sql_mode='STRICT_TRANS_TABLES'"
        }
    }
    
    # Security Configuration
    MAX_LOGIN_ATTEMPTS = 300
    LOCKOUT_DURATION = 300  # 5 minutes
    SESSION_TIMEOUT = 3600  # 1 hour
    ALLOWED_IPS = ['127.0.0.1', '::1']
    REQUIRE_HTTPS = False  # Set to True for production
    ENABLE_AUDIT_LOG = True

# Set the database URI after class definition
Config.SQLALCHEMY_DATABASE_URI = Config.get_database_uri()
