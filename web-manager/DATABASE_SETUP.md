# Database Setup and Migration Guide

## 📋 Overview

This guide explains how to set up and manage the database for the Secure Docker Manager application. The application uses **MySQL/MariaDB** as the primary database with **SQLAlchemy** as the ORM.

## 🗄️ Database Architecture

### Tables Structure

#### 1. **Users Table**
```sql
- id (Primary Key)
- username (Unique)
- email (Unique)
- password_hash
- totp_secret
- totp_enabled (Boolean)
- is_active (Boolean)
- is_admin (Boolean)
- created_at (DateTime)
- last_login (DateTime)
- failed_login_count (Integer)
- locked_until (DateTime)
```

#### 2. **Audit Logs Table**
```sql
- id (Primary Key)
- event_type (String)
- username (String)
- ip_address (String)
- status (String)
- message (String)
- timestamp (DateTime)
```

## 🚀 Initial Setup

### Prerequisites

1. **MySQL/MariaDB Server** installed and running
2. **Python 3.8+** with virtual environment
3. **Required Python packages** installed

### Step 1: Install Required Packages

```bash
# Activate virtual environment
source web-docker-manager-env/bin/activate

# Install required packages
pip install flask flask-sqlalchemy pymysql pyotp qrcode pillow werkzeug
```

### Step 2: Database Configuration

The database configuration is defined in `config.py`:

```python
SQLALCHEMY_DATABASE_URI = 'mysql+pymysql://docker_user:docker_password@localhost/docker_manager'
```

### Step 3: Create Database and User

Run the database setup script to create the database and user:

```bash
# Navigate to web-manager directory
cd web-manager

# Run database setup
python3 setup_database.py
```

## 📊 Database Setup Script (`setup_database.py`)

### What it does:

1. **Creates Database Tables**
   - Uses `db.create_all()` to create all tables
   - Handles table creation automatically

2. **Creates Default Admin User**
   - Username: `admin`
   - Password: `admin123`
   - Email: `admin@localhost`
   - Admin privileges: `True`
   - 2FA: `Disabled` (optional)

3. **Generates TOTP Secret**
   - Creates TOTP secret for 2FA
   - Available for enabling 2FA later

### Usage:

```bash
# Basic setup
python3 setup_database.py

# Output example:
# 🚀 Initializing database...
# Creating database tables...
# ✅ Database tables created successfully.
# ✅ Default admin user 'admin' created with password 'admin123'
# ✅ Database setup completed successfully!
```

## 🔄 Migration Process

### Current Approach: Direct Table Creation

The application currently uses **direct table creation** instead of migrations:

```python
# In setup_database.py
with app.app_context():
    db.create_all()  # Creates all tables
```

### Why No Migrations?

1. **Simplicity**: Direct table creation is simpler for small applications
2. **No Schema Changes**: Current schema is stable
3. **Development Speed**: Faster setup for development

### Adding New Columns

If you need to add new columns to existing tables:

#### Method 1: Manual SQL (Recommended)

```sql
-- Example: Adding a new column
ALTER TABLE users ADD COLUMN new_field VARCHAR(255);

-- Example: Adding a new table
CREATE TABLE new_table (
    id INT PRIMARY KEY AUTO_INCREMENT,
    name VARCHAR(255),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

#### Method 2: Python Script

Create a migration script:

```python
#!/usr/bin/env python3
"""
Migration script example
"""
from app import app, db
from sqlalchemy import text

def add_new_column():
    with app.app_context():
        try:
            # Add new column
            db.session.execute(text("ALTER TABLE users ADD COLUMN new_field VARCHAR(255)"))
            db.session.commit()
            print("✅ Column added successfully")
        except Exception as e:
            print(f"❌ Error: {e}")
            db.session.rollback()

if __name__ == '__main__':
    add_new_column()
```

## 🛠️ Database Management Commands

### Common Operations

```bash
# 1. Reset Database (WARNING: Deletes all data)
mysql -u docker_user -p docker_manager -e "DROP DATABASE docker_manager; CREATE DATABASE docker_manager;"

# 2. Backup Database
mysqldump -u docker_user -p docker_manager > backup.sql

# 3. Restore Database
mysql -u docker_user -p docker_manager < backup.sql

# 4. Check Database Status
mysql -u docker_user -p -e "SHOW TABLES;" docker_manager

# 5. View Table Structure
mysql -u docker_user -p -e "DESCRIBE users;" docker_manager
```

### Python Database Operations

```python
# Connect to database
from app import app, db, User, AuditLog

with app.app_context():
    # Create new user
    user = User(username='newuser', email='user@example.com')
    user.set_password('password123')
    db.session.add(user)
    db.session.commit()
    
    # Query users
    users = User.query.all()
    admin_users = User.query.filter_by(is_admin=True).all()
    
    # Update user
    user = User.query.filter_by(username='admin').first()
    user.is_active = False
    db.session.commit()
    
    # Delete user
    user = User.query.filter_by(username='olduser').first()
    if user:
        db.session.delete(user)
        db.session.commit()
```

## 🔧 Troubleshooting

### Common Issues

#### 1. **Connection Error**
```
Error: (2003, "Can't connect to MySQL server")
```
**Solution:**
- Check if MySQL service is running
- Verify connection parameters in `config.py`
- Check firewall settings

#### 2. **Access Denied**
```
Error: (1045, "Access denied for user 'docker_user'@'localhost'")
```
**Solution:**
- Verify username and password
- Check user privileges
- Run: `GRANT ALL PRIVILEGES ON docker_manager.* TO 'docker_user'@'localhost';`

#### 3. **Table Already Exists**
```
Error: Table 'users' already exists
```
**Solution:**
- This is normal if tables already exist
- The script will continue without errors

#### 4. **Module Not Found**
```
ModuleNotFoundError: No module named 'flask_sqlalchemy'
```
**Solution:**
```bash
# Activate virtual environment
source web-docker-manager-env/bin/activate

# Install packages
pip install flask flask-sqlalchemy pymysql
```

### Debug Mode

Enable debug mode for detailed error messages:

```python
# In app.py
app.config['DEBUG'] = True
app.config['SQLALCHEMY_ECHO'] = True  # Shows SQL queries
```

## 📈 Performance Optimization

### Database Connection Pooling

The application uses connection pooling:

```python
SQLALCHEMY_ENGINE_OPTIONS = {
    'pool_recycle': 300,
    'pool_pre_ping': True,
    'pool_size': 10,
    'max_overflow': 20
}
```

### Indexing Recommendations

```sql
-- Add indexes for better performance
CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_audit_logs_timestamp ON audit_logs(timestamp);
CREATE INDEX idx_audit_logs_event_type ON audit_logs(event_type);
```

## 🔒 Security Considerations

### Database Security

1. **Use Strong Passwords**
2. **Limit Database User Privileges**
3. **Enable SSL Connections**
4. **Regular Backups**
5. **Monitor Access Logs**

### Application Security

1. **Password Hashing**: Uses Werkzeug's secure password hashing
2. **CSRF Protection**: Implemented with session tokens
3. **Input Validation**: All inputs are sanitized
4. **Audit Logging**: All actions are logged

## 📝 Maintenance

### Regular Tasks

1. **Backup Database** (Daily)
2. **Monitor Log Files** (Weekly)
3. **Update Dependencies** (Monthly)
4. **Security Audit** (Quarterly)

### Monitoring Queries

```sql
-- Check user activity
SELECT username, last_login, failed_login_count 
FROM users 
ORDER BY last_login DESC;

-- Check audit logs
SELECT event_type, COUNT(*) as count 
FROM audit_logs 
WHERE timestamp >= DATE_SUB(NOW(), INTERVAL 7 DAY)
GROUP BY event_type;

-- Check locked users
SELECT username, locked_until 
FROM users 
WHERE locked_until > NOW();
```

## 🆘 Support

### Getting Help

1. **Check Logs**: `tail -f docker-manager.log`
2. **Database Logs**: MySQL error logs
3. **Application Logs**: Flask debug output
4. **System Logs**: `journalctl -u mysql`

### Useful Commands

```bash
# Check MySQL status
systemctl status mysql

# Restart MySQL
sudo systemctl restart mysql

# Check database size
mysql -u docker_user -p -e "SELECT table_schema AS 'Database', ROUND(SUM(data_length + index_length) / 1024 / 1024, 2) AS 'Size (MB)' FROM information_schema.tables WHERE table_schema = 'docker_manager' GROUP BY table_schema;"

# Check table sizes
mysql -u docker_user -p -e "SELECT table_name AS 'Table', ROUND(((data_length + index_length) / 1024 / 1024), 2) AS 'Size (MB)' FROM information_schema.tables WHERE table_schema = 'docker_manager' ORDER BY (data_length + index_length) DESC;"
```

---

## 📚 Additional Resources

- [SQLAlchemy Documentation](https://docs.sqlalchemy.org/)
- [Flask-SQLAlchemy Documentation](https://flask-sqlalchemy.palletsprojects.com/)
- [MySQL Documentation](https://dev.mysql.com/doc/)
- [PyMySQL Documentation](https://pymysql.readthedocs.io/)

---

**Last Updated**: January 2025  
**Version**: 1.0  
**Maintainer**: Secure Docker Manager Team
