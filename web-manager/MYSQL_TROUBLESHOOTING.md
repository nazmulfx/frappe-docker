# MySQL Connection Troubleshooting Guide

This guide helps resolve MySQL connection issues that occur on different PC configurations.

## Common Error: `Access denied for user 'root'@'localhost'`

This error occurs because different systems have different MySQL authentication methods.

## Quick Solutions

### Solution 1: Use the Test Command
```bash
cd /var/www/html/docker2\ 15/web-manager
./docker-manager.sh test
```

This will test all possible connection methods and show you which one works.

### Solution 2: Manual MySQL Configuration

#### For Ubuntu/Debian Systems:
```bash
# Check MySQL service
sudo systemctl status mysql
sudo systemctl start mysql

# Connect to MySQL
sudo mysql -u root

# In MySQL prompt, run:
ALTER USER 'root'@'localhost' IDENTIFIED WITH mysql_native_password BY 'your_password';
FLUSH PRIVILEGES;
EXIT;
```

#### For CentOS/RHEL Systems:
```bash
# Check MySQL service
sudo systemctl status mysqld
sudo systemctl start mysqld

# Get temporary password
sudo grep 'temporary password' /var/log/mysqld.log

# Connect with temporary password
mysql -u root -p

# Change password
ALTER USER 'root'@'localhost' IDENTIFIED BY 'your_new_password';
FLUSH PRIVILEGES;
EXIT;
```

#### For Windows Systems:
1. Open Command Prompt as Administrator
2. Navigate to MySQL bin directory
3. Run: `mysql -u root -p`
4. Follow the same ALTER USER commands above

### Solution 3: Create a Dedicated User

Instead of using root, create a dedicated user:

```sql
-- Connect as root first
mysql -u root -p

-- Create new user
CREATE USER 'docker_user'@'localhost' IDENTIFIED BY 'docker_password';
GRANT ALL PRIVILEGES ON docker_manager.* TO 'docker_user'@'localhost';
FLUSH PRIVILEGES;
EXIT;
```

Then use these credentials in the setup:
- Username: `docker_user`
- Password: `docker_password`

## Different PC Configurations

### Configuration A: Auth Socket Plugin (Common on Ubuntu)
- MySQL uses system authentication
- Root user doesn't need password
- Solution: Leave password empty or use `sudo mysql`

### Configuration B: Native Password Authentication
- MySQL uses password authentication
- Root user has a password
- Solution: Use the password or reset it

### Configuration C: Mixed Authentication
- Some users use auth_socket, others use passwords
- Solution: Check user authentication method

### Configuration D: Different Host Binding
- MySQL binds to 127.0.0.1 instead of localhost
- Solution: Use 127.0.0.1 as host

## Step-by-Step Troubleshooting

### Step 1: Check MySQL Service
```bash
# Ubuntu/Debian
sudo systemctl status mysql
sudo systemctl start mysql

# CentOS/RHEL
sudo systemctl status mysqld
sudo systemctl start mysqld

# Windows
net start mysql
```

### Step 2: Check MySQL Configuration
```bash
# Check if MySQL is listening
netstat -tlnp | grep mysql
# or
ss -tlnp | grep mysql
```

### Step 3: Test Connection Methods
```bash
# Method 1: With password
mysql -u root -p

# Method 2: Without password (auth_socket)
sudo mysql -u root

# Method 3: With 127.0.0.1
mysql -h 127.0.0.1 -u root -p

# Method 4: Check user authentication
mysql -u root -p -e "SELECT user, host, plugin FROM mysql.user WHERE user='root';"
```

### Step 4: Fix Authentication Method
```sql
-- Connect to MySQL first, then run:
SELECT user, host, plugin FROM mysql.user WHERE user='root';

-- If plugin is 'auth_socket', change to 'mysql_native_password':
ALTER USER 'root'@'localhost' IDENTIFIED WITH mysql_native_password BY 'your_password';
FLUSH PRIVILEGES;
```

### Step 5: Test Application Connection
```bash
cd /var/www/html/docker2\ 15/web-manager
./docker-manager.sh test
```

## Environment-Specific Solutions

### Ubuntu 20.04/22.04
```bash
# Install MySQL
sudo apt update
sudo apt install mysql-server

# Secure installation
sudo mysql_secure_installation

# Fix root authentication
sudo mysql -u root
ALTER USER 'root'@'localhost' IDENTIFIED WITH mysql_native_password BY 'password';
FLUSH PRIVILEGES;
EXIT;
```

### CentOS 7/8
```bash
# Install MySQL
sudo yum install mysql-server
# or for CentOS 8
sudo dnf install mysql-server

# Start service
sudo systemctl start mysqld
sudo systemctl enable mysqld

# Get temporary password
sudo grep 'temporary password' /var/log/mysqld.log

# Change password
mysql -u root -p
ALTER USER 'root'@'localhost' IDENTIFIED BY 'new_password';
FLUSH PRIVILEGES;
EXIT;
```

### Windows 10/11
1. Download MySQL Installer from mysql.com
2. Install MySQL Server
3. During installation, set root password
4. Add MySQL to PATH environment variable
5. Test connection: `mysql -u root -p`

### macOS
```bash
# Install MySQL
brew install mysql

# Start service
brew services start mysql

# Secure installation
mysql_secure_installation

# Connect
mysql -u root -p
```

## Application Setup

After fixing MySQL, run the application setup:

```bash
cd /var/www/html/docker2\ 15/web-manager
./docker-manager.sh install
```

When prompted:
1. Enter MySQL host (usually `localhost` or `127.0.0.1`)
2. Enter MySQL username (usually `root`)
3. Enter MySQL password (the one you set)
4. Set admin password for the web interface

## Common Issues and Solutions

### Issue: "Can't connect to local MySQL server"
**Solution**: Start MySQL service
```bash
sudo systemctl start mysql  # Ubuntu/Debian
sudo systemctl start mysqld  # CentOS/RHEL
```

### Issue: "Access denied for user 'root'@'localhost'"
**Solution**: Fix authentication method
```sql
ALTER USER 'root'@'localhost' IDENTIFIED WITH mysql_native_password BY 'password';
FLUSH PRIVILEGES;
```

### Issue: "Unknown database 'docker_manager'"
**Solution**: The application will create it automatically, or create manually:
```sql
CREATE DATABASE docker_manager CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
```

### Issue: "Connection refused"
**Solution**: Check MySQL is running and listening on correct port
```bash
sudo netstat -tlnp | grep 3306
```

## Testing Your Setup

Run the test command to verify everything works:
```bash
./docker-manager.sh test
```

This will show you exactly which connection method works on your system.

## Need Help?

If you're still having issues:
1. Run `./docker-manager.sh test` and share the output
2. Check MySQL error logs: `sudo tail -f /var/log/mysql/error.log`
3. Verify MySQL version: `mysql --version`
4. Check system info: `uname -a`

The test script will automatically detect the correct configuration for your system.
