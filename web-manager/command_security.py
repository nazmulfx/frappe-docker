#!/usr/bin/env python3
"""
Command Security Module
Comprehensive security validation for command execution
"""

import re
import logging
from typing import Dict, List, Tuple, Optional

logger = logging.getLogger(__name__)

class CommandSecurityValidator:
    """Validates and sanitizes commands for secure execution"""
    
    # Dangerous commands that should NEVER be executed
    DANGEROUS_COMMANDS = [
        # Destructive filesystem operations
        r'rm\s+-rf\s+/',
        r'rm\s+-rf\s+/\*',
        r'rm\s+-rf\s+~',
        r'rm\s+-rf\s+\.',
        r'dd\s+if=',
        r'mkfs\.',
        r'format\s+',
        
        # Privilege escalation
        r'sudo\s+su',
        r'sudo\s+bash',
        r'sudo\s+sh',
        r'chmod\s+777',
        r'chmod\s+-R\s+777',
        
        # Network attacks
        r'curl.*\|\s*bash',
        r'wget.*\|\s*bash',
        r'curl.*\|\s*sh',
        r'wget.*\|\s*sh',
        r'nc\s+-l',
        r'ncat\s+-l',
        r'socat.*EXEC',
        
        # Docker escapes
        r'docker\s+run.*--privileged',
        r'docker\s+exec.*root.*bash',
        r'docker\s+run.*-v\s+/:/host',
        
        # System modification
        r'iptables',
        r'systemctl.*stop',
        r'systemctl.*disable',
        r'kill\s+-9\s+1',
        r'reboot',
        r'shutdown',
        r'init\s+0',
        r'init\s+6',
        
        # Backdoors and persistence
        r'crontab.*-e',
        r'at\s+now',
        r'nohup.*&',
        r'disown',
        
        # Sensitive file access
        r'cat\s+/etc/shadow',
        r'cat\s+/etc/passwd.*\|',
        r'cat.*\.ssh/id_rsa',
        r'cat.*\.ssh/id_dsa',
        r'cat.*\.ssh/id_ecdsa',
        
        # Package manager abuse
        r'apt-get.*install.*ssh',
        r'yum.*install.*ssh',
        r'pip.*install.*--target',
        
        # Crypto mining
        r'xmrig',
        r'minerd',
        r'cpuminer',
        
        # Code injection
        r'eval\s*\(',
        r'exec\s*\(',
        r'__import__\s*\(',
        r'compile\s*\(',
        
        # Reverse shells
        r'bash.*-i.*>&',
        r'nc.*-e\s+/bin/bash',
        r'python.*socket.*exec',
    ]
    
    # Allowed safe commands for Frappe/ERPNext
    ALLOWED_COMMANDS = [
        # Bench commands - Basic (safe, read-only or routine operations)
        r'^bench\s+--version$',
        r'^bench\s+version$',
        r'^bench\s+-v$',
        r'^bench\s+doctor$',
        r'^bench\s+list-apps$',
        r'^bench\s+migrate$',
        r'^bench\s+clear-cache$',
        r'^bench\s+clear-website-cache$',
        r'^bench\s+backup$',
        r'^bench\s+backup\s+--with-files$',
        r'^bench\s+backup\s+--with-private-files$',
        r'^bench\s+backup\s+--with-public-files$',
        r'^bench\s+restore$',
        r'^bench\s+restore\s+[\w\./\-]+$',
        r'^bench\s+restart$',
        r'^bench\s+build$',
        r'^bench\s+build\s+--app\s+[\w\-]+$',
        r'^bench\s+build(\s+--force)?$',
        r'^bench\s+build\s+--app\s+[\w\-]+(\s+--force)?$',
        r'^bench\s+status$',
        r'^bench\s+switch-to-branch\s+[\w\-\.]+$',
        r'^bench\s+switch-to-branch\s+[\w\-\.]+\s+[\w\-]+$',
        
        # Bench commands - With site parameter
        r'^bench\s+--site\s+[\w\.\-]+\s+migrate$',
        r'^bench\s+--site\s+[\w\.\-]+\s+clear-cache$',
        r'^bench\s+--site\s+[\w\.\-]+\s+clear-website-cache$',
        r'^bench\s+--site\s+[\w\.\-]+\s+backup$',
        r'^bench\s+--site\s+[\w\.\-]+\s+backup\s+--with-files$',
        r'^bench\s+--site\s+[\w\.\-]+\s+backup\s+--with-private-files$',
        r'^bench\s+--site\s+[\w\.\-]+\s+backup\s+--with-public-files$',
        r'^bench\s+--site\s+[\w\.\-]+\s+restore\s+[\w\.\-/]+$',
        r'^bench\s+--site\s+[\w\.\-]+\s+list-apps$',
        r'^bench\s+--site\s+[\w\.\-]+\s+console$',
        r'^bench\s+--site\s+[\w\.\-]+\s+mariadb$',
        r'^bench\s+--site\s+[\w\.\-]+\s+mariadb\s+--execute\s+"[^"]*"$',
        r'^bench\s+--site\s+[\w\.\-]+\s+scheduler\s+(status|enable|disable|pause|resume)$',
        r'^bench\s+--site\s+[\w\.\-]+\s+set-config\s+[\w\-]+\s+[\w\-\.]+$',
        r'^bench\s+--site\s+[\w\.\-]+\s+browse$',
        r'^bench\s+--site\s+[\w\.\-]+\s+add-to-hosts$',
        
        # Bench update commands (with various flags)
        r'^bench\s+update\s+--patch$',
        r'^bench\s+update\s+--build$',
        r'^bench\s+update\s+--requirements$',
        r'^bench\s+update\s+--restart-supervisor$',
        r'^bench\s+update\s+--no-backup$',
        r'^bench\s+update(\s+--[\w\-]+)*$',
        
        # Safe filesystem commands
        r'^ls(\s+-[\w]+)*(\s+[\w\./\-\*~]+)?$',
        r'^ls\s+-[1d]\s+[\w\./\-\*~]+/?$',
        r'^ll(\s+-[\w]+)*(\s+[\w\./\-\*]+)?$',
        r'^pwd$',
        r'^cd(\s+[\w\./\-~]+)?$',
        r'^cat\s+[\w\./\-~]+\.(txt|log|json|yml|yaml|conf|config|py|js|html|css|md|sh|xml|csv|ini)$',
        r'^cat\s+~/frappe-bench/sites/(apps\.txt|currentsite\.txt|common_site_config\.json)$',
        r'^cat\s+~/frappe-bench/sites/[\w\.\-]+/site_config\.json$',
        r'^cat\s+~/frappe-bench/sites/[\w\.\-]+/(apps\.txt|currentsite\.txt|site_config\.json)$',
        
        # Heredoc file creation (cat > file << 'EOF' ... EOF)
        # Allows creating temp scripts in /tmp for Frappe maintenance
        r"^cat\s+>\s+/tmp/[\w\-_]+\.(py|sh|txt|json|conf)\s+<<\s+['\"]?[A-Z]+['\"]?.*",
        r'^tail\s+(-[fnF]+\s*)*(-?\d+\s+)?[\w\./\-~]+\.(txt|log|json|err|out)$',
        r'^tail\s+-\d+\s+[\w\./\-~]+\.(txt|log|json|err|out)$',
        r'^tail\s+-[fnF]\s+[\w\./\-~]+\.(txt|log|json|err|out)$',
        r'^head\s+(-n\s*\d+|\s+)*[\w\./\-]+\.(txt|log|json|err|out)$',
        r'^find\s+[\w\./\-~]+\s+-name\s+[\"\']?[\w\*\.\-]+[\"\']?$',
        r'^find\s+[\w\./\-~]+\s+-type\s+[fd](\s+-name\s+[\"\']?[\w\*\.\-]+[\"\']?)?$',
        r'^find\s+~/frappe-bench/sites/[\w\.\-]+/private/backups/?\s+-name\s+[\"\']?\*\.(sql|tar|gz|sql\.gz)[\"\']?$',
        r'^grep\s+(-[rinvE]+|\s+)*[\"\']?[\w\s\-]+[\"\']?\s+[\w\./\-\*]+$',
        r'^less\s+[\w\./\-]+\.(txt|log|json|py|js|md|conf|yml|yaml)$',
        r'^more\s+[\w\./\-]+\.(txt|log|json|py|js|md|conf|yml|yaml)$',
        r'^wc\s+(-[lwc]+|\s+)*[\w\./\-]+$',
        r'^tree(\s+-[\w]+)*(\s+[\w\./\-]+)?$',
        r'^file\s+[\w\./\-]+$',
        r'^stat\s+[\w\./\-]+$',
        
        # Safe information commands
        r'^ps(\s+aux)?$',
        r'^top\s+-bn1$',
        r'^df\s+-h$',
        r'^du\s+-sh(\s+[\w\./\-]+)?$',
        r'^free\s+-[mh]$',
        r'^uptime$',
        r'^whoami$',
        r'^id$',
        r'^date$',
        r'^hostname$',
        
        # Git commands (read-only)
        r'^git\s+(status|log|diff|branch|show|remote)(\s+[\w\.\-/]+)?$',
        r'^git\s+log\s+--oneline(\s+-\d+)?$',
        r'^git\s+log\s+(-\d+|--graph|--all|\s+)*$',
        r'^git\s+branch(\s+-[avrld])*$',
        r'^git\s+remote\s+-v$',
        r'^git\s+diff\s+[\w\.\-/]+$',
        r'^git\s+show\s+[\w\.\-:]+$',
        r'^git\s+config\s+--list$',
        r'^git\s+config\s+--get\s+[\w\.]+$',
        
        # Frappe-specific
        r'^frappe\s+--version$',
        r'^frappe\s+--help$',
        r'^python\s+-m\s+frappe\.commands\..*$',
        r'^python\s+--version$',
        r'^python3\s+--version$',
        
        # Execute Python/shell scripts from /tmp (for maintenance scripts)
        r'^python3?\s+/tmp/[\w\-_]+\.py$',
        r'^bash\s+/tmp/[\w\-_]+\.sh$',
        r'^sh\s+/tmp/[\w\-_]+\.sh$',
        
        # Execute script and cleanup (safe - only /tmp files)
        r'^python3?\s+/tmp/[\w\-_]+\.py\s+&&\s+rm\s+-f\s+/tmp/[\w\-_]+\.py$',
        r'^bash\s+/tmp/[\w\-_]+\.sh\s+&&\s+rm\s+-f\s+/tmp/[\w\-_]+\.sh$',
        r'^sh\s+/tmp/[\w\-_]+\.sh\s+&&\s+rm\s+-f\s+/tmp/[\w\-_]+\.sh$',
        
        # Safe rm operations (only /tmp files, not recursive)
        r'^rm\s+-f\s+/tmp/[\w\-_]+\.(py|sh|txt|json|conf|log)$',
        
        # Bench Python/Frappe operations
        r'^bench\s+--site\s+[\w\.\-]+\s+execute\s+[\w\.\-]+$',
        r'^bench\s+--site\s+[\w\.\-]+\s+run-patch\s+[\w\.\-]+$',
        r'^bench\s+--site\s+[\w\.\-]+\s+show-config$',
        r'^bench\s+--site\s+[\w\.\-]+\s+enable-scheduler$',
        r'^bench\s+--site\s+[\w\.\-]+\s+disable-scheduler$',
        r'^bench\s+--site\s+[\w\.\-]+\s+scheduler\s+(status|enable|disable|pause|resume)$',
        r'^bench\s+--site\s+[\w\.\-]+\s+set-admin-password\s+[\w@#$%^&*\-]+$',
        r'^bench\s+--site\s+[\w\.\-]+\s+use$',
        
        # Environment inspection
        r'^env$',
        r'^printenv(\s+\w+)?$',
        r'^echo\s+\$[\w_]+$',
        r'^echo\s+[\"\']?[:\w\s\.\-/]+[\"\']?$',
        r'^which\s+[\w\-]+$',
        r'^whereis\s+[\w\-]+$',
        
        # Echo commands (port numbers, simple strings)
        r'^echo\s+[\"\']?:[0-9]+[\"\']?(\s+&&\s+echo\s+[\"\']?:[0-9]+[\"\']?)*$',
        
        # Node/NPM (safe)
        r'^node\s+--version$',
        r'^npm\s+--version$',
        r'^npm\s+list(\s+--depth=\d+)?$',
        r'^yarn\s+--version$',
        r'^yarn\s+list(\s+--depth=\d+)?$',
        
        # Database inspection (safe)
        r'^bench\s+--site\s+[\w\.\-]+\s+mariadb\s+--execute\s+"SELECT\s+[^;]+;"$',
        r'^bench\s+--site\s+[\w\.\-]+\s+mariadb\s+--execute\s+"SHOW\s+[^;]+;"$',
        r'^bench\s+--site\s+[\w\.\-]+\s+mariadb\s+--execute\s+"DESCRIBE\s+[^;]+;"$',
        
        # Piped commands (safe combinations - grep, head, echo fallback, xargs)
        # Allow complex grep patterns with escaped quotes and regex patterns
        r'^cat\s+[\w\./\-~]+\.(txt|json|yml|yaml|conf|config)\s+2>/dev/null\s+\|\s+grep\s+(-[a-zA-Z]+\s+)?[\'"][^\'"]*\\"?[^\'"]*[\'"]?\s+\|\s+head\s+(-\d+|\d+)(\s+\|\|\s+echo\s+[\'"][^\'"]*[\'"])?$',
        r'^cat\s+[\w\./\-~]+\.(txt|json|yml|yaml|conf|config)\s+\|\s+grep\s+(-[a-zA-Z]+\s+)?[\'"][^\'"]+[\'"]?\s+\|\s+head\s+(-\d+|\d+)?$',
        # Simpler pattern for the specific case
        r'^cat\s+~/frappe-bench/sites/[\w\-]+\.json\s+2>/dev/null\s+\|\s+grep\s+-o\s+.*\s+\|\s+head\s+-?\d+(\s+\|\|\s+echo\s+.*)?$',
        
        # List directories with pipes (safe combinations for listing sites/logs)
        # Generic pattern that handles various quote styles and patterns
        r'^ls\s+-[1d]\s+~/frappe-bench/(sites|logs)/[\w\./\-\*]*/?(\s+\|\s+grep\s+-v\s+.+)?\s*(\|\s+xargs\s+-n\s+\d+\s+basename)?$',
        # Just ls without pipes
        r'^ls\s+-[1d]\s+~/frappe-bench/(sites|apps|logs)/[\w\./\-\*]*$',
        
        # Supervisor control (service management)
        r'^/?home/frappe/\.local/bin/supervisorctl\s+-c\s+/home/frappe/supervisor/supervisord\.conf\s+(status|restart|start|stop)(\s+(all|[\w\-:]+))?$',
        r'^/home/frappe/\.local/bin/supervisorctl\s+-c\s+/home/frappe/supervisor/supervisord\.conf\s+(status|restart|start|stop)(\s+(all|[\w\-:]+))?$',
        r'^supervisorctl\s+-c\s+[\w\./\-]+\s+(status|restart|start|stop)(\s+(all|[\w\-:]+))?$',
        r'^supervisorctl\s+(status|restart|start|stop)(\s+(all|[\w\-:]+))?$',
    ]
    
    # Commands that require special permissions (execute_privileged_commands)
    PRIVILEGED_COMMANDS = [
        # App management
        r'^bench\s+get-app\s+[\w\-]+$',
        r'^bench\s+get-app\s+[\w\-]+\s+--branch\s+[\w\-\.]+$',
        r'^bench\s+get-app\s+[\w\-]+(\s+--branch\s+[\w\-\.]+)?(\s+--overwrite)?$',
        r'^bench\s+get-app\s+https?://[^\s]+$',
        r'^bench\s+get-app\s+https?://[^\s]+\s+--branch\s+[\w\-\.]+$',
        r'^bench\s+get-app\s+https?://[^\s]+(\s+--branch\s+[\w\-\.]+)?(\s+--overwrite)?$',
        r'^bench\s+install-app\s+[\w\-]+$',
        r'^bench\s+--site\s+[\w\.\-]+\s+install-app\s+[\w\-]+$',
        r'^bench\s+--site\s+[\w\.\-]+\s+install-app\s+[\w\-]+\s+--force$',
        r'^bench\s+uninstall-app\s+[\w\-]+$',
        r'^bench\s+--site\s+[\w\.\-]+\s+uninstall-app\s+[\w\-]+$',
        r'^bench\s+--site\s+[\w\.\-]+\s+uninstall-app\s+[\w\-]+\s+--force$',
        r'^bench\s+remove-app\s+[\w\-]+$',
        r'^bench\s+--site\s+[\w\.\-]+\s+remove-app\s+[\w\-]+$',
        
        # Site management
        r'^bench\s+new-site\s+[\w\.\-]+$',
        r'^bench\s+new-site\s+[\w\.\-]+\s+--admin-password\s+[\w@#$%^&*\-]+$',
        r'^bench\s+new-site\s+[\w\.\-]+\s+--db-name\s+[\w\-]+$',
        r'^bench\s+drop-site\s+[\w\.\-]+$',
        r'^bench\s+--site\s+[\w\.\-]+\s+reinstall$',
        r'^bench\s+--site\s+[\w\.\-]+\s+migrate-to\s+[\w\.\-]+$',
        
        # Update commands (potentially dangerous, require privileged)
        r'^bench\s+update$',
        r'^bench\s+update\s+--reset$',
        
        # Package installation
        r'^pip\s+install\s+[\w\-\[\]]+$',
        r'^pip3\s+install\s+[\w\-\[\]]+$',
        r'^npm\s+install\s+(-g\s+)?[\w@/\-]+$',
        r'^yarn\s+install$',
        r'^yarn\s+add\s+[\w@/\-]+$',
        r'^yarn\s+global\s+add\s+[\w@/\-]+$',
        
        # Git operations
        r'^git\s+pull$',
        r'^git\s+pull\s+origin\s+[\w\-\.]+$',
        r'^git\s+push$',
        r'^git\s+push\s+origin\s+[\w\-\.]+$',
        r'^git\s+commit\s+-m\s+["\'][^"\']*["\']$',
        r'^git\s+commit\s+-am\s+["\'][^"\']*["\']$',
        r'^git\s+clone\s+https?://[^\s]+$',
        r'^git\s+checkout\s+[\w\-\.]+$',
        r'^git\s+checkout\s+-b\s+[\w\-\.]+$',
        r'^git\s+merge\s+[\w\-\.]+$',
        r'^git\s+rebase\s+[\w\-\.]+$',
        
        # Bench setup/configuration (advanced)
        r'^bench\s+setup\s+[\w\-]+$',
        r'^bench\s+config\s+[\w\-]+\s+[\w\-\.]+$',
    ]
    
    # Maximum command length (increased for heredoc scripts)
    MAX_COMMAND_LENGTH = 5000
    
    # Suspicious patterns (excluding legitimate uses)
    SUSPICIOUS_PATTERNS = [
        r'&\s*$',  # Background execution (but not && for chaining)
        r';\s*;',  # Multiple commands (but not single ;)
        r'`.*`',  # Command substitution
        r'\$\(.*\)',  # Command substitution (but allow \$VAR)
        r'>\s*/dev/(?!null)',  # Writing to devices (except /dev/null)
        r'<\s*/dev/(?!null)',  # Reading from devices (except /dev/null)
        r'\*\s*\*',  # Double wildcards
        r'\.\.\/.*\.\.\/',  # Multiple path traversals
    ]
    
    def __init__(self):
        self.dangerous_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in self.DANGEROUS_COMMANDS]
        self.allowed_patterns = [re.compile(pattern) for pattern in self.ALLOWED_COMMANDS]
        self.privileged_patterns = [re.compile(pattern) for pattern in self.PRIVILEGED_COMMANDS]
        self.suspicious_patterns = [re.compile(pattern) for pattern in self.SUSPICIOUS_PATTERNS]
    
    def validate_command(self, command: str, allow_privileged: bool = False) -> Tuple[bool, Optional[str], str]:
        """
        Validate command for security
        
        Returns:
            (is_valid, error_message, risk_level)
            risk_level: 'safe', 'privileged', 'suspicious', 'dangerous'
        """
        if not command or not command.strip():
            return False, "Empty command", "dangerous"
        
        # Remove leading/trailing whitespace
        command = command.strip()
        
        # Check command length
        if len(command) > self.MAX_COMMAND_LENGTH:
            logger.warning(f"Command too long: {len(command)} chars")
            return False, f"Command exceeds maximum length of {self.MAX_COMMAND_LENGTH} characters", "dangerous"
        
        # Check for dangerous commands (highest priority)
        for pattern in self.dangerous_patterns:
            if pattern.search(command):
                logger.error(f"Dangerous command blocked: {command}")
                return False, f"Dangerous command detected: This command is blocked for security reasons", "dangerous"
        
        # Check for suspicious patterns
        suspicious_count = 0
        suspicious_matches = []
        for pattern in self.suspicious_patterns:
            if pattern.search(command):
                suspicious_count += 1
                suspicious_matches.append(pattern.pattern)
        
        if suspicious_count >= 2:
            logger.warning(f"Highly suspicious command: {command}")
            return False, f"Suspicious command pattern detected: {', '.join(suspicious_matches)}", "suspicious"
        
        # Check if command requires privileged permissions
        for pattern in self.privileged_patterns:
            if pattern.match(command):
                if not allow_privileged:
                    logger.warning(f"Privileged command attempted without permission: {command}")
                    return False, "This command requires elevated permissions. Contact your administrator.", "privileged"
                logger.info(f"Privileged command allowed: {command}")
                return True, None, "privileged"
        
        # Check against allowed commands
        for pattern in self.allowed_patterns:
            if pattern.match(command):
                return True, None, "safe"
        
        # If command contains suspicious patterns but not too many, allow with warning
        if suspicious_count == 1:
            logger.warning(f"Command contains suspicious pattern but allowed: {command}")
            return True, None, "suspicious"
        
        # Command doesn't match any allowed pattern
        logger.warning(f"Command not in whitelist: {command}")
        return False, "This command is not in the allowed list. For security reasons, only whitelisted commands are permitted.", "unknown"
    
    def sanitize_container_name(self, container: str) -> Tuple[bool, Optional[str]]:
        """
        Validate and sanitize container name
        
        Returns:
            (is_valid, error_message)
        """
        if not container or not container.strip():
            return False, "Container name is required"
        
        container = container.strip()
        
        # Check length
        if len(container) > 255:
            return False, "Container name too long"
        
        # Only allow alphanumeric, dash, underscore, and dot
        if not re.match(r'^[a-zA-Z0-9_\-\.]+$', container):
            logger.warning(f"Invalid container name: {container}")
            return False, "Invalid container name format"
        
        # Block path traversal attempts
        if '..' in container or '/' in container or '\\' in container:
            logger.error(f"Path traversal attempt in container name: {container}")
            return False, "Invalid container name"
        
        return True, None
    
    def sanitize_path(self, path: str) -> Tuple[bool, Optional[str]]:
        """
        Validate and sanitize directory path
        
        Returns:
            (is_valid, error_message)
        """
        if not path or not path.strip():
            return False, "Path is required"
        
        path = path.strip()
        
        # Check length
        if len(path) > 4096:
            return False, "Path too long"
        
        # Must start with /
        if not path.startswith('/'):
            # Allow relative paths like '.', '..', './folder'
            if not re.match(r'^\.\.?(/[\w\-\.]+)*$', path):
                return False, "Invalid path format"
        
        # Block dangerous paths
        dangerous_paths = [
            '/etc/shadow',
            '/etc/passwd',
            '/root/.ssh',
            '/home/*/.ssh/id_',
            '/.ssh/',
            '/proc/',
            '/sys/',
            '/dev/',
        ]
        
        for dangerous in dangerous_paths:
            if dangerous in path or path.startswith(dangerous.rstrip('*')):
                logger.error(f"Access to dangerous path blocked: {path}")
                return False, "Access to this path is not allowed"
        
        # Only allow safe characters
        if not re.match(r'^[a-zA-Z0-9_\-\./]+$', path):
            logger.warning(f"Invalid characters in path: {path}")
            return False, "Path contains invalid characters"
        
        # Check for path traversal patterns
        if '../' * 3 in path or '/..' in path:
            logger.error(f"Path traversal attempt: {path}")
            return False, "Path traversal is not allowed"
        
        return True, None
    
    def get_command_risk_score(self, command: str) -> int:
        """
        Calculate risk score for a command (0-100)
        Higher score = more dangerous
        """
        score = 0
        
        # Dangerous command patterns
        for pattern in self.dangerous_patterns:
            if pattern.search(command):
                score += 100
                return min(score, 100)
        
        # Suspicious patterns
        for pattern in self.suspicious_patterns:
            if pattern.search(command):
                score += 20
        
        # Privileged operations
        for pattern in self.privileged_patterns:
            if pattern.match(command):
                score += 30
        
        # Check for special characters
        special_chars = ['|', '&', ';', '`', '$', '>', '<']
        for char in special_chars:
            if char in command:
                score += 5
        
        # Long commands are more suspicious
        if len(command) > 200:
            score += 10
        
        return min(score, 100)


# Create global validator instance
command_validator = CommandSecurityValidator()


def validate_command_security(command: str, container: str, current_dir: str, 
                             allow_privileged: bool = False) -> Tuple[bool, Optional[str], Dict]:
    """
    Comprehensive security validation for command execution
    
    Returns:
        (is_valid, error_message, security_info)
    """
    security_info = {
        'command_validated': False,
        'container_validated': False,
        'path_validated': False,
        'risk_level': 'unknown',
        'risk_score': 0
    }
    
    # Validate command
    is_valid, error, risk_level = command_validator.validate_command(command, allow_privileged)
    security_info['command_validated'] = is_valid
    security_info['risk_level'] = risk_level
    security_info['risk_score'] = command_validator.get_command_risk_score(command)
    
    if not is_valid:
        return False, error, security_info
    
    # Validate container name
    is_valid, error = command_validator.sanitize_container_name(container)
    security_info['container_validated'] = is_valid
    
    if not is_valid:
        return False, error, security_info
    
    # Validate path
    is_valid, error = command_validator.sanitize_path(current_dir)
    security_info['path_validated'] = is_valid
    
    if not is_valid:
        return False, error, security_info
    
    return True, None, security_info

