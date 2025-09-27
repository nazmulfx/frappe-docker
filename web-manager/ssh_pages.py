#!/usr/bin/env python3
"""
SSH Management Pages
HTML routes for SSH connection management
"""

from flask import Blueprint, render_template, request, session
from functools import wraps

# Create SSH pages blueprint
ssh_pages_bp = Blueprint('ssh_pages', __name__)

def require_auth(f):
    """Decorator to require authentication"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session or not session['logged_in']:
            from flask import redirect, url_for
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@ssh_pages_bp.route('/ssh-manager')
@require_auth
def ssh_manager_page():
    """SSH Manager main page"""
    return render_template('ssh_manager.html')

@ssh_pages_bp.route('/ssh-sessions')
@require_auth
def ssh_sessions_page():
    """SSH Sessions page (alias for ssh-manager)"""
    return render_template('ssh_manager.html')
