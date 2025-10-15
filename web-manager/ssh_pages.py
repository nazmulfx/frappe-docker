#!/usr/bin/env python3
"""
SSH Management Pages
HTML routes for SSH connection management
"""

from flask import Blueprint, render_template, request, session

# Create SSH pages blueprint
ssh_pages_bp = Blueprint('ssh_pages', __name__)

# Note: Permission checking is now handled by RBAC middleware
# All routes /ssh-manager and /ssh-sessions require 'ssh_access' permission

@ssh_pages_bp.route('/ssh-manager')
def ssh_manager_page():
    """SSH Manager main page - requires ssh_access permission (enforced by middleware)"""
    return render_template('ssh_manager.html')

@ssh_pages_bp.route('/ssh-sessions')
def ssh_sessions_page():
    """SSH Sessions page (alias for ssh-manager) - requires ssh_access permission (enforced by middleware)"""
    return render_template('ssh_manager.html')
