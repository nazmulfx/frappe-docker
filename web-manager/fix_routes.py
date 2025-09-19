# Fix the backward compatibility routes placement
import re

# Read app.py
with open('app.py', 'r') as f:
    content = f.read()

# Find the backward compatibility section
backward_section = '''# Backward compatibility routes for old SSH endpoints
@app.route('/api/temp-ssh/setup', methods=['POST'])
@require_auth
def temp_ssh_setup_compat():
    """Backward compatibility for /api/temp-ssh/setup"""
    from ssh_manager import ssh_manager
    data = request.json
    container = data.get('container')
    username = data.get('username', 'frappe')
    duration = int(data.get('duration', 24))
    port = data.get('port')
    description = data.get('description', '')
    
    result = ssh_manager.create_ssh_session(container, username, duration, port, description)
    return jsonify(result)

@app.route('/api/temp-ssh/sessions')
@require_auth
def temp_ssh_sessions_compat():
    """Backward compatibility for /api/temp-ssh/sessions"""
    from ssh_manager import ssh_manager
    sessions = ssh_manager.get_ssh_sessions()
    return jsonify({'success': True, 'sessions': sessions})

@app.route('/api/temp-ssh/download-key/<session_id>')
@require_auth
def temp_ssh_download_key_compat(session_id):
    """Backward compatibility for /api/temp-ssh/download-key/<session_id>"""
    from ssh_manager import ssh_manager
    private_key = ssh_manager.get_session_private_key(session_id)
    if not private_key:
        return jsonify({'error': 'Session not found'}), 404
    
    return Response(private_key, mimetype='application/octet-stream',
                   headers={'Content-Disposition': f'attachment; filename=ssh_key_{session_id[:8]}.pem'})

@app.route('/api/temp-ssh/status/<container>')
@require_auth
def temp_ssh_status_compat(container):
    """Backward compatibility for /api/temp-ssh/status/<container>"""
    import subprocess
    cmd = ["sudo", "docker", "exec", container, "pgrep", "sshd"]
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()
    
    if process.returncode == 0:
        status = 'SSH server is running'
    else:
        status = 'SSH server is not running'
    
    return jsonify({'success': True, 'status': status})

@app.route('/api/temp-ssh/revoke', methods=['POST'])
@require_auth
def temp_ssh_revoke_compat():
    """Backward compatibility for /api/temp-ssh/revoke"""
    from ssh_manager import ssh_manager
    data = request.json
    session_id = data.get('session_id')
    result = ssh_manager.revoke_ssh_session(session_id)
    return jsonify(result)

@app.route('/api/temp-ssh/extend', methods=['POST'])
@require_auth
def temp_ssh_extend_compat():
    """Backward compatibility for /api/temp-ssh/extend"""
    from ssh_manager import ssh_manager
    data = request.json
    session_id = data.get('session_id')
    duration = int(data.get('duration', 24))
    
    # Get session and create new one with extended duration
    sessions = ssh_manager.get_ssh_sessions()
    session_info = next((s for s in sessions if s['session_id'] == session_id), None)
    
    if not session_info:
        return jsonify({'success': False, 'error': 'Session not found'}), 404
    
    # Create new session with extended duration
    result = ssh_manager.create_ssh_session(
        session_info['container'], session_info['username'], duration, 
        session_info['port'], f"{session_info['description']} (Extended)"
    )
    
    # Revoke old session
    ssh_manager.revoke_ssh_session(session_id)
    
    return jsonify(result)'''

# Remove the backward compatibility section from the end
content = content.replace(backward_section, '')

# Find the location before the if __name__ == '__main__': block
main_block_start = content.find("if __name__ == '__main__':")

if main_block_start != -1:
    # Insert the backward compatibility routes before the main block
    content = content[:main_block_start] + backward_section + "\n\n" + content[main_block_start:]
    
    # Write back
    with open('app.py', 'w') as f:
        f.write(content)
    
    print("✅ Backward compatibility routes moved to correct location!")
else:
    print("❌ Could not find if __name__ == '__main__': block")
