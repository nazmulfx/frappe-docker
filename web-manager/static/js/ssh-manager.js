// SSH Manager JavaScript Module
// Temporary SSH Access Management
let currentSSHSession = null;

// Initialize SSH event listeners
function initializeSSHEventListeners() {
    const tempSSHForm = document.getElementById('temp-ssh-form');
    const checkStatusBtn = document.getElementById('check-ssh-status');
    const downloadKeyBtn = document.getElementById('download-private-key');
    const copyCommandBtn = document.getElementById('copy-ssh-command');
    const revokeBtn = document.getElementById('revoke-access');
    const extendBtn = document.getElementById('extend-access');
    
    if (tempSSHForm) {
        tempSSHForm.addEventListener('submit', handleTempSSHSetup);
    }
    
    if (checkStatusBtn) {
        checkStatusBtn.addEventListener('click', checkSSHStatus);
    }
    
    if (downloadKeyBtn) {
        downloadKeyBtn.addEventListener('click', downloadPrivateKey);
    }
    
    if (copyCommandBtn) {
        copyCommandBtn.addEventListener('click', copySSHCommand);
    }
    
    if (revokeBtn) {
        revokeBtn.addEventListener('click', revokeSSHAccess);
    }
    
    if (extendBtn) {
        extendBtn.addEventListener('click', extendSSHAccess);
    }
    
    // Load existing sessions on page load
    loadSSHSessions();
}

// Handle temporary SSH setup
async function handleTempSSHSetup(e) {
    e.preventDefault();
    
    const container = document.getElementById('temp-container-select').value;
    const username = document.getElementById('temp-username').value;
    const duration = document.getElementById('temp-duration').value;
    const port = document.getElementById('temp-port').value;
    const description = document.getElementById('temp-description').value;
    
    if (!container || !username) {
        showToast('Please select a container and enter username', 'error');
        return;
    }
    
    updateAccessInfo('Setting up SSH access...', 'warning');
    hideSSHConnectionDetails()
    
    try {
        const response = await fetch('/api/temp-ssh/setup', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                container: container,
                username: username,
                duration: duration,
                port: port,
                description: description
            })
        });
        
        const result = await response.json();
        
        if (result.success) {
            currentSSHSession = result.session;
            showSSHConnectionDetails(currentSSHSession,result.connection_details);
            updateAccessInfo('SSH access configured successfully!', 'success');
            showToast('Temporary SSH access created', 'success');
            loadSSHSessions(); // Refresh sessions table
        } else {
            updateAccessInfo(`SSH setup failed: ${result.error}`, 'danger');
            showToast(`SSH setup failed: ${result.error}`, 'error');
        }
    } catch (error) {
        updateAccessInfo(`SSH setup error: ${error.message}`, 'danger');
        showToast(`SSH setup error: ${error.message}`, 'error');
    }
}
function log(data){
    console.log(data)
}
// Show SSH connection details
function showSSHConnectionDetails(session, connectionDetails) {
    const detailsDiv = document.getElementById('ssh-connection-details');
    const hostInfo = document.getElementById('ssh-host-info');
    const portInfo = document.getElementById('ssh-port-info');
    const usernameInfo = document.getElementById('ssh-username-info');
    const keyInfo = document.getElementById('ssh-key-info');
    
    // Use connectionDetails if available, otherwise fall back to session
    const host = connectionDetails?.host || session?.host;
    const port = connectionDetails?.port || session?.port;
    const username = connectionDetails?.username || session?.username || 'frappe';
    const keyName = connectionDetails?.key_name || session?.key_name || 'temp_ssh_key';
    
    if (detailsDiv) detailsDiv.style.display = 'block';
    if (hostInfo) hostInfo.textContent = `Host: ${host}`;
    if (portInfo) portInfo.textContent = `Port: ${port}`;
    if (usernameInfo) usernameInfo.textContent = `Username: ${username}`;
    if (keyInfo) keyInfo.textContent = `Key: ${keyName}`;
    
    // Store current session for download
    window.currentSSHSession = session;
    
    // Show action buttons
    const revokeBtn = document.getElementById('revoke-access');
    const extendBtn = document.getElementById('extend-access');
    if (revokeBtn) revokeBtn.style.display = 'inline-block';
    if (extendBtn) extendBtn.style.display = 'inline-block';
}

// Download private key
async function downloadPrivateKey() {
    if (!currentSSHSession) {
        showToast('No active SSH session', 'error');
        return;
    }
    
    try {
        const response = await fetch(`/api/temp-ssh/download-key/${currentSSHSession.session_id}`);
        const blob = await response.blob();
        
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `${currentSSHSession.key_name}.pem`;
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        document.body.removeChild(a);
        
        showToast('Private key downloaded', 'success');
    } catch (error) {
        showToast(`Download failed: ${error.message}`, 'error');
    }
}

// Copy SSH command to clipboard
async function copySSHCommand() {
    if (!currentSSHSession) {
        showToast('No active SSH session', 'error');
        return;
    }
    
    const sshCommand = `ssh -i ${currentSSHSession.key_name}.pem -p ${currentSSHSession.port} ${currentSSHSession.username}@${currentSSHSession.host}`;
    
    try {
        await navigator.clipboard.writeText(sshCommand);
        showToast('SSH command copied to clipboard', 'success');
    } catch (error) {
        showToast(`Copy failed: ${error.message}`, 'error');
    }
}

// Check SSH status
async function checkSSHStatus() {
    const container = document.getElementById('temp-container-select').value;
    
    if (!container) {
        showToast('Please select a container', 'error');
        return;
    }
    
    try {
        const response = await fetch(`/api/temp-ssh/status/${container}`);
        const result = await response.json();
        
        if (result.success) {
            updateAccessInfo(`SSH Status: ${result.status}`, 'info');
            showToast(`SSH Status: ${result.status}`, 'info');
        } else {
            updateAccessInfo(`SSH Status Check Failed: ${result.error}`, 'danger');
            showToast(`Status check failed: ${result.error}`, 'error');
        }
    } catch (error) {
        updateAccessInfo(`Status check error: ${error.message}`, 'danger');
        showToast(`Status check error: ${error.message}`, 'error');
    }
}

// Revoke SSH access
async function revokeSSHAccess() {
    if (!currentSSHSession) {
        showToast('No active SSH session', 'error');
        return;
    }
    
    if (!confirm('Are you sure you want to revoke SSH access?')) {
        return;
    }
    
    try {
        const response = await fetch('/api/temp-ssh/revoke', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                session_id: currentSSHSession.session_id
            })
        });
        
        const result = await response.json();
        
        if (result.success) {
            currentSSHSession = null;
            hideSSHConnectionDetails();
            updateAccessInfo('SSH access revoked', 'info');
            showToast('SSH access revoked', 'info');
            loadSSHSessions(); // Refresh sessions table
        } else {
            showToast(`Revoke failed: ${result.error}`, 'error');
        }
    } catch (error) {
        showToast(`Revoke error: ${error.message}`, 'error');
    }
}

// Extend SSH access
async function extendSSHAccess() {
    if (!currentSSHSession) {
        showToast('No active SSH session', 'error');
        return;
    }
    
    const newDuration = prompt('Enter new duration in hours:', '24');
    if (!newDuration || isNaN(newDuration)) {
        return;
    }
    
    try {
        const response = await fetch('/api/temp-ssh/extend', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                session_id: currentSSHSession.session_id,
                duration: newDuration
            })
        });
        
        const result = await response.json();
        
        if (result.success) {
            currentSSHSession = result.session;
            updateAccessInfo('SSH access extended', 'success');
            showToast('SSH access extended', 'success');
            loadSSHSessions(); // Refresh sessions table
        } else {
            showToast(`Extend failed: ${result.error}`, 'error');
        }
    } catch (error) {
        showToast(`Extend error: ${error.message}`, 'error');
    }
}

// Load SSH sessions
async function loadSSHSessions() {
    try {
        const response = await fetch('/api/temp-ssh/sessions');
        const result = await response.json();
        
        if (result.success) {
            updateSSHSessionsTable(result.sessions);
        }
    } catch (error) {
        console.error('Error loading SSH sessions:', error);
    }
}

// Update SSH sessions table
function updateSSHSessionsTable(sessions) {
    const tbody = document.getElementById('ssh-sessions-tbody');
    if (!tbody) return;
    
    if (sessions.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7" class="text-center text-muted">No active SSH sessions</td></tr>';
        return;
    }
    
    tbody.innerHTML = sessions.map(session => `
        <tr>
            <td>${session.container}</td>
            <td>${session.username}</td>
            <td>${session.port}</td>
            <td>${new Date(session.created_at).toLocaleString()}</td>
            <td>${new Date(session.expires_at).toLocaleString()}</td>
            <td><span class="badge bg-${session.status === 'active' ? 'success' : 'danger'}">${session.status}</span></td>
            <td>
                <button class="btn btn-sm btn-outline-danger" onclick="revokeSession('${session.session_id}')">
                    <i class="bi bi-x-circle"></i> Revoke
                </button>
            </td>
        </tr>
    `).join('');
}

// Revoke specific session
async function revokeSession(sessionId) {
    if (!confirm('Are you sure you want to revoke this SSH session?')) {
        return;
    }
    
    try {
        const response = await fetch('/api/temp-ssh/revoke', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                session_id: sessionId
            })
        });
        
        const result = await response.json();
        
        if (result.success) {
            showToast('SSH session revoked', 'success');
            loadSSHSessions(); // Refresh sessions table
        } else {
            showToast(`Revoke failed: ${result.error}`, 'error');
        }
    } catch (error) {
        showToast(`Revoke error: ${error.message}`, 'error');
    }
}

// Update access info
function updateAccessInfo(message, type) {
    const infoDiv = document.getElementById('access-info');
    if (infoDiv) {
        infoDiv.className = `alert alert-${type}`;
        infoDiv.innerHTML = `<i class="bi bi-info-circle"></i> ${message}`;
    }
}

// Hide SSH connection details
function hideSSHConnectionDetails() {
    const detailsDiv = document.getElementById('ssh-connection-details');
    const revokeBtn = document.getElementById('revoke-access');
    const extendBtn = document.getElementById('extend-access');
    
    if (detailsDiv) detailsDiv.style.display = 'none';
    if (revokeBtn) revokeBtn.style.display = 'none';
    if (extendBtn) extendBtn.style.display = 'none';
}



// Make functions globally accessible for HTML event handlers
window.handleTempSSHSetup = handleTempSSHSetup;
window.showSSHConnectionDetails = showSSHConnectionDetails;
window.downloadPrivateKey = downloadPrivateKey;
window.copySSHCommand = copySSHCommand;
window.checkSSHStatus = checkSSHStatus;
window.revokeSSHAccess = revokeSSHAccess;
window.extendSSHAccess = extendSSHAccess;
window.loadSSHSessions = loadSSHSessions;
window.updateSSHSessionsTable = updateSSHSessionsTable;
window.revokeSession = revokeSession;
window.updateAccessInfo = updateAccessInfo;
window.hideSSHConnectionDetails = hideSSHConnectionDetails;
window.initializeSSHEventListeners = initializeSSHEventListeners;
// Export functions for global access
window.SSHManager = {
    initializeSSHEventListeners,
    handleTempSSHSetup,
    showSSHConnectionDetails,
    downloadPrivateKey,
    copySSHCommand,
    checkSSHStatus,
    revokeSSHAccess,
    extendSSHAccess,
    loadSSHSessions,
    updateSSHSessionsTable,
    revokeSession,
    updateAccessInfo,
    hideSSHConnectionDetails
};
