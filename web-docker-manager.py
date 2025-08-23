#!/usr/bin/env python3
"""
Web Docker Manager - A web interface for managing Docker containers
Based on the docker-manager.sh functionality
"""

from flask import Flask, render_template, request, jsonify, redirect, url_for, flash
import subprocess
import json
import re
import os
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'docker-manager-secret-key-change-this'

class DockerManager:
    @staticmethod
    def run_command(cmd, shell=True):
        """Execute shell command and return result"""
        try:
            result = subprocess.run(cmd, shell=shell, capture_output=True, text=True, timeout=30)
            return {
                'success': result.returncode == 0,
                'stdout': result.stdout.strip(),
                'stderr': result.stderr.strip(),
                'returncode': result.returncode
            }
        except subprocess.TimeoutExpired:
            return {'success': False, 'stdout': '', 'stderr': 'Command timeout', 'returncode': -1}
        except Exception as e:
            return {'success': False, 'stdout': '', 'stderr': str(e), 'returncode': -1}

    @staticmethod
    def get_containers():
        """Get all containers with details"""
        cmd = "sudo docker ps -a --format '{{json .}}'"
        result = DockerManager.run_command(cmd)
        
        containers = []
        if result['success']:
            for line in result['stdout'].split('\n'):
                if line.strip():
                    try:
                        container = json.loads(line)
                        containers.append(container)
                    except json.JSONDecodeError:
                        continue
        return containers

    @staticmethod
    def get_projects():
        """Get unique project names from container names"""
        containers = DockerManager.get_containers()
        projects = set()
        
        for container in containers:
            name = container.get('Names', '')
            if '-' in name:
                project = name.split('-')[0]
                projects.add(project)
        
        return sorted(list(projects))

    @staticmethod
    def get_project_containers(project_name):
        """Get containers for a specific project"""
        containers = DockerManager.get_containers()
        project_containers = []
        
        for container in containers:
            if container.get('Names', '').startswith(f"{project_name}-"):
                project_containers.append(container)
        
        return project_containers

    @staticmethod
    def get_docker_system_info():
        """Get Docker system information"""
        cmd = "sudo docker system df --format '{{json .}}'"
        result = DockerManager.run_command(cmd)
        
        if result['success']:
            try:
                return json.loads(result['stdout'])
            except json.JSONDecodeError:
                pass
        
        # Fallback to parsing text output
        cmd = "sudo docker system df"
        result = DockerManager.run_command(cmd)
        return {'raw_output': result['stdout']}

    @staticmethod
    def get_volumes(project_name=None):
        """Get Docker volumes, optionally filtered by project"""
        if project_name:
            cmd = f"sudo docker volume ls --format '{{{{.Name}}}}' | grep '{project_name}'"
        else:
            cmd = "sudo docker volume ls --format '{{.Name}}'"
        
        result = DockerManager.run_command(cmd)
        volumes = []
        
        if result['success']:
            volumes = [v.strip() for v in result['stdout'].split('\n') if v.strip()]
        
        return volumes

    @staticmethod
    def get_networks(project_name=None):
        """Get Docker networks, optionally filtered by project"""
        if project_name:
            cmd = f"sudo docker network ls --format '{{{{.Name}}}}' | grep '{project_name}'"
        else:
            cmd = "sudo docker network ls --format '{{.Name}}'"
        
        result = DockerManager.run_command(cmd)
        networks = []
        
        if result['success']:
            networks = [n.strip() for n in result['stdout'].split('\n') 
                       if n.strip() and n.strip() not in ['bridge', 'host', 'none']]
        
        return networks

    @staticmethod
    def container_action(container_name, action):
        """Perform action on container (start, stop, restart, remove)"""
        if action not in ['start', 'stop', 'restart', 'remove']:
            return {'success': False, 'message': 'Invalid action'}
        
        cmd = f"sudo docker {action} {container_name}"
        result = DockerManager.run_command(cmd)
        
        return {
            'success': result['success'],
            'message': result['stdout'] if result['success'] else result['stderr']
        }

    @staticmethod
    def get_container_logs(container_name, lines=50):
        """Get container logs"""
        cmd = f"sudo docker logs {container_name} --tail {lines}"
        result = DockerManager.run_command(cmd)
        
        return {
            'success': result['success'],
            'logs': result['stdout'] if result['success'] else result['stderr']
        }

    @staticmethod
    def cleanup_docker_system(cleanup_type):
        """Clean up Docker system"""
        cleanup_commands = {
            'containers': 'sudo docker container prune -f',
            'images': 'sudo docker image prune -f',
            'volumes': 'sudo docker volume prune -f',
            'networks': 'sudo docker network prune -f',
            'system': 'sudo docker system prune -f',
            'all': 'sudo docker system prune -a --volumes -f'
        }
        
        if cleanup_type not in cleanup_commands:
            return {'success': False, 'message': 'Invalid cleanup type'}
        
        cmd = cleanup_commands[cleanup_type]
        result = DockerManager.run_command(cmd)
        
        return {
            'success': result['success'],
            'message': result['stdout'] if result['success'] else result['stderr']
        }

# Routes
@app.route('/')
def index():
    """Main dashboard"""
    projects = DockerManager.get_projects()
    containers = DockerManager.get_containers()
    system_info = DockerManager.get_docker_system_info()
    
    # Count running vs stopped containers
    running_count = len([c for c in containers if 'Up' in c.get('Status', '')])
    stopped_count = len(containers) - running_count
    
    return render_template('dashboard.html', 
                         projects=projects,
                         containers=containers,
                         system_info=system_info,
                         running_count=running_count,
                         stopped_count=stopped_count,
                         total_containers=len(containers))

@app.route('/project/<project_name>')
def project_detail(project_name):
    """Project detail page"""
    containers = DockerManager.get_project_containers(project_name)
    volumes = DockerManager.get_volumes(project_name)
    networks = DockerManager.get_networks(project_name)
    
    return render_template('project.html',
                         project_name=project_name,
                         containers=containers,
                         volumes=volumes,
                         networks=networks)

@app.route('/container/<container_name>')
def container_detail(container_name):
    """Container detail page"""
    containers = DockerManager.get_containers()
    container = next((c for c in containers if c.get('Names') == container_name), None)
    
    if not container:
        flash(f'Container {container_name} not found', 'error')
        return redirect(url_for('index'))
    
    return render_template('container.html', container=container)

@app.route('/api/container/<container_name>/action', methods=['POST'])
def container_action_api(container_name):
    """API endpoint for container actions"""
    action = request.json.get('action')
    result = DockerManager.container_action(container_name, action)
    return jsonify(result)

@app.route('/api/container/<container_name>/logs')
def container_logs_api(container_name):
    """API endpoint for container logs"""
    lines = request.args.get('lines', 50, type=int)
    result = DockerManager.get_container_logs(container_name, lines)
    return jsonify(result)

@app.route('/api/cleanup', methods=['POST'])
def cleanup_api():
    """API endpoint for Docker cleanup"""
    cleanup_type = request.json.get('type')
    result = DockerManager.cleanup_docker_system(cleanup_type)
    return jsonify(result)

@app.route('/api/system/info')
def system_info_api():
    """API endpoint for system information"""
    info = DockerManager.get_docker_system_info()
    return jsonify(info)

@app.route('/cleanup')
def cleanup_page():
    """Docker cleanup page"""
    system_info = DockerManager.get_docker_system_info()
    return render_template('cleanup.html', system_info=system_info)

if __name__ == '__main__':
    # Create templates directory if it doesn't exist
    os.makedirs('templates', exist_ok=True)
    os.makedirs('static', exist_ok=True)
    
    print("🚀 Starting Web Docker Manager...")
    print("📱 Access at: http://localhost:5000")
    print("🛑 Press Ctrl+C to stop")
    
    app.run(host='0.0.0.0', port=5000, debug=True)
