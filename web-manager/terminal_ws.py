#!/usr/bin/env python3
"""
WebSocket server for terminal access to Docker containers
"""

import asyncio
import json
import logging
import os
import pty
import select
import signal
import subprocess
import sys
import termios
import threading
import time
import websockets
from websockets.exceptions import ConnectionClosed

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("terminal_ws.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("terminal_ws")

# Global variables
ACTIVE_TERMINALS = {}

class DockerTerminal:
    def __init__(self, container_name, cols=80, rows=24):
        self.container_name = container_name
        self.cols = cols
        self.rows = rows
        self.fd = None
        self.pid = None
        self.process = None
        self.running = False
        self.last_activity = time.time()
        self.clients = set()
        self.read_thread = None
        self.lock = threading.Lock()
    
    def start(self):
        """Start the terminal process"""
        try:
            # Create a pseudo-terminal
            self.pid, self.fd = pty.fork()
            
            if self.pid == 0:
                # We're in the child process
                # Execute docker exec
                cmd = [
                    "sudo", "docker", "exec", 
                    "-it", 
                    self.container_name, 
                    "bash"
                ]
                os.execvp(cmd[0], cmd)
            else:
                # We're in the parent process
                logger.info(f"Started terminal for container {self.container_name} with PID {self.pid}")
                
                # Set terminal size
                self.resize(self.cols, self.rows)
                
                # Start the read thread
                self.running = True
                self.read_thread = threading.Thread(target=self.read_output)
                self.read_thread.daemon = True
                self.read_thread.start()
                
                return True
        except Exception as e:
            logger.error(f"Error starting terminal: {str(e)}")
            return False
    
    def resize(self, cols, rows):
        """Resize the terminal"""
        try:
            term_size = struct.pack('HHHH', rows, cols, 0, 0)
            fcntl.ioctl(self.fd, termios.TIOCSWINSZ, term_size)
            logger.debug(f"Resized terminal to {cols}x{rows}")
        except Exception as e:
            logger.error(f"Error resizing terminal: {str(e)}")
    
    def write(self, data):
        """Write data to the terminal"""
        try:
            os.write(self.fd, data)
            self.last_activity = time.time()
        except Exception as e:
            logger.error(f"Error writing to terminal: {str(e)}")
    
    def read_output(self):
        """Read output from the terminal and broadcast to all clients"""
        try:
            max_read_bytes = 1024 * 20
            while self.running:
                r, _, _ = select.select([self.fd], [], [], 0.1)
                if self.fd in r:
                    try:
                        output = os.read(self.fd, max_read_bytes)
                        if output:
                            # Broadcast to all connected clients
                            for client in list(self.clients):
                                asyncio.run_coroutine_threadsafe(
                                    client.send(output), 
                                    asyncio.get_event_loop()
                                )
                            self.last_activity = time.time()
                        else:
                            # EOF - process terminated
                            self.stop()
                            break
                    except OSError:
                        # Process terminated
                        self.stop()
                        break
                
                # Check for inactivity
                if time.time() - self.last_activity > 3600:  # 1 hour timeout
                    logger.info(f"Terminal {self.container_name} timed out due to inactivity")
                    self.stop()
                    break
        except Exception as e:
            logger.error(f"Error in read thread: {str(e)}")
            self.stop()
    
    def stop(self):
        """Stop the terminal process"""
        with self.lock:
            if not self.running:
                return
            
            self.running = False
            
            # Kill the process if it's still running
            try:
                if self.pid:
                    os.kill(self.pid, signal.SIGTERM)
            except:
                pass
            
            # Close the file descriptor
            try:
                if self.fd:
                    os.close(self.fd)
            except:
                pass
            
            logger.info(f"Stopped terminal for container {self.container_name}")
            
            # Remove from active terminals
            if self.container_name in ACTIVE_TERMINALS:
                del ACTIVE_TERMINALS[self.container_name]
    
    def add_client(self, websocket):
        """Add a client to this terminal"""
        self.clients.add(websocket)
        self.last_activity = time.time()
        logger.info(f"Client added to terminal {self.container_name}, total clients: {len(self.clients)}")
    
    def remove_client(self, websocket):
        """Remove a client from this terminal"""
        if websocket in self.clients:
            self.clients.remove(websocket)
            logger.info(f"Client removed from terminal {self.container_name}, remaining clients: {len(self.clients)}")
            
            # Stop the terminal if no clients are connected
            if len(self.clients) == 0:
                logger.info(f"No clients left, stopping terminal {self.container_name}")
                self.stop()

async def validate_container(container_name):
    """Validate if a container exists"""
    try:
        # Run docker ps to check if the container exists
        cmd = ["sudo", "docker", "ps", "-a", "--format", "{{.Names}}"]
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await process.communicate()
        
        if process.returncode != 0:
            logger.error(f"Error checking container: {stderr.decode()}")
            return False
        
        containers = stdout.decode().strip().split('\n')
        return container_name in containers
    except Exception as e:
        logger.error(f"Error validating container: {str(e)}")
        return False

async def terminal_handler(websocket, path):
    """Handle WebSocket connections for terminal access"""
    try:
        # Wait for the initial message with container name
        message = await websocket.recv()
        data = json.loads(message)
        
        if 'container' not in data:
            await websocket.send(json.dumps({
                'error': 'Container name is required'
            }))
            return
        
        container_name = data['container']
        cols = data.get('cols', 80)
        rows = data.get('rows', 24)
        
        # Validate the container
        if not await validate_container(container_name):
            await websocket.send(json.dumps({
                'error': f'Container {container_name} not found'
            }))
            return
        
        # Get or create terminal
        terminal = None
        if container_name in ACTIVE_TERMINALS:
            terminal = ACTIVE_TERMINALS[container_name]
            logger.info(f"Reusing existing terminal for {container_name}")
        else:
            terminal = DockerTerminal(container_name, cols, rows)
            if terminal.start():
                ACTIVE_TERMINALS[container_name] = terminal
                logger.info(f"Created new terminal for {container_name}")
            else:
                await websocket.send(json.dumps({
                    'error': f'Failed to start terminal for container {container_name}'
                }))
                return
        
        # Add client to terminal
        terminal.add_client(websocket)
        
        # Send success message
        await websocket.send(json.dumps({
            'success': True,
            'message': f'Connected to {container_name}'
        }))
        
        # Handle incoming messages (terminal input)
        try:
            async for message in websocket:
                if not terminal.running:
                    break
                
                try:
                    data = json.loads(message)
                    
                    # Handle resize event
                    if 'resize' in data:
                        cols = data['resize'].get('cols', terminal.cols)
                        rows = data['resize'].get('rows', terminal.rows)
                        terminal.resize(cols, rows)
                    
                    # Handle input data
                    elif 'input' in data:
                        input_data = data['input']
                        if isinstance(input_data, str):
                            terminal.write(input_data.encode())
                        else:
                            terminal.write(bytes(input_data))
                except json.JSONDecodeError:
                    # Treat as raw input if not JSON
                    terminal.write(message.encode())
                
        except ConnectionClosed:
            pass
        finally:
            # Remove client when connection closes
            terminal.remove_client(websocket)
    
    except Exception as e:
        logger.error(f"Error in terminal handler: {str(e)}")
        try:
            await websocket.send(json.dumps({
                'error': str(e)
            }))
        except:
            pass

async def start_server():
    """Start the WebSocket server"""
    # Import missing modules
    global struct, fcntl
    import struct
    import fcntl
    
    # Start WebSocket server
    host = '0.0.0.0'
    port = 8765
    
    logger.info(f"Starting WebSocket server on {host}:{port}")
    
    async with websockets.serve(terminal_handler, host, port):
        await asyncio.Future()  # Run forever

if __name__ == "__main__":
    try:
        asyncio.run(start_server())
    except KeyboardInterrupt:
        logger.info("Server stopped by user")
    finally:
        # Clean up any remaining terminals
        for terminal in list(ACTIVE_TERMINALS.values()):
            terminal.stop()
        logger.info("Server shutdown complete") 