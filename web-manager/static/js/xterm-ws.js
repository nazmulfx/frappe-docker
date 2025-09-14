/**
 * XTerm WebSocket Terminal
 * A full-featured terminal emulator using xterm.js and WebSockets
 */

class XTermWS {
    constructor(container, options = {}) {
        // Default options
        this.options = {
            theme: {
                background: '#1a1a1a',
                foreground: '#ffffff',
                cursor: '#ffffff',
                selection: 'rgba(255, 255, 255, 0.3)',
                black: '#000000',
                red: '#cc0000',
                green: '#4e9a06',
                yellow: '#c4a000',
                blue: '#3465a4',
                magenta: '#75507b',
                cyan: '#06989a',
                white: '#d3d7cf',
                brightBlack: '#555753',
                brightRed: '#ef2929',
                brightGreen: '#8ae234',
                brightYellow: '#fce94f',
                brightBlue: '#729fcf',
                brightMagenta: '#ad7fa8',
                brightCyan: '#34e2e2',
                brightWhite: '#eeeeec'
            },
            fontSize: 14,
            fontFamily: '"Ubuntu Mono", "Courier New", monospace',
            cursorBlink: true,
            cursorStyle: 'block',
            scrollback: 10000,
            wsPort: 8765,  // Default WebSocket port
            fallbackToHttp: true,  // Whether to fall back to HTTP API if WebSocket fails
            ...options
        };

        // Container element
        if (typeof container === 'string') {
            this.container = document.getElementById(container);
        } else {
            this.container = container;
        }

        if (!this.container) {
            console.error('Terminal container not found');
            return;
        }

        // Terminal state
        this.terminal = null;
        this.fitAddon = null;
        this.websocket = null;
        this.connected = false;
        this.currentContainer = null;
        this.usingFallback = false;
        this.reconnectAttempts = 0;
        this.maxReconnectAttempts = 3;
        this.inputBuffer = ''; // Buffer for input in fallback mode
        this.commandHistory = []; // Command history
        this.historyIndex = -1; // Current position in command history
        this.currentDir = '/home/frappe/frappe-bench'; // Current directory
        this.isStreaming = false; // Whether we're streaming output
        this.streamingInterval = null; // Interval for polling streaming
        this.streamCommand = null; // Current streaming command
        this.streamContainer = null; // Container for streaming
        this.streamDir = null; // Directory for streaming
        
        // Initialize
        this.init();
    }

    /**
     * Initialize the terminal
     */
    async init() {
        try {
            // Load dependencies if needed
            await this.loadDependencies();
            
            // Create terminal instance
            this.terminal = new Terminal({
                theme: this.options.theme,
                fontFamily: this.options.fontFamily,
                fontSize: this.options.fontSize,
                cursorBlink: this.options.cursorBlink,
                cursorStyle: this.options.cursorStyle,
                scrollback: this.options.scrollback,
                allowTransparency: true,
                convertEol: true,
                disableStdin: false
            });

            // Load addons
            this.fitAddon = new FitAddon.FitAddon();
            this.terminal.loadAddon(this.fitAddon);
            this.terminal.loadAddon(new WebLinksAddon.WebLinksAddon());
            
            // Open terminal in container
            this.terminal.open(this.container);
            this.fitAddon.fit();
            
            // Set up event listeners
            this.setupEventListeners();
            
            // Show welcome message
            this.terminal.writeln('\x1B[1;34mXTerm.js Terminal Ready\x1B[0m');
            this.terminal.writeln('Connect to a container to begin.');
            this.terminal.writeln('');
            
            // Handle window resize
            window.addEventListener('resize', () => {
                this.fitAddon.fit();
                this.sendResize();
            });
            
            console.log('Terminal initialized successfully');
            return this;
        } catch (error) {
            console.error('Error initializing terminal:', error);
            this.terminal?.writeln(`\x1B[1;31mError initializing terminal: ${error.message}\x1B[0m`);
            throw error;
        }
    }

    /**
     * Load required dependencies
     */
    async loadDependencies() {
        // Check if we're in a browser environment
        if (typeof document === 'undefined' || !document) {
            console.error('Document is not defined or not available. Not in a browser environment.');
            return false;
        }
        
        // Check if dependencies are already loaded
        if (typeof Terminal !== 'undefined' && 
            typeof FitAddon !== 'undefined' && 
            typeof WebLinksAddon !== 'undefined') {
            console.log('Terminal dependencies already loaded');
            return true;
        }
        
        try {
            // Create a function to load scripts
            const loadScript = (src) => {
                return new Promise((resolve, reject) => {
                    try {
                        const script = document.createElement('script');
                        script.src = src;
                        script.onload = resolve;
                        script.onerror = reject;
                        document.head.appendChild(script);
                    } catch (error) {
                        console.error('Error creating script element:', error);
                        reject(error);
                    }
                });
            };

            // Create a function to load stylesheets
            const loadStylesheet = (href) => {
                return new Promise((resolve, reject) => {
                    try {
                        const link = document.createElement('link');
                        link.rel = 'stylesheet';
                        link.href = href;
                        link.onload = resolve;
                        link.onerror = reject;
                        document.head.appendChild(link);
                    } catch (error) {
                        console.error('Error creating link element:', error);
                        reject(error);
                    }
                });
            };
            
            // Load xterm.js and its addons if not already loaded
            if (typeof Terminal === 'undefined') {
                await loadStylesheet('https://cdn.jsdelivr.net/npm/xterm@5.1.0/css/xterm.min.css');
                await loadScript('https://cdn.jsdelivr.net/npm/xterm@5.1.0/lib/xterm.min.js');
            }
            
            if (typeof FitAddon === 'undefined') {
                await loadScript('https://cdn.jsdelivr.net/npm/xterm-addon-fit@0.7.0/lib/xterm-addon-fit.min.js');
            }
            
            if (typeof WebLinksAddon === 'undefined') {
                await loadScript('https://cdn.jsdelivr.net/npm/xterm-addon-web-links@0.8.0/lib/xterm-addon-web-links.min.js');
            }
            
            // Verify dependencies are loaded
            if (typeof Terminal === 'undefined' || 
                typeof FitAddon === 'undefined' || 
                typeof WebLinksAddon === 'undefined') {
                console.error('Failed to load terminal dependencies');
                return false;
            }
            
            return true;
        } catch (error) {
            console.error('Error loading dependencies:', error);
            return false;
        }
    }

    /**
     * Set up event listeners
     */
    setupEventListeners() {
        // Handle terminal input
        this.terminal.onData(data => {
            // Handle special keys in fallback mode
            if (this.usingFallback) {
                // Handle backspace key
                if (data === '\x7f') { // ASCII DEL (backspace)
                    if (this.inputBuffer && this.inputBuffer.length > 0) {
                        // Remove the last character from the input buffer
                        this.inputBuffer = this.inputBuffer.slice(0, -1);
                        // Move cursor back, clear character, move cursor back again
                        this.terminal.write('\b \b');
                    }
                    return;
                }
                // Handle Ctrl+U (clear line)
                else if (data === '\u0015') {
                    // Clear the current line
                    while (this.inputBuffer && this.inputBuffer.length > 0) {
                        this.terminal.write('\b \b');
                        this.inputBuffer = this.inputBuffer.slice(0, -1);
                    }
                    return;
                }
                // Handle arrow keys for command history
                else if (data === '\u001b[A') { // Up arrow
                    this.navigateHistory('up');
                    return;
                }
                else if (data === '\u001b[B') { // Down arrow
                    this.navigateHistory('down');
                    return;
                }
            }
            
            this.sendInput(data);
        });
        
        // Handle terminal resize
        this.terminal.onResize(size => {
            this.sendResize(size.cols, size.rows);
        });
        
        // Handle keydown events for special keys
        this.terminal.attachCustomKeyEventHandler((event) => {
            if (this.usingFallback) {
                // Prevent default for arrow keys to avoid double handling
                if (event.key === 'ArrowUp' || event.key === 'ArrowDown') {
                    return false;
                }
            }
            return true;
        });
    }
    
    /**
     * Navigate command history
     */
    navigateHistory(direction) {
        if (!this.commandHistory.length) {
            return;
        }
        
        // Save current input if we're just starting to navigate
        if (this.historyIndex === -1) {
            this.currentInput = this.inputBuffer;
        }
        
        // Update history index
        if (direction === 'up') {
            if (this.historyIndex < this.commandHistory.length - 1) {
                this.historyIndex++;
            }
        } else if (direction === 'down') {
            if (this.historyIndex > -1) {
                this.historyIndex--;
            }
        }
        
        // Clear current input
        while (this.inputBuffer.length > 0) {
            this.terminal.write('\b \b');
            this.inputBuffer = this.inputBuffer.slice(0, -1);
        }
        
        // Get command from history or restore current input
        let newInput = '';
        if (this.historyIndex >= 0) {
            newInput = this.commandHistory[this.commandHistory.length - 1 - this.historyIndex];
        } else {
            newInput = this.currentInput || '';
        }
        
        // Set new input
        this.inputBuffer = newInput;
        this.terminal.write(newInput);
    }

    /**
     * Connect to a container
     */
    async connectToContainer(container) {
        if (!container) {
            this.terminal.writeln('\x1B[1;31mError: No container specified\x1B[0m');
            return;
        }
        
        // Disconnect from any existing connection
        this.disconnect();
        
        this.terminal.writeln(`\x1B[1;33mConnecting to container: ${container}...\x1B[0m`);
        
        try {
            // First check if the container exists using HTTP API
            const containerExists = await this.checkContainerExists(container);
            if (!containerExists) {
                this.terminal.writeln(`\x1B[1;31mError: Container '${container}' not found\x1B[0m`);
                return;
            }
            
            // Try WebSocket connection
            await this.connectWebSocket(container);
        } catch (error) {
            console.error('Error connecting to container:', error);
            this.terminal.writeln(`\x1B[1;31mError connecting to container: ${error.message || 'Unknown error'}\x1B[0m`);
            
            // If WebSocket failed and fallback is enabled, try HTTP API
            if (this.options.fallbackToHttp && !this.usingFallback) {
                this.terminal.writeln('\x1B[1;33mFalling back to HTTP API (limited functionality)...\x1B[0m');
                this.usingFallback = true;
                this.currentContainer = container;
                this.connected = true;
                this.terminal.writeln(`\x1B[1;32mConnected to ${container} (HTTP fallback mode)\x1B[0m`);
                this.writePrompt();
            }
        }
    }

    /**
     * Check if a container exists using HTTP API
     */
    async checkContainerExists(container) {
        try {
            const response = await fetch(`/api/frappe/validate-container?container=${encodeURIComponent(container)}`);
            const data = await response.json();
            return data.exists;
        } catch (error) {
            console.error('Error checking container:', error);
            return false;
        }
    }

    /**
     * Connect to container using WebSocket
     */
    async connectWebSocket(container) {
        return new Promise((resolve, reject) => {
            try {
                // Create WebSocket connection
                const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
                const wsHost = window.location.hostname;
                const wsPort = this.options.wsPort;
                const wsUrl = `${wsProtocol}//${wsHost}:${wsPort}`;
                
                console.log(`Connecting to WebSocket at ${wsUrl}`);
                this.websocket = new WebSocket(wsUrl);
                
                // Set timeout for connection
                const connectionTimeout = setTimeout(() => {
                    if (this.websocket && this.websocket.readyState !== WebSocket.OPEN) {
                        this.websocket.close();
                        reject(new Error('Connection timeout'));
                    }
                }, 5000);
                
                // Set up WebSocket event handlers
                this.websocket.onopen = () => {
                    clearTimeout(connectionTimeout);
                    console.log('WebSocket connection established');
                    
                    // Send container information
                    const { cols, rows } = this.terminal;
                    this.websocket.send(JSON.stringify({
                        container: container,
                        cols: cols,
                        rows: rows
                    }));
                    
                    this.currentContainer = container;
                    this.usingFallback = false;
                };
                
                this.websocket.onmessage = (event) => {
                    const data = event.data;
                    
                    // Handle JSON messages
                    if (typeof data === 'string' && data.startsWith('{')) {
                        try {
                            const jsonData = JSON.parse(data);
                            
                            if (jsonData.error) {
                                this.terminal.writeln(`\x1B[1;31mError: ${jsonData.error}\x1B[0m`);
                                reject(new Error(jsonData.error));
                                return;
                            }
                            
                            if (jsonData.success) {
                                this.connected = true;
                                this.terminal.writeln(`\x1B[1;32m${jsonData.message}\x1B[0m`);
                                resolve();
                            }
                        } catch (e) {
                            // Not JSON, treat as terminal output
                            this.terminal.write(data);
                        }
                    } else {
                        // Binary data or non-JSON string, write directly to terminal
                        this.terminal.write(data);
                    }
                };
                
                this.websocket.onclose = (event) => {
                    clearTimeout(connectionTimeout);
                    this.connected = false;
                    
                    if (this.currentContainer) {
                        this.terminal.writeln(`\x1B[1;33mDisconnected from container (code: ${event.code})\x1B[0m`);
                        
                        // Try to reconnect if not intentionally closed
                        if (event.code !== 1000 && event.code !== 1001) {
                            this.tryReconnect();
                        } else {
                            this.currentContainer = null;
                        }
                    }
                    
                    reject(new Error(`WebSocket closed (code: ${event.code})`));
                };
                
                this.websocket.onerror = (error) => {
                    clearTimeout(connectionTimeout);
                    console.error('WebSocket error:', error);
                    this.terminal.writeln(`\x1B[1;31mWebSocket error: ${error.message || 'Unknown error'}\x1B[0m`);
                    reject(error);
                };
                
            } catch (error) {
                console.error('Error creating WebSocket:', error);
                reject(error);
            }
        });
    }

    /**
     * Try to reconnect to WebSocket
     */
    tryReconnect() {
        if (this.reconnectAttempts >= this.maxReconnectAttempts) {
            this.terminal.writeln('\x1B[1;31mFailed to reconnect after multiple attempts\x1B[0m');
            
            // Fall back to HTTP API if enabled
            if (this.options.fallbackToHttp && !this.usingFallback && this.currentContainer) {
                this.terminal.writeln('\x1B[1;33mFalling back to HTTP API (limited functionality)...\x1B[0m');
                this.usingFallback = true;
                this.connected = true;
                this.terminal.writeln(`\x1B[1;32mConnected to ${this.currentContainer} (HTTP fallback mode)\x1B[0m`);
                this.writePrompt();
            }
            
            return;
        }
        
        const container = this.currentContainer;
        if (!container) return;
        
        this.reconnectAttempts++;
        const delay = Math.min(1000 * Math.pow(2, this.reconnectAttempts - 1), 10000);
        
        this.terminal.writeln(`\x1B[1;33mReconnecting in ${delay/1000} seconds (attempt ${this.reconnectAttempts}/${this.maxReconnectAttempts})...\x1B[0m`);
        
        setTimeout(() => {
            if (this.currentContainer === container) {
                this.terminal.writeln('\x1B[1;33mAttempting to reconnect...\x1B[0m');
                this.connectWebSocket(container).catch(() => {
                    // Error handling is done in the connectWebSocket method
                });
            }
        }, delay);
    }

    /**
     * Disconnect from the current container
     */
    disconnect() {
        if (this.websocket) {
            this.websocket.close(1000, "Intentional disconnect");
            this.websocket = null;
        }
        
        this.connected = false;
        this.currentContainer = null;
        this.usingFallback = false;
        this.reconnectAttempts = 0;
        this.currentDir = '/home/frappe/frappe-bench'; // Reset current directory on disconnect
        this.isStreaming = false; // Reset streaming state
        this.stopStreaming(); // Stop any active polling
    }

    /**
     * Send input to the terminal
     */
    sendInput(data) {
        if (!this.connected || !this.currentContainer) {
            return;
        }
        
        if (this.usingFallback) {
            // Handle Ctrl+C to stop streaming
            if (data === '\u0003') {  // Ctrl+C
                if (this.isStreaming) {
                    this.stopStreaming();
                    return;
                } else {
                    this.terminal.writeln('^C');
                    this.inputBuffer = '';
                    this.writePrompt();
                    return;
                }
            }
            
            // If we're streaming, don't process other input
            if (this.isStreaming) {
                return;
            }
            
            // In fallback mode, collect input until Enter is pressed
            if (data === '\r') {
                // Execute the command using HTTP API
                this.executeCommandHttp(this.inputBuffer || '');
                this.inputBuffer = '';
            } else if (data === '\x7f') {  // Backspace
                // Handled in setupEventListeners
                return;
            } else if (data === '\t') {  // Tab
                // Simple tab completion could be added here
                return;
            } else if (data === '\u001b[A' || data === '\u001b[B') {  // Up/Down arrows
                // Command history could be added here
                return;
            } else {
                // Add to input buffer and echo to terminal
                // Only echo printable characters
                if (data >= ' ' && data !== '\x7f') {
                    this.inputBuffer += data;
                    this.terminal.write(data);
                }
            }
            return;
        }
        
        // Normal WebSocket mode
        if (this.websocket && this.websocket.readyState === WebSocket.OPEN) {
            try {
                this.websocket.send(JSON.stringify({
                    input: data
                }));
            } catch (error) {
                console.error('Error sending input:', error);
            }
        }
    }

    /**
     * Execute a command using HTTP API (fallback mode)
     */
    async executeCommandHttp(command) {
        if (!command || !this.currentContainer) return;
        
        // Save command to history if not empty
        if (command.trim() !== '') {
            // Don't add duplicate consecutive commands
            if (this.commandHistory.length === 0 || this.commandHistory[this.commandHistory.length - 1] !== command) {
                this.commandHistory.push(command);
                // Limit history size
                if (this.commandHistory.length > 50) {
                    this.commandHistory.shift();
                }
            }
            // Reset history navigation
            this.historyIndex = -1;
        }
        
        // Handle common command aliases
        const commandMap = {
            'll': 'ls -la',
            'la': 'ls -a',
            'lt': 'ls -lt',
            'cls': 'clear'
        };
        
        // Check if command is an alias and replace it
        if (commandMap[command]) {
            command = commandMap[command];
        }
        
        // Handle clear command directly
        if (command === 'clear') {
            this.terminal.clear();
            this.writePrompt();
            return;
        }
        
        // Handle exit/logout command
        if (command === 'exit' || command === 'logout') {
            this.terminal.writeln('');
            this.disconnect();
            this.terminal.writeln('\x1B[1;33mDisconnected from container\x1B[0m');
            return;
        }
        
        this.terminal.writeln('');  // New line after command
        
        // Stop any active streaming
        if (this.streamingInterval) {
            clearInterval(this.streamingInterval);
            this.streamingInterval = null;
            this.isStreaming = false;
        }
        
        try {
            const response = await fetch('/api/frappe/execute-command', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    container: this.currentContainer,
                    command: command,
                    current_dir: this.currentDir || '/home/frappe/frappe-bench'
                })
            });
            
            const data = await response.json();
            
            // Update current directory if provided
            if (data.current_dir) {
                this.currentDir = data.current_dir;
            }
            
            if (data.error) {
                this.terminal.writeln(`\x1B[1;31mError: ${data.error}\x1B[0m`);
            } else if (data.output !== undefined) {
                // Write output to terminal
                if (data.output.trim()) {
                    this.terminal.writeln(data.output);
                }
                
                // Handle streaming for tail -f
                if (data.is_streaming && data.stream_command) {
                    this.isStreaming = true;
                    this.streamCommand = data.stream_command;
                    this.streamContainer = this.currentContainer;
                    this.streamDir = this.currentDir;
                    
                    // Start streaming with polling
                    this.startStreamPolling();
                    
                    // Show streaming indicator
                    this.terminal.writeln('\x1B[1;33mStreaming... (Press Ctrl+C to stop)\x1B[0m');
                    return; // Don't show prompt while streaming
                }
            }
        } catch (error) {
            console.error('Error executing command:', error);
            this.terminal.writeln(`\x1B[1;31mError: ${error.message || 'Failed to execute command'}\x1B[0m`);
        }
        
        // Write prompt for next command
        this.writePrompt();
    }
    
    /**
     * Start polling for streaming output (for tail -f)
     */

    startBenchPolling() {
        if (this.benchPollingInterval) {
            clearInterval(this.benchPollingInterval);
        }
        
        // Set up polling interval for bench commands
        this.benchPollingInterval = setInterval(async () => {
            if (!this.isStreaming || !this.streamContainer) {
                clearInterval(this.benchPollingInterval);
                this.benchPollingInterval = null;
                return;
            }
            
            try {
                // Poll for command status
                const response = await fetch('/api/frappe/execute-command', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        container: this.streamContainer,
                        command: this.streamCommand,
                        current_dir: this.streamDir
                    })
                });
                
                const data = await response.json();
                
                if (data.output) {
                    this.terminal.write(data.output);
                }
                
                if (data.error) {
                    this.terminal.writeln(`[1;31mError: ${data.error}[0m`);
                    this.stopStreaming();
                }
                
                // If command completed (no streaming flag), stop polling
                if (!data.is_streaming) {
                    this.stopStreaming();
                }
                
            } catch (error) {
                console.error('Error polling bench command:', error);
                this.stopStreaming();
            }
        }, 2000); // Poll every 2 seconds
    }
    startStreamPolling() {
        if (this.streamingInterval) {
            clearInterval(this.streamingInterval);
        }
        
        // Extract file pattern from command
        const filePattern = this.streamCommand.split(' ', 3)[2];
        
        // Get initial timestamp to track new content
        this.lastStreamTime = Date.now();
        
        // Set up polling interval
        this.streamingInterval = setInterval(async () => {
            if (!this.isStreaming || !this.streamContainer) {
                clearInterval(this.streamingInterval);
                this.streamingInterval = null;
                return;
            }
            
            try {
                // Use a timestamp-based approach to get only new content
                const since = Math.floor((Date.now() - this.lastStreamTime) / 1000);
                const pollCommand = `tail -n 5 ${filePattern} | grep -a "."`;
                
                const response = await fetch('/api/frappe/execute-command', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        container: this.streamContainer,
                        command: pollCommand,
                        current_dir: this.streamDir || '/home/frappe/frappe-bench'
                    })
                });
                
                const data = await response.json();
                
                if (data.error) {
                    // If there's an error, stop streaming
                    clearInterval(this.streamingInterval);
                    this.streamingInterval = null;
                    this.isStreaming = false;
                    this.terminal.writeln(`\x1B[1;31mStreaming stopped: ${data.error}\x1B[0m`);
                    this.writePrompt();
                } else if (data.output && data.output.trim()) {
                    // Write new output to terminal
                    this.terminal.write(data.output);
                    this.lastStreamTime = Date.now();
                }
            } catch (error) {
                console.error('Error polling stream:', error);
            }
        }, 3000); // Poll every 3 seconds
    }
    
    /**
     * Stop streaming
     */
    stopStreaming() {
        if (this.streamingInterval) {
            clearInterval(this.streamingInterval);
            this.streamingInterval = null;
        }
        
        if (this.isStreaming) {
            this.isStreaming = false;
            this.terminal.writeln('\n\x1B[1;33mStreaming stopped\x1B[0m');
            this.writePrompt();
        }
    }

    /**
     * Write the command prompt
     */
    writePrompt() {
        if (!this.usingFallback || !this.currentContainer) return;
        
        // Get current directory (simplified)
        const dir = this.currentDir || '/home/frappe/frappe-bench'; // Use currentDir if available, otherwise default
        const prompt = `\x1B[1;32m${this.currentContainer}\x1B[0m:\x1B[1;34m${dir}\x1B[0m$ `;
        this.terminal.write(prompt);
        this.inputBuffer = '';
    }

    /**
     * Send terminal resize information
     */
    sendResize(cols, rows) {
        if (!this.connected || !this.currentContainer) {
            return;
        }
        
        if (!cols || !rows) {
            const dimensions = this.terminal;
            cols = dimensions.cols;
            rows = dimensions.rows;
        }
        
        // Only send resize in WebSocket mode
        if (!this.usingFallback && this.websocket && this.websocket.readyState === WebSocket.OPEN) {
            try {
                this.websocket.send(JSON.stringify({
                    resize: { cols, rows }
                }));
            } catch (error) {
                console.error('Error sending resize:', error);
            }
        }
    }

    /**
     * Write text to the terminal
     */
    write(text) {
        if (!this.terminal) {
            return;
        }
        
        this.terminal.write(text);
    }

    /**
     * Write a line of text to the terminal
     */
    writeln(text) {
        if (!this.terminal) {
            return;
        }
        
        this.terminal.writeln(text);
    }

    /**
     * Clear the terminal
     */
    clear() {
        if (!this.terminal) {
            return;
        }
        
        this.terminal.clear();
        
        // If in fallback mode, write the prompt again
        if (this.usingFallback && this.connected) {
            this.writePrompt();
        }
    }

    /**
     * Focus the terminal
     */
    focus() {
        if (!this.terminal) {
            return;
        }
        
        this.terminal.focus();
    }

    /**
     * Resize the terminal
     */
    fit() {
        if (!this.fitAddon) {
            return;
        }
        
        this.fitAddon.fit();
        this.sendResize();
    }
} 