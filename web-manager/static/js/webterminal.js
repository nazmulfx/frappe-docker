/**
 * WebTerminal - AWS Console-like Terminal Implementation
 * Based on xterm.js - the same terminal used by AWS Cloud9, VS Code, and other web terminals
 */

class WebTerminal {
    constructor(container, options = {}) {
        // Handle both DOM element and string ID
        if (typeof container === 'string') {
            this.container = document.getElementById(container);
        } else {
            this.container = container;
        }
        
        if (!this.container) {
            console.error('Terminal container not found');
            return;
        }
        
        this.options = Object.assign({
            promptPrefix: '',
            welcomeMessage: 'Welcome to Frappe Docker Web Terminal',
            theme: {
                background: '#300a24', // Ubuntu terminal purple
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
            }
        }, options);

        this.terminal = null;
        this.fitAddon = null;
        this.webSocket = null;
        this.currentContainer = null;
        this.commandHistory = [];
        this.historyIndex = -1;
        this.currentLine = '';
        this.currentDir = '/home/frappe';
        this.isWebSocketConnected = false;
        this.pendingCommands = [];
        this.commandQueue = [];
        this.isExecutingCommand = false;
        this.reconnectAttempts = 0;
        this.maxReconnectAttempts = 5;
        this.reconnectTimeout = null;
        this.sessionId = this.generateSessionId();
    }

    /**
     * Initialize the terminal
     */
    async init() {
        try {
        // Load xterm.js and its addons
            const dependenciesLoaded = await this.loadDependencies();
            if (!dependenciesLoaded) {
                console.error('Failed to load terminal dependencies');
                return this;
            }
        
        // Create terminal instance
        this.terminal = new Terminal({
            cursorBlink: true,
            cursorStyle: 'block',
            fontFamily: '"Ubuntu Mono", "Courier New", monospace',
            fontSize: 14,
            lineHeight: 1.2,
            theme: this.options.theme,
            allowTransparency: true,
            scrollback: 10000,
            cols: 100,
            rows: 30
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
        this.terminal.writeln('\x1B[1;34m' + this.options.welcomeMessage + '\x1B[0m');
        this.terminal.writeln('Type \x1B[1;33mhelp\x1B[0m for available commands.');
        this.terminal.writeln('Type \x1B[1;33mcontainers\x1B[0m to list available containers.');
        this.terminal.writeln('');
        this.writePrompt();
        
        // Handle window resize
        window.addEventListener('resize', () => {
            this.fitAddon.fit();
        });
            
            console.log('Terminal initialized successfully');
        } catch (error) {
            console.error('Error initializing terminal:', error);
        }

        return this;
    }

    /**
     * Load xterm.js and its addons
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
     * Set up event listeners for the terminal
     */
    setupEventListeners() {
        this.terminal.onData(data => {
            // Handle terminal input
            this.handleTerminalInput(data);
        });
    }

    /**
     * Handle terminal input
     */
    handleTerminalInput(data) {
        const ord = data.charCodeAt(0);
        
        // Handle special keys
        if (ord === 13) { // Enter key
            this.handleEnterKey();
        } else if (ord === 127) { // Backspace key
            if (this.currentLine.length > 0) {
                this.currentLine = this.currentLine.slice(0, -1);
                this.terminal.write('\b \b');
            }
        } else if (ord === 27) { // ESC key sequences (arrows, etc.)
            if (data === '\u001b[A') { // Up arrow
                this.handleUpArrow();
            } else if (data === '\u001b[B') { // Down arrow
                this.handleDownArrow();
            } else if (data === '\u001b[C') { // Right arrow
                // Handle right arrow if needed
            } else if (data === '\u001b[D') { // Left arrow
                // Handle left arrow if needed
            }
        } else if (ord === 9) { // Tab key
            // Handle tab completion
            this.handleTabCompletion();
        } else if (ord === 3) { // Ctrl+C
            this.handleCtrlC();
        } else if (ord >= 32 && ord < 127) { // Printable characters
            this.currentLine += data;
            this.terminal.write(data);
        }
    }

    /**
     * Handle Enter key press
     */
    handleEnterKey() {
        this.terminal.writeln('');
        
        if (this.currentLine.trim() !== '') {
            // Add command to history
            this.commandHistory.push(this.currentLine);
            this.historyIndex = this.commandHistory.length;
            
            // Execute command
            this.executeCommand(this.currentLine);
        } else {
            this.writePrompt();
        }
        
        // Reset current line
        this.currentLine = '';
    }

    /**
     * Handle Up arrow key press
     */
    handleUpArrow() {
        if (this.commandHistory.length > 0) {
            if (this.historyIndex > 0) {
                this.historyIndex--;
                this.clearCurrentLine();
                this.currentLine = this.commandHistory[this.historyIndex];
                this.terminal.write(this.currentLine);
            }
        }
    }

    /**
     * Handle Down arrow key press
     */
    handleDownArrow() {
        if (this.historyIndex < this.commandHistory.length - 1) {
            this.historyIndex++;
            this.clearCurrentLine();
            this.currentLine = this.commandHistory[this.historyIndex];
            this.terminal.write(this.currentLine);
        } else if (this.historyIndex === this.commandHistory.length - 1) {
            this.historyIndex++;
            this.clearCurrentLine();
            this.currentLine = '';
        }
    }

    /**
     * Handle Tab completion
     */
    handleTabCompletion() {
        // Implement tab completion logic here
        // For now, just add a tab character
        this.currentLine += '\t';
        this.terminal.write('\t');
    }

    /**
     * Handle Ctrl+C
     */
    handleCtrlC() {
        this.terminal.writeln('^C');
        this.writePrompt();
        this.currentLine = '';
    }

    /**
     * Clear the current line
     */
    clearCurrentLine() {
        // Move cursor to beginning of line
        this.terminal.write('\r');
        
        // Clear line
        this.terminal.write('\x1B[K');
        
        // Write prompt
        this.writePrompt();
    }

    /**
     * Write prompt to terminal
     */
    writePrompt() {
        if (!this.terminal) {
            console.error('Terminal not initialized');
            return;
        }
        
        const prompt = this.currentContainer 
            ? `\x1B[1;32mfrappe@${this.currentContainer}\x1B[0m:\x1B[1;34m${this.currentDir}\x1B[0m$ `
            : '\x1B[1;32mfrappe@localhost\x1B[0m:\x1B[1;34m~\x1B[0m$ ';
        
        this.terminal.write(prompt);
    }

    /**
     * Execute a command
     */
    async executeCommand(command) {
        if (!command.trim()) {
            this.writePrompt();
            return;
        }
        
        // Handle built-in commands
        if (command === 'clear' || command === 'cls') {
            this.terminal.clear();
            this.writePrompt();
            return;
        }
        
        if (command === 'help') {
            this.showHelp();
            return;
        }
        
        if (command === 'containers' || command === 'list' || command === 'ls containers') {
            this.listContainers();
            return;
        }
        
        if (command.startsWith('connect ')) {
            const container = command.split(' ')[1];
            this.connectToContainer(container);
            return;
        }
        
        // Check if connected to a container
        if (!this.currentContainer) {
            this.terminal.writeln('\x1B[1;31mError: Not connected to a container. Use "connect <container_name>" first.\x1B[0m');
            this.writePrompt();
            return;
        }
        
        // Special handling for tail -f command
        if (command.startsWith('tail -f ') || command.startsWith('tail -F ')) {
            this.executeTailCommand(command);
            return;
        }
        
        try {
            // Send command to server
            const response = await fetch('/api/frappe/execute-command', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    container: this.currentContainer,
                    command: command,
                    session_id: this.sessionId
                })
            });
            
            const result = await response.json();
            
            if (result.success) {
                // Update current directory if provided
                if (result.current_dir) {
                    this.currentDir = result.current_dir;
                }
                
                // Special handling for ls command output
                if (command.trim() === 'ls' || command.startsWith('ls ')) {
                    this.formatLsOutput(result.raw_output || result.output);
                } else {
                    // Regular command output
                    this.terminal.writeln(this.stripHtml(result.output || ''));
                }
            } else {
                this.terminal.writeln(`\x1B[1;31mError: ${result.error || 'Unknown error'}\x1B[0m`);
            }
        } catch (error) {
            this.terminal.writeln(`\x1B[1;31mError: ${error.message}\x1B[0m`);
        }
        
        this.addToHistory(command);
        this.writePrompt();
    }
    
    /**
     * Execute tail -f command with streaming support
     */
    async executeTailCommand(command) {
        if (!this.currentContainer) {
            this.terminal.writeln('\x1B[1;31mError: Not connected to a container\x1B[0m');
            this.writePrompt();
            return;
        }
        
        this.addToHistory(command);
        
        try {
            // Extract the file pattern
            const filePath = command.split(' ', 3)[2];
            
            this.terminal.writeln(`\x1B[1;33mStreaming log file: ${filePath}\x1B[0m`);
            this.terminal.writeln('\x1B[1;33mPress Ctrl+C to stop streaming\x1B[0m');
            
            // Set a flag to indicate we're in streaming mode
            this.isStreaming = true;
            
            // Execute the command normally first to get initial output
            const response = await fetch('/api/frappe/execute-command', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    container: this.currentContainer,
                    command: command,
                    session_id: this.sessionId
                })
            });
            
            const result = await response.json();
            
            if (result.success) {
                // Display initial output
                if (result.raw_output) {
                    this.terminal.writeln(this.stripHtml(result.raw_output));
                } else {
                    this.terminal.writeln('\x1B[1;33mWaiting for log entries...\x1B[0m');
                }
                
                // Set up polling for new content
                this.streamingInterval = setInterval(async () => {
                    if (!this.isStreaming) {
                        clearInterval(this.streamingInterval);
                        return;
                    }
                    
                    try {
                        // Use tail -n 5 to get just the latest entries
                        const pollResponse = await fetch('/api/frappe/execute-command', {
                            method: 'POST',
                            headers: {
                                'Content-Type': 'application/json'
                            },
                            body: JSON.stringify({
                                container: this.currentContainer,
                                command: `tail -n 5 ${filePath}`,
                                session_id: this.sessionId
                            })
                        });
                        
                        const pollResult = await pollResponse.json();
                        
                        if (pollResult.success && pollResult.raw_output) {
                            // Only show new content if it's different from what we've seen
                            const newContent = this.stripHtml(pollResult.raw_output);
                            if (newContent && newContent !== this.lastStreamContent) {
                                this.terminal.writeln(newContent);
                                this.lastStreamContent = newContent;
                            }
                        }
                    } catch (error) {
                        console.error('Error polling log:', error);
                    }
                }, 2000); // Poll every 2 seconds
                
                // Set up keyboard handler for Ctrl+C
                this.ctrlCHandler = (e) => {
                    if (e.key === 'c' && e.ctrlKey) {
                        if (this.isStreaming) {
                            this.isStreaming = false;
                            clearInterval(this.streamingInterval);
                            this.terminal.writeln('\n\x1B[1;33mStreaming stopped\x1B[0m');
                            this.writePrompt();
                            // Remove the event listener
                            document.removeEventListener('keydown', this.ctrlCHandler);
                        }
                    }
                };
                
                document.addEventListener('keydown', this.ctrlCHandler);
            } else {
                this.terminal.writeln(`\x1B[1;31mError: ${result.error || 'Failed to stream log file'}\x1B[0m`);
                this.writePrompt();
            }
        } catch (error) {
            this.terminal.writeln(`\x1B[1;31mError: ${error.message}\x1B[0m`);
            this.writePrompt();
        }
    }
    
    /**
     * Format ls command output in a more readable way
     */
    formatLsOutput(output) {
        if (!output) return;
        
        // Strip HTML tags if present
        const plainOutput = this.stripHtml(output);
        
        // Split output into lines
        const lines = plainOutput.split('\n').filter(line => line.trim());
        
        if (lines.length === 0) {
            this.terminal.writeln('\x1B[1;33mNo files found\x1B[0m');
            return;
        }
        
        // Process each line
        lines.forEach(line => {
            const trimmedLine = line.trim();
            
            // Skip empty lines or prompt lines
            if (!trimmedLine || trimmedLine.includes('$')) return;
            
            // Check if it's a file or directory
            if (trimmedLine.startsWith('d') || trimmedLine.includes('drwx')) {
                // Directory - blue color
                this.terminal.writeln(`\x1B[1;34m${trimmedLine}\x1B[0m`);
            } else if (trimmedLine.includes('rwx') && trimmedLine.includes('x')) {
                // Executable - green color
                this.terminal.writeln(`\x1B[1;32m${trimmedLine}\x1B[0m`);
            } else if (trimmedLine.startsWith('l') || trimmedLine.includes(' -> ')) {
                // Symlink - cyan color
                this.terminal.writeln(`\x1B[1;36m${trimmedLine}\x1B[0m`);
            } else if (trimmedLine.endsWith('.log') || trimmedLine.endsWith('.txt')) {
                // Log or text file - yellow color
                this.terminal.writeln(`\x1B[1;33m${trimmedLine}\x1B[0m`);
            } else {
                // Regular file - white color
                this.terminal.writeln(`\x1B[1;37m${trimmedLine}\x1B[0m`);
            }
        });
    }
    
    /**
     * Strip HTML tags from a string
     */
    stripHtml(html) {
        if (!html) return '';
        return html.replace(/<\/?[^>]+(>|$)/g, '');
    }

    /**
     * Display formatted output in the terminal
     */
    displayFormattedOutput(html) {
        // Convert HTML to terminal escape sequences
        const div = document.createElement('div');
        div.innerHTML = html;
        
        // Process the HTML and extract text with formatting
        this.processNode(div);
    }

    /**
     * Process HTML nodes and convert to terminal formatting
     */
    processNode(node) {
        if (node.nodeType === Node.TEXT_NODE) {
            // Write text content directly
            this.terminal.write(node.textContent);
        } else if (node.nodeType === Node.ELEMENT_NODE) {
            // Handle element nodes
            let format = '';
            
            // Apply formatting based on classes
            if (node.classList.contains('terminal-green')) {
                format = '\x1B[32m'; // Green
            } else if (node.classList.contains('terminal-red')) {
                format = '\x1B[31m'; // Red
            } else if (node.classList.contains('terminal-blue')) {
                format = '\x1B[34m'; // Blue
            } else if (node.classList.contains('terminal-yellow')) {
                format = '\x1B[33m'; // Yellow
            } else if (node.classList.contains('terminal-cyan')) {
                format = '\x1B[36m'; // Cyan
            } else if (node.classList.contains('terminal-white')) {
                format = '\x1B[37m'; // White
            } else if (node.classList.contains('terminal-gray')) {
                format = '\x1B[90m'; // Gray
            }
            
            if (node.classList.contains('terminal-bold')) {
                format += '\x1B[1m'; // Bold
            }
            
            // Write format code
            if (format) {
                this.terminal.write(format);
            }
            
            // Process child nodes
            for (const child of node.childNodes) {
                this.processNode(child);
            }
            
            // Reset formatting
            if (format) {
                this.terminal.write('\x1B[0m');
            }
            
            // Handle special elements
            if (node.tagName === 'BR' || node.tagName === 'DIV') {
                this.terminal.writeln('');
            }
        }
    }

    /**
     * Connect to a container
     */
    async connectToContainer(container) {
        if (!container) {
            console.error('No container specified');
            return;
        }
        
        if (!this.terminal) {
            console.error('Terminal not initialized');
            return;
        }
        
        this.terminal.writeln(`\x1B[1;33mConnecting to container: ${container}...\x1B[0m`);
        
        try {
            // Validate the container exists
            const validateResponse = await fetch(`/api/frappe/validate-container?container=${encodeURIComponent(container)}`);
            const validateResult = await validateResponse.json();
            
            if (!validateResult.success) {
                this.terminal.writeln(`\x1B[1;31mError: ${validateResult.error || 'Container not found'}\x1B[0m`);
                return;
            }
            
            // Set the current container
            this.currentContainer = container;
            
            // Update the prompt
            this.writePrompt();
            
            // Get current working directory if the method exists
            if (typeof this.getCurrentDirectory === 'function') {
                try {
                    await this.getCurrentDirectory();
                } catch (dirError) {
                    console.error('Error getting current directory:', dirError);
                }
            } else {
                console.warn('getCurrentDirectory method not found');
                // Set a default directory
                this.currentDir = '/home/frappe';
            }
            
            this.terminal.writeln(`\x1B[1;32mSuccessfully connected to container: ${container}\x1B[0m`);
            this.terminal.writeln('\x1B[1;32mType "help" for available commands\x1B[0m');
        } catch (error) {
            console.error('Error connecting to container:', error);
            if (this.terminal) {
            this.terminal.writeln(`\x1B[1;31mError connecting to container: ${error.message}\x1B[0m`);
        }
        }
    }


    /**
     * List available containers
     */
    async listContainers() {
        this.terminal.writeln('\x1B[1;33mFetching available containers...\x1B[0m');
        
        try {
            const response = await fetch('/api/frappe/list-containers', {
                method: 'GET'
            });
            
            const result = await response.json();
            
            if (result.success && result.containers && result.containers.length > 0) {
                this.terminal.writeln('\x1B[1;32mAvailable containers:\x1B[0m');
                
                // Display containers in a table format
                this.terminal.writeln('┌─────────────────────────────────┬───────────────────────┬───────────────────────┐');
                this.terminal.writeln('│ \x1B[1;36mContainer Name\x1B[0m                │ \x1B[1;36mStatus\x1B[0m                │ \x1B[1;36mImage\x1B[0m                 │');
                this.terminal.writeln('├─────────────────────────────────┼───────────────────────┼───────────────────────┤');
                
                result.containers.forEach(container => {
                    const name = container.Names.padEnd(30).substring(0, 30);
                    const status = container.Status.padEnd(22).substring(0, 22);
                    const image = container.Image.padEnd(22).substring(0, 22);
                    
                    let statusColor = '\x1B[0;37m'; // Default gray
                    if (container.Status.includes('Up')) {
                        statusColor = '\x1B[0;32m'; // Green for running
                    } else if (container.Status.includes('Exited')) {
                        statusColor = '\x1B[0;31m'; // Red for stopped
                    }
                    
                    this.terminal.writeln(`│ \x1B[1;34m${name}\x1B[0m │ ${statusColor}${status}\x1B[0m │ \x1B[0;37m${image}\x1B[0m │`);
                });
                
                this.terminal.writeln('└─────────────────────────────────┴───────────────────────┴───────────────────────┘');
                this.terminal.writeln('');
                this.terminal.writeln('\x1B[1;33mTo connect to a container, type:\x1B[0m \x1B[1;32mconnect <container_name>\x1B[0m');
            } else {
                this.terminal.writeln('\x1B[1;31mNo containers found\x1B[0m');
            }
        } catch (error) {
            this.terminal.writeln(`\x1B[1;31mError fetching containers: ${error.message}\x1B[0m`);
        }
        
        this.writePrompt();
    }
    /**
     * Get current working directory
     */
    async getCurrentDirectory() {
        if (!this.currentContainer) {
            return;
        }
        
        try {
            const response = await fetch('/api/frappe/get-current-dir', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    container: this.currentContainer
                })
            });
            
            const result = await response.json();
            
            if (result.success && result.current_dir) {
                this.currentDir = result.current_dir;
            }
        } catch (error) {
            console.error('Error getting current directory:', error);
        }
    }

    /**
     * Show help message
     */
    showHelp() {
        this.terminal.writeln('\x1B[1;33mAvailable Commands:\x1B[0m');
        this.terminal.writeln('  \x1B[1;32mcontainers\x1B[0m or \x1B[1;32mlist\x1B[0m - List available Docker containers');
        this.terminal.writeln('  \x1B[1;32mconnect <container>\x1B[0m - Connect to a Docker container');
        this.terminal.writeln('  \x1B[1;32mclear\x1B[0m or \x1B[1;32mcls\x1B[0m - Clear the terminal screen');
        this.terminal.writeln('  \x1B[1;32mhelp\x1B[0m - Show this help message');
        this.terminal.writeln('');
        this.terminal.writeln('\x1B[1;33mOnce connected to a container, you can run any command supported by the container.\x1B[0m');
        this.terminal.writeln('Examples:');
        this.terminal.writeln('  \x1B[1;36mls -la\x1B[0m - List files with details');
        this.terminal.writeln('  \x1B[1;36mcd frappe-bench\x1B[0m - Change directory');
        this.terminal.writeln('  \x1B[1;36mtail -f logs/bench.log\x1B[0m - Follow log file');
        this.terminal.writeln('  \x1B[1;36mbench get-app https://github.com/frappe/erpnext\x1B[0m - Get ERPNext app');
        this.terminal.writeln('');
        this.writePrompt();
    }

    /**
     * Generate a unique session ID
     */
    generateSessionId() {
        return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
            const r = Math.random() * 16 | 0;
            const v = c === 'x' ? r : (r & 0x3 | 0x8);
            return v.toString(16);
        });
    }
}

// Initialize the terminal when the page loads
document.addEventListener('DOMContentLoaded', function() {
    // Check if terminal container exists
    if (document.getElementById('terminal-container')) {
        // Initialize terminal
        const terminal = new WebTerminal({
            containerId: 'terminal-container',
            welcomeMessage: 'Frappe Docker Web Terminal'
        });
        
        // Make terminal accessible globally
        window.webTerminal = terminal;
        
        // Initialize terminal
        terminal.init().catch(error => {
            console.error('Failed to initialize terminal:', error);
        });
    }
});
