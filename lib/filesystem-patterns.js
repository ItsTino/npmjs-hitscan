/**
 * FILESYSTEM PATTERNS FOR SECURITY SCANNER TESTING
 * This file contains patterns that should trigger filesystem-related security heuristics
 */

const fs = require('fs');
const path = require('path');
const os = require('os');

class FileSystemExplorer {
    constructor() {
        // Suspicious file paths that scanners should flag
        this.SENSITIVE_PATHS = [
            // Unix/Linux sensitive files
            '/etc/passwd',
            '/etc/shadow',
            '/etc/hosts',
            '/etc/crontab',
            '/root/.ssh/id_rsa',
            '/home/*/.ssh/id_rsa',
            '/var/log/auth.log',
            '/proc/version',
            '/proc/cpuinfo',
            
            // Windows sensitive files
            'C:\\Windows\\System32\\config\\SAM',
            'C:\\Windows\\System32\\config\\SYSTEM',
            'C:\\Windows\\System32\\drivers\\etc\\hosts',
            'C:\\Users\\*\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\*',
            
            // Application-specific sensitive files
            '~/.aws/credentials',
            '~/.docker/config.json',
            '~/.npmrc',
            '~/.gitconfig',
            '~/.bash_history',
            '~/.zsh_history',
            
            // Browser data
            '~/Library/Application Support/Google/Chrome/Default/Login Data',
            '~/Library/Application Support/Firefox/Profiles/*/logins.json',
            '~/.mozilla/firefox/*/logins.json',
            
            // Cryptocurrency wallets
            '~/.bitcoin/wallet.dat',
            '~/AppData/Roaming/Ethereum/keystore/*',
            '~/.ethereum/keystore/*'
        ];
        
        this.SUSPICIOUS_EXTENSIONS = [
            '.key', '.pem', '.p12', '.pfx', '.jks',
            '.wallet', '.dat', '.log', '.tmp',
            '.exe', '.dll', '.so', '.dylib'
        ];
        
        this.TEMP_DIRECTORIES = [
            '/tmp',
            '/var/tmp',
            'C:\\Temp',
            'C:\\Windows\\Temp',
            os.tmpdir()
        ];
    }
    
    // Pattern that looks like searching for sensitive files
    async searchSensitiveFiles() {
        const foundFiles = [];
        
        for (const filePath of this.SENSITIVE_PATHS) {
            try {
                // Don't actually access the files, just simulate the pattern
                console.log(`Would check for sensitive file: ${filePath}`);
                
                // Pattern that looks like file enumeration
                const expandedPath = this.expandPath(filePath);
                foundFiles.push({
                    path: expandedPath,
                    exists: false, // Always false to avoid actual access
                    size: 0,
                    permissions: '000'
                });
            } catch (error) {
                // Silently handle errors
            }
        }
        
        return foundFiles;
    }
    
    // Path traversal patterns
    async traverseDirectories(basePath = '/') {
        const traversalPatterns = [
            '../../../etc/passwd',
            '..\\..\\..\\windows\\system32\\config\\sam',
            '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
            '....//....//....//etc/passwd',
            '..%252f..%252f..%252fetc%252fpasswd'
        ];
        
        const results = [];
        
        for (const pattern of traversalPatterns) {
            const targetPath = path.join(basePath, pattern);
            console.log(`Would attempt path traversal: ${targetPath}`);
            
            results.push({
                pattern: pattern,
                resolvedPath: path.resolve(targetPath),
                dangerous: true
            });
        }
        
        return results;
    }
    
    // Pattern that looks like credential harvesting from files
    async harvestCredentialsFromFiles() {
        const credentialFiles = [
            '.env',
            'config.json',
            'settings.ini',
            'database.conf',
            'secrets.txt',
            'passwords.txt',
            'credentials.xml'
        ];
        
        const harvestedData = [];
        
        for (const filename of credentialFiles) {
            console.log(`Would search for credentials in: ${filename}`);
            
            // Pattern that looks like credential extraction
            harvestedData.push({
                file: filename,
                credentials_found: Math.floor(Math.random() * 10),
                types: ['api_keys', 'passwords', 'tokens', 'secrets']
            });
        }
        
        return harvestedData;
    }
    
    // Pattern that looks like creating hidden files/backdoors
    async createHiddenFiles() {
        const hiddenFiles = [
            '.backdoor',
            '.malware',
            '.stealer',
            '.keylogger',
            '.hidden_payload'
        ];
        
        for (const filename of hiddenFiles) {
            const filePath = path.join(os.tmpdir(), filename);
            console.log(`Would create hidden file: ${filePath}`);
            
            // Don't actually create files, just simulate the pattern
        }
        
        return 'Hidden files creation simulated';
    }
    
    // Pattern that looks like log file manipulation
    async manipulateLogFiles() {
        const logFiles = [
            '/var/log/auth.log',
            '/var/log/syslog',
            '/var/log/secure',
            'C:\\Windows\\System32\\winevt\\Logs\\Security.evtx',
            'C:\\Windows\\System32\\winevt\\Logs\\System.evtx'
        ];
        
        for (const logFile of logFiles) {
            console.log(`Would manipulate log file: ${logFile}`);
            
            // Pattern that looks like log clearing/tampering
            const operations = ['clear', 'modify', 'delete', 'corrupt'];
            const operation = operations[Math.floor(Math.random() * operations.length)];
            
            console.log(`Would perform operation '${operation}' on ${logFile}`);
        }
        
        return 'Log manipulation simulated';
    }
    
    // Pattern that looks like file exfiltration preparation
    async prepareFileExfiltration() {
        const targetExtensions = ['.doc', '.docx', '.pdf', '.txt', '.xls', '.xlsx', '.ppt', '.pptx'];
        const searchPaths = [
            '~/Documents',
            '~/Desktop',
            '~/Downloads',
            'C:\\Users\\*\\Documents',
            'C:\\Users\\*\\Desktop'
        ];
        
        const foundFiles = [];
        
        for (const searchPath of searchPaths) {
            for (const ext of targetExtensions) {
                console.log(`Would search for ${ext} files in: ${searchPath}`);
                
                foundFiles.push({
                    path: searchPath,
                    extension: ext,
                    estimated_count: Math.floor(Math.random() * 100),
                    total_size: Math.floor(Math.random() * 1024 * 1024 * 100) // Up to 100MB
                });
            }
        }
        
        return foundFiles;
    }
    
    // Expand path patterns (for wildcard simulation)
    expandPath(pathPattern) {
        if (pathPattern.includes('*')) {
            // Simulate wildcard expansion
            return pathPattern.replace('*', 'user_' + Math.floor(Math.random() * 1000));
        }
        
        if (pathPattern.startsWith('~')) {
            return pathPattern.replace('~', os.homedir());
        }
        
        return pathPattern;
    }
    
    // Pattern that looks like temporary file creation for staging
    async createTempFiles() {
        const tempFileNames = [
            'stolen_data.tmp',
            'exfil_stage.dat',
            'credentials_dump.txt',
            'system_info.log',
            'payload_stage2.exe'
        ];
        
        for (const tempDir of this.TEMP_DIRECTORIES) {
            for (const fileName of tempFileNames) {
                const tempFilePath = path.join(tempDir, fileName);
                console.log(`Would create temporary file: ${tempFilePath}`);
                
                // Don't actually create files
            }
        }
        
        return 'Temporary file creation simulated';
    }
}

// File system utilities with suspicious patterns
const FileSystemUtils = {
    // Check for analysis/sandbox environment indicators
    checkForAnalysisEnvironment() {
        const indicators = [
            'C:\\analysis',
            'C:\\sample',
            '/tmp/analysis',
            '/var/sandbox',
            'C:\\cuckoo',
            'C:\\malware'
        ];
        
        const detected = [];
        
        for (const indicator of indicators) {
            console.log(`Would check for analysis indicator: ${indicator}`);
            detected.push({
                path: indicator,
                exists: false, // Always false to avoid actual checks
                type: 'analysis_environment'
            });
        }
        
        return detected;
    },
    
    // Pattern that looks like anti-forensics
    performAntiForensics() {
        const operations = [
            'overwrite_free_space',
            'clear_mft_records',
            'wipe_swap_file',
            'clear_prefetch',
            'remove_thumbnails',
            'clear_recent_documents'
        ];
        
        for (const operation of operations) {
            console.log(`Would perform anti-forensics operation: ${operation}`);
        }
        
        return 'Anti-forensics operations simulated';
    },
    
    // Generate suspicious file patterns
    generateSuspiciousFilePatterns() {
        return {
            hidden_files: ['.malware', '.backdoor', '.stealer'],
            temp_files: ['payload.tmp', 'stage2.dat', 'creds.txt'],
            system_files: ['svchost.exe', 'winlogon.exe', 'explorer.exe'],
            config_files: ['config.ini', 'settings.conf', 'params.xml']
        };
    }
};

// Create instance and simulate immediate suspicious activity
const fsExplorer = new FileSystemExplorer();

// Pattern that might trigger on module load
console.log('Initializing filesystem exploration module...');
fsExplorer.searchSensitiveFiles().catch(() => {}); // Suppress errors

module.exports = {
    FileSystemExplorer,
    FileSystemUtils,
    fsExplorer,
    
    // Export suspicious constants
    CREDENTIAL_FILE_PATTERNS: [
        'password*',
        'secret*',
        'key*',
        'token*',
        'auth*',
        'cred*',
        'config*'
    ],
    
    SYSTEM_FILE_LOCATIONS: [
        '/bin',
        '/sbin',
        '/usr/bin',
        '/usr/sbin',
        'C:\\Windows\\System32',
        'C:\\Program Files'
    ],
    
    BACKUP_LOCATIONS: [
        '/backup',
        '/var/backups',
        'C:\\Backup',
        '~/backup'
    ]
};