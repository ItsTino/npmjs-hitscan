/**
 * NETWORK AND DATA EXFILTRATION PATTERNS FOR SECURITY SCANNER TESTING
 * This file contains patterns that should trigger network-related security heuristics
 */

const https = require('https');
const http = require('http');
const dns = require('dns');
const net = require('net');
const url = require('url');

class NetworkExfiltrator {
    constructor() {
        // Suspicious domains and IPs
        this.C2_SERVERS = [
            'malicious-c2.com',
            'evil-domain.net',
            'attacker-server.org',
            'data-exfil.malicious',
            'backdoor.evil'
        ];
        
        this.SUSPICIOUS_IPS = [
            '192.168.1.100',  // Local network scanning
            '10.0.0.1',       // Internal network
            '127.0.0.1',      // Localhost
            '0.0.0.0',        // All interfaces
            '203.0.113.1'     // Documentation IP (RFC 5737)
        ];
        
        this.EXFIL_ENDPOINTS = [
            '/api/exfiltrate',
            '/upload/stolen',
            '/collect/data',
            '/beacon/checkin',
            '/c2/command'
        ];
        
        this.SUSPICIOUS_USER_AGENTS = [
            'Backdoor/1.0',
            'DataExfiltrator/2.1',
            'MalwareBot/3.0',
            'StealthyScraper/1.5'
        ];
    }
    
    // Pattern that looks like data exfiltration
    async exfiltrateData(sensitiveData) {
        const payload = {
            timestamp: Date.now(),
            hostname: require('os').hostname(),
            user: process.env.USER,
            data: sensitiveData,
            system_info: this.gatherSystemInfo()
        };
        
        // Pattern that looks like it's sending data to multiple C2 servers
        for (const server of this.C2_SERVERS) {
            for (const endpoint of this.EXFIL_ENDPOINTS) {
                const targetUrl = `https://${server}${endpoint}`;
                
                // Don't actually make the request, just log the pattern
                console.log(`Would exfiltrate to: ${targetUrl}`);
                console.log(`Payload size: ${JSON.stringify(payload).length} bytes`);
            }
        }
        
        return 'Data exfiltration simulated';
    }
    
    // Pattern that looks like system information gathering
    gatherSystemInfo() {
        return {
            platform: process.platform,
            arch: process.arch,
            version: process.version,
            memory: process.memoryUsage(),
            uptime: process.uptime(),
            env_vars: Object.keys(process.env).filter(key => 
                key.includes('TOKEN') || 
                key.includes('KEY') || 
                key.includes('SECRET') ||
                key.includes('PASSWORD')
            )
        };
    }
    
    // DNS queries that might look suspicious
    async performSuspiciousDnsQueries() {
        const suspiciousDomains = [
            'is-scanner-running.check.com',
            'vm-detection.analysis.net',
            'sandbox-evasion.test.org',
            'dynamic-analysis.detection.com'
        ];
        
        for (const domain of suspiciousDomains) {
            console.log(`Would perform DNS lookup for: ${domain}`);
            // Don't actually perform DNS queries
        }
    }
    
    // Pattern that looks like port scanning
    async portScan(target) {
        const commonPorts = [21, 22, 23, 25, 53, 80, 110, 443, 993, 995, 3389, 5432, 3306];
        const results = [];
        
        for (const port of commonPorts) {
            console.log(`Would scan ${target}:${port}`);
            // Don't actually scan ports
            results.push({
                host: target,
                port: port,
                status: 'simulated'
            });
        }
        
        return results;
    }
    
    // Pattern that looks like beacon/heartbeat to C2
    async sendBeacon() {
        const beaconData = {
            id: this.generateBotId(),
            timestamp: Date.now(),
            status: 'active',
            commands_pending: Math.floor(Math.random() * 5),
            last_command: Date.now() - Math.floor(Math.random() * 3600000)
        };
        
        for (const server of this.C2_SERVERS) {
            const beaconUrl = `https://${server}/beacon`;
            console.log(`Would send beacon to: ${beaconUrl}`);
            console.log(`Beacon data:`, beaconData);
        }
        
        return beaconData;
    }
    
    // Generate suspicious looking bot ID
    generateBotId() {
        const prefix = 'BOT_';
        const timestamp = Date.now().toString(36);
        const random = Math.random().toString(36).substring(2, 8);
        return `${prefix}${timestamp}_${random}`.toUpperCase();
    }
    
    // Pattern that looks like downloading additional payloads
    async downloadPayload(payloadUrl) {
        const suspiciousPayloads = [
            'https://evil-domain.com/stage2.js',
            'https://malicious-cdn.net/backdoor.exe',
            'https://attacker-server.org/keylogger.dll',
            'https://c2-server.evil/payload.bin'
        ];
        
        for (const payload of suspiciousPayloads) {
            console.log(`Would download payload from: ${payload}`);
            // Don't actually download anything
        }
        
        return 'Payload download simulated';
    }
    
    // Pattern that looks like credential theft over network
    async stealCredentials() {
        const credentialSources = [
            'browser_saved_passwords',
            'keychain_entries',
            'environment_variables',
            'config_files',
            'memory_dumps'
        ];
        
        const stolenCreds = credentialSources.map(source => ({
            source: source,
            count: Math.floor(Math.random() * 50),
            timestamp: Date.now(),
            encrypted: true
        }));
        
        // Pattern that looks like sending stolen credentials
        for (const server of this.C2_SERVERS) {
            const endpoint = `https://${server}/stolen-creds`;
            console.log(`Would upload stolen credentials to: ${endpoint}`);
            console.log(`Credentials:`, stolenCreds);
        }
        
        return stolenCreds;
    }
}

// Suspicious network utilities
const NetworkUtils = {
    // Check if running in analysis environment
    async isAnalysisEnvironment() {
        const checks = [
            // VM detection patterns
            'VirtualBox',
            'VMware',
            'QEMU',
            'Xen',
            'Hyper-V'
        ];
        
        // Pattern that looks like sandbox evasion
        return checks.some(vm => process.env.COMPUTERNAME?.includes(vm));
    },
    
    // Generate suspicious network traffic patterns
    generateTrafficPattern() {
        return {
            protocol: ['HTTP', 'HTTPS', 'FTP', 'SSH'][Math.floor(Math.random() * 4)],
            frequency: Math.floor(Math.random() * 3600), // seconds
            data_size: Math.floor(Math.random() * 1024 * 1024), // bytes
            encryption: true,
            obfuscated: true
        };
    },
    
    // Pattern that looks like network reconnaissance
    async networkRecon() {
        const targets = [
            '192.168.1.0/24',  // Local network
            '10.0.0.0/8',      // Private network
            '172.16.0.0/12'    // Private network
        ];
        
        for (const target of targets) {
            console.log(`Would perform network reconnaissance on: ${target}`);
        }
        
        return 'Network reconnaissance simulated';
    }
};

// Create instance for immediate suspicious activity
const exfiltrator = new NetworkExfiltrator();

// Patterns that might trigger on module load
console.log('Initializing network exfiltration module...');
exfiltrator.sendBeacon().catch(() => {}); // Suppress errors

module.exports = {
    NetworkExfiltrator,
    NetworkUtils,
    exfiltrator,
    
    // Export suspicious constants
    MALICIOUS_DOMAINS: [
        'stealer.malicious.com',
        'keylogger.evil.net',
        'backdoor.attacker.org'
    ],
    
    EXFIL_PORTS: [8080, 4444, 31337, 1337, 6666],
    
    C2_PROTOCOLS: ['HTTPS', 'DNS', 'ICMP', 'IRC', 'P2P']
};