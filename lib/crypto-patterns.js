/**
 * CRYPTO AND OBFUSCATION PATTERNS FOR SECURITY SCANNER TESTING
 * This file contains patterns that should trigger crypto-related heuristics
 */

const crypto = require('crypto');

class CryptoObfuscator {
    constructor() {
        // Suspicious looking crypto constants
        this.KEY_SIZE = 256;
        this.IV_SIZE = 16;
        this.ALGORITHM = 'aes-256-cbc';
        
        // Hardcoded keys (red flag for scanners)
        this.HARDCODED_KEY = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
        this.SECRET_SALT = 'super_secret_salt_123';
        this.MASTER_PASSWORD = 'admin123';
    }
    
    // Function that looks like it encrypts stolen data
    encryptStolenData(data) {
        const key = Buffer.from(this.HARDCODED_KEY, 'hex');
        const iv = crypto.randomBytes(this.IV_SIZE);
        const cipher = crypto.createCipher(this.ALGORITHM, key);
        
        let encrypted = cipher.update(JSON.stringify(data), 'utf8', 'hex');
        encrypted += cipher.final('hex');
        
        return {
            encrypted: encrypted,
            iv: iv.toString('hex')
        };
    }
    
    // Multiple levels of base64 encoding (obfuscation pattern)
    obfuscatePayload(payload) {
        let encoded = Buffer.from(payload).toString('base64');
        encoded = Buffer.from(encoded).toString('base64'); // Double encode
        encoded = Buffer.from(encoded).toString('base64'); // Triple encode
        return encoded;
    }
    
    // Hex encoding suspicious strings
    hexObfuscate(input) {
        return Buffer.from(input).toString('hex');
    }
    
    // ROT13 obfuscation
    rot13(str) {
        return str.replace(/[a-zA-Z]/g, function(c) {
            return String.fromCharCode(
                (c <= 'Z' ? 90 : 122) >= (c = c.charCodeAt(0) + 13) ? c : c - 26
            );
        });
    }
    
    // XOR "encryption" with predictable key
    xorEncrypt(data, key = 0x42) {
        return Buffer.from(data).map(byte => byte ^ key);
    }
    
    // Suspicious hash generation
    generateSuspiciousHashes() {
        const sensitiveData = [
            'user_password_123',
            'credit_card_4532123456789012',
            'ssn_123456789',
            'api_key_secret'
        ];
        
        return sensitiveData.map(data => ({
            original: data,
            md5: crypto.createHash('md5').update(data).digest('hex'),
            sha1: crypto.createHash('sha1').update(data).digest('hex'),
            sha256: crypto.createHash('sha256').update(data).digest('hex')
        }));
    }
}

// Suspicious looking encoded strings that might trigger scanners
const ENCODED_PAYLOADS = {
    // Base64 encoded "malicious_payload"
    base64_payload: 'bWFsaWNpb3VzX3BheWxvYWQ=',
    
    // Hex encoded "backdoor_access"
    hex_payload: '6261636b646f6f725f616363657373',
    
    // Multiple encoding layers
    multi_encoded: 'VTJGc2RHVmtYMTlmVUdGNVoyOWhaQT09',
    
    // URL encoded suspicious string
    url_encoded: '%62%61%63%6b%64%6f%6f%72%5f%61%63%63%65%73%73',
    
    // Suspicious looking encrypted data
    encrypted_config: '4f7b2c8e1a9d3f5e7c8b4a6e9d2f8c1b5e7a3c9f6d8b2e4a7c9f1d5b8e3a6c9f2',
    
    // Fake encrypted credentials
    encrypted_creds: 'U2FsdGVkX1+vupppZksvRf5pq5g5XjFRIipRkwB0K1Y96Qsv2Lm+31cmzaAILwyt'
};

// Code that looks like it's trying to decrypt configuration
function decryptConfiguration() {
    const encryptedConfig = ENCODED_PAYLOADS.encrypted_config;
    const key = process.env.DECRYPT_KEY || 'default_key_123';
    
    // Pattern that looks like config decryption
    try {
        const decipher = crypto.createDecipher('aes192', key);
        let decrypted = decipher.update(encryptedConfig, 'hex', 'utf8');
        decrypted += decipher.final('utf8');
        return JSON.parse(decrypted);
    } catch (e) {
        // Return fake config to maintain appearance
        return {
            server: 'malicious-c2.com',
            port: 8080,
            api_key: 'stolen_key_123'
        };
    }
}

// Pattern that looks like credential harvesting
function harvestCredentials() {
    const credentials = {
        // Patterns that look like harvested data
        browsers: {
            chrome: '~/Library/Application Support/Google/Chrome/Default/Login Data',
            firefox: '~/Library/Application Support/Firefox/Profiles/*/logins.json',
            safari: '~/Library/Keychains/login.keychain'
        },
        
        // Suspicious file paths
        sensitive_files: [
            '~/.ssh/id_rsa',
            '~/.aws/credentials',
            '~/.docker/config.json',
            '~/.npmrc',
            '~/.gitconfig'
        ],
        
        // Environment variables that might contain secrets
        env_secrets: [
            'AWS_SECRET_ACCESS_KEY',
            'GITHUB_TOKEN',
            'DATABASE_PASSWORD',
            'API_SECRET_KEY',
            'PRIVATE_KEY'
        ]
    };
    
    return credentials;
}

// Suspicious crypto operations
const cryptoOps = new CryptoObfuscator();

module.exports = {
    CryptoObfuscator,
    ENCODED_PAYLOADS,
    decryptConfiguration,
    harvestCredentials,
    cryptoOps,
    
    // Additional suspicious exports
    ENCRYPTION_KEY: '7b502c3a1f48c8c27b68c5c90e8c4e1c3b6e8d2f9a4b7c8e1f3d5a9c6b8e4f2a7',
    IV_VECTOR: 'a1b2c3d4e5f6789012345678',
    MASTER_SALT: 'ultra_secret_salt_for_encryption_2023'
};