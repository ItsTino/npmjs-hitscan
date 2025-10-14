/**
 * ADDITIONAL OBFUSCATED PATTERNS FOR SECURITY SCANNER TESTING
 * This file contains more advanced obfuscation techniques that scanners should detect
 */

// Obfuscated eval patterns
const evilEval = global['\x65\x76\x61\x6c']; // eval in hex
const hiddenFunction = Function('\x72\x65\x74\x75\x72\x6e\x20\x22\x62\x65\x6e\x69\x67\x6e\x22'); // return "benign" in hex

// Multiple layers of obfuscation
const layer1 = atob('bWFsaWNpb3VzX3BheWxvYWQ='); // malicious_payload
const layer2 = Buffer.from('6261636b646f6f72', 'hex').toString(); // backdoor
const layer3 = String.fromCharCode(115,116,101,97,108,95,100,97,116,97); // steal_data

// Suspicious looking encrypted configuration
const CONFIG = {
    // Fake encrypted C2 configuration
    c2: '\x68\x74\x74\x70\x73\x3a\x2f\x2f\x65\x76\x69\x6c\x2e\x63\x6f\x6d',
    // Fake API endpoints
    endpoints: [
        '/api/v1/exfiltrate',
        '/upload/stolen',
        '/c2/command',
        '/beacon/checkin'
    ],
    // Fake encryption keys
    keys: {
        master: '0x' + '41414141'.repeat(8),
        session: Buffer.from('secret_key_123').toString('base64'),
        backup: 'sk_live_' + Math.random().toString(36).substring(2, 15)
    }
};

// Pattern that looks like dynamic code loading
function loadMaliciousCode() {
    const encodedPayload = [
        'Y29uc29sZS5sb2coIkJlbmlnbiBmdW5jdGlvbiIp', // console.log("Benign function")
        '7B0K7D0A', // Empty object in hex
        'ZnVuY3Rpb24oKXtyZXR1cm4iYmVuaWduIn0=' // function(){return"benign"}
    ];
    
    encodedPayload.forEach(payload => {
        try {
            const decoded = atob(payload);
            console.log('Would execute payload:', decoded);
        } catch (e) {
            // Silently fail
        }
    });
}

// Suspicious regex patterns for data extraction
const REGEX_PATTERNS = {
    creditCard: /\b(?:\d{4}[-\s]?){3}\d{4}\b/g,
    ssn: /\b\d{3}-?\d{2}-?\d{4}\b/g,
    email: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g,
    apiKey: /\b[A-Za-z0-9]{32,}\b/g,
    password: /password[:\s=]+[^\s\n]+/gi,
    token: /token[:\s=]+[^\s\n]+/gi
};

// Pattern that looks like data extraction
function extractSensitiveData(text) {
    const matches = {};
    Object.keys(REGEX_PATTERNS).forEach(pattern => {
        matches[pattern] = text.match(REGEX_PATTERNS[pattern]) || [];
    });
    return matches;
}

// Suspicious looking shellcode patterns
const SHELLCODE_PATTERNS = [
    '\x90\x90\x90\x90', // NOP sled
    '\x48\x31\xc0',     // xor rax,rax
    '\xeb\xfe',         // jmp short $
    '\xcc\xcc\xcc\xcc', // int3 instructions
    '\x41\x41\x41\x41'  // Buffer overflow pattern
];

// Function that looks like it's preparing shellcode
function prepareShellcode() {
    const buffer = Buffer.alloc(256);
    
    SHELLCODE_PATTERNS.forEach((pattern, index) => {
        console.log(`Would write shellcode pattern ${index}: ${pattern}`);
        // Don't actually write anything malicious
    });
    
    return buffer;
}

// Anti-analysis patterns
const ANTI_ANALYSIS = {
    checkDebugger: function() {
        // Pattern that looks like debugger detection
        const start = Date.now();
        const end = Date.now();
        return (end - start) > 100; // Timing check
    },
    
    checkVM: function() {
        // Pattern that looks like VM detection
        const vmIndicators = [
            'VirtualBox',
            'VMware',
            'QEMU',
            'Xen'
        ];
        return vmIndicators.some(indicator => 
            process.env.COMPUTERNAME?.includes(indicator)
        );
    },
    
    checkSandbox: function() {
        // Pattern that looks like sandbox detection
        const sandboxIndicators = [
            '/tmp/analysis',
            'C:\\analysis',
            'cuckoo',
            'sandbox'
        ];
        return sandboxIndicators.some(indicator => 
            process.cwd().toLowerCase().includes(indicator.toLowerCase())
        );
    }
};

// Pattern that looks like polymorphic code
function generatePolymorphicCode() {
    const templates = [
        'function %s() { return "%s"; }',
        'const %s = () => "%s";',
        'var %s = function() { return "%s"; };'
    ];
    
    const randomName = Math.random().toString(36).substring(2, 8);
    const template = templates[Math.floor(Math.random() * templates.length)];
    
    console.log('Would generate polymorphic function:', template.replace(/%s/g, randomName));
    return template;
}

// Pattern that looks like command and control
class CommandControl {
    constructor() {
        this.commands = [];
        this.isActive = false;
        this.heartbeatInterval = null;
    }
    
    start() {
        console.log('Would start C2 communication');
        this.isActive = true;
        
        // Simulate heartbeat
        this.heartbeatInterval = setInterval(() => {
            console.log('Would send heartbeat to C2');
        }, 30000);
    }
    
    executeCommand(command) {
        console.log(`Would execute C2 command: ${command}`);
        this.commands.push({
            command: command,
            timestamp: Date.now(),
            status: 'simulated'
        });
    }
    
    stop() {
        console.log('Would stop C2 communication');
        this.isActive = false;
        if (this.heartbeatInterval) {
            clearInterval(this.heartbeatInterval);
        }
    }
}

// Create instances that might trigger on module load
const c2 = new CommandControl();

// Export everything with suspicious names
module.exports = {
    // Obfuscated functions
    evilEval,
    hiddenFunction,
    loadMaliciousCode,
    
    // Data extraction
    extractSensitiveData,
    REGEX_PATTERNS,
    
    // Shellcode patterns
    prepareShellcode,
    SHELLCODE_PATTERNS,
    
    // Anti-analysis
    ANTI_ANALYSIS,
    generatePolymorphicCode,
    
    // Command and control
    CommandControl,
    c2,
    
    // Suspicious constants
    CONFIG,
    OBFUSCATED_STRINGS: {
        backdoor: layer2,
        stealer: layer3,
        payload: layer1
    },
    
    // More suspicious exports
    EXPLOIT_BUFFER: Buffer.alloc(1024, 'A'),
    ROP_CHAIN: [0x41414141, 0x42424242, 0x43434343],
    SHELLCODE_SIZE: 256,
    PAYLOAD_OFFSET: 140
};