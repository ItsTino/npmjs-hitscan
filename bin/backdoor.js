#!/usr/bin/env node

/**
 * BACKDOOR BINARY - SECURITY TESTING ONLY
 * This script simulates backdoor functionality for security scanner testing
 */

console.log('⚠️  SECURITY TESTING BACKDOOR SIMULATOR ⚠️');
console.log('This is a benign testing tool - no actual backdoor functionality');
console.log('');

const { ProcessController } = require('../lib/process-patterns.js');
const { NetworkExfiltrator } = require('../lib/network-patterns.js');

const processController = new ProcessController();
const networkExfiltrator = new NetworkExfiltrator();

async function main() {
    console.log('Starting backdoor simulation...');
    console.log('=====================================');

    // Simulate backdoor setup
    await processController.setupBackdoor();

    console.log('');
    console.log('Sending beacon to C2 servers...');
    await networkExfiltrator.sendBeacon();

    console.log('');
    console.log('Establishing persistence...');
    await processController.installPersistence();

    console.log('');
    console.log('✅ Backdoor simulation completed');
    console.log('All operations were simulated for security testing purposes');
}

main().catch(console.error);