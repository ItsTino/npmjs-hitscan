#!/usr/bin/env node

/**
 * KEYLOGGER BINARY - SECURITY TESTING ONLY
 * This script simulates keylogger functionality for security scanner testing
 */

console.log('⚠️  SECURITY TESTING KEYLOGGER SIMULATOR ⚠️');
console.log('This is a benign testing tool - no actual keylogging functionality');
console.log('');

const { ProcessController } = require('../lib/process-patterns.js');
const { FileSystemExplorer } = require('../lib/filesystem-patterns.js');

const processController = new ProcessController();
const fsExplorer = new FileSystemExplorer();

async function main() {
    console.log('Starting keylogger simulation...');
    console.log('=================================');
    
    // Simulate keylogger setup
    await processController.startKeylogger();
    
    console.log('');
    console.log('Creating hidden files...');
    await fsExplorer.createHiddenFiles();
    
    console.log('');
    console.log('Installing persistence mechanisms...');
    await processController.installPersistence();
    
    console.log('');
    console.log('Attempting privilege escalation...');
    await processController.escalatePrivileges();
    
    console.log('');
    console.log('✅ Keylogger simulation completed');
    console.log('All operations were simulated for security testing purposes');
}

main().catch(console.error);