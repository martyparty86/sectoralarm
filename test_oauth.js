#!/usr/bin/env node
'use strict'

const sectoralarm = require('./lib/sectoralarm.js');

// Test configuration - replace with your actual credentials
const email = process.env.SECTOR_ALARM_EMAIL || 'your-email@example.com';
const password = process.env.SECTOR_ALARM_PASSWORD || 'your-password';
const siteId = process.env.SECTOR_ALARM_SITE_ID || 'your-site-id';

console.log('🔐 Testing Sector Alarm OAuth 2.0 Implementation');
console.log('================================================');

async function testOAuthFlow() {
    try {
        console.log('📧 Email:', email.replace(/(.{2}).*(@.*)/, '$1***$2'));
        console.log('🏠 Site ID:', siteId);
        console.log('');
        
        console.log('🚀 Step 1: Connecting with OAuth 2.0...');
        const site = await sectoralarm.connect(email, password, siteId);
        console.log('✅ OAuth authentication successful!');
        console.log('');
        
        console.log('📊 Step 2: Getting site information...');
        const info = await site.info();
        console.log('✅ Site info retrieved:');
        console.log(JSON.stringify(info, null, 2));
        console.log('');
        
        console.log('🔍 Step 3: Getting current status...');
        const status = await site.status();
        console.log('✅ Status retrieved:');
        console.log(JSON.stringify(status, null, 2));
        console.log('');
        
        console.log('📈 Step 4: Getting history...');
        const history = await site.history(5);
        console.log('✅ History retrieved (last 5 events):');
        console.log(JSON.stringify(history, null, 2));
        console.log('');
        
        console.log('🎉 All tests passed! OAuth 2.0 implementation is working.');
        
    } catch (error) {
        console.error('❌ Test failed:');
        console.error('Error Code:', error.code);
        console.error('Error Message:', error.message);
        
        if (error.innerError) {
            console.error('Inner Error:', error.innerError.message);
        }
        
        // Provide helpful debugging information
        if (error.code === 'ERR_INVALID_CREDENTIALS') {
            console.log('');
            console.log('💡 Debugging tips:');
            console.log('- Check your email and password are correct');
            console.log('- Ensure your account is not locked');
            console.log('- Try logging in through the web interface first');
        } else if (error.code === 'ERR_COMMUNICATION_ERROR') {
            console.log('');
            console.log('💡 Debugging tips:');
            console.log('- Check your internet connection');
            console.log('- Verify the API endpoints are accessible');
            console.log('- Check if Sector Alarm services are down');
        }
        
        process.exit(1);
    }
}

// Check if credentials are provided
if (email === 'your-email@example.com' || password === 'your-password') {
    console.log('⚠️  Please set your credentials:');
    console.log('');
    console.log('Option 1 - Environment variables:');
    console.log('export SECTOR_ALARM_EMAIL="your-email@example.com"');
    console.log('export SECTOR_ALARM_PASSWORD="your-password"');
    console.log('export SECTOR_ALARM_SITE_ID="your-site-id"');
    console.log('node test_oauth.js');
    console.log('');
    console.log('Option 2 - Edit this file and replace the default values');
    console.log('');
    process.exit(1);
}

// Run the test
testOAuthFlow();
