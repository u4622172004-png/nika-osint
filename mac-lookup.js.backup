#!/usr/bin/env node

const { exec } = require('child_process');
const { promisify } = require('util');
const execAsync = promisify(exec);
const fs = require('fs');

// ============================================
// MAC ADDRESS LOOKUP - Device Identification
// ============================================

// OUI Database (top vendors - full database would be too large)
const OUI_DATABASE = {
  '00:00:0C': { vendor: 'Cisco Systems', type: 'Network Equipment' },
  '00:00:5E': { vendor: 'IANA', type: 'Reserved' },
  '00:01:42': { vendor: 'Cisco Systems', type: 'Router/Switch' },
  '00:03:93': { vendor: 'Apple', type: 'Computer/Mobile' },
  '00:05:02': { vendor: 'Apple', type: 'Computer/Mobile' },
  '00:0A:95': { vendor: 'Apple', type: 'Computer/Mobile' },
  '00:0D:93': { vendor: 'Apple', type: 'Computer/Mobile' },
  '00:11:24': { vendor: 'Apple', type: 'Computer/Mobile' },
  '00:14:51': { vendor: 'Apple', type: 'Computer/Mobile' },
  '00:16:CB': { vendor: 'Apple', type: 'Computer/Mobile' },
  '00:17:F2': { vendor: 'Apple', type: 'Computer/Mobile' },
  '00:19:E3': { vendor: 'Apple', type: 'Computer/Mobile' },
  '00:1B:63': { vendor: 'Apple', type: 'Computer/Mobile' },
  '00:1C:B3': { vendor: 'Apple', type: 'Computer/Mobile' },
  '00:1D:4F': { vendor: 'Apple', type: 'Computer/Mobile' },
  '00:1E:52': { vendor: 'Apple', type: 'Computer/Mobile' },
  '00:1F:5B': { vendor: 'Apple', type: 'Computer/Mobile' },
  '00:21:E9': { vendor: 'Apple', type: 'Computer/Mobile' },
  '00:22:41': { vendor: 'Apple', type: 'Computer/Mobile' },
  '00:23:12': { vendor: 'Apple', type: 'Computer/Mobile' },
  '00:23:32': { vendor: 'Apple', type: 'Computer/Mobile' },
  '00:23:6C': { vendor: 'Apple', type: 'Computer/Mobile' },
  '00:23:DF': { vendor: 'Apple', type: 'Computer/Mobile' },
  '00:24:36': { vendor: 'Apple', type: 'Computer/Mobile' },
  '00:25:00': { vendor: 'Apple', type: 'Computer/Mobile' },
  '00:25:4B': { vendor: 'Apple', type: 'Computer/Mobile' },
  '00:25:BC': { vendor: 'Apple', type: 'Computer/Mobile' },
  '00:26:08': { vendor: 'Apple', type: 'Computer/Mobile' },
  '00:26:B0': { vendor: 'Apple', type: 'Computer/Mobile' },
  '00:26:BB': { vendor: 'Apple', type: 'Computer/Mobile' },
  '00:50:56': { vendor: 'VMware', type: 'Virtual Machine' },
  '00:0C:29': { vendor: 'VMware', type: 'Virtual Machine' },
  '00:1C:14': { vendor: 'VMware', type: 'Virtual Machine' },
  '00:05:69': { vendor: 'VMware', type: 'Virtual Machine' },
  '08:00:27': { vendor: 'VirtualBox', type: 'Virtual Machine' },
  '00:15:5D': { vendor: 'Microsoft Hyper-V', type: 'Virtual Machine' },
  '00:1B:21': { vendor: 'Intel', type: 'Network Interface' },
  '00:13:02': { vendor: 'Intel', type: 'Network Interface' },
  '00:1E:67': { vendor: 'Intel', type: 'Network Interface' },
  '00:25:00': { vendor: 'Intel', type: 'Network Interface' },
  'D4:BE:D9': { vendor: 'Dell', type: 'Computer' },
  'B8:CA:3A': { vendor: 'Dell', type: 'Computer' },
  '00:14:22': { vendor: 'Dell', type: 'Computer' },
  '00:1A:A0': { vendor: 'Dell', type: 'Computer' },
  '00:50:F2': { vendor: 'Microsoft', type: 'Computer' },
  '00:03:FF': { vendor: 'Microsoft', type: 'Computer' },
  '00:12:5A': { vendor: 'Microsoft', type: 'Xbox' },
  '7C:ED:8D': { vendor: 'Microsoft', type: 'Xbox/Surface' },
  '98:5F:D3': { vendor: 'Google', type: 'Nest/Chromecast' },
  '54:60:09': { vendor: 'Google', type: 'Nest/Chromecast' },
  'F4:F5:D8': { vendor: 'Google', type: 'Nest/Chromecast' },
  'E8:DE:27': { vendor: 'Raspberry Pi', type: 'IoT/SBC' },
  'B8:27:EB': { vendor: 'Raspberry Pi', type: 'IoT/SBC' },
  'DC:A6:32': { vendor: 'Raspberry Pi', type: 'IoT/SBC' },
  '28:CD:C1': { vendor: 'Raspberry Pi', type: 'IoT/SBC' },
  '00:50:C2': { vendor: 'IEEE 802.1', type: 'Standard' },
  '01:80:C2': { vendor: 'IEEE 802.1', type: 'Spanning Tree' },
  'FF:FF:FF': { vendor: 'Broadcast', type: 'Special' },
  '00:00:00': { vendor: 'Invalid/Test', type: 'Special' },
  '34:97:F6': { vendor: 'Amazon', type: 'Echo/Fire' },
  '68:37:E9': { vendor: 'Amazon', type: 'Echo/Fire' },
  '74:C2:46': { vendor: 'Amazon', type: 'Echo/Fire' },
  'AC:63:BE': { vendor: 'Amazon', type: 'Echo/Fire' },
  '00:FC:8B': { vendor: 'Amazon', type: 'Echo/Fire' },
  '18:74:2E': { vendor: 'TP-Link', type: 'Router/IoT' },
  '50:C7:BF': { vendor: 'TP-Link', type: 'Router/IoT' },
  'F4:F2:6D': { vendor: 'TP-Link', type: 'Router/IoT' },
  '14:CF:92': { vendor: 'TP-Link', type: 'Router/IoT' },
  '10:FE:ED': { vendor: 'Ubiquiti', type: 'Network Equipment' },
  '24:A4:3C': { vendor: 'Ubiquiti', type: 'Network Equipment' },
  '68:D7:9A': { vendor: 'Ubiquiti', type: 'Network Equipment' },
  'DC:9F:DB': { vendor: 'Ubiquiti', type: 'Network Equipment' },
  '00:04:20': { vendor: 'Netgear', type: 'Router' },
  '00:09:5B': { vendor: 'Netgear', type: 'Router' },
  '00:0F:B5': { vendor: 'Netgear', type: 'Router' },
  'A0:63:91': { vendor: 'Netgear', type: 'Router' },
  '20:E5:2A': { vendor: 'Samsung', type: 'Mobile/TV' },
  '34:23:BA': { vendor: 'Samsung', type: 'Mobile/TV' },
  '7C:61:66': { vendor: 'Samsung', type: 'Mobile/TV' },
  'E8:50:8B': { vendor: 'Samsung', type: 'Mobile/TV' },
  '6C:F3:73': { vendor: 'Xiaomi', type: 'Mobile/IoT' },
  '34:CE:00': { vendor: 'Xiaomi', type: 'Mobile/IoT' },
  '64:09:80': { vendor: 'Xiaomi', type: 'Mobile/IoT' },
  'F8:A4:5F': { vendor: 'Xiaomi', type: 'Mobile/IoT' }
};

function normalizeMac(mac) {
  // Remove common separators and convert to uppercase
  let normalized = mac.toUpperCase().replace(/[:-]/g, '');
  
  // Insert colons in standard format
  if (normalized.length === 12) {
    return normalized.match(/.{1,2}/g).join(':');
  }
  
  return mac.toUpperCase();
}

function getOUI(mac) {
  const normalized = normalizeMac(mac);
  const oui = normalized.substring(0, 8); // First 3 bytes (XX:XX:XX)
  
  return oui;
}

function lookupMAC(mac) {
  const normalized = normalizeMac(mac);
  const oui = getOUI(mac);
  
  const result = {
    mac: normalized,
    oui: oui,
    vendor: 'Unknown',
    deviceType: 'Unknown',
    isValid: validateMAC(normalized),
    isBroadcast: normalized === 'FF:FF:FF:FF:FF:FF',
    isMulticast: false,
    isLocal: false,
    isUniversal: false
  };
  
  if (!result.isValid) {
    return result;
  }
  
  // Check OUI database
  if (OUI_DATABASE[oui]) {
    result.vendor = OUI_DATABASE[oui].vendor;
    result.deviceType = OUI_DATABASE[oui].type;
  }
  
  // Check multicast bit (least significant bit of first byte)
  const firstByte = parseInt(normalized.substring(0, 2), 16);
  result.isMulticast = (firstByte & 1) === 1;
  
  // Check local/universal bit (second least significant bit of first byte)
  result.isLocal = (firstByte & 2) === 2;
  result.isUniversal = !result.isLocal;
  
  // Additional analysis
  result.analysis = analyzeMAC(normalized, result);
  
  return result;
}

function validateMAC(mac) {
  const macRegex = /^([0-9A-F]{2}:){5}[0-9A-F]{2}$/;
  return macRegex.test(mac);
}

function analyzeMAC(mac, basicInfo) {
  const analysis = [];
  
  if (basicInfo.isBroadcast) {
    analysis.push('Broadcast address - used to send data to all devices');
  }
  
  if (basicInfo.isMulticast) {
    analysis.push('Multicast address - used for one-to-many communication');
  }
  
  if (basicInfo.isLocal) {
    analysis.push('Locally administered address - manually set or virtual');
  }
  
  if (basicInfo.isUniversal) {
    analysis.push('Universally administered address - factory set by manufacturer');
  }
  
  if (basicInfo.vendor === 'VMware' || basicInfo.vendor === 'VirtualBox' || basicInfo.vendor.includes('Hyper-V')) {
    analysis.push('Virtual machine detected - not a physical device');
  }
  
  if (basicInfo.deviceType === 'Router/Switch') {
    analysis.push('Network infrastructure device');
  }
  
  if (basicInfo.deviceType === 'Mobile' || basicInfo.deviceType === 'Computer/Mobile') {
    analysis.push('End-user device (computer, phone, tablet)');
  }
  
  if (basicInfo.deviceType === 'IoT/SBC' || basicInfo.deviceType === 'IoT') {
    analysis.push('Internet of Things device - may have security implications');
  }
  
  return analysis;
}

async function lookupOnline(mac) {
  try {
    console.log('   Checking online API...');
    
    const cleanMac = mac.replace(/:/g, '');
    const url = `https://api.macvendors.com/${cleanMac}`;
    
    const { stdout } = await execAsync(`curl -s "${url}"`, { timeout: 5000 });
    
    if (stdout && !stdout.includes('error') && stdout.trim().length > 0) {
      return {
        found: true,
        vendor: stdout.trim()
      };
    }
    
    return { found: false };
  } catch (error) {
    return { found: false, error: error.message };
  }
}

function showBanner() {
  console.log("\x1b[31m");
  console.log("███╗   ███╗ █████╗  ██████╗     ██╗      ██████╗  ██████╗ ██╗  ██╗██╗   ██╗██████╗ ");
  console.log("████╗ ████║██╔══██╗██╔════╝     ██║     ██╔═══██╗██╔═══██╗██║ ██╔╝██║   ██║██╔══██╗");
  console.log("██╔████╔██║███████║██║          ██║     ██║   ██║██║   ██║█████╔╝ ██║   ██║██████╔╝");
  console.log("██║╚██╔╝██║██╔══██║██║          ██║     ██║   ██║██║   ██║██╔═██╗ ██║   ██║██╔═══╝ ");
  console.log("██║ ╚═╝ ██║██║  ██║╚██████╗     ███████╗╚██████╔╝╚██████╔╝██║  ██╗╚██████╔╝██║     ");
  console.log("╚═╝     ╚═╝╚═╝  ╚═╝ ╚═════╝     ╚══════╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝     ");
  console.log("\x1b[0m");
  console.log("\x1b[35m🥝 NIKA MAC Address Lookup - Device Identification\x1b[0m");
  console.log("\x1b[33m⚠️  For authorized network analysis only\x1b[0m\n");
}

function displayResults(data, onlineData) {
  console.log("\n╔════════════════════════════════════════════════════════╗");
  console.log("║         🖥️  MAC ADDRESS LOOKUP RESULTS 🖥️              ║");
  console.log("╚════════════════════════════════════════════════════════╝\n");
  
  if (!data.isValid) {
    console.log(`\x1b[31m❌ Invalid MAC address format\x1b[0m`);
    console.log(`   Expected format: XX:XX:XX:XX:XX:XX or XX-XX-XX-XX-XX-XX\n`);
    return;
  }
  
  console.log(`📍 MAC Address: \x1b[36m${data.mac}\x1b[0m`);
  console.log(`🔢 OUI: \x1b[33m${data.oui}\x1b[0m\n`);
  
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
  console.log("\x1b[36m🏭 VENDOR INFORMATION\x1b[0m");
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
  
  console.log(`   Local Database: \x1b[32m${data.vendor}\x1b[0m`);
  console.log(`   Device Type: ${data.deviceType}`);
  
  if (onlineData && onlineData.found) {
    console.log(`   Online API: \x1b[32m${onlineData.vendor}\x1b[0m`);
  }
  
  console.log('');
  
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
  console.log("\x1b[36m🔍 ADDRESS PROPERTIES\x1b[0m");
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
  
  console.log(`   Broadcast: ${data.isBroadcast ? '\x1b[31mYes\x1b[0m' : '\x1b[32mNo\x1b[0m'}`);
  console.log(`   Multicast: ${data.isMulticast ? '\x1b[33mYes\x1b[0m' : 'No'}`);
  console.log(`   Locally Administered: ${data.isLocal ? '\x1b[33mYes\x1b[0m' : 'No'}`);
  console.log(`   Universally Administered: ${data.isUniversal ? '\x1b[32mYes\x1b[0m' : 'No'}`);
  
  if (data.analysis && data.analysis.length > 0) {
    console.log('');
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
    console.log("\x1b[36m💡 ANALYSIS\x1b[0m");
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
    
    data.analysis.forEach(note => {
      console.log(`   • ${note}`);
    });
  }
  
  console.log('');
}

function saveResults(data, onlineData) {
  const dir = './mac-lookup-reports';
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, -5);
  const macSafe = data.mac.replace(/:/g, '-');
  const jsonFile = `${dir}/${macSafe}-${timestamp}.json`;
  const txtFile = jsonFile.replace('.json', '.txt');
  
  const fullData = {
    ...data,
    onlineVendor: onlineData?.vendor || null,
    timestamp: new Date().toISOString()
  };
  
  fs.writeFileSync(jsonFile, JSON.stringify(fullData, null, 2));
  
  let txtContent = `═══════════════════════════════════════════════════════════
MAC ADDRESS LOOKUP REPORT
═══════════════════════════════════════════════════════════

MAC Address: ${data.mac}
OUI: ${data.oui}
Date: ${new Date().toLocaleString()}

═══════════════════════════════════════════════════════════
VENDOR INFORMATION
═══════════════════════════════════════════════════════════

Vendor (Local DB): ${data.vendor}
Vendor (Online): ${onlineData?.vendor || 'Not checked'}
Device Type: ${data.deviceType}

═══════════════════════════════════════════════════════════
ADDRESS PROPERTIES
═══════════════════════════════════════════════════════════

Broadcast: ${data.isBroadcast ? 'Yes' : 'No'}
Multicast: ${data.isMulticast ? 'Yes' : 'No'}
Locally Administered: ${data.isLocal ? 'Yes' : 'No'}
Universally Administered: ${data.isUniversal ? 'Yes' : 'No'}

═══════════════════════════════════════════════════════════
ANALYSIS
═══════════════════════════════════════════════════════════

`;

  if (data.analysis && data.analysis.length > 0) {
    data.analysis.forEach(note => {
      txtContent += `• ${note}\n`;
    });
  } else {
    txtContent += 'No special notes.\n';
  }
  
  fs.writeFileSync(txtFile, txtContent);
  
  console.log(`\x1b[32m✅ Results saved:\x1b[0m`);
  console.log(`   JSON: ${jsonFile}`);
  console.log(`   TXT: ${txtFile}\n`);
}

function showHelp() {
  showBanner();
  
  console.log("Usage: node mac-lookup.js [OPTIONS] <MAC-address>\n");
  console.log("Options:");
  console.log("  --online         Check online API for vendor info");
  console.log("  --save           Save results to file");
  console.log("  --help           Show this help\n");
  
  console.log("MAC Address Formats:");
  console.log("  XX:XX:XX:XX:XX:XX");
  console.log("  XX-XX-XX-XX-XX-XX");
  console.log("  XXXXXXXXXXXX\n");
  
  console.log("Examples:");
  console.log("  node mac-lookup.js 00:1A:A0:12:34:56");
  console.log("  node mac-lookup.js 00-1A-A0-12-34-56 --online");
  console.log("  node mac-lookup.js 001AA0123456 --save\n");
}

async function main() {
  const args = process.argv.slice(2);
  
  if (args.includes('--help') || args.length === 0) {
    showHelp();
    process.exit(0);
  }
  
  let mac = null;
  let checkOnline = false;
  let saveResults_flag = false;
  
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--online') {
      checkOnline = true;
    } else if (args[i] === '--save') {
      saveResults_flag = true;
    } else if (!args[i].startsWith('--')) {
      mac = args[i];
    }
  }
  
  if (!mac) {
    console.log("\x1b[31m❌ No MAC address specified!\x1b[0m\n");
    showHelp();
    process.exit(1);
  }
  
  showBanner();
  
  console.log(`⏳ Analyzing MAC address: ${mac}...\n`);
  
  const results = lookupMAC(mac);
  
  let onlineData = null;
  if (checkOnline && results.isValid) {
    onlineData = await lookupOnline(results.mac);
  }
  
  displayResults(results, onlineData);
  
  if (saveResults_flag && results.isValid) {
    saveResults(results, onlineData);
  }
  
  console.log("\x1b[31m███╗   ███╗ █████╗  ██████╗\x1b[0m");
  console.log("\x1b[35m🥝 Lookup complete - by kiwi & 777\x1b[0m\n");
}

main().catch(console.error);
