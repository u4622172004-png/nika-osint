#!/usr/bin/env node

const { exec } = require('child_process');
const { promisify } = require('util');
const execAsync = promisify(exec);
const fs = require('fs');

// ============================================
// WIFI ANALYZER - Network Security Analysis
// ============================================

async function scanWiFiNetworks() {
  try {
    console.log('   Scanning WiFi networks...');
    
    // Use termux-wifi-scaninfo
    const { stdout } = await execAsync('termux-wifi-scaninfo', { timeout: 10000 });
    
    const networks = JSON.parse(stdout);
    
    return networks.map(net => ({
      ssid: net.ssid,
      bssid: net.bssid,
      frequency: net.frequency,
      rssi: net.rssi,
      security: analyzeSecurityType(net),
      channel: getChannel(net.frequency),
      signalStrength: calculateSignalStrength(net.rssi),
      vendor: getVendorFromBSSID(net.bssid),
      risk: assessSecurityRisk(net)
    }));
  } catch (error) {
    return {
      available: false,
      error: error.message,
      suggestion: 'Install termux-api: pkg install termux-api'
    };
  }
}

function analyzeSecurityType(network) {
  const capabilities = network.capabilities || '';
  
  let security = {
    type: 'Unknown',
    encryption: [],
    secure: false,
    vulnerabilities: []
  };
  
  if (capabilities.includes('WPA3')) {
    security.type = 'WPA3';
    security.encryption = ['SAE'];
    security.secure = true;
  } else if (capabilities.includes('WPA2')) {
    security.type = 'WPA2';
    security.encryption = capabilities.includes('CCMP') ? ['AES-CCMP'] : ['TKIP'];
    security.secure = true;
    if (capabilities.includes('TKIP')) {
      security.vulnerabilities.push('TKIP is deprecated, use AES-CCMP only');
    }
  } else if (capabilities.includes('WPA')) {
    security.type = 'WPA';
    security.encryption = ['TKIP'];
    security.secure = false;
    security.vulnerabilities.push('WPA is vulnerable, upgrade to WPA2/WPA3');
  } else if (capabilities.includes('WEP')) {
    security.type = 'WEP';
    security.encryption = ['WEP'];
    security.secure = false;
    security.vulnerabilities.push('WEP is completely broken, easily crackable');
  } else if (capabilities.includes('ESS')) {
    security.type = 'Open';
    security.encryption = [];
    security.secure = false;
    security.vulnerabilities.push('No encryption - all traffic visible');
  }
  
  return security;
}

function getChannel(frequency) {
  if (frequency >= 2412 && frequency <= 2484) {
    // 2.4 GHz band
    return Math.floor((frequency - 2412) / 5) + 1;
  } else if (frequency >= 5170 && frequency <= 5825) {
    // 5 GHz band
    const channels = {
      5180: 36, 5200: 40, 5220: 44, 5240: 48,
      5260: 52, 5280: 56, 5300: 60, 5320: 64,
      5500: 100, 5520: 104, 5540: 108, 5560: 112,
      5580: 116, 5600: 120, 5620: 124, 5640: 128,
      5660: 132, 5680: 136, 5700: 140, 5745: 149,
      5765: 153, 5785: 157, 5805: 161, 5825: 165
    };
    return channels[frequency] || Math.floor((frequency - 5000) / 5);
  }
  return 'Unknown';
}

function calculateSignalStrength(rssi) {
  if (rssi >= -50) return { level: 'Excellent', quality: 100 };
  if (rssi >= -60) return { level: 'Good', quality: 80 };
  if (rssi >= -70) return { level: 'Fair', quality: 60 };
  if (rssi >= -80) return { level: 'Weak', quality: 40 };
  return { level: 'Very Weak', quality: 20 };
}

function getVendorFromBSSID(bssid) {
  if (!bssid) return 'Unknown';
  
  const oui = bssid.substring(0, 8).toUpperCase();
  
  const vendors = {
    '00:03:93': 'Apple',
    '00:1B:63': 'Apple',
    '00:26:BB': 'Apple',
    'B8:27:EB': 'Raspberry Pi',
    'DC:A6:32': 'Raspberry Pi',
    '18:74:2E': 'TP-Link',
    '50:C7:BF': 'TP-Link',
    'F4:F2:6D': 'TP-Link',
    '00:50:56': 'VMware',
    '00:0C:29': 'VMware',
    'D4:6E:0E': 'TP-Link',
    'E8:DE:27': 'Raspberry Pi',
    '28:CD:C1': 'Raspberry Pi',
    '00:04:20': 'Netgear',
    '00:09:5B': 'Netgear',
    'A0:63:91': 'Netgear',
    '10:FE:ED': 'Ubiquiti',
    '24:A4:3C': 'Ubiquiti',
    '68:D7:9A': 'Ubiquiti',
    'DC:9F:DB': 'Ubiquiti',
    '00:1A:A0': 'Dell',
    'D4:BE:D9': 'Dell',
    '00:14:22': 'Dell'
  };
  
  return vendors[oui] || 'Unknown';
}

function assessSecurityRisk(network) {
  const risks = [];
  let score = 0;
  
  const security = analyzeSecurityType(network);
  
  if (security.type === 'Open') {
    risks.push('No encryption - CRITICAL security risk');
    score += 50;
  }
  
  if (security.type === 'WEP') {
    risks.push('WEP encryption - easily crackable within minutes');
    score += 40;
  }
  
  if (security.type === 'WPA') {
    risks.push('WPA encryption - vulnerable to dictionary attacks');
    score += 30;
  }
  
  if (security.encryption.includes('TKIP')) {
    risks.push('TKIP encryption - deprecated and vulnerable');
    score += 15;
  }
  
  if (network.ssid === '' || !network.ssid) {
    risks.push('Hidden SSID - potential rogue AP');
    score += 10;
  }
  
  if (network.ssid && (network.ssid.includes('Free') || network.ssid.includes('Public'))) {
    risks.push('Public WiFi name - possible evil twin attack');
    score += 20;
  }
  
  let level;
  if (score >= 40) level = 'CRITICAL';
  else if (score >= 25) level = 'HIGH';
  else if (score >= 10) level = 'MEDIUM';
  else level = 'LOW';
  
  return {
    score: Math.min(score, 100),
    level: level,
    risks: risks
  };
}

function detectRogueAPs(networks) {
  const rogueAPs = [];
  const ssidMap = {};
  
  networks.forEach(net => {
    if (!net.ssid) return;
    
    if (!ssidMap[net.ssid]) {
      ssidMap[net.ssid] = [];
    }
    ssidMap[net.ssid].push(net);
  });
  
  Object.entries(ssidMap).forEach(([ssid, aps]) => {
    if (aps.length > 1) {
      const vendors = [...new Set(aps.map(ap => ap.vendor))];
      if (vendors.length > 1 || vendors.includes('Unknown')) {
        rogueAPs.push({
          ssid: ssid,
          count: aps.length,
          bssids: aps.map(ap => ap.bssid),
          vendors: vendors,
          warning: 'Multiple APs with same SSID but different vendors - possible evil twin'
        });
      }
    }
  });
  
  return rogueAPs;
}

function showBanner() {
  console.log("\x1b[31m");
  console.log("██╗    ██╗██╗███████╗██╗     █████╗ ███╗   ██╗ █████╗ ██╗  ██╗   ██╗███████╗███████╗██████╗ ");
  console.log("██║    ██║██║██╔════╝██║    ██╔══██╗████╗  ██║██╔══██╗██║  ╚██╗ ██╔╝╚══███╔╝██╔════╝██╔══██╗");
  console.log("██║ █╗ ██║██║█████╗  ██║    ███████║██╔██╗ ██║███████║██║   ╚████╔╝   ███╔╝ █████╗  ██████╔╝");
  console.log("██║███╗██║██║██╔══╝  ██║    ██╔══██║██║╚██╗██║██╔══██║██║    ╚██╔╝   ███╔╝  ██╔══╝  ██╔══██╗");
  console.log("╚███╔███╔╝██║██║     ██║    ██║  ██║██║ ╚████║██║  ██║███████╗██║   ███████╗███████╗██║  ██║");
  console.log(" ╚══╝╚══╝ ╚═╝╚═╝     ╚═╝    ╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝╚═╝   ╚══════╝╚══════╝╚═╝  ╚═╝");
  console.log("\x1b[0m");
  console.log("\x1b[35m🥝 NIKA WiFi Analyzer - Network Security Analysis\x1b[0m");
  console.log("\x1b[33m⚠️  For authorized network testing only\x1b[0m\n");
}

function displayResults(data) {
  console.log("\n╔════════════════════════════════════════════════════════╗");
  console.log("║       📡 WIFI NETWORK ANALYSIS RESULTS 📡              ║");
  console.log("╚════════════════════════════════════════════════════════╝\n");
  
  if (data.error) {
    console.log(`\x1b[31m❌ Error: ${data.error}\x1b[0m`);
    console.log(`\x1b[33m💡 ${data.suggestion}\x1b[0m\n`);
    return;
  }
  
  console.log(`📊 Found ${data.networks.length} networks\n`);
  
  // Summary stats
  const securityStats = {
    'WPA3': 0,
    'WPA2': 0,
    'WPA': 0,
    'WEP': 0,
    'Open': 0
  };
  
  data.networks.forEach(net => {
    securityStats[net.security.type] = (securityStats[net.security.type] || 0) + 1;
  });
  
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
  console.log("\x1b[36m📊 SECURITY OVERVIEW\x1b[0m");
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
  
  Object.entries(securityStats).forEach(([type, count]) => {
    if (count > 0) {
      const color = type === 'WPA3' ? '\x1b[32m' :
                    type === 'WPA2' ? '\x1b[32m' :
                    type === 'WPA' ? '\x1b[33m' :
                    type === 'WEP' ? '\x1b[31m' : '\x1b[31m';
      console.log(`   ${color}${type}: ${count} networks\x1b[0m`);
    }
  });
  console.log('');
  
  // Network details
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
  console.log("\x1b[36m📡 DETECTED NETWORKS\x1b[0m");
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
  
  data.networks.slice(0, 20).forEach((net, i) => {
    const riskColor = net.risk.level === 'CRITICAL' ? '\x1b[41m\x1b[37m' :
                      net.risk.level === 'HIGH' ? '\x1b[31m' :
                      net.risk.level === 'MEDIUM' ? '\x1b[33m' : '\x1b[32m';
    
    console.log(`${i + 1}. ${net.ssid || '[Hidden SSID]'}`);
    console.log(`   BSSID: ${net.bssid}`);
    console.log(`   Security: ${net.security.type} (${net.security.encryption.join(', ') || 'None'})`);
    console.log(`   Channel: ${net.channel} (${net.frequency} MHz)`);
    console.log(`   Signal: ${net.signalStrength.level} (${net.rssi} dBm)`);
    console.log(`   Vendor: ${net.vendor}`);
    console.log(`   Risk Level: ${riskColor}${net.risk.level}\x1b[0m`);
    
    if (net.risk.risks.length > 0) {
      console.log(`   ⚠️  Risks:`);
      net.risk.risks.forEach(risk => {
        console.log(`      • ${risk}`);
      });
    }
    console.log('');
  });
  
  if (data.networks.length > 20) {
    console.log(`   ... and ${data.networks.length - 20} more networks\n`);
  }
  
  // Rogue AP detection
  if (data.rogueAPs.length > 0) {
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
    console.log("\x1b[36m⚠️  POTENTIAL ROGUE ACCESS POINTS\x1b[0m");
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
    
    data.rogueAPs.forEach((rogue, i) => {
      console.log(`${i + 1}. ${rogue.ssid}`);
      console.log(`   \x1b[31m⚠️  ${rogue.warning}\x1b[0m`);
      console.log(`   Count: ${rogue.count} APs`);
      console.log(`   BSSIDs: ${rogue.bssids.join(', ')}`);
      console.log(`   Vendors: ${rogue.vendors.join(', ')}`);
      console.log('');
    });
  }
  
  // Recommendations
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
  console.log("\x1b[36m💡 RECOMMENDATIONS\x1b[0m");
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
  
  const insecure = data.networks.filter(n => n.risk.level === 'CRITICAL' || n.risk.level === 'HIGH');
  
  if (insecure.length > 0) {
    console.log(`   \x1b[31m🚨 Found ${insecure.length} insecure networks!\x1b[0m`);
    console.log('   • Avoid connecting to WEP or Open networks');
    console.log('   • Use VPN on untrusted networks');
    console.log('   • Verify network authenticity before connecting');
  }
  
  if (data.rogueAPs.length > 0) {
    console.log('   • Possible evil twin attacks detected');
    console.log('   • Verify SSID with network administrator');
  }
  
  console.log('   • Prefer WPA3 networks when available');
  console.log('   • Disable auto-connect to open networks');
  console.log('   • Use strong WiFi passwords (20+ characters)');
  console.log('');
}

function saveResults(data) {
  const dir = './wifi-analyzer-reports';
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, -5);
  const jsonFile = `${dir}/wifi-scan-${timestamp}.json`;
  const txtFile = jsonFile.replace('.json', '.txt');
  
  fs.writeFileSync(jsonFile, JSON.stringify(data, null, 2));
  
  let txtContent = `═══════════════════════════════════════════════════════════
WIFI NETWORK ANALYSIS REPORT
═══════════════════════════════════════════════════════════

Scan Date: ${new Date(data.timestamp).toLocaleString()}
Networks Found: ${data.networks.length}

═══════════════════════════════════════════════════════════
SECURITY OVERVIEW
═══════════════════════════════════════════════════════════

`;

  const securityStats = {};
  data.networks.forEach(net => {
    securityStats[net.security.type] = (securityStats[net.security.type] || 0) + 1;
  });
  
  Object.entries(securityStats).forEach(([type, count]) => {
    txtContent += `${type}: ${count} networks\n`;
  });
  
  txtContent += `\n═══════════════════════════════════════════════════════════
DETECTED NETWORKS
═══════════════════════════════════════════════════════════\n\n`;

  data.networks.forEach((net, i) => {
    txtContent += `${i + 1}. ${net.ssid || '[Hidden SSID]'}\n`;
    txtContent += `   BSSID: ${net.bssid}\n`;
    txtContent += `   Security: ${net.security.type}\n`;
    txtContent += `   Encryption: ${net.security.encryption.join(', ') || 'None'}\n`;
    txtContent += `   Channel: ${net.channel} (${net.frequency} MHz)\n`;
    txtContent += `   Signal: ${net.signalStrength.level} (${net.rssi} dBm)\n`;
    txtContent += `   Vendor: ${net.vendor}\n`;
    txtContent += `   Risk Level: ${net.risk.level}\n`;
    
    if (net.risk.risks.length > 0) {
      txtContent += `   Risks:\n`;
      net.risk.risks.forEach(risk => {
        txtContent += `   • ${risk}\n`;
      });
    }
    txtContent += '\n';
  });
  
  if (data.rogueAPs.length > 0) {
    txtContent += `═══════════════════════════════════════════════════════════
POTENTIAL ROGUE ACCESS POINTS
═══════════════════════════════════════════════════════════\n\n`;

    data.rogueAPs.forEach((rogue, i) => {
      txtContent += `${i + 1}. ${rogue.ssid}\n`;
      txtContent += `   ${rogue.warning}\n`;
      txtContent += `   Count: ${rogue.count} APs\n`;
      txtContent += `   BSSIDs: ${rogue.bssids.join(', ')}\n`;
      txtContent += `   Vendors: ${rogue.vendors.join(', ')}\n\n`;
    });
  }
  
  fs.writeFileSync(txtFile, txtContent);
  
  console.log(`\x1b[32m✅ Results saved:\x1b[0m`);
  console.log(`   JSON: ${jsonFile}`);
  console.log(`   TXT: ${txtFile}\n`);
}

function showHelp() {
  showBanner();
  
  console.log("Usage: node wifi-analyzer.js [OPTIONS]\n");
  console.log("Options:");
  console.log("  --save           Save results to file");
  console.log("  --help           Show this help\n");
  
  console.log("Requirements:");
  console.log("  pkg install termux-api\n");
  
  console.log("Features:");
  console.log("  • Scan nearby WiFi networks");
  console.log("  • Security analysis (WEP/WPA/WPA2/WPA3)");
  console.log("  • Signal strength measurement");
  console.log("  • Vendor identification");
  console.log("  • Rogue AP detection");
  console.log("  • Security risk assessment\n");
  
  console.log("Examples:");
  console.log("  node wifi-analyzer.js");
  console.log("  node wifi-analyzer.js --save\n");
}

async function main() {
  const args = process.argv.slice(2);
  
  if (args.includes('--help')) {
    showHelp();
    process.exit(0);
  }
  
  let saveResults_flag = args.includes('--save');
  
  showBanner();
  
  console.log(`⏳ Scanning WiFi networks...\n`);
  
  const networks = await scanWiFiNetworks();
  
  if (networks.error) {
    displayResults(networks);
    process.exit(1);
  }
  
  const results = {
    timestamp: new Date().toISOString(),
    networks: networks,
    rogueAPs: detectRogueAPs(networks)
  };
  
  displayResults(results);
  
  if (saveResults_flag) {
    saveResults(results);
  }
  
  console.log("\x1b[31m██╗    ██╗██╗███████╗██╗\x1b[0m");
  console.log("\x1b[35m🥝 Scan complete - by kiwi & 777\x1b[0m\n");
}

main().catch(console.error);
