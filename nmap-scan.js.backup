#!/usr/bin/env node

const { exec } = require('child_process');
const { promisify } = require('util');
const execAsync = promisify(exec);
const fs = require('fs');

// ============================================
// CONFIGURATION
// ============================================

const SCAN_TYPES = {
  basic: {
    args: '-sV -sC -T4 --top-ports 100',
    description: 'Service detection + scripts (top 100 ports)',
    time: '~2 min'
  },
  fast: {
    args: '-F -T5',
    description: 'Fast scan (top 100 ports)',
    time: '~30 sec'
  },
  full: {
    args: '-p- -sV -T4',
    description: 'All 65535 ports + services',
    time: '~10-30 min'
  },
  vuln: {
    args: '-sV --script vuln --top-ports 100',
    description: 'Vulnerability scan',
    time: '~5 min'
  },
  ssl: {
    args: '--script ssl-enum-ciphers,ssl-cert -p 443,8443',
    description: 'SSL/TLS analysis',
    time: '~1 min'
  },
  web: {
    args: '--script http-enum,http-headers,http-methods,http-title -p 80,443,8080,8443',
    description: 'Web server enumeration',
    time: '~2 min'
  },
  aggressive: {
    args: '-A -T4 --top-ports 100',
    description: 'OS detection + traceroute + scripts',
    time: '~5 min'
  },
  stealth: {
    args: '-sS -T2 --top-ports 100',
    description: 'Stealth SYN scan (requires root)',
    time: '~3 min'
  }
};

// ============================================
// NMAP FUNCTIONS
// ============================================

async function runNmapScan(target, scanType = 'basic') {
  const scanConfig = SCAN_TYPES[scanType] || SCAN_TYPES.basic;
  const cmd = `nmap ${scanConfig.args} ${target} 2>&1`;
  
  console.log(`\n⏳ Running ${scanType} scan on ${target}...`);
  console.log(`   Estimated time: ${scanConfig.time}\n`);
  
  try {
    const { stdout } = await execAsync(cmd, { 
      timeout: 1800000,
      maxBuffer: 10 * 1024 * 1024
    });
    return parseNmapOutput(stdout, target, scanType);
  } catch (error) {
    if (error.message.includes('nmap: not found') || error.message.includes('command not found')) {
      return { 
        available: false, 
        error: 'Nmap not found',
        note: 'Install with: pkg install nmap'
      };
    }
    return { 
      available: false, 
      error: error.message,
      note: 'Some scans require root access'
    };
  }
}

function parseNmapOutput(output, target, scanType) {
  const result = {
    available: true,
    target: target,
    scanType: scanType,
    timestamp: new Date().toISOString(),
    ports: [],
    services: [],
    os: null,
    vulnerabilities: [],
    scripts: {},
    summary: {
      openPorts: 0,
      filteredPorts: 0,
      closedPorts: 0,
      totalScanned: 0
    },
    rawOutput: output
  };
  
  const portLines = output.split('\n').filter(line => 
    /^\d+\/\w+/.test(line.trim())
  );
  
  portLines.forEach(line => {
    const match = line.match(/(\d+)\/(\w+)\s+(\w+)\s+([\w\-\.]+)\s*(.*)/);
    if (match) {
      const port = {
        port: match[1],
        protocol: match[2],
        state: match[3],
        service: match[4],
        version: match[5]?.trim() || 'unknown'
      };
      
      result.ports.push(port);
      result.summary.totalScanned++;
      
      if (port.state === 'open') {
        result.summary.openPorts++;
        result.services.push(`${port.service} (${port.port}/${port.protocol})`);
      } else if (port.state === 'filtered') {
        result.summary.filteredPorts++;
      } else if (port.state === 'closed') {
        result.summary.closedPorts++;
      }
    }
  });
  
  const osMatch = output.match(/OS details: ([^\n]+)/);
  if (osMatch) result.os = osMatch[1].trim();
  
  const osGuessMatch = output.match(/Aggressive OS guesses: ([^\n]+)/);
  if (!result.os && osGuessMatch) {
    result.os = osGuessMatch[1].split(',')[0].trim();
  }
  
  const vulnRegex = /\|\s+(CVE-\d{4}-\d+)/g;
  let vulnMatch;
  const foundCVEs = new Set();
  
  while ((vulnMatch = vulnRegex.exec(output)) !== null) {
    const cve = vulnMatch[1];
    if (!foundCVEs.has(cve)) {
      foundCVEs.add(cve);
      result.vulnerabilities.push({
        cve: cve,
        url: `https://nvd.nist.gov/vuln/detail/${cve}`
      });
    }
  }
  
  const httpTitleMatch = output.match(/\|_http-title: ([^\n]+)/);
  if (httpTitleMatch) {
    result.scripts.httpTitle = httpTitleMatch[1].trim();
  }
  
  const sslCertMatch = output.match(/Subject: ([^\n]+)/);
  if (sslCertMatch) {
    result.scripts.sslCert = sslCertMatch[1].trim();
  }
  
  const sslCiphersMatch = output.match(/TLSv1\.\d+:\s+([^\n]+)/);
  if (sslCiphersMatch) {
    result.scripts.sslCiphers = sslCiphersMatch[1].trim();
  }
  
  const serviceInfoMatch = output.match(/Service Info: ([^\n]+)/);
  if (serviceInfoMatch) {
    result.scripts.serviceInfo = serviceInfoMatch[1].trim();
  }
  
  const httpMethodsMatch = output.match(/Supported Methods: ([^\n]+)/);
  if (httpMethodsMatch) {
    result.scripts.httpMethods = httpMethodsMatch[1].trim();
  }
  
  return result;
}

// ============================================
// DISPLAY FUNCTIONS
// ============================================

function showBanner() {
  console.log("\x1b[31m");
  console.log("███╗   ██╗███╗   ███╗ █████╗ ██████╗ ");
  console.log("████╗  ██║████╗ ████║██╔══██╗██╔══██╗");
  console.log("██╔██╗ ██║██╔████╔██║███████║██████╔╝");
  console.log("██║╚██╗██║██║╚██╔╝██║██╔══██║██╔═══╝ ");
  console.log("██║ ╚████║██║ ╚═╝ ██║██║  ██║██║     ");
  console.log("╚═╝  ╚═══╝╚═╝     ╚═╝╚═╝  ╚═╝╚═╝     ");
  console.log("\x1b[0m");
  console.log("\x1b[35m🥝 NIKA NMAP Scanner v1.0\x1b[0m");
  console.log("\x1b[33m⚠️  For authorized security testing only\x1b[0m\n");
}

function displayResults(data) {
  console.log("\n╔════════════════════════════════════════════════════════╗");
  console.log("║              🔍 NMAP SCAN RESULTS 🔍                   ║");
  console.log("╚════════════════════════════════════════════════════════╝\n");
  
  if (!data.available) {
    console.log(`\x1b[31m❌ Scan failed\x1b[0m`);
    if (data.error) console.log(`   Error: ${data.error}`);
    if (data.note) console.log(`   Note: ${data.note}`);
    console.log("");
    return;
  }
  
  console.log(`🎯 Target: \x1b[36m${data.target}\x1b[0m`);
  console.log(`📊 Scan Type: \x1b[33m${data.scanType}\x1b[0m`);
  console.log(`⏰ Timestamp: ${new Date(data.timestamp).toLocaleString()}\n`);
  
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
  console.log("\x1b[36m📊 SUMMARY\x1b[0m");
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
  
  console.log(`   Open ports: \x1b[32m${data.summary.openPorts}\x1b[0m`);
  console.log(`   Filtered ports: \x1b[33m${data.summary.filteredPorts}\x1b[0m`);
  console.log(`   Closed ports: \x1b[31m${data.summary.closedPorts}\x1b[0m`);
  console.log(`   Total scanned: ${data.summary.totalScanned}\n`);
  
  if (data.ports.length > 0) {
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
    console.log("\x1b[36m🔓 OPEN PORTS\x1b[0m");
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
    
    data.ports.filter(p => p.state === 'open').forEach(port => {
      console.log(`   \x1b[32m${port.port}/${port.protocol}\x1b[0m - ${port.service}`);
      if (port.version && port.version !== 'unknown') {
        console.log(`      Version: ${port.version}`);
      }
      console.log('');
    });
  }
  
  if (data.os) {
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
    console.log("\x1b[36m💻 OS DETECTION\x1b[0m");
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
    console.log(`   ${data.os}\n`);
  }
  
  if (data.vulnerabilities.length > 0) {
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
    console.log("\x1b[36m🔥 VULNERABILITIES\x1b[0m");
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
    
    data.vulnerabilities.forEach(vuln => {
      console.log(`   \x1b[31m⚠️  ${vuln.cve}\x1b[0m`);
      console.log(`      ${vuln.url}\n`);
    });
  }
  
  if (Object.keys(data.scripts).length > 0) {
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
    console.log("\x1b[36m📋 ADDITIONAL INFO\x1b[0m");
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
    
    if (data.scripts.httpTitle) {
      console.log(`   HTTP Title: ${data.scripts.httpTitle}`);
    }
    if (data.scripts.sslCert) {
      console.log(`   SSL Cert: ${data.scripts.sslCert}`);
    }
    if (data.scripts.httpMethods) {
      console.log(`   HTTP Methods: ${data.scripts.httpMethods}`);
    }
    if (data.scripts.serviceInfo) {
      console.log(`   Service Info: ${data.scripts.serviceInfo}`);
    }
    console.log('');
  }
  
  if (data.services.length > 0) {
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
    console.log("\x1b[36m⚙️  SERVICES\x1b[0m");
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
    
    data.services.forEach(service => {
      console.log(`   • ${service}`);
    });
    console.log('');
  }
}

function saveResults(data, filename) {
  const dir = './nmap-reports';
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, -5);
  const jsonFile = `${dir}/${filename || data.target.replace(/\./g, '_')}-${timestamp}.json`;
  const txtFile = jsonFile.replace('.json', '.txt');
  
  fs.writeFileSync(jsonFile, JSON.stringify(data, null, 2));
  
  let txtContent = `═══════════════════════════════════════════════════════════
NIKA NMAP SCAN REPORT
═══════════════════════════════════════════════════════════

Target: ${data.target}
Scan Type: ${data.scanType}
Date: ${new Date(data.timestamp).toLocaleString()}

═══════════════════════════════════════════════════════════
SUMMARY
═══════════════════════════════════════════════════════════

Open Ports: ${data.summary.openPorts}
Filtered Ports: ${data.summary.filteredPorts}
Closed Ports: ${data.summary.closedPorts}

`;

  if (data.ports.filter(p => p.state === 'open').length > 0) {
    txtContent += `═══════════════════════════════════════════════════════════
OPEN PORTS
═══════════════════════════════════════════════════════════

`;
    data.ports.filter(p => p.state === 'open').forEach(port => {
      txtContent += `${port.port}/${port.protocol} - ${port.service}\n`;
      if (port.version && port.version !== 'unknown') {
        txtContent += `   Version: ${port.version}\n`;
      }
      txtContent += '\n';
    });
  }
  
  if (data.os) {
    txtContent += `═══════════════════════════════════════════════════════════
OS DETECTION
═══════════════════════════════════════════════════════════

${data.os}

`;
  }
  
  if (data.vulnerabilities.length > 0) {
    txtContent += `═══════════════════════════════════════════════════════════
VULNERABILITIES
═══════════════════════════════════════════════════════════

`;
    data.vulnerabilities.forEach(vuln => {
      txtContent += `${vuln.cve}\n${vuln.url}\n\n`;
    });
  }
  
  txtContent += `═══════════════════════════════════════════════════════════
RAW OUTPUT
═══════════════════════════════════════════════════════════

${data.rawOutput}
`;
  
  fs.writeFileSync(txtFile, txtContent);
  
  console.log(`\x1b[32m✅ Results saved:\x1b[0m`);
  console.log(`   JSON: ${jsonFile}`);
  console.log(`   TXT: ${txtFile}\n`);
}

function showHelp() {
  showBanner();
  
  console.log("Usage: node nmap-scan.js [OPTIONS] <target>\n");
  console.log("Options:");
  console.log("  --type <type>    Scan type (default: basic)");
  console.log("  --save           Save results to file");
  console.log("  --list           List available scan types");
  console.log("  --help           Show this help\n");
  
  console.log("Examples:");
  console.log("  node nmap-scan.js example.com");
  console.log("  node nmap-scan.js --type vuln example.com --save");
  console.log("  node nmap-scan.js --type fast 1.2.3.4");
  console.log("  node nmap-scan.js --list\n");
}

function listScanTypes() {
  console.log("\n\x1b[36m╔════════════════════════════════════════════════════════╗\x1b[0m");
  console.log("\x1b[36m║           AVAILABLE SCAN TYPES                        ║\x1b[0m");
  console.log("\x1b[36m╚════════════════════════════════════════════════════════╝\x1b[0m\n");
  
  Object.keys(SCAN_TYPES).forEach(type => {
    const config = SCAN_TYPES[type];
    console.log(`\x1b[32m${type}\x1b[0m`);
    console.log(`   Description: ${config.description}`);
    console.log(`   Time: ${config.time}`);
    console.log(`   Args: ${config.args}\n`);
  });
}

// ============================================
// MAIN
// ============================================

async function main() {
  const args = process.argv.slice(2);
  
  if (args.includes('--help') || args.length === 0) {
    showHelp();
    process.exit(0);
  }
  
  if (args.includes('--list')) {
    listScanTypes();
    process.exit(0);
  }
  
  let scanType = 'basic';
  let target = null;
  let saveResults_flag = false;
  
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--type' && args[i + 1]) {
      scanType = args[i + 1];
      i++;
    } else if (args[i] === '--save') {
      saveResults_flag = true;
    } else if (!args[i].startsWith('--')) {
      target = args[i];
    }
  }
  
  if (!target) {
    console.log("\x1b[31m❌ No target specified!\x1b[0m\n");
    showHelp();
    process.exit(1);
  }
  
  if (!SCAN_TYPES[scanType]) {
    console.log(`\x1b[31m❌ Invalid scan type: ${scanType}\x1b[0m\n`);
    console.log("Use --list to see available types\n");
    process.exit(1);
  }
  
  showBanner();
  
  const results = await runNmapScan(target, scanType);
  
  displayResults(results);
  
  if (saveResults_flag && results.available) {
    saveResults(results);
  }
  
  console.log("\x1b[31m███╗   ██╗███╗   ███╗ █████╗ ██████╗\x1b[0m");
  console.log("\x1b[35m🥝 Scan complete - by kiwi & 777\x1b[0m\n");
}

main().catch(console.error);
