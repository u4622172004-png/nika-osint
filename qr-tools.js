#!/usr/bin/env node

const { exec } = require('child_process');
const { promisify } = require('util');
const execAsync = promisify(exec);
const fs = require('fs');

// ============================================
// QR CODE TOOLS - Decode, Analyze & Security Check
// ============================================

async function decodeQRCode(imagePath) {
  try {
    console.log('   Decoding QR code...');
    
    // Try zbarimg first (more reliable)
    try {
      const { stdout: zbarOut } = await execAsync(`zbarimg --raw "${imagePath}"`, { timeout: 5000 });
      if (zbarOut.trim()) {
        return {
          decoder: 'zbarimg',
          success: true,
          data: zbarOut.trim()
        };
      }
    } catch (zbarError) {
      // zbarimg not available or failed, try qrencode --decode (doesn't exist, fallback to manual)
    }
    
    // If zbar fails, return error
    return {
      decoder: 'none',
      success: false,
      error: 'QR code decoder not available. Install: pkg install zbar'
    };
  } catch (error) {
    return {
      decoder: 'error',
      success: false,
      error: error.message
    };
  }
}

function parseQRData(data) {
  const result = {
    raw: data,
    type: 'unknown',
    parsed: {},
    safe: true,
    warnings: []
  };
  
  // URL Detection
  if (/^https?:\/\//i.test(data)) {
    result.type = 'url';
    result.parsed = parseURL(data);
    result.safe = assessURLSafety(data, result.warnings);
  }
  // WiFi Config
  else if (data.startsWith('WIFI:')) {
    result.type = 'wifi';
    result.parsed = parseWiFi(data);
  }
  // Email
  else if (data.startsWith('mailto:')) {
    result.type = 'email';
    result.parsed = parseEmail(data);
  }
  // Phone
  else if (data.startsWith('tel:')) {
    result.type = 'phone';
    result.parsed = parsePhone(data);
  }
  // SMS
  else if (data.startsWith('smsto:')) {
    result.type = 'sms';
    result.parsed = parseSMS(data);
  }
  // vCard (Contact)
  else if (data.startsWith('BEGIN:VCARD')) {
    result.type = 'vcard';
    result.parsed = parseVCard(data);
  }
  // Geographic Location
  else if (data.startsWith('geo:')) {
    result.type = 'geo';
    result.parsed = parseGeo(data);
  }
  // Cryptocurrency Address
  else if (/^(bitcoin:|ethereum:|0x[a-fA-F0-9]{40}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})/i.test(data)) {
    result.type = 'crypto';
    result.parsed = parseCrypto(data);
  }
  // Plain Text
  else {
    result.type = 'text';
    result.parsed = { text: data };
  }
  
  return result;
}

function parseURL(url) {
  try {
    const urlObj = new URL(url);
    
    return {
      full: url,
      protocol: urlObj.protocol,
      hostname: urlObj.hostname,
      port: urlObj.port,
      path: urlObj.pathname,
      query: urlObj.search,
      hash: urlObj.hash
    };
  } catch (e) {
    return { full: url, error: 'Invalid URL' };
  }
}

function assessURLSafety(url, warnings) {
  let safe = true;
  
  // Check for suspicious TLDs
  const suspiciousTLDs = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.click', '.download'];
  if (suspiciousTLDs.some(tld => url.toLowerCase().includes(tld))) {
    warnings.push('Suspicious TLD - often used in phishing');
    safe = false;
  }
  
  // Check for IP address instead of domain
  if (/https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(url)) {
    warnings.push('Uses IP address instead of domain name');
    safe = false;
  }
  
  // Check for typosquatting indicators
  const commonBrands = ['paypal', 'amazon', 'google', 'microsoft', 'apple', 'facebook', 'instagram'];
  const urlLower = url.toLowerCase();
  commonBrands.forEach(brand => {
    if (urlLower.includes(brand) && !urlLower.includes(brand + '.com')) {
      warnings.push(`Possible ${brand} typosquatting`);
      safe = false;
    }
  });
  
  // Check for multiple redirects
  if (url.includes('redirect') || url.includes('r.php') || url.includes('/r/')) {
    warnings.push('Contains redirect - final destination unknown');
  }
  
  // Check for URL shorteners
  const shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd'];
  if (shorteners.some(s => urlLower.includes(s))) {
    warnings.push('URL shortener - final destination hidden');
  }
  
  // Check for @ symbol (credential phishing)
  if (url.includes('@')) {
    warnings.push('Contains @ symbol - possible credential harvesting');
    safe = false;
  }
  
  // Check for excessive subdomains
  const hostname = url.split('/')[2];
  if (hostname && hostname.split('.').length > 4) {
    warnings.push('Excessive subdomains - suspicious structure');
  }
  
  return safe;
}

function parseWiFi(data) {
  // Format: WIFI:T:WPA;S:NetworkName;P:Password;H:false;;
  const result = {};
  
  const parts = data.substring(5).split(';');
  parts.forEach(part => {
    const [key, value] = part.split(':');
    if (key && value) {
      switch(key) {
        case 'T': result.security = value; break;
        case 'S': result.ssid = value; break;
        case 'P': result.password = value; break;
        case 'H': result.hidden = value === 'true'; break;
      }
    }
  });
  
  return result;
}

function parseEmail(data) {
  // Format: mailto:email@example.com?subject=Hello
  const email = data.substring(7).split('?')[0];
  const params = {};
  
  if (data.includes('?')) {
    const query = data.split('?')[1];
    query.split('&').forEach(param => {
      const [key, value] = param.split('=');
      params[key] = decodeURIComponent(value || '');
    });
  }
  
  return {
    email: email,
    subject: params.subject,
    body: params.body,
    cc: params.cc,
    bcc: params.bcc
  };
}

function parsePhone(data) {
  // Format: tel:+1234567890
  return {
    number: data.substring(4)
  };
}

function parseSMS(data) {
  // Format: smsto:+1234567890:Message text
  const parts = data.substring(6).split(':');
  return {
    number: parts[0],
    message: parts[1] || ''
  };
}

function parseVCard(data) {
  const lines = data.split('\n');
  const vcard = {};
  
  lines.forEach(line => {
    if (line.startsWith('FN:')) vcard.name = line.substring(3);
    if (line.startsWith('TEL:')) vcard.phone = line.substring(4);
    if (line.startsWith('EMAIL:')) vcard.email = line.substring(6);
    if (line.startsWith('ORG:')) vcard.organization = line.substring(4);
    if (line.startsWith('TITLE:')) vcard.title = line.substring(6);
    if (line.startsWith('URL:')) vcard.url = line.substring(4);
  });
  
  return vcard;
}

function parseGeo(data) {
  // Format: geo:latitude,longitude or geo:latitude,longitude?q=query
  const coords = data.substring(4).split('?')[0];
  const [lat, lon] = coords.split(',');
  
  return {
    latitude: parseFloat(lat),
    longitude: parseFloat(lon),
    googleMaps: `https://www.google.com/maps?q=${lat},${lon}`,
    openStreetMap: `https://www.openstreetmap.org/?mlat=${lat}&mlon=${lon}`
  };
}

function parseCrypto(data) {
  let address = data;
  let currency = 'Unknown';
  
  if (data.startsWith('bitcoin:')) {
    currency = 'Bitcoin';
    address = data.substring(8).split('?')[0];
  } else if (data.startsWith('ethereum:')) {
    currency = 'Ethereum';
    address = data.substring(9).split('?')[0];
  } else if (/^0x[a-fA-F0-9]{40}$/.test(data)) {
    currency = 'Ethereum';
    address = data;
  } else if (/^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$/.test(data)) {
    currency = 'Bitcoin';
    address = data;
  }
  
  return {
    currency: currency,
    address: address
  };
}

async function checkMaliciousURL(url) {
  const checks = {
    virustotal: `https://www.virustotal.com/gui/url/${Buffer.from(url).toString('base64').replace(/=/g, '')}`,
    urlscan: `https://urlscan.io/search/#${encodeURIComponent(url)}`,
    google: `https://transparencyreport.google.com/safe-browsing/search?url=${encodeURIComponent(url)}`
  };
  
  return checks;
}

function showBanner() {
  console.log("\x1b[31m");
  console.log(" ██████╗ ██████╗      ██████╗ ██████╗ ██████╗ ███████╗    ████████╗ ██████╗  ██████╗ ██╗     ███████╗");
  console.log("██╔═══██╗██╔══██╗    ██╔════╝██╔═══██╗██╔══██╗██╔════╝    ╚══██╔══╝██╔═══██╗██╔═══██╗██║     ██╔════╝");
  console.log("██║   ██║██████╔╝    ██║     ██║   ██║██║  ██║█████╗         ██║   ██║   ██║██║   ██║██║     ███████╗");
  console.log("██║▄▄ ██║██╔══██╗    ██║     ██║   ██║██║  ██║██╔══╝         ██║   ██║   ██║██║   ██║██║     ╚════██║");
  console.log("╚██████╔╝██║  ██║    ╚██████╗╚██████╔╝██████╔╝███████╗       ██║   ╚██████╔╝╚██████╔╝███████╗███████║");
  console.log(" ╚══▀▀═╝ ╚═╝  ╚═╝     ╚═════╝ ╚═════╝ ╚═════╝ ╚══════╝       ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝╚══════╝");
  console.log("\x1b[0m");
  console.log("\x1b[35m🥝 NIKA QR Code Tools - Decode, Analyze & Security Check\x1b[0m");
  console.log("\x1b[33m⚠️  For security analysis and malware prevention\x1b[0m\n");
}

function displayResults(data) {
  console.log("\n╔════════════════════════════════════════════════════════╗");
  console.log("║       📱 QR CODE ANALYSIS RESULTS 📱                   ║");
  console.log("╚════════════════════════════════════════════════════════╝\n");
  
  if (!data.decoded.success) {
    console.log(`\x1b[31m❌ Failed to decode QR code\x1b[0m`);
    console.log(`   Error: ${data.decoded.error}\n`);
    return;
  }
  
  console.log(`📸 Image: \x1b[36m${data.imagePath}\x1b[0m`);
  console.log(`🔧 Decoder: ${data.decoded.decoder}\n`);
  
  // Content Type
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
  console.log("\x1b[36m📋 CONTENT TYPE\x1b[0m");
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
  
  console.log(`   Type: ${data.analysis.type.toUpperCase()}`);
  console.log(`   Safety: ${data.analysis.safe ? '\x1b[32mSAFE\x1b[0m' : '\x1b[31mSUSPICIOUS\x1b[0m'}\n`);
  
  // Parsed Data
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
  console.log("\x1b[36m📄 DECODED CONTENT\x1b[0m");
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
  
  if (data.analysis.type === 'url') {
    console.log(`   URL: ${data.analysis.parsed.full}`);
    console.log(`   Protocol: ${data.analysis.parsed.protocol}`);
    console.log(`   Hostname: ${data.analysis.parsed.hostname}`);
    if (data.analysis.parsed.path) console.log(`   Path: ${data.analysis.parsed.path}`);
    if (data.analysis.parsed.query) console.log(`   Query: ${data.analysis.parsed.query}`);
  } else if (data.analysis.type === 'wifi') {
    console.log(`   SSID: ${data.analysis.parsed.ssid}`);
    console.log(`   Security: ${data.analysis.parsed.security}`);
    console.log(`   Password: ${data.analysis.parsed.password || 'None (Open network)'}`);
    console.log(`   Hidden: ${data.analysis.parsed.hidden ? 'Yes' : 'No'}`);
  } else if (data.analysis.type === 'email') {
    console.log(`   Email: ${data.analysis.parsed.email}`);
    if (data.analysis.parsed.subject) console.log(`   Subject: ${data.analysis.parsed.subject}`);
    if (data.analysis.parsed.body) console.log(`   Body: ${data.analysis.parsed.body}`);
  } else if (data.analysis.type === 'phone') {
    console.log(`   Phone: ${data.analysis.parsed.number}`);
  } else if (data.analysis.type === 'sms') {
    console.log(`   Number: ${data.analysis.parsed.number}`);
    console.log(`   Message: ${data.analysis.parsed.message}`);
  } else if (data.analysis.type === 'vcard') {
    Object.entries(data.analysis.parsed).forEach(([key, value]) => {
      console.log(`   ${key}: ${value}`);
    });
  } else if (data.analysis.type === 'geo') {
    console.log(`   Latitude: ${data.analysis.parsed.latitude}`);
    console.log(`   Longitude: ${data.analysis.parsed.longitude}`);
    console.log(`   Google Maps: ${data.analysis.parsed.googleMaps}`);
  } else if (data.analysis.type === 'crypto') {
    console.log(`   Currency: ${data.analysis.parsed.currency}`);
    console.log(`   Address: ${data.analysis.parsed.address}`);
  } else {
    console.log(`   Text: ${data.analysis.parsed.text}`);
  }
  console.log('');
  
  // Security Warnings
  if (data.analysis.warnings && data.analysis.warnings.length > 0) {
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
    console.log("\x1b[36m⚠️  SECURITY WARNINGS\x1b[0m");
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
    
    data.analysis.warnings.forEach(warning => {
      console.log(`   \x1b[31m⚠️  ${warning}\x1b[0m`);
    });
    console.log('');
  }
  
  // Malicious URL Checks
  if (data.analysis.type === 'url' && data.maliciousChecks) {
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
    console.log("\x1b[36m🔍 MALICIOUS URL CHECKS\x1b[0m");
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
    
    console.log(`   VirusTotal: ${data.maliciousChecks.virustotal}`);
    console.log(`   URLScan.io: ${data.maliciousChecks.urlscan}`);
    console.log(`   Google Safe Browsing: ${data.maliciousChecks.google}`);
    console.log('');
  }
  
  // Raw Data
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
  console.log("\x1b[36m📝 RAW DATA\x1b[0m");
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
  
  console.log(`   ${data.analysis.raw}\n`);
  
  // Recommendations
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
  console.log("\x1b[36m💡 RECOMMENDATIONS\x1b[0m");
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
  
  if (!data.analysis.safe) {
    console.log('   \x1b[31m🚨 SUSPICIOUS QR CODE DETECTED\x1b[0m');
    console.log('   • DO NOT visit the URL without verification');
    console.log('   • Check URL reputation on VirusTotal');
    console.log('   • Look for typosquatting or phishing indicators');
    console.log('   • Be cautious of QR codes in public places');
  } else if (data.analysis.type === 'wifi') {
    console.log('   • Verify WiFi network with owner before connecting');
    console.log('   • Check if password matches expected credentials');
    console.log('   • Be cautious of public WiFi QR codes');
  } else if (data.analysis.type === 'url') {
    console.log('   • Verify URL destination before visiting');
    console.log('   • Check for HTTPS');
    console.log('   • Use URL reputation services');
  } else {
    console.log('   ✓ QR code appears safe');
    console.log('   • Always verify QR codes from trusted sources');
    console.log('   • Be cautious of codes in public spaces');
  }
  console.log('');
}

function saveResults(data) {
  const dir = './qr-tools-reports';
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, -5);
  const imageName = data.imagePath.split('/').pop().replace(/\.[^.]+$/, '');
  const jsonFile = `${dir}/${imageName}-${timestamp}.json`;
  const txtFile = jsonFile.replace('.json', '.txt');
  
  fs.writeFileSync(jsonFile, JSON.stringify(data, null, 2));
  
  let txtContent = `═══════════════════════════════════════════════════════════
QR CODE ANALYSIS REPORT
═══════════════════════════════════════════════════════════

Image: ${data.imagePath}
Decoder: ${data.decoded.decoder}
Date: ${new Date(data.timestamp).toLocaleString()}

═══════════════════════════════════════════════════════════
CONTENT TYPE
═══════════════════════════════════════════════════════════

Type: ${data.analysis.type.toUpperCase()}
Safety: ${data.analysis.safe ? 'SAFE' : 'SUSPICIOUS'}

═══════════════════════════════════════════════════════════
DECODED CONTENT
═══════════════════════════════════════════════════════════

${JSON.stringify(data.analysis.parsed, null, 2)}

═══════════════════════════════════════════════════════════
SECURITY WARNINGS
═══════════════════════════════════════════════════════════

${data.analysis.warnings.length > 0 ? data.analysis.warnings.map(w => `⚠️  ${w}`).join('\n') : 'No warnings'}

═══════════════════════════════════════════════════════════
RAW DATA
═══════════════════════════════════════════════════════════

${data.analysis.raw}
`;

  if (data.maliciousChecks) {
    txtContent += `\n═══════════════════════════════════════════════════════════
MALICIOUS URL CHECKS
═══════════════════════════════════════════════════════════

VirusTotal: ${data.maliciousChecks.virustotal}
URLScan.io: ${data.maliciousChecks.urlscan}
Google Safe Browsing: ${data.maliciousChecks.google}
`;
  }
  
  fs.writeFileSync(txtFile, txtContent);
  
  console.log(`\x1b[32m✅ Results saved:\x1b[0m`);
  console.log(`   JSON: ${jsonFile}`);
  console.log(`   TXT: ${txtFile}\n`);
}

function showHelp() {
  showBanner();
  
  console.log("Usage: node qr-tools.js [OPTIONS] <image-path>\n");
  console.log("Options:");
  console.log("  --save           Save results to file");
  console.log("  --help           Show this help\n");
  
  console.log("Requirements:");
  console.log("  pkg install zbar\n");
  
  console.log("Supported QR Code Types:");
  console.log("  • URLs");
  console.log("  • WiFi Credentials");
  console.log("  • Email Addresses");
  console.log("  • Phone Numbers");
  console.log("  • SMS Messages");
  console.log("  • vCards (Contacts)");
  console.log("  • Geographic Locations");
  console.log("  • Cryptocurrency Addresses");
  console.log("  • Plain Text\n");
  
  console.log("Examples:");
  console.log("  node qr-tools.js qrcode.png");
  console.log("  node qr-tools.js /sdcard/DCIM/qr.jpg --save\n");
}

async function main() {
  const args = process.argv.slice(2);
  
  if (args.includes('--help') || args.length === 0) {
    showHelp();
    process.exit(0);
  }
  
  let imagePath = null;
  let saveResults_flag = false;
  
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--save') {
      saveResults_flag = true;
    } else if (!args[i].startsWith('--')) {
      imagePath = args[i];
    }
  }
  
  if (!imagePath) {
    console.log("\x1b[31m❌ No image specified!\x1b[0m\n");
    showHelp();
    process.exit(1);
  }
  
  if (!fs.existsSync(imagePath)) {
    console.log(`\x1b[31m❌ Image not found: ${imagePath}\x1b[0m\n`);
    process.exit(1);
  }
  
  showBanner();
  
  console.log(`⏳ Decoding QR code from: ${imagePath}...\n`);
  
  const decoded = await decodeQRCode(imagePath);
  
  if (!decoded.success) {
    console.log(`\x1b[31m❌ ${decoded.error}\x1b[0m\n`);
    process.exit(1);
  }
  
  const analysis = parseQRData(decoded.data);
  
  const results = {
    imagePath: imagePath,
    timestamp: new Date().toISOString(),
    decoded: decoded,
    analysis: analysis,
    maliciousChecks: null
  };
  
  // Check for malicious URLs
  if (analysis.type === 'url') {
    results.maliciousChecks = await checkMaliciousURL(decoded.data);
  }
  
  displayResults(results);
  
  if (saveResults_flag) {
    saveResults(results);
  }
  
  console.log("\x1b[31m ██████╗ ██████╗      ██████╗ ██████╗ ██████╗ ███████╗\x1b[0m");
  console.log("\x1b[35m🥝 Scan complete - by kiwi & 777\x1b[0m\n");
}

main().catch(console.error);
