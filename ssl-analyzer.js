#!/usr/bin/env node

const { exec } = require('child_process');
const { promisify } = require('util');
const execAsync = promisify(exec);
const fs = require('fs');

// ============================================
// SSL/TLS ANALYZER - Certificate & Security Analysis
// ============================================

async function analyzeSSL(domain) {
  const results = {
    domain: domain,
    timestamp: new Date().toISOString(),
    certificate: null,
    security: {},
    vulnerabilities: [],
    recommendations: []
  };
  
  try {
    // Get certificate info
    console.log('   Retrieving SSL certificate...');
    results.certificate = await getCertificateInfo(domain);
    
    // Check SSL/TLS versions
    console.log('   Testing SSL/TLS protocols...');
    results.security.protocols = await testProtocols(domain);
    
    // Check cipher suites
    console.log('   Analyzing cipher suites...');
    results.security.ciphers = await testCiphers(domain);
    
    // Vulnerability checks
    console.log('   Checking for vulnerabilities...');
    results.vulnerabilities = await checkVulnerabilities(domain, results);
    
    // Generate recommendations
    results.recommendations = generateRecommendations(results);
    
    // Calculate security grade
    results.grade = calculateGrade(results);
    
    return results;
  } catch (error) {
    return {
      domain: domain,
      error: error.message,
      available: false
    };
  }
}

async function getCertificateInfo(domain) {
  try {
    const cmd = `echo | openssl s_client -connect ${domain}:443 -servername ${domain} 2>/dev/null | openssl x509 -noout -text 2>/dev/null`;
    const { stdout } = await execAsync(cmd, { timeout: 10000 });
    
    // Parse certificate details
    const cert = {
      found: true,
      issuer: extractField(stdout, 'Issuer:'),
      subject: extractField(stdout, 'Subject:'),
      validFrom: extractField(stdout, 'Not Before:'),
      validTo: extractField(stdout, 'Not After :'),
      serialNumber: extractField(stdout, 'Serial Number:'),
      signatureAlgorithm: extractField(stdout, 'Signature Algorithm:'),
      publicKeyAlgorithm: extractField(stdout, 'Public Key Algorithm:'),
      keySize: extractKeySize(stdout),
      sans: extractSANs(stdout)
    };
    
    // Check expiration
    if (cert.validTo) {
      const expiryDate = new Date(cert.validTo);
      const now = new Date();
      const daysUntilExpiry = Math.floor((expiryDate - now) / (1000 * 60 * 60 * 24));
      
      cert.daysUntilExpiry = daysUntilExpiry;
      cert.isExpired = daysUntilExpiry < 0;
      cert.expiringSoon = daysUntilExpiry < 30 && daysUntilExpiry >= 0;
    }
    
    return cert;
  } catch (error) {
    return { found: false, error: error.message };
  }
}

async function testProtocols(domain) {
  const protocols = ['ssl2', 'ssl3', 'tls1', 'tls1_1', 'tls1_2', 'tls1_3'];
  const results = {};
  
  for (const protocol of protocols) {
    try {
      const cmd = `echo | timeout 5 openssl s_client -connect ${domain}:443 -${protocol} 2>&1`;
      const { stdout } = await execAsync(cmd, { timeout: 6000 });
      
      results[protocol] = {
        supported: !stdout.includes('wrong version number') && 
                   !stdout.includes('unsupported protocol') &&
                   !stdout.includes('no protocols available'),
        secure: ['tls1_2', 'tls1_3'].includes(protocol)
      };
    } catch {
      results[protocol] = { supported: false, secure: false };
    }
  }
  
  return results;
}

async function testCiphers(domain) {
  try {
    const cmd = `echo | openssl s_client -connect ${domain}:443 -cipher ALL 2>&1 | grep "Cipher"`;
    const { stdout } = await execAsync(cmd, { timeout: 5000 });
    
    const cipher = stdout.split(':')[1]?.trim();
    
    return {
      negotiated: cipher || 'Unknown',
      strength: assessCipherStrength(cipher)
    };
  } catch {
    return { negotiated: 'Unknown', strength: 'Unknown' };
  }
}

async function checkVulnerabilities(domain, results) {
  const vulns = [];
  
  // Check for expired certificate
  if (results.certificate?.isExpired) {
    vulns.push({
      name: 'Expired Certificate',
      severity: 'CRITICAL',
      description: 'SSL certificate has expired',
      impact: 'Browsers will show security warnings'
    });
  }
  
  // Check for expiring soon
  if (results.certificate?.expiringSoon) {
    vulns.push({
      name: 'Certificate Expiring Soon',
      severity: 'MEDIUM',
      description: `Certificate expires in ${results.certificate.daysUntilExpiry} days`,
      impact: 'Certificate should be renewed soon'
    });
  }
  
  // Check for weak signature algorithm
  if (results.certificate?.signatureAlgorithm?.includes('SHA1')) {
    vulns.push({
      name: 'Weak Signature Algorithm',
      severity: 'HIGH',
      description: 'Certificate uses SHA-1 signature algorithm',
      impact: 'SHA-1 is deprecated and considered insecure'
    });
  }
  
  // Check for small key size
  if (results.certificate?.keySize && results.certificate.keySize < 2048) {
    vulns.push({
      name: 'Weak Key Size',
      severity: 'HIGH',
      description: `RSA key size is ${results.certificate.keySize} bits`,
      impact: 'Key size should be at least 2048 bits'
    });
  }
  
  // Check for SSLv2/SSLv3
  if (results.security?.protocols?.ssl2?.supported) {
    vulns.push({
      name: 'SSLv2 Enabled',
      severity: 'CRITICAL',
      description: 'Server supports SSLv2 protocol',
      impact: 'SSLv2 has known vulnerabilities (DROWN attack)'
    });
  }
  
  if (results.security?.protocols?.ssl3?.supported) {
    vulns.push({
      name: 'SSLv3 Enabled',
      severity: 'HIGH',
      description: 'Server supports SSLv3 protocol',
      impact: 'SSLv3 is vulnerable to POODLE attack'
    });
  }
  
  // Check for TLS 1.0/1.1
  if (results.security?.protocols?.tls1?.supported) {
    vulns.push({
      name: 'TLS 1.0 Enabled',
      severity: 'MEDIUM',
      description: 'Server supports TLS 1.0',
      impact: 'TLS 1.0 is deprecated, should use TLS 1.2+'
    });
  }
  
  if (results.security?.protocols?.tls1_1?.supported) {
    vulns.push({
      name: 'TLS 1.1 Enabled',
      severity: 'MEDIUM',
      description: 'Server supports TLS 1.1',
      impact: 'TLS 1.1 is deprecated, should use TLS 1.2+'
    });
  }
  
  return vulns;
}

function generateRecommendations(results) {
  const recommendations = [];
  
  // Certificate recommendations
  if (results.certificate?.isExpired || results.certificate?.expiringSoon) {
    recommendations.push('Renew SSL certificate immediately');
  }
  
  if (results.certificate?.keySize && results.certificate.keySize < 2048) {
    recommendations.push('Use at least 2048-bit RSA keys');
  }
  
  if (results.certificate?.signatureAlgorithm?.includes('SHA1')) {
    recommendations.push('Upgrade to SHA-256 signature algorithm');
  }
  
  // Protocol recommendations
  if (results.security?.protocols?.ssl2?.supported || 
      results.security?.protocols?.ssl3?.supported) {
    recommendations.push('Disable SSLv2 and SSLv3 protocols immediately');
  }
  
  if (results.security?.protocols?.tls1?.supported || 
      results.security?.protocols?.tls1_1?.supported) {
    recommendations.push('Disable TLS 1.0 and TLS 1.1, use only TLS 1.2+');
  }
  
  if (!results.security?.protocols?.tls1_3?.supported) {
    recommendations.push('Enable TLS 1.3 for better security and performance');
  }
  
  // General recommendations
  recommendations.push('Regularly update SSL/TLS configuration');
  recommendations.push('Monitor certificate expiration dates');
  recommendations.push('Use strong cipher suites only');
  recommendations.push('Enable HTTP Strict Transport Security (HSTS)');
  
  return recommendations;
}

function calculateGrade(results) {
  let score = 100;
  
  // Certificate issues
  if (results.certificate?.isExpired) score -= 50;
  else if (results.certificate?.expiringSoon) score -= 10;
  
  if (results.certificate?.keySize && results.certificate.keySize < 2048) score -= 20;
  if (results.certificate?.signatureAlgorithm?.includes('SHA1')) score -= 15;
  
  // Protocol issues
  if (results.security?.protocols?.ssl2?.supported) score -= 30;
  if (results.security?.protocols?.ssl3?.supported) score -= 20;
  if (results.security?.protocols?.tls1?.supported) score -= 10;
  if (results.security?.protocols?.tls1_1?.supported) score -= 10;
  
  // Bonus for TLS 1.3
  if (results.security?.protocols?.tls1_3?.supported) score += 5;
  
  score = Math.max(0, Math.min(100, score));
  
  let grade;
  if (score >= 90) grade = 'A+';
  else if (score >= 80) grade = 'A';
  else if (score >= 70) grade = 'B';
  else if (score >= 60) grade = 'C';
  else if (score >= 50) grade = 'D';
  else grade = 'F';
  
  return { score, grade };
}

function extractField(text, field) {
  const regex = new RegExp(`${field}\\s*(.+?)(?=\\n|$)`, 'i');
  const match = text.match(regex);
  return match ? match[1].trim() : null;
}

function extractKeySize(text) {
  const match = text.match(/Public-Key: \((\d+) bit\)/);
  return match ? parseInt(match[1]) : null;
}

function extractSANs(text) {
  const match = text.match(/DNS:([^\n]+)/);
  if (match) {
    return match[1].split(',').map(s => s.trim().replace('DNS:', ''));
  }
  return [];
}

function assessCipherStrength(cipher) {
  if (!cipher) return 'Unknown';
  
  if (cipher.includes('AES256-GCM') || cipher.includes('CHACHA20')) {
    return 'Strong';
  } else if (cipher.includes('AES128') || cipher.includes('AES256')) {
    return 'Good';
  } else if (cipher.includes('3DES') || cipher.includes('RC4')) {
    return 'Weak';
  }
  
  return 'Moderate';
}

function showBanner() {
  console.log("\x1b[31m");
  console.log("███████╗███████╗██╗         █████╗ ███╗   ██╗ █████╗ ██╗  ██╗   ██╗███████╗███████╗██████╗ ");
  console.log("██╔════╝██╔════╝██║        ██╔══██╗████╗  ██║██╔══██╗██║  ╚██╗ ██╔╝╚══███╔╝██╔════╝██╔══██╗");
  console.log("███████╗███████╗██║        ███████║██╔██╗ ██║███████║██║   ╚████╔╝   ███╔╝ █████╗  ██████╔╝");
  console.log("╚════██║╚════██║██║        ██╔══██║██║╚██╗██║██╔══██║██║    ╚██╔╝   ███╔╝  ██╔══╝  ██╔══██╗");
  console.log("███████║███████║███████╗   ██║  ██║██║ ╚████║██║  ██║███████╗██║   ███████╗███████╗██║  ██║");
  console.log("╚══════╝╚══════╝╚══════╝   ╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝╚═╝   ╚══════╝╚══════╝╚═╝  ╚═╝");
  console.log("\x1b[0m");
  console.log("\x1b[35m🥝 NIKA SSL/TLS Analyzer - Certificate & Security Analysis\x1b[0m");
  console.log("\x1b[33m⚠️  For authorized security assessment only\x1b[0m\n");
}

function displayResults(data) {
  console.log("\n╔════════════════════════════════════════════════════════╗");
  console.log("║       🔒 SSL/TLS ANALYSIS RESULTS 🔒                   ║");
  console.log("╚════════════════════════════════════════════════════════╝\n");
  
  if (data.error) {
    console.log(`\x1b[31m❌ Analysis failed: ${data.error}\x1b[0m\n`);
    return;
  }
  
  console.log(`🌐 Domain: \x1b[36m${data.domain}\x1b[0m\n`);
  
  // Security Grade
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
  console.log("\x1b[36m🏆 SECURITY GRADE\x1b[0m");
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
  
  const gradeColor = data.grade.grade === 'A+' || data.grade.grade === 'A' ? '\x1b[32m' :
                     data.grade.grade === 'B' || data.grade.grade === 'C' ? '\x1b[33m' : '\x1b[31m';
  
  console.log(`   Grade: ${gradeColor}${data.grade.grade}\x1b[0m`);
  console.log(`   Score: ${data.grade.score}/100\n`);
  
  // Certificate Info
  if (data.certificate?.found) {
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
    console.log("\x1b[36m📜 CERTIFICATE INFORMATION\x1b[0m");
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
    
    console.log(`   Subject: ${data.certificate.subject || 'N/A'}`);
    console.log(`   Issuer: ${data.certificate.issuer || 'N/A'}`);
    console.log(`   Valid From: ${data.certificate.validFrom || 'N/A'}`);
    console.log(`   Valid To: ${data.certificate.validTo || 'N/A'}`);
    
    if (data.certificate.daysUntilExpiry !== undefined) {
      const expiryColor = data.certificate.isExpired ? '\x1b[31m' :
                         data.certificate.expiringSoon ? '\x1b[33m' : '\x1b[32m';
      console.log(`   Days Until Expiry: ${expiryColor}${data.certificate.daysUntilExpiry}\x1b[0m`);
    }
    
    console.log(`   Signature Algorithm: ${data.certificate.signatureAlgorithm || 'N/A'}`);
    console.log(`   Key Size: ${data.certificate.keySize ? data.certificate.keySize + ' bits' : 'N/A'}`);
    
    if (data.certificate.sans && data.certificate.sans.length > 0) {
      console.log(`   SANs: ${data.certificate.sans.slice(0, 3).join(', ')}${data.certificate.sans.length > 3 ? '...' : ''}`);
    }
    console.log('');
  }
  
  // Protocol Support
  if (data.security?.protocols) {
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
    console.log("\x1b[36m🔐 PROTOCOL SUPPORT\x1b[0m");
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
    
    Object.entries(data.security.protocols).forEach(([protocol, info]) => {
      const statusColor = info.supported ? (info.secure ? '\x1b[32m' : '\x1b[31m') : '\x1b[90m';
      const status = info.supported ? (info.secure ? '✓ Supported (Secure)' : '✓ Supported (Insecure)') : '✗ Not Supported';
      console.log(`   ${protocol.toUpperCase().replace('_', '.')}: ${statusColor}${status}\x1b[0m`);
    });
    console.log('');
  }
  
  // Cipher Info
  if (data.security?.ciphers) {
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
    console.log("\x1b[36m🔑 CIPHER SUITE\x1b[0m");
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
    
    console.log(`   Negotiated: ${data.security.ciphers.negotiated}`);
    console.log(`   Strength: ${data.security.ciphers.strength}\n`);
  }
  
  // Vulnerabilities
  if (data.vulnerabilities && data.vulnerabilities.length > 0) {
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
    console.log("\x1b[36m⚠️  VULNERABILITIES DETECTED\x1b[0m");
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
    
    data.vulnerabilities.forEach(vuln => {
      const severityColor = vuln.severity === 'CRITICAL' ? '\x1b[41m\x1b[37m' :
                           vuln.severity === 'HIGH' ? '\x1b[31m' :
                           vuln.severity === 'MEDIUM' ? '\x1b[33m' : '\x1b[32m';
      
      console.log(`   ${severityColor}[${vuln.severity}]\x1b[0m ${vuln.name}`);
      console.log(`   ${vuln.description}`);
      console.log(`   Impact: ${vuln.impact}\n`);
    });
  }
  
  // Recommendations
  if (data.recommendations && data.recommendations.length > 0) {
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
    console.log("\x1b[36m💡 RECOMMENDATIONS\x1b[0m");
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
    
    data.recommendations.forEach((rec, i) => {
      console.log(`   ${i + 1}. ${rec}`);
    });
    console.log('');
  }
}

function saveResults(data) {
  const dir = './ssl-analyzer-reports';
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, -5);
  const domainSafe = data.domain.replace(/[^a-z0-9]/gi, '_');
  const jsonFile = `${dir}/${domainSafe}-${timestamp}.json`;
  const txtFile = jsonFile.replace('.json', '.txt');
  
  fs.writeFileSync(jsonFile, JSON.stringify(data, null, 2));
  
  let txtContent = `═══════════════════════════════════════════════════════════
SSL/TLS ANALYSIS REPORT
═══════════════════════════════════════════════════════════

Domain: ${data.domain}
Date: ${new Date(data.timestamp).toLocaleString()}

═══════════════════════════════════════════════════════════
SECURITY GRADE
═══════════════════════════════════════════════════════════

Grade: ${data.grade.grade}
Score: ${data.grade.score}/100

═══════════════════════════════════════════════════════════
CERTIFICATE INFORMATION
═══════════════════════════════════════════════════════════

Subject: ${data.certificate?.subject || 'N/A'}
Issuer: ${data.certificate?.issuer || 'N/A'}
Valid From: ${data.certificate?.validFrom || 'N/A'}
Valid To: ${data.certificate?.validTo || 'N/A'}
Days Until Expiry: ${data.certificate?.daysUntilExpiry !== undefined ? data.certificate.daysUntilExpiry : 'N/A'}
Signature Algorithm: ${data.certificate?.signatureAlgorithm || 'N/A'}
Key Size: ${data.certificate?.keySize ? data.certificate.keySize + ' bits' : 'N/A'}

═══════════════════════════════════════════════════════════
PROTOCOL SUPPORT
═══════════════════════════════════════════════════════════

`;

  if (data.security?.protocols) {
    Object.entries(data.security.protocols).forEach(([protocol, info]) => {
      const status = info.supported ? (info.secure ? 'Supported (Secure)' : 'Supported (Insecure)') : 'Not Supported';
      txtContent += `${protocol.toUpperCase().replace('_', '.')}: ${status}\n`;
    });
  }
  
  txtContent += `\n═══════════════════════════════════════════════════════════
VULNERABILITIES
═══════════════════════════════════════════════════════════\n\n`;

  if (data.vulnerabilities && data.vulnerabilities.length > 0) {
    data.vulnerabilities.forEach(vuln => {
      txtContent += `[${vuln.severity}] ${vuln.name}\n`;
      txtContent += `${vuln.description}\n`;
      txtContent += `Impact: ${vuln.impact}\n\n`;
    });
  } else {
    txtContent += 'No vulnerabilities detected.\n\n';
  }
  
  txtContent += `═══════════════════════════════════════════════════════════
RECOMMENDATIONS
═══════════════════════════════════════════════════════════\n\n`;

  if (data.recommendations) {
    data.recommendations.forEach((rec, i) => {
      txtContent += `${i + 1}. ${rec}\n`;
    });
  }
  
  fs.writeFileSync(txtFile, txtContent);
  
  console.log(`\x1b[32m✅ Results saved:\x1b[0m`);
  console.log(`   JSON: ${jsonFile}`);
  console.log(`   TXT: ${txtFile}\n`);
}

function showHelp() {
  showBanner();
  
  console.log("Usage: node ssl-analyzer.js [OPTIONS] <domain>\n");
  console.log("Options:");
  console.log("  --save           Save results to file");
  console.log("  --help           Show this help\n");
  
  console.log("Examples:");
  console.log("  node ssl-analyzer.js example.com");
  console.log("  node ssl-analyzer.js google.com --save\n");
  
  console.log("\x1b[33mNote: Requires openssl installed\x1b[0m\n");
}

async function main() {
  const args = process.argv.slice(2);
  
  if (args.includes('--help') || args.length === 0) {
    showHelp();
    process.exit(0);
  }
  
  let domain = null;
  let saveResults_flag = false;
  
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--save') {
      saveResults_flag = true;
    } else if (!args[i].startsWith('--')) {
      domain = args[i];
    }
  }
  
  if (!domain) {
    console.log("\x1b[31m❌ No domain specified!\x1b[0m\n");
    showHelp();
    process.exit(1);
  }
  
  showBanner();
  
  console.log(`⏳ Analyzing SSL/TLS for: ${domain}...\n`);
  
  const results = await analyzeSSL(domain);
  
  displayResults(results);
  
  if (saveResults_flag && !results.error) {
    saveResults(results);
  }
  
  console.log("\x1b[31m███████╗███████╗██╗\x1b[0m");
  console.log("\x1b[35m🥝 Analysis complete - by kiwi & 777\x1b[0m\n");
}

main().catch(console.error);
