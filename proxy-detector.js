#!/usr/bin/env node

const { exec } = require('child_process');
const { promisify } = require('util');
const execAsync = promisify(exec);
const fs = require('fs');

// ============================================
// PROXY/VPN DETECTOR - Anonymous Connection Detection
// ============================================

async function checkProxyCheck(ip) {
  try {
    console.log('   Checking ProxyCheck.io...');
    
    const apiKey = process.env.PROXYCHECK_API_KEY || '';
    const url = apiKey 
      ? `https://proxycheck.io/v2/${ip}?key=${apiKey}&vpn=1&asn=1`
      : `https://proxycheck.io/v2/${ip}?vpn=1&asn=1`;
    
    const { stdout } = await execAsync(`curl -s "${url}"`, { timeout: 10000 });
    const data = JSON.parse(stdout);
    
    if (data[ip]) {
      const result = data[ip];
      
      return {
        source: 'ProxyCheck.io',
        available: true,
        proxy: result.proxy === 'yes',
        type: result.type || 'Unknown',
        vpn: result.vpn === 'yes',
        country: result.country,
        isocode: result.isocode,
        provider: result.provider,
        asn: result.asn,
        organization: result.organisation || result.organization,
        riskScore: result.risk || 0
      };
    }
    
    return {
      source: 'ProxyCheck.io',
      available: true,
      proxy: false,
      vpn: false
    };
  } catch (error) {
    return {
      source: 'ProxyCheck.io',
      available: false,
      error: error.message
    };
  }
}

async function checkIPQuality(ip) {
  try {
    const apiKey = process.env.IPQUALITYSCORE_API_KEY;
    
    if (!apiKey) {
      return {
        source: 'IPQualityScore',
        available: false,
        error: 'API key required (set IPQUALITYSCORE_API_KEY env variable)',
        manualCheck: `https://www.ipqualityscore.com/free-ip-lookup-proxy-vpn-test/lookup/${ip}`
      };
    }
    
    console.log('   Checking IPQualityScore...');
    
    const url = `https://ipqualityscore.com/api/json/ip/${apiKey}/${ip}?strictness=1`;
    const { stdout } = await execAsync(`curl -s "${url}"`, { timeout: 10000 });
    const data = JSON.parse(stdout);
    
    if (data.success) {
      return {
        source: 'IPQualityScore',
        available: true,
        proxy: data.proxy,
        vpn: data.vpn,
        tor: data.tor,
        activeVPN: data.active_vpn,
        activeTor: data.active_tor,
        recentAbuse: data.recent_abuse,
        botStatus: data.bot_status,
        fraudScore: data.fraud_score,
        country: data.country_code,
        city: data.city,
        isp: data.ISP,
        asn: data.ASN,
        organization: data.organization,
        connectionType: data.connection_type,
        abuseVelocity: data.abuse_velocity
      };
    }
    
    return {
      source: 'IPQualityScore',
      available: false,
      error: data.message || 'Unknown error'
    };
  } catch (error) {
    return {
      source: 'IPQualityScore',
      available: false,
      error: error.message
    };
  }
}

async function checkIPHub(ip) {
  try {
    const apiKey = process.env.IPHUB_API_KEY;
    
    if (!apiKey) {
      return {
        source: 'IPHub',
        available: false,
        error: 'API key required (set IPHUB_API_KEY env variable)',
        manualCheck: `https://iphub.info/?ip=${ip}`
      };
    }
    
    console.log('   Checking IPHub...');
    
    const url = `http://v2.api.iphub.info/ip/${ip}`;
    const cmd = `curl -s -H "X-Key: ${apiKey}" "${url}"`;
    const { stdout } = await execAsync(cmd, { timeout: 10000 });
    const data = JSON.parse(stdout);
    
    if (data.ip) {
      return {
        source: 'IPHub',
        available: true,
        block: data.block,
        blockDescription: data.block === 0 ? 'Residential/Unclassified' :
                         data.block === 1 ? 'Proxy/VPN/Bad IP' :
                         data.block === 2 ? 'Datacenter IP' : 'Unknown',
        country: data.countryCode,
        countryName: data.countryName,
        asn: data.asn,
        isp: data.isp,
        hostname: data.hostname
      };
    }
    
    return {
      source: 'IPHub',
      available: false,
      error: 'No data returned'
    };
  } catch (error) {
    return {
      source: 'IPHub',
      available: false,
      error: error.message
    };
  }
}

async function checkGetIPIntel(ip) {
  try {
    console.log('   Checking GetIPIntel...');
    
    const contact = 'your@email.com'; // Should be customized
    const url = `http://check.getipintel.net/check.php?ip=${ip}&contact=${contact}&flags=m`;
    
    const { stdout } = await execAsync(`curl -s "${url}"`, { timeout: 10000 });
    
    const score = parseFloat(stdout.trim());
    
    if (!isNaN(score) && score >= 0) {
      return {
        source: 'GetIPIntel',
        available: true,
        proxyScore: score,
        isProxy: score > 0.95,
        isSuspicious: score > 0.90,
        confidence: score >= 0.99 ? 'Very High' :
                   score >= 0.95 ? 'High' :
                   score >= 0.90 ? 'Medium' :
                   score >= 0.50 ? 'Low' : 'Very Low'
      };
    }
    
    return {
      source: 'GetIPIntel',
      available: false,
      error: 'Invalid response'
    };
  } catch (error) {
    return {
      source: 'GetIPIntel',
      available: false,
      error: error.message
    };
  }
}

async function checkShodan(ip) {
  try {
    const apiKey = process.env.SHODAN_API_KEY;
    
    if (!apiKey) {
      return {
        source: 'Shodan',
        available: false,
        error: 'API key required (set SHODAN_API_KEY env variable)',
        manualCheck: `https://www.shodan.io/host/${ip}`
      };
    }
    
    console.log('   Checking Shodan...');
    
    const url = `https://api.shodan.io/shodan/host/${ip}?key=${apiKey}`;
    const { stdout } = await execAsync(`curl -s "${url}"`, { timeout: 10000 });
    const data = JSON.parse(stdout);
    
    if (data.ip_str) {
      // Check for VPN/Proxy indicators
      const tags = data.tags || [];
      const isVPN = tags.includes('vpn') || tags.includes('proxy');
      const isDatacenter = tags.includes('cloud') || tags.includes('datacenter');
      
      // Check hostnames for VPN indicators
      const hostnames = data.hostnames || [];
      const vpnKeywords = ['vpn', 'proxy', 'tunnel', 'relay'];
      const hasVPNHostname = hostnames.some(h => 
        vpnKeywords.some(k => h.toLowerCase().includes(k))
      );
      
      return {
        source: 'Shodan',
        available: true,
        tags: tags,
        isVPN: isVPN,
        isDatacenter: isDatacenter,
        hasVPNHostname: hasVPNHostname,
        organization: data.org,
        isp: data.isp,
        asn: data.asn,
        hostnames: hostnames,
        ports: data.ports || []
      };
    }
    
    return {
      source: 'Shodan',
      available: true,
      found: false
    };
  } catch (error) {
    return {
      source: 'Shodan',
      available: false,
      error: error.message
    };
  }
}

function checkKnownVPNProviders(data) {
  const vpnProviders = [
    'nordvpn', 'expressvpn', 'surfshark', 'cyberghost', 'private internet access',
    'pia', 'protonvpn', 'mullvad', 'ipvanish', 'vyprvpn', 'windscribe',
    'tunnelbear', 'purevpn', 'hotspot shield', 'hide.me', 'torguard',
    'perfect privacy', 'ivpn', 'airvpn', 'trust.zone', 'astrill',
    'buffered', 'bolehvpn', 'azirevpn', 'ovpn', 'digital ocean',
    'amazon', 'google cloud', 'microsoft azure', 'linode', 'vultr',
    'hetzner', 'ovh'
  ];
  
  const providers = [];
  const orgName = (
    data.proxycheck?.provider ||
    data.ipquality?.isp ||
    data.iphub?.isp ||
    data.shodan?.organization ||
    ''
  ).toLowerCase();
  
  vpnProviders.forEach(provider => {
    if (orgName.includes(provider)) {
      providers.push(provider);
    }
  });
  
  return providers;
}

function assessAnonymity(results) {
  let score = 0;
  const indicators = [];
  
  // ProxyCheck
  if (results.proxycheck?.vpn) {
    score += 30;
    indicators.push('ProxyCheck detected VPN');
  }
  if (results.proxycheck?.proxy) {
    score += 25;
    indicators.push('ProxyCheck detected Proxy');
  }
  
  // IPQualityScore
  if (results.ipquality?.vpn) {
    score += 30;
    indicators.push('IPQualityScore detected VPN');
  }
  if (results.ipquality?.proxy) {
    score += 25;
    indicators.push('IPQualityScore detected Proxy');
  }
  if (results.ipquality?.tor) {
    score += 40;
    indicators.push('IPQualityScore detected Tor');
  }
  
  // IPHub
  if (results.iphub?.block === 1) {
    score += 35;
    indicators.push('IPHub flagged as Proxy/VPN');
  }
  if (results.iphub?.block === 2) {
    score += 20;
    indicators.push('IPHub detected Datacenter IP');
  }
  
  // GetIPIntel
  if (results.getipintel?.isProxy) {
    score += 30;
    indicators.push(`GetIPIntel high proxy score (${results.getipintel.proxyScore})`);
  }
  
  // Shodan
  if (results.shodan?.isVPN || results.shodan?.hasVPNHostname) {
    score += 25;
    indicators.push('Shodan detected VPN indicators');
  }
  if (results.shodan?.isDatacenter) {
    score += 15;
    indicators.push('Shodan detected Datacenter hosting');
  }
  
  // Known VPN Providers
  if (results.knownProviders && results.knownProviders.length > 0) {
    score += 35;
    indicators.push(`Matched known VPN provider: ${results.knownProviders.join(', ')}`);
  }
  
  score = Math.min(score, 100);
  
  let level;
  let verdict;
  
  if (score >= 80) {
    level = 'VERY HIGH';
    verdict = 'VPN/Proxy CONFIRMED';
  } else if (score >= 60) {
    level = 'HIGH';
    verdict = 'Likely VPN/Proxy';
  } else if (score >= 40) {
    level = 'MEDIUM';
    verdict = 'Possible VPN/Proxy';
  } else if (score >= 20) {
    level = 'LOW';
    verdict = 'Suspicious but uncertain';
  } else {
    level = 'MINIMAL';
    verdict = 'Appears to be residential';
  }
  
  return {
    score: score,
    level: level,
    verdict: verdict,
    indicators: indicators
  };
}

function showBanner() {
  console.log("\x1b[31m");
  console.log("██████╗ ██████╗  ██████╗ ██╗  ██╗██╗   ██╗    ██████╗ ███████╗████████╗███████╗ ██████╗████████╗ ██████╗ ██████╗ ");
  console.log("██╔══██╗██╔══██╗██╔═══██╗╚██╗██╔╝╚██╗ ██╔╝    ██╔══██╗██╔════╝╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝██╔═══██╗██╔══██╗");
  console.log("██████╔╝██████╔╝██║   ██║ ╚███╔╝  ╚████╔╝     ██║  ██║█████╗     ██║   █████╗  ██║        ██║   ██║   ██║██████╔╝");
  console.log("██╔═══╝ ██╔══██╗██║   ██║ ██╔██╗   ╚██╔╝      ██║  ██║██╔══╝     ██║   ██╔══╝  ██║        ██║   ██║   ██║██╔══██╗");
  console.log("██║     ██║  ██║╚██████╔╝██╔╝ ██╗   ██║       ██████╔╝███████╗   ██║   ███████╗╚██████╗   ██║   ╚██████╔╝██║  ██║");
  console.log("╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝       ╚═════╝ ╚══════╝   ╚═╝   ╚══════╝ ╚═════╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝");
  console.log("\x1b[0m");
  console.log("\x1b[35m🥝 NIKA Proxy/VPN Detector - Anonymous Connection Detection\x1b[0m");
  console.log("\x1b[33m⚠️  For fraud prevention and security analysis only\x1b[0m\n");
}

function displayResults(data) {
  console.log("\n╔════════════════════════════════════════════════════════╗");
  console.log("║       🌍 PROXY/VPN DETECTION RESULTS 🌍                ║");
  console.log("╚════════════════════════════════════════════════════════╝\n");
  
  console.log(`🎯 IP Address: \x1b[36m${data.ip}\x1b[0m\n`);
  
  // Anonymity Assessment
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
  console.log("\x1b[36m🔍 ANONYMITY ASSESSMENT\x1b[0m");
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
  
  const levelColor = {
    'VERY HIGH': '\x1b[41m\x1b[37m',
    'HIGH': '\x1b[31m',
    'MEDIUM': '\x1b[33m',
    'LOW': '\x1b[32m',
    'MINIMAL': '\x1b[32m'
  };
  
  console.log(`   Verdict: ${levelColor[data.assessment.level]}${data.assessment.verdict}\x1b[0m`);
  console.log(`   Anonymity Level: ${levelColor[data.assessment.level]}${data.assessment.level}\x1b[0m`);
  console.log(`   Confidence Score: ${data.assessment.score}/100\n`);
  
  if (data.assessment.indicators.length > 0) {
    console.log('   Detection Indicators:');
    data.assessment.indicators.forEach(ind => {
      console.log(`   • ${ind}`);
    });
    console.log('');
  }
  
  // Known Providers
  if (data.results.knownProviders && data.results.knownProviders.length > 0) {
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
    console.log("\x1b[36m🏢 KNOWN VPN/CLOUD PROVIDERS\x1b[0m");
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
    
    console.log(`   Matched Providers: ${data.results.knownProviders.join(', ')}\n`);
  }
  
  // ProxyCheck
  if (data.results.proxycheck?.available) {
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
    console.log("\x1b[36m🔍 PROXYCHECK.IO\x1b[0m");
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
    
    const pc = data.results.proxycheck;
    console.log(`   Proxy: ${pc.proxy ? '\x1b[31mYes\x1b[0m' : '\x1b[32mNo\x1b[0m'}`);
    console.log(`   VPN: ${pc.vpn ? '\x1b[31mYes\x1b[0m' : '\x1b[32mNo\x1b[0m'}`);
    if (pc.type) console.log(`   Type: ${pc.type}`);
    if (pc.provider) console.log(`   Provider: ${pc.provider}`);
    if (pc.country) console.log(`   Country: ${pc.country}`);
    if (pc.riskScore !== undefined) console.log(`   Risk Score: ${pc.riskScore}%`);
    console.log('');
  }
  
  // IPQualityScore
  if (data.results.ipquality?.available) {
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
    console.log("\x1b[36m🛡️  IPQUALITYSCORE\x1b[0m");
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
    
    const iq = data.results.ipquality;
    console.log(`   Proxy: ${iq.proxy ? '\x1b[31mYes\x1b[0m' : '\x1b[32mNo\x1b[0m'}`);
    console.log(`   VPN: ${iq.vpn ? '\x1b[31mYes\x1b[0m' : '\x1b[32mNo\x1b[0m'}`);
    console.log(`   Tor: ${iq.tor ? '\x1b[31mYes\x1b[0m' : '\x1b[32mNo\x1b[0m'}`);
    console.log(`   Fraud Score: ${iq.fraudScore}/100`);
    if (iq.isp) console.log(`   ISP: ${iq.isp}`);
    if (iq.organization) console.log(`   Organization: ${iq.organization}`);
    if (iq.connectionType) console.log(`   Connection Type: ${iq.connectionType}`);
    console.log('');
  } else if (data.results.ipquality?.manualCheck) {
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
    console.log("\x1b[36m🛡️  IPQUALITYSCORE\x1b[0m");
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
    console.log(`   Manual check: ${data.results.ipquality.manualCheck}\n`);
  }
  
  // IPHub
  if (data.results.iphub?.available) {
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
    console.log("\x1b[36m🔎 IPHUB\x1b[0m");
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
    
    const ih = data.results.iphub;
    console.log(`   Block Status: ${ih.block === 0 ? '\x1b[32m' : '\x1b[31m'}${ih.blockDescription}\x1b[0m`);
    if (ih.isp) console.log(`   ISP: ${ih.isp}`);
    if (ih.country) console.log(`   Country: ${ih.countryName} (${ih.country})`);
    console.log('');
  }
  
  // GetIPIntel
  if (data.results.getipintel?.available) {
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
    console.log("\x1b[36m📊 GETIPINTEL\x1b[0m");
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
    
    const gi = data.results.getipintel;
    console.log(`   Proxy Score: ${(gi.proxyScore * 100).toFixed(2)}%`);
    console.log(`   Confidence: ${gi.confidence}`);
    console.log(`   Assessment: ${gi.isProxy ? '\x1b[31mProxy Detected\x1b[0m' : '\x1b[32mNot a Proxy\x1b[0m'}`);
    console.log('');
  }
  
  // Shodan
  if (data.results.shodan?.available && data.results.shodan.found !== false) {
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
    console.log("\x1b[36m🔎 SHODAN\x1b[0m");
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
    
    const sh = data.results.shodan;
    console.log(`   VPN Detected: ${sh.isVPN || sh.hasVPNHostname ? '\x1b[31mYes\x1b[0m' : '\x1b[32mNo\x1b[0m'}`);
    console.log(`   Datacenter: ${sh.isDatacenter ? '\x1b[33mYes\x1b[0m' : 'No'}`);
    if (sh.organization) console.log(`   Organization: ${sh.organization}`);
    if (sh.hostnames && sh.hostnames.length > 0) {
      console.log(`   Hostnames: ${sh.hostnames.slice(0, 3).join(', ')}`);
    }
    console.log('');
  }
  
  // Recommendations
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
  console.log("\x1b[36m💡 RECOMMENDATIONS\x1b[0m");
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
  
  if (data.assessment.level === 'VERY HIGH' || data.assessment.level === 'HIGH') {
    console.log('   \x1b[31m🚨 HIGH ANONYMITY DETECTED\x1b[0m');
    console.log('   • Consider additional verification for this user');
    console.log('   • Flag for manual review in fraud detection');
    console.log('   • Apply stricter rate limits or captchas');
    console.log('   • Log all activity for audit trail');
  } else if (data.assessment.level === 'MEDIUM') {
    console.log('   \x1b[33m⚠️  MODERATE SUSPICION\x1b[0m');
    console.log('   • Monitor user activity closely');
    console.log('   • Consider additional authentication');
  } else {
    console.log('   \x1b[32m✓ Appears to be residential connection\x1b[0m');
    console.log('   • Standard security measures apply');
  }
  console.log('');
}

function saveResults(data) {
  const dir = './proxy-detector-reports';
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, -5);
  const ipSafe = data.ip.replace(/\./g, '-');
  const jsonFile = `${dir}/${ipSafe}-${timestamp}.json`;
  const txtFile = jsonFile.replace('.json', '.txt');
  
  fs.writeFileSync(jsonFile, JSON.stringify(data, null, 2));
  
  let txtContent = `═══════════════════════════════════════════════════════════
PROXY/VPN DETECTOR REPORT
═══════════════════════════════════════════════════════════

IP Address: ${data.ip}
Date: ${new Date(data.timestamp).toLocaleString()}

═══════════════════════════════════════════════════════════
ANONYMITY ASSESSMENT
═══════════════════════════════════════════════════════════

Verdict: ${data.assessment.verdict}
Anonymity Level: ${data.assessment.level}
Confidence Score: ${data.assessment.score}/100

Detection Indicators:
${data.assessment.indicators.map(i => `• ${i}`).join('\n')}

`;

  if (data.results.knownProviders && data.results.knownProviders.length > 0) {
    txtContent += `\nKnown VPN/Cloud Providers: ${data.results.knownProviders.join(', ')}\n`;
  }
  
  txtContent += `\n═══════════════════════════════════════════════════════════
DETAILED RESULTS
═══════════════════════════════════════════════════════════\n\n`;

  Object.entries(data.results).forEach(([source, result]) => {
    if (result.available && source !== 'knownProviders') {
      txtContent += `${source.toUpperCase()}:\n`;
      txtContent += JSON.stringify(result, null, 2) + '\n\n';
    }
  });
  
  fs.writeFileSync(txtFile, txtContent);
  
  console.log(`\x1b[32m✅ Results saved:\x1b[0m`);
  console.log(`   JSON: ${jsonFile}`);
  console.log(`   TXT: ${txtFile}\n`);
}

function showHelp() {
  showBanner();
  
  console.log("Usage: node proxy-detector.js [OPTIONS] <ip-address>\n");
  console.log("Options:");
  console.log("  --save           Save results to file");
  console.log("  --help           Show this help\n");
  
  console.log("Environment Variables (Optional):");
  console.log("  PROXYCHECK_API_KEY        ProxyCheck.io API key");
  console.log("  IPQUALITYSCORE_API_KEY    IPQualityScore API key");
  console.log("  IPHUB_API_KEY             IPHub API key");
  console.log("  SHODAN_API_KEY            Shodan API key\n");
  
  console.log("Examples:");
  console.log("  node proxy-detector.js 8.8.8.8");
  console.log("  node proxy-detector.js 1.1.1.1 --save\n");
}

async function main() {
  const args = process.argv.slice(2);
  
  if (args.includes('--help') || args.length === 0) {
    showHelp();
    process.exit(0);
  }
  
  let ip = null;
  let saveResults_flag = false;
  
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--save') {
      saveResults_flag = true;
    } else if (!args[i].startsWith('--')) {
      ip = args[i];
    }
  }
  
  if (!ip) {
    console.log("\x1b[31m❌ No IP address specified!\x1b[0m\n");
    showHelp();
    process.exit(1);
  }
  
  showBanner();
  
  console.log(`⏳ Analyzing IP: ${ip}...\n`);
  
  const results = {
    ip: ip,
    timestamp: new Date().toISOString(),
    results: {},
    assessment: null
  };
  
  // Run all checks
  results.results.proxycheck = await checkProxyCheck(ip);
  results.results.ipquality = await checkIPQuality(ip);
  results.results.iphub = await checkIPHub(ip);
  results.results.getipintel = await checkGetIPIntel(ip);
  results.results.shodan = await checkShodan(ip);
  results.results.knownProviders = checkKnownVPNProviders(results.results);
  
  // Assess overall anonymity
  results.assessment = assessAnonymity(results);
  
  displayResults(results);
  
  if (saveResults_flag) {
    saveResults(results);
  }
  
  console.log("\x1b[31m██████╗ ██████╗  ██████╗ ██╗  ██╗██╗   ██╗\x1b[0m");
  console.log("\x1b[35m🥝 Detection complete - by kiwi & 777\x1b[0m\n");
}

main().catch(console.error);
