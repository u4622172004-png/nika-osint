#!/usr/bin/env node

const { exec } = require('child_process');
const { promisify } = require('util');
const execAsync = promisify(exec);
const fs = require('fs');

// ============================================
// IOC CHECKER - Indicator of Compromise Analysis
// ============================================

function detectIOCType(ioc) {
  // IP Address
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(ioc)) {
    return 'ip';
  }
  
  // Domain
  if (/^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$/i.test(ioc)) {
    return 'domain';
  }
  
  // URL
  if (/^https?:\/\//i.test(ioc)) {
    return 'url';
  }
  
  // MD5 Hash
  if (/^[a-f0-9]{32}$/i.test(ioc)) {
    return 'md5';
  }
  
  // SHA1 Hash
  if (/^[a-f0-9]{40}$/i.test(ioc)) {
    return 'sha1';
  }
  
  // SHA256 Hash
  if (/^[a-f0-9]{64}$/i.test(ioc)) {
    return 'sha256';
  }
  
  // Email
  if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(ioc)) {
    return 'email';
  }
  
  return 'unknown';
}

async function checkVirusTotal(ioc, type) {
  try {
    const apiKey = process.env.VT_API_KEY;
    
    if (!apiKey) {
      return {
        source: 'VirusTotal',
        available: false,
        error: 'API key required (set VT_API_KEY env variable)',
        manualCheck: `https://www.virustotal.com/gui/search/${encodeURIComponent(ioc)}`
      };
    }
    
    console.log('   Checking VirusTotal...');
    
    let endpoint;
    if (type === 'ip') {
      endpoint = `https://www.virustotal.com/api/v3/ip_addresses/${ioc}`;
    } else if (type === 'domain') {
      endpoint = `https://www.virustotal.com/api/v3/domains/${ioc}`;
    } else if (type === 'url') {
      const urlId = Buffer.from(ioc).toString('base64').replace(/=/g, '');
      endpoint = `https://www.virustotal.com/api/v3/urls/${urlId}`;
    } else if (['md5', 'sha1', 'sha256'].includes(type)) {
      endpoint = `https://www.virustotal.com/api/v3/files/${ioc}`;
    } else {
      return { source: 'VirusTotal', available: false, error: 'Unsupported IOC type' };
    }
    
    const cmd = `curl -s -H "x-apikey: ${apiKey}" "${endpoint}"`;
    const { stdout } = await execAsync(cmd, { timeout: 10000 });
    
    const data = JSON.parse(stdout);
    
    if (data.data) {
      const attrs = data.data.attributes;
      const stats = attrs.last_analysis_stats || {};
      
      return {
        source: 'VirusTotal',
        available: true,
        malicious: stats.malicious || 0,
        suspicious: stats.suspicious || 0,
        harmless: stats.harmless || 0,
        undetected: stats.undetected || 0,
        totalEngines: Object.values(stats).reduce((a, b) => a + b, 0),
        reputation: attrs.reputation || 0,
        lastAnalysis: attrs.last_analysis_date,
        categories: attrs.categories || {},
        verdict: (stats.malicious || 0) > 0 ? 'MALICIOUS' : 
                 (stats.suspicious || 0) > 0 ? 'SUSPICIOUS' : 'CLEAN'
      };
    }
    
    return {
      source: 'VirusTotal',
      available: true,
      found: false,
      note: 'Not found in VirusTotal database'
    };
  } catch (error) {
    return {
      source: 'VirusTotal',
      available: false,
      error: error.message
    };
  }
}

async function checkAbuseIPDB(ip) {
  try {
    const apiKey = process.env.ABUSEIPDB_API_KEY;
    
    if (!apiKey) {
      return {
        source: 'AbuseIPDB',
        available: false,
        error: 'API key required (set ABUSEIPDB_API_KEY env variable)',
        manualCheck: `https://www.abuseipdb.com/check/${ip}`
      };
    }
    
    console.log('   Checking AbuseIPDB...');
    
    const url = `https://api.abuseipdb.com/api/v2/check?ipAddress=${ip}&maxAgeInDays=90&verbose`;
    const cmd = `curl -s -H "Key: ${apiKey}" -H "Accept: application/json" "${url}"`;
    
    const { stdout } = await execAsync(cmd, { timeout: 10000 });
    const data = JSON.parse(stdout);
    
    if (data.data) {
      const d = data.data;
      
      return {
        source: 'AbuseIPDB',
        available: true,
        abuseScore: d.abuseConfidenceScore,
        totalReports: d.totalReports,
        lastReported: d.lastReportedAt,
        isWhitelisted: d.isWhitelisted,
        country: d.countryCode,
        usage: d.usageType,
        isp: d.isp,
        domain: d.domain,
        verdict: d.abuseConfidenceScore > 75 ? 'MALICIOUS' :
                 d.abuseConfidenceScore > 25 ? 'SUSPICIOUS' : 'CLEAN'
      };
    }
    
    return {
      source: 'AbuseIPDB',
      available: true,
      found: false
    };
  } catch (error) {
    return {
      source: 'AbuseIPDB',
      available: false,
      error: error.message
    };
  }
}

async function checkAlienVault(ioc, type) {
  try {
    console.log('   Checking AlienVault OTX...');
    
    let endpoint;
    if (type === 'ip') {
      endpoint = `https://otx.alienvault.com/api/v1/indicators/IPv4/${ioc}/general`;
    } else if (type === 'domain') {
      endpoint = `https://otx.alienvault.com/api/v1/indicators/domain/${ioc}/general`;
    } else if (['md5', 'sha1', 'sha256'].includes(type)) {
      endpoint = `https://otx.alienvault.com/api/v1/indicators/file/${ioc}/general`;
    } else {
      return { source: 'AlienVault OTX', available: false, error: 'Unsupported IOC type' };
    }
    
    const { stdout } = await execAsync(`curl -s "${endpoint}"`, { timeout: 10000 });
    const data = JSON.parse(stdout);
    
    if (data.pulse_info) {
      return {
        source: 'AlienVault OTX',
        available: true,
        pulseCount: data.pulse_info.count || 0,
        pulses: (data.pulse_info.pulses || []).slice(0, 5).map(p => ({
          name: p.name,
          created: p.created,
          tags: p.tags
        })),
        verdict: (data.pulse_info.count || 0) > 0 ? 'SUSPICIOUS' : 'CLEAN'
      };
    }
    
    return {
      source: 'AlienVault OTX',
      available: true,
      found: false
    };
  } catch (error) {
    return {
      source: 'AlienVault OTX',
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
      return {
        source: 'Shodan',
        available: true,
        openPorts: (data.ports || []).length,
        ports: data.ports || [],
        services: (data.data || []).slice(0, 5).map(s => ({
          port: s.port,
          service: s.product || s.transport,
          version: s.version
        })),
        vulns: data.vulns || [],
        os: data.os,
        organization: data.org,
        isp: data.isp,
        asn: data.asn,
        country: data.country_name,
        lastUpdate: data.last_update
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

async function checkThreatCrowd(ioc, type) {
  try {
    console.log('   Checking ThreatCrowd...');
    
    let url;
    if (type === 'ip') {
      url = `https://www.threatcrowd.org/searchApi/v2/ip/report/?ip=${ioc}`;
    } else if (type === 'domain') {
      url = `https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=${ioc}`;
    } else if (type === 'email') {
      url = `https://www.threatcrowd.org/searchApi/v2/email/report/?email=${ioc}`;
    } else {
      return { source: 'ThreatCrowd', available: false, error: 'Unsupported IOC type' };
    }
    
    const { stdout } = await execAsync(`curl -s "${url}"`, { timeout: 10000 });
    const data = JSON.parse(stdout);
    
    if (data.response_code === '1') {
      return {
        source: 'ThreatCrowd',
        available: true,
        votes: data.votes || 0,
        resolutions: (data.resolutions || []).length,
        hashes: (data.hashes || []).length,
        references: data.references || [],
        verdict: (data.votes || 0) < 0 ? 'MALICIOUS' : 'UNKNOWN'
      };
    }
    
    return {
      source: 'ThreatCrowd',
      available: true,
      found: false
    };
  } catch (error) {
    return {
      source: 'ThreatCrowd',
      available: false,
      error: error.message
    };
  }
}

function generateManualChecks(ioc, type) {
  const checks = {
    virustotal: `https://www.virustotal.com/gui/search/${encodeURIComponent(ioc)}`,
    hybridanalysis: `https://www.hybrid-analysis.com/search?query=${encodeURIComponent(ioc)}`,
    anyrun: `https://app.any.run/submissions/#filehash:${ioc}`,
    urlhaus: `https://urlhaus.abuse.ch/browse.php?search=${encodeURIComponent(ioc)}`,
    threatfox: `https://threatfox.abuse.ch/browse.php?search=ioc:${encodeURIComponent(ioc)}`,
    malwarebazaar: `https://bazaar.abuse.ch/browse.php?search=${encodeURIComponent(ioc)}`,
    google: `https://www.google.com/search?q="${encodeURIComponent(ioc)}"+malware+OR+threat+OR+ioc`
  };
  
  if (type === 'ip') {
    checks.abuseipdb = `https://www.abuseipdb.com/check/${ioc}`;
    checks.shodan = `https://www.shodan.io/host/${ioc}`;
    checks.greynoise = `https://www.greynoise.io/viz/ip/${ioc}`;
    checks.censys = `https://search.censys.io/hosts/${ioc}`;
    checks.ipvoid = `https://www.ipvoid.com/ip-blacklist-check/`;
  }
  
  if (type === 'domain') {
    checks.whois = `https://who.is/whois/${ioc}`;
    checks.urlscan = `https://urlscan.io/search/#domain:${ioc}`;
  }
  
  return checks;
}

function assessThreat(results) {
  let score = 0;
  const findings = [];
  
  // VirusTotal
  if (results.virustotal?.malicious > 0) {
    score += results.virustotal.malicious * 5;
    findings.push(`VirusTotal: ${results.virustotal.malicious}/${results.virustotal.totalEngines} engines detected as malicious`);
  }
  
  // AbuseIPDB
  if (results.abuseipdb?.abuseScore > 0) {
    score += results.abuseipdb.abuseScore;
    findings.push(`AbuseIPDB: Abuse score ${results.abuseipdb.abuseScore}%`);
  }
  
  // AlienVault
  if (results.alienvault?.pulseCount > 0) {
    score += results.alienvault.pulseCount * 2;
    findings.push(`AlienVault: Found in ${results.alienvault.pulseCount} threat pulses`);
  }
  
  // Shodan vulns
  if (results.shodan?.vulns && results.shodan.vulns.length > 0) {
    score += results.shodan.vulns.length * 10;
    findings.push(`Shodan: ${results.shodan.vulns.length} vulnerabilities detected`);
  }
  
  // ThreatCrowd
  if (results.threatcrowd?.votes < 0) {
    score += Math.abs(results.threatcrowd.votes) * 5;
    findings.push(`ThreatCrowd: Negative reputation (${results.threatcrowd.votes} votes)`);
  }
  
  let level;
  if (score >= 75) level = 'CRITICAL';
  else if (score >= 50) level = 'HIGH';
  else if (score >= 25) level = 'MEDIUM';
  else if (score > 0) level = 'LOW';
  else level = 'CLEAN';
  
  return {
    score: Math.min(score, 100),
    level: level,
    findings: findings
  };
}

function showBanner() {
  console.log("\x1b[31m");
  console.log("██╗ ██████╗  ██████╗     ██████╗██╗  ██╗███████╗ ██████╗██╗  ██╗███████╗██████╗ ");
  console.log("██║██╔═══██╗██╔════╝    ██╔════╝██║  ██║██╔════╝██╔════╝██║ ██╔╝██╔════╝██╔══██╗");
  console.log("██║██║   ██║██║         ██║     ███████║█████╗  ██║     █████╔╝ █████╗  ██████╔╝");
  console.log("██║██║   ██║██║         ██║     ██╔══██║██╔══╝  ██║     ██╔═██╗ ██╔══╝  ██╔══██╗");
  console.log("██║╚██████╔╝╚██████╗    ╚██████╗██║  ██║███████╗╚██████╗██║  ██╗███████╗██║  ██║");
  console.log("╚═╝ ╚═════╝  ╚═════╝     ╚═════╝╚═╝  ╚═╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝");
  console.log("\x1b[0m");
  console.log("\x1b[35m🥝 NIKA IOC Checker - Indicator of Compromise Analysis\x1b[0m");
  console.log("\x1b[33m⚠️  For malware analysis and threat intelligence only\x1b[0m\n");
}

function displayResults(data) {
  console.log("\n╔════════════════════════════════════════════════════════╗");
  console.log("║       🛡️  IOC ANALYSIS RESULTS 🛡️                      ║");
  console.log("╚════════════════════════════════════════════════════════╝\n");
  
  console.log(`🎯 IOC: \x1b[36m${data.ioc}\x1b[0m`);
  console.log(`📋 Type: ${data.type.toUpperCase()}\n`);
  
  // Threat Assessment
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
  console.log("\x1b[36m⚠️  THREAT ASSESSMENT\x1b[0m");
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
  
  const threatColor = {
    'CRITICAL': '\x1b[41m\x1b[37m',
    'HIGH': '\x1b[31m',
    'MEDIUM': '\x1b[33m',
    'LOW': '\x1b[32m',
    'CLEAN': '\x1b[32m'
  };
  
  console.log(`   Threat Level: ${threatColor[data.threat.level]}${data.threat.level}\x1b[0m`);
  console.log(`   Threat Score: ${data.threat.score}/100\n`);
  
  if (data.threat.findings.length > 0) {
    console.log('   Findings:');
    data.threat.findings.forEach(f => {
      console.log(`   • ${f}`);
    });
    console.log('');
  }
  
  // VirusTotal
  if (data.results.virustotal?.available) {
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
    console.log("\x1b[36m🔍 VIRUSTOTAL\x1b[0m");
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
    
    if (data.results.virustotal.found !== false) {
      const vt = data.results.virustotal;
      console.log(`   Verdict: ${threatColor[vt.verdict]}${vt.verdict}\x1b[0m`);
      console.log(`   Detections: ${vt.malicious}/${vt.totalEngines} engines`);
      console.log(`   Malicious: ${vt.malicious}`);
      console.log(`   Suspicious: ${vt.suspicious}`);
      console.log(`   Harmless: ${vt.harmless}`);
      console.log(`   Undetected: ${vt.undetected}`);
      if (vt.reputation) console.log(`   Reputation: ${vt.reputation}`);
    } else {
      console.log(`   ${data.results.virustotal.note || 'Not found'}`);
    }
    
    if (data.results.virustotal.manualCheck) {
      console.log(`   Manual check: ${data.results.virustotal.manualCheck}`);
    }
    console.log('');
  }
  
  // AbuseIPDB
  if (data.results.abuseipdb?.available && data.type === 'ip') {
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
    console.log("\x1b[36m🚨 ABUSEIPDB\x1b[0m");
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
    
    if (data.results.abuseipdb.found !== false) {
      const abuse = data.results.abuseipdb;
      console.log(`   Verdict: ${threatColor[abuse.verdict]}${abuse.verdict}\x1b[0m`);
      console.log(`   Abuse Score: ${abuse.abuseScore}%`);
      console.log(`   Total Reports: ${abuse.totalReports}`);
      console.log(`   Country: ${abuse.country}`);
      console.log(`   ISP: ${abuse.isp}`);
      console.log(`   Whitelisted: ${abuse.isWhitelisted ? 'Yes' : 'No'}`);
    } else {
      console.log(`   Not found in AbuseIPDB`);
    }
    
    if (data.results.abuseipdb.manualCheck) {
      console.log(`   Manual check: ${data.results.abuseipdb.manualCheck}`);
    }
    console.log('');
  }
  
  // AlienVault
  if (data.results.alienvault?.available) {
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
    console.log("\x1b[36m👽 ALIENVAULT OTX\x1b[0m");
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
    
    if (data.results.alienvault.found !== false) {
      const otx = data.results.alienvault;
      console.log(`   Verdict: ${threatColor[otx.verdict]}${otx.verdict}\x1b[0m`);
      console.log(`   Pulse Count: ${otx.pulseCount}`);
      
      if (otx.pulses && otx.pulses.length > 0) {
        console.log(`\n   Recent Pulses:`);
        otx.pulses.forEach((p, i) => {
          console.log(`   ${i + 1}. ${p.name}`);
          if (p.tags.length > 0) console.log(`      Tags: ${p.tags.join(', ')}`);
        });
      }
    } else {
      console.log(`   Not found in AlienVault OTX`);
    }
    console.log('');
  }
  
  // Shodan
  if (data.results.shodan?.available && data.type === 'ip') {
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
    console.log("\x1b[36m🔎 SHODAN\x1b[0m");
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
    
    if (data.results.shodan.found !== false) {
      const shodan = data.results.shodan;
      console.log(`   Open Ports: ${shodan.openPorts}`);
      console.log(`   Ports: ${shodan.ports.join(', ')}`);
      console.log(`   Organization: ${shodan.organization || 'N/A'}`);
      console.log(`   ISP: ${shodan.isp || 'N/A'}`);
      console.log(`   OS: ${shodan.os || 'N/A'}`);
      console.log(`   Country: ${shodan.country || 'N/A'}`);
      
      if (shodan.vulns && shodan.vulns.length > 0) {
        console.log(`\n   \x1b[31m⚠️  Vulnerabilities: ${shodan.vulns.length}\x1b[0m`);
        shodan.vulns.slice(0, 5).forEach(vuln => {
          console.log(`   • ${vuln}`);
        });
      }
      
      if (shodan.services && shodan.services.length > 0) {
        console.log(`\n   Services:`);
        shodan.services.forEach(s => {
          console.log(`   • Port ${s.port}: ${s.service} ${s.version || ''}`);
        });
      }
    } else {
      console.log(`   Not found in Shodan`);
    }
    
    if (data.results.shodan.manualCheck) {
      console.log(`\n   Manual check: ${data.results.shodan.manualCheck}`);
    }
    console.log('');
  }
  
  // ThreatCrowd
  if (data.results.threatcrowd?.available) {
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
    console.log("\x1b[36m👥 THREATCROWD\x1b[0m");
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
    
    if (data.results.threatcrowd.found !== false) {
      const tc = data.results.threatcrowd;
      console.log(`   Votes: ${tc.votes}`);
      console.log(`   Resolutions: ${tc.resolutions}`);
      console.log(`   Associated Hashes: ${tc.hashes}`);
      console.log(`   References: ${tc.references.length}`);
    } else {
      console.log(`   Not found in ThreatCrowd`);
    }
    console.log('');
  }
  
  // Manual Checks
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
  console.log("\x1b[36m🔗 MANUAL VERIFICATION LINKS\x1b[0m");
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
  
  Object.entries(data.manualChecks).forEach(([service, url]) => {
    console.log(`   ${service}: ${url}`);
  });
  console.log('');
  
  // Recommendations
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
  console.log("\x1b[36m💡 RECOMMENDATIONS\x1b[0m");
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
  
  if (data.threat.level === 'CRITICAL' || data.threat.level === 'HIGH') {
    console.log('   \x1b[31m🚨 HIGH RISK - IMMEDIATE ACTION REQUIRED\x1b[0m');
    console.log('   • Block this IOC immediately');
    console.log('   • Investigate all related activity');
    console.log('   • Check for lateral movement');
    console.log('   • Review security logs');
  } else if (data.threat.level === 'MEDIUM') {
    console.log('   \x1b[33m⚠️  MEDIUM RISK - INVESTIGATE FURTHER\x1b[0m');
    console.log('   • Monitor this IOC closely');
    console.log('   • Review associated connections');
    console.log('   • Consider blocking if confirmed malicious');
  } else {
    console.log('   \x1b[32m✓ Low risk or clean\x1b[0m');
    console.log('   • Continue monitoring');
    console.log('   • No immediate action required');
  }
  console.log('');
}

function saveResults(data) {
  const dir = './ioc-checker-reports';
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, -5);
  const iocSafe = data.ioc.replace(/[^a-z0-9]/gi, '_');
  const jsonFile = `${dir}/${data.type}-${iocSafe}-${timestamp}.json`;
  const txtFile = jsonFile.replace('.json', '.txt');
  
  fs.writeFileSync(jsonFile, JSON.stringify(data, null, 2));
  
  let txtContent = `═══════════════════════════════════════════════════════════
IOC CHECKER REPORT
═══════════════════════════════════════════════════════════

IOC: ${data.ioc}
Type: ${data.type.toUpperCase()}
Date: ${new Date(data.timestamp).toLocaleString()}

═══════════════════════════════════════════════════════════
THREAT ASSESSMENT
═══════════════════════════════════════════════════════════

Threat Level: ${data.threat.level}
Threat Score: ${data.threat.score}/100

Findings:
${data.threat.findings.map(f => `• ${f}`).join('\n')}

═══════════════════════════════════════════════════════════
DETAILED RESULTS
═══════════════════════════════════════════════════════════

`;

  // Add all results
  Object.entries(data.results).forEach(([source, result]) => {
    if (result.available) {
      txtContent += `${source.toUpperCase()}:\n`;
      txtContent += JSON.stringify(result, null, 2) + '\n\n';
    }
  });
  
  txtContent += `═══════════════════════════════════════════════════════════
MANUAL VERIFICATION LINKS
═══════════════════════════════════════════════════════════\n\n`;

  Object.entries(data.manualChecks).forEach(([service, url]) => {
    txtContent += `${service}: ${url}\n`;
  });
  
  fs.writeFileSync(txtFile, txtContent);
  
  console.log(`\x1b[32m✅ Results saved:\x1b[0m`);
  console.log(`   JSON: ${jsonFile}`);
  console.log(`   TXT: ${txtFile}\n`);
}

function showHelp() {
  showBanner();
  
  console.log("Usage: node ioc-checker.js [OPTIONS] <IOC>\n");
  console.log("Options:");
  console.log("  --save           Save results to file");
  console.log("  --help           Show this help\n");
  
  console.log("Supported IOC Types:");
  console.log("  • IP Address (IPv4)");
  console.log("  • Domain");
  console.log("  • URL");
  console.log("  • File Hash (MD5, SHA1, SHA256)");
  console.log("  • Email\n");
  
  console.log("Environment Variables (Optional):");
  console.log("  VT_API_KEY           VirusTotal API key");
  console.log("  ABUSEIPDB_API_KEY    AbuseIPDB API key");
  console.log("  SHODAN_API_KEY       Shodan API key\n");
  
  console.log("Examples:");
  console.log("  node ioc-checker.js 8.8.8.8");
  console.log("  node ioc-checker.js malicious-domain.com --save");
  console.log("  node ioc-checker.js 44d88612fea8a8f36de82e1278abb02f\n");
}

async function main() {
  const args = process.argv.slice(2);
  
  if (args.includes('--help') || args.length === 0) {
    showHelp();
    process.exit(0);
  }
  
  let ioc = null;
  let saveResults_flag = false;
  
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--save') {
      saveResults_flag = true;
    } else if (!args[i].startsWith('--')) {
      ioc = args[i];
    }
  }
  
  if (!ioc) {
    console.log("\x1b[31m❌ No IOC specified!\x1b[0m\n");
    showHelp();
    process.exit(1);
  }
  
  showBanner();
  
  const type = detectIOCType(ioc);
  
  console.log(`⏳ Analyzing IOC: ${ioc}`);
  console.log(`   Type: ${type.toUpperCase()}\n`);
  
  const results = {
    ioc: ioc,
    type: type,
    timestamp: new Date().toISOString(),
    results: {},
    manualChecks: null,
    threat: null
  };
  
  // Run checks
  results.results.virustotal = await checkVirusTotal(ioc, type);
  
  if (type === 'ip') {
    results.results.abuseipdb = await checkAbuseIPDB(ioc);
    results.results.shodan = await checkShodan(ioc);
  }
  
  results.results.alienvault = await checkAlienVault(ioc, type);
  results.results.threatcrowd = await checkThreatCrowd(ioc, type);
  
  results.manualChecks = generateManualChecks(ioc, type);
  results.threat = assessThreat(results);
  
  displayResults(results);
  
  if (saveResults_flag) {
    saveResults(results);
  }
  
  console.log("\x1b[31m██╗ ██████╗  ██████╗\x1b[0m");
  console.log("\x1b[35m🥝 Analysis complete - by kiwi & 777\x1b[0m\n");
}

main().catch(console.error);
