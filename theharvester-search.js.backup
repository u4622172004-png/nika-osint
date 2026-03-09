#!/usr/bin/env node

const { exec } = require('child_process');
const { promisify } = require('util');
const execAsync = promisify(exec);
const fs = require('fs');
const axios = require('axios');

// ============================================
// THEHARVESTER INTEGRATION (EMAIL HARVEST)
// ============================================

async function checkTheHarvesterInstalled() {
  try {
    await execAsync('which theHarvester');
    return true;
  } catch {
    return false;
  }
}

async function runTheHarvester(domain, sources = 'all', limit = 500) {
  console.log(`\n⏳ Harvesting emails from ${domain}...`);
  console.log(`   Sources: ${sources}`);
  console.log(`   Limit: ${limit} results\n`);
  
  const cmd = `theHarvester -d ${domain} -b ${sources} -l ${limit} 2>&1`;
  
  try {
    const { stdout } = await execAsync(cmd, { 
      timeout: 300000,
      maxBuffer: 10 * 1024 * 1024
    });
    return parseTheHarvesterOutput(stdout, domain);
  } catch (error) {
    return { 
      available: false, 
      error: error.message 
    };
  }
}

function parseTheHarvesterOutput(output, domain) {
  const result = {
    available: true,
    domain: domain,
    timestamp: new Date().toISOString(),
    emails: new Set(),
    hosts: new Set(),
    ips: new Set(),
    subdomains: new Set(),
    urls: new Set(),
    people: new Set(),
    rawOutput: output
  };
  
  const lines = output.split('\n');
  
  lines.forEach(line => {
    // Extract emails
    const emailMatch = line.match(/([a-zA-Z0-9._-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+)/g);
    if (emailMatch) {
      emailMatch.forEach(email => result.emails.add(email.toLowerCase()));
    }
    
    // Extract hosts/subdomains
    const hostMatch = line.match(/([a-zA-Z0-9.-]+\.(com|org|net|edu|gov|io|co|uk|de|fr|it|es))/g);
    if (hostMatch) {
      hostMatch.forEach(host => {
        if (host.includes(domain)) {
          result.subdomains.add(host.toLowerCase());
        }
        result.hosts.add(host.toLowerCase());
      });
    }
    
    // Extract IPs
    const ipMatch = line.match(/\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/g);
    if (ipMatch) {
      ipMatch.forEach(ip => result.ips.add(ip));
    }
    
    // Extract URLs
    const urlMatch = line.match(/https?:\/\/[^\s]+/g);
    if (urlMatch) {
      urlMatch.forEach(url => result.urls.add(url));
    }
  });
  
  // Convert Sets to Arrays
  result.emails = Array.from(result.emails);
  result.hosts = Array.from(result.hosts);
  result.ips = Array.from(result.ips);
  result.subdomains = Array.from(result.subdomains);
  result.urls = Array.from(result.urls);
  
  return result;
}

// Manual fallback search
async function manualEmailSearch(domain) {
  console.log(`\n⏳ Manual email search for ${domain}...\n`);
  
  const results = {
    emails: new Set(),
    sources: []
  };
  
  // Google dork search
  const dorks = [
    `"@${domain}"`,
    `site:${domain} email`,
    `site:${domain} contact`,
    `"contact" site:${domain}`,
    `intext:"@${domain}"`,
    `site:linkedin.com "${domain}"`,
    `site:github.com "${domain}"`
  ];
  
  console.log(`   Generated ${dorks.length} search queries`);
  console.log(`   Use these on Google manually:\n`);
  
  dorks.forEach((dork, i) => {
    const searchUrl = `https://www.google.com/search?q=${encodeURIComponent(dork)}`;
    console.log(`   ${i + 1}. ${dork}`);
    console.log(`      ${searchUrl}\n`);
    results.sources.push({ dork, url: searchUrl });
  });
  
  return {
    available: true,
    domain: domain,
    manualSearch: true,
    searchQueries: results.sources,
    note: 'Run these searches manually on Google and extract emails'
  };
}

// ============================================
// DISPLAY FUNCTIONS
// ============================================

function showBanner() {
  console.log("\x1b[31m");
  console.log("████████╗██╗  ██╗███████╗██╗  ██╗ █████╗ ██████╗ ██╗   ██╗███████╗███████╗████████╗███████╗██████╗ ");
  console.log("╚══██╔══╝██║  ██║██╔════╝██║  ██║██╔══██╗██╔══██╗██║   ██║██╔════╝██╔════╝╚══██╔══╝██╔════╝██╔══██╗");
  console.log("   ██║   ███████║█████╗  ███████║███████║██████╔╝██║   ██║█████╗  ███████╗   ██║   █████╗  ██████╔╝");
  console.log("   ██║   ██╔══██║██╔══╝  ██╔══██║██╔══██║██╔══██╗╚██╗ ██╔╝██╔══╝  ╚════██║   ██║   ██╔══╝  ██╔══██╗");
  console.log("   ██║   ██║  ██║███████╗██║  ██║██║  ██║██║  ██║ ╚████╔╝ ███████╗███████║   ██║   ███████╗██║  ██║");
  console.log("   ╚═╝   ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝  ╚═══╝  ╚══════╝╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝");
  console.log("\x1b[0m");
  console.log("\x1b[35m🥝 NIKA TheHarvester Integration - Email & Host Harvesting\x1b[0m");
  console.log("\x1b[33m⚠️  For authorized reconnaissance only\x1b[0m\n");
}

function displayResults(data) {
  console.log("\n╔════════════════════════════════════════════════════════╗");
  console.log("║         📧 THEHARVESTER RESULTS 📧                     ║");
  console.log("╚════════════════════════════════════════════════════════╝\n");
  
  if (!data.available) {
    console.log(`\x1b[31m❌ Harvesting failed\x1b[0m`);
    if (data.error) console.log(`   Error: ${data.error}`);
    console.log("");
    return;
  }
  
  if (data.manualSearch) {
    console.log(`🎯 Domain: \x1b[36m${data.domain}\x1b[0m\n`);
    console.log("\x1b[33m📋 MANUAL SEARCH QUERIES:\x1b[0m\n");
    console.log(data.note + '\n');
    return;
  }
  
  console.log(`🎯 Domain: \x1b[36m${data.domain}\x1b[0m`);
  console.log(`⏰ Date: ${new Date(data.timestamp).toLocaleString()}\n`);
  
  // Emails
  if (data.emails && data.emails.length > 0) {
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
    console.log(`\x1b[36m📧 EMAILS FOUND (${data.emails.length})\x1b[0m`);
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
    
    data.emails.forEach((email, i) => {
      console.log(`   ${i + 1}. \x1b[32m${email}\x1b[0m`);
    });
    console.log('');
  }
  
  // Subdomains
  if (data.subdomains && data.subdomains.length > 0) {
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
    console.log(`\x1b[36m🔍 SUBDOMAINS (${data.subdomains.length})\x1b[0m`);
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
    
    data.subdomains.slice(0, 20).forEach((sub, i) => {
      console.log(`   ${i + 1}. ${sub}`);
    });
    if (data.subdomains.length > 20) {
      console.log(`   ... and ${data.subdomains.length - 20} more`);
    }
    console.log('');
  }
  
  // IPs
  if (data.ips && data.ips.length > 0) {
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
    console.log(`\x1b[36m🌐 IP ADDRESSES (${data.ips.length})\x1b[0m`);
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
    
    data.ips.forEach((ip, i) => {
      console.log(`   ${i + 1}. ${ip}`);
    });
    console.log('');
  }
  
  // Summary
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
  console.log("\x1b[36m📊 SUMMARY\x1b[0m");
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
  console.log(`   Emails: \x1b[32m${data.emails?.length || 0}\x1b[0m`);
  console.log(`   Subdomains: \x1b[32m${data.subdomains?.length || 0}\x1b[0m`);
  console.log(`   Hosts: \x1b[32m${data.hosts?.length || 0}\x1b[0m`);
  console.log(`   IPs: \x1b[32m${data.ips?.length || 0}\x1b[0m`);
  console.log(`   URLs: \x1b[32m${data.urls?.length || 0}\x1b[0m`);
  console.log('');
}

function saveResults(data) {
  const dir = './harvester-reports';
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, -5);
  const jsonFile = `${dir}/${data.domain}-${timestamp}.json`;
  const txtFile = jsonFile.replace('.json', '.txt');
  
  // Save JSON
  fs.writeFileSync(jsonFile, JSON.stringify(data, null, 2));
  
  // Save TXT
  let txtContent = `═══════════════════════════════════════════════════════════
THEHARVESTER EMAIL HARVESTING REPORT
═══════════════════════════════════════════════════════════

Domain: ${data.domain}
Date: ${new Date(data.timestamp).toLocaleString()}

═══════════════════════════════════════════════════════════
EMAILS FOUND (${data.emails?.length || 0})
═══════════════════════════════════════════════════════════

`;

  if (data.emails) {
    data.emails.forEach(email => {
      txtContent += `${email}\n`;
    });
  }
  
  txtContent += `\n═══════════════════════════════════════════════════════════
SUBDOMAINS (${data.subdomains?.length || 0})
═══════════════════════════════════════════════════════════

`;

  if (data.subdomains) {
    data.subdomains.forEach(sub => {
      txtContent += `${sub}\n`;
    });
  }
  
  txtContent += `\n═══════════════════════════════════════════════════════════
IP ADDRESSES (${data.ips?.length || 0})
═══════════════════════════════════════════════════════════

`;

  if (data.ips) {
    data.ips.forEach(ip => {
      txtContent += `${ip}\n`;
    });
  }
  
  fs.writeFileSync(txtFile, txtContent);
  
  console.log(`\x1b[32m✅ Results saved:\x1b[0m`);
  console.log(`   JSON: ${jsonFile}`);
  console.log(`   TXT: ${txtFile}\n`);
}

function showHelp() {
  showBanner();
  
  console.log("Usage: node theharvester-search.js [OPTIONS] <domain>\n");
  console.log("Options:");
  console.log("  --sources <sources>  Search sources (default: all)");
  console.log("                       Options: google, bing, linkedin, twitter, all");
  console.log("  --limit <number>     Results limit (default: 500)");
  console.log("  --save               Save results to file");
  console.log("  --manual             Generate manual search queries");
  console.log("  --help               Show this help\n");
  
  console.log("Examples:");
  console.log("  node theharvester-search.js example.com");
  console.log("  node theharvester-search.js example.com --sources google,bing");
  console.log("  node theharvester-search.js example.com --save");
  console.log("  node theharvester-search.js example.com --manual\n");
  
  console.log("\x1b[33mNote: Requires theHarvester installed\x1b[0m");
  console.log("\x1b[33mInstall: pip install theHarvester --break-system-packages\x1b[0m\n");
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
  
  let domain = null;
  let sources = 'all';
  let limit = 500;
  let saveResults_flag = false;
  let manualMode = false;
  
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--sources' && args[i + 1]) {
      sources = args[i + 1];
      i++;
    } else if (args[i] === '--limit' && args[i + 1]) {
      limit = parseInt(args[i + 1]);
      i++;
    } else if (args[i] === '--save') {
      saveResults_flag = true;
    } else if (args[i] === '--manual') {
      manualMode = true;
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
  
  let results;
  
  if (manualMode) {
    results = await manualEmailSearch(domain);
  } else {
    // Check if theHarvester is installed
    const harvesterInstalled = await checkTheHarvesterInstalled();
    
    if (!harvesterInstalled) {
      console.log("\x1b[33m⚠️  TheHarvester not installed!\x1b[0m\n");
      console.log("Install with: \x1b[36mpip install theHarvester --break-system-packages\x1b[0m\n");
      console.log("Switching to manual mode...\n");
      results = await manualEmailSearch(domain);
    } else {
      results = await runTheHarvester(domain, sources, limit);
    }
  }
  
  // Display
  displayResults(results);
  
  // Save if requested
  if (saveResults_flag && !results.manualSearch) {
    saveResults(results);
  }
  
  console.log("\x1b[31m████████╗██╗  ██╗███████╗██╗  ██╗ █████╗ ██████╗ ██╗   ██╗███████╗███████╗████████╗███████╗██████╗\x1b[0m");
  console.log("\x1b[35m🥝 Harvesting complete - by kiwi & 777\x1b[0m\n");
}

main().catch(console.error);
