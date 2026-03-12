#!/usr/bin/env node

const { exec } = require('child_process');
const { promisify } = require('util');
const execAsync = promisify(exec);
const fs = require('fs');

// ============================================
// BREACH HUNTER - Advanced Data Leak Aggregator
// ============================================

const BREACH_SOURCES = {
  hibp: {
    name: 'HaveIBeenPwned',
    url: 'https://haveibeenpwned.com/api/v3/breachedaccount/',
    requiresKey: true
  },
  dehashed: {
    name: 'DeHashed',
    url: 'https://www.dehashed.com/search?query=',
    type: 'manual'
  },
  leakcheck: {
    name: 'LeakCheck',
    url: 'https://leakcheck.io/api/public?check=',
    type: 'api'
  },
  intelx: {
    name: 'Intelligence X',
    url: 'https://intelx.io/search?term=',
    type: 'manual'
  },
  snusbase: {
    name: 'Snusbase',
    url: 'https://snusbase.com/search/',
    type: 'manual'
  },
  ghostproject: {
    name: 'Ghost Project',
    url: 'https://ghostproject.fr/',
    type: 'manual'
  },
  breachdirectory: {
    name: 'Breach Directory',
    url: 'https://breachdirectory.org/search?q=',
    type: 'manual'
  },
  psbdmp: {
    name: 'Pastebin Dumps',
    url: 'https://psbdmp.ws/?q=',
    type: 'manual'
  }
};

const DARKWEB_PASTE_SITES = [
  'paste.onion',
  'stronghold paste',
  'deep paste',
  'zerobin',
  'privatebin',
  'controlc',
  'pastebin',
  'ghostbin',
  'hastebin'
];

const COMMON_BREACH_COLLECTIONS = [
  'Collection #1-5 (773M accounts)',
  'Anti Public Combo List (457M)',
  'Exploit.in (593M)',
  'Breached Compilation (1.4B)',
  'COMB (Compilation of Many Breaches - 3.2B)',
  'RockYou2021 (8.4B passwords)',
  'LinkedIn (700M - 2021)',
  'Facebook (533M - 2021)',
  'Clubhouse (1.3M - 2021)',
  'Twitter (5.4M - 2022)',
  'Parler (70M - 2021)',
  'Twitch (125M - 2021)',
  'Telegram (500M - 2023)'
];

async function searchHIBP(email) {
  try {
    const apiKey = process.env.HIBP_API_KEY;
    
    if (!apiKey) {
      return {
        source: 'HaveIBeenPwned',
        available: false,
        error: 'API key required (set HIBP_API_KEY env variable)',
        manualCheck: `https://haveibeenpwned.com/`
      };
    }
    
    console.log('   Checking HaveIBeenPwned...');
    
    const url = `https://haveibeenpwned.com/api/v3/breachedaccount/${encodeURIComponent(email)}?truncateResponse=false`;
    const cmd = `curl -s -H "hibp-api-key: ${apiKey}" "${url}"`;
    
    const { stdout } = await execAsync(cmd, { timeout: 10000 });
    
    if (stdout && stdout.trim() && !stdout.includes('error')) {
      const breaches = JSON.parse(stdout);
      return {
        source: 'HaveIBeenPwned',
        available: true,
        found: breaches.length > 0,
        count: breaches.length,
        breaches: breaches.map(b => ({
          name: b.Name,
          title: b.Title,
          domain: b.Domain,
          date: b.BreachDate,
          compromisedData: b.DataClasses,
          verified: b.IsVerified,
          fabricated: b.IsFabricated,
          sensitive: b.IsSensitive,
          retired: b.IsRetired,
          description: b.Description
        }))
      };
    }
    
    return {
      source: 'HaveIBeenPwned',
      available: true,
      found: false,
      count: 0
    };
  } catch (error) {
    return {
      source: 'HaveIBeenPwned',
      available: false,
      error: error.message
    };
  }
}

async function searchLeakCheck(query) {
  try {
    console.log('   Checking LeakCheck...');
    
    const url = `https://leakcheck.io/api/public?check=${encodeURIComponent(query)}`;
    const { stdout } = await execAsync(`curl -s "${url}"`, { timeout: 10000 });
    
    if (stdout && stdout.trim()) {
      const data = JSON.parse(stdout);
      
      if (data.success && data.found > 0) {
        return {
          source: 'LeakCheck',
          available: true,
          found: true,
          count: data.found,
          sources: data.sources || [],
          details: 'Use paid API for full details'
        };
      }
      
      return {
        source: 'LeakCheck',
        available: true,
        found: false,
        count: 0
      };
    }
    
    return {
      source: 'LeakCheck',
      available: false,
      error: 'No response'
    };
  } catch (error) {
    return {
      source: 'LeakCheck',
      available: false,
      error: error.message
    };
  }
}

async function searchPastebinDumps(query) {
  try {
    console.log('   Searching pastebin dumps...');
    
    const searches = [
      `site:pastebin.com "${query}"`,
      `site:ghostbin.com "${query}"`,
      `site:paste.ee "${query}"`,
      `site:controlc.com "${query}"`,
      `"${query}" password email leak`,
      `"${query}" database dump`,
      `"${query}" combo list`
    ];
    
    return {
      source: 'Pastebin Dumps',
      available: true,
      searches: searches,
      instructions: 'Use these Google dorks to find paste dumps',
      manualCheck: searches.map(s => `https://www.google.com/search?q=${encodeURIComponent(s)}`)
    };
  } catch (error) {
    return {
      source: 'Pastebin Dumps',
      available: false,
      error: error.message
    };
  }
}

async function searchDarkwebPastes(query) {
  try {
    console.log('   Generating darkweb paste searches...');
    
    const ahmiaSearches = [
      `${query} password`,
      `${query} email`,
      `${query} database`,
      `${query} dump`,
      `${query} leak`,
      `${query} combo`
    ];
    
    return {
      source: 'Darkweb Pastes',
      available: true,
      ahmiaLinks: ahmiaSearches.map(s => `https://ahmia.fi/search/?q=${encodeURIComponent(s)}`),
      onionSites: DARKWEB_PASTE_SITES,
      warning: 'Requires Tor browser to access .onion sites',
      instructions: 'Search these terms on Ahmia.fi or use Tor for .onion paste sites'
    };
  } catch (error) {
    return {
      source: 'Darkweb Pastes',
      available: false,
      error: error.message
    };
  }
}

function generateManualChecks(query) {
  return {
    dehashed: {
      name: 'DeHashed',
      url: `https://www.dehashed.com/search?query=${encodeURIComponent(query)}`,
      note: 'Premium service - extensive breach database'
    },
    intelx: {
      name: 'Intelligence X',
      url: `https://intelx.io/`,
      search: query,
      note: 'Search darknet, pastes, leaks'
    },
    snusbase: {
      name: 'Snusbase',
      url: 'https://snusbase.com/',
      search: query,
      note: 'Premium breach search engine'
    },
    breachdirectory: {
      name: 'Breach Directory',
      url: `https://breachdirectory.org/`,
      search: query,
      note: 'Free breach check'
    },
    ghostproject: {
      name: 'Ghost Project',
      url: 'https://ghostproject.fr/',
      search: query,
      note: '1.4B+ leaked records'
    },
    leakpeek: {
      name: 'LeakPeek',
      url: 'https://leakpeek.com/',
      search: query,
      note: 'Recent data leaks'
    },
    hudsonrock: {
      name: 'Hudson Rock',
      url: 'https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-email',
      search: query,
      note: 'Infostealer logs search'
    }
  };
}

function generateGoogleDorks(query) {
  const dorks = [
    `"${query}" filetype:sql`,
    `"${query}" filetype:csv password`,
    `"${query}" filetype:txt email password`,
    `"${query}" "database dump"`,
    `"${query}" "combo list"`,
    `"${query}" "leaked database"`,
    `intext:"${query}" intext:"password" filetype:txt`,
    `site:pastebin.com "${query}"`,
    `site:ghostbin.com "${query}"`,
    `"${query}" site:github.com password`,
    `"${query}" site:gitlab.com credentials`,
    `"${query}" inurl:dump`,
    `"${query}" inurl:leak`,
    `"${query}" breach database`
  ];
  
  return {
    source: 'Google Dorks',
    available: true,
    dorks: dorks,
    searchLinks: dorks.map(d => `https://www.google.com/search?q=${encodeURIComponent(d)}`)
  };
}

function generateTelegramChannels() {
  return {
    source: 'Telegram Channels',
    channels: [
      '@breachdetector',
      '@leak_tools',
      '@dataleak',
      '@combolist',
      '@database_leaks',
      '@exposed_db',
      '@leakednudes (adult content warning)',
      '@databreach_alert',
      '@combo_list_free'
    ],
    warning: 'Many channels contain illegal content. Access at your own risk.',
    howToAccess: 'Open Telegram and search for these channels'
  };
}

function assessSeverity(results) {
  let score = 0;
  const findings = [];
  
  // Check HIBP results
  if (results.hibp?.found) {
    score += results.hibp.count * 10;
    findings.push(`Found in ${results.hibp.count} data breaches`);
    
    const sensitive = results.hibp.breaches?.filter(b => b.sensitive).length || 0;
    if (sensitive > 0) {
      score += sensitive * 15;
      findings.push(`${sensitive} breaches marked as sensitive`);
    }
  }
  
  // Check LeakCheck
  if (results.leakcheck?.found) {
    score += results.leakcheck.count * 5;
    findings.push(`LeakCheck found ${results.leakcheck.count} sources`);
  }
  
  // Determine severity level
  let level;
  if (score >= 100) level = 'CRITICAL';
  else if (score >= 50) level = 'HIGH';
  else if (score >= 20) level = 'MEDIUM';
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
  console.log("██████╗ ██████╗ ███████╗ █████╗  ██████╗██╗  ██╗    ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗ ");
  console.log("██╔══██╗██╔══██╗██╔════╝██╔══██╗██╔════╝██║  ██║    ██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗");
  console.log("██████╔╝██████╔╝█████╗  ███████║██║     ███████║    ███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝");
  console.log("██╔══██╗██╔══██╗██╔══╝  ██╔══██║██║     ██╔══██║    ██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗");
  console.log("██████╔╝██║  ██║███████╗██║  ██║╚██████╗██║  ██║    ██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║");
  console.log("╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝    ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝");
  console.log("\x1b[0m");
  console.log("\x1b[35m🥝 NIKA Breach Hunter - Advanced Data Leak Aggregator\x1b[0m");
  console.log("\x1b[33m⚠️  For authorized investigation only - Handle leaked data responsibly\x1b[0m\n");
}

function displayResults(data) {
  console.log("\n╔════════════════════════════════════════════════════════╗");
  console.log("║       🔓 BREACH HUNTING RESULTS 🔓                     ║");
  console.log("╚════════════════════════════════════════════════════════╝\n");
  
  console.log(`🎯 Target: \x1b[36m${data.query}\x1b[0m`);
  console.log(`📅 Scan Date: ${new Date(data.timestamp).toLocaleString()}\n`);
  
  // Severity Assessment
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
  console.log("\x1b[36m⚠️  SEVERITY ASSESSMENT\x1b[0m");
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
  
  const severityColor = {
    'CRITICAL': '\x1b[41m\x1b[37m',
    'HIGH': '\x1b[31m',
    'MEDIUM': '\x1b[33m',
    'LOW': '\x1b[32m',
    'CLEAN': '\x1b[32m'
  };
  
  console.log(`   Risk Level: ${severityColor[data.severity.level]}${data.severity.level}\x1b[0m`);
  console.log(`   Risk Score: ${data.severity.score}/100\n`);
  
  if (data.severity.findings.length > 0) {
    console.log('   Findings:');
    data.severity.findings.forEach(f => {
      console.log(`   • ${f}`);
    });
    console.log('');
  }
  
  // API Results
  if (data.results.hibp) {
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
    console.log("\x1b[36m🔍 HAVEIBEENPWNED RESULTS\x1b[0m");
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
    
    if (data.results.hibp.found) {
      console.log(`   \x1b[31m✗ Found in ${data.results.hibp.count} breaches!\x1b[0m\n`);
      
      data.results.hibp.breaches.slice(0, 10).forEach((breach, i) => {
        console.log(`   ${i + 1}. ${breach.title || breach.name}`);
        console.log(`      Date: ${breach.date}`);
        console.log(`      Domain: ${breach.domain || 'N/A'}`);
        console.log(`      Data: ${breach.compromisedData.join(', ')}`);
        if (breach.sensitive) console.log(`      \x1b[31m⚠️  Marked as SENSITIVE\x1b[0m`);
        console.log('');
      });
      
      if (data.results.hibp.count > 10) {
        console.log(`   ... and ${data.results.hibp.count - 10} more breaches\n`);
      }
    } else if (data.results.hibp.available) {
      console.log(`   \x1b[32m✓ Not found in HIBP database\x1b[0m\n`);
    } else {
      console.log(`   ⚠️  ${data.results.hibp.error}\n`);
      if (data.results.hibp.manualCheck) {
        console.log(`   Manual check: ${data.results.hibp.manualCheck}\n`);
      }
    }
  }
  
  // LeakCheck Results
  if (data.results.leakcheck) {
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
    console.log("\x1b[36m🔍 LEAKCHECK RESULTS\x1b[0m");
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
    
    if (data.results.leakcheck.found) {
      console.log(`   \x1b[31m✗ Found in ${data.results.leakcheck.count} sources!\x1b[0m`);
      if (data.results.leakcheck.sources.length > 0) {
        console.log(`   Sources: ${data.results.leakcheck.sources.join(', ')}`);
      }
      console.log(`   ${data.results.leakcheck.details}\n`);
    } else if (data.results.leakcheck.available) {
      console.log(`   \x1b[32m✓ Not found in LeakCheck\x1b[0m\n`);
    } else {
      console.log(`   ⚠️  ${data.results.leakcheck.error}\n`);
    }
  }
  
  // Google Dorks
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
  console.log("\x1b[36m🔍 GOOGLE DORK SEARCHES\x1b[0m");
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
  
  console.log(`   Generated ${data.googleDorks.dorks.length} search queries\n`);
  data.googleDorks.dorks.slice(0, 5).forEach((dork, i) => {
    console.log(`   ${i + 1}. ${dork}`);
  });
  console.log(`   ... and ${data.googleDorks.dorks.length - 5} more (see report file)\n`);
  
  // Pastebin Dumps
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
  console.log("\x1b[36m📋 PASTEBIN DUMP SEARCHES\x1b[0m");
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
  
  data.pastebinDumps.searches.forEach((search, i) => {
    console.log(`   ${i + 1}. ${search}`);
  });
  console.log('');
  
  // Darkweb Pastes
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
  console.log("\x1b[36m🕸️  DARKWEB PASTE SITES\x1b[0m");
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
  
  console.log(`   \x1b[33m⚠️  ${data.darkwebPastes.warning}\x1b[0m\n`);
  console.log('   Ahmia.fi Searches:');
  data.darkwebPastes.ahmiaLinks.slice(0, 3).forEach((link, i) => {
    console.log(`   ${i + 1}. ${link}`);
  });
  console.log('');
  console.log('   .onion Paste Sites:');
  data.darkwebPastes.onionSites.slice(0, 5).forEach(site => {
    console.log(`   • ${site}`);
  });
  console.log('');
  
  // Manual Check Services
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
  console.log("\x1b[36m🔐 PREMIUM BREACH DATABASES (Manual Check)\x1b[0m");
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
  
  Object.entries(data.manualChecks).forEach(([key, service]) => {
    console.log(`   ${service.name}`);
    console.log(`   URL: ${service.url}`);
    console.log(`   Note: ${service.note}\n`);
  });
  
  // Telegram Channels
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
  console.log("\x1b[36m📱 TELEGRAM BREACH CHANNELS\x1b[0m");
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
  
  console.log(`   \x1b[31m⚠️  ${data.telegramChannels.warning}\x1b[0m\n`);
  data.telegramChannels.channels.forEach(ch => {
    console.log(`   • ${ch}`);
  });
  console.log(`\n   ${data.telegramChannels.howToAccess}\n`);
  
  // Known Breach Collections
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
  console.log("\x1b[36m💾 MAJOR BREACH COLLECTIONS TO CHECK\x1b[0m");
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
  
  COMMON_BREACH_COLLECTIONS.slice(0, 8).forEach(collection => {
    console.log(`   • ${collection}`);
  });
  console.log('');
  
  // Recommendations
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
  console.log("\x1b[36m💡 RECOMMENDATIONS\x1b[0m");
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
  
  if (data.severity.level === 'CRITICAL' || data.severity.level === 'HIGH') {
    console.log('   \x1b[31m🚨 URGENT ACTIONS REQUIRED:\x1b[0m');
    console.log('   1. Change password IMMEDIATELY on all affected accounts');
    console.log('   2. Enable 2FA/MFA on all accounts');
    console.log('   3. Check for unauthorized access in account activity');
    console.log('   4. Monitor credit reports for identity theft');
    console.log('   5. Consider identity theft protection services');
  } else if (data.severity.level === 'MEDIUM') {
    console.log('   \x1b[33m⚠️  RECOMMENDED ACTIONS:\x1b[0m');
    console.log('   1. Change passwords on affected accounts');
    console.log('   2. Enable 2FA where possible');
    console.log('   3. Review account activity');
  } else {
    console.log('   \x1b[32m✓ Account appears relatively safe\x1b[0m');
    console.log('   • Continue monitoring for new breaches');
    console.log('   • Use unique passwords for each service');
    console.log('   • Enable 2FA where available');
  }
  console.log('');
}

function saveResults(data) {
  const dir = './breach-hunter-reports';
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, -5);
  const querySafe = data.query.replace(/[^a-z0-9]/gi, '_');
  const jsonFile = `${dir}/${querySafe}-${timestamp}.json`;
  const txtFile = jsonFile.replace('.json', '.txt');
  
  fs.writeFileSync(jsonFile, JSON.stringify(data, null, 2));
  
  let txtContent = `═══════════════════════════════════════════════════════════
BREACH HUNTER REPORT
═══════════════════════════════════════════════════════════

Target: ${data.query}
Scan Date: ${new Date(data.timestamp).toLocaleString()}

═══════════════════════════════════════════════════════════
SEVERITY ASSESSMENT
═══════════════════════════════════════════════════════════

Risk Level: ${data.severity.level}
Risk Score: ${data.severity.score}/100

Findings:
${data.severity.findings.map(f => `• ${f}`).join('\n')}

═══════════════════════════════════════════════════════════
HAVEIBEENPWNED RESULTS
═══════════════════════════════════════════════════════════

`;

  if (data.results.hibp?.found) {
    txtContent += `Found in ${data.results.hibp.count} breaches:\n\n`;
    data.results.hibp.breaches.forEach((breach, i) => {
      txtContent += `${i + 1}. ${breach.title || breach.name}\n`;
      txtContent += `   Date: ${breach.date}\n`;
      txtContent += `   Domain: ${breach.domain || 'N/A'}\n`;
      txtContent += `   Compromised Data: ${breach.compromisedData.join(', ')}\n`;
      if (breach.sensitive) txtContent += `   ⚠️  SENSITIVE BREACH\n`;
      txtContent += '\n';
    });
  } else {
    txtContent += data.results.hibp?.error || 'Not found in HIBP database\n';
  }
  
  txtContent += `\n═══════════════════════════════════════════════════════════
GOOGLE DORK SEARCHES
═══════════════════════════════════════════════════════════\n\n`;

  data.googleDorks.dorks.forEach((dork, i) => {
    txtContent += `${i + 1}. ${dork}\n`;
  });
  
  txtContent += `\n═══════════════════════════════════════════════════════════
PASTEBIN DUMP SEARCHES
═══════════════════════════════════════════════════════════\n\n`;

  data.pastebinDumps.searches.forEach((search, i) => {
    txtContent += `${i + 1}. ${search}\n`;
  });
  
  txtContent += `\n═══════════════════════════════════════════════════════════
DARKWEB PASTE SITES
═══════════════════════════════════════════════════════════\n\n`;

  txtContent += `WARNING: ${data.darkwebPastes.warning}\n\n`;
  txtContent += 'Ahmia.fi Search Links:\n';
  data.darkwebPastes.ahmiaLinks.forEach((link, i) => {
    txtContent += `${i + 1}. ${link}\n`;
  });
  
  txtContent += '\n.onion Paste Sites (Require Tor):\n';
  data.darkwebPastes.onionSites.forEach(site => {
    txtContent += `• ${site}\n`;
  });
  
  txtContent += `\n═══════════════════════════════════════════════════════════
PREMIUM BREACH DATABASES (Manual Check)
═══════════════════════════════════════════════════════════\n\n`;

  Object.entries(data.manualChecks).forEach(([key, service]) => {
    txtContent += `${service.name}\n`;
    txtContent += `URL: ${service.url}\n`;
    txtContent += `Note: ${service.note}\n\n`;
  });
  
  txtContent += `═══════════════════════════════════════════════════════════
TELEGRAM BREACH CHANNELS
═══════════════════════════════════════════════════════════\n\n`;

  txtContent += `WARNING: ${data.telegramChannels.warning}\n\n`;
  data.telegramChannels.channels.forEach(ch => {
    txtContent += `• ${ch}\n`;
  });
  
  txtContent += `\n═══════════════════════════════════════════════════════════
MAJOR BREACH COLLECTIONS
═══════════════════════════════════════════════════════════\n\n`;

  COMMON_BREACH_COLLECTIONS.forEach(collection => {
    txtContent += `• ${collection}\n`;
  });
  
  fs.writeFileSync(txtFile, txtContent);
  
  console.log(`\x1b[32m✅ Results saved:\x1b[0m`);
  console.log(`   JSON: ${jsonFile}`);
  console.log(`   TXT: ${txtFile}\n`);
}

function showHelp() {
  showBanner();
  
  console.log("Usage: node breach-hunter.js [OPTIONS] <email|username|query>\n");
  console.log("Options:");
  console.log("  --save           Save results to file");
  console.log("  --help           Show this help\n");
  
  console.log("Environment Variables:");
  console.log("  HIBP_API_KEY     HaveIBeenPwned API key (get from haveibeenpwned.com)\n");
  
  console.log("Examples:");
  console.log("  node breach-hunter.js user@example.com");
  console.log("  node breach-hunter.js username123 --save");
  console.log("  HIBP_API_KEY=your_key node breach-hunter.js email@test.com --save\n");
  
  console.log("\x1b[33mData Sources:\x1b[0m");
  console.log("  • HaveIBeenPwned (API)");
  console.log("  • LeakCheck (Public API)");
  console.log("  • Google Dorks (14 queries)");
  console.log("  • Pastebin Dumps");
  console.log("  • Darkweb Paste Sites");
  console.log("  • Premium Breach DBs (DeHashed, Snusbase, etc.)");
  console.log("  • Telegram Channels\n");
  
  console.log("\x1b[31m⚠️  LEGAL WARNING:\x1b[0m");
  console.log("  This tool is for authorized security research only.");
  console.log("  Accessing or distributing leaked credentials is illegal.");
  console.log("  Use responsibly and ethically.\n");
}

async function main() {
  const args = process.argv.slice(2);
  
  if (args.includes('--help') || args.length === 0) {
    showHelp();
    process.exit(0);
  }
  
  let query = null;
  let saveResults_flag = false;
  
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--save') {
      saveResults_flag = true;
    } else if (!args[i].startsWith('--')) {
      query = args[i];
    }
  }
  
  if (!query) {
    console.log("\x1b[31m❌ No query specified!\x1b[0m\n");
    showHelp();
    process.exit(1);
  }
  
  showBanner();
  
  console.log(`⏳ Hunting breaches for: ${query}...\n`);
  
  const results = {
    query: query,
    timestamp: new Date().toISOString(),
    results: {},
    googleDorks: null,
    pastebinDumps: null,
    darkwebPastes: null,
    manualChecks: null,
    telegramChannels: null,
    severity: null
  };
  
  // Run searches
  results.results.hibp = await searchHIBP(query);
  results.results.leakcheck = await searchLeakCheck(query);
  results.googleDorks = generateGoogleDorks(query);
  results.pastebinDumps = await searchPastebinDumps(query);
  results.darkwebPastes = await searchDarkwebPastes(query);
  results.manualChecks = generateManualChecks(query);
  results.telegramChannels = generateTelegramChannels();
  
  // Assess severity
  results.severity = assessSeverity(results);
  
  displayResults(results);
  
  if (saveResults_flag) {
    saveResults(results);
  }
  
  console.log("\x1b[31m██████╗ ██████╗ ███████╗ █████╗  ██████╗██╗  ██╗\x1b[0m");
  console.log("\x1b[35m🥝 Hunt complete - by kiwi & 777\x1b[0m\n");
}

main().catch(console.error);
