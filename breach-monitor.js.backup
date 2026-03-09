#!/usr/bin/env node

const axios = require('axios');
const fs = require('fs');
const crypto = require('crypto');

// ============================================
// BREACH MONITOR - Check data leaks
// ============================================

const BREACH_SOURCES = {
  haveibeenpwned: {
    name: 'HaveIBeenPwned',
    url: 'https://haveibeenpwned.com/api/v3/breachedaccount/',
    requiresKey: true,
    note: 'Get API key from: https://haveibeenpwned.com/API/Key'
  },
  dehashed: {
    name: 'DeHashed',
    url: 'https://api.dehashed.com/search',
    requiresKey: true,
    note: 'Requires paid API key'
  },
  leakcheck: {
    name: 'LeakCheck',
    url: 'https://leakcheck.io/api/public',
    requiresKey: false,
    note: 'Public endpoint'
  },
  intelx: {
    name: 'Intelligence X',
    url: 'https://2.intelx.io/phonebook/search',
    requiresKey: true,
    note: 'Requires API key'
  }
};

async function checkHaveIBeenPwned(email, apiKey) {
  try {
    console.log(`   Checking HaveIBeenPwned...`);
    
    if (!apiKey) {
      return {
        source: 'HaveIBeenPwned',
        available: false,
        note: 'API key required',
        manual: `https://haveibeenpwned.com/account/${email}`
      };
    }
    
    const response = await axios.get(
      `https://haveibeenpwned.com/api/v3/breachedaccount/${encodeURIComponent(email)}`,
      {
        headers: {
          'hibp-api-key': apiKey,
          'User-Agent': 'NIKA-OSINT/4.0'
        },
        validateStatus: status => status === 200 || status === 404
      }
    );
    
    if (response.status === 404) {
      return {
        source: 'HaveIBeenPwned',
        available: true,
        breached: false,
        message: 'No breaches found! ✓'
      };
    }
    
    const breaches = response.data.map(breach => ({
      name: breach.Name,
      title: breach.Title,
      domain: breach.Domain,
      breachDate: breach.BreachDate,
      addedDate: breach.AddedDate,
      pwn_count: breach.PwnCount,
      description: breach.Description,
      dataClasses: breach.DataClasses,
      isVerified: breach.IsVerified,
      isFabricated: breach.IsFabricated,
      isSpamList: breach.IsSpamList,
      isRetired: breach.IsRetired,
      logoPath: breach.LogoPath
    }));
    
    return {
      source: 'HaveIBeenPwned',
      available: true,
      breached: true,
      breachCount: breaches.length,
      breaches: breaches,
      totalPwned: breaches.reduce((sum, b) => sum + b.pwn_count, 0)
    };
  } catch (error) {
    return {
      source: 'HaveIBeenPwned',
      available: false,
      error: error.message
    };
  }
}

async function checkPasswordPwned(password) {
  try {
    console.log(`   Checking password in Pwned Passwords database...`);
    
    // SHA-1 hash
    const hash = crypto.createHash('sha1').update(password).digest('hex').toUpperCase();
    const prefix = hash.substring(0, 5);
    const suffix = hash.substring(5);
    
    const response = await axios.get(`https://api.pwnedpasswords.com/range/${prefix}`);
    
    const hashes = response.data.split('\n');
    const found = hashes.find(line => line.startsWith(suffix));
    
    if (found) {
      const count = parseInt(found.split(':')[1]);
      return {
        source: 'Pwned Passwords',
        available: true,
        pwned: true,
        count: count,
        severity: count > 100000 ? 'CRITICAL' : count > 10000 ? 'HIGH' : count > 1000 ? 'MEDIUM' : 'LOW',
        recommendation: 'Change this password immediately!'
      };
    }
    
    return {
      source: 'Pwned Passwords',
      available: true,
      pwned: false,
      message: 'Password not found in breaches ✓'
    };
  } catch (error) {
    return {
      source: 'Pwned Passwords',
      available: false,
      error: error.message
    };
  }
}

async function checkLeakCheck(email) {
  try {
    console.log(`   Checking LeakCheck...`);
    
    // LeakCheck public API (limited)
    const response = await axios.get(`https://leakcheck.io/api/public?check=${email}`, {
      headers: {
        'User-Agent': 'NIKA-OSINT/4.0'
      },
      timeout: 10000
    });
    
    return {
      source: 'LeakCheck',
      available: true,
      found: response.data.found,
      sources: response.data.sources || []
    };
  } catch (error) {
    return {
      source: 'LeakCheck',
      available: false,
      note: 'Public API limited - use manual check',
      manual: `https://leakcheck.io/`
    };
  }
}

function generateManualChecks(query) {
  return [
    {
      name: 'HaveIBeenPwned',
      url: `https://haveibeenpwned.com/account/${query}`,
      description: 'Check email in data breaches'
    },
    {
      name: 'DeHashed',
      url: `https://dehashed.com/search?query=${query}`,
      description: 'Search leaked credentials (paid)'
    },
    {
      name: 'LeakCheck',
      url: `https://leakcheck.io/`,
      description: 'Check email in leaks'
    },
    {
      name: 'Snusbase',
      url: `https://snusbase.com/`,
      description: 'Database search (paid)'
    },
    {
      name: 'Intelligence X',
      url: `https://intelx.io/?s=${query}`,
      description: 'Search in leaked data'
    },
    {
      name: 'GhostProject',
      url: `https://ghostproject.fr/`,
      description: 'Credential leak search'
    },
    {
      name: 'Breach Directory',
      url: `https://breachdirectory.org/`,
      description: 'Public breach database'
    },
    {
      name: 'Scylla.sh',
      url: `https://scylla.sh/`,
      description: 'Credential database'
    }
  ];
}

function showBanner() {
  console.log("\x1b[31m");
  console.log("██████╗ ██████╗ ███████╗ █████╗  ██████╗██╗  ██╗    ███╗   ███╗ ██████╗ ███╗   ██╗██╗████████╗ ██████╗ ██████╗ ");
  console.log("██╔══██╗██╔══██╗██╔════╝██╔══██╗██╔════╝██║  ██║    ████╗ ████║██╔═══██╗████╗  ██║██║╚══██╔══╝██╔═══██╗██╔══██╗");
  console.log("██████╔╝██████╔╝█████╗  ███████║██║     ███████║    ██╔████╔██║██║   ██║██╔██╗ ██║██║   ██║   ██║   ██║██████╔╝");
  console.log("██╔══██╗██╔══██╗██╔══╝  ██╔══██║██║     ██╔══██║    ██║╚██╔╝██║██║   ██║██║╚██╗██║██║   ██║   ██║   ██║██╔══██╗");
  console.log("██████╔╝██║  ██║███████╗██║  ██║╚██████╗██║  ██║    ██║ ╚═╝ ██║╚██████╔╝██║ ╚████║██║   ██║   ╚██████╔╝██║  ██║");
  console.log("╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝    ╚═╝     ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝");
  console.log("\x1b[0m");
  console.log("\x1b[35m🥝 NIKA Breach Monitor - Check for data leaks and breaches\x1b[0m");
  console.log("\x1b[33m⚠️  For security research only\x1b[0m\n");
}

function displayResults(data) {
  console.log("\n╔════════════════════════════════════════════════════════╗");
  console.log("║         🔓 BREACH MONITOR RESULTS 🔓                   ║");
  console.log("╚════════════════════════════════════════════════════════╝\n");
  
  if (data.type === 'email') {
    console.log(`📧 Email: \x1b[36m${data.query}\x1b[0m\n`);
  } else if (data.type === 'password') {
    console.log(`🔐 Password: \x1b[36m[HIDDEN]\x1b[0m\n`);
  }
  
  data.results.forEach(result => {
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
    console.log(`\x1b[36m${result.source}\x1b[0m`);
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
    
    if (!result.available) {
      console.log(`   \x1b[33m⚠️  ${result.note || result.error}\x1b[0m`);
      if (result.manual) {
        console.log(`   Manual check: ${result.manual}`);
      }
      console.log('');
      return;
    }
    
    // HaveIBeenPwned results
    if (result.source === 'HaveIBeenPwned') {
      if (result.breached) {
        console.log(`   \x1b[31m❌ BREACHED!\x1b[0m`);
        console.log(`   Found in ${result.breachCount} breaches`);
        console.log(`   Total accounts affected: ${result.totalPwned.toLocaleString()}\n`);
        
        console.log(`   Breaches:`);
        result.breaches.forEach((breach, i) => {
          console.log(`\n   ${i + 1}. \x1b[31m${breach.title}\x1b[0m`);
          console.log(`      Domain: ${breach.domain}`);
          console.log(`      Date: ${breach.breachDate}`);
          console.log(`      Accounts: ${breach.pwn_count.toLocaleString()}`);
          console.log(`      Data leaked: ${breach.dataClasses.join(', ')}`);
          console.log(`      Verified: ${breach.isVerified ? 'Yes' : 'No'}`);
          if (breach.description) {
            console.log(`      Info: ${breach.description.replace(/<[^>]*>/g, '').substring(0, 100)}...`);
          }
        });
      } else {
        console.log(`   \x1b[32m✓ ${result.message}\x1b[0m`);
      }
    }
    
    // Pwned Passwords results
    if (result.source === 'Pwned Passwords') {
      if (result.pwned) {
        console.log(`   \x1b[31m❌ PASSWORD COMPROMISED!\x1b[0m`);
        console.log(`   Found ${result.count.toLocaleString()} times in data breaches`);
        console.log(`   Severity: \x1b[31m${result.severity}\x1b[0m`);
        console.log(`   \x1b[33m⚠️  ${result.recommendation}\x1b[0m`);
      } else {
        console.log(`   \x1b[32m✓ ${result.message}\x1b[0m`);
      }
    }
    
    // LeakCheck results
    if (result.source === 'LeakCheck') {
      if (result.found) {
        console.log(`   \x1b[31m❌ Found in leaks\x1b[0m`);
        if (result.sources && result.sources.length > 0) {
          console.log(`   Sources: ${result.sources.join(', ')}`);
        }
      } else {
        console.log(`   \x1b[32m✓ Not found\x1b[0m`);
      }
    }
    
    console.log('');
  });
  
  // Manual checks
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
  console.log("\x1b[36m🔍 MANUAL BREACH DATABASES\x1b[0m");
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
  
  const manualChecks = generateManualChecks(data.query);
  manualChecks.forEach((check, i) => {
    console.log(`${i + 1}. \x1b[32m${check.name}\x1b[0m`);
    console.log(`   ${check.description}`);
    console.log(`   ${check.url}\n`);
  });
  
  // Security recommendations
  if (data.type === 'email') {
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
    console.log("\x1b[36m🛡️  SECURITY RECOMMENDATIONS\x1b[0m");
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
    
    console.log("  1. Change passwords on affected accounts");
    console.log("  2. Enable 2FA/MFA on all accounts");
    console.log("  3. Use unique passwords for each service");
    console.log("  4. Monitor your credit report");
    console.log("  5. Consider using a password manager");
    console.log("  6. Set up breach alerts (HaveIBeenPwned notifications)");
    console.log("  7. Review account activity for suspicious logins\n");
  }
}

function saveResults(data) {
  const dir = './breach-monitor-reports';
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, -5);
  const filename = data.type === 'password' ? 'password-check' : data.query.replace(/[^a-z0-9]/gi, '_');
  const jsonFile = `${dir}/${filename}-${timestamp}.json`;
  const txtFile = jsonFile.replace('.json', '.txt');
  
  // Don't save actual password in reports
  const safeData = { ...data };
  if (data.type === 'password') {
    safeData.query = '[REDACTED]';
  }
  
  fs.writeFileSync(jsonFile, JSON.stringify(safeData, null, 2));
  
  let txtContent = `═══════════════════════════════════════════════════════════
BREACH MONITOR REPORT
═══════════════════════════════════════════════════════════

Type: ${data.type}
Query: ${data.type === 'password' ? '[REDACTED]' : data.query}
Date: ${new Date(data.timestamp).toLocaleString()}

═══════════════════════════════════════════════════════════
RESULTS
═══════════════════════════════════════════════════════════

`;

  data.results.forEach(result => {
    txtContent += `${result.source}\n`;
    txtContent += `${'─'.repeat(50)}\n`;
    
    if (!result.available) {
      txtContent += `Status: Unavailable\n`;
      txtContent += `Note: ${result.note || result.error}\n\n`;
      return;
    }
    
    if (result.breached || result.pwned) {
      txtContent += `Status: BREACHED\n`;
      if (result.breachCount) {
        txtContent += `Breaches: ${result.breachCount}\n`;
      }
      if (result.count) {
        txtContent += `Times seen: ${result.count}\n`;
        txtContent += `Severity: ${result.severity}\n`;
      }
      if (result.breaches) {
        txtContent += '\nBreach Details:\n';
        result.breaches.forEach(breach => {
          txtContent += `  - ${breach.title} (${breach.breachDate})\n`;
          txtContent += `    Accounts: ${breach.pwn_count}\n`;
          txtContent += `    Data: ${breach.dataClasses.join(', ')}\n`;
        });
      }
    } else {
      txtContent += `Status: Not Found\n`;
    }
    
    txtContent += '\n';
  });
  
  txtContent += `═══════════════════════════════════════════════════════════
MANUAL CHECKS
═══════════════════════════════════════════════════════════

`;

  const manualChecks = generateManualChecks(data.type === 'password' ? '' : data.query);
  manualChecks.forEach(check => {
    txtContent += `${check.name}\n`;
    txtContent += `${check.url}\n`;
    txtContent += `${check.description}\n\n`;
  });
  
  fs.writeFileSync(txtFile, txtContent);
  
  console.log(`\x1b[32m✅ Results saved:\x1b[0m`);
  console.log(`   JSON: ${jsonFile}`);
  console.log(`   TXT: ${txtFile}\n`);
}

function showHelp() {
  showBanner();
  
  console.log("Usage: node breach-monitor.js [OPTIONS]\n");
  console.log("Options:");
  console.log("  --email <email>      Check email in breaches");
  console.log("  --password           Check password (interactive)");
  console.log("  --api-key <key>      HaveIBeenPwned API key");
  console.log("  --save               Save results to file");
  console.log("  --help               Show this help\n");
  
  console.log("Examples:");
  console.log("  node breach-monitor.js --email test@example.com");
  console.log("  node breach-monitor.js --email test@example.com --api-key YOUR_KEY");
  console.log("  node breach-monitor.js --password");
  console.log("  node breach-monitor.js --email test@example.com --save\n");
  
  console.log("\x1b[33mAPI Keys (optional but recommended):\x1b[0m");
  console.log("  HaveIBeenPwned: https://haveibeenpwned.com/API/Key");
  console.log("  Set env: export HIBP_API_KEY='your_key'\n");
}

async function main() {
  const args = process.argv.slice(2);
  
  if (args.includes('--help') || args.length === 0) {
    showHelp();
    process.exit(0);
  }
  
  let email = null;
  let checkPassword = false;
  let apiKey = process.env.HIBP_API_KEY || null;
  let saveResults_flag = false;
  
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--email' && args[i + 1]) {
      email = args[i + 1];
      i++;
    } else if (args[i] === '--password') {
      checkPassword = true;
    } else if (args[i] === '--api-key' && args[i + 1]) {
      apiKey = args[i + 1];
      i++;
    } else if (args[i] === '--save') {
      saveResults_flag = true;
    }
  }
  
  showBanner();
  
  if (checkPassword) {
    // Interactive password check
    const readline = require('readline').createInterface({
      input: process.stdin,
      output: process.stdout
    });
    
    readline.question('Enter password to check (hidden): ', async (password) => {
      readline.close();
      
      process.stdout.write('\x1B[1A\x1B[2K'); // Clear line
      
      console.log('\n⏳ Checking password...\n');
      
      const result = await checkPasswordPwned(password);
      
      const data = {
        type: 'password',
        query: password,
        timestamp: new Date().toISOString(),
        results: [result]
      };
      
      displayResults(data);
      
      if (saveResults_flag) {
        saveResults(data);
      }
    });
    
    readline._writeToOutput = function _writeToOutput(stringToWrite) {
      if (stringToWrite.charCodeAt(0) === 13) {
        readline.output.write('\n');
      }
    };
    
  } else if (email) {
    console.log(`⏳ Checking breaches for: ${email}...\n`);
    
    const results = [];
    
    // HaveIBeenPwned
    results.push(await checkHaveIBeenPwned(email, apiKey));
    
    // LeakCheck
    results.push(await checkLeakCheck(email));
    
    const data = {
      type: 'email',
      query: email,
      timestamp: new Date().toISOString(),
      results: results
    };
    
    displayResults(data);
    
    if (saveResults_flag) {
      saveResults(data);
    }
  } else {
    console.log("\x1b[31m❌ No query specified!\x1b[0m\n");
    showHelp();
    process.exit(1);
  }
  
  console.log("\x1b[31m██████╗ ██████╗ ███████╗ █████╗  ██████╗██╗  ██╗\x1b[0m");
  console.log("\x1b[35m🥝 Check complete - by kiwi & 777\x1b[0m\n");
}

if (require.main === module) {
  main().catch(console.error);
}
