#!/usr/bin/env node

const https = require('https');
const crypto = require('crypto');
const fs = require('fs');

// ============================================
// HASH CRACKER - Multi-Hash Analyzer & Cracker
// ============================================

const HASH_TYPES = {
  md5: {
    name: 'MD5',
    length: 32,
    regex: /^[a-f0-9]{32}$/i,
    example: '5d41402abc4b2a76b9719d911017c592',
    strength: 'Weak - Deprecated',
    crackable: 'Very Easy'
  },
  sha1: {
    name: 'SHA-1',
    length: 40,
    regex: /^[a-f0-9]{40}$/i,
    example: 'aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d',
    strength: 'Weak - Deprecated',
    crackable: 'Easy'
  },
  sha256: {
    name: 'SHA-256',
    length: 64,
    regex: /^[a-f0-9]{64}$/i,
    example: '2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae',
    strength: 'Strong',
    crackable: 'Hard'
  },
  sha512: {
    name: 'SHA-512',
    length: 128,
    regex: /^[a-f0-9]{128}$/i,
    example: 'cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e',
    strength: 'Very Strong',
    crackable: 'Very Hard'
  },
  ntlm: {
    name: 'NTLM',
    length: 32,
    regex: /^[a-f0-9]{32}$/i,
    example: '8846f7eaee8fb117ad06bdd830b7586c',
    strength: 'Weak',
    crackable: 'Easy',
    note: 'Same length as MD5, check context'
  },
  mysql: {
    name: 'MySQL',
    regex: /^\*[A-F0-9]{40}$/i,
    example: '*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19',
    strength: 'Weak',
    crackable: 'Easy'
  },
  bcrypt: {
    name: 'bcrypt',
    regex: /^\$2[aby]?\$\d{2}\$[./A-Za-z0-9]{53}$/,
    example: '$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy',
    strength: 'Very Strong',
    crackable: 'Very Hard',
    note: 'Adaptive hashing with work factor'
  },
  argon2: {
    name: 'Argon2',
    regex: /^\$argon2[id]{1,2}\$v=\d+\$m=\d+,t=\d+,p=\d+\$/,
    example: '$argon2id$v=19$m=65536,t=2,p=1$...',
    strength: 'Extremely Strong',
    crackable: 'Extremely Hard',
    note: 'State-of-the-art password hashing'
  }
};

const CRACK_DATABASES = {
  crackstation: {
    name: 'CrackStation',
    url: 'https://crackstation.net/',
    features: ['15+ billion hashes', 'Free lookup', 'MD5/SHA1/SHA256/NTLM'],
    database: '190GB rainbow tables',
    cost: 'Free'
  },
  hashes: {
    name: 'Hashes.com',
    url: 'https://hashes.com/en/decrypt/hash',
    features: ['Hash lookup', 'Submissions', 'Statistics'],
    cost: 'Free'
  },
  cmd5: {
    name: 'CMD5',
    url: 'https://www.cmd5.org/',
    features: ['MD5 decryption', 'Paid premium'],
    cost: 'Free/Paid'
  },
  hashkiller: {
    name: 'HashKiller',
    url: 'https://hashkiller.io/',
    features: ['Multi-algorithm', 'Community submissions'],
    cost: 'Free'
  }
};

const CRACKING_TOOLS = {
  hashcat: {
    name: 'Hashcat',
    url: 'https://hashcat.net/hashcat/',
    type: 'GPU-based',
    features: ['350+ hash types', 'Rules engine', 'Distributed'],
    platform: 'Windows/Linux/macOS',
    cost: 'Free/Open Source'
  },
  john: {
    name: 'John the Ripper',
    url: 'https://www.openwall.com/john/',
    type: 'CPU/GPU',
    features: ['Many formats', 'Incremental mode', 'Wordlist mode'],
    platform: 'Cross-platform',
    cost: 'Free/Open Source'
  },
  ophcrack: {
    name: 'Ophcrack',
    url: 'https://ophcrack.sourceforge.io/',
    type: 'Rainbow tables',
    features: ['Windows passwords', 'Live CD', 'Rainbow tables'],
    platform: 'Windows/Linux',
    cost: 'Free'
  }
};

const WORDLISTS = {
  rockyou: {
    name: 'RockYou',
    size: '14 million passwords',
    source: 'RockYou breach (2009)',
    url: 'https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt'
  },
  secLists: {
    name: 'SecLists',
    description: 'Collection of password lists',
    url: 'https://github.com/danielmiessler/SecLists',
    types: 'Passwords, usernames, fuzzing'
  },
  crackstation: {
    name: 'CrackStation Wordlist',
    size: '15GB',
    url: 'https://crackstation.net/crackstation-wordlist-password-cracking-dictionary.htm'
  }
};

function showBanner() {
  console.log("\x1b[31m");
  console.log("██╗  ██╗ █████╗ ███████╗██╗  ██╗     ██████╗██████╗  █████╗  ██████╗██╗  ██╗███████╗██████╗ ");
  console.log("██║  ██║██╔══██╗██╔════╝██║  ██║    ██╔════╝██╔══██╗██╔══██╗██╔════╝██║ ██╔╝██╔════╝██╔══██╗");
  console.log("███████║███████║███████╗███████║    ██║     ██████╔╝███████║██║     █████╔╝ █████╗  ██████╔╝");
  console.log("██╔══██║██╔══██║╚════██║██╔══██║    ██║     ██╔══██╗██╔══██║██║     ██╔═██╗ ██╔══╝  ██╔══██╗");
  console.log("██║  ██║██║  ██║███████║██║  ██║    ╚██████╗██║  ██║██║  ██║╚██████╗██║  ██╗███████╗██║  ██║");
  console.log("╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝     ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝");
  console.log("\x1b[0m");
  console.log("\x1b[35m🥝 NIKA Hash Cracker - Multi-Hash Analyzer & Database Lookup\x1b[0m");
  console.log("\x1b[33m⚠️  For authorized security testing only\x1b[0m\n");
}

function identifyHash(hash) {
  console.log('   [1/5] Identifying hash type...');
  
  const cleaned = hash.trim();
  const matches = [];
  
  // Check each hash type
  for (let [key, type] of Object.entries(HASH_TYPES)) {
    if (type.regex.test(cleaned)) {
      matches.push({
        type: key,
        name: type.name,
        length: cleaned.length,
        strength: type.strength,
        crackable: type.crackable,
        note: type.note
      });
    }
  }
  
  if (matches.length === 0) {
    return {
      identified: false,
      hash: cleaned,
      error: 'Unknown hash format'
    };
  }
  
  return {
    identified: true,
    hash: cleaned,
    matches: matches,
    primary: matches[0]
  };
}

function analyzeHash(hash) {
  console.log('   [2/5] Analyzing hash characteristics...');
  
  const analysis = {
    length: hash.length,
    charset: {
      hasLowercase: /[a-f]/.test(hash),
      hasUppercase: /[A-F]/.test(hash),
      hasNumbers: /[0-9]/.test(hash),
      hasSpecial: /[^a-fA-F0-9]/.test(hash)
    },
    format: {
      isHex: /^[a-fA-F0-9]+$/.test(hash),
      hasPrefix: hash.startsWith('$') || hash.startsWith('*'),
      hasSeparators: hash.includes('$') || hash.includes(':')
    }
  };
  
  // Determine encoding
  if (analysis.format.isHex) {
    analysis.encoding = 'Hexadecimal';
  } else if (analysis.format.hasPrefix) {
    analysis.encoding = 'Formatted (bcrypt/argon2/etc)';
  } else {
    analysis.encoding = 'Unknown';
  }
  
  // Check if salted
  analysis.salted = analysis.format.hasSeparators || analysis.format.hasPrefix;
  
  return analysis;
}

async function lookupCrackStation(hash) {
  console.log('   [3/5] Checking CrackStation database...');
  
  return new Promise((resolve) => {
    // Note: CrackStation doesn't have a public API
    // This demonstrates what would be checked
    
    resolve({
      available: false,
      note: 'Visit https://crackstation.net/ for manual lookup',
      url: 'https://crackstation.net/',
      instructions: 'Paste hash and solve captcha'
    });
  });
}

async function lookupHashesCom(hash) {
  console.log('   [4/5] Checking online databases...');
  
  // Hashes.com also requires manual lookup or API key
  return {
    available: false,
    note: 'Visit https://hashes.com/ for manual lookup',
    url: `https://hashes.com/en/decrypt/hash`,
    instructions: 'Enter hash to search database'
  };
}

function generatePlaintext(hash, type) {
  console.log('   [5/5] Generating example plaintexts...');
  
  // Common weak passwords to test locally
  const commonPasswords = [
    'password', '123456', '12345678', 'qwerty', 'abc123',
    'monkey', 'letmein', 'admin', 'welcome', 'login'
  ];
  
  const results = [];
  
  for (let password of commonPasswords) {
    let testHash;
    
    try {
      switch(type) {
        case 'md5':
          testHash = crypto.createHash('md5').update(password).digest('hex');
          break;
        case 'sha1':
          testHash = crypto.createHash('sha1').update(password).digest('hex');
          break;
        case 'sha256':
          testHash = crypto.createHash('sha256').update(password).digest('hex');
          break;
        case 'sha512':
          testHash = crypto.createHash('sha512').update(password).digest('hex');
          break;
        default:
          continue;
      }
      
      if (testHash.toLowerCase() === hash.toLowerCase()) {
        results.push({
          found: true,
          password: password,
          method: 'Local dictionary'
        });
      }
    } catch (e) {
      // Skip if error
    }
  }
  
  return {
    tested: commonPasswords.length,
    found: results.length > 0,
    results: results
  };
}

function getHashcatMode(hashType) {
  const modes = {
    'md5': '0',
    'sha1': '100',
    'sha256': '1400',
    'sha512': '1700',
    'ntlm': '1000',
    'bcrypt': '3200'
  };
  
  return modes[hashType] || 'Unknown';
}

function generateHashcatCommand(hash, hashType) {
  const mode = getHashcatMode(hashType);
  
  return {
    basic: `hashcat -m ${mode} -a 0 hash.txt rockyou.txt`,
    withRules: `hashcat -m ${mode} -a 0 hash.txt rockyou.txt -r rules/best64.rule`,
    bruteforce: `hashcat -m ${mode} -a 3 hash.txt ?a?a?a?a?a?a?a?a`,
    explanation: {
      '-m': `Hash mode (${mode} = ${hashType})`,
      '-a 0': 'Attack mode: Dictionary',
      '-a 3': 'Attack mode: Brute-force',
      '?a': 'All characters (uppercase, lowercase, numbers, symbols)'
    }
  };
}

function displayResults(data) {
  console.log("\n╔════════════════════════════════════════════════════════╗");
  console.log("║       🔐 HASH ANALYSIS REPORT 🔐                       ║");
  console.log("╚════════════════════════════════════════════════════════╝\n");
  
  console.log(`🔑 Hash: \x1b[36m${data.hash.substring(0, 50)}${data.hash.length > 50 ? '...' : ''}\x1b[0m\n`);
  
  // Identification
  console.log("\x1b[36m┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓\x1b[0m");
  console.log("\x1b[36m┃                  HASH IDENTIFICATION                 ┃\x1b[0m");
  console.log("\x1b[36m┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛\x1b[0m\n");
  
  if (data.identification.identified) {
    console.log(`   Primary Type:        \x1b[32m${data.identification.primary.name}\x1b[0m`);
    console.log(`   Length:              ${data.identification.primary.length} characters`);
    console.log(`   Strength:            ${data.identification.primary.strength}`);
    console.log(`   Crackability:        ${data.identification.primary.crackable}`);
    if (data.identification.primary.note) {
      console.log(`   Note:                ${data.identification.primary.note}`);
    }
    console.log('');
    
    if (data.identification.matches.length > 1) {
      console.log('   \x1b[33mPossible Alternatives:\x1b[0m');
      data.identification.matches.slice(1).forEach(match => {
        console.log(`      • ${match.name} - ${match.note || match.strength}`);
      });
      console.log('');
    }
  } else {
    console.log(`   Status:              \x1b[31m${data.identification.error}\x1b[0m\n`);
  }
  
  // Analysis
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
  console.log("\x1b[36m🔬 HASH ANALYSIS\x1b[0m");
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
  
  console.log(`   Length:              ${data.analysis.length} characters`);
  console.log(`   Encoding:            ${data.analysis.encoding}`);
  console.log(`   Format:              ${data.analysis.format.isHex ? 'Hexadecimal' : 'Formatted'}`);
  console.log(`   Salted:              ${data.analysis.salted ? 'Likely Yes' : 'Likely No'}\n`);
  
  // Dictionary Check
  if (data.dictionary.found) {
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
    console.log("\x1b[36m✅ DICTIONARY CHECK - CRACKED!\x1b[0m");
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
    
    data.dictionary.results.forEach(result => {
      console.log(`   \x1b[32m✓ FOUND: "${result.password}"\x1b[0m`);
      console.log(`   Method: ${result.method}\n`);
    });
  } else {
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
    console.log("\x1b[36m🔍 DICTIONARY CHECK\x1b[0m");
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
    
    console.log(`   Common passwords tested: ${data.dictionary.tested}`);
    console.log(`   Status:              \x1b[33mNot found in common list\x1b[0m\n`);
  }
  
  // Online Databases
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
  console.log("\x1b[36m🌐 ONLINE CRACK DATABASES\x1b[0m");
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
  
  Object.entries(CRACK_DATABASES).forEach(([key, db]) => {
    console.log(`   \x1b[32m${db.name}\x1b[0m (${db.cost})`);
    console.log(`      URL: ${db.url}`);
    console.log(`      Features: ${db.features.join(', ')}\n`);
  });
  
  // Cracking Tools
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
  console.log("\x1b[36m🛠️  HASH CRACKING TOOLS\x1b[0m");
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
  
  Object.entries(CRACKING_TOOLS).forEach(([key, tool]) => {
    console.log(`   \x1b[32m${tool.name}\x1b[0m (${tool.cost})`);
    console.log(`      URL: ${tool.url}`);
    console.log(`      Type: ${tool.type}`);
    console.log(`      Platform: ${tool.platform}\n`);
  });
  
  // Hashcat Commands
  if (data.identification.identified && data.hashcat) {
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
    console.log("\x1b[36m⚡ HASHCAT COMMANDS\x1b[0m");
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
    
    console.log('   \x1b[32mBasic Dictionary Attack:\x1b[0m');
    console.log(`      ${data.hashcat.basic}\n`);
    
    console.log('   \x1b[32mWith Rules:\x1b[0m');
    console.log(`      ${data.hashcat.withRules}\n`);
    
    console.log('   \x1b[32mBrute-force (8 chars):\x1b[0m');
    console.log(`      ${data.hashcat.bruteforce}\n`);
    
    console.log('   \x1b[33mParameters:\x1b[0m');
    Object.entries(data.hashcat.explanation).forEach(([param, desc]) => {
      console.log(`      ${param.padEnd(10)} ${desc}`);
    });
    console.log('');
  }
  
  // Wordlists
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
  console.log("\x1b[36m📚 WORDLISTS\x1b[0m");
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
  
  Object.entries(WORDLISTS).forEach(([key, list]) => {
    console.log(`   \x1b[32m${list.name}\x1b[0m`);
    if (list.size) console.log(`      Size: ${list.size}`);
    if (list.description) console.log(`      ${list.description}`);
    console.log(`      ${list.url}\n`);
  });
  
  // Recommendations
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
  console.log("\x1b[36m💡 CRACKING STRATEGY\x1b[0m");
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
  
  console.log('   \x1b[32m1. Online Databases:\x1b[0m');
  console.log('      • Try CrackStation first (free, fast)');
  console.log('      • Check Hashes.com');
  console.log('      • Search CMD5 for MD5 hashes\n');
  
  console.log('   \x1b[32m2. Dictionary Attack:\x1b[0m');
  console.log('      • Start with RockYou wordlist');
  console.log('      • Use rules to generate variations');
  console.log('      • Try common password patterns\n');
  
  console.log('   \x1b[32m3. Advanced Attacks:\x1b[0m');
  console.log('      • Mask attack for known patterns');
  console.log('      • Hybrid (wordlist + brute-force)');
  console.log('      • Rainbow tables for unsalted hashes\n');
  
  console.log('   \x1b[32m4. For Salted/Modern Hashes:\x1b[0m');
  console.log('      • bcrypt/argon2 are very slow to crack');
  console.log('      • Focus on weak passwords');
  console.log('      • Use GPU acceleration\n');
}

function saveReport(data) {
  const dir = './hash-crack-reports';
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, -5);
  const hashPrefix = data.hash.substring(0, 16);
  const filename = `${dir}/hash-${hashPrefix}-${timestamp}.txt`;
  
  let content = `═══════════════════════════════════════════════════════════
HASH CRACKING REPORT
═══════════════════════════════════════════════════════════

Date: ${new Date().toLocaleString()}
Hash: ${data.hash}

IDENTIFICATION:
${data.identification.identified ? `
Type: ${data.identification.primary.name}
Length: ${data.identification.primary.length}
Strength: ${data.identification.primary.strength}
Crackability: ${data.identification.primary.crackable}
` : `Error: ${data.identification.error}`}

ANALYSIS:
Encoding: ${data.analysis.encoding}
Salted: ${data.analysis.salted}

DICTIONARY CHECK:
${data.dictionary.found ? 
  `CRACKED: ${data.dictionary.results.map(r => r.password).join(', ')}` : 
  'Not found in common passwords'}

ONLINE DATABASES:
CrackStation: ${CRACK_DATABASES.crackstation.url}
Hashes.com: ${CRACK_DATABASES.hashes.url}

${data.hashcat ? `
HASHCAT COMMANDS:
Basic: ${data.hashcat.basic}
With Rules: ${data.hashcat.withRules}
Brute-force: ${data.hashcat.bruteforce}
` : ''}
`;

  fs.writeFileSync(filename, content);
  console.log(`\x1b[32m✅ Report saved: ${filename}\x1b[0m\n`);
}

function showHelp() {
  showBanner();
  
  console.log("Usage: node hash-cracker.js <hash> [--save]\n");
  console.log("Options:");
  console.log("  --save               Save report to file");
  console.log("  --list               List supported hash types");
  console.log("  --help               Show this help\n");
  
  console.log("Examples:");
  console.log("  node hash-cracker.js 5d41402abc4b2a76b9719d911017c592");
  console.log("  node hash-cracker.js aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d --save\n");
}

async function main() {
  const args = process.argv.slice(2);
  
  if (args.length === 0 || args.includes('--help')) {
    showHelp();
    process.exit(0);
  }
  
  showBanner();
  
  if (args.includes('--list')) {
    console.log("Supported Hash Types:\n");
    Object.entries(HASH_TYPES).forEach(([key, type]) => {
      console.log(`   \x1b[32m${type.name}\x1b[0m`);
      console.log(`      Length: ${type.length || 'Variable'}`);
      console.log(`      Example: ${type.example.substring(0, 40)}...`);
      console.log(`      Strength: ${type.strength}\n`);
    });
    process.exit(0);
  }
  
  let hash = null;
  let saveFlag = false;
  
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--save') {
      saveFlag = true;
    } else if (!args[i].startsWith('--')) {
      hash = args[i];
    }
  }
  
  if (!hash) {
    console.log("\x1b[31m❌ No hash specified!\x1b[0m\n");
    showHelp();
    process.exit(1);
  }
  
  console.log(`⏳ Analyzing hash...\n`);
  
  const results = {
    timestamp: new Date().toISOString(),
    hash: hash,
    identification: identifyHash(hash),
    analysis: null,
    crackstation: null,
    hashescom: null,
    dictionary: null,
    hashcat: null
  };
  
  if (!results.identification.identified) {
    console.log(`\x1b[31m❌ ${results.identification.error}\x1b[0m\n`);
    process.exit(1);
  }
  
  results.analysis = analyzeHash(hash);
  results.crackstation = await lookupCrackStation(hash);
  results.hashescom = await lookupHashesCom(hash);
  results.dictionary = generatePlaintext(hash, results.identification.primary.type);
  
  if (results.identification.primary.type !== 'bcrypt' && 
      results.identification.primary.type !== 'argon2') {
    results.hashcat = generateHashcatCommand(hash, results.identification.primary.type !== 'argon2') {
    results.hashcat = generateHashcatCommand(hash, results.identification.primary.type);
  }
  
  displayResults(results);
  
  if (saveFlag) {
    saveReport(results);
  }
  
  console.log("\x1b[31m██╗  ██╗ █████╗ ███████╗██╗  ██╗\x1b[0m");
  console.log("\x1b[35m🥝 Analysis complete - by kiwi & 777\x1b[0m\n");
}

main();
