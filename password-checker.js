#!/usr/bin/env node

const https = require('https');
const crypto = require('crypto');
const fs = require('fs');

// ============================================
// PASSWORD LEAK CHECKER - Pwned Passwords
// ============================================

const BREACH_DATABASES = {
  hibp: {
    name: 'Have I Been Pwned',
    url: 'https://haveibeenpwned.com/Passwords',
    api: 'https://api.pwnedpasswords.com/range/',
    features: ['800M+ passwords', 'k-Anonymity', 'No logging'],
    method: 'SHA-1 hash prefix (first 5 chars)',
    privacy: 'Very High - Only sends first 5 chars of hash'
  },
  dehashed: {
    name: 'DeHashed',
    url: 'https://dehashed.com/',
    features: ['Real-time breach monitoring', 'Email search', 'Username search'],
    cost: 'Paid'
  },
  leakcheck: {
    name: 'LeakCheck',
    url: 'https://leakcheck.io/',
    features: ['Public and private databases', 'API access'],
    cost: 'Free/Paid'
  }
};

const PASSWORD_STRENGTH = {
  veryWeak: {
    name: 'Very Weak',
    color: '\x1b[31m',
    criteria: 'Less than 8 characters or common patterns'
  },
  weak: {
    name: 'Weak',
    color: '\x1b[33m',
    criteria: '8+ chars but simple (only lowercase or only numbers)'
  },
  medium: {
    name: 'Medium',
    color: '\x1b[33m',
    criteria: '8+ chars with some complexity'
  },
  strong: {
    name: 'Strong',
    color: '\x1b[32m',
    criteria: '12+ chars with mixed case, numbers, symbols'
  },
  veryStrong: {
    name: 'Very Strong',
    color: '\x1b[32m',
    criteria: '16+ chars with high complexity'
  }
};

const COMMON_PASSWORDS = [
  'password', '123456', '12345678', 'qwerty', 'abc123', 'monkey',
  'letmein', 'trustno1', 'dragon', 'baseball', 'iloveyou', 'master',
  'sunshine', 'ashley', 'bailey', 'shadow', 'superman', 'qwertyuiop',
  'admin', 'welcome', 'login', 'password1', 'Password1', 'Password123'
];

function showBanner() {
  console.log("\x1b[31m");
  console.log("██████╗  █████╗ ███████╗███████╗██╗    ██╗ ██████╗ ██████╗ ██████╗ ");
  console.log("██╔══██╗██╔══██╗██╔════╝██╔════╝██║    ██║██╔═══██╗██╔══██╗██╔══██╗");
  console.log("██████╔╝███████║███████╗███████╗██║ █╗ ██║██║   ██║██████╔╝██║  ██║");
  console.log("██╔═══╝ ██╔══██║╚════██║╚════██║██║███╗██║██║   ██║██╔══██╗██║  ██║");
  console.log("██║     ██║  ██║███████║███████║╚███╔███╔╝╚██████╔╝██║  ██║██████╔╝");
  console.log("╚═╝     ╚═╝  ╚═╝╚══════╝╚══════╝ ╚══╝╚══╝  ╚═════╝ ╚═╝  ╚═╝╚═════╝ ");
  console.log("                                                                     ");
  console.log(" ██████╗██╗  ██╗███████╗ ██████╗██╗  ██╗███████╗██████╗            ");
  console.log("██╔════╝██║  ██║██╔════╝██╔════╝██║ ██╔╝██╔════╝██╔══██╗           ");
  console.log("██║     ███████║█████╗  ██║     █████╔╝ █████╗  ██████╔╝           ");
  console.log("██║     ██╔══██║██╔══╝  ██║     ██╔═██╗ ██╔══╝  ██╔══██╗           ");
  console.log("╚██████╗██║  ██║███████╗╚██████╗██║  ██╗███████╗██║  ██║           ");
  console.log(" ╚═════╝╚═╝  ╚═╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝           ");
  console.log("\x1b[0m");
  console.log("\x1b[35m🥝 NIKA Password Checker - Leak Detection & Strength Analysis\x1b[0m");
  console.log("\x1b[33m⚠️  Uses k-Anonymity - Your password is NEVER sent fully\x1b[0m\n");
}

function hashPassword(password) {
  return crypto.createHash('sha1').update(password).digest('hex').toUpperCase();
}

async function checkPwnedPasswords(password) {
  console.log('   [1/4] Checking against Pwned Passwords database...');
  
  return new Promise((resolve) => {
    const hash = hashPassword(password);
    const prefix = hash.substring(0, 5);
    const suffix = hash.substring(5);
    
    const url = `https://api.pwnedpasswords.com/range/${prefix}`;
    
    https.get(url, {
      headers: {
        'User-Agent': 'NIKA-OSINT-PasswordChecker',
        'Add-Padding': 'true'
      }
    }, (res) => {
      let data = '';
      
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        const lines = data.split('\n');
        
        for (let line of lines) {
          const [hashSuffix, count] = line.split(':');
          if (hashSuffix.trim() === suffix) {
            resolve({
              pwned: true,
              count: parseInt(count.trim()),
              hash: hash,
              prefix: prefix
            });
            return;
          }
        }
        
        resolve({
          pwned: false,
          count: 0,
          hash: hash,
          prefix: prefix
        });
      });
    }).on('error', () => {
      resolve({
        error: 'API request failed',
        pwned: null
      });
    });
    
    setTimeout(() => {
      resolve({
        error: 'Timeout',
        pwned: null
      });
    }, 10000);
  });
}

function analyzeStrength(password) {
  console.log('   [2/4] Analyzing password strength...');
  
  const analysis = {
    length: password.length,
    hasLowercase: /[a-z]/.test(password),
    hasUppercase: /[A-Z]/.test(password),
    hasNumbers: /[0-9]/.test(password),
    hasSymbols: /[^a-zA-Z0-9]/.test(password),
    hasCommonPattern: false,
    isCommon: COMMON_PASSWORDS.includes(password.toLowerCase()),
    entropy: calculateEntropy(password),
    score: 0,
    level: null,
    suggestions: []
  };
  
  // Check common patterns
  const patterns = [
    /^[a-z]+$/,           // Only lowercase
    /^[A-Z]+$/,           // Only uppercase
    /^[0-9]+$/,           // Only numbers
    /^[a-zA-Z]+$/,        // Only letters
    /^(.)\1+$/,           // Repeated characters
    /^(12|abc|qwe)/i,     // Common sequences
    /password|admin|login|welcome/i  // Common words
  ];
  
  for (let pattern of patterns) {
    if (pattern.test(password)) {
      analysis.hasCommonPattern = true;
      break;
    }
  }
  
  // Calculate score
  if (analysis.length >= 8) analysis.score += 1;
  if (analysis.length >= 12) analysis.score += 1;
  if (analysis.length >= 16) analysis.score += 1;
  if (analysis.hasLowercase) analysis.score += 1;
  if (analysis.hasUppercase) analysis.score += 1;
  if (analysis.hasNumbers) analysis.score += 1;
  if (analysis.hasSymbols) analysis.score += 1;
  if (!analysis.hasCommonPattern) analysis.score += 1;
  if (!analysis.isCommon) analysis.score += 1;
  
  // Determine level
  if (analysis.score <= 2 || analysis.isCommon || analysis.length < 8) {
    analysis.level = PASSWORD_STRENGTH.veryWeak;
  } else if (analysis.score <= 4) {
    analysis.level = PASSWORD_STRENGTH.weak;
  } else if (analysis.score <= 6) {
    analysis.level = PASSWORD_STRENGTH.medium;
  } else if (analysis.score <= 8) {
    analysis.level = PASSWORD_STRENGTH.strong;
  } else {
    analysis.level = PASSWORD_STRENGTH.veryStrong;
  }
  
  // Generate suggestions
  if (analysis.length < 12) {
    analysis.suggestions.push('Use at least 12 characters');
  }
  if (!analysis.hasUppercase) {
    analysis.suggestions.push('Add uppercase letters');
  }
  if (!analysis.hasLowercase) {
    analysis.suggestions.push('Add lowercase letters');
  }
  if (!analysis.hasNumbers) {
    analysis.suggestions.push('Add numbers');
  }
  if (!analysis.hasSymbols) {
    analysis.suggestions.push('Add symbols (!@#$%^&*)');
  }
  if (analysis.hasCommonPattern) {
    analysis.suggestions.push('Avoid common patterns (abc, 123, qwerty)');
  }
  if (analysis.isCommon) {
    analysis.suggestions.push('This is a very common password - choose unique');
  }
  
  return analysis;
}

function calculateEntropy(password) {
  const charsetSize = getCharsetSize(password);
  const entropy = password.length * Math.log2(charsetSize);
  return entropy.toFixed(2);
}

function getCharsetSize(password) {
  let size = 0;
  if (/[a-z]/.test(password)) size += 26;
  if (/[A-Z]/.test(password)) size += 26;
  if (/[0-9]/.test(password)) size += 10;
  if (/[^a-zA-Z0-9]/.test(password)) size += 32;
  return size;
}

function estimateCrackTime(password) {
  console.log('   [3/4] Estimating crack time...');
  
  const charsetSize = getCharsetSize(password);
  const combinations = Math.pow(charsetSize, password.length);
  
  // Assume 10 billion guesses per second (modern GPU)
  const guessesPerSecond = 10000000000;
  const secondsToCrack = combinations / guessesPerSecond;
  
  return {
    combinations: combinations.toExponential(2),
    guessesPerSecond: guessesPerSecond.toLocaleString(),
    seconds: secondsToCrack,
    readable: formatTime(secondsToCrack)
  };
}

function formatTime(seconds) {
  if (seconds < 1) return 'Instant';
  if (seconds < 60) return `${seconds.toFixed(2)} seconds`;
  if (seconds < 3600) return `${(seconds / 60).toFixed(2)} minutes`;
  if (seconds < 86400) return `${(seconds / 3600).toFixed(2)} hours`;
  if (seconds < 31536000) return `${(seconds / 86400).toFixed(2)} days`;
  if (seconds < 3153600000) return `${(seconds / 31536000).toFixed(2)} years`;
  return `${(seconds / 31536000).toExponential(2)} years`;
}

function checkCommonLeaks(password) {
  console.log('   [4/4] Checking common breach patterns...');
  
  const leakPatterns = {
    rockyou: COMMON_PASSWORDS.includes(password.toLowerCase()),
    sequential: /^(12|23|34|45|56|67|78|89|90|abc|bcd|cde)/i.test(password),
    keyboard: /^(qwerty|asdfgh|zxcvbn|qazwsx)/i.test(password),
    repeated: /^(.)\1+$/.test(password),
    year: /19\d{2}|20\d{2}/.test(password),
    common_words: /(password|admin|login|welcome|letmein|monkey|dragon)/i.test(password)
  };
  
  const found = [];
  
  if (leakPatterns.rockyou) found.push('RockYou breach (2009) - 32M passwords');
  if (leakPatterns.sequential) found.push('Sequential pattern');
  if (leakPatterns.keyboard) found.push('Keyboard pattern');
  if (leakPatterns.repeated) found.push('Repeated characters');
  if (leakPatterns.year) found.push('Contains year');
  if (leakPatterns.common_words) found.push('Common words');
  
  return {
    patterns: leakPatterns,
    found: found
  };
}

function displayResults(data) {
  console.log("\n╔════════════════════════════════════════════════════════╗");
  console.log("║       🔐 PASSWORD ANALYSIS REPORT 🔐                   ║");
  console.log("╚════════════════════════════════════════════════════════╝\n");
  
  // Pwned Status
  console.log("\x1b[36m┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓\x1b[0m");
  console.log("\x1b[36m┃                  BREACH STATUS                       ┃\x1b[0m");
  console.log("\x1b[36m┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛\x1b[0m\n");
  
  if (data.pwned.error) {
    console.log(`   ⚠️  Could not check: ${data.pwned.error}\n`);
  } else if (data.pwned.pwned) {
    console.log(`   ❌ \x1b[31mPWNED - Found in breaches!\x1b[0m`);
    console.log(`   Times seen:          \x1b[31m${data.pwned.count.toLocaleString()}\x1b[0m`);
    console.log(`   SHA-1 (first 5):     ${data.pwned.prefix}`);
    console.log(`   \x1b[31m⚠️  This password has been exposed in data breaches!\x1b[0m\n`);
  } else {
    console.log(`   ✅ \x1b[32mNOT FOUND in breach databases\x1b[0m`);
    console.log(`   Times seen:          0`);
    console.log(`   SHA-1 (first 5):     ${data.pwned.prefix}`);
    console.log(`   \x1b[32m✓ This password hasn't been seen in known breaches\x1b[0m\n`);
  }
  
  // Strength Analysis
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
  console.log("\x1b[36m💪 PASSWORD STRENGTH\x1b[0m");
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
  
  console.log(`   Level:               ${data.strength.level.color}${data.strength.level.name}\x1b[0m`);
  console.log(`   Score:               ${data.strength.score}/9`);
  console.log(`   Length:              ${data.strength.length} characters`);
  console.log(`   Entropy:             ${data.strength.entropy} bits`);
  console.log(`   Lowercase:           ${data.strength.hasLowercase ? '✓' : '✗'}`);
  console.log(`   Uppercase:           ${data.strength.hasUppercase ? '✓' : '✗'}`);
  console.log(`   Numbers:             ${data.strength.hasNumbers ? '✓' : '✗'}`);
  console.log(`   Symbols:             ${data.strength.hasSymbols ? '✓' : '✗'}`);
  console.log(`   Common pattern:      ${data.strength.hasCommonPattern ? '\x1b[31m✗ Yes\x1b[0m' : '✓ No'}`);
  console.log(`   In common list:      ${data.strength.isCommon ? '\x1b[31m✗ Yes\x1b[0m' : '✓ No'}\n`);
  
  if (data.strength.suggestions.length > 0) {
    console.log('   \x1b[33mSuggestions to improve:\x1b[0m');
    data.strength.suggestions.forEach(s => {
      console.log(`      • ${s}`);
    });
    console.log('');
  }
  
  // Crack Time
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
  console.log("\x1b[36m⏱️  CRACK TIME ESTIMATE\x1b[0m");
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
  
  console.log(`   Possible combinations:   ${data.crackTime.combinations}`);
  console.log(`   Guesses/second (GPU):    ${data.crackTime.guessesPerSecond}`);
  console.log(`   Time to crack:           ${data.crackTime.readable}\n`);
  
  // Common Patterns
  if (data.commonLeaks.found.length > 0) {
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
    console.log("\x1b[36m⚠️  COMMON PATTERNS DETECTED\x1b[0m");
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
    
    data.commonLeaks.found.forEach(pattern => {
      console.log(`   ⚠️  ${pattern}`);
    });
    console.log('');
  }
  
  // Breach Databases
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
  console.log("\x1b[36m🗄️  BREACH DATABASES\x1b[0m");
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
  
  Object.entries(BREACH_DATABASES).forEach(([key, db]) => {
    console.log(`   \x1b[32m${db.name}\x1b[0m ${db.cost ? `(${db.cost})` : ''}`);
    console.log(`      URL: ${db.url}`);
    if (db.features) console.log(`      Features: ${db.features.join(', ')}`);
    if (db.privacy) console.log(`      Privacy: ${db.privacy}`);
    console.log('');
  });
  
  // Recommendations
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
  console.log("\x1b[36m💡 SECURITY RECOMMENDATIONS\x1b[0m");
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
  
  console.log('   \x1b[32m✓ Use a password manager (Bitwarden, 1Password, KeePass)\x1b[0m');
  console.log('   \x1b[32m✓ Enable 2FA/MFA on all accounts\x1b[0m');
  console.log('   \x1b[32m✓ Use unique passwords for each site\x1b[0m');
  console.log('   \x1b[32m✓ Minimum 16 characters with high complexity\x1b[0m');
  console.log('   \x1b[32m✓ Use passphrases (4+ random words)\x1b[0m');
  console.log('   \x1b[32m✓ Change passwords if found in breaches\x1b[0m');
  console.log('   \x1b[32m✓ Never reuse passwords across sites\x1b[0m\n');
}

function saveReport(data) {
  const dir = './password-check-reports';
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, -5);
  const filename = `${dir}/password-check-${timestamp}.txt`;
  
  let content = `═══════════════════════════════════════════════════════════
PASSWORD SECURITY REPORT
═══════════════════════════════════════════════════════════

Date: ${new Date().toLocaleString()}

BREACH STATUS:
Pwned: ${data.pwned.pwned ? 'YES' : 'NO'}
Times seen: ${data.pwned.count || 0}
SHA-1 prefix: ${data.pwned.prefix || 'N/A'}

PASSWORD STRENGTH:
Level: ${data.strength.level.name}
Score: ${data.strength.score}/9
Length: ${data.strength.length}
Entropy: ${data.strength.entropy} bits

FEATURES:
Lowercase: ${data.strength.hasLowercase}
Uppercase: ${data.strength.hasUppercase}
Numbers: ${data.strength.hasNumbers}
Symbols: ${data.strength.hasSymbols}
Common pattern: ${data.strength.hasCommonPattern}
In common list: ${data.strength.isCommon}

CRACK TIME ESTIMATE:
Combinations: ${data.crackTime.combinations}
Time to crack: ${data.crackTime.readable}

SUGGESTIONS:
${data.strength.suggestions.join('\n')}

COMMON PATTERNS DETECTED:
${data.commonLeaks.found.join('\n')}
`;

  fs.writeFileSync(filename, content);
  console.log(`\x1b[32m✅ Report saved: ${filename}\x1b[0m\n`);
}

function showHelp() {
  showBanner();
  
  console.log("Usage: node password-checker.js \"<password>\" [--save]\n");
  console.log("Options:");
  console.log("  --save               Save report to file");
  console.log("  --help               Show this help\n");
  
  console.log("Privacy:");
  console.log("  • Uses k-Anonymity model");
  console.log("  • Only first 5 chars of SHA-1 hash sent to API");
  console.log("  • Your full password is NEVER transmitted\n");
  
  console.log("Examples:");
  console.log("  node password-checker.js \"MyP@ssw0rd123\"");
  console.log("  node password-checker.js \"correct-horse-battery-staple\" --save\n");
}

async function main() {
  const args = process.argv.slice(2);
  
  if (args.length === 0 || args.includes('--help')) {
    showHelp();
    process.exit(0);
  }
  
  showBanner();
  
  let password = null;
  let saveFlag = false;
  
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--save') {
      saveFlag = true;
    } else if (!args[i].startsWith('--')) {
      password = args[i];
    }
  }
  
  if (!password) {
    console.log("\x1b[31m❌ No password specified!\x1b[0m\n");
    showHelp();
    process.exit(1);
  }
  
  console.log(`⏳ Analyzing password (${password.length} chars)...\n`);
  
  const results = {
    timestamp: new Date().toISOString(),
    pwned: await checkPwnedPasswords(password),
    strength: analyzeStrength(password),
    crackTime: estimateCrackTime(password),
    commonLeaks: checkCommonLeaks(password)
  };
  
  displayResults(results);
  
  if (saveFlag) {
    saveReport(results);
  }
  
  console.log("\x1b[31m██████╗  █████╗ ███████╗███████╗\x1b[0m");
  console.log("\x1b[35m🥝 Analysis complete - by kiwi & 777\x1b[0m\n");
}

main();
