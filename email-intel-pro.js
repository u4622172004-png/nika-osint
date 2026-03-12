#!/usr/bin/env node

const https = require('https');
const dns = require('dns').promises;
const fs = require('fs');
const { exec } = require('child_process');
const { promisify } = require('util');
const execAsync = promisify(exec);

// ============================================
// EMAIL INTELLIGENCE PRO - Advanced Email OSINT
// ============================================

const BREACH_DATABASES = {
  hibp: {
    name: 'Have I Been Pwned',
    url: 'https://haveibeenpwned.com/',
    api: 'https://haveibeenpwned.com/api/v3/breachedaccount/',
    features: ['Breach check', 'Paste check', '12+ billion accounts'],
    cost: 'Free (API key recommended)',
    rateLimit: '1 request per 1.5 seconds'
  },
  dehashed: {
    name: 'DeHashed',
    url: 'https://dehashed.com/',
    search: 'https://dehashed.com/search?query=',
    features: ['Email/username/password search', '18+ billion records'],
    cost: 'Paid'
  },
  leakcheck: {
    name: 'LeakCheck',
    url: 'https://leakcheck.io/',
    search: 'https://leakcheck.io/search/',
    features: ['Public/private databases', 'Real-time monitoring'],
    cost: 'Free/Paid'
  },
  intelx: {
    name: 'Intelligence X',
    url: 'https://intelx.io/',
    search: 'https://intelx.io/?s=',
    features: ['Darknet search', 'Pastes', 'Historical data'],
    cost: 'Free/Paid'
  }
};

const EMAIL_VERIFIERS = {
  hunter: {
    name: 'Hunter.io',
    url: 'https://hunter.io/email-verifier',
    features: ['SMTP check', 'Disposable detection', 'Free tier'],
    api: true
  },
  neverbounce: {
    name: 'NeverBounce',
    url: 'https://neverbounce.com/',
    features: ['Real-time verification', 'Bulk verification'],
    api: true
  },
  zerobounce: {
    name: 'ZeroBounce',
    url: 'https://www.zerobounce.net/',
    features: ['Email validation', 'Spam trap detection'],
    api: true
  },
  emailrep: {
    name: 'EmailRep.io',
    url: 'https://emailrep.io/',
    api: 'https://emailrep.io/',
    features: ['Reputation scoring', 'Free API'],
    cost: 'Free'
  }
};

const DISPOSABLE_PROVIDERS = [
  'tempmail.com', 'guerrillamail.com', '10minutemail.com', 'mailinator.com',
  'throwaway.email', 'temp-mail.org', 'getnada.com', 'maildrop.cc',
  'yopmail.com', 'fakeinbox.com', 'trashmail.com', 'emailondeck.com'
];

const SOCIAL_PLATFORMS = {
  gravatar: {
    name: 'Gravatar',
    url: 'https://en.gravatar.com/',
    check: email => `https://www.gravatar.com/avatar/${require('crypto').createHash('md5').update(email.toLowerCase().trim()).digest('hex')}?d=404`,
    features: ['Profile photo', 'Public profiles']
  },
  github: {
    name: 'GitHub',
    search: email => `https://github.com/search?q=${encodeURIComponent(email)}&type=users`,
    features: ['Developer profiles', 'Repositories']
  },
  google: {
    name: 'Google',
    search: email => `https://www.google.com/search?q="${encodeURIComponent(email)}"`,
    features: ['Web mentions', 'Social profiles']
  }
};

function showBanner() {
  console.log("\x1b[31m");
  console.log("███████╗███╗   ███╗ █████╗ ██╗██╗         ██╗███╗   ██╗████████╗███████╗██╗     ");
  console.log("██╔════╝████╗ ████║██╔══██╗██║██║         ██║████╗  ██║╚══██╔══╝██╔════╝██║     ");
  console.log("█████╗  ██╔████╔██║███████║██║██║         ██║██╔██╗ ██║   ██║   █████╗  ██║     ");
  console.log("██╔══╝  ██║╚██╔╝██║██╔══██║██║██║         ██║██║╚██╗██║   ██║   ██╔══╝  ██║     ");
  console.log("███████╗██║ ╚═╝ ██║██║  ██║██║███████╗    ██║██║ ╚████║   ██║   ███████╗███████╗");
  console.log("╚══════╝╚═╝     ╚═╝╚═╝  ╚═╝╚═╝╚══════╝    ╚═╝╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚══════╝");
  console.log("                                                                                  ");
  console.log("██████╗ ██████╗  ██████╗                                                         ");
  console.log("██╔══██╗██╔══██╗██╔═══██╗                                                        ");
  console.log("██████╔╝██████╔╝██║   ██║                                                        ");
  console.log("██╔═══╝ ██╔══██╗██║   ██║                                                        ");
  console.log("██║     ██║  ██║╚██████╔╝                                                        ");
  console.log("╚═╝     ╚═╝  ╚═╝ ╚═════╝                                                         ");
  console.log("\x1b[0m");
  console.log("\x1b[35m🥝 NIKA Email Intelligence Pro - Advanced Email OSINT\x1b[0m");
  console.log("\x1b[33m⚠️  For authorized investigation only\x1b[0m\n");
}

function validateEmail(email) {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  
  if (!emailRegex.test(email)) {
    return {
      valid: false,
      error: 'Invalid email format'
    };
  }
  
  const [localPart, domain] = email.split('@');
  
  return {
    valid: true,
    email: email.toLowerCase(),
    localPart: localPart,
    domain: domain,
    tld: domain.split('.').pop()
  };
}

function analyzeEmail(email) {
  console.log('   [1/8] Analyzing email structure...');
  
  const validation = validateEmail(email);
  if (!validation.valid) {
    return { error: validation.error };
  }
  
  const { localPart, domain, tld } = validation;
  
  const analysis = {
    email: validation.email,
    localPart: localPart,
    domain: domain,
    tld: tld,
    length: email.length,
    hasNumbers: /\d/.test(localPart),
    hasDots: localPart.includes('.'),
    hasPlus: localPart.includes('+'),
    hasUnderscore: localPart.includes('_'),
    pattern: identifyPattern(localPart),
    isDisposable: isDisposableEmail(domain),
    isFreeProvider: isFreeProvider(domain)
  };
  
  return analysis;
}

function identifyPattern(localPart) {
  if (/^[a-z]+\.[a-z]+\d*$/i.test(localPart)) return 'firstname.lastname';
  if (/^[a-z]\.[a-z]+$/i.test(localPart)) return 'f.lastname';
  if (/^[a-z]+\d+$/i.test(localPart)) return 'name+numbers';
  if (/^[a-z]+_[a-z]+$/i.test(localPart)) return 'name_name';
  if (/\+/.test(localPart)) return 'plus addressing';
  if (/^info|contact|admin|support$/i.test(localPart)) return 'generic/business';
  return 'custom';
}

function isDisposableEmail(domain) {
  return DISPOSABLE_PROVIDERS.some(provider => 
    domain.toLowerCase().includes(provider.toLowerCase())
  );
}

function isFreeProvider(domain) {
  const freeProviders = [
    'gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com',
    'aol.com', 'icloud.com', 'protonmail.com', 'mail.com'
  ];
  
  return freeProviders.includes(domain.toLowerCase());
}

async function checkDNS(domain) {
  console.log('   [2/8] Checking DNS records...');
  
  const results = {
    mx: [],
    txt: [],
    spf: null,
    dmarc: null,
    dkim: null,
    hasRecords: false
  };
  
  try {
    // MX Records
    const mx = await dns.resolveMx(domain);
    results.mx = mx.map(r => ({ priority: r.priority, exchange: r.exchange }));
    results.hasRecords = true;
  } catch (e) {
    results.mx = [];
  }
  
  try {
    // TXT Records
    const txt = await dns.resolveTxt(domain);
    results.txt = txt.map(r => r.join(''));
    
    // Check for SPF
    const spf = results.txt.find(r => r.startsWith('v=spf1'));
    if (spf) results.spf = spf;
  } catch (e) {
    results.txt = [];
  }
  
  try {
    // DMARC
    const dmarc = await dns.resolveTxt('_dmarc.' + domain);
    results.dmarc = dmarc.map(r => r.join('')).join('');
  } catch (e) {
    results.dmarc = null;
  }
  
  return results;
}

async function checkSMTP(email, domain) {
  console.log('   [3/8] Simulating SMTP verification...');
  
  // Note: Real SMTP check requires socket connection
  // This is a simplified simulation
  
  return {
    simulated: true,
    note: 'Use Hunter.io, NeverBounce, or ZeroBounce for real SMTP verification',
    recommendation: 'Check MX records availability as proxy indicator',
    hasMX: true // Would be determined from DNS check
  };
}

async function checkHIBP(email) {
  console.log('   [4/8] Checking breach databases...');
  
  return new Promise((resolve) => {
    // Note: Requires HIBP API key for production use
    // This shows the structure of how to call it
    
    const options = {
      hostname: 'haveibeenpwned.com',
      path: `/api/v3/breachedaccount/${encodeURIComponent(email)}`,
      method: 'GET',
      headers: {
        'User-Agent': 'NIKA-OSINT-Email-Intel',
        'hibp-api-key': process.env.HIBP_API_KEY || 'DEMO_MODE'
      }
    };
    
    if (!process.env.HIBP_API_KEY) {
      resolve({
        available: false,
        note: 'Set HIBP_API_KEY environment variable for breach checking',
        manualCheck: `https://haveibeenpwned.com/account/${encodeURIComponent(email)}`
      });
      return;
    }
    
    const req = https.request(options, (res) => {
      let data = '';
      
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        if (res.statusCode === 404) {
          resolve({
            available: true,
            breached: false,
            count: 0
          });
        } else if (res.statusCode === 200) {
          try {
            const breaches = JSON.parse(data);
            resolve({
              available: true,
              breached: true,
              count: breaches.length,
              breaches: breaches.map(b => ({
                name: b.Name,
                date: b.BreachDate,
                dataClasses: b.DataClasses
              }))
            });
          } catch (e) {
            resolve({ available: false, error: 'Parse error' });
          }
        } else {
          resolve({ available: false, error: `HTTP ${res.statusCode}` });
        }
      });
    });
    
    req.on('error', () => {
      resolve({ available: false, error: 'Request failed' });
    });
    
    req.end();
    
    setTimeout(() => {
      resolve({ available: false, error: 'Timeout' });
    }, 10000);
  });
}

function checkGravatar(email) {
  console.log('   [5/8] Checking Gravatar...');
  
  const crypto = require('crypto');
  const hash = crypto.createHash('md5').update(email.toLowerCase().trim()).digest('hex');
  
  return {
    url: `https://www.gravatar.com/avatar/${hash}`,
    checkUrl: `https://www.gravatar.com/avatar/${hash}?d=404`,
    profileUrl: `https://en.gravatar.com/${hash}`,
    note: 'Check if image loads to verify Gravatar exists'
  };
}

function generateSearchLinks(email) {
  console.log('   [6/8] Generating search links...');
  
  const encoded = encodeURIComponent(email);
  
  return {
    google: `https://www.google.com/search?q="${encoded}"`,
    bing: `https://www.bing.com/search?q="${encoded}"`,
    github: `https://github.com/search?q=${encoded}&type=users`,
    linkedin: `https://www.linkedin.com/search/results/people/?keywords=${encoded}`,
    twitter: `https://twitter.com/search?q=${encoded}`,
    facebook: `https://www.facebook.com/search/top?q=${encoded}`,
    dehashed: `https://dehashed.com/search?query=${encoded}`,
    leakcheck: `https://leakcheck.io/search/${encoded}`,
    intelx: `https://intelx.io/?s=${encoded}`,
    hibp: `https://haveibeenpwned.com/account/${encoded}`
  };
}

function analyzeReputation(data) {
  console.log('   [7/8] Analyzing reputation...');
  
  const score = {
    total: 0,
    factors: []
  };
  
  // Positive factors
  if (!data.analysis.isDisposable) {
    score.total += 20;
    score.factors.push('+20: Not disposable');
  } else {
    score.total -= 30;
    score.factors.push('-30: Disposable email');
  }
  
  if (data.dns.hasRecords && data.dns.mx.length > 0) {
    score.total += 15;
    score.factors.push('+15: Valid MX records');
  }
  
  if (data.dns.spf) {
    score.total += 10;
    score.factors.push('+10: SPF configured');
  }
  
  if (data.dns.dmarc) {
    score.total += 10;
    score.factors.push('+10: DMARC configured');
  }
  
  if (!data.analysis.isFreeProvider) {
    score.total += 15;
    score.factors.push('+15: Custom domain');
  }
  
  if (data.analysis.pattern === 'firstname.lastname') {
    score.total += 10;
    score.factors.push('+10: Professional format');
  }
  
  if (data.hibp.breached) {
    score.total -= 25;
    score.factors.push(`-25: Found in ${data.hibp.count} breaches`);
  }
  
  // Determine rating
  let rating;
  if (score.total >= 70) rating = 'Excellent';
  else if (score.total >= 50) rating = 'Good';
  else if (score.total >= 30) rating = 'Fair';
  else if (score.total >= 10) rating = 'Poor';
  else rating = 'Very Poor';
  
  return {
    score: Math.max(0, Math.min(100, score.total)),
    rating: rating,
    factors: score.factors
  };
}

function generateRecommendations(data) {
  console.log('   [8/8] Generating recommendations...');
  
  const recommendations = [];
  
  if (data.analysis.isDisposable) {
    recommendations.push('⚠️  Disposable email - High risk of spam/fraud');
  }
  
  if (!data.dns.hasRecords || data.dns.mx.length === 0) {
    recommendations.push('⚠️  No MX records - Domain may not receive email');
  }
  
  if (!data.dns.spf) {
    recommendations.push('💡 Domain lacks SPF record - May be spoofable');
  }
  
  if (!data.dns.dmarc) {
    recommendations.push('💡 Domain lacks DMARC - Less email security');
  }
  
  if (data.hibp.breached) {
    recommendations.push(`🚨 Email found in ${data.hibp.count} data breaches - Compromised`);
  }
  
  if (data.analysis.hasPlus) {
    recommendations.push('💡 Uses plus addressing - May be alias/filter');
  }
  
  if (data.analysis.pattern === 'generic/business') {
    recommendations.push('💡 Generic email - Likely shared/departmental');
  }
  
  if (recommendations.length === 0) {
    recommendations.push('✅ Email appears legitimate with good configuration');
  }
  
  return recommendations;
}

function displayResults(data) {
  console.log("\n╔════════════════════════════════════════════════════════╗");
  console.log("║       📧 EMAIL INTELLIGENCE REPORT 📧                  ║");
  console.log("╚════════════════════════════════════════════════════════╝\n");
  
  console.log(`📧 Email: \x1b[36m${data.analysis.email}\x1b[0m\n`);
  
  // Analysis
  console.log("\x1b[36m┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓\x1b[0m");
  console.log("\x1b[36m┃                  EMAIL ANALYSIS                      ┃\x1b[0m");
  console.log("\x1b[36m┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛\x1b[0m\n");
  
  console.log(`   Local Part:          ${data.analysis.localPart}`);
  console.log(`   Domain:              ${data.analysis.domain}`);
  console.log(`   TLD:                 ${data.analysis.tld}`);
  console.log(`   Pattern:             ${data.analysis.pattern}`);
  console.log(`   Free Provider:       ${data.analysis.isFreeProvider ? 'Yes' : 'No'}`);
  console.log(`   Disposable:          ${data.analysis.isDisposable ? '\x1b[31mYes\x1b[0m' : '\x1b[32mNo\x1b[0m'}`);
  console.log(`   Plus Addressing:     ${data.analysis.hasPlus ? 'Yes' : 'No'}\n`);
  
  // DNS
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
  console.log("\x1b[36m🌐 DNS RECORDS\x1b[0m");
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
  
  if (data.dns.mx.length > 0) {
    console.log(`   MX Records:          ${data.dns.mx.length} found`);
    data.dns.mx.forEach(mx => {
      console.log(`      ${mx.priority.toString().padStart(2)} - ${mx.exchange}`);
    });
  } else {
    console.log(`   MX Records:          \x1b[31mNone found\x1b[0m`);
  }
  console.log('');
  
  console.log(`   SPF Record:          ${data.dns.spf ? '\x1b[32mConfigured\x1b[0m' : '\x1b[33mNot found\x1b[0m'}`);
  if (data.dns.spf) console.log(`      ${data.dns.spf.substring(0, 60)}...`);
  console.log('');
  
  console.log(`   DMARC Record:        ${data.dns.dmarc ? '\x1b[32mConfigured\x1b[0m' : '\x1b[33mNot found\x1b[0m'}`);
  if (data.dns.dmarc) console.log(`      ${data.dns.dmarc.substring(0, 60)}...`);
  console.log('');
  
  // SMTP
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
  console.log("\x1b[36m📬 SMTP VERIFICATION\x1b[0m");
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
  
  console.log(`   Status:              ${data.smtp.simulated ? 'Simulated' : 'Live'}`);
  console.log(`   Note:                ${data.smtp.note}\n`);
  
  // Breach Check
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
  console.log("\x1b[36m🚨 DATA BREACH CHECK\x1b[0m");
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
  
  if (data.hibp.available) {
    if (data.hibp.breached) {
      console.log(`   Status:              \x1b[31m⚠️  BREACHED\x1b[0m`);
      console.log(`   Breaches Found:      ${data.hibp.count}`);
      console.log('\n   Recent Breaches:');
      data.hibp.breaches.slice(0, 5).forEach(b => {
        console.log(`      • ${b.name} (${b.date})`);
        console.log(`        Data: ${b.dataClasses.join(', ')}`);
      });
    } else {
      console.log(`   Status:              \x1b[32m✓ Clean\x1b[0m`);
      console.log(`   Breaches Found:      0`);
    }
  } else {
    console.log(`   Status:              Manual check required`);
    console.log(`   Check at:            ${data.hibp.manualCheck}`);
    if (data.hibp.note) console.log(`   Note:                ${data.hibp.note}`);
  }
  console.log('');
  
  // Gravatar
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
  console.log("\x1b[36m🖼️  GRAVATAR\x1b[0m");
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
  
  console.log(`   Check URL:           ${data.gravatar.checkUrl}`);
  console.log(`   Profile URL:         ${data.gravatar.profileUrl}\n`);
  
  // Reputation
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
  console.log("\x1b[36m⭐ REPUTATION SCORE\x1b[0m");
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
  
  const scoreColor = data.reputation.score >= 70 ? '\x1b[32m' : 
                     data.reputation.score >= 50 ? '\x1b[33m' : '\x1b[31m';
  
  console.log(`   Score:               ${scoreColor}${data.reputation.score}/100 (${data.reputation.rating})\x1b[0m\n`);
  console.log('   Factors:');
  data.reputation.factors.forEach(factor => {
    console.log(`      ${factor}`);
  });
  console.log('');
  
  // Recommendations
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
  console.log("\x1b[36m💡 RECOMMENDATIONS\x1b[0m");
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
  
  data.recommendations.forEach(rec => {
    console.log(`   ${rec}`);
  });
  console.log('');
  
  // Search Links
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
  console.log("\x1b[36m🔗 SEARCH LINKS\x1b[0m");
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
  
  console.log(`   Google:              ${data.searchLinks.google}`);
  console.log(`   GitHub:              ${data.searchLinks.github}`);
  console.log(`   LinkedIn:            ${data.searchLinks.linkedin}`);
  console.log(`   HIBP:                ${data.searchLinks.hibp}`);
  console.log(`   DeHashed:            ${data.searchLinks.dehashed}`);
  console.log(`   LeakCheck:           ${data.searchLinks.leakcheck}\n`);
  
  // Tools
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
  console.log("\x1b[36m🛠️  VERIFICATION TOOLS\x1b[0m");
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
  
  Object.entries(EMAIL_VERIFIERS).forEach(([key, tool]) => {
    console.log(`   \x1b[32m${tool.name}\x1b[0m`);
    console.log(`      ${tool.url}`);
    console.log(`      Features: ${tool.features.join(', ')}\n`);
  });
}

function saveReport(data) {
  const dir = './email-intel-reports';
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, -5);
  const safeName = data.analysis.email.replace(/[@.]/g, '-');
  const filename = `${dir}/email-${safeName}-${timestamp}.txt`;
  
  let content = `═══════════════════════════════════════════════════════════
EMAIL INTELLIGENCE REPORT
═══════════════════════════════════════════════════════════

Email: ${data.analysis.email}
Date: ${new Date().toLocaleString()}

ANALYSIS:
Domain: ${data.analysis.domain}
Pattern: ${data.analysis.pattern}
Free Provider: ${data.analysis.isFreeProvider}
Disposable: ${data.analysis.isDisposable}

DNS RECORDS:
MX Records: ${data.dns.mx.length}
${data.dns.mx.map(mx => `  ${mx.priority} - ${mx.exchange}`).join('\n')}
SPF: ${data.dns.spf ? 'Configured' : 'Not found'}
DMARC: ${data.dns.dmarc ? 'Configured' : 'Not found'}

BREACH CHECK:
${data.hibp.available ? (data.hibp.breached ? `BREACHED - ${data.hibp.count} breaches found` : 'Clean') : 'Manual check required'}

REPUTATION:
Score: ${data.reputation.score}/100 (${data.reputation.rating})
${data.reputation.factors.join('\n')}

RECOMMENDATIONS:
${data.recommendations.join('\n')}

SEARCH LINKS:
Google: ${data.searchLinks.google}
GitHub: ${data.searchLinks.github}
HIBP: ${data.searchLinks.hibp}
`;

  fs.writeFileSync(filename, content);
  console.log(`\x1b[32m✅ Report saved: ${filename}\x1b[0m\n`);
}

function showHelp() {
  showBanner();
  
  console.log("Usage: node email-intel-pro.js <email> [--save]\n");
  console.log("Options:");
  console.log("  --save               Save report to file");
  console.log("  --help               Show this help\n");
  
  console.log("Environment Variables:");
  console.log("  HIBP_API_KEY         Have I Been Pwned API key (optional)\n");
  
  console.log("Examples:");
  console.log("  node email-intel-pro.js user@example.com");
  console.log("  node email-intel-pro.js john.doe@company.com --save");
  console.log("  HIBP_API_KEY=xxx node email-intel-pro.js test@mail.com\n");
}

async function main() {
  const args = process.argv.slice(2);
  
  if (args.length === 0 || args.includes('--help')) {
    showHelp();
    process.exit(0);
  }
  
  showBanner();
  
  let email = null;
  let saveFlag = false;
  
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--save') {
      saveFlag = true;
    } else if (!args[i].startsWith('--')) {
      email = args[i];
    }
  }
  
  if (!email) {
    console.log("\x1b[31m❌ No email specified!\x1b[0m\n");
    showHelp();
    process.exit(1);
  }
  
  console.log(`⏳ Analyzing email: ${email}...\n`);
  
  const results = {
    timestamp: new Date().toISOString(),
    analysis: analyzeEmail(email),
    dns: null,
    smtp: null,
    hibp: null,
    gravatar: null,
    searchLinks: null,
    reputation: null,
    recommendations: null
  };
  
  if (results.analysis.error) {
    console.log(`\x1b[31m❌ ${results.analysis.error}\x1b[0m\n`);
    process.exit(1);
  }
  
  results.dns = await checkDNS(results.analysis.domain);
  results.smtp = await checkSMTP(email, results.analysis.domain);
  results.hibp = await checkHIBP(email);
  results.gravatar = checkGravatar(email);
  results.searchLinks = generateSearchLinks(email);
  results.reputation = analyzeReputation(results);
  results.recommendations = generateRecommendations(results);
  
  displayResults(results);
  
  if (saveFlag) {
    saveReport(results);
  }
  
  console.log("\x1b[31m███████╗███╗   ███╗ █████╗ ██╗██╗     \x1b[0m");
  console.log("\x1b[35m🥝 Analysis complete - by kiwi & 777\x1b[0m\n");
}

main();
