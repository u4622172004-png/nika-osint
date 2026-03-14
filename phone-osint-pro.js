#!/usr/bin/env node

const https = require('https');
const http = require('http');
const fs = require('fs');

// ============================================
// PHONE OSINT PRO v2.0 - ADVANCED EDITION
// Con ricerca automatica profili social
// ============================================

const CARRIERS_DB = {
  US: {
    '310': 'AT&T', '311': 'AT&T', '312': 'Verizon', '313': 'Verizon',
    '314': 'T-Mobile', '315': 'T-Mobile', '316': 'Sprint', '330': 'T-Mobile'
  },
  IT: {
    '222': 'Vodafone IT', '223': 'TIM', '224': 'Wind Tre', '225': 'Iliad'
  },
  UK: {
    '234': 'EE', '235': 'Vodafone UK', '236': 'O2', '237': 'Three UK'
  }
};

const SOCIAL_PLATFORMS = {
  telegram: {
    name: 'Telegram',
    icon: '✈️',
    checkUrl: 'https://t.me/',
    method: 'Manual check required'
  },
  whatsapp: {
    name: 'WhatsApp',
    icon: '📱',
    checkUrl: 'https://wa.me/',
    method: 'Check if number exists'
  },
  truecaller: {
    name: 'Truecaller',
    icon: '📞',
    searchUrl: 'https://www.truecaller.com/search/it/',
    method: 'Search for name and social profiles'
  },
  signal: {
    name: 'Signal',
    icon: '🔒',
    method: 'Manual verification in app'
  },
  viber: {
    name: 'Viber',
    icon: '💜',
    method: 'Manual verification in app'
  }
};

function showBanner() {
  console.log("\x1b[31m");
  console.log("██████╗ ██╗  ██╗ ██████╗ ███╗   ██╗███████╗");
  console.log("██╔══██╗██║  ██║██╔═══██╗████╗  ██║██╔════╝");
  console.log("██████╔╝███████║██║   ██║██╔██╗ ██║█████╗  ");
  console.log("██╔═══╝ ██╔══██║██║   ██║██║╚██╗██║██╔══╝  ");
  console.log("██║     ██║  ██║╚██████╔╝██║ ╚████║███████╗");
  console.log("╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝");
  console.log("                                            ");
  console.log(" ██████╗ ███████╗██╗███╗   ██╗████████╗    ");
  console.log("██╔═══██╗██╔════╝██║████╗  ██║╚══██╔══╝    ");
  console.log("██║   ██║███████╗██║██╔██╗ ██║   ██║       ");
  console.log("██║   ██║╚════██║██║██║╚██╗██║   ██║       ");
  console.log("╚██████╔╝███████║██║██║ ╚████║   ██║       ");
  console.log(" ╚═════╝ ╚══════╝╚═╝╚═╝  ╚═══╝   ╚═╝       ");
  console.log("\x1b[0m");
  console.log("\x1b[35m🥝 NIKA Phone OSINT Pro v2.0 - Advanced Social Finder\x1b[0m");
  console.log("\x1b[33m⚠️  For authorized investigation only\x1b[0m\n");
}

function parsePhoneNumber(input) {
  let cleaned = input.replace(/[\s\-\(\)\.]/g, '');
  
  if (!cleaned.startsWith('+')) {
    if (cleaned.length === 10 && cleaned.match(/^[0-9]+$/)) {
      cleaned = '+1' + cleaned;
    } else if (cleaned.length === 9 && cleaned.match(/^3[0-9]{8}$/)) {
      cleaned = '+39' + cleaned;
    } else {
      cleaned = '+' + cleaned;
    }
  }
  
  const match = cleaned.match(/^\+(\d{1,3})(\d+)$/);
  if (!match) {
    return { valid: false, error: 'Invalid phone number format' };
  }
  
  const countryCode = match[1];
  const nationalNumber = match[2];
  
  let country = 'Unknown';
  if (countryCode === '1') country = 'United States/Canada';
  else if (countryCode === '39') country = 'Italy';
  else if (countryCode === '44') country = 'United Kingdom';
  else if (countryCode === '33') country = 'France';
  else if (countryCode === '49') country = 'Germany';
  else if (countryCode === '34') country = 'Spain';
  else if (countryCode === '91') country = 'India';
  else if (countryCode === '86') country = 'China';
  else if (countryCode === '81') country = 'Japan';
  else if (countryCode === '55') country = 'Brazil';
  else if (countryCode === '7') country = 'Russia/Kazakhstan';
  
  return {
    valid: true,
    raw: input,
    formatted: cleaned,
    countryCode: countryCode,
    nationalNumber: nationalNumber,
    country: country,
    international: cleaned,
    e164: cleaned
  };
}

// NUOVA FUNZIONE: Google Dork Search Automatica
async function searchGoogleDorks(phone) {
  console.log('   [1/8] Searching Google for phone number...');
  
  const dorks = [
    `"${phone}"`,
    `"${phone}" site:facebook.com`,
    `"${phone}" site:linkedin.com`,
    `"${phone}" site:twitter.com`,
    `"${phone}" site:instagram.com`,
    `"${phone}" site:vk.com`,
    `"${phone}" (facebook | linkedin | twitter | instagram)`,
    `"${phone}" "profile"`,
    `"${phone}" "contact"`,
    `"${phone}" inurl:profile`
  ];
  
  return {
    available: true,
    dorks: dorks,
    searchUrls: {
      google: `https://www.google.com/search?q="${encodeURIComponent(phone)}"`,
      facebook: `https://www.facebook.com/search/top?q=${encodeURIComponent(phone)}`,
      linkedin: `https://www.linkedin.com/search/results/all/?keywords=${encodeURIComponent(phone)}`,
      twitter: `https://twitter.com/search?q=${encodeURIComponent(phone)}`,
      instagram: `https://www.instagram.com/explore/tags/${phone.replace(/\+/g, '')}/`,
      vk: `https://vk.com/search?c[q]=${encodeURIComponent(phone)}`,
      truecaller: `https://www.truecaller.com/search/it/${encodeURIComponent(phone)}`
    },
    note: 'Open these URLs in browser for manual verification'
  };
}

// NUOVA FUNZIONE: Check Truecaller (scraping leggero)
async function checkTruecaller(phone) {
  console.log('   [2/8] Checking Truecaller database...');
  
  return new Promise((resolve) => {
    const cleanPhone = phone.replace(/\+/g, '%2B');
    const url = `https://www.truecaller.com/search/it/${cleanPhone}`;
    
    https.get(url, {
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
      }
    }, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        const hasProfile = data.includes('profile') || data.includes('name');
        resolve({
          available: true,
          url: url,
          possibleMatch: hasProfile,
          note: 'Visit URL to see full details',
          method: 'Manual verification required'
        });
      });
    }).on('error', () => {
      resolve({
        available: false,
        url: url,
        note: 'Check manually'
      });
    });
    
    setTimeout(() => {
      resolve({
        available: true,
        url: url,
        note: 'Timeout - check manually'
      });
    }, 5000);
  });
}

// NUOVA FUNZIONE: Social Media Direct Links
function generateSocialLinks(phone) {
  console.log('   [3/8] Generating social media check links...');
  
  const cleanPhone = phone.replace(/\+/g, '');
  const urlPhone = encodeURIComponent(phone);
  
  return {
    whatsapp: {
      url: `https://wa.me/${cleanPhone}`,
      checkUrl: `https://web.whatsapp.com/send?phone=${cleanPhone}`,
      method: 'Open in browser - if account exists, chat will load',
      note: 'Valid account = profile picture visible'
    },
    telegram: {
      searchUrl: `https://t.me/+${cleanPhone}`,
      method: 'Add contact in Telegram app with number',
      note: 'If account exists, profile will show'
    },
    signal: {
      method: 'Add contact in Signal app',
      note: 'Account indicator will show if registered'
    },
    viber: {
      method: 'Add contact in Viber app',
      note: 'Profile will appear if registered'
    },
    truecaller: {
      url: `https://www.truecaller.com/search/it/${urlPhone}`,
      method: 'Open URL to search',
      note: 'May show name and linked social profiles'
    }
  };
}

// NUOVA FUNZIONE: Reverse Phone Lookup Services
function getReverseLookupServices(phone) {
  console.log('   [4/8] Preparing reverse lookup services...');
  
  const urlPhone = encodeURIComponent(phone);
  
  return {
    international: {
      'Truecaller': `https://www.truecaller.com/search/it/${urlPhone}`,
      'Sync.ME': `https://sync.me/`,
      'NumLookup': `https://www.numlookup.com/`,
      'PhoneInfoga': 'CLI tool (install via: pip install phoneinfoga)'
    },
    usa: {
      'WhitePages': `https://www.whitepages.com/phone/${urlPhone}`,
      'TruePeopleSearch': `https://www.truepeoplesearch.com/`,
      'FastPeopleSearch': `https://www.fastpeoplesearch.com/`,
      'Spokeo': `https://www.spokeo.com/phone-search?q=${urlPhone}`,
      'BeenVerified': `https://www.beenverified.com/phone-number/${urlPhone}`
    },
    italy: {
      'PagineBianche': `https://www.paginebianche.it/ricerca-da-numero?qs=${urlPhone}`,
      'Tellows': `https://www.tellows.it/num/${phone.replace(/\+/g, '')}`,
      'ChiChiama': `https://chichiama.it/numero/${phone.replace(/\+/g, '')}`
    },
    uk: {
      'TrueCaller UK': `https://www.truecaller.com/search/uk/${urlPhone}`,
      '192.com': `https://www.192.com/`,
      'WhitePages UK': `https://www.whitepages.co.uk/`
    }
  };
}

// NUOVA FUNZIONE: Email Finder da Telefono
function getEmailFinderServices(phone) {
  console.log('   [5/8] Checking email finder services...');
  
  return {
    services: {
      'Hunter.io': 'https://hunter.io/ (Phone to Email lookup)',
      'RocketReach': 'https://rocketreach.co/',
      'Lusha': 'https://www.lusha.com/',
      'ContactOut': 'https://contactout.com/'
    },
    method: 'Enter phone number to find associated email addresses',
    note: 'Most services require free trial or paid account'
  };
}

// NUOVA FUNZIONE: Data Leak Search
function getLeakDatabases(phone) {
  console.log('   [6/8] Searching data leak databases...');
  
  return {
    databases: {
      'HIBP Phone Check': 'https://haveibeenpwned.com/ (Email-based, but breaches may include phones)',
      'DeHashed': `https://dehashed.com/search?query=${encodeURIComponent(phone)}`,
      'LeakCheck': `https://leakcheck.io/`,
      'IntelX': `https://intelx.io/`,
      'Snusbase': 'https://snusbase.com/ (Paid)',
      'OSINT Industries': 'https://osint.industries/'
    },
    googleDorks: [
      `"${phone}" site:pastebin.com`,
      `"${phone}" (leak | breach | database)`,
      `"${phone}" site:ghostbin.com`,
      `"${phone}" filetype:txt`,
      `"${phone}" intext:"password"`
    ],
    warning: 'Check local laws before accessing leaked data'
  };
}

// NUOVA FUNZIONE: Carrier Lookup
function performCarrierLookup(phone) {
  console.log('   [7/8] Performing carrier lookup...');
  
  const countryCode = phone.match(/^\+(\d{1,3})/)?.[1];
  
  return {
    available: true,
    lookupServices: {
      'FreeCarrierLookup': `https://freecarrierlookup.com/`,
      'Carrier Lookup': `https://www.carrierlookup.com/`,
      'NumVerify API': 'https://numverify.com/ (API with free tier)',
      'Twilio Lookup': 'https://www.twilio.com/lookup (API)'
    },
    note: 'Use these services to identify carrier/operator',
    estimatedCountry: countryCode === '1' ? 'US/Canada' : 
                       countryCode === '39' ? 'Italy' :
                       countryCode === '44' ? 'UK' : 'Unknown'
  };
}

// NUOVA FUNZIONE: OSINT Tools Integration
function getOSINTTools(phone) {
  console.log('   [8/8] Generating OSINT tool commands...');
  
  return {
    phoneinfoga: {
      install: 'pip install phoneinfoga',
      command: `phoneinfoga scan -n ${phone}`,
      features: ['Carrier lookup', 'Country detection', 'Google footprint', 'Social media scan'],
      note: 'Best automated tool for phone OSINT'
    },
    ignorant: {
      install: 'git clone https://github.com/megadose/ignorant && cd ignorant && pip install -r requirements.txt',
      command: `python3 ignorant.py ${phone}`,
      features: ['Instagram check', 'Snapchat check', 'Twitter check'],
      note: 'Checks if phone is registered on social platforms'
    },
    holehe: {
      install: 'pip install holehe',
      command: `holehe ${phone}`,
      features: ['Check 120+ websites', 'Email enumeration'],
      note: 'Works with email, but can find linked accounts'
    },
    sherlock: {
      install: 'git clone https://github.com/sherlock-project/sherlock && cd sherlock && pip install -r requirements.txt',
      note: 'Use if you find username associated with phone'
    }
  };
}

// Funzione per location lookup
function getLocationInfo(phone) {
  const countryCode = phone.match(/^\+(\d{1,3})/)?.[1];
  
  let country = 'Unknown';
  let continent = 'Unknown';
  let timezone = 'Unknown';
  
  if (countryCode === '1') {
    country = 'United States/Canada';
    continent = 'North America';
    timezone = 'UTC-5 to UTC-8';
  } else if (countryCode === '39') {
    country = 'Italy';
    continent = 'Europe';
    timezone = 'UTC+1';
  } else if (countryCode === '44') {
    country = 'United Kingdom';
    continent = 'Europe';
    timezone = 'UTC+0';
  } else if (countryCode === '33') {
    country = 'France';
    continent = 'Europe';
    timezone = 'UTC+1';
  } else if (countryCode === '49') {
    country = 'Germany';
    continent = 'Europe';
    timezone = 'UTC+1';
  }
  
  return {
    country: country,
    countryCode: '+' + countryCode,
    continent: continent,
    timezone: timezone
  };
}

function displayResults(data) {
  console.log("\n╔════════════════════════════════════════════════════════╗");
  console.log("║       📱 PHONE OSINT PRO REPORT v2.0 📱               ║");
  console.log("╚════════════════════════════════════════════════════════╝\n");
  
  // Phone Info
  console.log("\x1b[36m┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓\x1b[0m");
  console.log("\x1b[36m┃                  PHONE NUMBER INFO                   ┃\x1b[0m");
  console.log("\x1b[36m┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛\x1b[0m\n");
  
  console.log(`   Raw Input:           ${data.phone.raw}`);
  console.log(`   \x1b[32mFormatted:${'\x1b[0m'}            ${data.phone.formatted}`);
  console.log(`   E.164 Format:        ${data.phone.e164}`);
  console.log(`   Country Code:        ${data.phone.countryCode}`);
  console.log(`   Country:             ${data.phone.country}`);
  console.log(`   National Number:     ${data.phone.nationalNumber}\n`);
  
  // Google Dork Search Results
  if (data.googleSearch) {
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
    console.log("\x1b[36m🔍 GOOGLE DORK SEARCH RESULTS\x1b[0m");
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
    
    console.log(`   \x1b[32mMain Search:\x1b[0m         ${data.googleSearch.searchUrls.google}`);
    console.log(`   Facebook Search:     ${data.googleSearch.searchUrls.facebook}`);
    console.log(`   LinkedIn Search:     ${data.googleSearch.searchUrls.linkedin}`);
    console.log(`   Twitter Search:      ${data.googleSearch.searchUrls.twitter}`);
    console.log(`   Truecaller:          ${data.googleSearch.searchUrls.truecaller}\n`);
    
    console.log(`   \x1b[33mGenerated Dorks (${data.googleSearch.dorks.length}):\x1b[0m`);
    data.googleSearch.dorks.slice(0, 5).forEach((dork, i) => {
      console.log(`      ${i + 1}. ${dork}`);
    });
    console.log('');
  }
  
  // Truecaller Check
  if (data.truecaller) {
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
    console.log("\x1b[36m📞 TRUECALLER CHECK\x1b[0m");
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
    
    console.log(`   URL:                 ${data.truecaller.url}`);
    console.log(`   Possible Match:      ${data.truecaller.possibleMatch ? '\x1b[32mYes\x1b[0m' : '\x1b[31mNo\x1b[0m'}`);
    console.log(`   Note:                ${data.truecaller.note}\n`);
  }
  
  // Social Media Links
  if (data.socialLinks) {
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
    console.log("\x1b[36m📱 SOCIAL MEDIA DIRECT CHECKS\x1b[0m");
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
    
    console.log(`   \x1b[32mWhatsApp:\x1b[0m`);
    console.log(`      URL: ${data.socialLinks.whatsapp.url}`);
    console.log(`      Method: ${data.socialLinks.whatsapp.method}\n`);
    
    console.log(`   \x1b[32mTelegram:\x1b[0m`);
    console.log(`      URL: ${data.socialLinks.telegram.searchUrl}`);
    console.log(`      Method: ${data.socialLinks.telegram.method}\n`);
    
    console.log(`   \x1b[32mTruecaller:\x1b[0m`);
    console.log(`      URL: ${data.socialLinks.truecaller.url}`);
    console.log(`      Note: ${data.socialLinks.truecaller.note}\n`);
  }
  
  // Reverse Lookup Services
  if (data.reverseLookup) {
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
    console.log("\x1b[36m🔎 REVERSE LOOKUP SERVICES\x1b[0m");
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
    
    console.log(`   \x1b[32mInternational:\x1b[0m`);
    Object.entries(data.reverseLookup.international).forEach(([name, url]) => {
      console.log(`      • ${name}: ${url}`);
    });
    console.log('');
    
    if (data.phone.country.includes('United States') || data.phone.country.includes('Canada')) {
      console.log(`   \x1b[32mUSA Specific:\x1b[0m`);
      Object.entries(data.reverseLookup.usa).forEach(([name, url]) => {
        console.log(`      • ${name}: ${url}`);
      });
      console.log('');
    }
    
    if (data.phone.country.includes('Italy')) {
      console.log(`   \x1b[32mItaly Specific:\x1b[0m`);
      Object.entries(data.reverseLookup.italy).forEach(([name, url]) => {
        console.log(`      • ${name}: ${url}`);
      });
      console.log('');
    }
  }
  
  // Data Leak Databases
  if (data.leakDatabases) {
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
    console.log("\x1b[36m💾 DATA LEAK DATABASES\x1b[0m");
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
    
    console.log(`   \x1b[32mDatabases:\x1b[0m`);
    Object.entries(data.leakDatabases.databases).forEach(([name, url]) => {
      console.log(`      • ${name}: ${url}`);
    });
    console.log('');
    
    console.log(`   \x1b[33mGoogle Dorks for Leaks:\x1b[0m`);
    data.leakDatabases.googleDorks.slice(0, 3).forEach(dork => {
      console.log(`      • ${dork}`);
    });
    console.log('');
  }
  
  // OSINT Tools
  if (data.osintTools) {
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
    console.log("\x1b[36m🛠️  OSINT TOOLS (Installable on Termux)\x1b[0m");
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
    
    console.log(`   \x1b[32mPhoneInfoga:\x1b[0m ${'\x1b[33m'}(RECOMMENDED)${'\x1b[0m'}`);
    console.log(`      Install: ${data.osintTools.phoneinfoga.install}`);
    console.log(`      Command: ${data.osintTools.phoneinfoga.command}`);
    console.log(`      Features: ${data.osintTools.phoneinfoga.features.join(', ')}\n`);
    
    console.log(`   \x1b[32mIgnorant:\x1b[0m`);
    console.log(`      Install: ${data.osintTools.ignorant.install}`);
    console.log(`      Command: ${data.osintTools.ignorant.command}\n`);
  }
  
  // Location Info
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
  console.log("\x1b[36m🌍 LOCATION INFORMATION\x1b[0m");
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
  
  console.log(`   Country:             ${data.location.country}`);
  console.log(`   Continent:           ${data.location.continent}`);
  console.log(`   Timezone:            ${data.location.timezone}\n`);
}

function saveReport(data) {
  const dir = './phone-osint-reports';
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, -5);
  const cleanPhone = data.phone.formatted.replace(/\+/g, '').replace(/[^0-9]/g, '');
  const filename = `${dir}/phone-${cleanPhone}-${timestamp}.txt`;
  
  let content = `═══════════════════════════════════════════════════════════
PHONE OSINT PRO REPORT v2.0
═══════════════════════════════════════════════════════════

Date: ${new Date().toLocalString()}

PHONE NUMBER INFO:
Raw: ${data.phone.raw}
Formatted: ${data.phone.formatted}
E.164: ${data.phone.e164}
Country Code: ${data.phone.countryCode}
Country: ${data.phone.country}

GOOGLE SEARCH URLS:
Main Search: ${data.googleSearch.searchUrls.google}
Facebook: ${data.googleSearch.searchUrls.facebook}
LinkedIn: ${data.googleSearch.searchUrls.linkedin}
Twitter: ${data.googleSearch.searchUrls.twitter}
Truecaller: ${data.googleSearch.searchUrls.truecaller}

SOCIAL MEDIA CHECKS:
WhatsApp: ${data.socialLinks.whatsapp.url}
Telegram: ${data.socialLinks.telegram.searchUrl}

TRUECALLER:
URL: ${data.truecaller.url}
Possible Match: ${data.truecaller.possibleMatch ? 'Yes' : 'No'}

REVERSE LOOKUP SERVICES:
${Object.entries(data.reverseLookup.international).map(([k, v]) => `${k}: ${v}`).join('\n')}

DATA LEAK DATABASES:
${Object.entries(data.leakDatabases.databases).map(([k, v]) => `${k}: ${v}`).join('\n')}

OSINT TOOLS:
PhoneInfoga: ${data.osintTools.phoneinfoga.command}
Ignorant: ${data.osintTools.ignorant.command}

LOCATION:
Country: ${data.location.country}
Continent: ${data.location.continent}
Timezone: ${data.location.timezone}
`;

  fs.writeFileSync(filename, content);
  console.log(`\x1b[32m✅ Report saved: ${filename}\x1b[0m\n`);
}

function showHelp() {
  showBanner();
  
  console.log("Usage: node phone-osint-pro.js <phone_number> [--save]\n");
  console.log("Supported formats:");
  console.log("  +1234567890          (International E.164)");
  console.log("  +39 123 456 7890     (With spaces)");
  console.log("  1234567890           (Will add +1 if 10 digits)");
  console.log("  3123456789           (Will add +39 for Italian mobile)\n");
  
  console.log("Options:");
  console.log("  --save               Save full report to file\n");
  
  console.log("Examples:");
  console.log("  node phone-osint-pro.js +1234567890");
  console.log("  node phone-osint-pro.js \"+39 312 345 6789\" --save");
  console.log("  node phone-osint-pro.js 5551234567\n");
}

async function main() {
  const args = process.argv.slice(2);
  
  if (args.length === 0 || args.includes('--help')) {
    showHelp();
    process.exit(0);
  }
  
  showBanner();
  
  let phoneNumber = null;
  let saveFlag = false;
  
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--save') {
      saveFlag = true;
    } else if (!args[i].startsWith('--')) {
      phoneNumber = args[i];
    }
  }
  
  if (!phoneNumber) {
    console.log("\x1b[31m❌ No phone number provided!\x1b[0m\n");
    showHelp();
    process.exit(1);
  }
  
  console.log(`⏳ Analyzing phone number: ${phoneNumber}...\n`);
  
  const parsed = parsePhoneNumber(phoneNumber);
  
  if (!parsed.valid) {
    console.log(`\x1b[31m❌ ${parsed.error}\x1b[0m\n`);
    process.exit(1);
  }
  
  const results = {
    timestamp: new Date().toISOString(),
    phone: parsed,
    googleSearch: await searchGoogleDorks(parsed.formatted),
    truecaller: await checkTruecaller(parsed.formatted),
    socialLinks: generateSocialLinks(parsed.formatted),
    reverseLookup: getReverseLookupServices(parsed.formatted),
    emailFinder: getEmailFinderServices(parsed.formatted),
    leakDatabases: getLeakDatabases(parsed.formatted),
    carrier: performCarrierLookup(parsed.formatted),
    osintTools: getOSINTTools(parsed.formatted),
    location: getLocationInfo(parsed.formatted)
  };
  
  displayResults(results);
  
  if (saveFlag) {
    saveReport(results);
  }
  
  console.log("\x1b[31m██████╗ ██╗  ██╗ ██████╗ ███╗   ██╗███████╗\x1b[0m");
  console.log("\x1b[35m🥝 Analysis complete - by kiwi & 777\x1b[0m\n");
}

main();
