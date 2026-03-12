#!/usr/bin/env node

const { exec } = require('child_process');
const { promisify } = require('util');
const execAsync = promisify(exec);
const fs = require('fs');
const https = require('https');
const http = require('http');

// ============================================
// TORBOT OSINT - Darkweb/Tor Intelligence
// ============================================

const ONION_SEARCH_ENGINES = {
  ahmia: {
    name: 'Ahmia.fi',
    url: 'https://ahmia.fi/search/?q=',
    clearnet: true,
    description: 'Main Tor search engine (clearnet access)'
  },
  torch: {
    name: 'Torch',
    onion: 'http://torchdeedp3i2jigzjdmfpn5ttjhthh5wbmda2rr3jvqjg5p77c54dqd.onion',
    description: 'Oldest Tor search engine'
  },
  notevil: {
    name: 'Not Evil',
    onion: 'http://hss3uro2hsxfogfq.onion',
    description: 'Tor search engine'
  },
  candle: {
    name: 'Candle',
    onion: 'http://gjobqjj7wyczbqie.onion',
    description: 'Simple Tor search'
  },
  onionland: {
    name: 'Onion.land',
    url: 'https://onion.land/search?q=',
    clearnet: true,
    description: 'Tor search via clearnet'
  },
  darksearch: {
    name: 'DarkSearch.io',
    url: 'https://darksearch.io/search?query=',
    clearnet: true,
    description: 'Modern Tor search engine'
  }
};

const POPULAR_ONION_SITES = {
  markets: [
    { name: 'Dark Web Markets List', info: 'Check DNM forums for current markets' },
    { name: 'Darknet Live', url: 'https://darknetlive.com', clearnet: true },
    { name: 'Dark.fail', url: 'https://dark.fail', clearnet: true }
  ],
  forums: [
    { name: 'Dread Forum', info: 'Reddit-style darknet forum' },
    { name: 'RaidForums (archived)', info: 'Data breach forum' },
    { name: 'Exploit.in', info: 'Russian hacking forum' }
  ],
  wikis: [
    { name: 'Hidden Wiki', info: 'Main darknet wiki' },
    { name: 'The Hub', info: 'Links directory' },
    { name: 'OnionTree', url: 'https://oniontree.org', clearnet: true }
  ],
  tools: [
    { name: 'ProtonMail', onion: 'https://protonmailrmez3lotccipshtkleegetolb73fuirgj7r4o4vfu7ozyd.onion' },
    { name: 'DuckDuckGo', onion: 'https://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion' },
    { name: 'SecureDrop', info: 'Anonymous whistleblowing' }
  ]
};

const TOR_CHECK_ENDPOINTS = [
  'https://check.torproject.org/api/ip',
  'https://www.atagar.com/echo.php'
];

async function checkTorConnection() {
  console.log('   [1/6] Checking Tor connection...');
  
  try {
    // Check if using Tor SOCKS proxy
    const { stdout } = await execAsync('curl -s --socks5 127.0.0.1:9050 https://check.torproject.org/api/ip', { timeout: 10000 });
    const data = JSON.parse(stdout);
    
    return {
      connected: data.IsTor === true,
      ip: data.IP,
      message: data.IsTor ? 'Connected via Tor' : 'NOT using Tor'
    };
  } catch (error) {
    return {
      connected: false,
      error: 'Tor not running or not accessible',
      help: 'Install: pkg install tor && tor &'
    };
  }
}

async function searchAhmia(query) {
  console.log('   [2/6] Searching Ahmia.fi...');
  
  return new Promise((resolve) => {
    const url = `https://ahmia.fi/search/?q=${encodeURIComponent(query)}`;
    
    https.get(url, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        const results = parseAhmiaResults(data);
        resolve({
          engine: 'Ahmia.fi',
          url: url,
          results: results,
          count: results.length
        });
      });
    }).on('error', () => {
      resolve({
        engine: 'Ahmia.fi',
        error: 'Search failed'
      });
    });
    
    setTimeout(() => resolve({ engine: 'Ahmia.fi', error: 'Timeout' }), 10000);
  });
}

function parseAhmiaResults(html) {
  const results = [];
  const regex = /<h4><a href="([^"]+)">([^<]+)<\/a><\/h4>/g;
  let match;
  
  while ((match = regex.exec(html)) !== null && results.length < 10) {
    results.push({
      url: match[1],
      title: match[2]
    });
  }
  
  return results;
}

async function searchDarkSearch(query) {
  console.log('   [3/6] Searching DarkSearch.io...');
  
  return new Promise((resolve) => {
    const url = `https://darksearch.io/api/search?query=${encodeURIComponent(query)}`;
    
    https.get(url, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          const json = JSON.parse(data);
          const results = json.data ? json.data.slice(0, 10).map(r => ({
            url: r.link,
            title: r.title || 'No title',
            description: r.description || ''
          })) : [];
          
          resolve({
            engine: 'DarkSearch.io',
            url: `https://darksearch.io/search?query=${encodeURIComponent(query)}`,
            results: results,
            count: results.length
          });
        } catch (e) {
          resolve({ engine: 'DarkSearch.io', error: 'Parse error' });
        }
      });
    }).on('error', () => {
      resolve({ engine: 'DarkSearch.io', error: 'Search failed' });
    });
    
    setTimeout(() => resolve({ engine: 'DarkSearch.io', error: 'Timeout' }), 10000);
  });
}

async function crawlOnionSite(onionUrl) {
  console.log('   [4/6] Crawling onion site (via Tor)...');
  
  if (!onionUrl.includes('.onion')) {
    return {
      error: 'Not a valid .onion URL'
    };
  }
  
  try {
    // Use Tor SOCKS proxy
    const { stdout } = await execAsync(`curl -s --socks5 127.0.0.1:9050 "${onionUrl}" -m 30`, { timeout: 35000 });
    
    const analysis = {
      url: onionUrl,
      size: stdout.length,
      links: extractLinks(stdout, onionUrl),
      emails: extractEmails(stdout),
      images: extractImages(stdout),
      forms: extractForms(stdout),
      title: extractTitle(stdout)
    };
    
    return analysis;
  } catch (error) {
    return {
      url: onionUrl,
      error: 'Crawl failed - Site offline or Tor not running',
      help: 'Make sure Tor is running: tor &'
    };
  }
}

function extractLinks(html, baseUrl) {
  const links = new Set();
  const regex = /href=["']([^"']+)["']/g;
  let match;
  
  while ((match = regex.exec(html)) !== null) {
    let link = match[1];
    
    // Filter and normalize links
    if (link.startsWith('http') || link.includes('.onion')) {
      links.add(link);
    } else if (link.startsWith('/')) {
      const base = new URL(baseUrl);
      links.add(`${base.protocol}//${base.host}${link}`);
    }
  }
  
  return Array.from(links).slice(0, 50);
}

function extractEmails(html) {
  const emails = new Set();
  const regex = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
  let match;
  
  while ((match = regex.exec(html)) !== null) {
    emails.add(match[0]);
  }
  
  return Array.from(emails);
}

function extractImages(html) {
  const images = new Set();
  const regex = /src=["']([^"']+\.(jpg|jpeg|png|gif|webp))["']/gi;
  let match;
  
  while ((match = regex.exec(html)) !== null) {
    images.add(match[1]);
  }
  
  return Array.from(images).slice(0, 20);
}

function extractForms(html) {
  const forms = [];
  const formRegex = /<form[^>]*>(.*?)<\/form>/gis;
  let match;
  
  while ((match = formRegex.exec(html)) !== null && forms.length < 5) {
    const actionMatch = match[0].match(/action=["']([^"']+)["']/i);
    const methodMatch = match[0].match(/method=["']([^"']+)["']/i);
    
    forms.push({
      action: actionMatch ? actionMatch[1] : 'none',
      method: methodMatch ? methodMatch[1].toUpperCase() : 'GET',
      inputs: (match[1].match(/<input/gi) || []).length
    });
  }
  
  return forms;
}

function extractTitle(html) {
  const match = html.match(/<title>([^<]+)<\/title>/i);
  return match ? match[1] : 'No title';
}

function generateOnionDorks(keyword) {
  console.log('   [5/6] Generating Tor-specific dorks...');
  
  return [
    `${keyword} site:.onion`,
    `${keyword} inurl:.onion`,
    `"${keyword}" site:.onion`,
    `${keyword} marketplace site:.onion`,
    `${keyword} forum site:.onion`,
    `${keyword} wiki site:.onion`,
    `${keyword} market site:.onion`,
    `${keyword} shop site:.onion`,
    `${keyword} vendor site:.onion`,
    `${keyword} login site:.onion`,
    `${keyword} register site:.onion`,
    `${keyword} database site:.onion`
  ];
}

function getTorSetupGuide() {
  console.log('   [6/6] Preparing Tor setup guide...');
  
  return {
    termux: {
      install: [
        'pkg update && pkg upgrade -y',
        'pkg install tor -y',
        'pkg install torsocks -y'
      ],
      config: [
        'Edit /data/data/com.termux/files/usr/etc/tor/torrc',
        'Add: SOCKSPort 9050',
        'Add: ControlPort 9051'
      ],
      start: [
        'tor &',
        'Wait 30 seconds for bootstrap'
      ],
      test: [
        'curl --socks5 127.0.0.1:9050 https://check.torproject.org/api/ip',
        'Should return {"IsTor":true}'
      ]
    },
    usage: {
      curl: 'curl --socks5 127.0.0.1:9050 http://example.onion',
      torsocks: 'torsocks curl http://example.onion',
      browser: 'Use Tor Browser or Orbot on Android'
    },
    safety: [
      '⚠️  NEVER login with real credentials',
      '⚠️  NEVER download unknown files',
      '⚠️  NEVER enable JavaScript on .onion sites',
      '⚠️  Use VPN + Tor for extra anonymity',
      '⚠️  Clear all traces after session'
    ]
  };
}

function showBanner() {
  console.log("\x1b[31m");
  console.log("████████╗ ██████╗ ██████╗ ██████╗  ██████╗ ████████╗");
  console.log("╚══██╔══╝██╔═══██╗██╔══██╗██╔══██╗██╔═══██╗╚══██╔══╝");
  console.log("   ██║   ██║   ██║██████╔╝██████╔╝██║   ██║   ██║   ");
  console.log("   ██║   ██║   ██║██╔══██╗██╔══██╗██║   ██║   ██║   ");
  console.log("   ██║   ╚██████╔╝██║  ██║██████╔╝╚██████╔╝   ██║   ");
  console.log("   ╚═╝    ╚═════╝ ╚═╝  ╚═╝╚═════╝  ╚═════╝    ╚═╝   ");
  console.log("\x1b[0m");
  console.log("\x1b[35m🥝 NIKA TorBot - Darkweb/Tor OSINT\x1b[0m");
  console.log("\x1b[33m⚠️  For research only - Stay anonymous - Use responsibly\x1b[0m\n");
}

function displayResults(data) {
  console.log("\n╔════════════════════════════════════════════════════════╗");
  console.log("║       🕵️  TOR OSINT RESULTS 🕵️                         ║");
  console.log("╚════════════════════════════════════════════════════════╝\n");
  
  // Tor Connection Status
  if (data.torCheck) {
    console.log("\x1b[36m┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓\x1b[0m");
    console.log("\x1b[36m┃                  TOR CONNECTION                      ┃\x1b[0m");
    console.log("\x1b[36m┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛\x1b[0m\n");
    
    if (data.torCheck.connected) {
      console.log(`   Status:              ${'\x1b[32m✓ Connected\x1b[0m'}`);
      console.log(`   Exit IP:             ${data.torCheck.ip}`);
      console.log(`   Message:             ${data.torCheck.message}\n`);
    } else {
      console.log(`   Status:              ${'\x1b[31m✗ Not Connected\x1b[0m'}`);
      console.log(`   Error:               ${data.torCheck.error}`);
      console.log(`   Help:                ${data.torCheck.help}\n`);
    }
  }
  
  // Search Results
  if (data.searches && data.searches.length > 0) {
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
    console.log("\x1b[36m🔍 SEARCH RESULTS\x1b[0m");
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
    
    data.searches.forEach(search => {
      console.log(`   Engine: \x1b[32m${search.engine}\x1b[0m`);
      
      if (search.error) {
        console.log(`   Error: ${search.error}\n`);
      } else {
        console.log(`   Results: ${search.count}`);
        console.log(`   URL: ${search.url}\n`);
        
        if (search.results && search.results.length > 0) {
          search.results.slice(0, 5).forEach((r, i) => {
            console.log(`      ${i + 1}. ${r.title}`);
            console.log(`         ${r.url}`);
            if (r.description) console.log(`         ${r.description.substring(0, 80)}...`);
            console.log('');
          });
        }
      }
    });
  }
  
  // Crawl Results
  if (data.crawl) {
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
    console.log("\x1b[36m🕸️  SITE CRAWL ANALYSIS\x1b[0m");
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
    
    if (data.crawl.error) {
      console.log(`   URL: ${data.crawl.url}`);
      console.log(`   Error: ${data.crawl.error}`);
      if (data.crawl.help) console.log(`   Help: ${data.crawl.help}`);
      console.log('');
    } else {
      console.log(`   URL:                 ${data.crawl.url}`);
      console.log(`   Title:               ${data.crawl.title}`);
      console.log(`   Page Size:           ${data.crawl.size} bytes`);
      console.log(`   Links Found:         ${data.crawl.links.length}`);
      console.log(`   Emails Found:        ${data.crawl.emails.length}`);
      console.log(`   Images Found:        ${data.crawl.images.length}`);
      console.log(`   Forms Found:         ${data.crawl.forms.length}\n`);
      
      if (data.crawl.emails.length > 0) {
        console.log('   Emails:');
        data.crawl.emails.forEach(email => console.log(`      • ${email}`));
        console.log('');
      }
      
      if (data.crawl.links.length > 0) {
        console.log(`   Links (first 10):`);
        data.crawl.links.slice(0, 10).forEach(link => console.log(`      • ${link}`));
        console.log('');
      }
      
      if (data.crawl.forms.length > 0) {
        console.log('   Forms:');
        data.crawl.forms.forEach((form, i) => {
          console.log(`      ${i + 1}. Action: ${form.action} | Method: ${form.method} | Inputs: ${form.inputs}`);
        });
        console.log('');
      }
    }
  }
  
  // Onion Search Engines
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
  console.log("\x1b[36m🔎 ONION SEARCH ENGINES\x1b[0m");
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
  
  Object.values(ONION_SEARCH_ENGINES).forEach(engine => {
    console.log(`   \x1b[32m${engine.name}\x1b[0m`);
    if (engine.url) console.log(`      Clearnet: ${engine.url}`);
    if (engine.onion) console.log(`      Onion: ${engine.onion}`);
    console.log(`      ${engine.description}\n`);
  });
  
  // Popular Sites
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
  console.log("\x1b[36m📚 POPULAR ONION CATEGORIES\x1b[0m");
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
  
  console.log('   \x1b[32mMarketplaces:\x1b[0m');
  POPULAR_ONION_SITES.markets.forEach(s => {
    console.log(`      • ${s.name}${s.url ? ` - ${s.url}` : ` - ${s.info}`}`);
  });
  console.log('');
  
  console.log('   \x1b[32mForums:\x1b[0m');
  POPULAR_ONION_SITES.forums.forEach(s => {
    console.log(`      • ${s.name} - ${s.info}`);
  });
  console.log('');
  
  console.log('   \x1b[32mWikis:\x1b[0m');
  POPULAR_ONION_SITES.wikis.forEach(s => {
    console.log(`      • ${s.name}${s.url ? ` - ${s.url}` : ` - ${s.info}`}`);
  });
  console.log('');
  
  // Dorks
  if (data.dorks) {
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
    console.log("\x1b[36m🎯 GENERATED DORKS\x1b[0m");
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
    
    data.dorks.forEach((dork, i) => {
      console.log(`   ${i + 1}. ${dork}`);
    });
    console.log('');
  }
  
  // Setup Guide
  if (data.setup) {
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
    console.log("\x1b[36m⚙️  TOR SETUP GUIDE (TERMUX)\x1b[0m");
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
    
    console.log('   \x1b[32m1. Install:\x1b[0m');
    data.setup.termux.install.forEach(cmd => console.log(`      $ ${cmd}`));
    console.log('');
    
    console.log('   \x1b[32m2. Start:\x1b[0m');
    data.setup.termux.start.forEach(cmd => console.log(`      $ ${cmd}`));
    console.log('');
    
    console.log('   \x1b[32m3. Test:\x1b[0m');
    data.setup.termux.test.forEach(cmd => console.log(`      $ ${cmd}`));
    console.log('');
    
    console.log('   \x1b[32m4. Usage:\x1b[0m');
    Object.entries(data.setup.usage).forEach(([k, v]) => {
      console.log(`      ${k}: ${v}`);
    });
    console.log('');
    
    console.log('   \x1b[31m⚠️  SAFETY REMINDERS:\x1b[0m');
    data.setup.safety.forEach(tip => console.log(`      ${tip}`));
    console.log('');
  }
}

function saveResults(data) {
  const dir = './torbot-reports';
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, -5);
  const jsonFile = `${dir}/torbot-${timestamp}.json`;
  const txtFile = jsonFile.replace('.json', '.txt');
  
  fs.writeFileSync(jsonFile, JSON.stringify(data, null, 2));
  
  let txtContent = `═══════════════════════════════════════════════════════════
TORBOT OSINT REPORT
═══════════════════════════════════════════════════════════

Date: ${new Date().toLocaleString()}

`;

  if (data.torCheck) {
    txtContent += `TOR CONNECTION:\nStatus: ${data.torCheck.connected ? 'Connected' : 'Not Connected'}\n`;
    if (data.torCheck.ip) txtContent += `Exit IP: ${data.torCheck.ip}\n`;
    txtContent += '\n';
  }
  
  if (data.crawl && !data.crawl.error) {
    txtContent += `CRAWL ANALYSIS:\nURL: ${data.crawl.url}\nTitle: ${data.crawl.title}\nLinks: ${data.crawl.links.length}\nEmails: ${data.crawl.emails.length}\n\n`;
    
    if (data.crawl.emails.length > 0) {
      txtContent += 'EMAILS:\n';
      data.crawl.emails.forEach(e => txtContent += `${e}\n`);
      txtContent += '\n';
    }
    
    if (data.crawl.links.length > 0) {
      txtContent += 'LINKS:\n';
      data.crawl.links.forEach(l => txtContent += `${l}\n`);
      txtContent += '\n';
    }
  }
  
  fs.writeFileSync(txtFile, txtContent);
  
  console.log(`\x1b[32m✅ Results saved:\x1b[0m`);
  console.log(`   JSON: ${jsonFile}`);
  console.log(`   TXT: ${txtFile}\n`);
}

function showHelp() {
  showBanner();
  
  console.log("Usage: node torbot-osint.js [OPTIONS]\n");
  console.log("Options:");
  console.log("  --search <keyword>   Search onion sites");
  console.log("  --crawl <url>        Crawl .onion site");
  console.log("  --check              Check Tor connection");
  console.log("  --setup              Show Tor setup guide");
  console.log("  --engines            List search engines");
  console.log("  --sites              List popular sites");
  console.log("  --save               Save results");
  console.log("  --help               Show this help\n");
  
  console.log("Examples:");
  console.log("  node torbot-osint.js --check");
  console.log("  node torbot-osint.js --search drugs");
  console.log("  node torbot-osint.js --crawl http://example.onion");
  console.log("  node torbot-osint.js --setup");
  console.log("  node torbot-osint.js --search hacking --save\n");
}

async function main() {
  const args = process.argv.slice(2);
  
  if (args.length === 0 || args.includes('--help')) {
    showHelp();
    process.exit(0);
  }
  
  showBanner();
  
  let searchQuery = null;
  let crawlUrl = null;
  let checkFlag = false;
  let setupFlag = false;
  let enginesFlag = false;
  let sitesFlag = false;
  let saveFlag = false;
  
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--search') {
      searchQuery = args[i + 1];
      i++;
    } else if (args[i] === '--crawl') {
      crawlUrl = args[i + 1];
      i++;
    } else if (args[i] === '--check') {
      checkFlag = true;
    } else if (args[i] === '--setup') {
      setupFlag = true;
    } else if (args[i] === '--engines') {
      enginesFlag = true;
    } else if (args[i] === '--sites') {
      sitesFlag = true;
    } else if (args[i] === '--save') {
      saveFlag = true;
    }
  }
  
  console.log(`⏳ Initializing TorBot OSINT...\n`);
  
  const results = {
    timestamp: new Date().toISOString(),
    torCheck: null,
    searches: [],
    crawl: null,
    dorks: null,
    setup: null
  };
  
  // Always check Tor connection first
  results.torCheck = await checkTorConnection();
  
  if (searchQuery) {
    // Search multiple engines
    results.searches.push(await searchAhmia(searchQuery));
    results.searches.push(await searchDarkSearch(searchQuery));
    results.dorks = generateOnionDorks(searchQuery);
  }
  
  if (crawlUrl) {
    results.crawl = await crawlOnionSite(crawlUrl);
  }
  
  if (setupFlag || !results.torCheck.connected) {
    results.setup = getTorSetupGuide();
  }
  
  displayResults(results);
  
  if (saveFlag) {
    saveResults(results);
  }
  
  console.log("\x1b[31m████████╗ ██████╗ ██████╗ ██████╗  ██████╗ ████████╗\x1b[0m");
  console.log("\x1b[35m🥝 Analysis complete - Stay anonymous - by kiwi & 777\x1b[0m\n");
}

main().catch(console.error);
