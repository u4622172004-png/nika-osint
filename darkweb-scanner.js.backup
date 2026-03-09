#!/usr/bin/env node

const axios = require('axios');
const { exec } = require('child_process');
const { promisify } = require('util');
const execAsync = promisify(exec);
const fs = require('fs');

// ============================================
// DARKWEB SCANNER - Search .onion sites
// ============================================

const DARKWEB_ENGINES = {
  ahmia: {
    name: 'Ahmia',
    url: 'https://ahmia.fi/search/?q=',
    type: 'clearnet'
  },
  torch: {
    name: 'Torch (via Ahmia)',
    note: 'Requires Tor for direct access'
  },
  notevil: {
    name: 'notEvil',
    note: 'Requires Tor'
  }
};

async function checkTorInstalled() {
  try {
    await execAsync('which tor');
    return true;
  } catch {
    return false;
  }
}

async function searchAhmia(query) {
  try {
    const url = `https://ahmia.fi/search/?q=${encodeURIComponent(query)}`;
    console.log(`   Searching Ahmia for: ${query}...`);
    
    const response = await axios.get(url, {
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
      },
      timeout: 30000
    });
    
    const results = parseAhmiaResults(response.data, query);
    
    return {
      engine: 'Ahmia',
      query: query,
      results: results,
      searchUrl: url
    };
  } catch (error) {
    return {
      engine: 'Ahmia',
      query: query,
      error: error.message,
      results: []
    };
  }
}

function parseAhmiaResults(html, query) {
  const results = [];
  
  // Simple regex parsing (in real implementation, use cheerio)
  const urlRegex = /href="([^"]*\.onion[^"]*)"/g;
  const titleRegex = /<h4[^>]*>(.*?)<\/h4>/g;
  
  let urlMatch, titleMatch;
  const urls = [];
  const titles = [];
  
  while ((urlMatch = urlRegex.exec(html)) !== null) {
    urls.push(urlMatch[1]);
  }
  
  while ((titleMatch = titleRegex.exec(html)) !== null) {
    titles.push(titleMatch[1].replace(/<[^>]*>/g, ''));
  }
  
  for (let i = 0; i < Math.min(urls.length, titles.length, 10); i++) {
    results.push({
      title: titles[i] || 'No title',
      url: urls[i],
      onion: urls[i].includes('.onion')
    });
  }
  
  return results;
}

function generateDarkwebDorks(query) {
  return [
    `site:*.onion "${query}"`,
    `site:*.onion ${query}`,
    `inurl:.onion "${query}"`,
    `${query} site:pastebin.com`,
    `${query} site:ghostbin.com`,
    `${query} site:rentry.co`,
    `${query} "onion link"`,
    `${query} "dark web"`,
    `${query} "tor hidden service"`
  ];
}

function showBanner() {
  console.log("\x1b[31m");
  console.log("██████╗  █████╗ ██████╗ ██╗  ██╗██╗    ██╗███████╗██████╗ ");
  console.log("██╔══██╗██╔══██╗██╔══██╗██║ ██╔╝██║    ██║██╔════╝██╔══██╗");
  console.log("██║  ██║███████║██████╔╝█████╔╝ ██║ █╗ ██║█████╗  ██████╔╝");
  console.log("██║  ██║██╔══██║██╔══██╗██╔═██╗ ██║███╗██║██╔══╝  ██╔══██╗");
  console.log("██████╔╝██║  ██║██║  ██║██║  ██╗╚███╔███╔╝███████╗██████╔╝");
  console.log("╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚══╝╚══╝ ╚══════╝╚═════╝ ");
  console.log("\x1b[0m");
  console.log("\x1b[35m🥝 NIKA Darkweb Scanner - Search .onion sites\x1b[0m");
  console.log("\x1b[33m⚠️  For authorized investigation only\x1b[0m");
  console.log("\x1b[31m⚠️  EXTREME CAUTION: Accessing darkweb can be dangerous\x1b[0m\n");
}

function displayResults(data) {
  console.log("\n╔════════════════════════════════════════════════════════╗");
  console.log("║         🕸️  DARKWEB SEARCH RESULTS 🕸️                  ║");
  console.log("╚════════════════════════════════════════════════════════╝\n");
  
  console.log(`🔍 Query: \x1b[36m${data.query}\x1b[0m`);
  console.log(`🌐 Engine: ${data.engine}\n`);
  
  if (data.error) {
    console.log(`\x1b[31m❌ Error: ${data.error}\x1b[0m\n`);
    return;
  }
  
  if (data.results.length === 0) {
    console.log("\x1b[33m⚠️  No results found\x1b[0m\n");
    return;
  }
  
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
  console.log(`\x1b[36m📋 FOUND ${data.results.length} RESULTS\x1b[0m`);
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
  
  data.results.forEach((result, i) => {
    console.log(`${i + 1}. \x1b[32m${result.title}\x1b[0m`);
    console.log(`   URL: ${result.url}`);
    if (result.onion) {
      console.log(`   \x1b[31m⚠️  .onion site (requires Tor Browser)\x1b[0m`);
    }
    console.log('');
  });
  
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
  console.log("\x1b[36m🔍 MANUAL SEARCH QUERIES\x1b[0m");
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
  
  const dorks = generateDarkwebDorks(data.query);
  dorks.forEach((dork, i) => {
    console.log(`${i + 1}. ${dork}`);
  });
  
  console.log('');
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
  console.log("\x1b[36m🔒 SAFETY TIPS\x1b[0m");
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
  
  console.log("  ⚠️  Always use Tor Browser for .onion sites");
  console.log("  ⚠️  Never download files from unknown sources");
  console.log("  ⚠️  Do not provide personal information");
  console.log("  ⚠️  Many darkweb sites are illegal/dangerous");
  console.log("  ⚠️  Use VPN + Tor for extra security\n");
}

function saveResults(data) {
  const dir = './darkweb-reports';
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, -5);
  const jsonFile = `${dir}/${data.query.replace(/[^a-z0-9]/gi, '_')}-${timestamp}.json`;
  const txtFile = jsonFile.replace('.json', '.txt');
  
  fs.writeFileSync(jsonFile, JSON.stringify(data, null, 2));
  
  let txtContent = `═══════════════════════════════════════════════════════════
DARKWEB SCANNER REPORT
═══════════════════════════════════════════════════════════

Query: ${data.query}
Engine: ${data.engine}
Date: ${new Date().toLocaleString()}

═══════════════════════════════════════════════════════════
RESULTS (${data.results.length})
═══════════════════════════════════════════════════════════

`;

  data.results.forEach((result, i) => {
    txtContent += `${i + 1}. ${result.title}\n`;
    txtContent += `   ${result.url}\n`;
    if (result.onion) {
      txtContent += `   [.onion site - requires Tor]\n`;
    }
    txtContent += '\n';
  });
  
  txtContent += `═══════════════════════════════════════════════════════════
MANUAL SEARCH QUERIES
═══════════════════════════════════════════════════════════

`;

  const dorks = generateDarkwebDorks(data.query);
  dorks.forEach((dork, i) => {
    txtContent += `${i + 1}. ${dork}\n`;
  });
  
  fs.writeFileSync(txtFile, txtContent);
  
  console.log(`\x1b[32m✅ Results saved:\x1b[0m`);
  console.log(`   JSON: ${jsonFile}`);
  console.log(`   TXT: ${txtFile}\n`);
}

function showHelp() {
  showBanner();
  
  console.log("Usage: node darkweb-scanner.js [OPTIONS] <query>\n");
  console.log("Options:");
  console.log("  --save           Save results to file");
  console.log("  --help           Show this help\n");
  
  console.log("Examples:");
  console.log("  node darkweb-scanner.js \"example.com\"");
  console.log("  node darkweb-scanner.js \"data breach\" --save\n");
  
  console.log("\x1b[33mNote: For full darkweb access, install Tor\x1b[0m");
  console.log("\x1b[33mInstall: pkg install tor\x1b[0m\n");
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
  
  const torInstalled = await checkTorInstalled();
  if (!torInstalled) {
    console.log("\x1b[33m⚠️  Tor not installed - using clearnet search only\x1b[0m");
    console.log("\x1b[33m   Install Tor for full darkweb access: pkg install tor\x1b[0m\n");
  }
  
  console.log(`⏳ Searching darkweb for: ${query}...\n`);
  
  const results = await searchAhmia(query);
  
  displayResults(results);
  
  if (saveResults_flag) {
    saveResults(results);
  }
  
  console.log("\x1b[31m██████╗  █████╗ ██████╗ ██╗  ██╗██╗    ██╗███████╗██████╗\x1b[0m");
  console.log("\x1b[35m🥝 Search complete - by kiwi & 777\x1b[0m\n");
}

main().catch(console.error);
