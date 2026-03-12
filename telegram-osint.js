#!/usr/bin/env node

const { exec } = require('child_process');
const { promisify } = require('util');
const execAsync = promisify(exec);
const fs = require('fs');

// ============================================
// TELEGRAM OSINT - Channel & User Intelligence
// ============================================

async function searchTelegramChannel(query) {
  const searches = {
    tgstat: `https://tgstat.com/search?q=${encodeURIComponent(query)}`,
    telegram_search: `https://www.telegram-search.com/?q=${encodeURIComponent(query)}`,
    lyzem: `https://lyzem.com/search?q=${encodeURIComponent(query)}`,
    tgchannels: `https://tgchannels.org/search/?q=${encodeURIComponent(query)}`,
    telegramdb: `https://telegramdb.org/search?q=${encodeURIComponent(query)}`,
    telemetr: `https://telemetr.io/en/channels?search=${encodeURIComponent(query)}`,
    combot: `https://combot.org/telegram/top/chats?q=${encodeURIComponent(query)}`,
    tdirectory: `https://tdirectory.me/search?q=${encodeURIComponent(query)}`
  };
  
  return searches;
}

async function getUserInfo(username) {
  // Remove @ if present
  username = username.replace('@', '');
  
  return {
    username: username,
    profileLink: `https://t.me/${username}`,
    webPreview: `https://t.me/s/${username}`,
    checks: {
      exists: `Check manually: https://t.me/${username}`,
      publicPosts: `View posts: https://t.me/s/${username}`,
      bot: username.toLowerCase().endsWith('bot')
    }
  };
}

function analyzeChannelLink(link) {
  const patterns = {
    publicChannel: /t\.me\/([a-zA-Z0-9_]+)/,
    privateChannel: /t\.me\/joinchat\/([a-zA-Z0-9_-]+)/,
    privateInvite: /t\.me\/\+([a-zA-Z0-9_-]+)/
  };
  
  let type = 'unknown';
  let identifier = null;
  
  if (patterns.publicChannel.test(link)) {
    type = 'public';
    identifier = link.match(patterns.publicChannel)[1];
  } else if (patterns.privateChannel.test(link)) {
    type = 'private_old';
    identifier = link.match(patterns.privateChannel)[1];
  } else if (patterns.privateInvite.test(link)) {
    type = 'private_new';
    identifier = link.match(patterns.privateInvite)[1];
  }
  
  return {
    type: type,
    identifier: identifier,
    link: link,
    isBot: identifier && identifier.toLowerCase().endsWith('bot'),
    webView: type === 'public' ? `https://t.me/s/${identifier}` : null
  };
}

function generateDorks(target) {
  return [
    `site:t.me "${target}"`,
    `site:t.me/s "${target}"`,
    `"t.me/${target}"`,
    `"@${target}" site:t.me`,
    `inurl:t.me "${target}"`,
    `site:web.telegram.org "${target}"`,
    `"telegram.me/${target}"`,
    `site:tgstat.com "${target}"`,
    `site:combot.org "${target}"`,
    `"${target}" telegram channel`,
    `"${target}" telegram group`,
    `"${target}" site:pastebin.com telegram`
  ];
}

function getChannelAnalytics() {
  return {
    tgstat: {
      name: 'TGStat',
      url: 'https://tgstat.com',
      features: ['Statistics', 'Growth charts', 'Post analytics', 'Mentions'],
      note: 'Best for channel statistics and analytics'
    },
    telemetr: {
      name: 'Telemetr',
      url: 'https://telemetr.io',
      features: ['Channel ratings', 'Subscriber growth', 'ER metrics'],
      note: 'Comprehensive channel metrics'
    },
    tgchannels: {
      name: 'TGChannels',
      url: 'https://tgchannels.org',
      features: ['Directory', 'Categories', 'Language filter'],
      note: 'Large channel directory'
    }
  };
}

function getScrapingTools() {
  return {
    manual: {
      name: 'Manual Web Preview',
      method: 'Visit https://t.me/s/channelname',
      note: 'View public posts without Telegram app',
      limitations: 'Limited to public channels only'
    },
    telethon: {
      name: 'Telethon (Python)',
      method: 'pip install telethon',
      note: 'Full API access for automation',
      requirements: 'API ID/Hash from my.telegram.org'
    },
    export: {
      name: 'Telegram Desktop Export',
      method: 'Settings > Advanced > Export Chat History',
      note: 'Official export feature',
      formats: 'JSON, HTML'
    },
    ArchiveTeam: {
      name: 'Archive Team Telegram',
      url: 'https://gitlab.com/derfnull/telegram-archive',
      note: 'Archive public channels',
      requirements: 'Command line tool'
    }
  };
}

function getSecurityTips() {
  return [
    'Phone Number Privacy: Check Settings > Privacy > Phone Number',
    'Last Seen: May reveal activity patterns',
    'Profile Photos: Can be downloaded and reverse searched',
    'Mutual Contacts: May reveal real identity',
    'Group Memberships: Visible in common groups',
    'Forwarded Messages: Preserve original sender info',
    'Username History: Old usernames may be cached',
    'Deleted Messages: Can sometimes be recovered by recipients',
    'Media Files: Contain metadata (EXIF)',
    'Bots: Can log interactions and data'
  ];
}

function showBanner() {
  console.log("\x1b[31m");
  console.log("████████╗███████╗██╗     ███████╗ ██████╗ ██████╗  █████╗ ███╗   ███╗");
  console.log("╚══██╔══╝██╔════╝██║     ██╔════╝██╔════╝ ██╔══██╗██╔══██╗████╗ ████║");
  console.log("   ██║   █████╗  ██║     █████╗  ██║  ███╗██████╔╝███████║██╔████╔██║");
  console.log("   ██║   ██╔══╝  ██║     ██╔══╝  ██║   ██║██╔══██╗██╔══██║██║╚██╔╝██║");
  console.log("   ██║   ███████╗███████╗███████╗╚██████╔╝██║  ██║██║  ██║██║ ╚═╝ ██║");
  console.log("   ╚═╝   ╚══════╝╚══════╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝");
  console.log("\x1b[0m");
  console.log("\x1b[35m🥝 NIKA Telegram OSINT - Channel & User Intelligence\x1b[0m");
  console.log("\x1b[33m⚠️  For OSINT research on public data only\x1b[0m\n");
}

function displayResults(data) {
  console.log("\n╔════════════════════════════════════════════════════════╗");
  console.log("║       📱 TELEGRAM OSINT RESULTS 📱                     ║");
  console.log("╚════════════════════════════════════════════════════════╝\n");
  
  console.log(`🎯 Target: \x1b[36m${data.target}\x1b[0m`);
  console.log(`📋 Mode: ${data.mode}\n`);
  
  if (data.mode === 'channel') {
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
    console.log("\x1b[36m🔍 CHANNEL SEARCH ENGINES\x1b[0m");
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
    
    Object.entries(data.searches).forEach(([name, url]) => {
      console.log(`   ${name}: ${url}`);
    });
    console.log('');
  }
  
  if (data.mode === 'user') {
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
    console.log("\x1b[36m👤 USER INFORMATION\x1b[0m");
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
    
    console.log(`   Username: @${data.userInfo.username}`);
    console.log(`   Profile Link: ${data.userInfo.profileLink}`);
    console.log(`   Web Preview: ${data.userInfo.webPreview}`);
    console.log(`   Is Bot: ${data.userInfo.checks.bot ? 'Yes' : 'Unknown'}`);
    console.log('');
  }
  
  if (data.mode === 'link') {
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
    console.log("\x1b[36m🔗 LINK ANALYSIS\x1b[0m");
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
    
    console.log(`   Type: ${data.linkInfo.type.toUpperCase()}`);
    console.log(`   Identifier: ${data.linkInfo.identifier}`);
    console.log(`   Original Link: ${data.linkInfo.link}`);
    if (data.linkInfo.webView) {
      console.log(`   Web View: ${data.linkInfo.webView}`);
    }
    console.log('');
  }
  
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
  console.log("\x1b[36m🔍 GOOGLE DORKS\x1b[0m");
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
  
  data.dorks.slice(0, 8).forEach((dork, i) => {
    console.log(`   ${i + 1}. ${dork}`);
  });
  console.log(`\n   ... and ${data.dorks.length - 8} more (see report)\n`);
  
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
  console.log("\x1b[36m📊 ANALYTICS PLATFORMS\x1b[0m");
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
  
  Object.entries(data.analytics).forEach(([key, platform]) => {
    console.log(`   \x1b[32m${platform.name}\x1b[0m`);
    console.log(`   URL: ${platform.url}`);
    console.log(`   Features: ${platform.features.join(', ')}`);
    console.log(`   Note: ${platform.note}\n`);
  });
  
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
  console.log("\x1b[36m🛠️  SCRAPING TOOLS\x1b[0m");
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
  
  Object.entries(data.tools).forEach(([key, tool]) => {
    console.log(`   \x1b[32m${tool.name}\x1b[0m`);
    if (tool.method) console.log(`   Method: ${tool.method}`);
    if (tool.url) console.log(`   URL: ${tool.url}`);
    console.log(`   Note: ${tool.note}\n`);
  });
  
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
  console.log("\x1b[36m🔒 PRIVACY & SECURITY TIPS\x1b[0m");
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
  
  data.securityTips.slice(0, 5).forEach(tip => {
    console.log(`   • ${tip}`);
  });
  console.log(`\n   ... and ${data.securityTips.length - 5} more tips (see report)\n`);
}

function saveResults(data) {
  const dir = './telegram-osint-reports';
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, -5);
  const targetSafe = data.target.replace(/[^a-z0-9]/gi, '_');
  const jsonFile = `${dir}/${targetSafe}-${timestamp}.json`;
  const txtFile = jsonFile.replace('.json', '.txt');
  
  fs.writeFileSync(jsonFile, JSON.stringify(data, null, 2));
  
  let txtContent = `═══════════════════════════════════════════════════════════
TELEGRAM OSINT REPORT
═══════════════════════════════════════════════════════════

Target: ${data.target}
Mode: ${data.mode}
Date: ${new Date(data.timestamp).toLocaleString()}

`;

  if (data.searches) {
    txtContent += `═══════════════════════════════════════════════════════════
CHANNEL SEARCH ENGINES
═══════════════════════════════════════════════════════════\n\n`;

    Object.entries(data.searches).forEach(([name, url]) => {
      txtContent += `${name}: ${url}\n`;
    });
  }
  
  if (data.userInfo) {
    txtContent += `\n═══════════════════════════════════════════════════════════
USER INFORMATION
═══════════════════════════════════════════════════════════\n\n`;

    txtContent += `Username: @${data.userInfo.username}\n`;
    txtContent += `Profile Link: ${data.userInfo.profileLink}\n`;
    txtContent += `Web Preview: ${data.userInfo.webPreview}\n`;
  }
  
  txtContent += `\n═══════════════════════════════════════════════════════════
GOOGLE DORKS
═══════════════════════════════════════════════════════════\n\n`;

  data.dorks.forEach((dork, i) => {
    txtContent += `${i + 1}. ${dork}\n`;
  });
  
  txtContent += `\n═══════════════════════════════════════════════════════════
ANALYTICS PLATFORMS
═══════════════════════════════════════════════════════════\n\n`;

  Object.entries(data.analytics).forEach(([key, platform]) => {
    txtContent += `${platform.name}\n`;
    txtContent += `URL: ${platform.url}\n`;
    txtContent += `Features: ${platform.features.join(', ')}\n`;
    txtContent += `Note: ${platform.note}\n\n`;
  });
  
  fs.writeFileSync(txtFile, txtContent);
  
  console.log(`\x1b[32m✅ Results saved:\x1b[0m`);
  console.log(`   JSON: ${jsonFile}`);
  console.log(`   TXT: ${txtFile}\n`);
}

function showHelp() {
  showBanner();
  
  console.log("Usage: node telegram-osint.js [OPTIONS] <target>\n");
  console.log("Options:");
  console.log("  --channel        Search for channel (default)");
  console.log("  --user           Lookup user information");
  console.log("  --link           Analyze Telegram link");
  console.log("  --save           Save results to file");
  console.log("  --help           Show this help\n");
  
  console.log("Examples:");
  console.log("  node telegram-osint.js channelname");
  console.log("  node telegram-osint.js @username --user");
  console.log("  node telegram-osint.js https://t.me/channel --link");
  console.log("  node telegram-osint.js keyword --channel --save\n");
}

async function main() {
  const args = process.argv.slice(2);
  
  if (args.includes('--help') || args.length === 0) {
    showHelp();
    process.exit(0);
  }
  
  let target = null;
  let mode = 'channel';
  let saveResults_flag = false;
  
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--channel') {
      mode = 'channel';
    } else if (args[i] === '--user') {
      mode = 'user';
    } else if (args[i] === '--link') {
      mode = 'link';
    } else if (args[i] === '--save') {
      saveResults_flag = true;
    } else if (!args[i].startsWith('--')) {
      target = args[i];
    }
  }
  
  if (!target) {
    console.log("\x1b[31m❌ No target specified!\x1b[0m\n");
    showHelp();
    process.exit(1);
  }
  
  showBanner();
  
  console.log(`⏳ Analyzing: ${target}...\n`);
  
  const results = {
    target: target,
    mode: mode,
    timestamp: new Date().toISOString(),
    searches: null,
    userInfo: null,
    linkInfo: null,
    dorks: generateDorks(target),
    analytics: getChannelAnalytics(),
    tools: getScrapingTools(),
    securityTips: getSecurityTips()
  };
  
  if (mode === 'channel') {
    results.searches = await searchTelegramChannel(target);
  } else if (mode === 'user') {
    results.userInfo = await getUserInfo(target);
  } else if (mode === 'link') {
    results.linkInfo = analyzeChannelLink(target);
  }
  
  displayResults(results);
  
  if (saveResults_flag) {
    saveResults(results);
  }
  
  console.log("\x1b[31m████████╗███████╗██╗     ███████╗ ██████╗ ██████╗  █████╗ ███╗   ███╗\x1b[0m");
  console.log("\x1b[35m🥝 Analysis complete - by kiwi & 777\x1b[0m\n");
}

main().catch(console.error);
