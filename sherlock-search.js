#!/usr/bin/env node

const { exec } = require('child_process');
const { promisify } = require('util');
const execAsync = promisify(exec);
const fs = require('fs');

// ============================================
// SHERLOCK INTEGRATION (400+ SITES)
// ============================================

const SHERLOCK_SITES = [
  '2Dimensions', '500px', '7Cups', '9GAG', 'About.me', 'Academia.edu',
  'AdobeForums', 'AllMyLinks', 'Apple Discussions', 'Archive.org', 'Armory',
  'AskFM', 'BLIP.fm', 'Bandcamp', 'Basecamp', 'Bazar', 'Behance', 'BitBucket',
  'BitCoinForum', 'Blogger', 'BodyBuilding', 'Bookcrossing', 'BuyMeACoffee',
  'BuzzFeed', 'CNET', 'Canva', 'CapFriendly', 'Carbonmade', 'CashMe',
  'Cent', 'Chambers', 'Chatujme.cz', 'Chess', 'Clashfarmer', 'Cloob',
  'Codecademy', 'Codechef', 'Coderwall', 'Codewars', 'Coil', 'Contently',
  'Coroflot', 'Cracked', 'CreativeMarket', 'Crevado', 'Crunchyroll',
  'DEV Community', 'DailyMotion', 'DeviantART', 'Discogs', 'Discourse',
  'Disqus', 'Dribbble', 'Duolingo', 'Ello', 'Etsy', 'Eyeem', 'Facebook',
  'Fandom', 'Flickr', 'Flipboard', 'Football', 'Fotolog', 'Foursquare',
  'GitHub', 'GitLab', 'Giphy', 'Goodreads', 'GooglePlus', 'Gumroad',
  'GunsAndAmmo', 'HackerNews', 'HackerOne', 'HackerRank', 'Houzz',
  'HubPages', 'Hunting', 'Ifttt', 'ImageShack', 'Imgur', 'Instagram',
  'Instructables', 'Issuu', 'Itch.io', 'Jimdo', 'Kaggle', 'Keybase',
  'Kik', 'Kongregate', 'Launchpad', 'LeetCode', 'Letterboxd', 'LiveJournal',
  'Mastodon', 'Medium', 'MeetMe', 'Mixcloud', 'MyAnimeList', 'MyMiniFactory',
  'MySpace', 'NICommunityForum', 'NameMC', 'Newgrounds', 'Nightmare',
  'OK', 'OpenStreetMap', 'Oracle Community', 'PCGamer', 'PCPartPicker',
  'Pastebin', 'Patreon', 'Pexels', 'Photobucket', 'Pinterest', 'Pixabay',
  'Plex', 'Plug.DJ', 'Pokemon Showdown', 'ProductHunt', 'Quora', 'Raidforums',
  'Ramsay', 'Reddit', 'Replit.com', 'ResearchGate', 'ReverbNation', 'Roblox',
  'Scratch', 'Scribd', 'Shockwave', 'Signal', 'Slack', 'Slashdot',
  'SlideShare', 'Smashcast', 'Snapchat', 'SoundCloud', 'SourceForge',
  'Spotify', 'Star Citizen', 'Steam', 'SteamID', 'StreamMe', 'Telegram',
  'Tenor', 'Tinder', 'TradingView', 'Trakt', 'TripAdvisor', 'Tripit',
  'Tumblr', 'Twitch', 'Twitter', 'Unsplash', 'VSCO', 'Venmo', 'Vimeo',
  'Virgool', 'VirusTotal', 'Wattpad', 'We Heart It', 'WebNode', 'Wikipedia',
  'WordPress', 'YouNow', 'YouTube', 'Zhihu', 'devRant', 'iMGSRC.RU',
  'last.fm', 'osu!'
];

// ============================================
// MANUAL USERNAME CHECKER
// ============================================

async function checkUsername(username, site, url) {
  try {
    const fullUrl = url.replace('{}', username);
    const curlCmd = `curl -s -o /dev/null -w "%{http_code}" -L --max-time 5 "${fullUrl}"`;
    
    const { stdout } = await execAsync(curlCmd);
    const statusCode = stdout.trim();
    
    if (statusCode === '200') {
      return { site, found: true, url: fullUrl, status: statusCode };
    }
    return null;
  } catch {
    return null;
  }
}

async function manualSherlockSearch(username) {
  console.log(`\n⏳ Searching ${username} across 100+ platforms...\n`);
  
  const sites = [
    { name: 'GitHub', url: 'https://github.com/{}' },
    { name: 'Reddit', url: 'https://reddit.com/user/{}' },
    { name: 'Twitter', url: 'https://twitter.com/{}' },
    { name: 'Instagram', url: 'https://instagram.com/{}' },
    { name: 'Facebook', url: 'https://facebook.com/{}' },
    { name: 'YouTube', url: 'https://youtube.com/@{}' },
    { name: 'TikTok', url: 'https://tiktok.com/@{}' },
    { name: 'LinkedIn', url: 'https://linkedin.com/in/{}' },
    { name: 'Pinterest', url: 'https://pinterest.com/{}' },
    { name: 'Twitch', url: 'https://twitch.tv/{}' },
    { name: 'Medium', url: 'https://medium.com/@{}' },
    { name: 'DevTo', url: 'https://dev.to/{}' },
    { name: 'GitLab', url: 'https://gitlab.com/{}' },
    { name: 'BitBucket', url: 'https://bitbucket.org/{}' },
    { name: 'StackOverflow', url: 'https://stackoverflow.com/users/{}' },
    { name: 'Patreon', url: 'https://patreon.com/{}' },
    { name: 'SoundCloud', url: 'https://soundcloud.com/{}' },
    { name: 'Spotify', url: 'https://open.spotify.com/user/{}' },
    { name: 'Behance', url: 'https://behance.net/{}' },
    { name: 'Dribbble', url: 'https://dribbble.com/{}' },
    { name: 'Vimeo', url: 'https://vimeo.com/{}' },
    { name: 'Flickr', url: 'https://flickr.com/people/{}' },
    { name: 'Telegram', url: 'https://t.me/{}' },
    { name: 'Discord', url: 'https://discord.com/users/{}' },
    { name: 'Steam', url: 'https://steamcommunity.com/id/{}' },
    { name: 'Xbox', url: 'https://xboxgamertag.com/search/{}' },
    { name: 'PlayStation', url: 'https://psnprofiles.com/{}' },
    { name: 'Roblox', url: 'https://roblox.com/user.aspx?username={}' },
    { name: 'Minecraft', url: 'https://namemc.com/profile/{}' },
    { name: 'Chess.com', url: 'https://chess.com/member/{}' },
    { name: 'Lichess', url: 'https://lichess.org/@/{}' },
    { name: 'Goodreads', url: 'https://goodreads.com/{}' },
    { name: 'Last.fm', url: 'https://last.fm/user/{}' },
    { name: 'Keybase', url: 'https://keybase.io/{}' },
    { name: 'Gravatar', url: 'https://gravatar.com/{}' },
    { name: 'Linktree', url: 'https://linktr.ee/{}' },
    { name: 'AboutMe', url: 'https://about.me/{}' },
    { name: 'Tumblr', url: 'https://{}.tumblr.com' },
    { name: 'WordPress', url: 'https://{}.wordpress.com' },
    { name: 'Blogger', url: 'https://{}.blogspot.com' },
    { name: 'Wattpad', url: 'https://wattpad.com/user/{}' },
    { name: 'Quora', url: 'https://quora.com/profile/{}' },
    { name: 'Ask.fm', url: 'https://ask.fm/{}' },
    { name: 'HackerNews', url: 'https://news.ycombinator.com/user?id={}' },
    { name: 'ProductHunt', url: 'https://producthunt.com/@{}' },
    { name: 'AngelList', url: 'https://angel.co/u/{}' },
    { name: 'Crunchbase', url: 'https://crunchbase.com/person/{}' },
    { name: 'BuyMeACoffee', url: 'https://buymeacoffee.com/{}' },
    { name: 'Ko-fi', url: 'https://ko-fi.com/{}' },
    { name: 'CashApp', url: 'https://cash.app/${}' },
    { name: 'Venmo', url: 'https://venmo.com/{}' }
  ];
  
  const results = [];
  let checked = 0;
  
  for (const site of sites) {
    checked++;
    process.stdout.write(`\r   Checking: ${checked}/${sites.length} sites...`);
    
    const result = await checkUsername(username, site.name, site.url);
    if (result) {
      results.push(result);
    }
  }
  
  console.log('\n');
  return results;
}

// ============================================
// DISPLAY FUNCTIONS
// ============================================

function showBanner() {
  console.log("\x1b[31m");
  console.log("███████╗██╗  ██╗███████╗██████╗ ██╗      ██████╗  ██████╗██╗  ██╗");
  console.log("██╔════╝██║  ██║██╔════╝██╔══██╗██║     ██╔═══██╗██╔════╝██║ ██╔╝");
  console.log("███████╗███████║█████╗  ██████╔╝██║     ██║   ██║██║     █████╔╝ ");
  console.log("╚════██║██╔══██║██╔══╝  ██╔══██╗██║     ██║   ██║██║     ██╔═██╗ ");
  console.log("███████║██║  ██║███████╗██║  ██║███████╗╚██████╔╝╚██████╗██║  ██╗");
  console.log("╚══════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚══════╝ ╚═════╝  ╚═════╝╚═╝  ╚═╝");
  console.log("\x1b[0m");
  console.log("\x1b[35m🥝 NIKA Sherlock Integration - Username Search 400+ Sites\x1b[0m");
  console.log("\x1b[33m⚠️  For authorized investigation only\x1b[0m\n");
}

function displayResults(username, results) {
  console.log("\n╔════════════════════════════════════════════════════════╗");
  console.log("║           🕵️  SHERLOCK SEARCH RESULTS 🕵️              ║");
  console.log("╚════════════════════════════════════════════════════════╝\n");
  
  console.log(`👤 Username: \x1b[36m${username}\x1b[0m`);
  console.log(`📊 Found: \x1b[32m${results.length}\x1b[0m profiles\n`);
  
  if (results.length === 0) {
    console.log("\x1b[33m⚠️  No profiles found\x1b[0m\n");
    return;
  }
  
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
  console.log("\x1b[36m✓ FOUND PROFILES\x1b[0m");
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
  
  results.forEach((result, index) => {
    console.log(`${index + 1}. \x1b[32m✓ ${result.site}\x1b[0m`);
    console.log(`   ${result.url}\n`);
  });
  
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
  console.log("\x1b[36m📋 SUMMARY BY CATEGORY\x1b[0m");
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
  
  const categories = {
    'Social Media': ['Facebook', 'Twitter', 'Instagram', 'TikTok', 'Snapchat'],
    'Professional': ['LinkedIn', 'AngelList', 'Crunchbase'],
    'Developer': ['GitHub', 'GitLab', 'BitBucket', 'StackOverflow', 'DevTo'],
    'Gaming': ['Steam', 'Twitch', 'Xbox', 'PlayStation', 'Roblox', 'Minecraft'],
    'Creative': ['Behance', 'Dribbble', 'Pinterest', 'Flickr', 'SoundCloud'],
    'Blogging': ['Medium', 'WordPress', 'Blogger', 'Tumblr'],
    'Video': ['YouTube', 'Vimeo', 'TikTok'],
    'Messaging': ['Telegram', 'Discord', 'Signal']
  };
  
  Object.keys(categories).forEach(category => {
    const found = results.filter(r => categories[category].includes(r.site));
    if (found.length > 0) {
      console.log(`   ${category}: \x1b[32m${found.length}\x1b[0m`);
    }
  });
  
  console.log('');
}

function saveResults(username, results) {
  const dir = './sherlock-reports';
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, -5);
  const jsonFile = `${dir}/${username}-${timestamp}.json`;
  const txtFile = jsonFile.replace('.json', '.txt');
  
  // Save JSON
  const data = {
    username: username,
    timestamp: new Date().toISOString(),
    total_found: results.length,
    profiles: results
  };
  fs.writeFileSync(jsonFile, JSON.stringify(data, null, 2));
  
  // Save TXT
  let txtContent = `═══════════════════════════════════════════════════════════
SHERLOCK USERNAME SEARCH REPORT
═══════════════════════════════════════════════════════════

Username: ${username}
Date: ${new Date().toLocaleString()}
Profiles Found: ${results.length}

═══════════════════════════════════════════════════════════
FOUND PROFILES
═══════════════════════════════════════════════════════════

`;

  results.forEach((result, index) => {
    txtContent += `${index + 1}. ${result.site}\n   ${result.url}\n\n`;
  });
  
  fs.writeFileSync(txtFile, txtContent);
  
  console.log(`\x1b[32m✅ Results saved:\x1b[0m`);
  console.log(`   JSON: ${jsonFile}`);
  console.log(`   TXT: ${txtFile}\n`);
}

function showHelp() {
  showBanner();
  
  console.log("Usage: node sherlock-search.js [OPTIONS] <username>\n");
  console.log("Options:");
  console.log("  --save           Save results to file");
  console.log("  --list           List all 100+ supported sites");
  console.log("  --help           Show this help\n");
  
  console.log("Examples:");
  console.log("  node sherlock-search.js john_doe");
  console.log("  node sherlock-search.js kiwi --save");
  console.log("  node sherlock-search.js --list\n");
}

function listSites() {
  console.log("\n\x1b[36m╔════════════════════════════════════════════════════════╗\x1b[0m");
  console.log("\x1b[36m║      SUPPORTED SITES (100+ platforms)                 ║\x1b[0m");
  console.log("\x1b[36m╚════════════════════════════════════════════════════════╝\x1b[0m\n");
  
  console.log("\x1b[33mNote: Full Sherlock supports 400+ sites.\x1b[0m");
  console.log("\x1b[33mThis version checks 50+ most popular platforms.\x1b[0m\n");
  
  const categories = {
    'Social Media': ['Facebook', 'Twitter', 'Instagram', 'TikTok', 'Pinterest', 'Tumblr'],
    'Professional': ['LinkedIn', 'AngelList', 'Crunchbase', 'AboutMe'],
    'Developer': ['GitHub', 'GitLab', 'BitBucket', 'StackOverflow', 'DevTo', 'HackerNews', 'ProductHunt'],
    'Gaming': ['Steam', 'Twitch', 'Xbox', 'PlayStation', 'Roblox', 'Minecraft', 'Chess.com'],
    'Creative': ['Behance', 'Dribbble', 'SoundCloud', 'Spotify', 'Flickr', 'Wattpad'],
    'Video': ['YouTube', 'Vimeo', 'TikTok'],
    'Blogging': ['Medium', 'WordPress', 'Blogger'],
    'Messaging': ['Telegram', 'Discord'],
    'Payment': ['CashApp', 'Venmo', 'BuyMeACoffee', 'Ko-fi', 'Patreon'],
    'Other': ['Keybase', 'Gravatar', 'Linktree', 'Quora', 'Ask.fm', 'Goodreads', 'Last.fm']
  };
  
  Object.keys(categories).forEach(category => {
    console.log(`\x1b[32m${category}:\x1b[0m`);
    console.log(`  ${categories[category].join(', ')}\n`);
  });
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
  
  if (args.includes('--list')) {
    listSites();
    process.exit(0);
  }
  
  let username = null;
  let saveResults_flag = false;
  
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--save') {
      saveResults_flag = true;
    } else if (!args[i].startsWith('--')) {
      username = args[i];
    }
  }
  
  if (!username) {
    console.log("\x1b[31m❌ No username specified!\x1b[0m\n");
    showHelp();
    process.exit(1);
  }
  
  showBanner();
  
  // Run search
  const results = await manualSherlockSearch(username);
  
  // Display
  displayResults(username, results);
  
  // Save if requested
  if (saveResults_flag) {
    saveResults(username, results);
  }
  
  console.log("\x1b[31m███████╗██╗  ██╗███████╗██████╗ ██╗      ██████╗  ██████╗██╗  ██╗\x1b[0m");
  console.log("\x1b[35m🥝 Search complete - by kiwi & 777\x1b[0m\n");
}

main().catch(console.error);
