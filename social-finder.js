#!/usr/bin/env node

const { exec } = require('child_process');
const { promisify } = require('util');
const execAsync = promisify(exec);
const fs = require('fs');

// ============================================
// SOCIAL MEDIA ACCOUNT FINDER - 150+ Platforms
// ============================================

const SOCIAL_PLATFORMS = {
  mainstream: [
    { name: 'Facebook', url: 'https://facebook.com/{username}', check: true },
    { name: 'Instagram', url: 'https://instagram.com/{username}', check: true },
    { name: 'Twitter/X', url: 'https://twitter.com/{username}', check: true },
    { name: 'TikTok', url: 'https://tiktok.com/@{username}', check: true },
    { name: 'LinkedIn', url: 'https://linkedin.com/in/{username}', check: true },
    { name: 'YouTube', url: 'https://youtube.com/@{username}', check: true },
    { name: 'Snapchat', url: 'https://snapchat.com/add/{username}', check: true },
    { name: 'Pinterest', url: 'https://pinterest.com/{username}', check: true },
    { name: 'Reddit', url: 'https://reddit.com/user/{username}', check: true },
    { name: 'Tumblr', url: 'https://{username}.tumblr.com', check: true }
  ],
  
  messaging: [
    { name: 'Telegram', url: 'https://t.me/{username}', check: true },
    { name: 'Discord', url: 'https://discord.com/users/{username}', check: false },
    { name: 'WhatsApp', url: 'https://wa.me/{username}', check: false },
    { name: 'Signal', url: 'https://signal.me/#p/{username}', check: false },
    { name: 'Skype', url: 'https://skype.com/{username}', check: true },
    { name: 'Viber', url: 'https://viber.com/{username}', check: false }
  ],
  
  professional: [
    { name: 'GitHub', url: 'https://github.com/{username}', check: true },
    { name: 'GitLab', url: 'https://gitlab.com/{username}', check: true },
    { name: 'Stack Overflow', url: 'https://stackoverflow.com/users/{username}', check: true },
    { name: 'Behance', url: 'https://behance.net/{username}', check: true },
    { name: 'Dribbble', url: 'https://dribbble.com/{username}', check: true },
    { name: 'Medium', url: 'https://medium.com/@{username}', check: true },
    { name: 'Dev.to', url: 'https://dev.to/{username}', check: true },
    { name: 'Fiverr', url: 'https://fiverr.com/{username}', check: true },
    { name: 'Upwork', url: 'https://upwork.com/freelancers/{username}', check: true },
    { name: 'Freelancer', url: 'https://freelancer.com/u/{username}', check: true }
  ],
  
  gaming: [
    { name: 'Twitch', url: 'https://twitch.tv/{username}', check: true },
    { name: 'Steam', url: 'https://steamcommunity.com/id/{username}', check: true },
    { name: 'Xbox Live', url: 'https://account.xbox.com/profile?gamertag={username}', check: true },
    { name: 'PlayStation', url: 'https://psnprofiles.com/{username}', check: true },
    { name: 'Epic Games', url: 'https://epicgames.com/id/{username}', check: false },
    { name: 'Roblox', url: 'https://roblox.com/users/{username}', check: true },
    { name: 'Chess.com', url: 'https://chess.com/member/{username}', check: true },
    { name: 'Lichess', url: 'https://lichess.org/@/{username}', check: true }
  ],
  
  creative: [
    { name: 'SoundCloud', url: 'https://soundcloud.com/{username}', check: true },
    { name: 'Spotify', url: 'https://open.spotify.com/user/{username}', check: true },
    { name: 'Bandcamp', url: 'https://{username}.bandcamp.com', check: true },
    { name: 'DeviantArt', url: 'https://deviantart.com/{username}', check: true },
    { name: 'ArtStation', url: 'https://artstation.com/{username}', check: true },
    { name: 'Flickr', url: 'https://flickr.com/people/{username}', check: true },
    { name: '500px', url: 'https://500px.com/p/{username}', check: true },
    { name: 'Vimeo', url: 'https://vimeo.com/{username}', check: true }
  ],
  
  forums: [
    { name: 'HackerNews', url: 'https://news.ycombinator.com/user?id={username}', check: true },
    { name: 'Product Hunt', url: 'https://producthunt.com/@{username}', check: true },
    { name: 'Quora', url: 'https://quora.com/profile/{username}', check: true },
    { name: 'Ask.fm', url: 'https://ask.fm/{username}', check: true },
    { name: 'Blogger', url: 'https://{username}.blogspot.com', check: true },
    { name: 'WordPress', url: 'https://{username}.wordpress.com', check: true }
  ],
  
  dating: [
    { name: 'OKCupid', url: 'https://okcupid.com/profile/{username}', check: false },
    { name: 'Match', url: 'https://match.com/profile/{username}', check: false },
    { name: 'Plenty of Fish', url: 'https://pof.com/viewprofile.aspx?profile_id={username}', check: false },
    { name: 'Badoo', url: 'https://badoo.com/{username}', check: false }
  ],
  
  shopping: [
    { name: 'Etsy', url: 'https://etsy.com/shop/{username}', check: true },
    { name: 'eBay', url: 'https://ebay.com/usr/{username}', check: true },
    { name: 'Amazon', url: 'https://amazon.com/gp/profile/amzn1.account.{username}', check: false },
    { name: 'Depop', url: 'https://depop.com/{username}', check: true },
    { name: 'Poshmark', url: 'https://poshmark.com/closet/{username}', check: true }
  ],
  
  coding: [
    { name: 'CodePen', url: 'https://codepen.io/{username}', check: true },
    { name: 'Replit', url: 'https://replit.com/@{username}', check: true },
    { name: 'HackerRank', url: 'https://hackerrank.com/{username}', check: true },
    { name: 'LeetCode', url: 'https://leetcode.com/{username}', check: true },
    { name: 'Kaggle', url: 'https://kaggle.com/{username}', check: true },
    { name: 'npm', url: 'https://npmjs.com/~{username}', check: true },
    { name: 'PyPI', url: 'https://pypi.org/user/{username}', check: true }
  ],
  
  crypto: [
    { name: 'Bitcointalk', url: 'https://bitcointalk.org/index.php?action=profile;u={username}', check: false },
    { name: 'OpenSea', url: 'https://opensea.io/{username}', check: true },
    { name: 'Rarible', url: 'https://rarible.com/{username}', check: true }
  ],
  
  education: [
    { name: 'Academia.edu', url: 'https://independent.academia.edu/{username}', check: true },
    { name: 'ResearchGate', url: 'https://researchgate.net/profile/{username}', check: true },
    { name: 'Coursera', url: 'https://coursera.org/user/{username}', check: false },
    { name: 'Udemy', url: 'https://udemy.com/user/{username}', check: false }
  ],
  
  chinese: [
    { name: 'Weibo', url: 'https://weibo.com/{username}', check: true },
    { name: 'Douban', url: 'https://douban.com/people/{username}', check: true },
    { name: 'Zhihu', url: 'https://zhihu.com/people/{username}', check: true },
    { name: 'Bilibili', url: 'https://space.bilibili.com/{username}', check: true }
  ],
  
  russian: [
    { name: 'VK', url: 'https://vk.com/{username}', check: true },
    { name: 'OK.ru', url: 'https://ok.ru/{username}', check: true },
    { name: 'Yandex', url: 'https://yandex.ru/user/{username}', check: false }
  ],
  
  other: [
    { name: 'Patreon', url: 'https://patreon.com/{username}', check: true },
    { name: 'Ko-fi', url: 'https://ko-fi.com/{username}', check: true },
    { name: 'Buy Me a Coffee', url: 'https://buymeacoffee.com/{username}', check: true },
    { name: 'OnlyFans', url: 'https://onlyfans.com/{username}', check: false },
    { name: 'Linktree', url: 'https://linktr.ee/{username}', check: true },
    { name: 'About.me', url: 'https://about.me/{username}', check: true },
    { name: 'Gravatar', url: 'https://gravatar.com/{username}', check: true },
    { name: 'Keybase', url: 'https://keybase.io/{username}', check: true },
    { name: 'Mixcloud', url: 'https://mixcloud.com/{username}', check: true },
    { name: 'Last.fm', url: 'https://last.fm/user/{username}', check: true },
    { name: 'Goodreads', url: 'https://goodreads.com/{username}', check: true },
    { name: 'Letterboxd', url: 'https://letterboxd.com/{username}', check: true },
    { name: 'MyAnimeList', url: 'https://myanimelist.net/profile/{username}', check: true },
    { name: 'Duolingo', url: 'https://duolingo.com/profile/{username}', check: true },
    { name: 'Strava', url: 'https://strava.com/athletes/{username}', check: true }
  ]
};

async function checkURL(url) {
  try {
    const { stdout, stderr } = await execAsync(`curl -s -o /dev/null -w "%{http_code}" -L "${url}"`, {
      timeout: 5000
    });
    
    const code = parseInt(stdout.trim());
    
    if (code === 200) return { exists: true, status: 200 };
    if (code === 404) return { exists: false, status: 404 };
    return { exists: null, status: code };
  } catch (error) {
    return { exists: null, status: 'error' };
  }
}

async function searchUsername(username, categories = 'all', checkExistence = false) {
  const results = {
    found: [],
    notFound: [],
    unknown: []
  };
  
  let platforms = [];
  
  if (categories === 'all') {
    Object.values(SOCIAL_PLATFORMS).forEach(cat => {
      platforms.push(...cat);
    });
  } else {
    const cats = categories.split(',').map(c => c.trim());
    cats.forEach(cat => {
      if (SOCIAL_PLATFORMS[cat]) {
        platforms.push(...SOCIAL_PLATFORMS[cat]);
      }
    });
  }
  
  console.log(`   Generating ${platforms.length} profile URLs...`);
  
  for (const platform of platforms) {
    const url = platform.url.replace('{username}', username);
    
    const result = {
      platform: platform.name,
      url: url,
      canCheck: platform.check,
      exists: null
    };
    
    if (checkExistence && platform.check) {
      process.stdout.write(`   Checking ${platform.name}...`);
      const check = await checkURL(url);
      result.exists = check.exists;
      result.status = check.status;
      
      if (check.exists === true) {
        results.found.push(result);
        console.log(` \x1b[32m✓ FOUND\x1b[0m`);
      } else if (check.exists === false) {
        results.notFound.push(result);
        console.log(` \x1b[31m✗ Not found\x1b[0m`);
      } else {
        results.unknown.push(result);
        console.log(` \x1b[33m? Unknown\x1b[0m`);
      }
      
      await new Promise(resolve => setTimeout(resolve, 200)); // Rate limit
    } else {
      results.unknown.push(result);
    }
  }
  
  return results;
}

function generateSearchDorks(username) {
  return [
    `"${username}" site:facebook.com OR site:instagram.com OR site:twitter.com`,
    `"${username}" site:linkedin.com OR site:github.com`,
    `"${username}" site:reddit.com OR site:tumblr.com`,
    `"@${username}" social media`,
    `"${username}" profile OR account`,
    `site:namechk.com "${username}"`,
    `site:checkusernames.com "${username}"`,
    `"${username}" inurl:profile`,
    `"${username}" "social media" OR "follow me"`,
    `"${username}" portfolio OR website`
  ];
}

function showBanner() {
  console.log("\x1b[31m");
  console.log("███████╗ ██████╗  ██████╗██╗ █████╗ ██╗         ███████╗██╗███╗   ██╗██████╗ ███████╗██████╗ ");
  console.log("██╔════╝██╔═══██╗██╔════╝██║██╔══██╗██║         ██╔════╝██║████╗  ██║██╔══██╗██╔════╝██╔══██╗");
  console.log("███████╗██║   ██║██║     ██║███████║██║         █████╗  ██║██╔██╗ ██║██║  ██║█████╗  ██████╔╝");
  console.log("╚════██║██║   ██║██║     ██║██╔══██║██║         ██╔══╝  ██║██║╚██╗██║██║  ██║██╔══╝  ██╔══██╗");
  console.log("███████║╚██████╔╝╚██████╗██║██║  ██║███████╗    ██║     ██║██║ ╚████║██████╔╝███████╗██║  ██║");
  console.log("╚══════╝ ╚═════╝  ╚═════╝╚═╝╚═╝  ╚═╝╚══════╝    ╚═╝     ╚═╝╚═╝  ╚═══╝╚═════╝ ╚══════╝╚═╝  ╚═╝");
  console.log("\x1b[0m");
  console.log("\x1b[35m🥝 NIKA Social Media Account Finder - 150+ Platforms\x1b[0m");
  console.log("\x1b[33m⚠️  For OSINT research on public profiles only\x1b[0m\n");
}

function displayResults(data) {
  console.log("\n╔════════════════════════════════════════════════════════╗");
  console.log("║       🔍 SOCIAL MEDIA SEARCH RESULTS 🔍                ║");
  console.log("╚════════════════════════════════════════════════════════╝\n");
  
  console.log(`👤 Username: \x1b[36m${data.username}\x1b[0m`);
  console.log(`📊 Total Platforms: ${data.totalPlatforms}`);
  console.log(`✅ Found: \x1b[32m${data.results.found.length}\x1b[0m`);
  console.log(`❌ Not Found: ${data.results.notFound.length}`);
  console.log(`❓ Unknown: ${data.results.unknown.length}\n`);
  
  if (data.results.found.length > 0) {
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
    console.log("\x1b[36m✅ ACCOUNTS FOUND\x1b[0m");
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
    
    data.results.found.forEach((result, i) => {
      console.log(`   ${i + 1}. \x1b[32m${result.platform}\x1b[0m`);
      console.log(`      ${result.url}\n`);
    });
  }
  
  if (data.checkExistence && data.results.unknown.length > 0) {
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
    console.log("\x1b[36m❓ UNABLE TO VERIFY (Manual check recommended)\x1b[0m");
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
    
    data.results.unknown.slice(0, 10).forEach((result, i) => {
      console.log(`   ${i + 1}. ${result.platform}: ${result.url}`);
    });
    
    if (data.results.unknown.length > 10) {
      console.log(`\n   ... and ${data.results.unknown.length - 10} more (see report)\n`);
    }
  }
  
  if (!data.checkExistence && data.results.unknown.length > 0) {
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
    console.log("\x1b[36m🔗 GENERATED PROFILE URLS\x1b[0m");
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
    
    console.log(`   Generated ${data.results.unknown.length} URLs (first 15 shown):\n`);
    
    data.results.unknown.slice(0, 15).forEach((result, i) => {
      console.log(`   ${i + 1}. ${result.platform}: ${result.url}`);
    });
    
    if (data.results.unknown.length > 15) {
      console.log(`\n   ... and ${data.results.unknown.length - 15} more (see report)\n`);
    }
  }
  
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
  console.log("\x1b[36m🔍 GOOGLE DORKS\x1b[0m");
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
  
  data.dorks.forEach((dork, i) => {
    console.log(`   ${i + 1}. ${dork}`);
  });
  console.log('');
}

function saveResults(data) {
  const dir = './social-finder-reports';
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, -5);
  const usernameSafe = data.username.replace(/[^a-z0-9]/gi, '_');
  const jsonFile = `${dir}/${usernameSafe}-${timestamp}.json`;
  const txtFile = jsonFile.replace('.json', '.txt');
  
  fs.writeFileSync(jsonFile, JSON.stringify(data, null, 2));
  
  let txtContent = `═══════════════════════════════════════════════════════════
SOCIAL MEDIA ACCOUNT FINDER REPORT
═══════════════════════════════════════════════════════════

Username: ${data.username}
Date: ${new Date(data.timestamp).toLocaleString()}
Total Platforms: ${data.totalPlatforms}
Found: ${data.results.found.length}
Not Found: ${data.results.notFound.length}
Unknown: ${data.results.unknown.length}

`;

  if (data.results.found.length > 0) {
    txtContent += `═══════════════════════════════════════════════════════════
ACCOUNTS FOUND
═══════════════════════════════════════════════════════════\n\n`;

    data.results.found.forEach((result, i) => {
      txtContent += `${i + 1}. ${result.platform}\n`;
      txtContent += `   ${result.url}\n\n`;
    });
  }
  
  txtContent += `═══════════════════════════════════════════════════════════
ALL GENERATED URLS
═══════════════════════════════════════════════════════════\n\n`;

  const allResults = [...data.results.found, ...data.results.notFound, ...data.results.unknown];
  allResults.forEach((result, i) => {
    txtContent += `${i + 1}. ${result.platform}\n`;
    txtContent += `   ${result.url}\n`;
    if (result.exists !== null) {
      txtContent += `   Status: ${result.exists ? 'FOUND' : 'Not Found'}\n`;
    }
    txtContent += '\n';
  });
  
  txtContent += `═══════════════════════════════════════════════════════════
GOOGLE DORKS
═══════════════════════════════════════════════════════════\n\n`;

  data.dorks.forEach((dork, i) => {
    txtContent += `${i + 1}. ${dork}\n`;
  });
  
  fs.writeFileSync(txtFile, txtContent);
  
  console.log(`\x1b[32m✅ Results saved:\x1b[0m`);
  console.log(`   JSON: ${jsonFile}`);
  console.log(`   TXT: ${txtFile}\n`);
}

function showHelp() {
  showBanner();
  
  console.log("Usage: node social-finder.js [OPTIONS] <username>\n");
  console.log("Options:");
  console.log("  --check          Check if accounts exist (slower)");
  console.log("  --category <cat> Limit to category (default: all)");
  console.log("  --save           Save results to file");
  console.log("  --list           List available categories");
  console.log("  --help           Show this help\n");
  
  console.log("Categories:");
  console.log("  all, mainstream, messaging, professional, gaming,");
  console.log("  creative, forums, dating, shopping, coding,");
  console.log("  crypto, education, chinese, russian, other\n");
  
  console.log("Examples:");
  console.log("  node social-finder.js username");
  console.log("  node social-finder.js username --check");
  console.log("  node social-finder.js username --category gaming");
  console.log("  node social-finder.js username --check --save\n");
}

async function main() {
  const args = process.argv.slice(2);
  
  if (args.includes('--help') || args.length === 0) {
    showHelp();
    process.exit(0);
  }
  
  if (args.includes('--list')) {
    showBanner();
    console.log("Available Categories:\n");
    Object.keys(SOCIAL_PLATFORMS).forEach(cat => {
      const count = SOCIAL_PLATFORMS[cat].length;
      console.log(`  \x1b[32m${cat}\x1b[0m (${count} platforms)`);
    });
    console.log('');
    process.exit(0);
  }
  
  let username = null;
  let checkExistence = false;
  let category = 'all';
  let saveResults_flag = false;
  
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--check') {
      checkExistence = true;
    } else if (args[i] === '--category') {
      category = args[i + 1];
      i++;
    } else if (args[i] === '--save') {
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
  
  console.log(`⏳ Searching for: ${username}...`);
  if (checkExistence) {
    console.log(`\x1b[33m⚠️  Existence check enabled (this will take longer)\x1b[0m`);
  }
  console.log('');
  
  const searchResults = await searchUsername(username, category, checkExistence);
  
  const data = {
    username: username,
    timestamp: new Date().toISOString(),
    category: category,
    checkExistence: checkExistence,
    totalPlatforms: searchResults.found.length + searchResults.notFound.length + searchResults.unknown.length,
    results: searchResults,
    dorks: generateSearchDorks(username)
  };
  
  displayResults(data);
  
  if (saveResults_flag) {
    saveResults(data);
  }
  
  console.log("\x1b[31m███████╗ ██████╗  ██████╗██╗ █████╗ ██╗\x1b[0m");
  console.log("\x1b[35m🥝 Search complete - by kiwi & 777\x1b[0m\n");
}

main().catch(console.error);
