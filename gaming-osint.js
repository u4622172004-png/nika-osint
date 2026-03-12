#!/usr/bin/env node

const https = require('https');
const http = require('http');
const fs = require('fs');

// ============================================
// GAMING OSINT - Gamertag Intelligence
// ============================================

const GAMING_PLATFORMS = {
  steam: {
    name: 'Steam',
    icon: '🎮',
    lookup: {
      profile: 'https://steamcommunity.com/id/',
      search: 'https://steamcommunity.com/search/users/#text=',
      api: 'https://steamcommunity.com/id/{username}/?xml=1'
    },
    features: ['Profile', 'Games library', 'Friends', 'Groups', 'Screenshots', 'Achievements'],
    data: ['Real name', 'Location', 'Join date', 'Level', 'VAC bans', 'Trade ban']
  },
  xbox: {
    name: 'Xbox Live',
    icon: '🎮',
    lookup: {
      profile: 'https://account.xbox.com/en-us/profile?gamertag=',
      search: 'https://xboxgamertag.com/search/',
      api: 'https://xbl.io/api/v2/friends'
    },
    features: ['Gamerscore', 'Achievements', 'Games played', 'Clips', 'Screenshots'],
    data: ['Gamertag', 'Real name', 'Bio', 'Location', 'Tenure', 'Rep']
  },
  psn: {
    name: 'PlayStation Network',
    icon: '🎮',
    lookup: {
      profile: 'https://psnprofiles.com/',
      search: 'https://psnprofiles.com/search/users?q=',
      api: 'https://us-tpy.np.community.playstation.net/userProfile/v1/users/'
    },
    features: ['Trophies', 'Games', 'Level', 'Rarity', 'Friends'],
    data: ['PSN ID', 'Avatar', 'About me', 'Level', 'Platinum count']
  },
  epic: {
    name: 'Epic Games',
    icon: '🎮',
    lookup: {
      profile: 'https://fortnitetracker.com/profile/all/',
      search: 'https://fortnitetracker.com/profile/all/',
      leaderboard: 'https://fortnitetracker.com/leaderboards'
    },
    features: ['Fortnite stats', 'K/D ratio', 'Wins', 'Matches played'],
    data: ['Display name', 'Level', 'Stats', 'Season data']
  },
  discord: {
    name: 'Discord',
    icon: '💬',
    lookup: {
      profile: 'https://discord.id/',
      search: 'https://discord.id/?prefill=',
      lookup_by_id: 'https://discordlookup.com/user/'
    },
    features: ['User ID', 'Servers', 'Badges', 'Creation date', 'Avatar'],
    data: ['Username', 'Discriminator', 'ID', 'Badges', 'Bio', 'Servers']
  },
  twitch: {
    name: 'Twitch',
    icon: '📺',
    lookup: {
      profile: 'https://www.twitch.tv/',
      search: 'https://www.twitch.tv/search?term=',
      stats: 'https://twitchtracker.com/'
    },
    features: ['Streams', 'Clips', 'Followers', 'VODs', 'Chat logs'],
    data: ['Display name', 'Bio', 'Join date', 'Follower count', 'Stream schedule']
  },
  riot: {
    name: 'Riot Games',
    icon: '⚔️',
    lookup: {
      lol: 'https://www.op.gg/summoners/',
      valorant: 'https://tracker.gg/valorant/profile/riot/',
      tft: 'https://lolchess.gg/profile/'
    },
    features: ['Rank', 'Win rate', 'Champions', 'Match history', 'MMR'],
    data: ['Summoner name', 'Region', 'Level', 'Rank', 'LP']
  },
  minecraft: {
    name: 'Minecraft',
    icon: '🧱',
    lookup: {
      namemc: 'https://namemc.com/profile/',
      uuid: 'https://api.mojang.com/users/profiles/minecraft/',
      history: 'https://namemc.com/profile/'
    },
    features: ['UUID', 'Name history', 'Skins', 'Capes', 'Servers'],
    data: ['Current name', 'Past names', 'Skin', 'First seen']
  },
  battlenet: {
    name: 'Battle.net',
    icon: '⚔️',
    lookup: {
      overwatch: 'https://playoverwatch.com/en-us/career/',
      wow: 'https://worldofwarcraft.com/en-us/character/',
      diablo: 'https://diablo3.com/en-us/profile/'
    },
    features: ['Heroes', 'Stats', 'Competitive rank', 'Play time'],
    data: ['BattleTag', 'Level', 'Competitive rating', 'Heroes played']
  }
};

const GAMING_TRACKERS = {
  general: {
    'SteamID.uk': 'https://steamid.uk/',
    'NameMC': 'https://namemc.com/',
    'Xbox Gamertag': 'https://xboxgamertag.com/',
    'PSNProfiles': 'https://psnprofiles.com/'
  },
  stats: {
    'Tracker Network': 'https://tracker.gg/',
    'OP.GG': 'https://op.gg/',
    'Fortnite Tracker': 'https://fortnitetracker.com/',
    'Apex Tracker': 'https://apex.tracker.gg/',
    'COD Tracker': 'https://cod.tracker.gg/',
    'Destiny Tracker': 'https://destinytracker.com/'
  },
  community: {
    'Steam Community': 'https://steamcommunity.com/',
    'Reddit Gaming': 'https://reddit.com/r/gaming',
    'Discord Servers': 'https://disboard.org/',
    'Twitch': 'https://twitch.tv/'
  }
};

const CROSS_REFERENCE = [
  'Check if username exists on multiple platforms',
  'Look for linked social media in bio/profile',
  'Search Steam/Discord for real name leaks',
  'Check Twitch for face reveals',
  'Look for YouTube channels with same name',
  'Search Reddit for username posts',
  'Check Twitter for gaming handle',
  'Look for email in Steam profile (if public)',
  'Search Discord servers they\'re in',
  'Check for leaked voice in Discord/Twitch'
];

function showBanner() {
  console.log("\x1b[31m");
  console.log(" ██████╗  █████╗ ███╗   ███╗██╗███╗   ██╗ ██████╗      ██████╗ ███████╗██╗███╗   ██╗████████╗");
  console.log("██╔════╝ ██╔══██╗████╗ ████║██║████╗  ██║██╔════╝     ██╔═══██╗██╔════╝██║████╗  ██║╚══██╔══╝");
  console.log("██║  ███╗███████║██╔████╔██║██║██╔██╗ ██║██║  ███╗    ██║   ██║███████╗██║██╔██╗ ██║   ██║   ");
  console.log("██║   ██║██╔══██║██║╚██╔╝██║██║██║╚██╗██║██║   ██║    ██║   ██║╚════██║██║██║╚██╗██║   ██║   ");
  console.log("╚██████╔╝██║  ██║██║ ╚═╝ ██║██║██║ ╚████║╚██████╔╝    ╚██████╔╝███████║██║██║ ╚████║   ██║   ");
  console.log(" ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝╚═╝╚═╝  ╚═══╝ ╚═════╝      ╚═════╝ ╚══════╝╚═╝╚═╝  ╚═══╝   ╚═╝   ");
  console.log("\x1b[0m");
  console.log("\x1b[35m🥝 NIKA Gaming OSINT - Gamertag Intelligence\x1b[0m");
  console.log("\x1b[33m⚠️  For authorized investigation only\x1b[0m\n");
}

function generateSearchLinks(username) {
  const links = {};
  
  Object.entries(GAMING_PLATFORMS).forEach(([platform, data]) => {
    links[platform] = {};
    
    Object.entries(data.lookup).forEach(([type, url]) => {
      if (type === 'profile' || type === 'search') {
        links[platform][type] = url + encodeURIComponent(username);
      } else {
        links[platform][type] = url.replace('{username}', encodeURIComponent(username));
      }
    });
  });
  
  return links;
}

function generateGoogleDorks(username) {
  return [
    `"${username}" site:steamcommunity.com`,
    `"${username}" site:twitch.tv`,
    `"${username}" site:discord.com`,
    `"${username}" site:reddit.com/r/gaming`,
    `"${username}" "gamertag" OR "PSN" OR "Xbox"`,
    `"${username}" "Steam" OR "Discord"`,
    `"${username}" site:youtube.com gaming`,
    `"${username}" site:twitter.com gamer`,
    `"${username}" "Fortnite" OR "Valorant" OR "COD"`,
    `"${username}" "streaming" OR "streamer"`,
    `"${username}" inurl:profile gaming`,
    `"${username}" "add me" OR "friend me"`
  ];
}

function displayResults(data) {
  console.log("\n╔════════════════════════════════════════════════════════╗");
  console.log("║       🎮 GAMING OSINT RESULTS 🎮                       ║");
  console.log("╚════════════════════════════════════════════════════════╝\n");
  
  console.log(`🎯 Username: \x1b[36m${data.username}\x1b[0m\n`);
  
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
  console.log("\x1b[36m🎮 GAMING PLATFORMS\x1b[0m");
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
  
  Object.entries(GAMING_PLATFORMS).forEach(([platform, info]) => {
    console.log(`   ${info.icon} \x1b[32m${info.name}\x1b[0m`);
    
    if (data.searchLinks[platform]) {
      Object.entries(data.searchLinks[platform]).forEach(([type, url]) => {
        console.log(`      ${type}: ${url}`);
      });
    }
    
    console.log(`      Features: ${info.features.slice(0, 3).join(', ')}`);
    console.log(`      Data: ${info.data.slice(0, 3).join(', ')}\n`);
  });
  
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
  console.log("\x1b[36m📊 GAMING TRACKERS & STATS\x1b[0m");
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
  
  console.log('   \x1b[32mGeneral Trackers:\x1b[0m');
  Object.entries(GAMING_TRACKERS.general).forEach(([name, url]) => {
    console.log(`      • ${name}: ${url}`);
  });
  console.log('');
  
  console.log('   \x1b[32mStats Trackers:\x1b[0m');
  Object.entries(GAMING_TRACKERS.stats).forEach(([name, url]) => {
    console.log(`      • ${name}: ${url}`);
  });
  console.log('');
  
  console.log('   \x1b[32mCommunity Sites:\x1b[0m');
  Object.entries(GAMING_TRACKERS.community).forEach(([name, url]) => {
    console.log(`      • ${name}: ${url}`);
  });
  console.log('');
  
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
  console.log("\x1b[36m🔍 GOOGLE DORKS (First 6)\x1b[0m");
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
  
  data.googleDorks.slice(0, 6).forEach((dork, i) => {
    console.log(`   ${i + 1}. ${dork}`);
  });
  console.log(`\n   ... and ${data.googleDorks.length - 6} more dorks\n`);
  
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
  console.log("\x1b[36m🔗 CROSS-REFERENCE TECHNIQUES\x1b[0m");
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
  
  CROSS_REFERENCE.forEach((tip, i) => {
    console.log(`   ${i + 1}. ${tip}`);
  });
  console.log('');
  
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
  console.log("\x1b[36m💡 INVESTIGATION WORKFLOW\x1b[0m");
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
  
  console.log('   \x1b[32m1. Initial Search:\x1b[0m');
  console.log('      • Check all major platforms (Steam, Xbox, PSN)');
  console.log('      • Look for profile pictures (reverse image search)');
  console.log('      • Note any real names or locations in bio\n');
  
  console.log('   \x1b[32m2. Deep Dive:\x1b[0m');
  console.log('      • Check friends lists for mutual connections');
  console.log('      • Look at game libraries for interests');
  console.log('      • Check achievements for activity patterns');
  console.log('      • Review screenshots/clips for data leaks\n');
  
  console.log('   \x1b[32m3. Social Links:\x1b[0m');
  console.log('      • Check for linked Twitch/YouTube');
  console.log('      • Search Discord servers they\'re in');
  console.log('      • Look for Reddit posts with username');
  console.log('      • Check Twitter for same handle\n');
  
  console.log('   \x1b[32m4. Data Collection:\x1b[0m');
  console.log('      • Save profile URLs and IDs');
  console.log('      • Screenshot profiles (evidence)');
  console.log('      • Note join dates and activity');
  console.log('      • Document all connected accounts\n');
  
  console.log('   \x1b[32m5. Timeline Analysis:\x1b[0m');
  console.log('      • Check account creation dates');
  console.log('      • Look for name change history');
  console.log('      • Analyze posting patterns');
  console.log('      • Check for gaps in activity\n');
}

function saveReport(data) {
  const dir = './gaming-osint-reports';
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, -5);
  const filename = `${dir}/gaming-${data.username}-${timestamp}.txt`;
  
  let content = `═══════════════════════════════════════════════════════════
GAMING OSINT REPORT
═══════════════════════════════════════════════════════════

Username: ${data.username}
Date: ${new Date().toLocaleString()}

PLATFORM SEARCH LINKS:
`;

  Object.entries(data.searchLinks).forEach(([platform, links]) => {
    content += `\n${GAMING_PLATFORMS[platform].name}:\n`;
    Object.entries(links).forEach(([type, url]) => {
      content += `  ${type}: ${url}\n`;
    });
  });
  
  content += `\nGOOGLE DORKS:\n`;
  data.googleDorks.forEach((dork, i) => {
    content += `${i + 1}. ${dork}\n`;
  });
  
  content += `\nCROSS-REFERENCE TECHNIQUES:\n`;
  CROSS_REFERENCE.forEach((tip, i) => {
    content += `${i + 1}. ${tip}\n`;
  });
  
  fs.writeFileSync(filename, content);
  console.log(`\x1b[32m✅ Report saved: ${filename}\x1b[0m\n`);
}

function showHelp() {
  showBanner();
  
  console.log("Usage: node gaming-osint.js <username> [--save]\n");
  console.log("Options:");
  console.log("  --save               Save report to file");
  console.log("  --list               List all platforms");
  console.log("  --help               Show this help\n");
  
  console.log("Examples:");
  console.log("  node gaming-osint.js ProGamer123");
  console.log("  node gaming-osint.js xXSniperXx --save");
  console.log("  node gaming-osint.js --list\n");
}

function main() {
  const args = process.argv.slice(2);
  
  if (args.length === 0 || args.includes('--help')) {
    showHelp();
    process.exit(0);
  }
  
  showBanner();
  
  if (args.includes('--list')) {
    console.log("Available Gaming Platforms:\n");
    Object.entries(GAMING_PLATFORMS).forEach(([key, platform]) => {
      console.log(`   ${platform.icon} \x1b[32m${platform.name}\x1b[0m`);
      console.log(`      Features: ${platform.features.join(', ')}\n`);
    });
    process.exit(0);
  }
  
  let username = null;
  let saveFlag = false;
  
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--save') {
      saveFlag = true;
    } else if (!args[i].startsWith('--')) {
      username = args[i];
    }
  }
  
  if (!username) {
    console.log("\x1b[31m❌ No username specified!\x1b[0m\n");
    showHelp();
    process.exit(1);
  }
  
  console.log(`⏳ Searching for username: ${username}...\n`);
  
  const results = {
    timestamp: new Date().toISOString(),
    username: username,
    searchLinks: generateSearchLinks(username),
    googleDorks: generateGoogleDorks(username)
  };
  
  displayResults(results);
  
  if (saveFlag) {
    saveReport(results);
  }
  
  console.log("\x1b[31m ██████╗  █████╗ ███╗   ███╗██╗███╗   ██╗ ██████╗ \x1b[0m");
  console.log("\x1b[35m🥝 Search complete - by kiwi & 777\x1b[0m\n");
}

main();
