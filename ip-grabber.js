#!/usr/bin/env node

const fs = require('fs');

// ============================================
// IP GRABBER GENERATOR - Link Generator for IP Tracking
// ============================================

const GRABIFY_ALTERNATIVES = {
  grabify: {
    name: 'Grabify',
    url: 'https://grabify.link',
    method: 'manual',
    note: 'Most popular - Paste URL and get tracking link'
  },
  iplogger: {
    name: 'IPLogger',
    url: 'https://iplogger.org',
    method: 'manual',
    note: 'Feature-rich with detailed logs'
  },
  blasze: {
    name: 'Blasze',
    url: 'https://blasze.tk',
    method: 'manual',
    note: 'Simple and anonymous'
  },
  linkify: {
    name: 'Linkify',
    url: 'https://linkify.me',
    method: 'manual',
    note: 'Custom link shortening'
  },
  ps3cfw: {
    name: 'PS3CFW',
    url: 'https://ps3cfw.com/iplog',
    method: 'manual',
    note: 'Gaming community focused'
  },
  shortlink: {
    name: 'ShortLink',
    url: 'https://short.link',
    method: 'manual',
    note: 'Professional tracking'
  }
};

const TEMPLATES = {
  youtube: {
    name: 'YouTube Video',
    examples: [
      'https://www.youtube.com/watch?v=dQw4w9WgXcQ',
      'https://www.youtube.com/watch?v=9bZkp7q19f0',
      'https://www.youtube.com/watch?v=kJQP7kiw5Fk'
    ],
    description: 'Popular video links that look legitimate'
  },
  wikipedia: {
    name: 'Wikipedia Article',
    examples: [
      'https://en.wikipedia.org/wiki/Special:Random',
      'https://en.wikipedia.org/wiki/Internet_meme',
      'https://en.wikipedia.org/wiki/Privacy'
    ],
    description: 'Educational articles that don\'t raise suspicion'
  },
  news: {
    name: 'News Article',
    examples: [
      'https://www.bbc.com/news',
      'https://www.cnn.com/world',
      'https://www.reuters.com/technology'
    ],
    description: 'Current events and breaking news'
  },
  telegram: {
    name: 'Telegram Channel',
    examples: [
      'https://t.me/example',
      'https://t.me/news',
      'https://t.me/updates'
    ],
    description: 'Telegram group or channel invites'
  },
  github: {
    name: 'GitHub Repository',
    examples: [
      'https://github.com/trending',
      'https://github.com/topics/security',
      'https://github.com/topics/osint'
    ],
    description: 'Open source projects and code'
  },
  reddit: {
    name: 'Reddit Post',
    examples: [
      'https://www.reddit.com/r/funny',
      'https://www.reddit.com/r/pics',
      'https://www.reddit.com/r/todayilearned'
    ],
    description: 'Popular subreddit posts'
  },
  spotify: {
    name: 'Spotify Playlist',
    examples: [
      'https://open.spotify.com/playlist/37i9dQZF1DXcBWIGoYBM5M',
      'https://open.spotify.com/playlist/37i9dQZF1DX0XUsuxWHRQd',
      'https://open.spotify.com/playlist/37i9dQZEVXbMDoHDwVN2tF'
    ],
    description: 'Music playlists and tracks'
  },
  instagram: {
    name: 'Instagram Profile',
    examples: [
      'https://www.instagram.com/explore',
      'https://www.instagram.com/p/example',
      'https://www.instagram.com/reels'
    ],
    description: 'Posts, reels, and profiles'
  },
  tiktok: {
    name: 'TikTok Video',
    examples: [
      'https://www.tiktok.com/@user/video/1234567890',
      'https://www.tiktok.com/discover',
      'https://www.tiktok.com/trending'
    ],
    description: 'Trending videos and creators'
  },
  discord: {
    name: 'Discord Server',
    examples: [
      'https://discord.gg/example',
      'https://discord.com/invite/example',
      'https://discord.gg/AbCdEfGh'
    ],
    description: 'Server invites and communities'
  },
  random: {
    name: 'Random',
    examples: [
      'https://example.com/article',
      'https://example.com/download',
      'https://example.com/offer'
    ],
    description: 'Generic links'
  }
};

function generateLink(category) {
  const template = TEMPLATES[category] || TEMPLATES['random'];
  const randomExample = template.examples[Math.floor(Math.random() * template.examples.length)];
  
  return {
    category: category,
    name: template.name,
    description: template.description,
    exampleURL: randomExample,
    instructions: [
      '1. Copy the example URL above',
      '2. Visit one of the IP grabber services',
      '3. Paste the URL and generate tracking link',
      '4. Share the tracking link with target',
      '5. View IP logs on the service dashboard'
    ]
  };
}

function showBanner() {
  console.log("\x1b[31m");
  console.log("██╗██████╗      ██████╗ ██████╗  █████╗ ██████╗ ██████╗ ███████╗██████╗ ");
  console.log("██║██╔══██╗    ██╔════╝ ██╔══██╗██╔══██╗██╔══██╗██╔══██╗██╔════╝██╔══██╗");
  console.log("██║██████╔╝    ██║  ███╗██████╔╝███████║██████╔╝██████╔╝█████╗  ██████╔╝");
  console.log("██║██╔═══╝     ██║   ██║██╔══██╗██╔══██║██╔══██╗██╔══██╗██╔══╝  ██╔══██╗");
  console.log("██║██║         ╚██████╔╝██║  ██║██║  ██║██████╔╝██████╔╝███████╗██║  ██║");
  console.log("╚═╝╚═╝          ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝");
  console.log("\x1b[0m");
  console.log("\x1b[35m🥝 NIKA IP Grabber Generator - Link Generator for IP Tracking\x1b[0m");
  console.log("\x1b[31m⚠️  FOR AUTHORIZED TESTING ONLY - Unauthorized tracking is illegal!\x1b[0m\n");
}

function displayResult(data) {
  console.log("\n╔════════════════════════════════════════════════════════╗");
  console.log("║       🎣 IP GRABBER LINK GENERATED 🎣                  ║");
  console.log("╚════════════════════════════════════════════════════════╝\n");
  
  console.log(`📂 Category: \x1b[36m${data.name}\x1b[0m`);
  console.log(`📝 Description: ${data.description}\n`);
  
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
  console.log("\x1b[36m🔗 EXAMPLE URL TO USE\x1b[0m");
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
  
  console.log(`   ${data.exampleURL}\n`);
  
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
  console.log("\x1b[36m📋 INSTRUCTIONS\x1b[0m");
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
  
  data.instructions.forEach(instruction => {
    console.log(`   ${instruction}`);
  });
  console.log('');
  
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
  console.log("\x1b[36m🌐 IP GRABBER SERVICES\x1b[0m");
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
  
  Object.entries(GRABIFY_ALTERNATIVES).forEach(([key, service]) => {
    console.log(`   \x1b[32m${service.name}\x1b[0m`);
    console.log(`   URL: ${service.url}`);
    console.log(`   Note: ${service.note}\n`);
  });
  
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
  console.log("\x1b[36m💡 TIPS FOR SUCCESS\x1b[0m");
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
  
  console.log('   • Choose a URL relevant to your target');
  console.log('   • Use URL shorteners to hide the tracking domain');
  console.log('   • Add context when sharing the link (e.g., "Check this out!")');
  console.log('   • Monitor the dashboard for IP logs');
  console.log('   • Most services provide: IP, Location, Device, Browser');
  console.log('');
  
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
  console.log("\x1b[36m⚠️  LEGAL WARNING\x1b[0m");
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
  
  console.log('   \x1b[31m🚨 IMPORTANT:\x1b[0m');
  console.log('   • Only use for authorized security testing');
  console.log('   • Get explicit permission before tracking anyone');
  console.log('   • Unauthorized tracking may violate privacy laws');
  console.log('   • Use responsibly and ethically');
  console.log('');
}

function saveResults(data) {
  const dir = './ip-grabber-reports';
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, -5);
  const txtFile = `${dir}/${data.category}-${timestamp}.txt`;
  
  let txtContent = `═══════════════════════════════════════════════════════════
IP GRABBER LINK GENERATOR
═══════════════════════════════════════════════════════════

Category: ${data.name}
Description: ${data.description}
Generated: ${new Date().toLocaleString()}

═══════════════════════════════════════════════════════════
EXAMPLE URL
═══════════════════════════════════════════════════════════

${data.exampleURL}

═══════════════════════════════════════════════════════════
INSTRUCTIONS
═══════════════════════════════════════════════════════════

${data.instructions.join('\n')}

═══════════════════════════════════════════════════════════
IP GRABBER SERVICES
═══════════════════════════════════════════════════════════

`;

  Object.entries(GRABIFY_ALTERNATIVES).forEach(([key, service]) => {
    txtContent += `${service.name}\n`;
    txtContent += `URL: ${service.url}\n`;
    txtContent += `Note: ${service.note}\n\n`;
  });
  
  txtContent += `═══════════════════════════════════════════════════════════
LEGAL WARNING
═══════════════════════════════════════════════════════════

⚠️  IMPORTANT:
• Only use for authorized security testing
• Get explicit permission before tracking anyone
• Unauthorized tracking may violate privacy laws
• Use responsibly and ethically
`;

  fs.writeFileSync(txtFile, txtContent);
  
  console.log(`\x1b[32m✅ Results saved:\x1b[0m`);
  console.log(`   TXT: ${txtFile}\n`);
}

function showHelp() {
  showBanner();
  
  console.log("Usage: node ip-grabber.js [OPTIONS] <category>\n");
  console.log("Options:");
  console.log("  --save           Save link to file");
  console.log("  --list           List all available categories");
  console.log("  --help           Show this help\n");
  
  console.log("Available Categories:");
  Object.entries(TEMPLATES).forEach(([key, template]) => {
    console.log(`  ${key.padEnd(15)} - ${template.name}`);
  });
  console.log('');
  
  console.log("Examples:");
  console.log("  node ip-grabber.js youtube");
  console.log("  node ip-grabber.js telegram --save");
  console.log("  node ip-grabber.js --list\n");
}

function main() {
  const args = process.argv.slice(2);
  
  if (args.includes('--help') || args.length === 0) {
    showHelp();
    process.exit(0);
  }
  
  if (args.includes('--list')) {
    showBanner();
    console.log("Available Categories:\n");
    Object.entries(TEMPLATES).forEach(([key, template]) => {
      console.log(`\x1b[32m${key}\x1b[0m`);
      console.log(`  Name: ${template.name}`);
      console.log(`  Description: ${template.description}`);
      console.log(`  Examples: ${template.examples.length}`);
      console.log('');
    });
    process.exit(0);
  }
  
  let category = null;
  let saveResults_flag = false;
  
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--save') {
      saveResults_flag = true;
    } else if (!args[i].startsWith('--')) {
      category = args[i].toLowerCase();
    }
  }
  
  if (!category) {
    console.log("\x1b[31m❌ No category specified!\x1b[0m\n");
    showHelp();
    process.exit(1);
  }
  
  if (!TEMPLATES[category]) {
    console.log(`\x1b[31m❌ Invalid category: ${category}\x1b[0m`);
    console.log(`\x1b[33mUse --list to see available categories\x1b[0m\n`);
    process.exit(1);
  }
  
  showBanner();
  
  const result = generateLink(category);
  
  displayResult(result);
  
  if (saveResults_flag) {
    saveResults(result);
  }
  
  console.log("\x1b[31m██╗██████╗      ██████╗ ██████╗  █████╗ ██████╗ ██████╗ ███████╗██████╗\x1b[0m");
  console.log("\x1b[35m🥝 Link generated - by kiwi & 777\x1b[0m\n");
}

main();
