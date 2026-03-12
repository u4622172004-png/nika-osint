#!/usr/bin/env node

const https = require('https');
const fs = require('fs');

// ============================================
// MESSAGING APP OSINT - Messaging Intelligence
// ============================================

const MESSAGING_PLATFORMS = {
  whatsapp: {
    name: 'WhatsApp',
    icon: '📱',
    checkMethods: {
      web: {
        name: 'WhatsApp Web Check',
        url: 'https://web.whatsapp.com/',
        method: 'Manual - Add contact and check if account exists',
        features: ['Profile photo', 'Status', 'Last seen', 'About']
      },
      api: {
        name: 'WhatsApp Business API',
        note: 'Requires business account',
        cost: 'Paid'
      }
    },
    dataPoints: ['Phone number', 'Profile picture', 'Status message', 'Last seen', 'Groups in common'],
    privacy: 'Can hide last seen, profile photo, status',
    format: 'E.164 format (+1234567890)'
  },
  telegram: {
    name: 'Telegram',
    icon: '✈️',
    checkMethods: {
      username: {
        name: 'Username Search',
        url: 'https://t.me/',
        method: 'Direct URL: t.me/username',
        features: ['Public profiles', 'Channels', 'Groups']
      },
      phone: {
        name: 'Phone Number Check',
        method: 'Add contact in Telegram app',
        features: ['Check if number has Telegram']
      },
      bots: {
        name: 'OSINT Bots',
        examples: ['@username_to_id_bot', '@getidsbot'],
        features: ['Get user ID', 'Check username availability']
      }
    },
    dataPoints: ['Username', 'User ID', 'Phone (if shared)', 'Bio', 'Profile photo', 'Channels/Groups'],
    privacy: 'Username can be hidden, phone optional',
    format: 'Username (@example) or phone'
  },
  signal: {
    name: 'Signal',
    icon: '🔒',
    checkMethods: {
      phone: {
        name: 'Phone Number Check',
        method: 'Add contact in Signal app',
        note: 'Only shows if number uses Signal'
      }
    },
    dataPoints: ['Phone number', 'Profile name', 'Profile photo'],
    privacy: 'Very private - minimal metadata',
    format: 'Phone number only'
  },
  discord: {
    name: 'Discord',
    icon: '🎮',
    checkMethods: {
      username: {
        name: 'Username Search',
        format: 'username#1234',
        tools: ['Discord Lookup websites', 'Bots']
      },
      id: {
        name: 'User ID Lookup',
        tools: ['https://discord.id/', 'https://discordlookup.com/'],
        features: ['Profile', 'Avatar', 'Creation date', 'Badges']
      }
    },
    dataPoints: ['Username', 'Discriminator', 'User ID', 'Avatar', 'Banner', 'Badges', 'Servers', 'Bio'],
    privacy: 'Public by default, can limit DMs',
    format: 'username#1234 or User ID'
  },
  snapchat: {
    name: 'Snapchat',
    icon: '👻',
    checkMethods: {
      username: {
        name: 'Username Search',
        url: 'https://www.snapchat.com/add/',
        method: 'snapchat.com/add/username',
        features: ['Public profiles', 'Snap Map']
      },
      snapmap: {
        name: 'Snap Map',
        url: 'https://map.snapchat.com/',
        features: ['Location sharing', 'Stories'],
        note: 'Only if user shares location publicly'
      }
    },
    dataPoints: ['Username', 'Display name', 'Snapcode', 'Bitmoji', 'Story', 'Location'],
    privacy: 'Can hide from search, disable Snap Map',
    format: 'Username'
  },
  wechat: {
    name: 'WeChat',
    icon: '💬',
    checkMethods: {
      id: {
        name: 'WeChat ID Search',
        method: 'Add friend in app',
        features: ['QR code scan', 'ID search']
      }
    },
    dataPoints: ['WeChat ID', 'QR code', 'Name', 'Location', 'Moments'],
    privacy: 'Can require verification to add',
    format: 'WeChat ID',
    region: 'Popular in China/Asia'
  },
  viber: {
    name: 'Viber',
    icon: '📞',
    checkMethods: {
      phone: {
        name: 'Phone Number Check',
        method: 'Add contact in Viber app',
        features: ['Check if number uses Viber']
      }
    },
    dataPoints: ['Phone number', 'Name', 'Status', 'Profile photo'],
    privacy: 'Phone-based, can hide online status',
    format: 'Phone number'
  }
};

const LOOKUP_TOOLS = {
  phoneNumber: {
    'WhatsApp Checker': {
      method: 'Manual - WhatsApp Web',
      cost: 'Free'
    },
    'Signal Check': {
      method: 'Add contact in Signal',
      cost: 'Free'
    },
    'Telegram Check': {
      method: 'Add contact in Telegram',
      cost: 'Free'
    },
    'Viber Check': {
      method: 'Add contact in Viber',
      cost: 'Free'
    }
  },
  username: {
    'Telegram': 'https://t.me/username',
    'Discord ID': 'https://discord.id/',
    'Discord Lookup': 'https://discordlookup.com/',
    'Snapchat': 'https://www.snapchat.com/add/username'
  },
  general: {
    'Sherlock': {
      name: 'Sherlock Project',
      url: 'https://github.com/sherlock-project/sherlock',
      note: 'Username search across 300+ sites (includes some messaging)'
    }
  }
};

const TELEGRAM_OSINT = {
  bots: {
    'username_to_id_bot': {
      function: 'Get Telegram user ID from username',
      command: '@username_to_id_bot'
    },
    'getidsbot': {
      function: 'Get user/chat/channel IDs',
      command: '@getidsbot'
    },
    'userinfobot': {
      function: 'Get detailed user information',
      command: '@userinfobot'
    }
  },
  tools: {
    'Telegram Database': {
      url: 'https://telegramdb.org/',
      features: ['Channel search', 'Group search', 'User search']
    },
    'Telegram Analytics': {
      url: 'https://tgstat.com/',
      features: ['Channel analytics', 'User statistics']
    }
  },
  search: {
    channels: 'Use @TelegramDB_bot or telegramdb.org',
    groups: 'Search within Telegram app',
    messages: 'Use Telegram search (only in joined groups/channels)'
  }
};

const DISCORD_OSINT = {
  tools: {
    'Discord ID': {
      url: 'https://discord.id/',
      features: ['User lookup', 'Avatar', 'Creation date']
    },
    'Discord Lookup': {
      url: 'https://discordlookup.com/',
      features: ['User info', 'Server info', 'Invite lookup']
    },
    'Discord History Tracker': {
      url: 'https://dht.chylex.com/',
      type: 'Browser extension',
      features: ['Archive messages', 'Export data']
    }
  },
  userIdFormat: {
    format: '18-digit number',
    example: '123456789012345678',
    location: 'Right-click user → Copy ID (requires Developer Mode)'
  },
  developerMode: {
    enable: 'Settings → Advanced → Developer Mode',
    allows: 'Copy IDs for users, channels, servers'
  }
};

function showBanner() {
  console.log("\x1b[31m");
  console.log("███╗   ███╗███████╗███████╗███████╗ █████╗  ██████╗ ██╗███╗   ██╗ ██████╗ ");
  console.log("████╗ ████║██╔════╝██╔════╝██╔════╝██╔══██╗██╔════╝ ██║████╗  ██║██╔════╝ ");
  console.log("██╔████╔██║█████╗  ███████╗███████╗███████║██║  ███╗██║██╔██╗ ██║██║  ███╗");
  console.log("██║╚██╔╝██║██╔══╝  ╚════██║╚════██║██╔══██║██║   ██║██║██║╚██╗██║██║   ██║");
  console.log("██║ ╚═╝ ██║███████╗███████║███████║██║  ██║╚██████╔╝██║██║ ╚████║╚██████╔╝");
  console.log("╚═╝     ╚═╝╚══════╝╚══════╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝╚═╝  ╚═══╝ ╚═════╝ ");
  console.log("                                                                            ");
  console.log(" ██████╗ ███████╗██╗███╗   ██╗████████╗");
  console.log("██╔═══██╗██╔════╝██║████╗  ██║╚══██╔══╝");
  console.log("██║   ██║███████╗██║██╔██╗ ██║   ██║   ");
  console.log("██║   ██║╚════██║██║██║╚██╗██║   ██║   ");
  console.log("╚██████╔╝███████║██║██║ ╚████║   ██║   ");
  console.log(" ╚═════╝ ╚══════╝╚═╝╚═╝  ╚═══╝   ╚═╝   ");
  console.log("\x1b[0m");
  console.log("\x1b[35m🥝 NIKA Messaging OSINT - Messaging App Intelligence\x1b[0m");
  console.log("\x1b[33m⚠️  For authorized investigation only - Respect privacy\x1b[0m\n");
}

function parseIdentifier(input) {
  const cleaned = input.trim();
  
  // Phone number (E.164 format)
  if (/^\+?\d{7,15}$/.test(cleaned.replace(/[\s-]/g, ''))) {
    return {
      type: 'phone',
      value: cleaned,
      formatted: cleaned.startsWith('+') ? cleaned : '+' + cleaned,
      platforms: ['WhatsApp', 'Signal', 'Telegram', 'Viber']
    };
  }
  
  // Telegram username (@username)
  if (/^@?[a-zA-Z0-9_]{5,32}$/.test(cleaned)) {
    return {
      type: 'telegram_username',
      value: cleaned.startsWith('@') ? cleaned : '@' + cleaned,
      platforms: ['Telegram']
    };
  }
  
  // Discord username (username#1234)
  if (/^.+#\d{4}$/.test(cleaned)) {
    return {
      type: 'discord_username',
      value: cleaned,
      platforms: ['Discord']
    };
  }
  
  // Discord User ID (18 digits)
  if (/^\d{17,19}$/.test(cleaned)) {
    return {
      type: 'discord_id',
      value: cleaned,
      platforms: ['Discord']
    };
  }
  
  // Generic username
  if (/^[a-zA-Z0-9_.-]{3,30}$/.test(cleaned)) {
    return {
      type: 'username',
      value: cleaned,
      platforms: ['Snapchat', 'Telegram', 'Various']
    };
  }
  
  return {
    type: 'unknown',
    value: cleaned,
    platforms: []
  };
}

function generateCheckLinks(data) {
  console.log('   [1/4] Generating check links...');
  
  const links = {};
  
  if (data.type === 'phone') {
    links.whatsapp = {
      method: 'Open WhatsApp Web, add contact, check if account exists',
      url: 'https://web.whatsapp.com/'
    };
    links.telegram = {
      method: 'Add contact in Telegram app',
      url: 'https://telegram.org/'
    };
    links.signal = {
      method: 'Add contact in Signal app',
      url: 'https://signal.org/'
    };
  }
  
  if (data.type === 'telegram_username') {
    links.telegram = {
      direct: `https://t.me/${data.value.replace('@', '')}`,
      method: 'Visit URL to check if profile exists'
    };
  }
  
  if (data.type === 'discord_username' || data.type === 'discord_id') {
    links.discordid = `https://discord.id/?prefill=${encodeURIComponent(data.value)}`;
    links.discordlookup = `https://discordlookup.com/user/${data.value}`;
  }
  
  if (data.type === 'username') {
    links.snapchat = `https://www.snapchat.com/add/${data.value}`;
    links.telegram = `https://t.me/${data.value}`;
  }
  
  return links;
}

function getInvestigationSteps(data) {
  console.log('   [2/4] Preparing investigation steps...');
  
  const steps = {
    initial: [],
    verification: [],
    dataCollection: [],
    advanced: []
  };
  
  if (data.type === 'phone') {
    steps.initial = [
      'Format phone number in E.164 format (+countrycode + number)',
      'Save number in phone contacts',
      'Check WhatsApp Web for account existence',
      'Open Telegram and search for contact',
      'Check Signal app for account'
    ];
    
    steps.verification = [
      'Verify profile photo matches (if available)',
      'Check last seen / online status',
      'Note status messages / bio',
      'Check groups in common (WhatsApp)',
      'Verify phone number country code matches'
    ];
    
    steps.dataCollection = [
      'Screenshot profile information',
      'Save profile photos',
      'Note status message / about info',
      'Check privacy settings (what\'s visible)',
      'Document last seen patterns'
    ];
    
    steps.advanced = [
      'Cross-reference with other platforms',
      'Check if number appears in data breaches',
      'Use reverse phone lookup tools',
      'Monitor status updates over time',
      'Check for linked social media'
    ];
  }
  
  if (data.type === 'telegram_username' || data.type === 'username') {
    steps.initial = [
      'Visit t.me/username directly',
      'Check if profile is public',
      'Note user ID (use @username_to_id_bot)',
      'Check bio and profile photo'
    ];
    
    steps.dataCollection = [
      'Screenshot profile',
      'Check channels owned/admin',
      'Look for groups in common',
      'Note when account was created',
      'Check for forwarded messages'
    ];
  }
  
  if (data.type === 'discord_username' || data.type === 'discord_id') {
    steps.initial = [
      'Enable Discord Developer Mode',
      'Copy User ID (right-click → Copy ID)',
      'Use discord.id or discordlookup.com',
      'Check avatar and banner'
    ];
    
    steps.dataCollection = [
      'Note account creation date',
      'Check badges (Nitro, Early Supporter, etc)',
      'Screenshot profile',
      'Check mutual servers',
      'Look for linked social accounts'
    ];
  }
  
  return steps;
}

function getPrivacyConsiderations() {
  console.log('   [3/4] Preparing privacy considerations...');
  
  return {
    whatsapp: [
      'Profile photo can be hidden from non-contacts',
      'Last seen can be disabled',
      'Status can be hidden',
      'Read receipts can be disabled',
      'Groups in common only shows if both are members'
    ],
    telegram: [
      'Username is optional (can use phone only)',
      'Phone number can be hidden',
      'Last seen can be restricted',
      'Profile photo can be hidden',
      'Forwarded messages show original sender'
    ],
    signal: [
      'Very privacy-focused',
      'Minimal metadata collection',
      'No username system (phone only)',
      'Profile name is optional',
      'Disappearing messages'
    ],
    discord: [
      'User ID is always visible',
      'Username can be changed anytime',
      'Profile is public by default',
      'Can limit who can DM',
      'Activity status can be hidden'
    ]
  };
}

function generateRecommendations(data) {
  console.log('   [4/4] Generating recommendations...');
  
  const recs = [];
  
  if (data.type === 'phone') {
    recs.push('💡 Start with WhatsApp - most widely used globally');
    recs.push('💡 Check Telegram - popular for privacy-conscious users');
    recs.push('💡 Signal for security-focused individuals');
    recs.push('💡 Use phone number for multiple platforms simultaneously');
  }
  
  if (data.type === 'telegram_username') {
    recs.push('💡 Use Telegram bots to get user ID');
    recs.push('💡 Check if user owns any public channels');
    recs.push('💡 Look for messages in public groups');
  }
  
  if (data.type === 'discord_username' || data.type === 'discord_id') {
    recs.push('💡 Enable Developer Mode in Discord');
    recs.push('💡 Use discord.id for quick lookup');
    recs.push('💡 Check account creation date for age verification');
    recs.push('💡 Look for mutual servers');
  }
  
  if (data.type === 'username') {
    recs.push('💡 Try username across multiple platforms');
    recs.push('💡 Use Sherlock for username enumeration');
    recs.push('💡 Check variations (with/without underscores, dots)');
  }
  
  recs.push('⚠️  Always verify information from multiple sources');
  recs.push('⚠️  Respect privacy settings and legal boundaries');
  recs.push('⚠️  Document all findings with timestamps');
  
  return recs;
}

function displayResults(data) {
  console.log("\n╔════════════════════════════════════════════════════════╗");
  console.log("║       💬 MESSAGING OSINT REPORT 💬                     ║");
  console.log("╚════════════════════════════════════════════════════════╝\n");
  
  console.log(`🔍 Identifier: \x1b[36m${data.identifier.value}\x1b[0m`);
  console.log(`   Type: ${data.identifier.type}`);
  console.log(`   Platforms: ${data.identifier.platforms.join(', ') || 'Unknown'}\n`);
  
  // Check Links
  if (Object.keys(data.checkLinks).length > 0) {
    console.log("\x1b[36m┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓\x1b[0m");
    console.log("\x1b[36m┃                  CHECK LINKS                         ┃\x1b[0m");
    console.log("\x1b[36m┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛\x1b[0m\n");
    
    Object.entries(data.checkLinks).forEach(([platform, info]) => {
      console.log(`   \x1b[32m${platform}:\x1b[0m`);
      if (info.direct) console.log(`      Direct: ${info.direct}`);
      if (info.url) console.log(`      URL: ${info.url}`);
      if (info.method) console.log(`      Method: ${info.method}`);
      console.log('');
    });
  }
  
  // Messaging Platforms
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
  console.log("\x1b[36m💬 MESSAGING PLATFORMS\x1b[0m");
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
  
  Object.entries(MESSAGING_PLATFORMS).forEach(([key, platform]) => {
    console.log(`   ${platform.icon} \x1b[32m${platform.name}\x1b[0m`);
    console.log(`      Format: ${platform.format}`);
    console.log(`      Data Points: ${platform.dataPoints.join(', ')}`);
    console.log(`      Privacy: ${platform.privacy}\n`);
  });
  
  // Investigation Steps
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
  console.log("\x1b[36m🔬 INVESTIGATION WORKFLOW\x1b[0m");
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
  
  if (data.steps.initial.length > 0) {
    console.log('   \x1b[32mInitial Checks:\x1b[0m');
    data.steps.initial.forEach(step => {
      console.log(`      • ${step}`);
    });
    console.log('');
  }
  
  if (data.steps.verification.length > 0) {
    console.log('   \x1b[32mVerification:\x1b[0m');
    data.steps.verification.forEach(step => {
      console.log(`      • ${step}`);
    });
    console.log('');
  }
  
  if (data.steps.dataCollection.length > 0) {
    console.log('   \x1b[32mData Collection:\x1b[0m');
    data.steps.dataCollection.forEach(step => {
      console.log(`      • ${step}`);
    });
    console.log('');
  }
  
  if (data.steps.advanced.length > 0) {
    console.log('   \x1b[32mAdvanced Techniques:\x1b[0m');
    data.steps.advanced.forEach(step => {
      console.log(`      • ${step}`);
    });
    console.log('');
  }
  
  // Telegram OSINT
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
  console.log("\x1b[36m✈️  TELEGRAM OSINT TOOLS\x1b[0m");
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
  
  console.log('   \x1b[32mBots:\x1b[0m');
  Object.entries(TELEGRAM_OSINT.bots).forEach(([key, bot]) => {
    console.log(`      • ${bot.command}: ${bot.function}`);
  });
  console.log('');
  
  console.log('   \x1b[32mTools:\x1b[0m');
  Object.entries(TELEGRAM_OSINT.tools).forEach(([name, tool]) => {
    console.log(`      • ${name}: ${tool.url}`);
    console.log(`        Features: ${tool.features.join(', ')}`);
  });
  console.log('');
  
  // Discord OSINT
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
  console.log("\x1b[36m🎮 DISCORD OSINT TOOLS\x1b[0m");
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
  
  Object.entries(DISCORD_OSINT.tools).forEach(([name, tool]) => {
    console.log(`   \x1b[32m${name}\x1b[0m`);
    console.log(`      URL: ${tool.url}`);
    console.log(`      Features: ${tool.features.join(', ')}\n`);
  });
  
  console.log('   \x1b[33mDeveloper Mode:\x1b[0m');
  console.log(`      Enable: ${DISCORD_OSINT.developerMode.enable}`);
  console.log(`      Allows: ${DISCORD_OSINT.developerMode.allows}\n`);
  
  // Privacy Considerations
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
  console.log("\x1b[36m🔒 PRIVACY CONSIDERATIONS\x1b[0m");
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
  
  Object.entries(data.privacy).forEach(([platform, considerations]) => {
    console.log(`   \x1b[32m${platform}:\x1b[0m`);
    considerations.forEach(item => {
      console.log(`      • ${item}`);
    });
    console.log('');
  });
  
  // Recommendations
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
  console.log("\x1b[36m💡 RECOMMENDATIONS\x1b[0m");
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
  
  data.recommendations.forEach(rec => {
    console.log(`   ${rec}`);
  });
  console.log('');
}

function saveReport(data) {
  const dir = './messaging-osint-reports';
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, -5);
  const safeName = data.identifier.value.replace(/[^a-zA-Z0-9]/g, '-').substring(0, 50);
  const filename = `${dir}/messaging-${safeName}-${timestamp}.txt`;
  
  let content = `═══════════════════════════════════════════════════════════
MESSAGING OSINT REPORT
═══════════════════════════════════════════════════════════

Identifier: ${data.identifier.value}
Type: ${data.identifier.type}
Platforms: ${data.identifier.platforms.join(', ')}
Date: ${new Date().toLocaleString()}

CHECK LINKS:
${Object.entries(data.checkLinks).map(([platform, info]) => 
  `${platform}:\n${info.direct ? `  Direct: ${info.direct}\n` : ''}${info.url ? `  URL: ${info.url}\n` : ''}${info.method ? `  Method: ${info.method}\n` : ''}`
).join('\n')}

INVESTIGATION STEPS:
${data.steps.initial.length > 0 ? `Initial:\n${data.steps.initial.map(s => `  • ${s}`).join('\n')}` : ''}
${data.steps.verification.length > 0 ? `\nVerification:\n${data.steps.verification.map(s => `  • ${s}`).join('\n')}` : ''}
${data.steps.dataCollection.length > 0 ? `\nData Collection:\n${data.steps.dataCollection.map(s => `  • ${s}`).join('\n')}` : ''}
${data.steps.advanced.length > 0 ? `\nAdvanced:\n${data.steps.advanced.map(s => `  • ${s}`).join('\n')}` : ''}

RECOMMENDATIONS:
${data.recommendations.join('\n')}
`;

  fs.writeFileSync(filename, content);
  console.log(`\x1b[32m✅ Report saved: ${filename}\x1b[0m\n`);
}

function showHelp() {
  showBanner();
  
  console.log("Usage: node messaging-osint.js <identifier> [--save]\n");
  console.log("Supported Identifiers:");
  console.log("  Phone:               +1234567890");
  console.log("  Telegram Username:   @username");
  console.log("  Discord Username:    username#1234");
  console.log("  Discord ID:          123456789012345678");
  console.log("  Generic Username:    username\n");
  
  console.log("Options:");
  console.log("  --save               Save report to file");
  console.log("  --help               Show this help\n");
  
  console.log("Examples:");
  console.log("  node messaging-osint.js \"+1234567890\"");
  console.log("  node messaging-osint.js \"@telegram_user\"");
  console.log("  node messaging-osint.js \"username#1234\" --save\n");
}

function main() {
  const args = process.argv.slice(2);
  
  if (args.length === 0 || args.includes('--help')) {
    showHelp();
    process.exit(0);
  }
  
  showBanner();
  
  let identifier = null;
  let saveFlag = false;
  
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--save') {
      saveFlag = true;
    } else if (!args[i].startsWith('--')) {
      identifier = args[i];
    }
  }
  
  if (!identifier) {
    console.log("\x1b[31m❌ No identifier specified!\x1b[0m\n");
    showHelp();
    process.exit(1);
  }
  
  console.log(`⏳ Analyzing identifier: ${identifier}...\n`);
  
  const parsed = parseIdentifier(identifier);
  
  const results = {
    timestamp: new Date().toISOString(),
    identifier: parsed,
    checkLinks: generateCheckLinks(parsed),
    steps: getInvestigationSteps(parsed),
    privacy: getPrivacyConsiderations(),
    recommendations: generateRecommendations(parsed)
  };
  
  displayResults(results);
  
  if (saveFlag) {
    saveReport(results);
  }
  
  console.log("\x1b[31m███╗   ███╗███████╗███████╗███████╗ █████╗  ██████╗ ██╗███╗   ██╗ ██████╗ \x1b[0m");
  console.log("\x1b[35m🥝 Analysis complete - by kiwi & 777\x1b[0m\n");
}

main();
