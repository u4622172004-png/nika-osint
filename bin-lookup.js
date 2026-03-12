#!/usr/bin/env node

const https = require('https');
const fs = require('fs');

// ============================================
// BIN LOOKUP - Credit Card BIN Intelligence
// ============================================

const BIN_DATABASES = {
  binlist: {
    name: 'BINList.net',
    url: 'https://binlist.net/',
    api: 'https://lookup.binlist.net/',
    features: ['Brand', 'Type', 'Category', 'Bank', 'Country'],
    cost: 'Free',
    rateLimit: '10 requests/minute'
  },
  bindb: {
    name: 'BIN-DB',
    url: 'https://bin-db.com/',
    api: 'https://bin-db.com/api/',
    features: ['Bank name', 'Card type', 'Level', 'Country'],
    cost: 'Free',
    rateLimit: 'Unlimited'
  },
  bincheck: {
    name: 'BINCheck.io',
    url: 'https://bincheck.io/',
    features: ['Full BIN data', 'Bank info', 'Card details'],
    cost: 'Free/Paid',
    api: true
  },
  freebinchecker: {
    name: 'FreeBinChecker',
    url: 'https://freebinchecker.com/',
    features: ['Brand', 'Type', 'Level', 'Bank', 'Country', 'Phone'],
    cost: 'Free',
    api: false
  }
};

const CARD_BRANDS = {
  '4': 'Visa',
  '51': 'Mastercard', '52': 'Mastercard', '53': 'Mastercard', '54': 'Mastercard', '55': 'Mastercard',
  '2221': 'Mastercard', '2720': 'Mastercard',
  '34': 'American Express', '37': 'American Express',
  '6011': 'Discover', '65': 'Discover',
  '35': 'JCB',
  '36': 'Diners Club', '38': 'Diners Club',
  '62': 'UnionPay',
  '50': 'Maestro', '56': 'Maestro', '57': 'Maestro', '58': 'Maestro'
};

const CARD_TYPES = {
  credit: 'Credit Card',
  debit: 'Debit Card',
  prepaid: 'Prepaid Card',
  charge: 'Charge Card'
};

const CARD_LEVELS = {
  classic: 'Classic/Standard',
  gold: 'Gold',
  platinum: 'Platinum',
  signature: 'Signature',
  infinite: 'Infinite',
  black: 'Black/Centurion',
  business: 'Business',
  corporate: 'Corporate'
};

function showBanner() {
  console.log("\x1b[31m");
  console.log("██████╗ ██╗███╗   ██╗    ██╗      ██████╗  ██████╗ ██╗  ██╗██╗   ██╗██████╗ ");
  console.log("██╔══██╗██║████╗  ██║    ██║     ██╔═══██╗██╔═══██╗██║ ██╔╝██║   ██║██╔══██╗");
  console.log("██████╔╝██║██╔██╗ ██║    ██║     ██║   ██║██║   ██║█████╔╝ ██║   ██║██████╔╝");
  console.log("██╔══██╗██║██║╚██╗██║    ██║     ██║   ██║██║   ██║██╔═██╗ ██║   ██║██╔═══╝ ");
  console.log("██████╔╝██║██║ ╚████║    ███████╗╚██████╔╝╚██████╔╝██║  ██╗╚██████╔╝██║     ");
  console.log("╚═════╝ ╚═╝╚═╝  ╚═══╝    ╚══════╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝     ");
  console.log("\x1b[0m");
  console.log("\x1b[35m🥝 NIKA BIN Lookup - Credit Card BIN Intelligence\x1b[0m");
  console.log("\x1b[33m⚠️  For educational/verification purposes only - NOT for fraud\x1b[0m\n");
}

function validateBIN(bin) {
  const cleaned = bin.replace(/\s/g, '');
  
  if (!/^\d{6,8}$/.test(cleaned)) {
    return {
      valid: false,
      error: 'BIN must be 6-8 digits'
    };
  }
  
  return {
    valid: true,
    bin: cleaned,
    length: cleaned.length
  };
}

function identifyBrand(bin) {
  // Check from longest to shortest prefix
  for (let len = 4; len >= 1; len--) {
    const prefix = bin.substring(0, len);
    if (CARD_BRANDS[prefix]) {
      return CARD_BRANDS[prefix];
    }
  }
  return 'Unknown';
}

function luhnCheck(cardNumber) {
  // Luhn algorithm for card validation
  let sum = 0;
  let isEven = false;
  
  for (let i = cardNumber.length - 1; i >= 0; i--) {
    let digit = parseInt(cardNumber[i]);
    
    if (isEven) {
      digit *= 2;
      if (digit > 9) digit -= 9;
    }
    
    sum += digit;
    isEven = !isEven;
  }
  
  return sum % 10 === 0;
}

async function lookupBINList(bin) {
  return new Promise((resolve) => {
    const url = `https://lookup.binlist.net/${bin}`;
    
    https.get(url, {
      headers: {
        'Accept-Version': '3',
        'User-Agent': 'NIKA-OSINT'
      }
    }, (res) => {
      let data = '';
      
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          const json = JSON.parse(data);
          resolve({
            available: true,
            source: 'BINList.net',
            data: {
              brand: json.scheme?.toUpperCase() || 'Unknown',
              type: json.type || 'Unknown',
              category: json.brand || 'Unknown',
              bank: json.bank?.name || 'Unknown',
              country: json.country?.name || 'Unknown',
              countryCode: json.country?.alpha2 || 'Unknown',
              phone: json.bank?.phone || 'N/A',
              website: json.bank?.url || 'N/A'
            }
          });
        } catch (e) {
          resolve({
            available: false,
            error: 'Failed to parse response'
          });
        }
      });
    }).on('error', () => {
      resolve({
        available: false,
        error: 'API request failed'
      });
    });
    
    setTimeout(() => {
      resolve({
        available: false,
        error: 'Timeout'
      });
    }, 10000);
  });
}

function generateBINInfo(bin) {
  const brand = identifyBrand(bin);
  
  return {
    bin: bin,
    brand: brand,
    iin: bin.substring(0, 6),
    majorIndustry: getMajorIndustry(bin[0]),
    issuerCategory: getIssuerCategory(bin[0]),
    possibleTypes: ['Credit', 'Debit', 'Prepaid'],
    possibleLevels: Object.values(CARD_LEVELS)
  };
}

function getMajorIndustry(firstDigit) {
  const industries = {
    '0': 'ISO/TC 68 and other industry assignments',
    '1': 'Airlines',
    '2': 'Airlines and other future industry assignments',
    '3': 'Travel and entertainment',
    '4': 'Banking and financial',
    '5': 'Banking and financial',
    '6': 'Merchandising and banking',
    '7': 'Petroleum',
    '8': 'Healthcare, telecommunications',
    '9': 'National assignment'
  };
  
  return industries[firstDigit] || 'Unknown';
}

function getIssuerCategory(firstDigit) {
  if (['4', '5'].includes(firstDigit)) return 'Banking/Financial';
  if (firstDigit === '3') return 'Travel/Entertainment';
  if (firstDigit === '6') return 'Merchandising';
  return 'Other';
}

function generateTestCards(bin) {
  // Generate valid test card numbers using Luhn
  const testCards = [];
  
  for (let i = 0; i < 3; i++) {
    let card = bin;
    
    // Pad to 15 digits
    while (card.length < 15) {
      card += Math.floor(Math.random() * 10);
    }
    
    // Calculate Luhn check digit
    let sum = 0;
    for (let j = 0; j < 15; j++) {
      let digit = parseInt(card[j]);
      if (j % 2 === 0) {
        digit *= 2;
        if (digit > 9) digit -= 9;
      }
      sum += digit;
    }
    
    const checkDigit = (10 - (sum % 10)) % 10;
    card += checkDigit;
    
    testCards.push({
      number: card,
      formatted: formatCard(card),
      valid: luhnCheck(card),
      note: 'Test card - DO NOT use for real transactions'
    });
  }
  
  return testCards;
}

function formatCard(number) {
  // Format as XXXX XXXX XXXX XXXX
  return number.match(/.{1,4}/g).join(' ');
}

function displayResults(data) {
  console.log("\n╔════════════════════════════════════════════════════════╗");
  console.log("║       💳 BIN LOOKUP RESULTS 💳                         ║");
  console.log("╚════════════════════════════════════════════════════════╝\n");
  
  console.log(`🔢 BIN: \x1b[36m${data.binInfo.bin}\x1b[0m\n`);
  
  console.log("\x1b[36m┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓\x1b[0m");
  console.log("\x1b[36m┃                  BASIC INFORMATION                   ┃\x1b[0m");
  console.log("\x1b[36m┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛\x1b[0m\n");
  
  console.log(`   IIN/BIN:             ${data.binInfo.iin}`);
  console.log(`   Brand:               ${data.binInfo.brand}`);
  console.log(`   Major Industry:      ${data.binInfo.majorIndustry}`);
  console.log(`   Issuer Category:     ${data.binInfo.issuerCategory}\n`);
  
  if (data.apiLookup && data.apiLookup.available) {
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
    console.log("\x1b[36m🌐 API LOOKUP DATA (BINList.net)\x1b[0m");
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
    
    const api = data.apiLookup.data;
    console.log(`   Card Brand:          ${api.brand}`);
    console.log(`   Card Type:           ${api.type}`);
    console.log(`   Category:            ${api.category}`);
    console.log(`   Bank Name:           ${api.bank}`);
    console.log(`   Country:             ${api.country} (${api.countryCode})`);
    if (api.phone !== 'N/A') console.log(`   Bank Phone:          ${api.phone}`);
    if (api.website !== 'N/A') console.log(`   Bank Website:        ${api.website}`);
    console.log('');
  } else if (data.apiLookup) {
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
    console.log("\x1b[36m🌐 API LOOKUP\x1b[0m");
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
    
    console.log(`   Status:              ${data.apiLookup.error}\n`);
  }
  
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
  console.log("\x1b[36m🔍 BIN LOOKUP DATABASES\x1b[0m");
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
  
  Object.entries(BIN_DATABASES).forEach(([key, db]) => {
    console.log(`   \x1b[32m${db.name}\x1b[0m (${db.cost})`);
    console.log(`      URL: ${db.url}${data.binInfo.bin}`);
    console.log(`      Features: ${db.features.join(', ')}`);
    if (db.rateLimit) console.log(`      Rate Limit: ${db.rateLimit}`);
    console.log('');
  });
  
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
  console.log("\x1b[36m🧪 GENERATED TEST CARDS (FOR TESTING ONLY)\x1b[0m");
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
  
  data.testCards.forEach((card, i) => {
    console.log(`   ${i + 1}. ${card.formatted}`);
    console.log(`      Luhn Valid: ${card.valid ? '\x1b[32m✓\x1b[0m' : '\x1b[31m✗\x1b[0m'}`);
    console.log(`      ⚠️  ${card.note}\n`);
  });
  
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
  console.log("\x1b[36m📚 CARD KNOWLEDGE BASE\x1b[0m");
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
  
  console.log('   \x1b[32mCard Brands:\x1b[0m');
  console.log('      • Visa: Starts with 4');
  console.log('      • Mastercard: Starts with 51-55 or 2221-2720');
  console.log('      • American Express: Starts with 34 or 37');
  console.log('      • Discover: Starts with 6011 or 65');
  console.log('      • JCB: Starts with 35');
  console.log('      • Diners Club: Starts with 36 or 38\n');
  
  console.log('   \x1b[32mCard Types:\x1b[0m');
  Object.entries(CARD_TYPES).forEach(([key, value]) => {
    console.log(`      • ${value}`);
  });
  console.log('');
  
  console.log('   \x1b[32mCard Levels:\x1b[0m');
  Object.values(CARD_LEVELS).forEach(level => {
    console.log(`      • ${level}`);
  });
  console.log('');
  
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
  console.log("\x1b[36m⚠️  LEGAL DISCLAIMER\x1b[0m");
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
  
  console.log('   \x1b[31m⚠️  BIN data is PUBLIC information\x1b[0m');
  console.log('   \x1b[31m⚠️  FOR VERIFICATION PURPOSES ONLY\x1b[0m');
  console.log('   \x1b[31m⚠️  DO NOT use for fraud or carding\x1b[0m');
  console.log('   \x1b[31m⚠️  Test cards are for development only\x1b[0m');
  console.log('   \x1b[31m⚠️  Violating card regulations is a CRIME\x1b[0m\n');
}

function saveReport(data) {
  const dir = './bin-lookup-reports';
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, -5);
  const filename = `${dir}/bin-${data.binInfo.bin}-${timestamp}.txt`;
  
  let content = `═══════════════════════════════════════════════════════════
BIN LOOKUP REPORT
═══════════════════════════════════════════════════════════

BIN: ${data.binInfo.bin}
Date: ${new Date().toLocaleString()}

BASIC INFORMATION:
IIN/BIN: ${data.binInfo.iin}
Brand: ${data.binInfo.brand}
Major Industry: ${data.binInfo.majorIndustry}
Issuer Category: ${data.binInfo.issuerCategory}

`;

  if (data.apiLookup && data.apiLookup.available) {
    const api = data.apiLookup.data;
    content += `API LOOKUP DATA (${data.apiLookup.source}):
Card Brand: ${api.brand}
Card Type: ${api.type}
Category: ${api.category}
Bank: ${api.bank}
Country: ${api.country} (${api.countryCode})
Phone: ${api.phone}
Website: ${api.website}

`;
  }
  
  content += `BIN LOOKUP DATABASES:\n`;
  Object.entries(BIN_DATABASES).forEach(([key, db]) => {
    content += `\n${db.name}:\n${db.url}${data.binInfo.bin}\n`;
  });
  
  content += `\nGENERATED TEST CARDS (FOR TESTING ONLY):\n`;
  data.testCards.forEach((card, i) => {
    content += `${i + 1}. ${card.formatted} (Luhn: ${card.valid})\n`;
  });
  
  fs.writeFileSync(filename, content);
  console.log(`\x1b[32m✅ Report saved: ${filename}\x1b[0m\n`);
}

function showHelp() {
  showBanner();
  
  console.log("Usage: node bin-lookup.js <BIN> [--save]\n");
  console.log("Options:");
  console.log("  --save               Save report to file");
  console.log("  --help               Show this help\n");
  
  console.log("BIN Format:");
  console.log("  6-8 digit number (first digits of card)\n");
  
  console.log("Examples:");
  console.log("  node bin-lookup.js 424242");
  console.log("  node bin-lookup.js 411111 --save");
  console.log("  node bin-lookup.js 55555555\n");
}

async function main() {
  const args = process.argv.slice(2);
  
  if (args.length === 0 || args.includes('--help')) {
    showHelp();
    process.exit(0);
  }
  
  showBanner();
  
  let bin = null;
  let saveFlag = false;
  
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--save') {
      saveFlag = true;
    } else if (!args[i].startsWith('--')) {
      bin = args[i];
    }
  }
  
  if (!bin) {
    console.log("\x1b[31m❌ No BIN specified!\x1b[0m\n");
    showHelp();
    process.exit(1);
  }
  
  const validation = validateBIN(bin);
  
  if (!validation.valid) {
    console.log(`\x1b[31m❌ ${validation.error}\x1b[0m\n`);
    process.exit(1);
  }
  
  console.log(`⏳ Looking up BIN: ${validation.bin}...\n`);
  
  const results = {
    timestamp: new Date().toISOString(),
    binInfo: generateBINInfo(validation.bin),
    apiLookup: await lookupBINList(validation.bin),
    testCards: generateTestCards(validation.bin)
  };
  
  displayResults(results);
  
  if (saveFlag) {
    saveReport(results);
  }
  
  console.log("\x1b[31m██████╗ ██╗███╗   ██╗\x1b[0m");
  console.log("\x1b[35m🥝 Lookup complete - by kiwi & 777\x1b[0m\n");
}

main();
