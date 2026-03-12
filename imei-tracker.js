#!/usr/bin/env node

const https = require('https');
const fs = require('fs');

// ============================================
// IMEI TRACKER - Device Intelligence
// ============================================

const IMEI_DATABASES = {
  imeiinfo: {
    name: 'IMEI.info',
    url: 'https://www.imei.info/?imei=',
    features: ['Brand', 'Model', 'Specs', 'Warranty', 'Carrier'],
    cost: 'Free basic, Paid premium',
    api: false
  },
  imeipro: {
    name: 'IMEIPro',
    url: 'https://imeipro.info/check_imei.html',
    features: ['Model', 'Serial', 'Purchase date', 'Warranty'],
    cost: 'Free',
    api: false
  },
  imei24: {
    name: 'IMEI24',
    url: 'https://imei24.com/imei_check/',
    features: ['Full specs', 'Blacklist check', 'Find My iPhone'],
    cost: 'Free/Paid',
    api: false
  },
  checkmend: {
    name: 'CheckMEND',
    url: 'https://www.checkmend.com',
    features: ['Stolen check', 'Blacklist', 'Insurance'],
    cost: 'Paid',
    api: true
  },
  imeicheck: {
    name: 'IMEI Check',
    url: 'https://www.imeicheck.com',
    features: ['Carrier', 'Lock status', 'iCloud', 'Blacklist'],
    cost: 'Free basic',
    api: false
  }
};

const CARRIER_CHECKERS = {
  usa: {
    att: { name: 'AT&T', url: 'https://www.att.com/deviceunlock/' },
    tmobile: { name: 'T-Mobile', url: 'https://www.t-mobile.com/responsibility/consumer-info/policies/sim-unlock-policy' },
    verizon: { name: 'Verizon', url: 'https://www.verizon.com/support/device-unlock/' },
    sprint: { name: 'Sprint', url: 'https://www.sprint.com/en/support/solutions/device/device-unlock.html' }
  },
  uk: {
    ee: { name: 'EE', url: 'https://ee.co.uk/help/phones-and-device/unlocking' },
    o2: { name: 'O2', url: 'https://www.o2.co.uk/help/device-and-sim-support/unlocking' },
    vodafone: { name: 'Vodafone', url: 'https://www.vodafone.co.uk/mobile/network-unlock-code' },
    three: { name: 'Three', url: 'https://www.three.co.uk/support/device-guides/unlock-device' }
  }
};

const APPLE_SERVICES = {
  warranty: 'https://checkcoverage.apple.com/',
  activation: 'https://www.icloud.com/activationlock/',
  findmy: 'https://www.icloud.com/find',
  gsx: 'Apple GSX (Authorized service providers only)'
};

function validateIMEI(imei) {
  // Remove spaces and dashes
  const cleaned = imei.replace(/[\s-]/g, '');
  
  if (!/^\d{15}$/.test(cleaned)) {
    return {
      valid: false,
      error: 'IMEI must be exactly 15 digits'
    };
  }
  
  // Luhn algorithm check
  let sum = 0;
  for (let i = 0; i < 15; i++) {
    let digit = parseInt(cleaned[i]);
    
    if (i % 2 === 1) {
      digit *= 2;
      if (digit > 9) digit -= 9;
    }
    
    sum += digit;
  }
  
  return {
    valid: sum % 10 === 0,
    imei: cleaned,
    formatted: `${cleaned.slice(0, 2)} ${cleaned.slice(2, 8)} ${cleaned.slice(8, 14)} ${cleaned.slice(14)}`
  };
}

function parseIMEI(imei) {
  const tac = imei.slice(0, 8);  // Type Allocation Code
  const snr = imei.slice(8, 14); // Serial Number
  const cd = imei.slice(14, 15); // Check Digit
  
  const reportingBody = imei.slice(0, 2);
  const manufacturer = imei.slice(2, 6);
  
  return {
    imei: imei,
    tac: tac,
    serialNumber: snr,
    checkDigit: cd,
    reportingBody: reportingBody,
    manufacturer: manufacturer,
    breakdown: {
      'Full IMEI': imei,
      'TAC (Type Allocation Code)': tac,
      'Serial Number': snr,
      'Check Digit': cd,
      'Reporting Body ID': reportingBody,
      'Manufacturer Code': manufacturer
    }
  };
}

function getManufacturerInfo(tac) {
  // Basic manufacturer database (TAC prefix)
  const manufacturers = {
    '01': 'Apple',
    '35': 'Apple',
    '86': 'Samsung',
    '35': 'Samsung',
    '49': 'Huawei',
    '52': 'Nokia',
    '35': 'Motorola',
    '35': 'LG',
    '35': 'Sony',
    '35': 'HTC',
    '35': 'Xiaomi',
    '35': 'OnePlus',
    '35': 'Google'
  };
  
  const prefix = tac.slice(0, 2);
  
  return {
    prefix: prefix,
    manufacturer: manufacturers[prefix] || 'Unknown',
    note: 'Full TAC lookup requires paid database access'
  };
}

function generateCheckLinks(imei) {
  return {
    imeiinfo: `${IMEI_DATABASES.imeiinfo.url}${imei}`,
    imeipro: IMEI_DATABASES.imeipro.url,
    imei24: IMEI_DATABASES.imei24.url,
    imeicheck: IMEI_DATABASES.imeicheck.url,
    checkmend: IMEI_DATABASES.checkmend.url,
    apple: imei.slice(0, 2) === '01' || imei.slice(0, 2) === '35' ? APPLE_SERVICES.warranty : null
  };
}

function getBlacklistCheckers() {
  return {
    gsma: {
      name: 'GSMA Device Check',
      url: 'https://www.devicecheck.gsma.com/',
      coverage: 'Global',
      features: ['Stolen status', 'Blacklist check'],
      cost: 'Free'
    },
    checkmend: {
      name: 'CheckMEND',
      url: 'https://www.checkmend.com',
      coverage: 'UK/USA/Canada',
      features: ['Police database', 'Insurance'],
      cost: 'Paid'
    },
    swappa: {
      name: 'Swappa ESN Checker',
      url: 'https://swappa.com/esn',
      coverage: 'USA carriers',
      features: ['Blacklist', 'Financing check'],
      cost: 'Free'
    },
    imeipro: {
      name: 'IMEIPro Blacklist',
      url: 'https://imeipro.info/check_imei_blacklist.html',
      coverage: 'Global',
      features: ['Lost/Stolen check'],
      cost: 'Free'
    }
  };
}

function showBanner() {
  console.log("\x1b[31m");
  console.log("██╗███╗   ███╗███████╗██╗    ████████╗██████╗  █████╗  ██████╗██╗  ██╗███████╗██████╗ ");
  console.log("██║████╗ ████║██╔════╝██║    ╚══██╔══╝██╔══██╗██╔══██╗██╔════╝██║ ██╔╝██╔════╝██╔══██╗");
  console.log("██║██╔████╔██║█████╗  ██║       ██║   ██████╔╝███████║██║     █████╔╝ █████╗  ██████╔╝");
  console.log("██║██║╚██╔╝██║██╔══╝  ██║       ██║   ██╔══██╗██╔══██║██║     ██╔═██╗ ██╔══╝  ██╔══██╗");
  console.log("██║██║ ╚═╝ ██║███████╗██║       ██║   ██║  ██║██║  ██║╚██████╗██║  ██╗███████╗██║  ██║");
  console.log("╚═╝╚═╝     ╚═╝╚══════╝╚═╝       ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝");
  console.log("\x1b[0m");
  console.log("\x1b[35m🥝 NIKA IMEI Tracker - Device Intelligence\x1b[0m");
  console.log("\x1b[33m⚠️  For authorized device verification only\x1b[0m\n");
}

function displayResults(data) {
  console.log("\n╔════════════════════════════════════════════════════════╗");
  console.log("║       📱 IMEI ANALYSIS REPORT 📱                       ║");
  console.log("╚════════════════════════════════════════════════════════╝\n");
  
  if (!data.validation.valid) {
    console.log(`\x1b[31m❌ Invalid IMEI: ${data.validation.error}\x1b[0m\n`);
    return;
  }
  
  console.log("\x1b[36m┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓\x1b[0m");
  console.log("\x1b[36m┃                  IMEI VALIDATION                     ┃\x1b[0m");
  console.log("\x1b[36m┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛\x1b[0m\n");
  
  console.log(`   Status:              \x1b[32m✓ Valid\x1b[0m`);
  console.log(`   IMEI:                ${data.validation.imei}`);
  console.log(`   Formatted:           ${data.validation.formatted}\n`);
  
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
  console.log("\x1b[36m🔢 IMEI BREAKDOWN\x1b[0m");
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
  
  Object.entries(data.parsed.breakdown).forEach(([key, value]) => {
    console.log(`   ${key.padEnd(30)} ${value}`);
  });
  console.log('');
  
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
  console.log("\x1b[36m🏭 MANUFACTURER INFO\x1b[0m");
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
  
  console.log(`   TAC Prefix:          ${data.manufacturer.prefix}`);
  console.log(`   Manufacturer:        ${data.manufacturer.manufacturer}`);
  console.log(`   Note:                ${data.manufacturer.note}\n`);
  
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
  console.log("\x1b[36m🔍 IMEI LOOKUP DATABASES\x1b[0m");
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
  
  Object.entries(IMEI_DATABASES).forEach(([key, db]) => {
    console.log(`   \x1b[32m${db.name}\x1b[0m (${db.cost})`);
    console.log(`      URL: ${db.url}${key === 'imeiinfo' ? data.validation.imei : ''}`);
    console.log(`      Features: ${db.features.join(', ')}\n`);
  });
  
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
  console.log("\x1b[36m🚨 BLACKLIST CHECKERS\x1b[0m");
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
  
  Object.entries(data.blacklistCheckers).forEach(([key, checker]) => {
    console.log(`   \x1b[32m${checker.name}\x1b[0m (${checker.cost})`);
    console.log(`      URL: ${checker.url}`);
    console.log(`      Coverage: ${checker.coverage}`);
    console.log(`      Features: ${checker.features.join(', ')}\n`);
  });
  
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
  console.log("\x1b[36m📡 CARRIER UNLOCK CHECKERS\x1b[0m");
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
  
  console.log('   \x1b[32mUSA Carriers:\x1b[0m');
  Object.entries(CARRIER_CHECKERS.usa).forEach(([key, carrier]) => {
    console.log(`      • ${carrier.name}: ${carrier.url}`);
  });
  console.log('');
  
  console.log('   \x1b[32mUK Carriers:\x1b[0m');
  Object.entries(CARRIER_CHECKERS.uk).forEach(([key, carrier]) => {
    console.log(`      • ${carrier.name}: ${carrier.url}`);
  });
  console.log('');
  
  if (data.checkLinks.apple) {
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
    console.log("\x1b[36m APPLE DEVICE SERVICES\x1b[0m");
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
    
    console.log(`   Warranty Check:      ${APPLE_SERVICES.warranty}`);
    console.log(`   Activation Lock:     ${APPLE_SERVICES.activation}`);
    console.log(`   Find My iPhone:      ${APPLE_SERVICES.findmy}`);
    console.log(`   GSX Access:          ${APPLE_SERVICES.gsx}\n`);
  }
  
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
  console.log("\x1b[36m💡 INVESTIGATION TIPS\x1b[0m");
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
  
  console.log('   • Check IMEI on multiple databases');
  console.log('   • Verify blacklist status before purchase');
  console.log('   • Check if device is carrier locked');
  console.log('   • For Apple: Check iCloud activation lock');
  console.log('   • Cross-reference with serial number');
  console.log('   • Report stolen devices to police + GSMA\n');
}

function saveReport(data) {
  const dir = './imei-reports';
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, -5);
  const filename = `${dir}/imei-${data.validation.imei}-${timestamp}.txt`;
  
  let content = `═══════════════════════════════════════════════════════════
IMEI TRACKER REPORT
═══════════════════════════════════════════════════════════

Date: ${new Date().toLocaleString()}
IMEI: ${data.validation.imei}
Formatted: ${data.validation.formatted}
Valid: ${data.validation.valid}

IMEI BREAKDOWN:
${Object.entries(data.parsed.breakdown).map(([k, v]) => `${k}: ${v}`).join('\n')}

MANUFACTURER:
TAC Prefix: ${data.manufacturer.prefix}
Manufacturer: ${data.manufacturer.manufacturer}

LOOKUP DATABASES:
${Object.entries(IMEI_DATABASES).map(([k, db]) => `${db.name}: ${db.url}`).join('\n')}

BLACKLIST CHECKERS:
${Object.entries(data.blacklistCheckers).map(([k, c]) => `${c.name} (${c.cost}): ${c.url}`).join('\n')}
`;

  fs.writeFileSync(filename, content);
  console.log(`\x1b[32m✅ Report saved: ${filename}\x1b[0m\n`);
}

function showHelp() {
  showBanner();
  
  console.log("Usage: node imei-tracker.js <IMEI> [--save]\n");
  console.log("Options:");
  console.log("  --save               Save report to file");
  console.log("  --help               Show this help\n");
  
  console.log("Examples:");
  console.log("  node imei-tracker.js 123456789012345");
  console.log("  node imei-tracker.js 12-345678-901234-5 --save\n");
}

function main() {
  const args = process.argv.slice(2);
  
  if (args.length === 0 || args.includes('--help')) {
    showHelp();
    process.exit(0);
  }
  
  showBanner();
  
  let imei = null;
  let saveFlag = false;
  
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--save') {
      saveFlag = true;
    } else if (!args[i].startsWith('--')) {
      imei = args[i];
    }
  }
  
  if (!imei) {
    console.log("\x1b[31m❌ No IMEI specified!\x1b[0m\n");
    showHelp();
    process.exit(1);
  }
  
  console.log(`⏳ Analyzing IMEI: ${imei}...\n`);
  
  const validation = validateIMEI(imei);
  
  if (!validation.valid) {
    console.log(`\x1b[31m❌ ${validation.error}\x1b[0m\n`);
    process.exit(1);
  }
  
  const results = {
    timestamp: new Date().toISOString(),
    validation: validation,
    parsed: parseIMEI(validation.imei),
    manufacturer: getManufacturerInfo(validation.imei.slice(0, 8)),
    checkLinks: generateCheckLinks(validation.imei),
    blacklistCheckers: getBlacklistCheckers()
  };
  
  displayResults(results);
  
  if (saveFlag) {
    saveReport(results);
  }
  
  console.log("\x1b[31m██╗███╗   ███╗███████╗██╗\x1b[0m");
  console.log("\x1b[35m🥝 Analysis complete - by kiwi & 777\x1b[0m\n");
}

main();
