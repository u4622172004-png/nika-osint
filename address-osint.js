#!/usr/bin/env node

const https = require('https');
const fs = require('fs');

// ============================================
// ADDRESS OSINT - Property & Location Intelligence
// ============================================

const PROPERTY_DATABASES = {
  usa: {
    zillow: {
      name: 'Zillow',
      url: 'https://www.zillow.com/',
      search: 'https://www.zillow.com/homes/',
      features: ['Home value', 'Sale history', 'Tax records', 'Photos', 'Schools'],
      cost: 'Free',
      coverage: 'USA'
    },
    realtor: {
      name: 'Realtor.com',
      url: 'https://www.realtor.com/',
      search: 'https://www.realtor.com/realestateandhomes-search/',
      features: ['Listings', 'Sold prices', 'Neighborhood info'],
      cost: 'Free',
      coverage: 'USA'
    },
    trulia: {
      name: 'Trulia',
      url: 'https://www.trulia.com/',
      search: 'https://www.trulia.com/for_sale/',
      features: ['Crime maps', 'School ratings', 'Commute times'],
      cost: 'Free',
      coverage: 'USA'
    },
    redfin: {
      name: 'Redfin',
      url: 'https://www.redfin.com/',
      search: 'https://www.redfin.com/city/',
      features: ['Hot homes', 'Walk score', 'Market trends'],
      cost: 'Free',
      coverage: 'USA'
    }
  },
  uk: {
    rightmove: {
      name: 'Rightmove',
      url: 'https://www.rightmove.co.uk/',
      search: 'https://www.rightmove.co.uk/house-prices/',
      features: ['Sold prices', 'Property estimates', 'Schools'],
      cost: 'Free',
      coverage: 'UK'
    },
    zoopla: {
      name: 'Zoopla',
      url: 'https://www.zoopla.co.uk/',
      search: 'https://www.zoopla.co.uk/house-prices/',
      features: ['Valuations', 'Rental estimates', 'Area guides'],
      cost: 'Free',
      coverage: 'UK'
    },
    landregistry: {
      name: 'Land Registry',
      url: 'https://landregistry.data.gov.uk/',
      search: 'https://landregistry.data.gov.uk/app/ppd',
      features: ['Official sale prices', 'Ownership', 'Title deeds'],
      cost: 'Free/Paid',
      coverage: 'UK'
    }
  },
  global: {
    googlemaps: {
      name: 'Google Maps',
      url: 'https://maps.google.com/',
      search: 'https://www.google.com/maps/search/',
      features: ['Street View', 'Satellite', 'Photos', 'Reviews'],
      cost: 'Free',
      coverage: 'Global'
    },
    googleearth: {
      name: 'Google Earth',
      url: 'https://earth.google.com/',
      features: ['3D view', 'Historical imagery', 'Measurements'],
      cost: 'Free',
      coverage: 'Global'
    }
  }
};

const REVERSE_ADDRESS_LOOKUP = {
  whitepages: {
    name: 'Whitepages',
    url: 'https://www.whitepages.com/address/',
    features: ['Residents', 'Phone numbers', 'Property value', 'Neighbors'],
    cost: 'Free basic'
  },
  spokeo: {
    name: 'Spokeo',
    url: 'https://www.spokeo.com/reverse-address',
    features: ['Current residents', 'Past residents', 'Photos', 'Social media'],
    cost: 'Paid'
  },
  truepeoplesearch: {
    name: 'TruePeopleSearch',
    url: 'https://www.truepeoplesearch.com/',
    features: ['Free people search', 'Associates', 'Relatives'],
    cost: 'Free'
  },
  fastpeoplesearch: {
    name: 'FastPeopleSearch',
    url: 'https://www.fastpeoplesearch.com/',
    features: ['Address history', 'Phone', 'Email', 'Relatives'],
    cost: 'Free'
  }
};

const TAX_ASSESSOR_RECORDS = {
  info: 'Property tax records are public and contain valuable OSINT data',
  search: 'Search "[County Name] property tax assessor" or "[County Name] GIS"',
  data: [
    'Owner name and mailing address',
    'Property value and tax amount',
    'Square footage and lot size',
    'Year built and renovations',
    'Number of bedrooms/bathrooms',
    'Sale history and prices',
    'Legal description',
    'Parcel/APN number'
  ],
  examples: {
    'Los Angeles': 'https://portal.assessor.lacounty.gov/',
    'New York': 'https://www1.nyc.gov/site/finance/property/property.page',
    'Cook County (Chicago)': 'https://www.cookcountyassessor.com/',
    'Miami-Dade': 'https://www.miamidade.gov/pa/'
  }
};

const NEIGHBORHOOD_INTEL = {
  crime: {
    'CrimeReports': 'https://www.crimereports.com/',
    'SpotCrime': 'https://spotcrime.com/',
    'NeighborhoodScout': 'https://www.neighborhoodscout.com/',
    'City-Data': 'https://www.city-data.com/'
  },
  demographics: {
    'Census.gov': 'https://data.census.gov/',
    'City-Data': 'https://www.city-data.com/',
    'AreaVibes': 'https://www.areavibes.com/',
    'Niche': 'https://www.niche.com/'
  },
  schools: {
    'GreatSchools': 'https://www.greatschools.org/',
    'SchoolDigger': 'https://www.schooldigger.com/',
    'Niche Schools': 'https://www.niche.com/k12/'
  }
};

function showBanner() {
  console.log("\x1b[31m");
  console.log(" █████╗ ██████╗ ██████╗ ██████╗ ███████╗███████╗███████╗     ██████╗ ███████╗██╗███╗   ██╗████████╗");
  console.log("██╔══██╗██╔══██╗██╔══██╗██╔══██╗██╔════╝██╔════╝██╔════╝    ██╔═══██╗██╔════╝██║████╗  ██║╚══██╔══╝");
  console.log("███████║██║  ██║██║  ██║██████╔╝█████╗  ███████╗███████╗    ██║   ██║███████╗██║██╔██╗ ██║   ██║   ");
  console.log("██╔══██║██║  ██║██║  ██║██╔══██╗██╔══╝  ╚════██║╚════██║    ██║   ██║╚════██║██║██║╚██╗██║   ██║   ");
  console.log("██║  ██║██████╔╝██████╔╝██║  ██║███████╗███████║███████║    ╚██████╔╝███████║██║██║ ╚████║   ██║   ");
  console.log("╚═╝  ╚═╝╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝     ╚═════╝ ╚══════╝╚═╝╚═╝  ╚═══╝   ╚═╝   ");
  console.log("\x1b[0m");
  console.log("\x1b[35m🥝 NIKA Address OSINT - Property & Location Intelligence\x1b[0m");
  console.log("\x1b[33m⚠️  For authorized investigation only - Respect privacy laws\x1b[0m\n");
}

function parseAddress(address) {
  const encoded = encodeURIComponent(address);
  const simplified = address.replace(/[,\.]/g, ' ').replace(/\s+/g, ' ').trim();
  
  return {
    original: address,
    encoded: encoded,
    simplified: simplified,
    words: simplified.split(' ')
  };
}

function generateSearchLinks(address) {
  const parsed = parseAddress(address);
  const links = {};
  
  // Property databases
  links.usa = {};
  Object.entries(PROPERTY_DATABASES.usa).forEach(([key, db]) => {
    links.usa[key] = db.search + parsed.encoded;
  });
  
  links.uk = {};
  Object.entries(PROPERTY_DATABASES.uk).forEach(([key, db]) => {
    links.uk[key] = db.search + parsed.encoded;
  });
  
  links.global = {};
  Object.entries(PROPERTY_DATABASES.global).forEach(([key, db]) => {
    links.global[key] = db.search + parsed.encoded;
  });
  
  // Reverse lookup
  links.reverse = {};
  Object.entries(REVERSE_ADDRESS_LOOKUP).forEach(([key, db]) => {
    links.reverse[key] = db.url + parsed.encoded;
  });
  
  return links;
}

function generateGoogleDorks(address) {
  return [
    `"${address}"`,
    `"${address}" site:zillow.com`,
    `"${address}" site:realtor.com`,
    `"${address}" "owner" OR "resident"`,
    `"${address}" "sold" OR "sale"`,
    `"${address}" "property" OR "real estate"`,
    `"${address}" site:whitepages.com`,
    `"${address}" site:facebook.com`,
    `"${address}" site:linkedin.com`,
    `"${address}" "phone" OR "email"`,
    `"${address}" filetype:pdf`,
    `"${address}" "tax" OR "assessor"`
  ];
}

function displayResults(data) {
  console.log("\n╔════════════════════════════════════════════════════════╗");
  console.log("║       🏠 ADDRESS OSINT RESULTS 🏠                      ║");
  console.log("╚════════════════════════════════════════════════════════╝\n");
  
  console.log(`📍 Address: \x1b[36m${data.address}\x1b[0m\n`);
  
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
  console.log("\x1b[36m🏘️  USA PROPERTY DATABASES\x1b[0m");
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
  
  Object.entries(PROPERTY_DATABASES.usa).forEach(([key, db]) => {
    console.log(`   \x1b[32m${db.name}\x1b[0m (${db.cost})`);
    console.log(`      URL: ${data.searchLinks.usa[key]}`);
    console.log(`      Features: ${db.features.join(', ')}\n`);
  });
  
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
  console.log("\x1b[36m🇬🇧 UK PROPERTY DATABASES\x1b[0m");
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
  
  Object.entries(PROPERTY_DATABASES.uk).forEach(([key, db]) => {
    console.log(`   \x1b[32m${db.name}\x1b[0m (${db.cost})`);
    console.log(`      URL: ${data.searchLinks.uk[key]}`);
    console.log(`      Features: ${db.features.join(', ')}\n`);
  });
  
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
  console.log("\x1b[36m🌍 GLOBAL MAPPING\x1b[0m");
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
  
  Object.entries(PROPERTY_DATABASES.global).forEach(([key, db]) => {
    console.log(`   \x1b[32m${db.name}\x1b[0m`);
    console.log(`      URL: ${data.searchLinks.global[key]}`);
    console.log(`      Features: ${db.features.join(', ')}\n`);
  });
  
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
  console.log("\x1b[36m🔍 REVERSE ADDRESS LOOKUP\x1b[0m");
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
  
  Object.entries(REVERSE_ADDRESS_LOOKUP).forEach(([key, db]) => {
    console.log(`   \x1b[32m${db.name}\x1b[0m (${db.cost})`);
    console.log(`      URL: ${data.searchLinks.reverse[key]}`);
    console.log(`      Features: ${db.features.join(', ')}\n`);
  });
  
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
  console.log("\x1b[36m📋 TAX ASSESSOR RECORDS\x1b[0m");
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
  
  console.log(`   💡 ${TAX_ASSESSOR_RECORDS.info}`);
  console.log(`   🔍 ${TAX_ASSESSOR_RECORDS.search}\n`);
  
  console.log('   \x1b[32mData Available:\x1b[0m');
  TAX_ASSESSOR_RECORDS.data.forEach(item => {
    console.log(`      • ${item}`);
  });
  console.log('');
  
  console.log('   \x1b[32mExample County Sites:\x1b[0m');
  Object.entries(TAX_ASSESSOR_RECORDS.examples).forEach(([county, url]) => {
    console.log(`      ${county}: ${url}`);
  });
  console.log('');
  
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
  console.log("\x1b[36m🏘️  NEIGHBORHOOD INTELLIGENCE\x1b[0m");
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
  
  console.log('   \x1b[32mCrime Data:\x1b[0m');
  Object.entries(NEIGHBORHOOD_INTEL.crime).forEach(([name, url]) => {
    console.log(`      • ${name}: ${url}`);
  });
  console.log('');
  
  console.log('   \x1b[32mDemographics:\x1b[0m');
  Object.entries(NEIGHBORHOOD_INTEL.demographics).forEach(([name, url]) => {
    console.log(`      • ${name}: ${url}`);
  });
  console.log('');
  
  console.log('   \x1b[32mSchools:\x1b[0m');
  Object.entries(NEIGHBORHOOD_INTEL.schools).forEach(([name, url]) => {
    console.log(`      • ${name}: ${url}`);
  });
  console.log('');
  
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
  console.log("\x1b[36m🔍 GOOGLE DORKS\x1b[0m");
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
  
  data.googleDorks.forEach((dork, i) => {
    console.log(`   ${i + 1}. ${dork}`);
  });
  console.log('');
  
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
  console.log("\x1b[36m💡 INVESTIGATION WORKFLOW\x1b[0m");
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
  
  console.log('   \x1b[32m1. Property Records:\x1b[0m');
  console.log('      • Search Zillow/Realtor for property value');
  console.log('      • Check county tax assessor for owner name');
  console.log('      • Look up sale history and prices');
  console.log('      • Note lot size and square footage\n');
  
  console.log('   \x1b[32m2. Resident Identification:\x1b[0m');
  console.log('      • Use reverse address lookup (Whitepages)');
  console.log('      • Check for current and past residents');
  console.log('      • Look for associated phone numbers');
  console.log('      • Search for email addresses\n');
  
  console.log('   \x1b[32m3. Visual Intelligence:\x1b[0m');
  console.log('      • Check Google Street View (current)');
  console.log('      • Review historical Street View images');
  console.log('      • Use Google Earth for satellite view');
  console.log('      • Look for security cameras/features\n');
  
  console.log('   \x1b[32m4. Neighborhood Context:\x1b[0m');
  console.log('      • Check crime statistics');
  console.log('      • Review demographics data');
  console.log('      • Look at school ratings');
  console.log('      • Check nearby businesses\n');
  
  console.log('   \x1b[32m5. Cross-Reference:\x1b[0m');
  console.log('      • Search address on social media');
  console.log('      • Look for business registrations');
  console.log('      • Check voter records (public)');
  console.log('      • Review court records\n');
}

function saveReport(data) {
  const dir = './address-osint-reports';
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, -5);
  const safeName = data.address.replace(/[^a-zA-Z0-9]/g, '-').substring(0, 50);
  const filename = `${dir}/address-${safeName}-${timestamp}.txt`;
  
  let content = `═══════════════════════════════════════════════════════════
ADDRESS OSINT REPORT
═══════════════════════════════════════════════════════════

Address: ${data.address}
Date: ${new Date().toLocaleString()}

USA PROPERTY DATABASES:
`;

  Object.entries(PROPERTY_DATABASES.usa).forEach(([key, db]) => {
    content += `\n${db.name}:\n${data.searchLinks.usa[key]}\n`;
  });
  
  content += `\nUK PROPERTY DATABASES:\n`;
  Object.entries(PROPERTY_DATABASES.uk).forEach(([key, db]) => {
    content += `\n${db.name}:\n${data.searchLinks.uk[key]}\n`;
  });
  
  content += `\nREVERSE ADDRESS LOOKUP:\n`;
  Object.entries(REVERSE_ADDRESS_LOOKUP).forEach(([key, db]) => {
    content += `\n${db.name}:\n${data.searchLinks.reverse[key]}\n`;
  });
  
  content += `\nGOOGLE DORKS:\n`;
  data.googleDorks.forEach((dork, i) => {
    content += `${i + 1}. ${dork}\n`;
  });
  
  fs.writeFileSync(filename, content);
  console.log(`\x1b[32m✅ Report saved: ${filename}\x1b[0m\n`);
}

function showHelp() {
  showBanner();
  
  console.log("Usage: node address-osint.js \"<address>\" [--save]\n");
  console.log("Options:");
  console.log("  --save               Save report to file");
  console.log("  --help               Show this help\n");
  
  console.log("Examples:");
  console.log("  node address-osint.js \"123 Main St, New York, NY\"");
  console.log("  node address-osint.js \"10 Downing Street, London\" --save\n");
}

function main() {
  const args = process.argv.slice(2);
  
  if (args.length === 0 || args.includes('--help')) {
    showHelp();
    process.exit(0);
  }
  
  showBanner();
  
  let address = null;
  let saveFlag = false;
  
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--save') {
      saveFlag = true;
    } else if (!args[i].startsWith('--')) {
      address = args[i];
    }
  }
  
  if (!address) {
    console.log("\x1b[31m❌ No address specified!\x1b[0m\n");
    showHelp();
    process.exit(1);
  }
  
  console.log(`⏳ Analyzing address: ${address}...\n`);
  
  const results = {
    timestamp: new Date().toISOString(),
    address: address,
    searchLinks: generateSearchLinks(address),
    googleDorks: generateGoogleDorks(address)
  };
  
  displayResults(results);
  
  if (saveFlag) {
    saveReport(results);
  }
  
  console.log("\x1b[31m █████╗ ██████╗ ██████╗ ██████╗ ███████╗███████╗███████╗\x1b[0m");
  console.log("\x1b[35m🥝 Analysis complete - by kiwi & 777\x1b[0m\n");
}

main();
