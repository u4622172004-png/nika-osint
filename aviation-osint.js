#!/usr/bin/env node

const https = require('https');
const fs = require('fs');

// ============================================
// AVIATION OSINT - Flight & Aircraft Intelligence
// ============================================

const FLIGHT_TRACKERS = {
  flightradar24: {
    name: 'FlightRadar24',
    url: 'https://www.flightradar24.com/',
    search: 'https://www.flightradar24.com/data/aircraft/',
    features: ['Live tracking', 'Flight history', 'Aircraft photos', 'Playback'],
    coverage: 'Global',
    cost: 'Free/Premium',
    api: true
  },
  flightaware: {
    name: 'FlightAware',
    url: 'https://www.flightaware.com/',
    search: 'https://www.flightaware.com/live/flight/',
    features: ['Flight tracking', 'Airport delays', 'Weather', 'Historical data'],
    coverage: 'Global',
    cost: 'Free/Premium',
    api: true
  },
  adsbexchange: {
    name: 'ADS-B Exchange',
    url: 'https://www.adsbexchange.com/',
    search: 'https://globe.adsbexchange.com/',
    features: ['Unfiltered data', 'Military aircraft', 'No blocking'],
    coverage: 'Global',
    cost: 'Free',
    api: true
  },
  planefinder: {
    name: 'Plane Finder',
    url: 'https://planefinder.net/',
    features: ['3D view', 'Photos', 'Airport info'],
    coverage: 'Global',
    cost: 'Free/Premium',
    api: false
  },
  radarbox: {
    name: 'RadarBox',
    url: 'https://www.radarbox.com/',
    features: ['Live tracking', 'Photos', 'Statistics'],
    coverage: 'Global',
    cost: 'Free/Premium',
    api: true
  }
};

const AIRCRAFT_DATABASES = {
  faa: {
    name: 'FAA Registry',
    url: 'https://registry.faa.gov/aircraftinquiry/',
    search: 'https://registry.faa.gov/aircraftinquiry/Search/NNumberInquiry',
    coverage: 'USA (N-numbers)',
    data: ['Owner name', 'Address', 'Aircraft type', 'Serial number', 'Manufacturer'],
    cost: 'Free'
  },
  planespotters: {
    name: 'Planespotters.net',
    url: 'https://www.planespotters.net/',
    search: 'https://www.planespotters.net/search?q=',
    coverage: 'Global',
    data: ['Registration', 'Type', 'Airline', 'Photos', 'History'],
    cost: 'Free'
  },
  jetphotos: {
    name: 'JetPhotos',
    url: 'https://www.jetphotos.com/',
    search: 'https://www.jetphotos.com/search?q=',
    coverage: 'Global',
    data: ['Photos', 'Aircraft info', 'Airline data'],
    cost: 'Free'
  },
  airframes: {
    name: 'Airframes.org',
    url: 'https://www.airframes.org/',
    coverage: 'Global',
    data: ['Serial numbers', 'Production lists', 'History'],
    cost: 'Free'
  }
};

const AIRPORT_INFO = {
  ourairports: {
    name: 'OurAirports',
    url: 'https://ourairports.com/',
    features: ['Airport data', 'Runways', 'Frequencies', 'Charts'],
    cost: 'Free'
  },
  gcmap: {
    name: 'Great Circle Mapper',
    url: 'https://www.gcmap.com/',
    features: ['Route maps', 'Distance calculation', 'Airport codes'],
    cost: 'Free'
  },
  skyvector: {
    name: 'SkyVector',
    url: 'https://skyvector.com/',
    features: ['Aviation charts', 'Flight planning', 'Weather'],
    cost: 'Free'
  }
};

const SPECIAL_AIRCRAFT = {
  military: {
    name: 'Military Aircraft',
    identifiers: ['Blocked on commercial trackers', 'Use ADS-B Exchange'],
    callsigns: ['Various tactical callsigns', 'Often blocked/filtered'],
    tracking: 'ADS-B Exchange, Scramble'
  },
  government: {
    name: 'Government/VIP',
    examples: ['Air Force One', 'SAM (Special Air Mission)', 'Executive jets'],
    tracking: 'Often visible but with delayed/filtered data'
  },
  private: {
    name: 'Private Jets',
    blocking: 'Many use LADD/PIA blocking programs',
    tracking: 'May be filtered on FlightRadar24/FlightAware'
  }
};

const TAIL_NUMBER_FORMATS = {
  usa: {
    prefix: 'N',
    format: 'N12345 or N123AB',
    example: 'N12345',
    registry: 'FAA Registry'
  },
  uk: {
    prefix: 'G-',
    format: 'G-ABCD',
    example: 'G-BOAC',
    registry: 'UK CAA'
  },
  canada: {
    prefix: 'C-',
    format: 'C-ABCD',
    example: 'C-GABC',
    registry: 'Transport Canada'
  },
  germany: {
    prefix: 'D-',
    format: 'D-ABCD',
    example: 'D-AIRC',
    registry: 'German LBA'
  },
  france: {
    prefix: 'F-',
    format: 'F-ABCD',
    example: 'F-GFKL',
    registry: 'French DGAC'
  }
};

function showBanner() {
  console.log("\x1b[31m");
  console.log(" █████╗ ██╗   ██╗██╗ █████╗ ████████╗██╗ ██████╗ ███╗   ██╗");
  console.log("██╔══██╗██║   ██║██║██╔══██╗╚══██╔══╝██║██╔═══██╗████╗  ██║");
  console.log("███████║██║   ██║██║███████║   ██║   ██║██║   ██║██╔██╗ ██║");
  console.log("██╔══██║╚██╗ ██╔╝██║██╔══██║   ██║   ██║██║   ██║██║╚██╗██║");
  console.log("██║  ██║ ╚████╔╝ ██║██║  ██║   ██║   ██║╚██████╔╝██║ ╚████║");
  console.log("╚═╝  ╚═╝  ╚═══╝  ╚═╝╚═╝  ╚═╝   ╚═╝   ╚═╝ ╚═════╝ ╚═╝  ╚═══╝");
  console.log("                                                             ");
  console.log(" ██████╗ ███████╗██╗███╗   ██╗████████╗                     ");
  console.log("██╔═══██╗██╔════╝██║████╗  ██║╚══██╔══╝                     ");
  console.log("██║   ██║███████╗██║██╔██╗ ██║   ██║                        ");
  console.log("██║   ██║╚════██║██║██║╚██╗██║   ██║                        ");
  console.log("╚██████╔╝███████║██║██║ ╚████║   ██║                        ");
  console.log(" ╚═════╝ ╚══════╝╚═╝╚═╝  ╚═══╝   ╚═╝                        ");
  console.log("\x1b[0m");
  console.log("\x1b[35m🥝 NIKA Aviation OSINT - Flight & Aircraft Intelligence\x1b[0m");
  console.log("\x1b[33m⚠️  For authorized aviation research only\x1b[0m\n");
}

function identifyRegistration(input) {
  const cleaned = input.toUpperCase().replace(/\s/g, '');
  
  for (let [country, format] of Object.entries(TAIL_NUMBER_FORMATS)) {
    if (cleaned.startsWith(format.prefix)) {
      return {
        valid: true,
        registration: cleaned,
        country: country,
        format: format.format,
        registry: format.registry,
        example: format.example
      };
    }
  }
  
  // Could be ICAO hex or other format
  if (/^[A-F0-9]{6}$/.test(cleaned)) {
    return {
      valid: true,
      registration: cleaned,
      type: 'ICAO Hex',
      note: 'Use Mode-S decoder to find registration'
    };
  }
  
  return {
    valid: false,
    registration: cleaned,
    error: 'Unknown registration format'
  };
}

function generateSearchLinks(identifier) {
  const encoded = encodeURIComponent(identifier);
  
  return {
    flightradar24: `https://www.flightradar24.com/data/aircraft/${encoded}`,
    flightaware: `https://www.flightaware.com/live/flight/${encoded}`,
    adsbexchange: `https://globe.adsbexchange.com/?icao=${encoded}`,
    planespotters: `https://www.planespotters.net/search?q=${encoded}`,
    jetphotos: `https://www.jetphotos.com/search?q=${encoded}`,
    faa: identifier.toUpperCase().startsWith('N') 
      ? `https://registry.faa.gov/aircraftinquiry/Search/NNumberResult?nNumberTxt=${encoded}`
      : null,
    radarbox: `https://www.radarbox.com/data/registration/${encoded}`
  };
}

function displayResults(data) {
  console.log("\n╔════════════════════════════════════════════════════════╗");
  console.log("║       ✈️  AVIATION OSINT RESULTS ✈️                     ║");
  console.log("╚════════════════════════════════════════════════════════╝\n");
  
  if (data.identifier) {
    console.log(`🔍 Identifier: \x1b[36m${data.identifier}\x1b[0m\n`);
    
    if (data.registration) {
      console.log("\x1b[36m┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓\x1b[0m");
      console.log("\x1b[36m┃                  REGISTRATION INFO                   ┃\x1b[0m");
      console.log("\x1b[36m┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛\x1b[0m\n");
      
      if (data.registration.valid) {
        console.log(`   Registration:        ${data.registration.registration}`);
        if (data.registration.country) {
          console.log(`   Country:             ${data.registration.country.toUpperCase()}`);
          console.log(`   Format:              ${data.registration.format}`);
          console.log(`   Registry:            ${data.registration.registry}`);
        } else if (data.registration.type) {
          console.log(`   Type:                ${data.registration.type}`);
          console.log(`   Note:                ${data.registration.note}`);
        }
      } else {
        console.log(`   Status:              ${data.registration.error}`);
      }
      console.log('');
    }
    
    if (data.searchLinks) {
      console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
      console.log("\x1b[36m🔗 TRACKING LINKS\x1b[0m");
      console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
      
      Object.entries(data.searchLinks).forEach(([platform, url]) => {
        if (url) {
          console.log(`   ${platform.charAt(0).toUpperCase() + platform.slice(1).padEnd(18)}: ${url}`);
        }
      });
      console.log('');
    }
  }
  
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
  console.log("\x1b[36m✈️  FLIGHT TRACKING PLATFORMS\x1b[0m");
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
  
  Object.entries(FLIGHT_TRACKERS).forEach(([key, tracker]) => {
    console.log(`   \x1b[32m${tracker.name}\x1b[0m (${tracker.cost})`);
    console.log(`      URL: ${tracker.url}`);
    console.log(`      Features: ${tracker.features.join(', ')}`);
    console.log(`      API: ${tracker.api ? 'Yes' : 'No'}\n`);
  });
  
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
  console.log("\x1b[36m🛩️  AIRCRAFT DATABASES\x1b[0m");
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
  
  Object.entries(AIRCRAFT_DATABASES).forEach(([key, db]) => {
    console.log(`   \x1b[32m${db.name}\x1b[0m (${db.cost})`);
    console.log(`      URL: ${db.url}`);
    console.log(`      Coverage: ${db.coverage}`);
    console.log(`      Data: ${db.data.join(', ')}\n`);
  });
  
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
  console.log("\x1b[36m🛫 AIRPORT RESOURCES\x1b[0m");
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
  
  Object.entries(AIRPORT_INFO).forEach(([key, resource]) => {
    console.log(`   \x1b[32m${resource.name}\x1b[0m (${resource.cost})`);
    console.log(`      URL: ${resource.url}`);
    console.log(`      Features: ${resource.features.join(', ')}\n`);
  });
  
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
  console.log("\x1b[36m🎖️  SPECIAL AIRCRAFT CATEGORIES\x1b[0m");
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
  
  Object.entries(SPECIAL_AIRCRAFT).forEach(([key, category]) => {
    console.log(`   \x1b[32m${category.name}\x1b[0m`);
    if (category.identifiers) console.log(`      Identifiers: ${category.identifiers.join(', ')}`);
    if (category.examples) console.log(`      Examples: ${category.examples.join(', ')}`);
    if (category.blocking) console.log(`      Blocking: ${category.blocking}`);
    if (category.tracking) console.log(`      Tracking: ${category.tracking}`);
    console.log('');
  });
  
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
  console.log("\x1b[36m🌍 REGISTRATION FORMATS\x1b[0m");
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
  
  Object.entries(TAIL_NUMBER_FORMATS).forEach(([country, format]) => {
    console.log(`   \x1b[32m${country.toUpperCase()}\x1b[0m`);
    console.log(`      Prefix: ${format.prefix}`);
    console.log(`      Format: ${format.format}`);
    console.log(`      Example: ${format.example}`);
    console.log(`      Registry: ${format.registry}\n`);
  });
  
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
  console.log("\x1b[36m💡 INVESTIGATION TECHNIQUES\x1b[0m");
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
  
  console.log('   \x1b[32m1. Tail Number Lookup:\x1b[0m');
  console.log('      • Identify country from prefix');
  console.log('      • Search national registry (FAA, CAA, etc.)');
  console.log('      • Find owner name and address');
  console.log('      • Check aircraft type and serial number\n');
  
  console.log('   \x1b[32m2. Live Tracking:\x1b[0m');
  console.log('      • FlightRadar24 for commercial flights');
  console.log('      • ADS-B Exchange for military/unfiltered');
  console.log('      • Check multiple platforms');
  console.log('      • Screenshot for evidence\n');
  
  console.log('   \x1b[32m3. Historical Analysis:\x1b[0m');
  console.log('      • FlightAware flight history');
  console.log('      • Look for patterns (routes, times)');
  console.log('      • Check past airports visited');
  console.log('      • Analyze frequency of flights\n');
  
  console.log('   \x1b[32m4. Owner Research:\x1b[0m');
  console.log('      • Registry data for owner name');
  console.log('      • Corporate records if company-owned');
  console.log('      • Cross-reference with business databases');
  console.log('      • Check for shell companies/trusts\n');
  
  console.log('   \x1b[32m5. Photo Intelligence:\x1b[0m');
  console.log('      • Planespotters.net for aircraft photos');
  console.log('      • JetPhotos for more images');
  console.log('      • Check livery for airline/owner');
  console.log('      • Verify registration markings\n');
}

function saveReport(data) {
  const dir = './aviation-osint-reports';
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, -5);
  const safeName = data.identifier ? data.identifier.replace(/[^a-zA-Z0-9]/g, '-') : 'general';
  const filename = `${dir}/aviation-${safeName}-${timestamp}.txt`;
  
  let content = `═══════════════════════════════════════════════════════════
AVIATION OSINT REPORT
═══════════════════════════════════════════════════════════

Date: ${new Date().toLocaleString()}

`;

  if (data.identifier) {
    content += `IDENTIFIER: ${data.identifier}\n\n`;
    
    if (data.registration && data.registration.valid) {
      content += `REGISTRATION INFO:\n`;
      content += `Registration: ${data.registration.registration}\n`;
      if (data.registration.country) {
        content += `Country: ${data.registration.country.toUpperCase()}\n`;
        content += `Format: ${data.registration.format}\n`;
        content += `Registry: ${data.registration.registry}\n`;
      }
      content += '\n';
    }
    
    if (data.searchLinks) {
      content += `TRACKING LINKS:\n`;
      Object.entries(data.searchLinks).forEach(([platform, url]) => {
        if (url) content += `${platform}: ${url}\n`;
      });
      content += '\n';
    }
  }
  
  content += `FLIGHT TRACKING PLATFORMS:\n`;
  Object.entries(FLIGHT_TRACKERS).forEach(([key, tracker]) => {
    content += `\n${tracker.name}:\n${tracker.url}\n`;
  });
  
  content += `\nAIRCRAFT DATABASES:\n`;
  Object.entries(AIRCRAFT_DATABASES).forEach(([key, db]) => {
    content += `\n${db.name}:\n${db.url}\n`;
  });
  
  fs.writeFileSync(filename, content);
  console.log(`\x1b[32m✅ Report saved: ${filename}\x1b[0m\n`);
}

function showHelp() {
  showBanner();
  
  console.log("Usage: node aviation-osint.js [OPTIONS] [identifier]\n");
  console.log("Options:");
  console.log("  --tail <registration>    Lookup tail number");
  console.log("  --flight <number>        Track flight number");
  console.log("  --list                   List all platforms");
  console.log("  --save                   Save report to file");
  console.log("  --help                   Show this help\n");
  
  console.log("Examples:");
  console.log("  node aviation-osint.js --tail N12345");
  console.log("  node aviation-osint.js --flight AA100");
  console.log("  node aviation-osint.js --list");
  console.log("  node aviation-osint.js --tail G-BOAC --save\n");
}

function main() {
  const args = process.argv.slice(2);
  
  if (args.length === 0 || args.includes('--help')) {
    showHelp();
    process.exit(0);
  }
  
  showBanner();
  
  if (args.includes('--list')) {
    console.log("Aviation Tracking Platforms:\n");
    Object.entries(FLIGHT_TRACKERS).forEach(([key, tracker]) => {
      console.log(`   \x1b[32m${tracker.name}\x1b[0m`);
      console.log(`      ${tracker.url}\n`);
    });
    process.exit(0);
  }
  
  let identifier = null;
  let saveFlag = false;
  
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--tail' || args[i] === '--flight') {
      identifier = args[i + 1];
      i++;
    } else if (args[i] === '--save') {
      saveFlag = true;
    } else if (!args[i].startsWith('--')) {
      identifier = args[i];
    }
  }
  
  const results = {
    timestamp: new Date().toISOString(),
    identifier: identifier,
    registration: null,
    searchLinks: null
  };
  
  if (identifier) {
    console.log(`⏳ Looking up: ${identifier}...\n`);
    
    results.registration = identifyRegistration(identifier);
    results.searchLinks = generateSearchLinks(identifier);
  } else {
    console.log(`⏳ Generating aviation platform guide...\n`);
  }
  
  displayResults(results);
  
  if (saveFlag) {
    saveReport(results);
  }
  
  console.log("\x1b[31m █████╗ ██╗   ██╗██╗ █████╗ ████████╗██╗ ██████╗ ███╗   ██╗\x1b[0m");
  console.log("\x1b[35m🥝 Analysis complete - by kiwi & 777\x1b[0m\n");
}

main();
