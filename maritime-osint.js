#!/usr/bin/env node

const https = require('https');
const fs = require('fs');

// ============================================
// MARITIME OSINT - Ship & Vessel Intelligence
// ============================================

const VESSEL_TRACKERS = {
  marinetraffic: {
    name: 'MarineTraffic',
    url: 'https://www.marinetraffic.com/',
    search: 'https://www.marinetraffic.com/en/ais/home/shipid:',
    features: ['Live AIS tracking', 'Port calls', 'Photos', 'Ship details', 'Historical data'],
    coverage: 'Global',
    cost: 'Free/Premium',
    api: true
  },
  vesselfinder: {
    name: 'VesselFinder',
    url: 'https://www.vesselfinder.com/',
    search: 'https://www.vesselfinder.com/vessels/',
    features: ['Real-time tracking', 'Port arrivals', 'Fleet tracking'],
    coverage: 'Global',
    cost: 'Free/Premium',
    api: true
  },
  fleetmon: {
    name: 'FleetMon',
    url: 'https://www.fleetmon.com/',
    search: 'https://www.fleetmon.com/vessels/',
    features: ['AIS tracking', 'Photos', 'Port database', 'Schedules'],
    coverage: 'Global',
    cost: 'Free/Premium',
    api: true
  },
  myshiptracking: {
    name: 'MyShipTracking',
    url: 'https://www.myshiptracking.com/',
    features: ['Free tracking', 'Port info', 'Weather'],
    coverage: 'Global',
    cost: 'Free',
    api: false
  },
  cruisemapper: {
    name: 'CruiseMapper',
    url: 'https://www.cruisemapper.com/',
    features: ['Cruise ship tracking', 'Itineraries', 'Deck plans'],
    coverage: 'Cruise ships',
    cost: 'Free',
    api: false
  }
};

const SHIP_REGISTRIES = {
  equasis: {
    name: 'Equasis',
    url: 'https://www.equasis.org/',
    coverage: 'Global',
    data: ['Ship details', 'Safety records', 'Port state control', 'Ownership'],
    cost: 'Free (registration required)'
  },
  imo: {
    name: 'IMO Database',
    url: 'https://gisis.imo.org/',
    coverage: 'Global',
    data: ['IMO number lookup', 'Safety data', 'Certificates'],
    cost: 'Free'
  },
  ihs: {
    name: 'IHS Markit Sea-web',
    url: 'https://maritime.ihs.com/',
    coverage: 'Global',
    data: ['Fleet data', 'Ownership', 'Technical specs'],
    cost: 'Commercial/Paid'
  },
  lloyds: {
    name: 'Lloyd\'s List Intelligence',
    url: 'https://lloydslist.maritimeintelligence.informa.com/',
    coverage: 'Global',
    data: ['Ship movements', 'Port calls', 'Trade flows'],
    cost: 'Commercial/Paid'
  }
};

const PORT_DATABASES = {
  searates: {
    name: 'SeaRates',
    url: 'https://www.searates.com/maritime/',
    features: ['Port info', 'Distances', 'Routes', 'Schedules'],
    cost: 'Free'
  },
  worldportsource: {
    name: 'World Port Source',
    url: 'https://www.worldportsource.com/',
    features: ['Port database', 'Facilities', 'Services'],
    cost: 'Free'
  },
  ports: {
    name: 'Ports.com',
    url: 'https://ports.com/',
    features: ['Port directory', 'Webcams', 'News'],
    cost: 'Free'
  }
};

const SPECIALIZED_TOOLS = {
  sanctions: {
    'OFAC Sanctions': 'https://sanctionssearch.ofac.treas.gov/',
    'EU Sanctions': 'https://webgate.ec.europa.eu/fsd/fsf',
    'UN Sanctions': 'https://www.un.org/securitycouncil/sanctions/information'
  },
  piracy: {
    'ICC Piracy Map': 'https://www.icc-ccs.org/piracy-reporting-centre',
    'UKMTO': 'https://www.ukmto.org/'
  },
  environment: {
    'Global Fishing Watch': 'https://globalfishingwatch.org/',
    'Oil Spill Detection': 'https://www.esa.int/Applications/Observing_the_Earth'
  },
  cargo: {
    'Container Tracking': 'https://www.track-trace.com/container',
    'Bill of Lading': 'https://www.searates.com/container/tracking/'
  }
};

const VESSEL_IDENTIFIERS = {
  imo: {
    name: 'IMO Number',
    format: '7-digit number (IMO 1234567)',
    description: 'Unique identifier assigned to ships',
    permanent: true,
    example: 'IMO 9876543'
  },
  mmsi: {
    name: 'MMSI',
    format: '9-digit number',
    description: 'Maritime Mobile Service Identity',
    permanent: false,
    example: '123456789'
  },
  callsign: {
    name: 'Call Sign',
    format: 'Alpha-numeric',
    description: 'Radio call sign',
    permanent: false,
    example: 'ABCD1'
  },
  flag: {
    name: 'Flag State',
    description: 'Country of registration',
    examples: ['Panama', 'Liberia', 'Marshall Islands', 'Malta']
  }
};

function showBanner() {
  console.log("\x1b[31m");
  console.log("███╗   ███╗ █████╗ ██████╗ ██╗████████╗██╗███╗   ███╗███████╗");
  console.log("████╗ ████║██╔══██╗██╔══██╗██║╚══██╔══╝██║████╗ ████║██╔════╝");
  console.log("██╔████╔██║███████║██████╔╝██║   ██║   ██║██╔████╔██║█████╗  ");
  console.log("██║╚██╔╝██║██╔══██║██╔══██╗██║   ██║   ██║██║╚██╔╝██║██╔══╝  ");
  console.log("██║ ╚═╝ ██║██║  ██║██║  ██║██║   ██║   ██║██║ ╚═╝ ██║███████╗");
  console.log("╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝   ╚═╝   ╚═╝╚═╝     ╚═╝╚══════╝");
  console.log("                                                               ");
  console.log(" ██████╗ ███████╗██╗███╗   ██╗████████╗                       ");
  console.log("██╔═══██╗██╔════╝██║████╗  ██║╚══██╔══╝                       ");
  console.log("██║   ██║███████╗██║██╔██╗ ██║   ██║                          ");
  console.log("██║   ██║╚════██║██║██║╚██╗██║   ██║                          ");
  console.log("╚██████╔╝███████║██║██║ ╚████║   ██║                          ");
  console.log(" ╚═════╝ ╚══════╝╚═╝╚═╝  ╚═══╝   ╚═╝                          ");
  console.log("\x1b[0m");
  console.log("\x1b[35m🥝 NIKA Maritime OSINT - Ship & Vessel Intelligence\x1b[0m");
  console.log("\x1b[33m⚠️  For authorized maritime research only\x1b[0m\n");
}

function identifyVessel(input) {
  const cleaned = input.replace(/\s/g, '');
  
  // IMO number format: IMO + 7 digits
  if (/^IMO\d{7}$/i.test(cleaned)) {
    return {
      valid: true,
      type: 'IMO Number',
      identifier: cleaned.toUpperCase(),
      format: VESSEL_IDENTIFIERS.imo.format,
      permanent: true
    };
  }
  
  // MMSI: 9 digits
  if (/^\d{9}$/.test(cleaned)) {
    return {
      valid: true,
      type: 'MMSI',
      identifier: cleaned,
      format: VESSEL_IDENTIFIERS.mmsi.format,
      permanent: false
    };
  }
  
  // Call sign or vessel name
  if (/^[A-Z0-9]{3,}$/i.test(cleaned)) {
    return {
      valid: true,
      type: 'Call Sign or Vessel Name',
      identifier: cleaned.toUpperCase(),
      note: 'Could be call sign or vessel name - check both'
    };
  }
  
  return {
    valid: true,
    type: 'Vessel Name',
    identifier: input,
    note: 'Searching by vessel name'
  };
}

function generateSearchLinks(identifier) {
  const encoded = encodeURIComponent(identifier);
  
  return {
    marinetraffic: `https://www.marinetraffic.com/en/ais/home/shipid:0/shipname:${encoded}`,
    vesselfinder: `https://www.vesselfinder.com/vessels?name=${encoded}`,
    fleetmon: `https://www.fleetmon.com/vessels/?quick_search=${encoded}`,
    myshiptracking: `https://www.myshiptracking.com/?search=${encoded}`,
    equasis: `https://www.equasis.org/EquasisWeb/public/HomePage`,
    imo: `https://gisis.imo.org/Public/Default.aspx`
  };
}

function displayResults(data) {
  console.log("\n╔════════════════════════════════════════════════════════╗");
  console.log("║       🚢 MARITIME OSINT RESULTS 🚢                     ║");
  console.log("╚════════════════════════════════════════════════════════╝\n");
  
  if (data.vessel) {
    console.log(`🔍 Query: \x1b[36m${data.query}\x1b[0m\n`);
    
    console.log("\x1b[36m┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓\x1b[0m");
    console.log("\x1b[36m┃                  VESSEL IDENTIFICATION               ┃\x1b[0m");
    console.log("\x1b[36m┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛\x1b[0m\n");
    
    console.log(`   Type:                ${data.vessel.type}`);
    console.log(`   Identifier:          ${data.vessel.identifier}`);
    if (data.vessel.format) console.log(`   Format:              ${data.vessel.format}`);
    if (data.vessel.permanent !== undefined) console.log(`   Permanent ID:        ${data.vessel.permanent ? 'Yes' : 'No'}`);
    if (data.vessel.note) console.log(`   Note:                ${data.vessel.note}`);
    console.log('');
    
    if (data.searchLinks) {
      console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
      console.log("\x1b[36m🔗 TRACKING LINKS\x1b[0m");
      console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
      
      Object.entries(data.searchLinks).forEach(([platform, url]) => {
        console.log(`   ${platform.charAt(0).toUpperCase() + platform.slice(1).padEnd(18)}: ${url}`);
      });
      console.log('');
    }
  }
  
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
  console.log("\x1b[36m🌊 VESSEL TRACKING PLATFORMS\x1b[0m");
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
  
  Object.entries(VESSEL_TRACKERS).forEach(([key, tracker]) => {
    console.log(`   \x1b[32m${tracker.name}\x1b[0m (${tracker.cost})`);
    console.log(`      URL: ${tracker.url}`);
    console.log(`      Coverage: ${tracker.coverage}`);
    console.log(`      Features: ${tracker.features.join(', ')}`);
    console.log(`      API: ${tracker.api ? 'Yes' : 'No'}\n`);
  });
  
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
  console.log("\x1b[36m📋 SHIP REGISTRIES\x1b[0m");
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
  
  Object.entries(SHIP_REGISTRIES).forEach(([key, registry]) => {
    console.log(`   \x1b[32m${registry.name}\x1b[0m (${registry.cost})`);
    console.log(`      URL: ${registry.url}`);
    console.log(`      Coverage: ${registry.coverage}`);
    console.log(`      Data: ${registry.data.join(', ')}\n`);
  });
  
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
  console.log("\x1b[36m⚓ PORT DATABASES\x1b[0m");
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
  
  Object.entries(PORT_DATABASES).forEach(([key, port]) => {
    console.log(`   \x1b[32m${port.name}\x1b[0m (${port.cost})`);
    console.log(`      URL: ${port.url}`);
    console.log(`      Features: ${port.features.join(', ')}\n`);
  });
  
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
  console.log("\x1b[36m🎯 SPECIALIZED TOOLS\x1b[0m");
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
  
  console.log('   \x1b[32mSanctions Screening:\x1b[0m');
  Object.entries(SPECIALIZED_TOOLS.sanctions).forEach(([name, url]) => {
    console.log(`      • ${name}: ${url}`);
  });
  console.log('');
  
  console.log('   \x1b[32mPiracy & Security:\x1b[0m');
  Object.entries(SPECIALIZED_TOOLS.piracy).forEach(([name, url]) => {
    console.log(`      • ${name}: ${url}`);
  });
  console.log('');
  
  console.log('   \x1b[32mEnvironmental Monitoring:\x1b[0m');
  Object.entries(SPECIALIZED_TOOLS.environment).forEach(([name, url]) => {
    console.log(`      • ${name}: ${url}`);
  });
  console.log('');
  
  console.log('   \x1b[32mCargo Tracking:\x1b[0m');
  Object.entries(SPECIALIZED_TOOLS.cargo).forEach(([name, url]) => {
    console.log(`      • ${name}: ${url}`);
  });
  console.log('');
  
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
  console.log("\x1b[36m🆔 VESSEL IDENTIFIER TYPES\x1b[0m");
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
  
  Object.entries(VESSEL_IDENTIFIERS).forEach(([key, id]) => {
    console.log(`   \x1b[32m${id.name}\x1b[0m`);
    console.log(`      Format: ${id.format}`);
    console.log(`      Description: ${id.description}`);
    if (id.permanent !== undefined) console.log(`      Permanent: ${id.permanent ? 'Yes' : 'No'}`);
    if (id.example) console.log(`      Example: ${id.example}`);
    if (id.examples) console.log(`      Examples: ${id.examples.join(', ')}`);
    console.log('');
  });
  
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
  console.log("\x1b[36m💡 INVESTIGATION TECHNIQUES\x1b[0m");
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
  
  console.log('   \x1b[32m1. Vessel Identification:\x1b[0m');
  console.log('      • Start with IMO number (permanent)');
  console.log('      • Cross-check with MMSI and call sign');
  console.log('      • Verify vessel name (can change)');
  console.log('      • Check flag state registration\n');
  
  console.log('   \x1b[32m2. Live Tracking:\x1b[0m');
  console.log('      • MarineTraffic for real-time position');
  console.log('      • Check multiple platforms');
  console.log('      • Note course, speed, destination');
  console.log('      • Screenshot for evidence\n');
  
  console.log('   \x1b[32m3. Historical Analysis:\x1b[0m');
  console.log('      • Port call history');
  console.log('      • Route patterns');
  console.log('      • Time in ports');
  console.log('      • Compare with cargo manifests\n');
  
  console.log('   \x1b[32m4. Ownership Research:\x1b[0m');
  console.log('      • Equasis for registered owner');
  console.log('      • Check beneficial ownership');
  console.log('      • Flag state registry search');
  console.log('      • Corporate records lookup\n');
  
  console.log('   \x1b[32m5. Compliance Checks:\x1b[0m');
  console.log('      • OFAC sanctions screening');
  console.log('      • EU sanctions list');
  console.log('      • Port state control records');
  console.log('      • Safety inspection history\n');
  
  console.log('   \x1b[32m6. Cargo Intelligence:\x1b[0m');
  console.log('      • Container tracking');
  console.log('      • Bill of lading search');
  console.log('      • Port manifests');
  console.log('      • Trade flow analysis\n');
}

function saveReport(data) {
  const dir = './maritime-osint-reports';
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, -5);
  const safeName = data.query ? data.query.replace(/[^a-zA-Z0-9]/g, '-') : 'general';
  const filename = `${dir}/maritime-${safeName}-${timestamp}.txt`;
  
  let content = `═══════════════════════════════════════════════════════════
MARITIME OSINT REPORT
═══════════════════════════════════════════════════════════

Date: ${new Date().toLocaleString()}

`;

  if (data.vessel) {
    content += `QUERY: ${data.query}\n\n`;
    content += `VESSEL IDENTIFICATION:\n`;
    content += `Type: ${data.vessel.type}\n`;
    content += `Identifier: ${data.vessel.identifier}\n`;
    if (data.vessel.format) content += `Format: ${data.vessel.format}\n`;
    content += '\n';
    
    if (data.searchLinks) {
      content += `TRACKING LINKS:\n`;
      Object.entries(data.searchLinks).forEach(([platform, url]) => {
        content += `${platform}: ${url}\n`;
      });
      content += '\n';
    }
  }
  
  content += `VESSEL TRACKING PLATFORMS:\n`;
  Object.entries(VESSEL_TRACKERS).forEach(([key, tracker]) => {
    content += `\n${tracker.name}:\n${tracker.url}\n`;
  });
  
  content += `\nSHIP REGISTRIES:\n`;
  Object.entries(SHIP_REGISTRIES).forEach(([key, registry]) => {
    content += `\n${registry.name}:\n${registry.url}\n`;
  });
  
  fs.writeFileSync(filename, content);
  console.log(`\x1b[32m✅ Report saved: ${filename}\x1b[0m\n`);
}

function showHelp() {
  showBanner();
  
  console.log("Usage: node maritime-osint.js [OPTIONS] [identifier]\n");
  console.log("Options:");
  console.log("  --vessel <name/imo>      Lookup vessel");
  console.log("  --imo <number>           Lookup by IMO number");
  console.log("  --mmsi <number>          Lookup by MMSI");
  console.log("  --list                   List all platforms");
  console.log("  --save                   Save report to file");
  console.log("  --help                   Show this help\n");
  
  console.log("Examples:");
  console.log("  node maritime-osint.js --vessel \"MSC Oscar\"");
  console.log("  node maritime-osint.js --imo IMO9676774");
  console.log("  node maritime-osint.js --mmsi 123456789");
  console.log("  node maritime-osint.js --list");
  console.log("  node maritime-osint.js --vessel \"Ever Given\" --save\n");
}

function main() {
  const args = process.argv.slice(2);
  
  if (args.length === 0 || args.includes('--help')) {
    showHelp();
    process.exit(0);
  }
  
  showBanner();
  
  if (args.includes('--list')) {
    console.log("Maritime Tracking Platforms:\n");
    Object.entries(VESSEL_TRACKERS).forEach(([key, tracker]) => {
      console.log(`   \x1b[32m${tracker.name}\x1b[0m`);
      console.log(`      ${tracker.url}\n`);
    });
    process.exit(0);
  }
  
  let query = null;
  let saveFlag = false;
  
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--vessel' || args[i] === '--imo' || args[i] === '--mmsi') {
      query = args[i + 1];
      i++;
    } else if (args[i] === '--save') {
      saveFlag = true;
    } else if (!args[i].startsWith('--')) {
      query = args[i];
    }
  }
  
  const results = {
    timestamp: new Date().toISOString(),
    query: query,
    vessel: null,
    searchLinks: null
  };
  
  if (query) {
    console.log(`⏳ Looking up vessel: ${query}...\n`);
    
    results.vessel = identifyVessel(query);
    results.searchLinks = generateSearchLinks(query);
  } else {
    console.log(`⏳ Generating maritime platform guide...\n`);
  }
  
  displayResults(results);
  
  if (saveFlag) {
    saveReport(results);
  }
  
  console.log("\x1b[31m███╗   ███╗ █████╗ ██████╗ ██╗████████╗██╗███╗   ███╗███████╗\x1b[0m");
  console.log("\x1b[35m🥝 Analysis complete - by kiwi & 777\x1b[0m\n");
}

main();
