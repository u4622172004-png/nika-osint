#!/usr/bin/env node

const https = require('https');
const fs = require('fs');

// ============================================
// SATELLITE OSINT - Geospatial Intelligence
// ============================================

const SATELLITE_PLATFORMS = {
  sentinel: {
    name: 'Sentinel Hub',
    url: 'https://www.sentinel-hub.com/',
    browser: 'https://apps.sentinel-hub.com/eo-browser/',
    features: ['Sentinel-1/2/3/5P', 'Free access', 'Historical data', 'Near real-time'],
    resolution: '10-60m',
    coverage: 'Global',
    cost: 'Free with registration'
  },
  nasa: {
    name: 'NASA Worldview',
    url: 'https://worldview.earthdata.nasa.gov/',
    features: ['Near real-time', '900+ layers', 'Natural disasters', 'Weather'],
    resolution: '250m-1km',
    coverage: 'Global',
    cost: 'Free'
  },
  googleearth: {
    name: 'Google Earth',
    url: 'https://earth.google.com/',
    features: ['3D terrain', 'Historical imagery', 'Street View integration'],
    resolution: 'Up to 15cm (premium areas)',
    coverage: 'Global',
    cost: 'Free'
  },
  zoom: {
    name: 'Zoom Earth',
    url: 'https://zoom.earth/',
    features: ['Live satellite', 'Weather', 'Fires', 'Storms'],
    resolution: 'Variable',
    coverage: 'Global',
    cost: 'Free'
  },
  eosdis: {
    name: 'NASA EOSDIS Worldview',
    url: 'https://worldview.earthdata.nasa.gov/',
    features: ['Daily imagery', 'Scientific data', 'Export tools'],
    resolution: '250m+',
    coverage: 'Global',
    cost: 'Free'
  },
  planet: {
    name: 'Planet Labs',
    url: 'https://www.planet.com/',
    features: ['Daily global imagery', 'High resolution', 'Change detection'],
    resolution: '3-5m',
    coverage: 'Global',
    cost: 'Commercial/Paid'
  }
};

const COMMERCIAL_PROVIDERS = {
  maxar: {
    name: 'Maxar',
    url: 'https://www.maxar.com/',
    satellites: ['WorldView-1/2/3/4', 'GeoEye-1'],
    resolution: '30cm-50cm',
    features: ['Very high resolution', 'SecureWatch', 'Change detection'],
    cost: 'Commercial'
  },
  airbus: {
    name: 'Airbus Defence & Space',
    url: 'https://www.intelligence-airbusds.com/',
    satellites: ['Pleiades', 'SPOT'],
    resolution: '50cm-1.5m',
    features: ['Stereo imagery', '3D models'],
    cost: 'Commercial'
  },
  planet: {
    name: 'Planet Labs',
    url: 'https://www.planet.com/',
    satellites: ['SkySat', 'Dove'],
    resolution: '3-5m',
    features: ['Daily coverage', 'Video capability'],
    cost: 'Commercial'
  }
};

const HISTORICAL_IMAGERY = {
  landsatlook: {
    name: 'LandSat Look',
    url: 'https://landsatlook.usgs.gov/',
    timespan: '1972-present',
    features: ['50+ years of data', 'Free download'],
    resolution: '15-30m'
  },
  googleearth: {
    name: 'Google Earth Time Slider',
    url: 'https://earth.google.com/',
    timespan: '1984-present',
    features: ['Easy interface', 'Side-by-side comparison'],
    resolution: 'Variable'
  },
  terraserver: {
    name: 'TerraServer',
    url: 'https://www.terraserver.com/',
    timespan: '1990s-present',
    features: ['Aerial photos', 'Topographic maps'],
    resolution: 'Variable'
  }
};

const SPECIALIZED_TOOLS = {
  fires: {
    'FIRMS': 'https://firms.modaps.eosdis.nasa.gov/',
    'Global Forest Watch': 'https://www.globalforestwatch.org/'
  },
  disasters: {
    'Copernicus EMS': 'https://emergency.copernicus.eu/',
    'GDACS': 'https://www.gdacs.org/'
  },
  weather: {
    'Ventusky': 'https://www.ventusky.com/',
    'Windy': 'https://www.windy.com/',
    'Nullschool Earth': 'https://earth.nullschool.net/'
  },
  maritime: {
    'Sentinel Marine': 'https://marine.copernicus.eu/',
    'NASA Ocean Color': 'https://oceancolor.gsfc.nasa.gov/'
  },
  urban: {
    'Sentinel Urban': 'https://land.copernicus.eu/local/urban-atlas',
    'Global Human Settlement': 'https://ghsl.jrc.ec.europa.eu/'
  }
};

function showBanner() {
  console.log("\x1b[31m");
  console.log("███████╗ █████╗ ████████╗███████╗██╗     ██╗     ██╗████████╗███████╗");
  console.log("██╔════╝██╔══██╗╚══██╔══╝██╔════╝██║     ██║     ██║╚══██╔══╝██╔════╝");
  console.log("███████╗███████║   ██║   █████╗  ██║     ██║     ██║   ██║   █████╗  ");
  console.log("╚════██║██╔══██║   ██║   ██╔══╝  ██║     ██║     ██║   ██║   ██╔══╝  ");
  console.log("███████║██║  ██║   ██║   ███████╗███████╗███████╗██║   ██║   ███████╗");
  console.log("╚══════╝╚═╝  ╚═╝   ╚═╝   ╚══════╝╚══════╝╚══════╝╚═╝   ╚═╝   ╚══════╝");
  console.log("                                                                       ");
  console.log(" ██████╗ ███████╗██╗███╗   ██╗████████╗                              ");
  console.log("██╔═══██╗██╔════╝██║████╗  ██║╚══██╔══╝                              ");
  console.log("██║   ██║███████╗██║██╔██╗ ██║   ██║                                 ");
  console.log("██║   ██║╚════██║██║██║╚██╗██║   ██║                                 ");
  console.log("╚██████╔╝███████║██║██║ ╚████║   ██║                                 ");
  console.log(" ╚═════╝ ╚══════╝╚═╝╚═╝  ╚═══╝   ╚═╝                                 ");
  console.log("\x1b[0m");
  console.log("\x1b[35m🥝 NIKA Satellite OSINT - Geospatial Intelligence\x1b[0m");
  console.log("\x1b[33m⚠️  For authorized geospatial analysis only\x1b[0m\n");
}

function parseCoordinates(input) {
  // Try different formats
  let lat, lon;
  
  // Format: "lat, lon"
  if (input.includes(',')) {
    const parts = input.split(',').map(p => parseFloat(p.trim()));
    if (parts.length === 2) {
      lat = parts[0];
      lon = parts[1];
    }
  }
  // Format: "lat lon"
  else if (input.includes(' ')) {
    const parts = input.split(' ').filter(p => p).map(p => parseFloat(p));
    if (parts.length === 2) {
      lat = parts[0];
      lon = parts[1];
    }
  }
  
  if (lat && lon && !isNaN(lat) && !isNaN(lon)) {
    return {
      valid: true,
      latitude: lat,
      longitude: lon,
      dms: convertToDMS(lat, lon)
    };
  }
  
  return {
    valid: false,
    error: 'Invalid coordinates format. Use: "lat, lon" or "lat lon"'
  };
}

function convertToDMS(lat, lon) {
  function toDMS(coord, isLat) {
    const absolute = Math.abs(coord);
    const degrees = Math.floor(absolute);
    const minutesNotTruncated = (absolute - degrees) * 60;
    const minutes = Math.floor(minutesNotTruncated);
    const seconds = ((minutesNotTruncated - minutes) * 60).toFixed(2);
    
    const direction = isLat 
      ? (coord >= 0 ? 'N' : 'S')
      : (coord >= 0 ? 'E' : 'W');
    
    return `${degrees}°${minutes}'${seconds}"${direction}`;
  }
  
  return {
    latitude: toDMS(lat, true),
    longitude: toDMS(lon, false),
    combined: `${toDMS(lat, true)} ${toDMS(lon, false)}`
  };
}

function generateSatelliteLinks(coords) {
  const { latitude, longitude } = coords;
  
  return {
    sentinel: `https://apps.sentinel-hub.com/eo-browser/?zoom=14&lat=${latitude}&lng=${longitude}`,
    nasa: `https://worldview.earthdata.nasa.gov/?v=${longitude-1},${latitude-1},${longitude+1},${latitude+1}`,
    googleearth: `https://earth.google.com/web/@${latitude},${longitude},1000a,1000d,35y,0h,0t,0r`,
    googlemaps: `https://www.google.com/maps/@${latitude},${longitude},1000m/data=!3m1!1e3`,
    zoom: `https://zoom.earth/#view=${latitude},${longitude},14z`,
    bing: `https://www.bing.com/maps?cp=${latitude}~${longitude}&lvl=16&style=h`,
    openstreetmap: `https://www.openstreetmap.org/#map=16/${latitude}/${longitude}`,
    windy: `https://www.windy.com/?${latitude},${longitude},11`
  };
}

function getUseCases() {
  return {
    military: [
      'Base monitoring',
      'Troop movement analysis',
      'Equipment identification',
      'Change detection'
    ],
    environmental: [
      'Deforestation tracking',
      'Urban expansion',
      'Flood monitoring',
      'Agricultural analysis'
    ],
    disaster: [
      'Earthquake damage assessment',
      'Wildfire tracking',
      'Hurricane monitoring',
      'Flood extent mapping'
    ],
    maritime: [
      'Vessel tracking',
      'Port activity',
      'Oil spill detection',
      'Illegal fishing'
    ],
    investigative: [
      'Property verification',
      'Construction monitoring',
      'Land use changes',
      'Infrastructure analysis'
    ]
  };
}

function displayResults(data) {
  console.log("\n╔════════════════════════════════════════════════════════╗");
  console.log("║       🛰️  SATELLITE OSINT RESULTS 🛰️                   ║");
  console.log("╚════════════════════════════════════════════════════════╝\n");
  
  if (data.coordinates) {
    console.log("\x1b[36m┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓\x1b[0m");
    console.log("\x1b[36m┃                  COORDINATES                         ┃\x1b[0m");
    console.log("\x1b[36m┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛\x1b[0m\n");
    
    console.log(`   Decimal:             ${data.coordinates.latitude}, ${data.coordinates.longitude}`);
    console.log(`   DMS:                 ${data.coordinates.dms.combined}\n`);
  }
  
  if (data.satelliteLinks) {
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
    console.log("\x1b[36m🛰️  SATELLITE IMAGERY LINKS\x1b[0m");
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
    
    console.log(`   Sentinel Hub:        ${data.satelliteLinks.sentinel}`);
    console.log(`   NASA Worldview:      ${data.satelliteLinks.nasa}`);
    console.log(`   Google Earth:        ${data.satelliteLinks.googleearth}`);
    console.log(`   Google Maps:         ${data.satelliteLinks.googlemaps}`);
    console.log(`   Zoom Earth:          ${data.satelliteLinks.zoom}`);
    console.log(`   Bing Maps:           ${data.satelliteLinks.bing}`);
    console.log(`   OpenStreetMap:       ${data.satelliteLinks.openstreetmap}\n`);
  }
  
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
  console.log("\x1b[36m🌍 SATELLITE PLATFORMS\x1b[0m");
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
  
  Object.entries(SATELLITE_PLATFORMS).forEach(([key, platform]) => {
    console.log(`   \x1b[32m${platform.name}\x1b[0m (${platform.cost})`);
    console.log(`      URL: ${platform.url}`);
    console.log(`      Resolution: ${platform.resolution}`);
    console.log(`      Features: ${platform.features.join(', ')}\n`);
  });
  
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
  console.log("\x1b[36m💼 COMMERCIAL PROVIDERS\x1b[0m");
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
  
  Object.entries(COMMERCIAL_PROVIDERS).forEach(([key, provider]) => {
    console.log(`   \x1b[32m${provider.name}\x1b[0m`);
    console.log(`      URL: ${provider.url}`);
    console.log(`      Resolution: ${provider.resolution}`);
    console.log(`      Satellites: ${provider.satellites.join(', ')}\n`);
  });
  
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
  console.log("\x1b[36m📅 HISTORICAL IMAGERY\x1b[0m");
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
  
  Object.entries(HISTORICAL_IMAGERY).forEach(([key, source]) => {
    console.log(`   \x1b[32m${source.name}\x1b[0m`);
    console.log(`      URL: ${source.url}`);
    console.log(`      Timespan: ${source.timespan}`);
    console.log(`      Resolution: ${source.resolution}\n`);
  });
  
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
  console.log("\x1b[36m🎯 SPECIALIZED TOOLS\x1b[0m");
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
  
  console.log('   \x1b[32mFire Detection:\x1b[0m');
  Object.entries(SPECIALIZED_TOOLS.fires).forEach(([name, url]) => {
    console.log(`      • ${name}: ${url}`);
  });
  console.log('');
  
  console.log('   \x1b[32mDisaster Response:\x1b[0m');
  Object.entries(SPECIALIZED_TOOLS.disasters).forEach(([name, url]) => {
    console.log(`      • ${name}: ${url}`);
  });
  console.log('');
  
  console.log('   \x1b[32mWeather:\x1b[0m');
  Object.entries(SPECIALIZED_TOOLS.weather).forEach(([name, url]) => {
    console.log(`      • ${name}: ${url}`);
  });
  console.log('');
  
  console.log('   \x1b[32mMaritime:\x1b[0m');
  Object.entries(SPECIALIZED_TOOLS.maritime).forEach(([name, url]) => {
    console.log(`      • ${name}: ${url}`);
  });
  console.log('');
  
  console.log('   \x1b[32mUrban Analysis:\x1b[0m');
  Object.entries(SPECIALIZED_TOOLS.urban).forEach(([name, url]) => {
    console.log(`      • ${name}: ${url}`);
  });
  console.log('');
  
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
  console.log("\x1b[36m💡 USE CASES\x1b[0m");
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
  
  const useCases = getUseCases();
  
  Object.entries(useCases).forEach(([category, cases]) => {
    console.log(`   \x1b[32m${category.charAt(0).toUpperCase() + category.slice(1)}:\x1b[0m`);
    cases.forEach(useCase => {
      console.log(`      • ${useCase}`);
    });
    console.log('');
  });
  
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
  console.log("\x1b[36m🔍 INVESTIGATION WORKFLOW\x1b[0m");
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
  
  console.log('   \x1b[32m1. Initial Survey:\x1b[0m');
  console.log('      • Start with Google Earth for context');
  console.log('      • Use Street View if available');
  console.log('      • Check OpenStreetMap for infrastructure\n');
  
  console.log('   \x1b[32m2. Current Imagery:\x1b[0m');
  console.log('      • Sentinel Hub for recent satellite data');
  console.log('      • NASA Worldview for daily updates');
  console.log('      • Zoom Earth for live weather\n');
  
  console.log('   \x1b[32m3. Historical Analysis:\x1b[0m');
  console.log('      • Google Earth time slider');
  console.log('      • LandSat for long-term changes');
  console.log('      • Compare multiple dates\n');
  
  console.log('   \x1b[32m4. Specialized Analysis:\x1b[0m');
  console.log('      • Use appropriate specialized tool');
  console.log('      • Export data if needed');
  console.log('      • Document findings with screenshots\n');
  
  console.log('   \x1b[32m5. Verification:\x1b[0m');
  console.log('      • Cross-reference multiple sources');
  console.log('      • Check acquisition dates');
  console.log('      • Verify cloud cover and quality\n');
}

function saveReport(data) {
  const dir = './satellite-osint-reports';
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, -5);
  const coordStr = data.coordinates 
    ? `${data.coordinates.latitude}_${data.coordinates.longitude}`.replace(/\./g, '-')
    : 'general';
  const filename = `${dir}/satellite-${coordStr}-${timestamp}.txt`;
  
  let content = `═══════════════════════════════════════════════════════════
SATELLITE OSINT REPORT
═══════════════════════════════════════════════════════════

Date: ${new Date().toLocaleString()}

`;

  if (data.coordinates) {
    content += `COORDINATES:
Decimal: ${data.coordinates.latitude}, ${data.coordinates.longitude}
DMS: ${data.coordinates.dms.combined}

SATELLITE IMAGERY LINKS:
Sentinel Hub: ${data.satelliteLinks.sentinel}
NASA Worldview: ${data.satelliteLinks.nasa}
Google Earth: ${data.satelliteLinks.googleearth}
Google Maps: ${data.satelliteLinks.googlemaps}
Zoom Earth: ${data.satelliteLinks.zoom}

`;
  }
  
  content += `SATELLITE PLATFORMS:\n`;
  Object.entries(SATELLITE_PLATFORMS).forEach(([key, platform]) => {
    content += `\n${platform.name}:\n${platform.url}\nResolution: ${platform.resolution}\n`;
  });
  
  content += `\nSPECIALIZED TOOLS:\n`;
  Object.entries(SPECIALIZED_TOOLS).forEach(([category, tools]) => {
    content += `\n${category.toUpperCase()}:\n`;
    Object.entries(tools).forEach(([name, url]) => {
      content += `${name}: ${url}\n`;
    });
  });
  
  fs.writeFileSync(filename, content);
  console.log(`\x1b[32m✅ Report saved: ${filename}\x1b[0m\n`);
}

function showHelp() {
  showBanner();
  
  console.log("Usage: node satellite-osint.js [OPTIONS] [\"lat, lon\"]\n");
  console.log("Options:");
  console.log("  --coords \"lat, lon\"  Coordinates to analyze");
  console.log("  --list               List all platforms");
  console.log("  --save               Save report to file");
  console.log("  --help               Show this help\n");
  
  console.log("Coordinate Formats:");
  console.log("  \"40.7128, -74.0060\"  (New York)");
  console.log("  \"51.5074 -0.1278\"    (London)\n");
  
  console.log("Examples:");
  console.log("  node satellite-osint.js --coords \"40.7128, -74.0060\"");
  console.log("  node satellite-osint.js --list");
  console.log("  node satellite-osint.js --coords \"51.5074, -0.1278\" --save\n");
}

function main() {
  const args = process.argv.slice(2);
  
  if (args.length === 0 || args.includes('--help')) {
    showHelp();
    process.exit(0);
  }
  
  showBanner();
  
  if (args.includes('--list')) {
    console.log("Available Satellite Platforms:\n");
    Object.entries(SATELLITE_PLATFORMS).forEach(([key, platform]) => {
      console.log(`   \x1b[32m${platform.name}\x1b[0m`);
      console.log(`      Resolution: ${platform.resolution}`);
      console.log(`      Cost: ${platform.cost}\n`);
    });
    process.exit(0);
  }
  
  let coords = null;
  let saveFlag = false;
  
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--coords') {
      coords = args[i + 1];
      i++;
    } else if (args[i] === '--save') {
      saveFlag = true;
    } else if (!args[i].startsWith('--')) {
      coords = args[i];
    }
  }
  
  const results = {
    timestamp: new Date().toISOString(),
    coordinates: null,
    satelliteLinks: null
  };
  
  if (coords) {
    const parsed = parseCoordinates(coords);
    
    if (!parsed.valid) {
      console.log(`\x1b[31m❌ ${parsed.error}\x1b[0m\n`);
      process.exit(1);
    }
    
    console.log(`⏳ Generating satellite links for: ${parsed.latitude}, ${parsed.longitude}...\n`);
    
    results.coordinates = parsed;
    results.satelliteLinks = generateSatelliteLinks(parsed);
  } else {
    console.log(`⏳ Generating satellite platform guide...\n`);
  }
  
  displayResults(results);
  
  if (saveFlag) {
    saveReport(results);
  }
  
  console.log("\x1b[31m███████╗ █████╗ ████████╗███████╗██╗     ██╗     ██╗████████╗███████╗\x1b[0m");
  console.log("\x1b[35m🥝 Analysis complete - by kiwi & 777\x1b[0m\n");
}

main();
