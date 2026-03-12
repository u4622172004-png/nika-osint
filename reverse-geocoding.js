#!/usr/bin/env node

const https = require('https');
const fs = require('fs');

// ============================================
// REVERSE GEOCODING - Coordinates to Address
// ============================================

const GEOCODING_APIS = {
  nominatim: {
    name: 'Nominatim (OpenStreetMap)',
    url: 'https://nominatim.openstreetmap.org/',
    api: 'https://nominatim.openstreetmap.org/reverse',
    features: ['Free', 'No API key', 'Global coverage', 'Open source'],
    rateLimit: '1 request/second',
    cost: 'Free'
  },
  google: {
    name: 'Google Geocoding API',
    url: 'https://developers.google.com/maps/documentation/geocoding',
    api: 'https://maps.googleapis.com/maps/api/geocode/json',
    features: ['High accuracy', 'Detailed results', 'Place IDs'],
    cost: 'Paid (Free tier)',
    apiKey: true
  },
  opencage: {
    name: 'OpenCage Geocoding',
    url: 'https://opencagedata.com/',
    api: 'https://api.opencagedata.com/geocode/v1/json',
    features: ['Multiple sources', 'Annotations', 'Global'],
    cost: 'Free tier/Paid',
    apiKey: true
  },
  locationiq: {
    name: 'LocationIQ',
    url: 'https://locationiq.com/',
    api: 'https://us1.locationiq.com/v1/reverse.php',
    features: ['OSM-based', 'Fast', 'Autocomplete'],
    cost: 'Free tier/Paid',
    apiKey: true
  }
};

const COORDINATE_SYSTEMS = {
  decimal: {
    name: 'Decimal Degrees (DD)',
    format: '40.7128, -74.0060',
    example: { lat: 40.7128, lon: -74.0060 }
  },
  dms: {
    name: 'Degrees Minutes Seconds (DMS)',
    format: '40°42\'46.08"N, 74°0\'21.6"W',
    example: "40°42'46.08\"N, 74°0'21.6\"W"
  },
  pluscode: {
    name: 'Plus Codes (Open Location Code)',
    format: '87G8Q2J8+2X',
    url: 'https://plus.codes/'
  },
  what3words: {
    name: 'what3words',
    format: '///filled.count.soap',
    url: 'https://what3words.com/'
  },
  mgrs: {
    name: 'MGRS (Military Grid Reference)',
    format: '18TWL8745415395'
  },
  utm: {
    name: 'UTM (Universal Transverse Mercator)',
    format: 'Zone 18N 585628mE 4511322mN'
  }
};

const TIMEZONE_APIS = {
  timezonedb: {
    name: 'TimeZoneDB',
    url: 'https://timezonedb.com/',
    api: 'https://api.timezonedb.com/v2.1/get-time-zone',
    cost: 'Free tier/Paid'
  },
  geonames: {
    name: 'GeoNames',
    url: 'http://www.geonames.org/',
    api: 'http://api.geonames.org/timezoneJSON',
    cost: 'Free'
  }
};

function showBanner() {
  console.log("\x1b[31m");
  console.log("██████╗ ███████╗██╗   ██╗███████╗██████╗ ███████╗███████╗");
  console.log("██╔══██╗██╔════╝██║   ██║██╔════╝██╔══██╗██╔════╝██╔════╝");
  console.log("██████╔╝█████╗  ██║   ██║█████╗  ██████╔╝███████╗█████╗  ");
  console.log("██╔══██╗██╔══╝  ╚██╗ ██╔╝██╔══╝  ██╔══██╗╚════██║██╔══╝  ");
  console.log("██║  ██║███████╗ ╚████╔╝ ███████╗██║  ██║███████║███████╗");
  console.log("╚═╝  ╚═╝╚══════╝  ╚═══╝  ╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝");
  console.log("                                                          ");
  console.log(" ██████╗ ███████╗ ██████╗  ██████╗ ██████╗ ██████╗ ██╗███╗   ██╗ ██████╗ ");
  console.log("██╔════╝ ██╔════╝██╔═══██╗██╔════╝██╔═══██╗██╔══██╗██║████╗  ██║██╔════╝ ");
  console.log("██║  ███╗█████╗  ██║   ██║██║     ██║   ██║██║  ██║██║██╔██╗ ██║██║  ███╗");
  console.log("██║   ██║██╔══╝  ██║   ██║██║     ██║   ██║██║  ██║██║██║╚██╗██║██║   ██║");
  console.log("╚██████╔╝███████╗╚██████╔╝╚██████╗╚██████╔╝██████╔╝██║██║ ╚████║╚██████╔╝");
  console.log(" ╚═════╝ ╚══════╝ ╚═════╝  ╚═════╝ ╚═════╝ ╚═════╝ ╚═╝╚═╝  ╚═══╝ ╚═════╝ ");
  console.log("\x1b[0m");
  console.log("\x1b[35m🥝 NIKA Reverse Geocoding - Coordinates to Address\x1b[0m");
  console.log("\x1b[33m⚠️  For geospatial intelligence only\x1b[0m\n");
}

function parseCoordinates(input) {
  const cleaned = input.trim();
  
  // Decimal degrees: "40.7128, -74.0060"
  const ddMatch = cleaned.match(/^(-?\d+\.?\d*)[,\s]+(-?\d+\.?\d*)$/);
  if (ddMatch) {
    const lat = parseFloat(ddMatch[1]);
    const lon = parseFloat(ddMatch[2]);
    
    if (lat >= -90 && lat <= 90 && lon >= -180 && lon <= 180) {
      return {
        valid: true,
        format: 'decimal',
        latitude: lat,
        longitude: lon
      };
    }
  }
  
  // DMS format: 40°42'46"N, 74°0'22"W
  const dmsMatch = cleaned.match(/(\d+)[°\s]+(\d+)['\s]+(\d+\.?\d*)["\s]*([NSEW])[,\s]+(\d+)[°\s]+(\d+)['\s]+(\d+\.?\d*)["\s]*([NSEW])/i);
  if (dmsMatch) {
    const latDeg = parseInt(dmsMatch[1]);
    const latMin = parseInt(dmsMatch[2]);
    const latSec = parseFloat(dmsMatch[3]);
    const latDir = dmsMatch[4].toUpperCase();
    
    const lonDeg = parseInt(dmsMatch[5]);
    const lonMin = parseInt(dmsMatch[6]);
    const lonSec = parseFloat(dmsMatch[7]);
    const lonDir = dmsMatch[8].toUpperCase();
    
    let lat = latDeg + latMin / 60 + latSec / 3600;
    let lon = lonDeg + lonMin / 60 + lonSec / 3600;
    
    if (latDir === 'S') lat = -lat;
    if (lonDir === 'W') lon = -lon;
    
    return {
      valid: true,
      format: 'dms',
      latitude: lat,
      longitude: lon,
      original: cleaned
    };
  }
  
  // Plus Code: 87G8Q2J8+2X
  if (/^[23456789CFGHJMPQRVWX]{4,8}\+[23456789CFGHJMPQRVWX]{2,3}/.test(cleaned.toUpperCase())) {
    return {
      valid: true,
      format: 'pluscode',
      code: cleaned.toUpperCase(),
      decodeUrl: `https://plus.codes/${cleaned}`,
      note: 'Visit plus.codes to decode'
    };
  }
  
  // what3words: ///filled.count.soap
  if (/^\/\/\/[\w]+\.[\w]+\.[\w]+$/.test(cleaned)) {
    return {
      valid: true,
      format: 'what3words',
      address: cleaned,
      decodeUrl: `https://what3words.com/${cleaned}`,
      note: 'Visit what3words.com to decode (requires API key)'
    };
  }
  
  return {
    valid: false,
    error: 'Invalid coordinate format'
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
    combined: `${toDMS(lat, true)}, ${toDMS(lon, false)}`
  };
}

function generatePlusCode(lat, lon) {
  // Simplified - real implementation needs full algorithm
  return {
    code: '[Requires full algorithm]',
    url: `https://plus.codes/`,
    note: 'Use Google Maps or plus.codes website to generate'
  };
}

async function reverseGeocode(lat, lon) {
  console.log('   [1/4] Performing reverse geocoding...');
  
  return new Promise((resolve) => {
    const url = `https://nominatim.openstreetmap.org/reverse?format=json&lat=${lat}&lon=${lon}&zoom=18&addressdetails=1`;
    
    const options = {
      headers: {
        'User-Agent': 'NIKA-OSINT-Geocoding'
      }
    };
    
    https.get(url, options, (res) => {
      let data = '';
      
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          const json = JSON.parse(data);
          
          if (json.error) {
            resolve({
              available: false,
              error: json.error
            });
            return;
          }
          
          resolve({
            available: true,
            source: 'Nominatim (OpenStreetMap)',
            displayName: json.display_name,
            address: {
              road: json.address.road || null,
              houseNumber: json.address.house_number || null,
              suburb: json.address.suburb || json.address.neighbourhood || null,
              city: json.address.city || json.address.town || json.address.village || null,
              county: json.address.county || null,
              state: json.address.state || null,
              postcode: json.address.postcode || null,
              country: json.address.country || null,
              countryCode: json.address.country_code?.toUpperCase() || null
            },
            placeId: json.place_id,
            osmType: json.osm_type,
            osmId: json.osm_id,
            category: json.class,
            type: json.type,
            importance: json.importance
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
        error: 'Request failed'
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

function getElevation(lat, lon) {
  console.log('   [2/4] Estimating elevation...');
  
  // Note: Real elevation requires API like Open-Elevation or USGS
  return {
    available: false,
    note: 'Use https://open-elevation.com/ or https://elevation-api.io/',
    apiExample: `https://api.open-elevation.com/api/v1/lookup?locations=${lat},${lon}`
  };
}

function getTimezone(lat, lon) {
  console.log('   [3/4] Determining timezone...');
  
  // Simplified timezone estimation
  const offset = Math.round(lon / 15);
  
  return {
    estimated: true,
    utcOffset: offset,
    note: 'Use TimeZoneDB or GeoNames API for accurate timezone',
    apis: {
      timezonedb: `${TIMEZONE_APIS.timezonedb.api}?key=YOUR_KEY&format=json&by=position&lat=${lat}&lng=${lon}`,
      geonames: `${TIMEZONE_APIS.geonames.api}?lat=${lat}&lng=${lon}&username=YOUR_USERNAME`
    }
  };
}

function getNearbyPlaces(lat, lon) {
  console.log('   [4/4] Generating nearby place search...');
  
  return {
    overpass: `https://overpass-turbo.eu/?Q=[out:json];node(around:1000,${lat},${lon});out;`,
    nominatim: `https://nominatim.openstreetmap.org/search?format=json&lat=${lat}&lon=${lon}&addressdetails=1`,
    note: 'Use Overpass API for nearby POIs'
  };
}

function displayResults(data) {
  console.log("\n╔════════════════════════════════════════════════════════╗");
  console.log("║       🗺️  REVERSE GEOCODING REPORT 🗺️                  ║");
  console.log("╚════════════════════════════════════════════════════════╝\n");
  
  // Coordinates
  console.log("\x1b[36m┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓\x1b[0m");
  console.log("\x1b[36m┃                  COORDINATES                         ┃\x1b[0m");
  console.log("\x1b[36m┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛\x1b[0m\n");
  
  if (data.coords.format === 'decimal') {
    console.log(`   Format:              Decimal Degrees`);
    console.log(`   Latitude:            ${data.coords.latitude}`);
    console.log(`   Longitude:           ${data.coords.longitude}`);
    console.log(`   DMS:                 ${data.dms.combined}\n`);
  } else if (data.coords.format === 'dms') {
    console.log(`   Format:              Degrees Minutes Seconds`);
    console.log(`   Original:            ${data.coords.original}`);
    console.log(`   Decimal:             ${data.coords.latitude}, ${data.coords.longitude}\n`);
  } else if (data.coords.format === 'pluscode') {
    console.log(`   Format:              Plus Code`);
    console.log(`   Code:                ${data.coords.code}`);
    console.log(`   Decode at:           ${data.coords.decodeUrl}\n`);
  } else if (data.coords.format === 'what3words') {
    console.log(`   Format:              what3words`);
    console.log(`   Address:             ${data.coords.address}`);
    console.log(`   Decode at:           ${data.coords.decodeUrl}\n`);
  }
  
  // Reverse Geocoding Result
  if (data.geocode && data.geocode.available) {
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
    console.log("\x1b[36m📍 REVERSE GEOCODING RESULT\x1b[0m");
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
    
    console.log(`   Source:              ${data.geocode.source}`);
    console.log(`   \x1b[32mFull Address:\x1b[0m         ${data.geocode.displayName}\n`);
    
    const addr = data.geocode.address;
    if (addr.road || addr.houseNumber) {
      console.log(`   Street:              ${[addr.houseNumber, addr.road].filter(Boolean).join(' ') || 'N/A'}`);
    }
    if (addr.suburb) console.log(`   Suburb:              ${addr.suburb}`);
    if (addr.city) console.log(`   City:                ${addr.city}`);
    if (addr.county) console.log(`   County:              ${addr.county}`);
    if (addr.state) console.log(`   State/Province:      ${addr.state}`);
    if (addr.postcode) console.log(`   Postal Code:         ${addr.postcode}`);
    if (addr.country) console.log(`   Country:             ${addr.country} (${addr.countryCode})`);
    console.log('');
    
    console.log(`   Place Type:          ${data.geocode.category} / ${data.geocode.type}`);
    console.log(`   OSM ID:              ${data.geocode.osmType}/${data.geocode.osmId}\n`);
  } else if (data.geocode) {
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
    console.log("\x1b[36m📍 REVERSE GEOCODING\x1b[0m");
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
    
    console.log(`   Status:              ${data.geocode.error || 'Not available'}\n`);
  }
  
  // Timezone
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
  console.log("\x1b[36m🕐 TIMEZONE\x1b[0m");
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
  
  if (data.timezone.estimated) {
    console.log(`   Estimated UTC:       ${data.timezone.utcOffset >= 0 ? '+' : ''}${data.timezone.utcOffset}`);
    console.log(`   Note:                ${data.timezone.note}\n`);
  }
  
  // Elevation
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
  console.log("\x1b[36m⛰️  ELEVATION\x1b[0m");
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
  
  console.log(`   Status:              ${data.elevation.note}`);
  console.log(`   API:                 ${data.elevation.apiExample}\n`);
  
  // Geocoding APIs
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
  console.log("\x1b[36m🌐 GEOCODING APIs\x1b[0m");
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
  
  Object.entries(GEOCODING_APIS).forEach(([key, api]) => {
    console.log(`   \x1b[32m${api.name}\x1b[0m (${api.cost})`);
    console.log(`      URL: ${api.url}`);
    console.log(`      Features: ${api.features.join(', ')}`);
    if (api.rateLimit) console.log(`      Rate Limit: ${api.rateLimit}`);
    console.log('');
  });
  
  // Coordinate Systems
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
  console.log("\x1b[36m🧭 COORDINATE SYSTEMS\x1b[0m");
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
  
  Object.entries(COORDINATE_SYSTEMS).forEach(([key, system]) => {
    console.log(`   \x1b[32m${system.name}\x1b[0m`);
    console.log(`      Format: ${system.format}`);
    if (system.url) console.log(`      URL: ${system.url}`);
    console.log('');
  });
  
  // Links
  if (data.coords.latitude && data.coords.longitude) {
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
    console.log("\x1b[36m🔗 MAP LINKS\x1b[0m");
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
    
    const { latitude, longitude } = data.coords;
    console.log(`   Google Maps:         https://www.google.com/maps?q=${latitude},${longitude}`);
    console.log(`   OpenStreetMap:       https://www.openstreetmap.org/?mlat=${latitude}&mlon=${longitude}&zoom=15`);
    console.log(`   Bing Maps:           https://www.bing.com/maps?cp=${latitude}~${longitude}&lvl=15`);
    console.log(`   Nearby Places:       ${data.nearby.overpass}\n`);
  }
}

function saveReport(data) {
  const dir = './geocoding-reports';
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, -5);
  const coordStr = data.coords.latitude && data.coords.longitude
    ? `${data.coords.latitude.toFixed(4)}_${data.coords.longitude.toFixed(4)}`.replace(/\./g, '-')
    : 'coords';
  const filename = `${dir}/geocode-${coordStr}-${timestamp}.txt`;
  
  let content = `═══════════════════════════════════════════════════════════
REVERSE GEOCODING REPORT
═══════════════════════════════════════════════════════════

Date: ${new Date().toLocaleString()}

COORDINATES:
Format: ${data.coords.format}
`;

  if (data.coords.latitude && data.coords.longitude) {
    content += `Decimal: ${data.coords.latitude}, ${data.coords.longitude}\n`;
    content += `DMS: ${data.dms.combined}\n`;
  }
  
  if (data.geocode && data.geocode.available) {
    content += `\nREVERSE GEOCODING:
Source: ${data.geocode.source}
Address: ${data.geocode.displayName}

DETAILS:
${Object.entries(data.geocode.address).map(([k, v]) => v ? `${k}: ${v}` : '').filter(Boolean).join('\n')}
`;
  }
  
  if (data.coords.latitude && data.coords.longitude) {
    const { latitude, longitude } = data.coords;
    content += `\nMAP LINKS:
Google Maps: https://www.google.com/maps?q=${latitude},${longitude}
OpenStreetMap: https://www.openstreetmap.org/?mlat=${latitude}&mlon=${longitude}&zoom=15
`;
  }
  
  fs.writeFileSync(filename, content);
  console.log(`\x1b[32m✅ Report saved: ${filename}\x1b[0m\n`);
}

function showHelp() {
  showBanner();
  
  console.log("Usage: node reverse-geocoding.js <coordinates> [--save]\n");
  console.log("Supported Formats:");
  console.log("  Decimal:             40.7128, -74.0060");
  console.log("  DMS:                 40°42'46\"N, 74°0'22\"W");
  console.log("  Plus Code:           87G8Q2J8+2X");
  console.log("  what3words:          ///filled.count.soap\n");
  
  console.log("Options:");
  console.log("  --save               Save report to file");
  console.log("  --help               Show this help\n");
  
  console.log("Examples:");
  console.log("  node reverse-geocoding.js \"40.7128, -74.0060\"");
  console.log("  node reverse-geocoding.js \"51.5074, -0.1278\" --save");
  console.log("  node reverse-geocoding.js \"87G8Q2J8+2X\"\n");
}

async function main() {
  const args = process.argv.slice(2);
  
  if (args.length === 0 || args.includes('--help')) {
    showHelp();
    process.exit(0);
  }
  
  showBanner();
  
  let coordinates = null;
  let saveFlag = false;
  
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--save') {
      saveFlag = true;
    } else if (!args[i].startsWith('--')) {
      coordinates = args[i];
    }
  }
  
  if (!coordinates) {
    console.log("\x1b[31m❌ No coordinates specified!\x1b[0m\n");
    showHelp();
    process.exit(1);
  }
  
  console.log(`⏳ Processing coordinates: ${coordinates}...\n`);
  
  const parsed = parseCoordinates(coordinates);
  
  if (!parsed.valid) {
    console.log(`\x1b[31m❌ ${parsed.error}\x1b[0m\n`);
    console.log("Supported formats:");
    console.log("  • Decimal: 40.7128, -74.0060");
    console.log("  • DMS: 40°42'46\"N, 74°0'22\"W");
    console.log("  • Plus Code: 87G8Q2J8+2X");
    console.log("  • what3words: ///filled.count.soap\n");
    process.exit(1);
  }
  
  const results = {
    timestamp: new Date().toISOString(),
    coords: parsed,
    dms: null,
    geocode: null,
    elevation: null,
    timezone: null,
    nearby: null
  };
  
  if (parsed.latitude && parsed.longitude) {
    results.dms = convertToDMS(parsed.latitude, parsed.longitude);
    results.geocode = await reverseGeocode(parsed.latitude, parsed.longitude);
    results.elevation = getElevation(parsed.latitude, parsed.longitude);
    results.timezone = getTimezone(parsed.latitude, parsed.longitude);
    results.nearby = getNearbyPlaces(parsed.latitude, parsed.longitude);
  }
  
  displayResults(results);
  
  if (saveFlag) {
    saveReport(results);
  }
  
  console.log("\x1b[31m██████╗ ███████╗██╗   ██╗███████╗██████╗ ███████╗███████╗\x1b[0m");
  console.log("\x1b[35m🥝 Geocoding complete - by kiwi & 777\x1b[0m\n");
}

main();
