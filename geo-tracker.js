#!/usr/bin/env node

const { exec } = require('child_process');
const { promisify } = require('util');
const execAsync = promisify(exec);
const fs = require('fs');

// ============================================
// GEOLOCATION TRACKER - Extract GPS from images
// ============================================

async function extractGPS(imagePath) {
  try {
    const { stdout } = await execAsync(`exiftool -json "${imagePath}"`);
    const data = JSON.parse(stdout)[0];
    
    const result = {
      available: true,
      filename: data.FileName,
      fileSize: data.FileSize,
      imageSize: `${data.ImageWidth}x${data.ImageHeight}`,
      camera: data.Make ? `${data.Make} ${data.Model}` : 'Unknown',
      dateTime: data.DateTimeOriginal || data.CreateDate || 'Unknown',
      software: data.Software || 'Unknown',
      gps: null,
      location: null,
      allMetadata: data
    };
    
    if (data.GPSLatitude && data.GPSLongitude) {
      const lat = parseGPS(data.GPSLatitude, data.GPSLatitudeRef);
      const lon = parseGPS(data.GPSLongitude, data.GPSLongitudeRef);
      
      result.gps = {
        latitude: lat,
        longitude: lon,
        altitude: data.GPSAltitude || 'Unknown',
        timestamp: data.GPSDateStamp || 'Unknown',
        googleMaps: `https://www.google.com/maps?q=${lat},${lon}`,
        openStreetMap: `https://www.openstreetmap.org/?mlat=${lat}&mlon=${lon}&zoom=15`
      };
      
      // Reverse geocoding (approximate)
      result.location = await reverseGeocode(lat, lon);
    }
    
    return result;
  } catch (error) {
    if (error.message.includes('exiftool: not found')) {
      return {
        available: false,
        error: 'ExifTool not installed',
        install: 'pkg install exiftool'
      };
    }
    return {
      available: false,
      error: error.message
    };
  }
}

function parseGPS(coord, ref) {
  if (typeof coord === 'string') {
    const parts = coord.match(/(\d+) deg (\d+)' ([\d.]+)"/);
    if (parts) {
      let decimal = parseFloat(parts[1]) + parseFloat(parts[2])/60 + parseFloat(parts[3])/3600;
      if (ref === 'S' || ref === 'W') decimal *= -1;
      return decimal.toFixed(6);
    }
  }
  return coord;
}

async function reverseGeocode(lat, lon) {
  try {
    const url = `https://nominatim.openstreetmap.org/reverse?lat=${lat}&lon=${lon}&format=json`;
    const { stdout } = await execAsync(`curl -s "${url}" -H "User-Agent: NIKA-OSINT/3.0"`);
    const data = JSON.parse(stdout);
    
    return {
      address: data.display_name || 'Unknown',
      city: data.address?.city || data.address?.town || data.address?.village || 'Unknown',
      country: data.address?.country || 'Unknown',
      postcode: data.address?.postcode || 'Unknown'
    };
  } catch {
    return null;
  }
}

function showBanner() {
  console.log("\x1b[31m");
  console.log("██████╗ ███████╗ ██████╗     ████████╗██████╗  █████╗  ██████╗██╗  ██╗███████╗██████╗ ");
  console.log("██╔════╝ ██╔════╝██╔═══██╗    ╚══██╔══╝██╔══██╗██╔══██╗██╔════╝██║ ██╔╝██╔════╝██╔══██╗");
  console.log("██║  ███╗█████╗  ██║   ██║       ██║   ██████╔╝███████║██║     █████╔╝ █████╗  ██████╔╝");
  console.log("██║   ██║██╔══╝  ██║   ██║       ██║   ██╔══██╗██╔══██║██║     ██╔═██╗ ██╔══╝  ██╔══██╗");
  console.log("╚██████╔╝███████╗╚██████╔╝       ██║   ██║  ██║██║  ██║╚██████╗██║  ██╗███████╗██║  ██║");
  console.log(" ╚═════╝ ╚══════╝ ╚═════╝        ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝");
  console.log("\x1b[0m");
  console.log("\x1b[35m🥝 NIKA Geolocation Tracker - Extract GPS from Images\x1b[0m");
  console.log("\x1b[33m⚠️  For authorized investigation only\x1b[0m\n");
}

function displayResults(data) {
  console.log("\n╔════════════════════════════════════════════════════════╗");
  console.log("║         🌍 GEOLOCATION RESULTS 🌍                      ║");
  console.log("╚════════════════════════════════════════════════════════╝\n");
  
  if (!data.available) {
    console.log(`\x1b[31m❌ Error: ${data.error}\x1b[0m`);
    if (data.install) console.log(`   Install: ${data.install}`);
    return;
  }
  
  console.log(`📁 File: \x1b[36m${data.filename}\x1b[0m`);
  console.log(`📊 Size: ${data.fileSize}`);
  console.log(`📐 Dimensions: ${data.imageSize}`);
  console.log(`📷 Camera: ${data.camera}`);
  console.log(`🕐 Date: ${data.dateTime}`);
  console.log(`💻 Software: ${data.software}\n`);
  
  if (data.gps) {
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
    console.log("\x1b[36m📍 GPS LOCATION FOUND!\x1b[0m");
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
    
    console.log(`   \x1b[32m✓ Latitude:\x1b[0m ${data.gps.latitude}`);
    console.log(`   \x1b[32m✓ Longitude:\x1b[0m ${data.gps.longitude}`);
    console.log(`   \x1b[32m✓ Altitude:\x1b[0m ${data.gps.altitude}`);
    console.log(`   \x1b[32m✓ Timestamp:\x1b[0m ${data.gps.timestamp}\n`);
    
    if (data.location) {
      console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
      console.log("\x1b[36m🏙️  REVERSE GEOCODING\x1b[0m");
      console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
      
      console.log(`   City: ${data.location.city}`);
      console.log(`   Country: ${data.location.country}`);
      console.log(`   Postcode: ${data.location.postcode}`);
      console.log(`   Address: ${data.location.address}\n`);
    }
    
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
    console.log("\x1b[36m🗺️  VIEW ON MAP\x1b[0m");
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
    
    console.log(`   Google Maps: ${data.gps.googleMaps}`);
    console.log(`   OpenStreetMap: ${data.gps.openStreetMap}\n`);
  } else {
    console.log("\x1b[33m⚠️  No GPS data found in this image\x1b[0m\n");
    console.log("Possible reasons:");
    console.log("  • GPS was disabled when photo was taken");
    console.log("  • Metadata was stripped");
    console.log("  • Photo was edited/compressed\n");
  }
}

function saveResults(data) {
  const dir = './geo-reports';
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, -5);
  const jsonFile = `${dir}/${data.filename}-${timestamp}.json`;
  const txtFile = jsonFile.replace('.json', '.txt');
  
  fs.writeFileSync(jsonFile, JSON.stringify(data, null, 2));
  
  let txtContent = `═══════════════════════════════════════════════════════════
GEOLOCATION TRACKER REPORT
═══════════════════════════════════════════════════════════

File: ${data.filename}
Date: ${new Date().toLocaleString()}

═══════════════════════════════════════════════════════════
IMAGE INFO
═══════════════════════════════════════════════════════════

Size: ${data.fileSize}
Dimensions: ${data.imageSize}
Camera: ${data.camera}
Date Taken: ${data.dateTime}
Software: ${data.software}

`;

  if (data.gps) {
    txtContent += `═══════════════════════════════════════════════════════════
GPS LOCATION
═══════════════════════════════════════════════════════════

Latitude: ${data.gps.latitude}
Longitude: ${data.gps.longitude}
Altitude: ${data.gps.altitude}
Timestamp: ${data.gps.timestamp}

Google Maps: ${data.gps.googleMaps}
OpenStreetMap: ${data.gps.openStreetMap}

`;

    if (data.location) {
      txtContent += `═══════════════════════════════════════════════════════════
LOCATION INFO
═══════════════════════════════════════════════════════════

City: ${data.location.city}
Country: ${data.location.country}
Postcode: ${data.location.postcode}
Address: ${data.location.address}

`;
    }
  }
  
  fs.writeFileSync(txtFile, txtContent);
  
  console.log(`\x1b[32m✅ Results saved:\x1b[0m`);
  console.log(`   JSON: ${jsonFile}`);
  console.log(`   TXT: ${txtFile}\n`);
}

function showHelp() {
  showBanner();
  
  console.log("Usage: node geo-tracker.js [OPTIONS] <image>\n");
  console.log("Options:");
  console.log("  --save           Save results to file");
  console.log("  --help           Show this help\n");
  
  console.log("Examples:");
  console.log("  node geo-tracker.js photo.jpg");
  console.log("  node geo-tracker.js image.png --save\n");
  
  console.log("\x1b[33mNote: Requires exiftool installed\x1b[0m");
  console.log("\x1b[33mInstall: pkg install exiftool\x1b[0m\n");
}

async function main() {
  const args = process.argv.slice(2);
  
  if (args.includes('--help') || args.length === 0) {
    showHelp();
    process.exit(0);
  }
  
  let imagePath = null;
  let saveResults_flag = false;
  
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--save') {
      saveResults_flag = true;
    } else if (!args[i].startsWith('--')) {
      imagePath = args[i];
    }
  }
  
  if (!imagePath) {
    console.log("\x1b[31m❌ No image specified!\x1b[0m\n");
    showHelp();
    process.exit(1);
  }
  
  if (!fs.existsSync(imagePath)) {
    console.log(`\x1b[31m❌ Image not found: ${imagePath}\x1b[0m\n`);
    process.exit(1);
  }
  
  showBanner();
  
  console.log(`⏳ Extracting GPS data from ${imagePath}...\n`);
  
  const results = await extractGPS(imagePath);
  
  displayResults(results);
  
  if (saveResults_flag && results.available) {
    saveResults(results);
  }
  
  console.log("\x1b[31m██████╗ ███████╗ ██████╗\x1b[0m");
  console.log("\x1b[35m🥝 Scan complete - by kiwi & 777\x1b[0m\n");
}

main().catch(console.error);

