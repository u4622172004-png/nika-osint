#!/usr/bin/env node

const { exec } = require('child_process');
const { promisify } = require('util');
const execAsync = promisify(exec);
const fs = require('fs');
const path = require('path');

// ============================================
// EXIF MASS SCANNER - Bulk GPS & Metadata Extraction
// ============================================

const IMAGE_EXTENSIONS = ['.jpg', '.jpeg', '.png', '.tiff', '.tif', '.heic', '.heif', '.webp', '.gif'];

async function scanDirectory(dirPath, recursive = true) {
  const results = {
    totalFiles: 0,
    scannedFiles: 0,
    withGPS: 0,
    withoutGPS: 0,
    errors: 0,
    locations: [],
    metadata: []
  };
  
  async function scanDir(dir) {
    const files = fs.readdirSync(dir);
    
    for (const file of files) {
      const filePath = path.join(dir, file);
      const stat = fs.statSync(filePath);
      
      if (stat.isDirectory() && recursive) {
        await scanDir(filePath);
      } else if (stat.isFile()) {
        const ext = path.extname(file).toLowerCase();
        if (IMAGE_EXTENSIONS.includes(ext)) {
          results.totalFiles++;
          console.log(`   [${results.scannedFiles + 1}/${results.totalFiles}] Scanning: ${file}`);
          
          const metadata = await extractMetadata(filePath);
          if (metadata.success) {
            results.scannedFiles++;
            results.metadata.push(metadata);
            
            if (metadata.hasGPS) {
              results.withGPS++;
              results.locations.push({
                file: file,
                path: filePath,
                lat: metadata.gps.latitude,
                lon: metadata.gps.longitude,
                timestamp: metadata.timestamp,
                camera: metadata.camera
              });
            } else {
              results.withoutGPS++;
            }
          } else {
            results.errors++;
          }
        }
      }
    }
  }
  
  await scanDir(dirPath);
  return results;
}

async function extractMetadata(filePath) {
  try {
    const { stdout } = await execAsync(`exiftool -json "${filePath}"`, {
      maxBuffer: 5 * 1024 * 1024,
      timeout: 5000
    });
    
    const data = JSON.parse(stdout)[0];
    
    const result = {
      success: true,
      file: path.basename(filePath),
      path: filePath,
      hasGPS: false,
      gps: null,
      camera: null,
      timestamp: null,
      author: null,
      software: null
    };
    
    // GPS data
    if (data.GPSLatitude && data.GPSLongitude) {
      result.hasGPS = true;
      result.gps = {
        latitude: data.GPSLatitude,
        longitude: data.GPSLongitude,
        altitude: data.GPSAltitude || null,
        timestamp: data.GPSDateTime || data.GPSDateStamp || null
      };
    }
    
    // Camera info
    if (data.Make || data.Model) {
      result.camera = `${data.Make || ''} ${data.Model || ''}`.trim();
    }
    
    // Timestamp
    result.timestamp = data.DateTimeOriginal || data.CreateDate || data.FileModifyDate;
    
    // Author
    result.author = data.Author || data.Creator || data.Artist;
    
    // Software
    result.software = data.Software || data.CreatorTool;
    
    return result;
  } catch (error) {
    return {
      success: false,
      file: path.basename(filePath),
      error: error.message
    };
  }
}

function generateMap(locations) {
  if (locations.length === 0) return null;
  
  const mapData = {
    type: 'FeatureCollection',
    features: locations.map(loc => ({
      type: 'Feature',
      geometry: {
        type: 'Point',
        coordinates: [loc.lon, loc.lat]
      },
      properties: {
        file: loc.file,
        path: loc.path,
        timestamp: loc.timestamp,
        camera: loc.camera
      }
    }))
  };
  
  return mapData;
}

function generateTimeline(locations) {
  const timeline = locations
    .filter(loc => loc.timestamp)
    .sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp))
    .map(loc => ({
      timestamp: loc.timestamp,
      file: loc.file,
      location: `${loc.lat}, ${loc.lon}`
    }));
  
  return timeline;
}

function analyzePrivacyRisk(results) {
  let score = 0;
  const risks = [];
  
  if (results.withGPS > 0) {
    score += results.withGPS * 10;
    risks.push(`${results.withGPS} images contain GPS coordinates`);
  }
  
  const withAuthor = results.metadata.filter(m => m.author).length;
  if (withAuthor > 0) {
    score += withAuthor * 5;
    risks.push(`${withAuthor} images contain author information`);
  }
  
  const withCamera = results.metadata.filter(m => m.camera).length;
  if (withCamera > 0) {
    score += withCamera * 2;
    risks.push(`${withCamera} images reveal camera model`);
  }
  
  let level;
  if (score >= 50) level = 'CRITICAL';
  else if (score >= 25) level = 'HIGH';
  else if (score >= 10) level = 'MEDIUM';
  else if (score > 0) level = 'LOW';
  else level = 'MINIMAL';
  
  return {
    score: Math.min(score, 100),
    level: level,
    risks: risks
  };
}

function showBanner() {
  console.log("\x1b[31m");
  console.log("███████╗██╗  ██╗██╗███████╗    ███╗   ███╗ █████╗ ███████╗███╗   ███╗ █████╗ ███████╗███████╗");
  console.log("██╔════╝╚██╗██╔╝██║██╔════╝    ████╗ ████║██╔══██╗██╔════╝████╗ ████║██╔══██╗██╔════╝██╔════╝");
  console.log("█████╗   ╚███╔╝ ██║█████╗      ██╔████╔██║███████║███████╗██╔████╔██║███████║███████╗███████╗");
  console.log("██╔══╝   ██╔██╗ ██║██╔══╝      ██║╚██╔╝██║██╔══██║╚════██║██║╚██╔╝██║██╔══██║╚════██║╚════██║");
  console.log("███████╗██╔╝ ██╗██║██║         ██║ ╚═╝ ██║██║  ██║███████║██║ ╚═╝ ██║██║  ██║███████║███████║");
  console.log("╚══════╝╚═╝  ╚═╝╚═╝╚═╝         ╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝╚══════╝");
  console.log("\x1b[0m");
  console.log("\x1b[35m🥝 NIKA EXIF Mass Scanner - Bulk GPS & Metadata Extraction\x1b[0m");
  console.log("\x1b[33m⚠️  For privacy audits and authorized research only\x1b[0m\n");
}

function displayResults(data) {
  console.log("\n╔════════════════════════════════════════════════════════╗");
  console.log("║       📸 MASS EXIF SCAN RESULTS 📸                     ║");
  console.log("╚════════════════════════════════════════════════════════╝\n");
  
  console.log(`📊 Scan Statistics:`);
  console.log(`   Total Images: ${data.totalFiles}`);
  console.log(`   Successfully Scanned: ${data.scannedFiles}`);
  console.log(`   With GPS: \x1b[31m${data.withGPS}\x1b[0m`);
  console.log(`   Without GPS: \x1b[32m${data.withoutGPS}\x1b[0m`);
  console.log(`   Errors: ${data.errors}\n`);
  
  // Privacy Risk
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
  console.log("\x1b[36m🔒 PRIVACY RISK ASSESSMENT\x1b[0m");
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
  
  const riskColor = {
    'CRITICAL': '\x1b[41m\x1b[37m',
    'HIGH': '\x1b[31m',
    'MEDIUM': '\x1b[33m',
    'LOW': '\x1b[32m',
    'MINIMAL': '\x1b[32m'
  };
  
  console.log(`   Risk Level: ${riskColor[data.privacyRisk.level]}${data.privacyRisk.level}\x1b[0m`);
  console.log(`   Risk Score: ${data.privacyRisk.score}/100\n`);
  
  if (data.privacyRisk.risks.length > 0) {
    console.log('   Risk Factors:');
    data.privacyRisk.risks.forEach(risk => {
      console.log(`   • ${risk}`);
    });
    console.log('');
  }
  
  // GPS Locations
  if (data.locations.length > 0) {
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
    console.log("\x1b[36m📍 GPS LOCATIONS FOUND\x1b[0m");
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
    
    data.locations.slice(0, 10).forEach((loc, i) => {
      console.log(`   ${i + 1}. ${loc.file}`);
      console.log(`      Coordinates: ${loc.lat}, ${loc.lon}`);
      console.log(`      Google Maps: https://www.google.com/maps?q=${loc.lat},${loc.lon}`);
      if (loc.timestamp) console.log(`      Timestamp: ${loc.timestamp}`);
      if (loc.camera) console.log(`      Camera: ${loc.camera}`);
      console.log('');
    });
    
    if (data.locations.length > 10) {
      console.log(`   ... and ${data.locations.length - 10} more locations\n`);
    }
  }
  
  // Timeline
  if (data.timeline && data.timeline.length > 0) {
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
    console.log("\x1b[36m📅 TIMELINE (Chronological)\x1b[0m");
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
    
    data.timeline.slice(0, 10).forEach((item, i) => {
      console.log(`   ${i + 1}. ${item.timestamp}`);
      console.log(`      File: ${item.file}`);
      console.log(`      Location: ${item.location}\n`);
    });
    
    if (data.timeline.length > 10) {
      console.log(`   ... and ${data.timeline.length - 10} more events\n`);
    }
  }
  
  // Recommendations
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
  console.log("\x1b[36m💡 RECOMMENDATIONS\x1b[0m");
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
  
  if (data.withGPS > 0) {
    console.log('   \x1b[31m⚠️  GPS data found in images!\x1b[0m');
    console.log('   • Remove GPS data before sharing images online');
    console.log('   • Use: exiftool -gps:all= -r /path/to/images/');
    console.log('   • Enable "Remove location data" in camera settings');
  } else {
    console.log('   \x1b[32m✓ No GPS data found\x1b[0m');
  }
  
  console.log('   • Always review metadata before sharing images');
  console.log('   • Consider using metadata removal tools');
  console.log('   • Be aware of what information your devices embed');
  console.log('');
}

function saveResults(data, dirPath) {
  const dir = './exif-mass-reports';
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, -5);
  const safeName = path.basename(dirPath).replace(/[^a-z0-9]/gi, '_');
  const jsonFile = `${dir}/${safeName}-${timestamp}.json`;
  const txtFile = jsonFile.replace('.json', '.txt');
  const mapFile = `${dir}/${safeName}-${timestamp}-map.geojson`;
  
  // Save JSON
  fs.writeFileSync(jsonFile, JSON.stringify(data, null, 2));
  
  // Save TXT
  let txtContent = `═══════════════════════════════════════════════════════════
EXIF MASS SCANNER REPORT
═══════════════════════════════════════════════════════════

Directory: ${dirPath}
Scan Date: ${new Date(data.timestamp).toLocaleString()}

═══════════════════════════════════════════════════════════
STATISTICS
═══════════════════════════════════════════════════════════

Total Images: ${data.totalFiles}
Successfully Scanned: ${data.scannedFiles}
With GPS: ${data.withGPS}
Without GPS: ${data.withoutGPS}
Errors: ${data.errors}

═══════════════════════════════════════════════════════════
PRIVACY RISK ASSESSMENT
═══════════════════════════════════════════════════════════

Risk Level: ${data.privacyRisk.level}
Risk Score: ${data.privacyRisk.score}/100

Risk Factors:
${data.privacyRisk.risks.map(r => `• ${r}`).join('\n')}

═══════════════════════════════════════════════════════════
GPS LOCATIONS
═══════════════════════════════════════════════════════════

`;

  if (data.locations.length > 0) {
    data.locations.forEach((loc, i) => {
      txtContent += `${i + 1}. ${loc.file}\n`;
      txtContent += `   Coordinates: ${loc.lat}, ${loc.lon}\n`;
      txtContent += `   Google Maps: https://www.google.com/maps?q=${loc.lat},${loc.lon}\n`;
      if (loc.timestamp) txtContent += `   Timestamp: ${loc.timestamp}\n`;
      if (loc.camera) txtContent += `   Camera: ${loc.camera}\n`;
      txtContent += '\n';
    });
  } else {
    txtContent += 'No GPS data found.\n';
  }
  
  txtContent += `\n═══════════════════════════════════════════════════════════
TIMELINE
═══════════════════════════════════════════════════════════\n\n`;

  if (data.timeline && data.timeline.length > 0) {
    data.timeline.forEach((item, i) => {
      txtContent += `${i + 1}. ${item.timestamp}\n`;
      txtContent += `   File: ${item.file}\n`;
      txtContent += `   Location: ${item.location}\n\n`;
    });
  } else {
    txtContent += 'No timeline data available.\n';
  }
  
  fs.writeFileSync(txtFile, txtContent);
  
  // Save GeoJSON map
  if (data.map) {
    fs.writeFileSync(mapFile, JSON.stringify(data.map, null, 2));
  }
  
  console.log(`\x1b[32m✅ Results saved:\x1b[0m`);
  console.log(`   JSON: ${jsonFile}`);
  console.log(`   TXT: ${txtFile}`);
  if (data.map) {
    console.log(`   Map (GeoJSON): ${mapFile}`);
    console.log(`   View map at: https://geojson.io/`);
  }
  console.log('');
}

function showHelp() {
  showBanner();
  
  console.log("Usage: node exif-mass-scanner.js [OPTIONS] <directory>\n");
  console.log("Options:");
  console.log("  --recursive      Scan subdirectories (default: true)");
  console.log("  --no-recursive   Don't scan subdirectories");
  console.log("  --save           Save results to file");
  console.log("  --help           Show this help\n");
  
  console.log("Examples:");
  console.log("  node exif-mass-scanner.js /sdcard/DCIM/");
  console.log("  node exif-mass-scanner.js ~/Pictures --save");
  console.log("  node exif-mass-scanner.js . --no-recursive\n");
  
  console.log("Requirements:");
  console.log("  pkg install exiftool\n");
}

async function main() {
  const args = process.argv.slice(2);
  
  if (args.includes('--help') || args.length === 0) {
    showHelp();
    process.exit(0);
  }
  
  let dirPath = null;
  let recursive = true;
  let saveResults_flag = false;
  
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--no-recursive') {
      recursive = false;
    } else if (args[i] === '--recursive') {
      recursive = true;
    } else if (args[i] === '--save') {
      saveResults_flag = true;
    } else if (!args[i].startsWith('--')) {
      dirPath = args[i];
    }
  }
  
  if (!dirPath) {
    console.log("\x1b[31m❌ No directory specified!\x1b[0m\n");
    showHelp();
    process.exit(1);
  }
  
  if (!fs.existsSync(dirPath)) {
    console.log(`\x1b[31m❌ Directory not found: ${dirPath}\x1b[0m\n`);
    process.exit(1);
  }
  
  showBanner();
  
  console.log(`⏳ Scanning directory: ${dirPath}`);
  console.log(`   Recursive: ${recursive}\n`);
  
  const results = await scanDirectory(dirPath, recursive);
  
  results.timestamp = new Date().toISOString();
  results.dirPath = dirPath;
  results.privacyRisk = analyzePrivacyRisk(results);
  results.map = generateMap(results.locations);
  results.timeline = generateTimeline(results.locations);
  
  displayResults(results);
  
  if (saveResults_flag) {
    saveResults(results, dirPath);
  }
  
  console.log("\x1b[31m███████╗██╗  ██╗██╗███████╗\x1b[0m");
  console.log("\x1b[35m🥝 Scan complete - by kiwi & 777\x1b[0m\n");
}

main().catch(console.error);
