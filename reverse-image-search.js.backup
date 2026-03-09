#!/usr/bin/env node

const fs = require('fs');
const crypto = require('crypto');

// ============================================
// REVERSE IMAGE SEARCH
// ============================================

function generateSearchUrls(imagePath, imageUrl) {
  const urls = {};
  
  if (imageUrl) {
    // Image from URL
    const encoded = encodeURIComponent(imageUrl);
    
    urls.google = `https://images.google.com/searchbyimage?image_url=${encoded}`;
    urls.yandex = `https://yandex.com/images/search?rpt=imageview&url=${encoded}`;
    urls.tineye = `https://tineye.com/search?url=${encoded}`;
    urls.bing = `https://www.bing.com/images/searchbyimage?cbir=sbi&imgurl=${encoded}`;
    
  } else if (imagePath) {
    // Local image file
    urls.google = `https://images.google.com/`;
    urls.googleUpload = 'Go to Google Images → Click camera icon → Upload image';
    
    urls.yandex = `https://yandex.com/images/`;
    urls.yandexUpload = 'Go to Yandex Images → Click camera icon → Upload image';
    
    urls.tineye = `https://tineye.com/`;
    urls.tineyeUpload = 'Go to TinEye → Click upload button → Select image';
    
    urls.bing = `https://www.bing.com/images/`;
    urls.bingUpload = 'Go to Bing Images → Click search icon → Upload image';
  }
  
  // Additional search engines
  urls.saucenao = 'https://saucenao.com/';
  urls.iqdb = 'https://iqdb.org/';
  urls.karma_decay = 'http://karmadecay.com/';
  urls.baidu = 'https://image.baidu.com/';
  urls.sogou = 'https://pic.sogou.com/';
  
  return urls;
}

async function extractMetadata(imagePath) {
  const { exec } = require('child_process');
  const { promisify } = require('util');
  const execAsync = promisify(exec);
  
  try {
    // Check if exiftool is available
    await execAsync('which exiftool');
    
    const { stdout } = await execAsync(`exiftool -json "${imagePath}"`);
    const metadata = JSON.parse(stdout)[0];
    
    return {
      available: true,
      filename: metadata.FileName,
      fileSize: metadata.FileSize,
      imageSize: `${metadata.ImageWidth}x${metadata.ImageHeight}`,
      camera: metadata.Make ? `${metadata.Make} ${metadata.Model}` : 'Unknown',
      dateTime: metadata.DateTimeOriginal || metadata.CreateDate,
      gps: metadata.GPSLatitude && metadata.GPSLongitude ? {
        latitude: metadata.GPSLatitude,
        longitude: metadata.GPSLongitude,
        mapsUrl: `https://www.google.com/maps?q=${metadata.GPSLatitude},${metadata.GPSLongitude}`
      } : null,
      software: metadata.Software,
      copyright: metadata.Copyright,
      artist: metadata.Artist,
      rawMetadata: metadata
    };
  } catch {
    return {
      available: false,
      note: 'Install exiftool for metadata extraction: pkg install exiftool'
    };
  }
}

function getImageHash(imagePath) {
  try {
    const fileBuffer = fs.readFileSync(imagePath);
    const hashSum = crypto.createHash('sha256');
    hashSum.update(fileBuffer);
    return hashSum.digest('hex');
  } catch {
    return null;
  }
}

// ============================================
// DISPLAY FUNCTIONS
// ============================================

function showBanner() {
  console.log("\x1b[31m");
  console.log("██████╗ ███████╗██╗   ██╗███████╗██████╗ ███████╗███████╗");
  console.log("██╔══██╗██╔════╝██║   ██║██╔════╝██╔══██╗██╔════╝██╔════╝");
  console.log("██████╔╝█████╗  ██║   ██║█████╗  ██████╔╝███████╗█████╗  ");
  console.log("██╔══██╗██╔══╝  ╚██╗ ██╔╝██╔══╝  ██╔══██╗╚════██║██╔══╝  ");
  console.log("██║  ██║███████╗ ╚████╔╝ ███████╗██║  ██║███████║███████╗");
  console.log("╚═╝  ╚═╝╚══════╝  ╚═══╝  ╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝");
  console.log("██╗███╗   ███╗ █████╗  ██████╗ ███████╗");
  console.log("██║████╗ ████║██╔══██╗██╔════╝ ██╔════╝");
  console.log("██║██╔████╔██║███████║██║  ███╗█████╗  ");
  console.log("██║██║╚██╔╝██║██╔══██║██║   ██║██╔══╝  ");
  console.log("██║██║ ╚═╝ ██║██║  ██║╚██████╔╝███████╗");
  console.log("╚═╝╚═╝     ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝");
  console.log("\x1b[0m");
  console.log("\x1b[35m🥝 NIKA Reverse Image Search + Metadata Extractor\x1b[0m");
  console.log("\x1b[33m⚠️  For authorized investigation only\x1b[0m\n");
}

async function displayResults(imagePath, imageUrl, metadata, urls, hash) {
  console.log("\n╔════════════════════════════════════════════════════════╗");
  console.log("║         🖼️  REVERSE IMAGE SEARCH RESULTS 🖼️           ║");
  console.log("╚════════════════════════════════════════════════════════╝\n");
  
  if (imagePath) {
    console.log(`📁 Image File: \x1b[36m${imagePath}\x1b[0m`);
  }
  if (imageUrl) {
    console.log(`🔗 Image URL: \x1b[36m${imageUrl}\x1b[0m`);
  }
  if (hash) {
    console.log(`#️⃣  SHA-256: \x1b[33m${hash}\x1b[0m`);
  }
  console.log('');
  
  // Metadata
  if (metadata && metadata.available) {
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
    console.log("\x1b[36m📋 IMAGE METADATA\x1b[0m");
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
    
    if (metadata.fileSize) console.log(`   File Size: ${metadata.fileSize}`);
    if (metadata.imageSize) console.log(`   Dimensions: ${metadata.imageSize}`);
    if (metadata.camera) console.log(`   Camera: ${metadata.camera}`);
    if (metadata.dateTime) console.log(`   Date/Time: ${metadata.dateTime}`);
    if (metadata.software) console.log(`   Software: ${metadata.software}`);
    if (metadata.artist) console.log(`   Artist: ${metadata.artist}`);
    if (metadata.copyright) console.log(`   Copyright: ${metadata.copyright}`);
    
    if (metadata.gps) {
      console.log(`\n   \x1b[32m📍 GPS LOCATION FOUND!\x1b[0m`);
      console.log(`      Latitude: ${metadata.gps.latitude}`);
      console.log(`      Longitude: ${metadata.gps.longitude}`);
      console.log(`      Google Maps: ${metadata.gps.mapsUrl}`);
    }
    
    console.log('');
  } else if (metadata && !metadata.available) {
    console.log("\x1b[33m⚠️  Metadata extraction not available\x1b[0m");
    console.log(`   ${metadata.note}\n`);
  }
  
  // Search URLs
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
  console.log("\x1b[36m🔍 REVERSE IMAGE SEARCH ENGINES\x1b[0m");
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
  
  console.log("\x1b[33m🌐 MAJOR SEARCH ENGINES:\x1b[0m\n");
  
  if (urls.google) {
    console.log(`   1. \x1b[32mGoogle Images\x1b[0m`);
    if (urls.googleUpload) {
      console.log(`      ${urls.googleUpload}`);
    } else {
      console.log(`      ${urls.google}`);
    }
    console.log('');
  }
  
  if (urls.yandex) {
    console.log(`   2. \x1b[32mYandex Images\x1b[0m (Best for faces)`);
    if (urls.yandexUpload) {
      console.log(`      ${urls.yandexUpload}`);
    } else {
      console.log(`      ${urls.yandex}`);
    }
    console.log('');
  }
  
  if (urls.tineye) {
    console.log(`   3. \x1b[32mTinEye\x1b[0m (Oldest results)`);
    if (urls.tineyeUpload) {
      console.log(`      ${urls.tineyeUpload}`);
    } else {
      console.log(`      ${urls.tineye}`);
    }
    console.log('');
  }
  
  if (urls.bing) {
    console.log(`   4. \x1b[32mBing Images\x1b[0m`);
    if (urls.bingUpload) {
      console.log(`      ${urls.bingUpload}`);
    } else {
      console.log(`      ${urls.bing}`);
    }
    console.log('');
  }
  
  console.log("\x1b[33m🎨 SPECIALIZED ENGINES:\x1b[0m\n");
  console.log(`   5. \x1b[32mSauceNAO\x1b[0m (Anime/Art)`);
  console.log(`      ${urls.saucenao}\n`);
  
  console.log(`   6. \x1b[32mIQDB\x1b[0m (Anime/Booru)`);
  console.log(`      ${urls.iqdb}\n`);
  
  console.log(`   7. \x1b[32mKarmaDecay\x1b[0m (Reddit reposts)`);
  console.log(`      ${urls.karma_decay}\n`);
  
  console.log("\x1b[33m🌏 INTERNATIONAL:\x1b[0m\n");
  console.log(`   8. \x1b[32mBaidu Images\x1b[0m (China)`);
  console.log(`      ${urls.baidu}\n`);
  
  console.log(`   9. \x1b[32mSogou Images\x1b[0m (China)`);
  console.log(`      ${urls.sogou}\n`);
  
  // Tips
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
  console.log("\x1b[36m💡 SEARCH TIPS\x1b[0m");
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
  
  console.log("   🔍 Use Google for general searches");
  console.log("   👤 Use Yandex for face recognition");
  console.log("   ⏰ Use TinEye to find oldest version");
  console.log("   🎨 Use SauceNAO for anime/art");
  console.log("   📱 Check all engines for best results");
  console.log("   🔄 Try cropping image if no results");
  console.log('');
}

function saveResults(data, outputFile) {
  const jsonData = {
    timestamp: new Date().toISOString(),
    imagePath: data.imagePath,
    imageUrl: data.imageUrl,
    hash: data.hash,
    metadata: data.metadata,
    searchUrls: data.urls
  };
  
  fs.writeFileSync(outputFile, JSON.stringify(jsonData, null, 2));
  console.log(`\x1b[32m✅ Results saved to: ${outputFile}\x1b[0m\n`);
}

function showHelp() {
  showBanner();
  
  console.log("Usage: node reverse-image-search.js [OPTIONS] <image>\n");
  console.log("Options:");
  console.log("  --url <url>          Search by image URL");
  console.log("  --file <path>        Search by local file");
  console.log("  --save <file>        Save results to JSON");
  console.log("  --help               Show this help\n");
  
  console.log("Examples:");
  console.log("  node reverse-image-search.js --file photo.jpg");
  console.log("  node reverse-image-search.js --url https://example.com/image.jpg");
  console.log("  node reverse-image-search.js --file photo.jpg --save results.json\n");
}

// ============================================
// MAIN
// ============================================

async function main() {
  const args = process.argv.slice(2);
  
  if (args.includes('--help') || args.length === 0) {
    showHelp();
    process.exit(0);
  }
  
  let imagePath = null;
  let imageUrl = null;
  let saveFile = null;
  
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--file' && args[i + 1]) {
      imagePath = args[i + 1];
      i++;
    } else if (args[i] === '--url' && args[i + 1]) {
      imageUrl = args[i + 1];
      i++;
    } else if (args[i] === '--save' && args[i + 1]) {
      saveFile = args[i + 1];
      i++;
    } else if (!args[i].startsWith('--')) {
      imagePath = args[i];
    }
  }
  
  if (!imagePath && !imageUrl) {
    console.log("\x1b[31m❌ No image specified!\x1b[0m\n");
    showHelp();
    process.exit(1);
  }
  
  if (imagePath && !fs.existsSync(imagePath)) {
    console.log(`\x1b[31m❌ Image file not found: ${imagePath}\x1b[0m\n`);
    process.exit(1);
  }
  
  showBanner();
  
  // Generate search URLs
  const urls = generateSearchUrls(imagePath, imageUrl);
  
  // Extract metadata if local file
  let metadata = null;
  let hash = null;
  
  if (imagePath) {
    console.log(`⏳ Extracting metadata from ${imagePath}...\n`);
    metadata = await extractMetadata(imagePath);
    hash = getImageHash(imagePath);
  }
  
  // Display results
  await displayResults(imagePath, imageUrl, metadata, urls, hash);
  
  // Save if requested
  if (saveFile) {
    saveResults({ imagePath, imageUrl, metadata, urls, hash }, saveFile);
  }
  
  console.log("\x1b[31m██████╗ ███████╗██╗   ██╗███████╗██████╗ ███████╗███████╗\x1b[0m");
  console.log("\x1b[35m🥝 Search complete - by kiwi & 777\x1b[0m\n");
}

main().catch(console.error);
