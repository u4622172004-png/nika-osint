#!/usr/bin/env node

const fs = require('fs');
const { exec } = require('child_process');
const { promisify } = require('util');
const execAsync = promisify(exec);

// ============================================
// FACE RECOGNITION - Reverse Face Search
// ============================================

const FACE_SEARCH_ENGINES = {
  pimeyes: {
    name: 'PimEyes',
    url: 'https://pimeyes.com',
    method: 'Upload image on website',
    features: ['Face recognition', 'Social media profiles', 'Dating sites', 'News articles'],
    cost: 'Free trial, then paid',
    accuracy: 'Very High'
  },
  yandex: {
    name: 'Yandex Images',
    url: 'https://yandex.com/images/',
    method: 'Upload or paste image URL',
    features: ['Russian social networks', 'VK profiles', 'Global search'],
    cost: 'Free',
    accuracy: 'High'
  },
  google: {
    name: 'Google Lens',
    url: 'https://lens.google.com',
    method: 'Upload image',
    features: ['Similar faces', 'Related images', 'Websites'],
    cost: 'Free',
    accuracy: 'Medium-High'
  },
  tineye: {
    name: 'TinEye',
    url: 'https://tineye.com',
    method: 'Upload image',
    features: ['Exact image matches', 'Reverse search'],
    cost: 'Free',
    accuracy: 'Medium'
  },
  socialcatfish: {
    name: 'Social Catfish',
    url: 'https://socialcatfish.com',
    method: 'Upload image',
    features: ['Dating profiles', 'Social media', 'Scammer detection'],
    cost: 'Paid',
    accuracy: 'High'
  },
  facecheck: {
    name: 'FaceCheck.ID',
    url: 'https://facecheck.id',
    method: 'Upload image',
    features: ['Criminal records', 'Social media', 'News'],
    cost: 'Paid',
    accuracy: 'Very High'
  },
  betaface: {
    name: 'BetaFace',
    url: 'https://www.betaface.com/demo.html',
    method: 'Upload image',
    features: ['Face detection', 'Age/gender estimation', 'Demographics'],
    cost: 'Free',
    accuracy: 'Medium'
  }
};

const SOCIAL_PLATFORMS_FACE_SEARCH = {
  facebook: {
    name: 'Facebook',
    method: 'Manual upload to search',
    tip: 'Use Facebook mobile app → Search by photo'
  },
  vk: {
    name: 'VK (VKontakte)',
    url: 'https://vk.com',
    method: 'Use FindFace or manual search',
    tip: 'Very effective for Russian/Eastern European faces'
  },
  instagram: {
    name: 'Instagram',
    method: 'Use Google Lens on Instagram photos',
    tip: 'Search username, then use Google Lens'
  },
  linkedin: {
    name: 'LinkedIn',
    method: 'Manual search by company + face',
    tip: 'Filter by company, then browse faces'
  }
};

const FACE_ANALYSIS_TOOLS = {
  demographics: {
    name: 'Face Demographics',
    tools: ['BetaFace', 'Microsoft Face API', 'Face++'],
    features: ['Age estimation', 'Gender detection', 'Emotion analysis', 'Ethnicity']
  },
  comparison: {
    name: 'Face Comparison',
    tools: ['FindClone', 'Face Match', 'Twins or Not'],
    features: ['Face similarity score', 'Celebrity lookalike', 'Facial features comparison']
  },
  enhancement: {
    name: 'Image Enhancement',
    tools: ['Remini', 'Let\'s Enhance', 'Bigjpg'],
    features: ['Upscale low quality', 'Deblur', 'Restore old photos']
  }
};

function showBanner() {
  console.log("\x1b[31m");
  console.log("███████╗ █████╗  ██████╗███████╗    ██████╗ ███████╗ ██████╗ ██████╗  ██████╗ ");
  console.log("██╔════╝██╔══██╗██╔════╝██╔════╝    ██╔══██╗██╔════╝██╔════╝██╔═══██╗██╔════╝ ");
  console.log("█████╗  ███████║██║     █████╗      ██████╔╝█████╗  ██║     ██║   ██║██║  ███╗");
  console.log("██╔══╝  ██╔══██║██║     ██╔══╝      ██╔══██╗██╔══╝  ██║     ██║   ██║██║   ██║");
  console.log("██║     ██║  ██║╚██████╗███████╗    ██║  ██║███████╗╚██████╗╚██████╔╝╚██████╔╝");
  console.log("╚═╝     ╚═╝  ╚═╝ ╚═════╝╚══════╝    ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝  ╚═════╝ ");
  console.log("\x1b[0m");
  console.log("\x1b[35m🥝 NIKA Face Recognition - Reverse Face Search OSINT\x1b[0m");
  console.log("\x1b[33m⚠️  For authorized investigation only - Respect privacy laws\x1b[0m\n");
}

function analyzeImage(imagePath) {
  console.log(`\n📸 Analyzing image: ${imagePath}\n`);
  
  if (!fs.existsSync(imagePath)) {
    return {
      error: 'Image file not found',
      path: imagePath
    };
  }
  
  const stats = fs.statSync(imagePath);
  
  return {
    path: imagePath,
    size: stats.size,
    sizeHuman: `${(stats.size / 1024).toFixed(2)} KB`,
    exists: true,
    format: imagePath.split('.').pop().toUpperCase()
  };
}

function displayResults(data) {
  console.log("\n╔════════════════════════════════════════════════════════╗");
  console.log("║       🎭 FACE RECOGNITION SEARCH GUIDE 🎭              ║");
  console.log("╚════════════════════════════════════════════════════════╝\n");
  
  if (data.imageAnalysis) {
    console.log("\x1b[36m┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓\x1b[0m");
    console.log("\x1b[36m┃                  IMAGE ANALYSIS                      ┃\x1b[0m");
    console.log("\x1b[36m┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛\x1b[0m\n");
    
    if (data.imageAnalysis.error) {
      console.log(`   ❌ ${data.imageAnalysis.error}`);
      console.log(`   Path: ${data.imageAnalysis.path}\n`);
    } else {
      console.log(`   ✅ File Found`);
      console.log(`   Path:                ${data.imageAnalysis.path}`);
      console.log(`   Size:                ${data.imageAnalysis.sizeHuman}`);
      console.log(`   Format:              ${data.imageAnalysis.format}\n`);
    }
  }
  
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
  console.log("\x1b[36m🔍 RECOMMENDED SEARCH ENGINES\x1b[0m");
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
  
  Object.entries(FACE_SEARCH_ENGINES).forEach(([key, engine]) => {
    console.log(`   \x1b[32m${engine.name}\x1b[0m (${engine.accuracy})`);
    console.log(`      URL: ${engine.url}`);
    console.log(`      Method: ${engine.method}`);
    console.log(`      Cost: ${engine.cost}`);
    console.log(`      Features: ${engine.features.join(', ')}\n`);
  });
  
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
  console.log("\x1b[36m📱 SOCIAL MEDIA FACE SEARCH\x1b[0m");
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
  
  Object.entries(SOCIAL_PLATFORMS_FACE_SEARCH).forEach(([key, platform]) => {
    console.log(`   \x1b[32m${platform.name}\x1b[0m`);
    if (platform.url) console.log(`      URL: ${platform.url}`);
    console.log(`      Method: ${platform.method}`);
    console.log(`      💡 ${platform.tip}\n`);
  });
  
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
  console.log("\x1b[36m🎯 FACE ANALYSIS TOOLS\x1b[0m");
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
  
  Object.entries(FACE_ANALYSIS_TOOLS).forEach(([key, category]) => {
    console.log(`   \x1b[32m${category.name}\x1b[0m`);
    console.log(`      Tools: ${category.tools.join(', ')}`);
    console.log(`      Features: ${category.features.join(', ')}\n`);
  });
  
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
  console.log("\x1b[36m💡 SEARCH WORKFLOW\x1b[0m");
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
  
  console.log('   \x1b[32m1. Prepare Image:\x1b[0m');
  console.log('      • Crop face only (better results)');
  console.log('      • Use high resolution');
  console.log('      • Front-facing preferred');
  console.log('      • Good lighting\n');
  
  console.log('   \x1b[32m2. Start with Free Tools:\x1b[0m');
  console.log('      • Google Lens (quick check)');
  console.log('      • Yandex Images (Russian/Eastern Europe)');
  console.log('      • TinEye (exact matches)\n');
  
  console.log('   \x1b[32m3. Use Premium if Needed:\x1b[0m');
  console.log('      • PimEyes (most comprehensive)');
  console.log('      • FaceCheck.ID (criminal records)');
  console.log('      • Social Catfish (dating scams)\n');
  
  console.log('   \x1b[32m4. Analyze Results:\x1b[0m');
  console.log('      • Save all matching images');
  console.log('      • Note usernames/profiles');
  console.log('      • Cross-reference with other OSINT');
  console.log('      • Check metadata of found images\n');
  
  console.log('   \x1b[32m5. Verify Identity:\x1b[0m');
  console.log('      • Multiple photo comparison');
  console.log('      • Check posting dates');
  console.log('      • Look for location tags');
  console.log('      • Analyze friend lists\n');
  
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
  console.log("\x1b[36m⚠️  LEGAL & ETHICAL CONSIDERATIONS\x1b[0m");
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
  
  console.log('   \x1b[31m⚠️  DO NOT use for stalking or harassment\x1b[0m');
  console.log('   \x1b[31m⚠️  Respect privacy laws (GDPR, etc.)\x1b[0m');
  console.log('   \x1b[31m⚠️  Only for authorized investigations\x1b[0m');
  console.log('   \x1b[31m⚠️  Get consent when possible\x1b[0m');
  console.log('   \x1b[31m⚠️  Be aware of false positives\x1b[0m\n');
  
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
  console.log("\x1b[36m🔗 QUICK LINKS\x1b[0m");
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
  
  console.log('   PimEyes:         https://pimeyes.com');
  console.log('   Yandex Images:   https://yandex.com/images/');
  console.log('   Google Lens:     https://lens.google.com');
  console.log('   TinEye:          https://tineye.com');
  console.log('   FaceCheck.ID:    https://facecheck.id');
  console.log('   BetaFace:        https://www.betaface.com/demo.html\n');
}

function saveReport(data) {
  const dir = './face-recognition-reports';
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, -5);
  const filename = `${dir}/face-search-${timestamp}.txt`;
  
  let content = `═══════════════════════════════════════════════════════════
FACE RECOGNITION SEARCH REPORT
═══════════════════════════════════════════════════════════

Date: ${new Date().toLocaleString()}

`;

  if (data.imageAnalysis && !data.imageAnalysis.error) {
    content += `IMAGE ANALYZED:\nPath: ${data.imageAnalysis.path}\nSize: ${data.imageAnalysis.sizeHuman}\nFormat: ${data.imageAnalysis.format}\n\n`;
  }
  
  content += `RECOMMENDED SEARCH ENGINES:\n\n`;
  
  Object.entries(FACE_SEARCH_ENGINES).forEach(([key, engine]) => {
    content += `${engine.name} (${engine.accuracy})\nURL: ${engine.url}\nCost: ${engine.cost}\nFeatures: ${engine.features.join(', ')}\n\n`;
  });
  
  content += `\nSOCIAL MEDIA PLATFORMS:\n\n`;
  
  Object.entries(SOCIAL_PLATFORMS_FACE_SEARCH).forEach(([key, platform]) => {
    content += `${platform.name}\n${platform.url || ''}\nMethod: ${platform.method}\nTip: ${platform.tip}\n\n`;
  });
  
  fs.writeFileSync(filename, content);
  
  console.log(`\x1b[32m✅ Report saved: ${filename}\x1b[0m\n`);
}

function showHelp() {
  showBanner();
  
  console.log("Usage: node face-recognition.js [OPTIONS] <image-path>\n");
  console.log("Options:");
  console.log("  --image <path>       Path to image file");
  console.log("  --list               List all search engines");
  console.log("  --save               Save search guide");
  console.log("  --help               Show this help\n");
  
  console.log("Examples:");
  console.log("  node face-recognition.js --image /path/to/photo.jpg");
  console.log("  node face-recognition.js --list");
  console.log("  node face-recognition.js --image photo.jpg --save\n");
}

function main() {
  const args = process.argv.slice(2);
  
  if (args.length === 0 || args.includes('--help')) {
    showHelp();
    process.exit(0);
  }
  
  showBanner();
  
  let imagePath = null;
  let listFlag = false;
  let saveFlag = false;
  
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--image') {
      imagePath = args[i + 1];
      i++;
    } else if (args[i] === '--list') {
      listFlag = true;
    } else if (args[i] === '--save') {
      saveFlag = true;
    } else if (!args[i].startsWith('--')) {
      imagePath = args[i];
    }
  }
  
  const results = {
    timestamp: new Date().toISOString(),
    imageAnalysis: null
  };
  
  if (imagePath) {
    results.imageAnalysis = analyzeImage(imagePath);
  }
  
  displayResults(results);
  
  if (saveFlag) {
    saveReport(results);
  }
  
  console.log("\x1b[31m███████╗ █████╗  ██████╗███████╗\x1b[0m");
  console.log("\x1b[35m🥝 Search guide complete - by kiwi & 777\x1b[0m\n");
}

main();
