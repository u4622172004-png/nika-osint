#!/usr/bin/env node

const { exec } = require('child_process');
const { promisify } = require('util');
const execAsync = promisify(exec);
const fs = require('fs');
const path = require('path');

// ============================================
// METADATA EXTRACTOR PRO - Document Forensics
// ============================================

async function checkExiftool() {
  try {
    await execAsync('which exiftool');
    return true;
  } catch {
    return false;
  }
}

async function extractMetadata(filePath) {
  try {
    console.log('   Extracting metadata with exiftool...');
    
    const { stdout } = await execAsync(`exiftool -j "${filePath}"`, {
      maxBuffer: 10 * 1024 * 1024
    });
    
    const data = JSON.parse(stdout)[0];
    
    return {
      available: true,
      file: path.basename(filePath),
      path: filePath,
      metadata: data,
      sensitive: findSensitiveData(data),
      privacy: assessPrivacyRisk(data),
      forensics: extractForensicData(data)
    };
  } catch (error) {
    return {
      available: false,
      error: error.message,
      file: path.basename(filePath)
    };
  }
}

function findSensitiveData(metadata) {
  const sensitive = {
    found: false,
    items: []
  };
  
  // Author information
  if (metadata.Author || metadata.Creator || metadata.Artist) {
    sensitive.found = true;
    sensitive.items.push({
      type: 'Author',
      value: metadata.Author || metadata.Creator || metadata.Artist,
      risk: 'MEDIUM',
      note: 'Reveals document creator identity'
    });
  }
  
  // Company/Organization
  if (metadata.Company || metadata.Organization) {
    sensitive.found = true;
    sensitive.items.push({
      type: 'Company',
      value: metadata.Company || metadata.Organization,
      risk: 'MEDIUM',
      note: 'Reveals organizational affiliation'
    });
  }
  
  // GPS Location
  if (metadata.GPSLatitude || metadata.GPSLongitude) {
    sensitive.found = true;
    const lat = metadata.GPSLatitude;
    const lon = metadata.GPSLongitude;
    sensitive.items.push({
      type: 'GPS Location',
      value: `${lat}, ${lon}`,
      risk: 'HIGH',
      note: 'Reveals exact location where photo was taken',
      maps: `https://www.google.com/maps?q=${lat},${lon}`
    });
  }
  
  // Email addresses
  const emailFields = ['AuthorEmail', 'CreatorEmail', 'Email'];
  for (const field of emailFields) {
    if (metadata[field]) {
      sensitive.found = true;
      sensitive.items.push({
        type: 'Email',
        value: metadata[field],
        risk: 'HIGH',
        note: 'Personal email address exposed'
      });
    }
  }
  
  // Phone numbers
  if (metadata.Phone || metadata.Telephone) {
    sensitive.found = true;
    sensitive.items.push({
      type: 'Phone',
      value: metadata.Phone || metadata.Telephone,
      risk: 'HIGH',
      note: 'Phone number exposed'
    });
  }
  
  // Software/Application
  if (metadata.Software || metadata.Application || metadata.CreatorTool) {
    sensitive.found = true;
    sensitive.items.push({
      type: 'Software',
      value: metadata.Software || metadata.Application || metadata.CreatorTool,
      risk: 'LOW',
      note: 'Reveals software used for creation'
    });
  }
  
  // Operating System
  if (metadata.Platform || metadata.OperatingSystem) {
    sensitive.found = true;
    sensitive.items.push({
      type: 'OS',
      value: metadata.Platform || metadata.OperatingSystem,
      risk: 'LOW',
      note: 'Reveals operating system'
    });
  }
  
  // Camera Make/Model
  if (metadata.Make || metadata.Model) {
    const camera = `${metadata.Make || ''} ${metadata.Model || ''}`.trim();
    sensitive.found = true;
    sensitive.items.push({
      type: 'Camera',
      value: camera,
      risk: 'LOW',
      note: 'Reveals camera/phone model'
    });
  }
  
  // Serial Numbers
  if (metadata.SerialNumber || metadata.InternalSerialNumber) {
    sensitive.found = true;
    sensitive.items.push({
      type: 'Serial Number',
      value: metadata.SerialNumber || metadata.InternalSerialNumber,
      risk: 'MEDIUM',
      note: 'Device serial number - can track device'
    });
  }
  
  // Comments/Descriptions
  if (metadata.Comment || metadata.Description || metadata.Subject) {
    const comment = metadata.Comment || metadata.Description || metadata.Subject;
    if (comment.length > 0) {
      sensitive.found = true;
      sensitive.items.push({
        type: 'Comment',
        value: comment.substring(0, 100) + (comment.length > 100 ? '...' : ''),
        risk: 'LOW',
        note: 'May contain sensitive information'
      });
    }
  }
  
  return sensitive;
}

function assessPrivacyRisk(metadata) {
  let score = 0;
  const risks = [];
  
  // High risk factors
  if (metadata.GPSLatitude || metadata.GPSLongitude) {
    score += 30;
    risks.push('GPS coordinates present - exact location leaked');
  }
  
  if (metadata.AuthorEmail || metadata.CreatorEmail || metadata.Email) {
    score += 25;
    risks.push('Email address exposed');
  }
  
  if (metadata.Phone || metadata.Telephone) {
    score += 25;
    risks.push('Phone number exposed');
  }
  
  // Medium risk factors
  if (metadata.Author || metadata.Creator || metadata.Artist) {
    score += 15;
    risks.push('Author/Creator name present');
  }
  
  if (metadata.Company || metadata.Organization) {
    score += 15;
    risks.push('Company/Organization information present');
  }
  
  if (metadata.SerialNumber || metadata.InternalSerialNumber) {
    score += 10;
    risks.push('Device serial number present');
  }
  
  // Low risk factors
  if (metadata.Software || metadata.Application) {
    score += 5;
    risks.push('Software information present');
  }
  
  if (metadata.Make || metadata.Model) {
    score += 5;
    risks.push('Camera/Device model information present');
  }
  
  // Determine risk level
  let level;
  if (score >= 50) level = 'CRITICAL';
  else if (score >= 30) level = 'HIGH';
  else if (score >= 15) level = 'MEDIUM';
  else if (score > 0) level = 'LOW';
  else level = 'MINIMAL';
  
  return {
    score: Math.min(score, 100),
    level: level,
    risks: risks
  };
}

function extractForensicData(metadata) {
  const forensics = {};
  
  // Creation timestamp
  if (metadata.CreateDate || metadata.DateTimeOriginal || metadata.FileModifyDate) {
    forensics.created = metadata.CreateDate || metadata.DateTimeOriginal || metadata.FileModifyDate;
  }
  
  // Modification timestamp
  if (metadata.ModifyDate || metadata.FileModifyDate) {
    forensics.modified = metadata.ModifyDate || metadata.FileModifyDate;
  }
  
  // Edit history
  if (metadata.History) {
    forensics.editHistory = metadata.History;
  }
  
  // Document stats
  if (metadata.Pages || metadata.PageCount) {
    forensics.pages = metadata.Pages || metadata.PageCount;
  }
  
  if (metadata.Words || metadata.WordCount) {
    forensics.words = metadata.Words || metadata.WordCount;
  }
  
  if (metadata.Characters || metadata.CharacterCount) {
    forensics.characters = metadata.Characters || metadata.CharacterCount;
  }
  
  // Editing time
  if (metadata.TotalEditTime) {
    forensics.editTime = metadata.TotalEditTime;
  }
  
  // Revision number
  if (metadata.RevisionNumber) {
    forensics.revisions = metadata.RevisionNumber;
  }
  
  // Last modified by
  if (metadata.LastModifiedBy) {
    forensics.lastModifiedBy = metadata.LastModifiedBy;
  }
  
  // Template
  if (metadata.Template) {
    forensics.template = metadata.Template;
  }
  
  // PDF specific
  if (metadata.Producer) {
    forensics.pdfProducer = metadata.Producer;
  }
  
  if (metadata.PDFVersion) {
    forensics.pdfVersion = metadata.PDFVersion;
  }
  
  // Image specific
  if (metadata.ImageWidth && metadata.ImageHeight) {
    forensics.dimensions = `${metadata.ImageWidth}x${metadata.ImageHeight}`;
  }
  
  if (metadata.ColorSpace) {
    forensics.colorSpace = metadata.ColorSpace;
  }
  
  if (metadata.XResolution && metadata.YResolution) {
    forensics.resolution = `${metadata.XResolution}x${metadata.YResolution} DPI`;
  }
  
  return forensics;
}

function showBanner() {
  console.log("\x1b[31m");
  console.log("███╗   ███╗███████╗████████╗ █████╗ ██████╗  █████╗ ████████╗ █████╗ ");
  console.log("████╗ ████║██╔════╝╚══██╔══╝██╔══██╗██╔══██╗██╔══██╗╚══██╔══╝██╔══██╗");
  console.log("██╔████╔██║█████╗     ██║   ███████║██║  ██║███████║   ██║   ███████║");
  console.log("██║╚██╔╝██║██╔══╝     ██║   ██╔══██║██║  ██║██╔══██║   ██║   ██╔══██║");
  console.log("██║ ╚═╝ ██║███████╗   ██║   ██║  ██║██████╔╝██║  ██║   ██║   ██║  ██║");
  console.log("╚═╝     ╚═╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝");
  console.log("\x1b[0m");
  console.log("\x1b[35m🥝 NIKA Metadata Extractor - Document Forensics\x1b[0m");
  console.log("\x1b[33m⚠️  For authorized investigation only\x1b[0m\n");
}

function displayResults(data) {
  console.log("\n╔════════════════════════════════════════════════════════╗");
  console.log("║       📸 METADATA EXTRACTION RESULTS 📸                ║");
  console.log("╚════════════════════════════════════════════════════════╝\n");
  
  if (!data.available) {
    console.log(`\x1b[31m❌ Failed to extract metadata\x1b[0m`);
    console.log(`   Error: ${data.error}\n`);
    return;
  }
  
  console.log(`📁 File: \x1b[36m${data.file}\x1b[0m`);
  console.log(`📍 Path: ${data.path}\n`);
  
  // Privacy Risk Assessment
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
  
  console.log(`   Risk Score: ${riskColor[data.privacy.level]}${data.privacy.score}/100\x1b[0m`);
  console.log(`   Risk Level: ${riskColor[data.privacy.level]}${data.privacy.level}\x1b[0m\n`);
  
  if (data.privacy.risks.length > 0) {
    console.log('   Risk Factors:');
    data.privacy.risks.forEach(risk => {
      console.log(`   • ${risk}`);
    });
    console.log('');
  }
  
  // Sensitive Data
  if (data.sensitive.found) {
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
    console.log("\x1b[36m⚠️  SENSITIVE DATA FOUND\x1b[0m");
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
    
    data.sensitive.items.forEach(item => {
      const itemRiskColor = {
        'HIGH': '\x1b[31m',
        'MEDIUM': '\x1b[33m',
        'LOW': '\x1b[32m'
      };
      
      console.log(`   ${itemRiskColor[item.risk]}[${item.risk}]\x1b[0m ${item.type}: ${item.value}`);
      console.log(`   ${item.note}`);
      if (item.maps) {
        console.log(`   View on map: ${item.maps}`);
      }
      console.log('');
    });
  }
  
  // Forensic Data
  if (Object.keys(data.forensics).length > 0) {
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
    console.log("\x1b[36m🔍 FORENSIC DATA\x1b[0m");
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
    
    if (data.forensics.created) {
      console.log(`   Created: ${data.forensics.created}`);
    }
    if (data.forensics.modified) {
      console.log(`   Modified: ${data.forensics.modified}`);
    }
    if (data.forensics.lastModifiedBy) {
      console.log(`   Last Modified By: ${data.forensics.lastModifiedBy}`);
    }
    if (data.forensics.pages) {
      console.log(`   Pages: ${data.forensics.pages}`);
    }
    if (data.forensics.words) {
      console.log(`   Words: ${data.forensics.words}`);
    }
    if (data.forensics.characters) {
      console.log(`   Characters: ${data.forensics.characters}`);
    }
    if (data.forensics.editTime) {
      console.log(`   Total Edit Time: ${data.forensics.editTime}`);
    }
    if (data.forensics.revisions) {
      console.log(`   Revisions: ${data.forensics.revisions}`);
    }
    if (data.forensics.template) {
      console.log(`   Template: ${data.forensics.template}`);
    }
    if (data.forensics.pdfProducer) {
      console.log(`   PDF Producer: ${data.forensics.pdfProducer}`);
    }
    if (data.forensics.dimensions) {
      console.log(`   Dimensions: ${data.forensics.dimensions}`);
    }
    if (data.forensics.resolution) {
      console.log(`   Resolution: ${data.forensics.resolution}`);
    }
    console.log('');
  }
  
  // Recommendations
  if (data.privacy.score > 0) {
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
    console.log("\x1b[36m💡 RECOMMENDATIONS\x1b[0m");
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
    
    console.log('   To remove metadata:');
    console.log(`   exiftool -all= "${data.path}"`);
    console.log('');
    console.log('   To strip GPS data only:');
    console.log(`   exiftool -gps:all= "${data.path}"`);
    console.log('');
    console.log('   To view all metadata:');
    console.log(`   exiftool "${data.path}"`);
    console.log('');
  }
}

function saveResults(data) {
  const dir = './metadata-reports';
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, -5);
  const fileBase = data.file.replace(/[^a-z0-9]/gi, '_');
  const jsonFile = `${dir}/${fileBase}-${timestamp}.json`;
  const txtFile = jsonFile.replace('.json', '.txt');
  
  fs.writeFileSync(jsonFile, JSON.stringify(data, null, 2));
  
  let txtContent = `═══════════════════════════════════════════════════════════
METADATA EXTRACTION REPORT
═══════════════════════════════════════════════════════════

File: ${data.file}
Path: ${data.path}
Date: ${new Date().toLocaleString()}

═══════════════════════════════════════════════════════════
PRIVACY RISK ASSESSMENT
═══════════════════════════════════════════════════════════

Risk Score: ${data.privacy.score}/100
Risk Level: ${data.privacy.level}

Risk Factors:
${data.privacy.risks.map(r => `• ${r}`).join('\n')}

═══════════════════════════════════════════════════════════
SENSITIVE DATA
═══════════════════════════════════════════════════════════

`;

  if (data.sensitive.found) {
    data.sensitive.items.forEach(item => {
      txtContent += `[${item.risk}] ${item.type}: ${item.value}\n`;
      txtContent += `${item.note}\n`;
      if (item.maps) {
        txtContent += `Map: ${item.maps}\n`;
      }
      txtContent += '\n';
    });
  } else {
    txtContent += 'No sensitive data found.\n';
  }
  
  txtContent += `═══════════════════════════════════════════════════════════
FORENSIC DATA
═══════════════════════════════════════════════════════════

`;

  Object.entries(data.forensics).forEach(([key, value]) => {
    txtContent += `${key}: ${value}\n`;
  });
  
  txtContent += `\n═══════════════════════════════════════════════════════════
RECOMMENDATIONS
═══════════════════════════════════════════════════════════

To remove all metadata:
exiftool -all= "${data.path}"

To strip GPS data only:
exiftool -gps:all= "${data.path}"

To view all metadata:
exiftool "${data.path}"
`;
  
  fs.writeFileSync(txtFile, txtContent);
  
  console.log(`\x1b[32m✅ Results saved:\x1b[0m`);
  console.log(`   JSON: ${jsonFile}`);
  console.log(`   TXT: ${txtFile}\n`);
}

function showHelp() {
  showBanner();
  
  console.log("Usage: node metadata-extractor.js [OPTIONS] <file>\n");
  console.log("Options:");
  console.log("  --save           Save results to file");
  console.log("  --help           Show this help\n");
  
  console.log("Supported Formats:");
  console.log("  Images:  JPG, PNG, GIF, TIFF, RAW, HEIC");
  console.log("  Docs:    PDF, DOCX, XLSX, PPTX");
  console.log("  Videos:  MP4, MOV, AVI, MKV");
  console.log("  Audio:   MP3, WAV, FLAC\n");
  
  console.log("Examples:");
  console.log("  node metadata-extractor.js photo.jpg");
  console.log("  node metadata-extractor.js document.pdf --save");
  console.log("  node metadata-extractor.js report.docx --save\n");
  
  console.log("\x1b[33mNote: Requires exiftool installed\x1b[0m");
  console.log("\x1b[33mInstall: pkg install exiftool\x1b[0m\n");
}

async function main() {
  const args = process.argv.slice(2);
  
  if (args.includes('--help') || args.length === 0) {
    showHelp();
    process.exit(0);
  }
  
  // Check exiftool
  const hasExiftool = await checkExiftool();
  if (!hasExiftool) {
    console.log("\x1b[31m❌ exiftool not installed!\x1b[0m");
    console.log("\x1b[33mInstall with: pkg install exiftool\x1b[0m\n");
    process.exit(1);
  }
  
  let filePath = null;
  let saveResults_flag = false;
  
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--save') {
      saveResults_flag = true;
    } else if (!args[i].startsWith('--')) {
      filePath = args[i];
    }
  }
  
  if (!filePath) {
    console.log("\x1b[31m❌ No file specified!\x1b[0m\n");
    showHelp();
    process.exit(1);
  }
  
  if (!fs.existsSync(filePath)) {
    console.log(`\x1b[31m❌ File not found: ${filePath}\x1b[0m\n`);
    process.exit(1);
  }
  
  showBanner();
  
  console.log(`⏳ Extracting metadata from: ${filePath}...\n`);
  
  const results = await extractMetadata(filePath);
  
  displayResults(results);
  
  if (saveResults_flag && results.available) {
    saveResults(results);
  }
  
  console.log("\x1b[31m███╗   ███╗███████╗████████╗ █████╗\x1b[0m");
  console.log("\x1b[35m🥝 Extraction complete - by kiwi & 777\x1b[0m\n");
}

main().catch(console.error);
