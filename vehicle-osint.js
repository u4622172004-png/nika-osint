#!/usr/bin/env node

const { exec } = require('child_process');
const { promisify } = require('util');
const execAsync = promisify(exec);
const fs = require('fs');

// ============================================
// VEHICLE OSINT - License Plate & VIN Lookup
// ============================================

function parseVIN(vin) {
  if (!vin || vin.length !== 17) {
    return {
      valid: false,
      error: 'VIN must be exactly 17 characters'
    };
  }
  
  // Remove invalid characters
  const invalid = ['I', 'O', 'Q'];
  for (let char of invalid) {
    if (vin.toUpperCase().includes(char)) {
      return {
        valid: false,
        error: `VIN cannot contain ${char}`
      };
    }
  }
  
  const result = {
    valid: true,
    vin: vin.toUpperCase(),
    wmi: vin.substring(0, 3),
    vds: vin.substring(3, 9),
    vis: vin.substring(9, 17),
    checkDigit: vin.charAt(8),
    yearCode: vin.charAt(9),
    plantCode: vin.charAt(10),
    serialNumber: vin.substring(11, 17)
  };
  
  // Decode manufacturer (WMI - World Manufacturer Identifier)
  result.manufacturer = decodeWMI(result.wmi);
  
  // Decode year
  result.year = decodeYear(result.yearCode);
  
  // Decode country
  result.country = decodeCountry(result.wmi.charAt(0));
  
  return result;
}

function decodeWMI(wmi) {
  const manufacturers = {
    '1C3': 'Chrysler',
    '1C4': 'Chrysler (trucks)',
    '1C6': 'Chrysler',
    '1FA': 'Ford',
    '1FB': 'Ford (trucks)',
    '1FC': 'Ford (trucks)',
    '1FD': 'Ford (trucks)',
    '1FM': 'Ford (MPV)',
    '1FT': 'Ford (trucks)',
    '1G1': 'Chevrolet',
    '1G3': 'Oldsmobile',
    '1G4': 'Buick',
    '1G6': 'Cadillac',
    '1GC': 'Chevrolet (trucks)',
    '1GM': 'Pontiac',
    '1GT': 'GMC (trucks)',
    '1GY': 'Cadillac',
    '1HG': 'Honda',
    '1J4': 'Jeep',
    '1L1': 'Lincoln',
    '1LN': 'Lincoln',
    '1ME': 'Mercury',
    '1N4': 'Nissan',
    '1VW': 'Volkswagen',
    '1YV': 'Mazda',
    '2C3': 'Chrysler (Canada)',
    '2FA': 'Ford (Canada)',
    '2G1': 'Chevrolet (Canada)',
    '2HG': 'Honda (Canada)',
    '2HM': 'Hyundai (Canada)',
    '2T1': 'Toyota (Canada)',
    '3FA': 'Ford (Mexico)',
    '3G1': 'Chevrolet (Mexico)',
    '3HG': 'Honda (Mexico)',
    '3N1': 'Nissan (Mexico)',
    '3VW': 'Volkswagen (Mexico)',
    '4F2': 'Mazda',
    '4F4': 'Mazda',
    '4M2': 'Mercury',
    '4S3': 'Subaru',
    '4S4': 'Subaru',
    '4T1': 'Toyota',
    '4US': 'BMW',
    '5FN': 'Honda (USA)',
    '5J6': 'Honda',
    '5L1': 'Lincoln',
    '5N1': 'Nissan',
    '5NP': 'Hyundai',
    '5T': 'Toyota',
    '5YJ': 'Tesla',
    'JA3': 'Mitsubishi',
    'JA4': 'Mitsubishi',
    'JF1': 'Subaru',
    'JF2': 'Subaru',
    'JH4': 'Acura',
    'JHM': 'Honda',
    'JM1': 'Mazda',
    'JN1': 'Nissan',
    'JN8': 'Nissan',
    'JT': 'Toyota',
    'KL': 'Daewoo/GM Korea',
    'KM': 'Hyundai',
    'KN': 'Kia',
    'KPT': 'SsangYong',
    'LFV': 'FAW (China)',
    'LGW': 'Great Wall',
    'LHG': 'Honda (China)',
    'LSV': 'SAIC',
    'LVS': 'Ford (China)',
    'SAJ': 'Jaguar',
    'SAL': 'Land Rover',
    'SAR': 'Rover',
    'SB1': 'Toyota (GB)',
    'SCC': 'Lotus',
    'SCE': 'DeLorean',
    'SDB': 'Peugeot',
    'SHH': 'Honda (UK)',
    'SJN': 'Nissan (UK)',
    'TMB': 'Skoda',
    'TMA': 'Hyundai (Czech)',
    'TRU': 'Audi (Hungary)',
    'TSM': 'Suzuki (Hungary)',
    'VF1': 'Renault',
    'VF3': 'Peugeot',
    'VF7': 'Citroën',
    'VF8': 'Matra',
    'VNK': 'Toyota (France)',
    'VSS': 'SEAT',
    'VWV': 'Volkswagen (Spain)',
    'WAU': 'Audi',
    'WBA': 'BMW',
    'WBS': 'BMW M',
    'WBX': 'BMW (M5)',
    'WDB': 'Mercedes-Benz',
    'WDC': 'DaimlerChrysler',
    'WDD': 'Mercedes-Benz',
    'WEB': 'Evobus (Mercedes)',
    'WF0': 'Ford (Germany)',
    'WJM': 'Iveco',
    'WJR': 'Irmscher',
    'WME': 'Smart',
    'WP0': 'Porsche',
    'WP1': 'Porsche',
    'WUA': 'Audi (quattro)',
    'WVG': 'Volkswagen (MPV)',
    'WVW': 'Volkswagen',
    'WV1': 'Volkswagen (commercial)',
    'WV2': 'Volkswagen (bus/van)',
    'YK1': 'Saab',
    'YS3': 'Saab',
    'YV1': 'Volvo',
    'YV2': 'Volvo (truck)',
    'YV3': 'Volvo (bus)',
    'ZAM': 'Maserati',
    'ZAP': 'Piaggio',
    'ZAR': 'Alfa Romeo',
    'ZCF': 'Ferrari',
    'ZDF': 'Ferrari',
    'ZFA': 'Fiat',
    'ZFF': 'Ferrari',
    'ZHW': 'Lamborghini',
    'ZLA': 'Lancia'
  };
  
  return manufacturers[wmi] || `Unknown (${wmi})`;
}

function decodeYear(code) {
  const yearCodes = {
    'A': 1980, 'B': 1981, 'C': 1982, 'D': 1983, 'E': 1984,
    'F': 1985, 'G': 1986, 'H': 1987, 'J': 1988, 'K': 1989,
    'L': 1990, 'M': 1991, 'N': 1992, 'P': 1993, 'R': 1994,
    'S': 1995, 'T': 1996, 'V': 1997, 'W': 1998, 'X': 1999,
    'Y': 2000, '1': 2001, '2': 2002, '3': 2003, '4': 2004,
    '5': 2005, '6': 2006, '7': 2007, '8': 2008, '9': 2009,
    // Second cycle (2010-2039)
    'A': 2010, 'B': 2011, 'C': 2012, 'D': 2013, 'E': 2014,
    'F': 2015, 'G': 2016, 'H': 2017, 'J': 2018, 'K': 2019,
    'L': 2020, 'M': 2021, 'N': 2022, 'P': 2023, 'R': 2024,
    'S': 2025, 'T': 2026, 'V': 2027, 'W': 2028, 'X': 2029
  };
  
  return yearCodes[code.toUpperCase()] || 'Unknown';
}

function decodeCountry(code) {
  const countries = {
    '1': 'United States', '2': 'Canada', '3': 'Mexico',
    '4': 'United States', '5': 'United States',
    'J': 'Japan', 'K': 'South Korea', 'L': 'China',
    'M': 'India', 'S': 'United Kingdom', 'T': 'Czech Republic/Hungary',
    'V': 'France/Spain', 'W': 'Germany', 'Y': 'Sweden/Finland',
    'Z': 'Italy', '9': 'Brazil'
  };
  
  return countries[code.toUpperCase()] || 'Unknown';
}

function parseLicensePlate(plate, country = 'US') {
  const cleaned = plate.toUpperCase().replace(/[^A-Z0-9]/g, '');
  
  const patterns = {
    US: {
      pattern: /^[A-Z0-9]{2,8}$/,
      note: 'Format varies by state'
    },
    UK: {
      pattern: /^[A-Z]{2}[0-9]{2}[A-Z]{3}$/,
      note: 'Current format: XX99XXX'
    },
    IT: {
      pattern: /^[A-Z]{2}[0-9]{3}[A-Z]{2}$/,
      note: 'Format: XX999XX'
    },
    DE: {
      pattern: /^[A-Z]{1,3}[A-Z]{1,2}[0-9]{1,4}$/,
      note: 'Format varies by region'
    },
    FR: {
      pattern: /^[A-Z]{2}[0-9]{3}[A-Z]{2}$/,
      note: 'Format: XX-999-XX'
    },
    ES: {
      pattern: /^[0-9]{4}[A-Z]{3}$/,
      note: 'Format: 9999XXX'
    }
  };
  
  const format = patterns[country] || patterns.US;
  
  return {
    plate: plate,
    cleaned: cleaned,
    country: country,
    valid: format.pattern.test(cleaned),
    format: format.note
  };
}

function generateLookupLinks(data) {
  const links = {};
  
  if (data.type === 'vin') {
    links.nhtsa = `https://vpic.nhtsa.dot.gov/decoder/decode/vin/${data.vin}?format=json`;
    links.autocheck = `https://www.autocheck.com/vehiclehistory/?vin=${data.vin}`;
    links.carfax = `https://www.carfax.com/VIN/${data.vin}`;
    links.vindecoder = `https://www.vindecoder.eu/${data.vin}`;
    links.vincheck = `https://www.vincheck.info/check/vin/${data.vin}`;
    links.faxvin = `https://www.faxvin.com/vin-check/${data.vin}`;
    links.epicvin = `https://www.epicvin.com/vin-check/${data.vin}`;
    links.bumper = `https://www.bumper.com/vin/${data.vin}`;
  } else if (data.type === 'plate') {
    links.faxvin = `https://www.faxvin.com/license-plate-lookup`;
    links.vehiclehistory = `https://www.vehiclehistory.com/license-plate-search`;
    links.searchquarry = `https://www.searchquarry.com/license-plate`;
    links.dmv = `https://dmv.org/vehicle-history`;
  }
  
  return links;
}

function getVehicleHistory() {
  return {
    carfax: {
      name: 'Carfax',
      url: 'https://carfax.com',
      features: ['Accident history', 'Service records', 'Ownership', 'Mileage'],
      cost: 'Paid'
    },
    autocheck: {
      name: 'AutoCheck',
      url: 'https://autocheck.com',
      features: ['Title check', 'Auction records', 'Odometer readings'],
      cost: 'Paid'
    },
    nhtsa: {
      name: 'NHTSA (Free)',
      url: 'https://vpic.nhtsa.dot.gov',
      features: ['VIN decode', 'Recall info', 'Specs'],
      cost: 'Free'
    },
    vincheck: {
      name: 'VINCheck.info',
      url: 'https://vincheck.info',
      features: ['Free basic decode', 'Theft check', 'Salvage check'],
      cost: 'Free/Paid'
    },
    epicvin: {
      name: 'EpicVIN',
      url: 'https://epicvin.com',
      features: ['Market value', 'Photos', 'Equipment list'],
      cost: 'Paid'
    }
  };
}

function showBanner() {
  console.log("\x1b[31m");
  console.log("██╗   ██╗███████╗██╗  ██╗██╗ ██████╗██╗     ███████╗     ██████╗ ███████╗██╗███╗   ██╗████████╗");
  console.log("██║   ██║██╔════╝██║  ██║██║██╔════╝██║     ██╔════╝    ██╔═══██╗██╔════╝██║████╗  ██║╚══██╔══╝");
  console.log("██║   ██║█████╗  ███████║██║██║     ██║     █████╗      ██║   ██║███████╗██║██╔██╗ ██║   ██║   ");
  console.log("╚██╗ ██╔╝██╔══╝  ██╔══██║██║██║     ██║     ██╔══╝      ██║   ██║╚════██║██║██║╚██╗██║   ██║   ");
  console.log(" ╚████╔╝ ███████╗██║  ██║██║╚██████╗███████╗███████╗    ╚██████╔╝███████║██║██║ ╚████║   ██║   ");
  console.log("  ╚═══╝  ╚══════╝╚═╝  ╚═╝╚═╝ ╚═════╝╚══════╝╚══════╝     ╚═════╝ ╚══════╝╚═╝╚═╝  ╚═══╝   ╚═╝   ");
  console.log("\x1b[0m");
  console.log("\x1b[35m🥝 NIKA Vehicle OSINT - License Plate & VIN Lookup\x1b[0m");
  console.log("\x1b[33m⚠️  For authorized investigation only - respect privacy laws\x1b[0m\n");
}

function displayResults(data) {
  console.log("\n╔════════════════════════════════════════════════════════╗");
  console.log("║       🚗 VEHICLE OSINT RESULTS 🚗                      ║");
  console.log("╚════════════════════════════════════════════════════════╝\n");
  
  if (data.type === 'vin') {
    console.log(`🔢 VIN: \x1b[36m${data.decoded.vin}\x1b[0m`);
    console.log(`✅ Valid: ${data.decoded.valid ? '\x1b[32mYes\x1b[0m' : '\x1b[31mNo\x1b[0m'}\n`);
    
    if (data.decoded.valid) {
      console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
      console.log("\x1b[36m🔍 VIN BREAKDOWN\x1b[0m");
      console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
      
      console.log(`   WMI (Manufacturer): ${data.decoded.wmi} - ${data.decoded.manufacturer}`);
      console.log(`   VDS (Description): ${data.decoded.vds}`);
      console.log(`   VIS (Identifier): ${data.decoded.vis}`);
      console.log(`   Check Digit: ${data.decoded.checkDigit}`);
      console.log(`   Year: ${data.decoded.year}`);
      console.log(`   Plant Code: ${data.decoded.plantCode}`);
      console.log(`   Serial Number: ${data.decoded.serialNumber}`);
      console.log(`   Country: ${data.decoded.country}\n`);
    }
  } else if (data.type === 'plate') {
    console.log(`🔢 Plate: \x1b[36m${data.plate.plate}\x1b[0m`);
    console.log(`🌍 Country: ${data.plate.country}`);
    console.log(`✅ Valid Format: ${data.plate.valid ? '\x1b[32mYes\x1b[0m' : '\x1b[31mNo\x1b[0m'}`);
    console.log(`📋 Format: ${data.plate.format}\n`);
  }
  
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
  console.log("\x1b[36m🔗 LOOKUP SERVICES\x1b[0m");
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
  
  Object.entries(data.lookupLinks).forEach(([service, url]) => {
    console.log(`   ${service}: ${url}`);
  });
  console.log('');
  
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
  console.log("\x1b[36m📊 VEHICLE HISTORY SERVICES\x1b[0m");
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
  
  Object.entries(data.historyServices).forEach(([key, service]) => {
    console.log(`   \x1b[32m${service.name}\x1b[0m (${service.cost})`);
    console.log(`   URL: ${service.url}`);
    console.log(`   Features: ${service.features.join(', ')}\n`);
  });
  
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
  console.log("\x1b[36m💡 INVESTIGATION TIPS\x1b[0m");
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
  
  console.log('   • Check NHTSA for free VIN decode and recalls');
  console.log('   • Use multiple sources to verify information');
  console.log('   • Look for accident/damage history');
  console.log('   • Verify odometer readings');
  console.log('   • Check for title issues (salvage, flood, etc.)');
  console.log('   • Search Google Images for the VIN or plate');
  console.log('   • Check social media for vehicle photos');
  console.log('   • Look up recall campaigns');
  console.log('');
}

function saveResults(data) {
  const dir = './vehicle-osint-reports';
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, -5);
  const identifier = data.type === 'vin' ? data.decoded.vin : data.plate.cleaned;
  const jsonFile = `${dir}/${identifier}-${timestamp}.json`;
  const txtFile = jsonFile.replace('.json', '.txt');
  
  fs.writeFileSync(jsonFile, JSON.stringify(data, null, 2));
  
  let txtContent = `═══════════════════════════════════════════════════════════
VEHICLE OSINT REPORT
═══════════════════════════════════════════════════════════

Type: ${data.type.toUpperCase()}
Date: ${new Date(data.timestamp).toLocaleString()}

`;

  if (data.type === 'vin') {
    txtContent += `VIN: ${data.decoded.vin}
Valid: ${data.decoded.valid}

═══════════════════════════════════════════════════════════
VIN BREAKDOWN
═══════════════════════════════════════════════════════════

WMI (Manufacturer): ${data.decoded.wmi} - ${data.decoded.manufacturer}
VDS (Description): ${data.decoded.vds}
VIS (Identifier): ${data.decoded.vis}
Check Digit: ${data.decoded.checkDigit}
Year: ${data.decoded.year}
Plant Code: ${data.decoded.plantCode}
Serial Number: ${data.decoded.serialNumber}
Country: ${data.decoded.country}

`;
  } else {
    txtContent += `Plate: ${data.plate.plate}
Cleaned: ${data.plate.cleaned}
Country: ${data.plate.country}
Valid Format: ${data.plate.valid}
Format: ${data.plate.format}

`;
  }
  
  txtContent += `═══════════════════════════════════════════════════════════
LOOKUP SERVICES
═══════════════════════════════════════════════════════════\n\n`;

  Object.entries(data.lookupLinks).forEach(([service, url]) => {
    txtContent += `${service}: ${url}\n`;
  });
  
  txtContent += `\n═══════════════════════════════════════════════════════════
VEHICLE HISTORY SERVICES
═══════════════════════════════════════════════════════════\n\n`;

  Object.entries(data.historyServices).forEach(([key, service]) => {
    txtContent += `${service.name} (${service.cost})\n`;
    txtContent += `URL: ${service.url}\n`;
    txtContent += `Features: ${service.features.join(', ')}\n\n`;
  });
  
  fs.writeFileSync(txtFile, txtContent);
  
  console.log(`\x1b[32m✅ Results saved:\x1b[0m`);
  console.log(`   JSON: ${jsonFile}`);
  console.log(`   TXT: ${txtFile}\n`);
}

function showHelp() {
  showBanner();
  
  console.log("Usage: node vehicle-osint.js [OPTIONS] <vin|plate>\n");
  console.log("Options:");
  console.log("  --vin            Lookup by VIN (default if 17 chars)");
  console.log("  --plate          Lookup by license plate");
  console.log("  --country <CC>   Country code for plate (default: US)");
  console.log("  --save           Save results to file");
  console.log("  --help           Show this help\n");
  
  console.log("Country Codes:");
  console.log("  US, UK, IT, DE, FR, ES\n");
  
  console.log("Examples:");
  console.log("  node vehicle-osint.js 1HGBH41JXMN109186");
  console.log("  node vehicle-osint.js ABC1234 --plate --country US");
  console.log("  node vehicle-osint.js 5YJSA1E14HF000001 --save\n");
}

async function main() {
  const args = process.argv.slice(2);
  
  if (args.includes('--help') || args.length === 0) {
    showHelp();
    process.exit(0);
  }
  
  let input = null;
  let mode = 'auto';
  let country = 'US';
  let saveResults_flag = false;
  
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--vin') {
      mode = 'vin';
    } else if (args[i] === '--plate') {
      mode = 'plate';
    } else if (args[i] === '--country') {
      country = args[i + 1].toUpperCase();
      i++;
    } else if (args[i] === '--save') {
      saveResults_flag = true;
    } else if (!args[i].startsWith('--')) {
      input = args[i];
    }
  }
  
  if (!input) {
    console.log("\x1b[31m❌ No VIN or plate specified!\x1b[0m\n");
    showHelp();
    process.exit(1);
  }
  
  showBanner();
  
  // Auto-detect if VIN (17 chars) or plate
  if (mode === 'auto') {
    mode = input.replace(/[^A-Z0-9]/gi, '').length === 17 ? 'vin' : 'plate';
  }
  
  console.log(`⏳ Analyzing ${mode.toUpperCase()}: ${input}...\n`);
  
  const results = {
    timestamp: new Date().toISOString(),
    type: mode,
    decoded: null,
    plate: null,
    lookupLinks: null,
    historyServices: getVehicleHistory()
  };
  
  if (mode === 'vin') {
    results.decoded = parseVIN(input);
    results.lookupLinks = generateLookupLinks({ type: 'vin', vin: input });
  } else {
    results.plate = parseLicensePlate(input, country);
    results.lookupLinks = generateLookupLinks({ type: 'plate', plate: input });
  }
  
  displayResults(results);
  
  if (saveResults_flag) {
    saveResults(results);
  }
  
  console.log("\x1b[31m██╗   ██╗███████╗██╗  ██╗██╗ ██████╗██╗     ███████╗\x1b[0m");
  console.log("\x1b[35m🥝 Lookup complete - by kiwi & 777\x1b[0m\n");
}

main().catch(console.error);
