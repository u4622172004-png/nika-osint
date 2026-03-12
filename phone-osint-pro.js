#!/usr/bin/env node

const { exec } = require('child_process');
const { promisify } = require('util');
const execAsync = promisify(exec);
const fs = require('fs');

// ============================================
// PHONE OSINT PRO - Advanced Phone Number Intelligence
// ============================================

const COUNTRY_CODES = {
  '1': 'US/Canada',
  '7': 'Russia/Kazakhstan',
  '20': 'Egypt',
  '27': 'South Africa',
  '30': 'Greece',
  '31': 'Netherlands',
  '32': 'Belgium',
  '33': 'France',
  '34': 'Spain',
  '36': 'Hungary',
  '39': 'Italy',
  '40': 'Romania',
  '41': 'Switzerland',
  '43': 'Austria',
  '44': 'UK',
  '45': 'Denmark',
  '46': 'Sweden',
  '47': 'Norway',
  '48': 'Poland',
  '49': 'Germany',
  '51': 'Peru',
  '52': 'Mexico',
  '53': 'Cuba',
  '54': 'Argentina',
  '55': 'Brazil',
  '56': 'Chile',
  '57': 'Colombia',
  '58': 'Venezuela',
  '60': 'Malaysia',
  '61': 'Australia',
  '62': 'Indonesia',
  '63': 'Philippines',
  '64': 'New Zealand',
  '65': 'Singapore',
  '66': 'Thailand',
  '81': 'Japan',
  '82': 'South Korea',
  '84': 'Vietnam',
  '86': 'China',
  '90': 'Turkey',
  '91': 'India',
  '92': 'Pakistan',
  '93': 'Afghanistan',
  '94': 'Sri Lanka',
  '95': 'Myanmar',
  '98': 'Iran',
  '212': 'Morocco',
  '213': 'Algeria',
  '216': 'Tunisia',
  '218': 'Libya',
  '220': 'Gambia',
  '221': 'Senegal',
  '223': 'Mali',
  '224': 'Guinea',
  '225': 'Ivory Coast',
  '226': 'Burkina Faso',
  '227': 'Niger',
  '228': 'Togo',
  '229': 'Benin',
  '230': 'Mauritius',
  '231': 'Liberia',
  '232': 'Sierra Leone',
  '233': 'Ghana',
  '234': 'Nigeria',
  '235': 'Chad',
  '236': 'CAR',
  '237': 'Cameroon',
  '238': 'Cape Verde',
  '239': 'Sao Tome',
  '240': 'Equatorial Guinea',
  '241': 'Gabon',
  '242': 'Congo',
  '243': 'DR Congo',
  '244': 'Angola',
  '245': 'Guinea-Bissau',
  '246': 'Diego Garcia',
  '248': 'Seychelles',
  '249': 'Sudan',
  '250': 'Rwanda',
  '251': 'Ethiopia',
  '252': 'Somalia',
  '253': 'Djibouti',
  '254': 'Kenya',
  '255': 'Tanzania',
  '256': 'Uganda',
  '257': 'Burundi',
  '258': 'Mozambique',
  '260': 'Zambia',
  '261': 'Madagascar',
  '262': 'Reunion',
  '263': 'Zimbabwe',
  '264': 'Namibia',
  '265': 'Malawi',
  '266': 'Lesotho',
  '267': 'Botswana',
  '268': 'Swaziland',
  '269': 'Comoros',
  '290': 'Saint Helena',
  '291': 'Eritrea',
  '297': 'Aruba',
  '298': 'Faroe Islands',
  '299': 'Greenland',
  '350': 'Gibraltar',
  '351': 'Portugal',
  '352': 'Luxembourg',
  '353': 'Ireland',
  '354': 'Iceland',
  '355': 'Albania',
  '356': 'Malta',
  '357': 'Cyprus',
  '358': 'Finland',
  '359': 'Bulgaria',
  '370': 'Lithuania',
  '371': 'Latvia',
  '372': 'Estonia',
  '373': 'Moldova',
  '374': 'Armenia',
  '375': 'Belarus',
  '376': 'Andorra',
  '377': 'Monaco',
  '378': 'San Marino',
  '380': 'Ukraine',
  '381': 'Serbia',
  '382': 'Montenegro',
  '383': 'Kosovo',
  '385': 'Croatia',
  '386': 'Slovenia',
  '387': 'Bosnia',
  '389': 'Macedonia',
  '420': 'Czech Republic',
  '421': 'Slovakia',
  '423': 'Liechtenstein',
  '500': 'Falkland Islands',
  '501': 'Belize',
  '502': 'Guatemala',
  '503': 'El Salvador',
  '504': 'Honduras',
  '505': 'Nicaragua',
  '506': 'Costa Rica',
  '507': 'Panama',
  '508': 'St Pierre',
  '509': 'Haiti',
  '590': 'Guadeloupe',
  '591': 'Bolivia',
  '592': 'Guyana',
  '593': 'Ecuador',
  '594': 'French Guiana',
  '595': 'Paraguay',
  '596': 'Martinique',
  '597': 'Suriname',
  '598': 'Uruguay',
  '599': 'Netherlands Antilles',
  '670': 'East Timor',
  '672': 'Antarctica',
  '673': 'Brunei',
  '674': 'Nauru',
  '675': 'Papua New Guinea',
  '676': 'Tonga',
  '677': 'Solomon Islands',
  '678': 'Vanuatu',
  '679': 'Fiji',
  '680': 'Palau',
  '681': 'Wallis and Futuna',
  '682': 'Cook Islands',
  '683': 'Niue',
  '685': 'Samoa',
  '686': 'Kiribati',
  '687': 'New Caledonia',
  '688': 'Tuvalu',
  '689': 'French Polynesia',
  '690': 'Tokelau',
  '691': 'Micronesia',
  '692': 'Marshall Islands',
  '850': 'North Korea',
  '852': 'Hong Kong',
  '853': 'Macau',
  '855': 'Cambodia',
  '856': 'Laos',
  '880': 'Bangladesh',
  '886': 'Taiwan',
  '960': 'Maldives',
  '961': 'Lebanon',
  '962': 'Jordan',
  '963': 'Syria',
  '964': 'Iraq',
  '965': 'Kuwait',
  '966': 'Saudi Arabia',
  '967': 'Yemen',
  '968': 'Oman',
  '970': 'Palestine',
  '971': 'UAE',
  '972': 'Israel',
  '973': 'Bahrain',
  '974': 'Qatar',
  '975': 'Bhutan',
  '976': 'Mongolia',
  '977': 'Nepal',
  '992': 'Tajikistan',
  '993': 'Turkmenistan',
  '994': 'Azerbaijan',
  '995': 'Georgia',
  '996': 'Kyrgyzstan',
  '998': 'Uzbekistan'
};

function parsePhoneNumber(phone) {
  // Remove all non-digit characters
  let cleaned = phone.replace(/\D/g, '');
  
  // Remove leading + if present
  if (phone.startsWith('+')) {
    cleaned = cleaned;
  }
  
  const result = {
    original: phone,
    e164: '+' + cleaned,
    digits: cleaned,
    country: null,
    countryCode: null,
    localNumber: null,
    isValid: false
  };
  
  // Try to match country code
  for (let i = 4; i >= 1; i--) {
    const code = cleaned.substring(0, i);
    if (COUNTRY_CODES[code]) {
      result.country = COUNTRY_CODES[code];
      result.countryCode = code;
      result.localNumber = cleaned.substring(i);
      result.isValid = true;
      break;
    }
  }
  
  return result;
}

function determineNumberType(parsed) {
  const local = parsed.localNumber || '';
  
  // This is a simplified heuristic
  if (local.length >= 10) {
    return {
      type: 'Mobile',
      confidence: 'Medium',
      note: 'Based on length analysis'
    };
  } else if (local.length >= 7) {
    return {
      type: 'Landline/Mobile',
      confidence: 'Low',
      note: 'Could be either type'
    };
  } else {
    return {
      type: 'Unknown',
      confidence: 'Very Low',
      note: 'Number too short'
    };
  }
}

async function checkNumverify(phone) {
  try {
    console.log('   Checking Numverify API...');
    
    const apiKey = process.env.NUMVERIFY_API_KEY || 'free';
    const url = `http://apilayer.net/api/validate?access_key=${apiKey}&number=${encodeURIComponent(phone)}`;
    
    const { stdout } = await execAsync(`curl -s "${url}"`, { timeout: 10000 });
    const data = JSON.parse(stdout);
    
    if (data.valid) {
      return {
        available: true,
        valid: true,
        country: data.country_name,
        countryCode: data.country_code,
        carrier: data.carrier,
        lineType: data.line_type,
        location: data.location
      };
    }
    
    return {
      available: true,
      valid: false
    };
  } catch (error) {
    return {
      available: false,
      error: error.message,
      note: 'Set NUMVERIFY_API_KEY for full features'
    };
  }
}

function checkWhatsApp(phone) {
  // WhatsApp uses E.164 format
  return {
    possible: true,
    checkUrl: `https://wa.me/${phone.replace(/\D/g, '')}`,
    note: 'Open this URL to check if number is on WhatsApp'
  };
}

function checkTelegram(phone) {
  return {
    possible: true,
    checkUrl: `https://t.me/+${phone.replace(/\D/g, '')}`,
    note: 'Open this URL in Telegram to check presence'
  };
}

function checkTruecaller(phone) {
  return {
    available: true,
    searchUrl: `https://www.truecaller.com/search/${encodeURIComponent(phone)}`,
    note: 'Manual check required - search on Truecaller website'
  };
}

function checkSignal(phone) {
  return {
    possible: true,
    note: 'Signal requires app to check - cannot verify remotely',
    suggestion: 'Add number in Signal app to check if registered'
  };
}

function generateGoogleDorks(phone) {
  const cleaned = phone.replace(/\D/g, '');
  const formatted = phone;
  
  return [
    `"${formatted}"`,
    `"${cleaned}"`,
    `"${formatted}" site:facebook.com`,
    `"${formatted}" site:linkedin.com`,
    `"${formatted}" site:twitter.com`,
    `"${formatted}" site:instagram.com`,
    `"${cleaned}" site:truecaller.com`,
    `"${formatted}" "email" OR "contact"`,
    `"${formatted}" filetype:pdf`,
    `"${formatted}" filetype:doc OR filetype:docx`
  ];
}

function generateSocialSearches(phone) {
  const cleaned = phone.replace(/\D/g, '');
  
  return {
    facebook: `https://www.facebook.com/search/top/?q=${encodeURIComponent(phone)}`,
    linkedin: `https://www.linkedin.com/search/results/all/?keywords=${encodeURIComponent(phone)}`,
    twitter: `https://twitter.com/search?q=${encodeURIComponent(phone)}`,
    instagram: `https://www.instagram.com/explore/tags/${cleaned}/`,
    truecaller: `https://www.truecaller.com/search/${encodeURIComponent(phone)}`,
    sync: `https://www.sync.me/search/?query=${cleaned}`
  };
}

function showBanner() {
  console.log("\x1b[31m");
  console.log("██████╗ ██╗  ██╗ ██████╗ ███╗   ██╗███████╗     ██████╗ ███████╗██╗███╗   ██╗████████╗");
  console.log("██╔══██╗██║  ██║██╔═══██╗████╗  ██║██╔════╝    ██╔═══██╗██╔════╝██║████╗  ██║╚══██╔══╝");
  console.log("██████╔╝███████║██║   ██║██╔██╗ ██║█████╗      ██║   ██║███████╗██║██╔██╗ ██║   ██║   ");
  console.log("██╔═══╝ ██╔══██║██║   ██║██║╚██╗██║██╔══╝      ██║   ██║╚════██║██║██║╚██╗██║   ██║   ");
  console.log("██║     ██║  ██║╚██████╔╝██║ ╚████║███████╗    ╚██████╔╝███████║██║██║ ╚████║   ██║   ");
  console.log("╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝     ╚═════╝ ╚══════╝╚═╝╚═╝  ╚═══╝   ╚═╝   ");
  console.log("\x1b[0m");
  console.log("\x1b[35m🥝 NIKA Phone OSINT Pro - Advanced Phone Intelligence\x1b[0m");
  console.log("\x1b[33m⚠️  For authorized investigation only\x1b[0m\n");
}

function displayResults(data) {
  console.log("\n╔════════════════════════════════════════════════════════╗");
  console.log("║       📞 PHONE OSINT RESULTS 📞                        ║");
  console.log("╚════════════════════════════════════════════════════════╝\n");
  
  console.log(`📱 Phone Number: \x1b[36m${data.phone}\x1b[0m\n`);
  
  // Parsing Results
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
  console.log("\x1b[36m🔍 NUMBER ANALYSIS\x1b[0m");
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
  
  console.log(`   E.164 Format: ${data.parsed.e164}`);
  console.log(`   Country: ${data.parsed.country || 'Unknown'}`);
  console.log(`   Country Code: +${data.parsed.countryCode || 'Unknown'}`);
  console.log(`   Local Number: ${data.parsed.localNumber || 'Unknown'}`);
  console.log(`   Valid: ${data.parsed.isValid ? '\x1b[32mYes\x1b[0m' : '\x1b[31mNo\x1b[0m'}\n`);
  
  // Number Type
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
  console.log("\x1b[36m📋 NUMBER TYPE\x1b[0m");
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
  
  console.log(`   Type: ${data.numberType.type}`);
  console.log(`   Confidence: ${data.numberType.confidence}`);
  console.log(`   Note: ${data.numberType.note}\n`);
  
  // API Results
  if (data.numverify) {
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
    console.log("\x1b[36m🌐 NUMVERIFY API\x1b[0m");
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
    
    if (data.numverify.valid) {
      console.log(`   Valid: \x1b[32mYes\x1b[0m`);
      console.log(`   Country: ${data.numverify.country || 'N/A'}`);
      console.log(`   Carrier: ${data.numverify.carrier || 'N/A'}`);
      console.log(`   Line Type: ${data.numverify.lineType || 'N/A'}`);
      console.log(`   Location: ${data.numverify.location || 'N/A'}`);
    } else {
      console.log(`   ${data.numverify.note || 'No data available'}`);
    }
    console.log('');
  }
  
  // Messaging Apps
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
  console.log("\x1b[36m💬 MESSAGING APPS\x1b[0m");
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
  
  console.log(`   WhatsApp:`);
  console.log(`   ${data.whatsapp.checkUrl}`);
  console.log(`   ${data.whatsapp.note}\n`);
  
  console.log(`   Telegram:`);
  console.log(`   ${data.telegram.checkUrl}`);
  console.log(`   ${data.telegram.note}\n`);
  
  console.log(`   Signal:`);
  console.log(`   ${data.signal.note}`);
  console.log(`   ${data.signal.suggestion}\n`);
  
  // Truecaller
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
  console.log("\x1b[36m🔍 TRUECALLER\x1b[0m");
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
  
  console.log(`   ${data.truecaller.searchUrl}`);
  console.log(`   ${data.truecaller.note}\n`);
  
  // Social Media
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
  console.log("\x1b[36m📱 SOCIAL MEDIA SEARCHES\x1b[0m");
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
  
  Object.entries(data.socialSearches).forEach(([platform, url]) => {
    console.log(`   ${platform.charAt(0).toUpperCase() + platform.slice(1)}: ${url}`);
  });
  console.log('');
  
  // Google Dorks
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
  console.log("\x1b[36m🔍 GOOGLE DORKS\x1b[0m");
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
  
  data.googleDorks.slice(0, 5).forEach((dork, i) => {
    console.log(`   ${i + 1}. ${dork}`);
  });
  console.log(`   ... and ${data.googleDorks.length - 5} more (see report file)\n`);
}

function saveResults(data) {
  const dir = './phone-osint-reports';
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, -5);
  const phoneSafe = data.phone.replace(/\D/g, '');
  const jsonFile = `${dir}/${phoneSafe}-${timestamp}.json`;
  const txtFile = jsonFile.replace('.json', '.txt');
  
  fs.writeFileSync(jsonFile, JSON.stringify(data, null, 2));
  
  let txtContent = `═══════════════════════════════════════════════════════════
PHONE OSINT PRO REPORT
═══════════════════════════════════════════════════════════

Phone Number: ${data.phone}
Date: ${new Date(data.timestamp).toLocaleString()}

═══════════════════════════════════════════════════════════
NUMBER ANALYSIS
═══════════════════════════════════════════════════════════

E.164 Format: ${data.parsed.e164}
Country: ${data.parsed.country || 'Unknown'}
Country Code: +${data.parsed.countryCode || 'Unknown'}
Local Number: ${data.parsed.localNumber || 'Unknown'}
Valid: ${data.parsed.isValid ? 'Yes' : 'No'}

Number Type: ${data.numberType.type}
Confidence: ${data.numberType.confidence}
Note: ${data.numberType.note}

═══════════════════════════════════════════════════════════
MESSAGING APPS
═══════════════════════════════════════════════════════════

WhatsApp:
${data.whatsapp.checkUrl}
${data.whatsapp.note}

Telegram:
${data.telegram.checkUrl}
${data.telegram.note}

Signal:
${data.signal.note}
${data.signal.suggestion}

═══════════════════════════════════════════════════════════
TRUECALLER
═══════════════════════════════════════════════════════════

${data.truecaller.searchUrl}
${data.truecaller.note}

═══════════════════════════════════════════════════════════
SOCIAL MEDIA SEARCHES
═══════════════════════════════════════════════════════════

`;

  Object.entries(data.socialSearches).forEach(([platform, url]) => {
    txtContent += `${platform.charAt(0).toUpperCase() + platform.slice(1)}: ${url}\n`;
  });
  
  txtContent += `\n═══════════════════════════════════════════════════════════
GOOGLE DORKS
═══════════════════════════════════════════════════════════\n\n`;

  data.googleDorks.forEach((dork, i) => {
    txtContent += `${i + 1}. ${dork}\n`;
  });
  
  fs.writeFileSync(txtFile, txtContent);
  
  console.log(`\x1b[32m✅ Results saved:\x1b[0m`);
  console.log(`   JSON: ${jsonFile}`);
  console.log(`   TXT: ${txtFile}\n`);
}

function showHelp() {
  showBanner();
  
  console.log("Usage: node phone-osint-pro.js [OPTIONS] <phone-number>\n");
  console.log("Options:");
  console.log("  --save           Save results to file");
  console.log("  --help           Show this help\n");
  
  console.log("Phone Number Format:");
  console.log("  +1234567890");
  console.log("  +44 20 1234 5678");
  console.log("  (123) 456-7890\n");
  
  console.log("Environment Variables:");
  console.log("  NUMVERIFY_API_KEY    Numverify API key (optional)\n");
  
  console.log("Examples:");
  console.log("  node phone-osint-pro.js +1234567890");
  console.log("  node phone-osint-pro.js \"+44 20 1234 5678\" --save\n");
}

async function main() {
  const args = process.argv.slice(2);
  
  if (args.includes('--help') || args.length === 0) {
    showHelp();
    process.exit(0);
  }
  
  let phone = null;
  let saveResults_flag = false;
  
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--save') {
      saveResults_flag = true;
    } else if (!args[i].startsWith('--')) {
      phone = args[i];
    }
  }
  
  if (!phone) {
    console.log("\x1b[31m❌ No phone number specified!\x1b[0m\n");
    showHelp();
    process.exit(1);
  }
  
  showBanner();
  
  console.log(`⏳ Analyzing phone number: ${phone}...\n`);
  
  const results = {
    phone: phone,
    timestamp: new Date().toISOString(),
    parsed: parsePhoneNumber(phone),
    numberType: null,
    numverify: null,
    whatsapp: null,
    telegram: null,
    signal: null,
    truecaller: null,
    socialSearches: null,
    googleDorks: null
  };
  
  results.numberType = determineNumberType(results.parsed);
  results.numverify = await checkNumverify(phone);
  results.whatsapp = checkWhatsApp(phone);
  results.telegram = checkTelegram(phone);
  results.signal = checkSignal(phone);
  results.truecaller = checkTruecaller(phone);
  results.socialSearches = generateSocialSearches(phone);
  results.googleDorks = generateGoogleDorks(phone);
  
  displayResults(results);
  
  if (saveResults_flag) {
    saveResults(results);
  }
  
  console.log("\x1b[31m██████╗ ██╗  ██╗ ██████╗ ███╗   ██╗███████╗\x1b[0m");
  console.log("\x1b[35m🥝 Analysis complete - by kiwi & 777\x1b[0m\n");
}

main().catch(console.error);
