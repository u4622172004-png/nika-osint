#!/usr/bin/env node

const fs = require('fs');
const { exec } = require('child_process');
const { promisify } = require('util');
const execAsync = promisify(exec);

// ============================================
// SECRET LANGUAGE CRACKER - Universal Decoder
// ============================================

const CIPHER_METHODS = {
  base64: {
    name: 'Base64',
    detect: (input) => /^[A-Za-z0-9+/=]+$/.test(input) && input.length % 4 === 0,
    decode: (input) => {
      try {
        return Buffer.from(input, 'base64').toString('utf8');
      } catch (e) {
        return null;
      }
    }
  },
  
  base32: {
    name: 'Base32',
    detect: (input) => /^[A-Z2-7=]+$/.test(input.toUpperCase()),
    decode: (input) => {
      try {
        const base32chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        input = input.toUpperCase().replace(/=+$/, '');
        let bits = 0;
        let value = 0;
        let output = '';
        
        for (let i = 0; i < input.length; i++) {
          value = (value << 5) | base32chars.indexOf(input[i]);
          bits += 5;
          
          if (bits >= 8) {
            output += String.fromCharCode((value >>> (bits - 8)) & 255);
            bits -= 8;
          }
        }
        return output;
      } catch (e) {
        return null;
      }
    }
  },
  
  hex: {
    name: 'Hexadecimal',
    detect: (input) => /^[0-9A-Fa-f\s]+$/.test(input),
    decode: (input) => {
      try {
        const cleaned = input.replace(/\s/g, '');
        if (cleaned.length % 2 !== 0) return null;
        return Buffer.from(cleaned, 'hex').toString('utf8');
      } catch (e) {
        return null;
      }
    }
  },
  
  binary: {
    name: 'Binary',
    detect: (input) => /^[01\s]+$/.test(input),
    decode: (input) => {
      try {
        const cleaned = input.replace(/\s/g, '');
        let output = '';
        for (let i = 0; i < cleaned.length; i += 8) {
          const byte = cleaned.substr(i, 8);
          if (byte.length === 8) {
            output += String.fromCharCode(parseInt(byte, 2));
          }
        }
        return output;
      } catch (e) {
        return null;
      }
    }
  },
  
  morse: {
    name: 'Morse Code',
    detect: (input) => /^[.\-\s/]+$/.test(input),
    decode: (input) => {
      const morseCode = {
        '.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D', '.': 'E',
        '..-.': 'F', '--.': 'G', '....': 'H', '..': 'I', '.---': 'J',
        '-.-': 'K', '.-..': 'L', '--': 'M', '-.': 'N', '---': 'O',
        '.--.': 'P', '--.-': 'Q', '.-.': 'R', '...': 'S', '-': 'T',
        '..-': 'U', '...-': 'V', '.--': 'W', '-..-': 'X', '-.--': 'Y',
        '--..': 'Z', '-----': '0', '.----': '1', '..---': '2', '...--': '3',
        '....-': '4', '.....': '5', '-....': '6', '--...': '7', '---..': '8',
        '----.': '9', '/': ' '
      };
      
      try {
        const words = input.split('/');
        let output = '';
        
        for (let word of words) {
          const letters = word.trim().split(/\s+/);
          for (let letter of letters) {
            if (morseCode[letter]) {
              output += morseCode[letter];
            }
          }
          output += ' ';
        }
        
        return output.trim();
      } catch (e) {
        return null;
      }
    }
  },
  
  rot13: {
    name: 'ROT13',
    detect: () => true,
    decode: (input) => {
      return input.replace(/[a-zA-Z]/g, (char) => {
        const start = char <= 'Z' ? 65 : 97;
        return String.fromCharCode(((char.charCodeAt(0) - start + 13) % 26) + start);
      });
    }
  },
  
  caesar: {
    name: 'Caesar Cipher',
    detect: () => true,
    decode: (input) => {
      const results = [];
      for (let shift = 1; shift < 26; shift++) {
        const decoded = input.replace(/[a-zA-Z]/g, (char) => {
          const start = char <= 'Z' ? 65 : 97;
          return String.fromCharCode(((char.charCodeAt(0) - start + shift) % 26) + start);
        });
        results.push({ shift: shift, text: decoded });
      }
      return results;
    }
  },
  
  reverse: {
    name: 'Reversed Text',
    detect: () => true,
    decode: (input) => input.split('').reverse().join('')
  },
  
  atbash: {
    name: 'Atbash Cipher',
    detect: () => true,
    decode: (input) => {
      return input.replace(/[a-zA-Z]/g, (char) => {
        if (char <= 'Z') {
          return String.fromCharCode(90 - (char.charCodeAt(0) - 65));
        } else {
          return String.fromCharCode(122 - (char.charCodeAt(0) - 97));
        }
      });
    }
  },
  
  url: {
    name: 'URL Encoding',
    detect: (input) => /%[0-9A-Fa-f]{2}/.test(input),
    decode: (input) => {
      try {
        return decodeURIComponent(input);
      } catch (e) {
        return null;
      }
    }
  },
  
  html: {
    name: 'HTML Entities',
    detect: (input) => /&[a-z]+;|&#[0-9]+;/.test(input),
    decode: (input) => {
      const entities = {
        '&lt;': '<', '&gt;': '>', '&amp;': '&', '&quot;': '"',
        '&apos;': "'", '&nbsp;': ' '
      };
      
      let output = input;
      for (let [entity, char] of Object.entries(entities)) {
        output = output.replace(new RegExp(entity, 'g'), char);
      }
      
      output = output.replace(/&#(\d+);/g, (match, code) => {
        return String.fromCharCode(parseInt(code));
      });
      
      return output;
    }
  },
  
  leetspeak: {
    name: 'Leetspeak (1337)',
    detect: (input) => /[0-9]/.test(input),
    decode: (input) => {
      const leet = {
        '0': 'o', '1': 'i', '3': 'e', '4': 'a', '5': 's',
        '7': 't', '8': 'b', '9': 'g'
      };
      
      let output = input.toLowerCase();
      for (let [l, char] of Object.entries(leet)) {
        output = output.replace(new RegExp(l, 'g'), char);
      }
      return output;
    }
  },
  
  bacon: {
    name: 'Bacon Cipher',
    detect: (input) => /^[AB\s]+$/i.test(input),
    decode: (input) => {
      const bacon = {
        'AAAAA': 'A', 'AAAAB': 'B', 'AAABA': 'C', 'AAABB': 'D', 'AABAA': 'E',
        'AABAB': 'F', 'AABBA': 'G', 'AABBB': 'H', 'ABAAA': 'I', 'ABAAB': 'J',
        'ABABA': 'K', 'ABABB': 'L', 'ABBAA': 'M', 'ABBAB': 'N', 'ABBBA': 'O',
        'ABBBB': 'P', 'BAAAA': 'Q', 'BAAAB': 'R', 'BAABA': 'S', 'BAABB': 'T',
        'BABAA': 'U', 'BABAB': 'V', 'BABBA': 'W', 'BABBB': 'X', 'BBAAA': 'Y',
        'BBAAB': 'Z'
      };
      
      try {
        const cleaned = input.toUpperCase().replace(/\s/g, '');
        let output = '';
        
        for (let i = 0; i < cleaned.length; i += 5) {
          const chunk = cleaned.substr(i, 5);
          if (bacon[chunk]) {
            output += bacon[chunk];
          }
        }
        
        return output || null;
      } catch (e) {
        return null;
      }
    }
  },
  
  piglatin: {
    name: 'Pig Latin',
    detect: (input) => /ay\s/i.test(input),
    decode: (input) => {
      try {
        const words = input.split(/\s+/);
        return words.map(word => {
          if (word.toLowerCase().endsWith('ay')) {
            const base = word.slice(0, -2);
            if (base.length > 0) {
              const firstChar = base.charAt(base.length - 1);
              const rest = base.slice(0, -1);
              return firstChar + rest;
            }
          }
          return word;
        }).join(' ');
      } catch (e) {
        return null;
      }
    }
  }
};

function detectType(input) {
  const detected = [];
  
  for (let [type, method] of Object.entries(CIPHER_METHODS)) {
    if (method.detect(input)) {
      detected.push(type);
    }
  }
  
  return detected;
}

function analyzeText(text) {
  const analysis = {
    length: text.length,
    hasLetters: /[a-zA-Z]/.test(text),
    hasNumbers: /[0-9]/.test(text),
    hasSpecial: /[^a-zA-Z0-9\s]/.test(text),
    entropy: calculateEntropy(text),
    isReadable: isReadableText(text),
    language: 'unknown'
  };
  
  return analysis;
}

function calculateEntropy(text) {
  const freq = {};
  for (let char of text) {
    freq[char] = (freq[char] || 0) + 1;
  }
  
  let entropy = 0;
  const len = text.length;
  
  for (let count of Object.values(freq)) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  
  return entropy.toFixed(2);
}

function isReadableText(text) {
  // Check if text contains common English words
  const commonWords = ['the', 'be', 'to', 'of', 'and', 'a', 'in', 'that', 'have', 'i'];
  const lowerText = text.toLowerCase();
  
  for (let word of commonWords) {
    if (lowerText.includes(word)) {
      return true;
    }
  }
  
  // Check if mostly alphanumeric
  const alphanumeric = text.replace(/[^a-zA-Z0-9]/g, '').length;
  return (alphanumeric / text.length) > 0.7;
}

function identifyHash(input) {
  const hashTypes = {
    32: ['MD5', 'MD4', 'MD2', 'NTLM'],
    40: ['SHA-1', 'RIPEMD-160'],
    56: ['SHA-224'],
    64: ['SHA-256', 'SHA3-256', 'BLAKE2s'],
    96: ['SHA-384'],
    128: ['SHA-512', 'SHA3-512', 'BLAKE2b']
  };
  
  const cleaned = input.replace(/\s/g, '');
  
  if (/^[0-9a-fA-F]+$/.test(cleaned)) {
    const len = cleaned.length;
    if (hashTypes[len]) {
      return {
        isHash: true,
        possibleTypes: hashTypes[len],
        length: len,
        crackTools: ['hashcat', 'john', 'rainbow tables']
      };
    }
  }
  
  return { isHash: false };
}

async function deepDecode(input, maxDepth = 3) {
  const layers = [{ layer: 0, type: 'original', text: input }];
  let current = input;
  
  for (let depth = 1; depth <= maxDepth; depth++) {
    let decoded = null;
    let decodedType = null;
    
    // Try each decoder
    for (let [type, method] of Object.entries(CIPHER_METHODS)) {
      if (type === 'caesar') continue; // Skip multi-result decoders
      
      if (method.detect(current)) {
        const result = method.decode(current);
        if (result && result !== current && isReadableText(result)) {
          decoded = result;
          decodedType = type;
          break;
        }
      }
    }
    
    if (decoded) {
      layers.push({ layer: depth, type: decodedType, text: decoded });
      current = decoded;
    } else {
      break;
    }
  }
  
  return layers;
}

function showBanner() {
  console.log("\x1b[31m");
  console.log("███████╗███████╗ ██████╗██████╗ ███████╗████████╗    ██╗      █████╗ ███╗   ██╗ ██████╗ ");
  console.log("██╔════╝██╔════╝██╔════╝██╔══██╗██╔════╝╚══██╔══╝    ██║     ██╔══██╗████╗  ██║██╔════╝ ");
  console.log("███████╗█████╗  ██║     ██████╔╝█████╗     ██║       ██║     ███████║██╔██╗ ██║██║  ███╗");
  console.log("╚════██║██╔══╝  ██║     ██╔══██╗██╔══╝     ██║       ██║     ██╔══██║██║╚██╗██║██║   ██║");
  console.log("███████║███████╗╚██████╗██║  ██║███████╗   ██║       ███████╗██║  ██║██║ ╚████║╚██████╔╝");
  console.log("╚══════╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚══════╝   ╚═╝       ╚══════╝╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝ ");
  console.log("                                                                                          ");
  console.log(" ██████╗██████╗  █████╗  ██████╗██╗  ██╗███████╗██████╗                                 ");
  console.log("██╔════╝██╔══██╗██╔══██╗██╔════╝██║ ██╔╝██╔════╝██╔══██╗                                ");
  console.log("██║     ██████╔╝███████║██║     █████╔╝ █████╗  ██████╔╝                                ");
  console.log("██║     ██╔══██╗██╔══██║██║     ██╔═██╗ ██╔══╝  ██╔══██╗                                ");
  console.log("╚██████╗██║  ██║██║  ██║╚██████╗██║  ██╗███████╗██║  ██║                                ");
  console.log(" ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝                                ");
  console.log("\x1b[0m");
  console.log("\x1b[35m🥝 NIKA Secret Language Cracker - Universal Decoder\x1b[0m");
  console.log("\x1b[33m⚠️  For CTF, forensics, and authorized decryption only\x1b[0m\n");
}

function displayResults(data) {
  console.log("\n╔════════════════════════════════════════════════════════╗");
  console.log("║       🔓 DECRYPTION RESULTS 🔓                         ║");
  console.log("╚════════════════════════════════════════════════════════╝\n");
  
  console.log(`📝 Input: \x1b[36m${data.input.substring(0, 100)}${data.input.length > 100 ? '...' : ''}\x1b[0m`);
  console.log(`📊 Length: ${data.input.length} characters\n`);
  
  // Hash check
  if (data.hashCheck.isHash) {
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
    console.log("\x1b[36m🔐 HASH IDENTIFIED\x1b[0m");
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
    
    console.log(`   Possible Types: ${data.hashCheck.possibleTypes.join(', ')}`);
    console.log(`   Length: ${data.hashCheck.length} characters`);
    console.log(`   Crack Tools: ${data.hashCheck.crackTools.join(', ')}\n`);
  }
  
  // Detected types
  if (data.detectedTypes.length > 0) {
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
    console.log("\x1b[36m🔍 DETECTED ENCODINGS\x1b[0m");
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
    
    data.detectedTypes.forEach(type => {
      console.log(`   • ${CIPHER_METHODS[type].name}`);
    });
    console.log('');
  }
  
  // Successful decodes
  if (data.successful.length > 0) {
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
    console.log("\x1b[36m✅ SUCCESSFUL DECODES\x1b[0m");
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
    
    data.successful.forEach((result, i) => {
      console.log(`   ${i + 1}. \x1b[32m${result.method}\x1b[0m`);
      console.log(`      Result: ${result.result.substring(0, 200)}${result.result.length > 200 ? '...' : ''}`);
      console.log(`      Readable: ${result.analysis.isReadable ? '\x1b[32mYes\x1b[0m' : '\x1b[31mNo\x1b[0m'}`);
      console.log(`      Entropy: ${result.analysis.entropy}\n`);
    });
  }
  
  // Caesar cipher results
  if (data.caesar && data.caesar.length > 0) {
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
    console.log("\x1b[36m🔄 CAESAR CIPHER (All Shifts)\x1b[0m");
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
    
    const readableShifts = data.caesar.filter(r => isReadableText(r.text));
    
    if (readableShifts.length > 0) {
      console.log(`   Found ${readableShifts.length} potentially readable shift(s):\n`);
      readableShifts.forEach(result => {
        console.log(`   Shift ${result.shift}: ${result.text.substring(0, 100)}`);
      });
    } else {
      console.log(`   Showing first 5 shifts:\n`);
      data.caesar.slice(0, 5).forEach(result => {
        console.log(`   Shift ${result.shift}: ${result.text.substring(0, 80)}`);
      });
    }
    console.log('');
  }
  
  // Deep decode layers
  if (data.deepDecode && data.deepDecode.length > 1) {
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
    console.log("\x1b[36m🎯 MULTI-LAYER DECODE\x1b[0m");
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
    
    data.deepDecode.forEach(layer => {
      console.log(`   Layer ${layer.layer} [${layer.type}]:`);
      console.log(`   ${layer.text.substring(0, 150)}${layer.text.length > 150 ? '...' : ''}\n`);
    });
  }
  
  // Best guess
  if (data.bestGuess) {
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
    console.log("\x1b[36m🎯 BEST GUESS\x1b[0m");
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
    
    console.log(`   Method: \x1b[32m${data.bestGuess.method}\x1b[0m`);
    console.log(`   Result: ${data.bestGuess.result}\n`);
  }
}

function saveResults(data) {
  const dir = './secret-language-reports';
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, -5);
  const inputHash = require('crypto').createHash('md5').update(data.input).digest('hex').substring(0, 8);
  const jsonFile = `${dir}/decode-${inputHash}-${timestamp}.json`;
  const txtFile = jsonFile.replace('.json', '.txt');
  
  fs.writeFileSync(jsonFile, JSON.stringify(data, null, 2));
  
  let txtContent = `═══════════════════════════════════════════════════════════
SECRET LANGUAGE CRACKER REPORT
═══════════════════════════════════════════════════════════

Input: ${data.input}
Length: ${data.input.length} characters
Date: ${new Date(data.timestamp).toLocaleString()}

`;

  if (data.hashCheck.isHash) {
    txtContent += `═══════════════════════════════════════════════════════════
HASH IDENTIFIED
═══════════════════════════════════════════════════════════

Possible Types: ${data.hashCheck.possibleTypes.join(', ')}
Length: ${data.hashCheck.length}
Crack Tools: ${data.hashCheck.crackTools.join(', ')}

`;
  }
  
  if (data.detectedTypes.length > 0) {
    txtContent += `═══════════════════════════════════════════════════════════
DETECTED ENCODINGS
═══════════════════════════════════════════════════════════

${data.detectedTypes.map(t => `• ${CIPHER_METHODS[t].name}`).join('\n')}

`;
  }
  
  if (data.successful.length > 0) {
    txtContent += `═══════════════════════════════════════════════════════════
SUCCESSFUL DECODES
═══════════════════════════════════════════════════════════\n\n`;

    data.successful.forEach((result, i) => {
      txtContent += `${i + 1}. ${result.method}\n`;
      txtContent += `Result: ${result.result}\n`;
      txtContent += `Readable: ${result.analysis.isReadable}\n`;
      txtContent += `Entropy: ${result.analysis.entropy}\n\n`;
    });
  }
  
  if (data.caesar) {
    txtContent += `═══════════════════════════════════════════════════════════
CAESAR CIPHER (ALL SHIFTS)
═══════════════════════════════════════════════════════════\n\n`;

    data.caesar.forEach(result => {
      txtContent += `Shift ${result.shift}: ${result.text}\n`;
    });
    txtContent += '\n';
  }
  
  fs.writeFileSync(txtFile, txtContent);
  
  console.log(`\x1b[32m✅ Results saved:\x1b[0m`);
  console.log(`   JSON: ${jsonFile}`);
  console.log(`   TXT: ${txtFile}\n`);
}

function showHelp() {
  showBanner();
  
  console.log("Usage: node secret-language-cracker.js [OPTIONS] <input>\n");
  console.log("Options:");
  console.log("  --all            Try all decoding methods");
  console.log("  --deep           Multi-layer decode (max 3 layers)");
  console.log("  --caesar         Show all Caesar cipher shifts");
  console.log("  --method <type>  Use specific method only");
  console.log("  --save           Save results to file");
  console.log("  --list           List all available methods");
  console.log("  --help           Show this help\n");
  
  console.log("Examples:");
  console.log("  node secret-language-cracker.js 'SGVsbG8gV29ybGQ='");
  console.log("  node secret-language-cracker.js 'Uryyb Jbeyq' --all");
  console.log("  node secret-language-cracker.js '.... . .-.. .-.. ---' --method morse");
  console.log("  node secret-language-cracker.js 'encoded text' --deep --save\n");
}

async function main() {
  const args = process.argv.slice(2);
  
  if (args.includes('--help') || args.length === 0) {
    showHelp();
    process.exit(0);
  }
  
  if (args.includes('--list')) {
    showBanner();
    console.log("Available Decoding Methods:\n");
    Object.entries(CIPHER_METHODS).forEach(([key, method]) => {
      console.log(`  \x1b[32m${method.name}\x1b[0m (${key})`);
    });
    console.log('');
    process.exit(0);
  }
  
  let input = null;
  let tryAll = false;
  let tryDeep = false;
  let showCaesar = false;
  let specificMethod = null;
  let saveResults_flag = false;
  
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--all') {
      tryAll = true;
    } else if (args[i] === '--deep') {
      tryDeep = true;
    } else if (args[i] === '--caesar') {
         showCaesar = true;
    } else if (args[i] === '--method') {
      specificMethod = args[i + 1];
      i++;
    } else if (args[i] === '--save') {
      saveResults_flag = true;
    } else if (!args[i].startsWith('--')) {
      input = args[i];
    }
  }
  
  if (!input) {
    console.log("\x1b[31m❌ No input specified!\x1b[0m\n");
    showHelp();
    process.exit(1);
  }
  
  showBanner();
  
  console.log(`⏳ Analyzing input...\n`);
  
  const results = {
    input: input,
    timestamp: new Date().toISOString(),
    detectedTypes: detectType(input),
    hashCheck: identifyHash(input),
    successful: [],
    caesar: null,
    deepDecode: null,
    bestGuess: null
  };
  
  // Try specific method
  if (specificMethod && CIPHER_METHODS[specificMethod]) {
    const method = CIPHER_METHODS[specificMethod];
    const decoded = method.decode(input);
    
    if (decoded) {
      if (Array.isArray(decoded)) {
        results.caesar = decoded;
      } else {
        results.successful.push({
          method: method.name,
          result: decoded,
          analysis: analyzeText(decoded)
        });
      }
    }
  }
  // Try all methods
  else {
    for (let [type, method] of Object.entries(CIPHER_METHODS)) {
      if (type === 'caesar' && !showCaesar) continue;
      
      const decoded = method.decode(input);
      
      if (decoded) {
        if (Array.isArray(decoded)) {
          if (showCaesar) {
            results.caesar = decoded;
          }
        } else if (decoded !== input) {
          results.successful.push({
            method: method.name,
            result: decoded,
            analysis: analyzeText(decoded)
          });
        }
      }
    }
  }
  
  // Deep decode
  if (tryDeep) {
    results.deepDecode = await deepDecode(input);
  }
  
  // Find best guess (most readable)
  if (results.successful.length > 0) {
    results.bestGuess = results.successful
      .filter(r => r.analysis.isReadable)
      .sort((a, b) => b.analysis.entropy - a.analysis.entropy)[0] || results.successful[0];
  }
  
  displayResults(results);
  
  if (saveResults_flag) {
    saveResults(results);
  }
  
  console.log("\x1b[31m███████╗███████╗ ██████╗██████╗ ███████╗████████╗\x1b[0m");
  console.log("\x1b[35m🥝 Decryption complete - by kiwi & 777\x1b[0m\n");
}

main().catch(console.error);
