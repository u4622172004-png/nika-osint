#!/usr/bin/env node

const { exec } = require('child_process');
const { promisify } = require('util');
const execAsync = promisify(exec);
const fs = require('fs');

// ============================================
// CRYPTO TRACKER - Cryptocurrency Investigation
// ============================================

async function checkBitcoinAddress(address) {
  try {
    console.log('   Checking Bitcoin address...');
    
    // Using blockchain.info API
    const url = `https://blockchain.info/rawaddr/${address}`;
    const { stdout } = await execAsync(`curl -s "${url}"`, { timeout: 10000 });
    
    const data = JSON.parse(stdout);
    
    return {
      available: true,
      address: address,
      balance: data.final_balance / 100000000, // Convert satoshis to BTC
      totalReceived: data.total_received / 100000000,
      totalSent: data.total_sent / 100000000,
      transactions: data.n_tx,
      firstSeen: data.txs && data.txs.length > 0 ? new Date(data.txs[data.txs.length - 1].time * 1000).toISOString() : null,
      lastActivity: data.txs && data.txs.length > 0 ? new Date(data.txs[0].time * 1000).toISOString() : null,
      recentTxs: data.txs ? data.txs.slice(0, 5).map(tx => ({
        hash: tx.hash,
        time: new Date(tx.time * 1000).toISOString(),
        value: tx.result / 100000000,
        fee: tx.fee / 100000000
      })) : []
    };
  } catch (error) {
    return {
      available: false,
      error: error.message,
      address: address
    };
  }
}

async function checkEthereumAddress(address) {
  try {
    console.log('   Checking Ethereum address...');
    
    // Using Etherscan API (public endpoint - limited)
    const url = `https://api.etherscan.io/api?module=account&action=balance&address=${address}&tag=latest`;
    const { stdout } = await execAsync(`curl -s "${url}"`, { timeout: 10000 });
    
    const data = JSON.parse(stdout);
    
    if (data.status === '1') {
      const balance = parseInt(data.result) / 1e18; // Convert wei to ETH
      
      return {
        available: true,
        address: address,
        balance: balance,
        explorer: `https://etherscan.io/address/${address}`
      };
    }
    
    return {
      available: false,
      error: 'Invalid response from API',
      address: address
    };
  } catch (error) {
    return {
      available: false,
      error: error.message,
      address: address
    };
  }
}

function validateBitcoinAddress(address) {
  // Basic Bitcoin address validation
  const btcRegex = /^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$|^bc1[a-z0-9]{39,59}$/;
  return btcRegex.test(address);
}

function validateEthereumAddress(address) {
  // Basic Ethereum address validation
  const ethRegex = /^0x[a-fA-F0-9]{40}$/;
  return ethRegex.test(address);
}

function detectCryptoType(address) {
  if (validateBitcoinAddress(address)) {
    return 'bitcoin';
  } else if (validateEthereumAddress(address)) {
    return 'ethereum';
  }
  return 'unknown';
}

function showBanner() {
  console.log("\x1b[31m");
  console.log(" ██████╗██████╗ ██╗   ██╗██████╗ ████████╗ ██████╗ ");
  console.log("██╔════╝██╔══██╗╚██╗ ██╔╝██╔══██╗╚══██╔══╝██╔═══██╗");
  console.log("██║     ██████╔╝ ╚████╔╝ ██████╔╝   ██║   ██║   ██║");
  console.log("██║     ██╔══██╗  ╚██╔╝  ██╔═══╝    ██║   ██║   ██║");
  console.log("╚██████╗██║  ██║   ██║   ██║        ██║   ╚██████╔╝");
  console.log(" ╚═════╝╚═╝  ╚═╝   ╚═╝   ╚═╝        ╚═╝    ╚═════╝ ");
  console.log("\x1b[0m");
  console.log("\x1b[35m🥝 NIKA Crypto Tracker - Cryptocurrency Investigation\x1b[0m");
  console.log("\x1b[33m⚠️  For authorized investigation only\x1b[0m\n");
}

function displayResults(data, type) {
  console.log("\n╔════════════════════════════════════════════════════════╗");
  console.log("║       💰 CRYPTOCURRENCY TRACKING RESULTS 💰            ║");
  console.log("╚════════════════════════════════════════════════════════╝\n");
  
  if (!data.available) {
    console.log(`\x1b[31m❌ Failed to retrieve data\x1b[0m`);
    console.log(`   Error: ${data.error}\n`);
    return;
  }
  
  console.log(`💳 Address: \x1b[36m${data.address}\x1b[0m`);
  console.log(`🪙 Type: ${type.toUpperCase()}\n`);
  
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
  console.log("\x1b[36m💵 BALANCE & ACTIVITY\x1b[0m");
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
  
  if (type === 'bitcoin') {
    console.log(`   Current Balance: \x1b[32m${data.balance.toFixed(8)} BTC\x1b[0m`);
    console.log(`   Total Received: ${data.totalReceived.toFixed(8)} BTC`);
    console.log(`   Total Sent: ${data.totalSent.toFixed(8)} BTC`);
    console.log(`   Transactions: ${data.transactions}`);
    
    if (data.firstSeen) {
      console.log(`   First Seen: ${new Date(data.firstSeen).toLocaleString()}`);
    }
    if (data.lastActivity) {
      console.log(`   Last Activity: ${new Date(data.lastActivity).toLocaleString()}`);
    }
    
    if (data.recentTxs && data.recentTxs.length > 0) {
      console.log('\n\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m');
      console.log('\x1b[36m📊 RECENT TRANSACTIONS (Last 5)\x1b[0m');
      console.log('\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n');
      
      data.recentTxs.forEach((tx, i) => {
        console.log(`   ${i + 1}. ${tx.hash.substring(0, 16)}...`);
        console.log(`      Time: ${new Date(tx.time).toLocaleString()}`);
        console.log(`      Value: ${tx.value >= 0 ? '+' : ''}${tx.value.toFixed(8)} BTC`);
        console.log(`      Fee: ${tx.fee.toFixed(8)} BTC\n`);
      });
    }
    
    console.log('\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m');
    console.log('\x1b[36m🔗 EXPLORER LINKS\x1b[0m');
    console.log('\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n');
    console.log(`   Blockchain.com: https://www.blockchain.com/btc/address/${data.address}`);
    console.log(`   Blockchair: https://blockchair.com/bitcoin/address/${data.address}`);
    
  } else if (type === 'ethereum') {
    console.log(`   Current Balance: \x1b[32m${data.balance.toFixed(8)} ETH\x1b[0m\n`);
    
    console.log('\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m');
    console.log('\x1b[36m🔗 EXPLORER LINKS\x1b[0m');
    console.log('\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n');
    console.log(`   Etherscan: ${data.explorer}`);
    console.log(`   Ethplorer: https://ethplorer.io/address/${data.address}`);
  }
  
  console.log('');
}

function saveResults(data, type) {
  const dir = './crypto-tracker-reports';
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, -5);
  const addrShort = data.address.substring(0, 16);
  const jsonFile = `${dir}/${type}-${addrShort}-${timestamp}.json`;
  const txtFile = jsonFile.replace('.json', '.txt');
  
  const fullData = {
    ...data,
    type: type,
    timestamp: new Date().toISOString()
  };
  
  fs.writeFileSync(jsonFile, JSON.stringify(fullData, null, 2));
  
  let txtContent = `═══════════════════════════════════════════════════════════
CRYPTOCURRENCY TRACKING REPORT
═══════════════════════════════════════════════════════════

Address: ${data.address}
Type: ${type.toUpperCase()}
Date: ${new Date().toLocaleString()}

═══════════════════════════════════════════════════════════
BALANCE & ACTIVITY
═══════════════════════════════════════════════════════════

`;

  if (type === 'bitcoin') {
    txtContent += `Current Balance: ${data.balance.toFixed(8)} BTC
Total Received: ${data.totalReceived.toFixed(8)} BTC
Total Sent: ${data.totalSent.toFixed(8)} BTC
Transactions: ${data.transactions}
First Seen: ${data.firstSeen ? new Date(data.firstSeen).toLocaleString() : 'N/A'}
Last Activity: ${data.lastActivity ? new Date(data.lastActivity).toLocaleString() : 'N/A'}

═══════════════════════════════════════════════════════════
RECENT TRANSACTIONS
═══════════════════════════════════════════════════════════

`;
    if (data.recentTxs) {
      data.recentTxs.forEach((tx, i) => {
        txtContent += `${i + 1}. ${tx.hash}
   Time: ${new Date(tx.time).toLocaleString()}
   Value: ${tx.value >= 0 ? '+' : ''}${tx.value.toFixed(8)} BTC
   Fee: ${tx.fee.toFixed(8)} BTC

`;
      });
    }
    
    txtContent += `═══════════════════════════════════════════════════════════
EXPLORER LINKS
═══════════════════════════════════════════════════════════

Blockchain.com: https://www.blockchain.com/btc/address/${data.address}
Blockchair: https://blockchair.com/bitcoin/address/${data.address}
`;
  } else if (type === 'ethereum') {
    txtContent += `Current Balance: ${data.balance.toFixed(8)} ETH

═══════════════════════════════════════════════════════════
EXPLORER LINKS
═══════════════════════════════════════════════════════════

Etherscan: ${data.explorer}
Ethplorer: https://ethplorer.io/address/${data.address}
`;
  }
  
  fs.writeFileSync(txtFile, txtContent);
  
  console.log(`\x1b[32m✅ Results saved:\x1b[0m`);
  console.log(`   JSON: ${jsonFile}`);
  console.log(`   TXT: ${txtFile}\n`);
}

function showHelp() {
  showBanner();
  
  console.log("Usage: node crypto-tracker.js [OPTIONS] <address>\n");
  console.log("Options:");
  console.log("  --type <crypto>   Specify crypto type (bitcoin, ethereum)");
  console.log("  --save            Save results to file");
  console.log("  --help            Show this help\n");
  
  console.log("Supported Cryptocurrencies:");
  console.log("  Bitcoin (BTC)     - Address starts with 1, 3, or bc1");
  console.log("  Ethereum (ETH)    - Address starts with 0x\n");
  
  console.log("Examples:");
  console.log("  node crypto-tracker.js 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa");
  console.log("  node crypto-tracker.js 0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb");
  console.log("  node crypto-tracker.js 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa --save\n");
}

async function main() {
  const args = process.argv.slice(2);
  
  if (args.includes('--help') || args.length === 0) {
    showHelp();
    process.exit(0);
  }
  
  let address = null;
  let cryptoType = null;
  let saveResults_flag = false;
  
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--type' && args[i + 1]) {
      cryptoType = args[i + 1].toLowerCase();
      i++;
    } else if (args[i] === '--save') {
      saveResults_flag = true;
    } else if (!args[i].startsWith('--')) {
      address = args[i];
    }
  }
  
  if (!address) {
    console.log("\x1b[31m❌ No address specified!\x1b[0m\n");
    showHelp();
    process.exit(1);
  }
  
  // Auto-detect crypto type if not specified
  if (!cryptoType) {
    cryptoType = detectCryptoType(address);
    if (cryptoType === 'unknown') {
      console.log("\x1b[31m❌ Invalid cryptocurrency address!\x1b[0m\n");
      console.log("Supported formats:");
      console.log("  Bitcoin: 1... or 3... or bc1...");
      console.log("  Ethereum: 0x...\n");
      process.exit(1);
    }
  }
  
  showBanner();
  
  console.log(`⏳ Tracking ${cryptoType} address: ${address}...\n`);
  
  let results;
  if (cryptoType === 'bitcoin') {
    results = await checkBitcoinAddress(address);
  } else if (cryptoType === 'ethereum') {
    results = await checkEthereumAddress(address);
  } else {
    console.log(`\x1b[31m❌ Unsupported crypto type: ${cryptoType}\x1b[0m\n`);
    process.exit(1);
  }
  
  displayResults(results, cryptoType);
  
  if (saveResults_flag && results.available) {
    saveResults(results, cryptoType);
  }
  
  console.log("\x1b[31m ██████╗██████╗ ██╗   ██╗██████╗ ████████╗ ██████╗\x1b[0m");
  console.log("\x1b[35m🥝 Tracking complete - by kiwi & 777\x1b[0m\n");
}

main().catch(console.error);
