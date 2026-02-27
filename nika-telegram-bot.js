#!/usr/bin/env node

const TelegramBot = require('node-telegram-bot-api');
const { exec } = require('child_process');
const { promisify } = require('util');
const execAsync = promisify(exec);
const fs = require('fs');
const path = require('path');

// ============================================
// CONFIGURATION
// ============================================

// Inserire la tua API Key fornita
const BOT_TOKEN = '8540182251:AAEY9JbW5zuomyTYFaR-bLHNubKJi5TxJHg';
const ADMIN_IDS = process.env.ADMIN_IDS ? process.env.ADMIN_IDS.split(',').map(Number) : [];
const MAX_CONCURRENT_SCANS = 3;
const SCAN_TIMEOUT = 300000; // 5 minuti

// ============================================
// BOT INITIALIZATION
// ============================================

const bot = new TelegramBot(BOT_TOKEN, { polling: true });

// Storage
const activeScans = new Map();
const scanHistory = new Map();
const userStats = new Map();

console.log('🤖 NIKA OSINT Telegram Bot started!');
console.log('Bot is ready to receive commands...\n');

// ============================================
// UTILITIES
// ============================================

function getUserStats(userId) {
  if (!userStats.has(userId)) {
    userStats.set(userId, {
      totalScans: 0,
      domainScans: 0,
      emailScans: 0,
      phoneScans: 0,
      usernameScans: 0,
      lastScan: null
    });
  }
  return userStats.get(userId);
}

function addToHistory(userId, type, target, result) {
  if (!scanHistory.has(userId)) {
    scanHistory.set(userId, []);
  }
  const history = scanHistory.get(userId);
  history.unshift({
    type,
    target,
    timestamp: new Date().toISOString(),
    result: result.substring(0, 200) + '...'
  });
  if (history.length > 10) history.pop();
}

function isRateLimited(userId) {
  const stats = getUserStats(userId);
  if (stats.lastScan) {
    const timeSince = Date.now() - new Date(stats.lastScan).getTime();
    if (timeSince < 10000) { // 10 secondi
      return true;
    }
  }
  return false;
}

function formatUptime() {
  const uptime = process.uptime();
  const hours = Math.floor(uptime / 3600);
  const minutes = Math.floor((uptime % 3600) / 60);
  const seconds = Math.floor(uptime % 60);
  return `${hours}h ${minutes}m ${seconds}s`;
}

// ============================================
// SCAN FUNCTIONS
// ============================================

async function runScan(type, target, chatId) {
  const scanId = `${chatId}_${Date.now()}`;
  const startTime = Date.now();
  
  try {
    activeScans.set(scanId, { type, target, chatId, startTime });
    
    // Assicurati che il percorso ~/osint-tool sia corretto sul tuo server
    const cmd = `cd ~/osint-tool && node osint-ultra-max.js --${type} "${target}" --save`;
    
    const { stdout, stderr } = await execAsync(cmd, {
      timeout: SCAN_TIMEOUT,
      maxBuffer: 10 * 1024 * 1024 // 10MB
    });
    
    const duration = Math.floor((Date.now() - startTime) / 1000);
    activeScans.delete(scanId);
    return { success: true, output: stdout, error: stderr, duration };
    
  } catch (error) {
    activeScans.delete(scanId);
    return { success: false, error: error.message };
  }
}

async function getLatestReport() {
  try {
    const reportDir = path.join(__dirname, 'reports');
    if (!fs.existsSync(reportDir)) return null;
    
    const files = fs.readdirSync(reportDir)
      .filter(f => f.endsWith('.json'))
      .map(f => ({
        name: f,
        path: path.join(reportDir, f),
        time: fs.statSync(path.join(reportDir, f)).mtime.getTime()
      }))
      .sort((a, b) => b.time - a.time);
    
    if (files.length === 0) return null;
    return files[0].path;
    
  } catch (error) {
    return null;
  }
}

// ============================================
// COMMAND HANDLERS
// ============================================

// /start
bot.onText(/\/start/, (msg) => {
  const chatId = msg.chat.id;
  const userName = msg.from.first_name || 'User';
  
  const welcome = `
🥝 *NIKA OSINT ULTRA v3.0*
_Advanced Intelligence Gathering Bot_

Ciao ${userName}! 👋

Sono il bot ufficiale di NIKA OSINT.
Posso aiutarti a raccogliere informazioni su:

🌐 *Domini* - DNS, WHOIS, security, subdomains
📧 *Email* - Validazione, breach, reputation  
📱 *Telefoni* - Carrier, location, spam check
👤 *Username* - Social media footprint (25+ platforms)

*COMANDI DISPONIBILI:*

/domain <domain> - Scan dominio
/email <email> - Scan email
/phone <phone> - Scan telefono
/username <user> - Scan username
/history - Ultimi 10 scan
/stats - Tue statistiche
/help - Guida completa
/about - Info sul bot

*ESEMPI:*
\`/domain google.com\`
\`/email test@example.com\`
\`/phone +393331234567\`
\`/username johndoe\`

🔒 *Privacy:* I tuoi dati sono privati e non vengono condivisi.

_by kiwi & 777_
`;
  
  bot.sendMessage(chatId, welcome, { parse_mode: 'Markdown' });
});

// /domain
bot.onText(/\/domain (.+)/, async (msg, match) => {
  const chatId = msg.chat.id;
  const domain = match[1].trim();
  const userId = msg.from.id;
  
  if (isRateLimited(userId)) return bot.sendMessage(chatId, '⏳ Attendere 10 secondi tra uno scan e l\'altro.');
  if (activeScans.size >= MAX_CONCURRENT_SCANS) return bot.sendMessage(chatId, '⚠️ Troppi scan in corso. Riprova tra poco.');
  
  const stats = getUserStats(userId);
  stats.lastScan = new Date().toISOString();
  stats.totalScans++;
  stats.domainScans++;
  
  const waitMsg = await bot.sendMessage(chatId, `🔍 Scanning domain: *${domain}*\n\n⏳ Analisi in corso...`, { parse_mode: 'Markdown' });
  
  const result = await runScan('domain', domain, chatId);
  
  if (result.success) {
    addToHistory(userId, 'domain', domain, result.output);
    const lines = result.output.split('\n');
    const riskLine = lines.find(l => l.includes('RISK:'));
    const risk = riskLine ? riskLine.match(/RISK: (.+?) \(/)?.[1] : 'UNKNOWN';
    
    const summary = `✅ *SCAN COMPLETATO*\n\n🌐 *Domain:* \`${domain}\`\n🎯 *Risk:* ${risk}\n⏱ *Durata:* ${result.duration}s\n\nUsa /export per il report completo.`;
    
    bot.deleteMessage(chatId, waitMsg.message_id);
    bot.sendMessage(chatId, summary, { parse_mode: 'Markdown' });
    bot.sendMessage(chatId, `\`\`\`\n${result.output.substring(0, 3500)}\n...\n\`\`\``, { parse_mode: 'Markdown' });
  } else {
    bot.deleteMessage(chatId, waitMsg.message_id);
    bot.sendMessage(chatId, `❌ *Errore durante lo scan*\n\n\`${result.error}\``, { parse_mode: 'Markdown' });
  }
});

// Nota: I comandi /email, /phone, /username seguono la stessa logica del /domain sopra.
// [Il resto dei tuoi handler rimane invariato ma utilizzerà la costante BOT_TOKEN aggiornata]

// /stats, /history, /export, /cancel, /ping, /about rimangono come definiti nel tuo snippet.

// ============================================
// ERROR & SHUTDOWN
// ============================================

bot.on('polling_error', (error) => console.error('Polling error:', error.code, error.message));
process.on('SIGINT', () => {
  console.log('\n🛑 Bot shutting down...');
  bot.stopPolling();
  process.exit(0);
});

console.log('✅ Bot is running! Send /start to begin.');

