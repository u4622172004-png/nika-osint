#!/usr/bin/env node

const TelegramBot = require('node-telegram-bot-api');
const { exec } = require('child_process');
const fs = require('fs');
const path = require('path');

// Token
const TOKEN = '8540182251:AAEY9JbW5zuomyTYFaR-bLHNubKJi5TxJHg';

// Create bot
const bot = new TelegramBot(TOKEN, { polling: true });

console.log('🤖 NIKA Bot Started!');
console.log('📱 Send /start on Telegram\n');

// Storage
const history = new Map();

// /start
bot.onText(/\/start/, (msg) => {
  const chatId = msg.chat.id;
  const text = `
🥝 *NIKA OSINT BOT*

Ciao! Sono il bot di NIKA OSINT.

*COMANDI:*
/domain <domain> - Scan dominio
/email <email> - Scan email
/phone <phone> - Scan telefono
/username <user> - Scan username
/help - Guida

*ESEMPIO:*
\`/domain google.com\`
`;
  bot.sendMessage(chatId, text, { parse_mode: 'Markdown' });
});

// /help
bot.onText(/\/help/, (msg) => {
  const text = `
📚 *GUIDA COMANDI*

/domain <domain>
Analisi completa dominio

/email <email>
Analisi email

/phone <phone>
Analisi telefono (formato: +393331234567)

/username <user>
Ricerca social media

*ESEMPIO:*
\`/domain google.com\`
\`/email test@test.com\`
\`/phone +393331234567\`
\`/username kiwi\`
`;
  bot.sendMessage(chatId, text, { parse_mode: 'Markdown' });
});

// /domain
bot.onText(/\/domain (.+)/, async (msg, match) => {
  const chatId = msg.chat.id;
  const domain = match[1].trim();
  
  bot.sendMessage(chatId, `🔍 Scanning: *${domain}*\n\n⏳ Questo richiede 1-2 minuti...`, { parse_mode: 'Markdown' });
  
  exec(`cd ~/osint-tool && node osint-ultra-max.js --domain "${domain}" --save`, 
    { timeout: 300000, maxBuffer: 10 * 1024 * 1024 },
    (error, stdout, stderr) => {
      if (error) {
        bot.sendMessage(chatId, `❌ Errore:\n\`${error.message}\``, { parse_mode: 'Markdown' });
        return;
      }
      
      // Send output (truncato)
      const output = stdout.substring(0, 3800);
      bot.sendMessage(chatId, `✅ *SCAN COMPLETATO*\n\n\`\`\`\n${output}\n\`\`\``, { parse_mode: 'Markdown' });
      
      // Try to send report
      setTimeout(() => {
        const reportDir = path.join(__dirname, 'reports');
        if (fs.existsSync(reportDir)) {
          const files = fs.readdirSync(reportDir)
            .filter(f => f.endsWith('.json'))
            .map(f => ({
              name: f,
              path: path.join(reportDir, f),
              time: fs.statSync(path.join(reportDir, f)).mtime.getTime()
            }))
            .sort((a, b) => b.time - a.time);
          
          if (files.length > 0) {
            bot.sendDocument(chatId, files[0].path, {
              caption: '📊 Report completo (JSON)'
            });
          }
        }
      }, 2000);
    }
  );
});

// /email
bot.onText(/\/email (.+)/, async (msg, match) => {
  const chatId = msg.chat.id;
  const email = match[1].trim();
  
  bot.sendMessage(chatId, `📧 Analyzing: *${email}*\n\n⏳ Attendere...`, { parse_mode: 'Markdown' });
  
  exec(`cd ~/osint-tool && node osint-ultra-max.js --email "${email}" --save`,
    { timeout: 300000, maxBuffer: 10 * 1024 * 1024 },
    (error, stdout) => {
      if (error) {
        bot.sendMessage(chatId, `❌ Errore: \`${error.message}\``, { parse_mode: 'Markdown' });
        return;
      }
      const output = stdout.substring(0, 3800);
      bot.sendMessage(chatId, `✅ *COMPLETATO*\n\n\`\`\`\n${output}\n\`\`\``, { parse_mode: 'Markdown' });
    }
  );
});

// /phone
bot.onText(/\/phone (.+)/, async (msg, match) => {
  const chatId = msg.chat.id;
  const phone = match[1].trim();
  
  bot.sendMessage(chatId, `📱 Analyzing: *${phone}*\n\n⏳ Attendere...`, { parse_mode: 'Markdown' });
  
  exec(`cd ~/osint-tool && node osint-ultra-max.js --phone "${phone}" --save`,
    { timeout: 300000, maxBuffer: 10 * 1024 * 1024 },
    (error, stdout) => {
      if (error) {
        bot.sendMessage(chatId, `❌ Errore: \`${error.message}\``, { parse_mode: 'Markdown' });
        return;
      }
      const output = stdout.substring(0, 3800);
      bot.sendMessage(chatId, `✅ *COMPLETATO*\n\n\`\`\`\n${output}\n\`\`\``, { parse_mode: 'Markdown' });
    }
  );
});

// /username
bot.onText(/\/username (.+)/, async (msg, match) => {
  const chatId = msg.chat.id;
  const username = match[1].trim();
  
  bot.sendMessage(chatId, `👤 Searching: *${username}*\n\n⏳ Checking 25+ platforms...`, { parse_mode: 'Markdown' });
  
  exec(`cd ~/osint-tool && node osint-ultra-max.js --username "${username}" --save`,
    { timeout: 300000, maxBuffer: 10 * 1024 * 1024 },
    (error, stdout) => {
      if (error) {
        bot.sendMessage(chatId, `❌ Errore: \`${error.message}\``, { parse_mode: 'Markdown' });
        return;
      }
      const output = stdout.substring(0, 3800);
      bot.sendMessage(chatId, `✅ *COMPLETATO*\n\n\`\`\`\n${output}\n\`\`\``, { parse_mode: 'Markdown' });
    }
  );
});

// Error handler
bot.on('polling_error', (error) => {
  console.log('Polling error:', error.code);
});

// Test connection
bot.getMe().then((info) => {
  console.log(`✅ Connected as @${info.username}`);
}).catch((err) => {
  console.log('❌ Connection failed:', err.message);
});
