# 🔥 NIKA OSINT ULTRA

```
███╗   ██╗██╗██╗  ██╗ █████╗ 
████╗  ██║██║██║ ██╔╝██╔══██╗
██╔██╗ ██║██║█████╔╝ ███████║
██║╚██╗██║██║██╔═██╗ ██╔══██║
██║ ╚████║██║██║  ██╗██║  ██║
╚═╝  ╚═══╝╚═╝╚═╝  ╚═╝╚═╝  ╚═╝

                ⚡ ULTRA OSINT INTELLIGENCE TOOLKIT ⚡
```

### Advanced Open Source Intelligence Toolkit  
**Developed by Kiwi & 777**

![License](https://img.shields.io/badge/License-MIT-green)
![Node](https://img.shields.io/badge/Node.js-14%2B-brightgreen)
![Platform](https://img.shields.io/badge/Platform-Terminal-blue)

---

# 📚 Table of Contents

- Overview  
- Features  
- Installation  
- Usage  
- Advanced Features  
- Risk Scoring  
- Legal & Ethics  
- Troubleshooting  
- Project Structure  
- Updates  
- Credits  
- License  

---

# 🧠 Overview

**NIKA OSINT ULTRA** is a powerful terminal-based OSINT toolkit designed for:

- Security researchers  
- Penetration testers  
- Digital investigators  
- Defensive security analysts  

Built with Node.js, it performs real-time intelligence gathering across multiple domains directly from your terminal.

---

# 🚀 Why NIKA?

- ⚡ Lightning-fast concurrent scanning  
- 🖥 100% terminal output (no files generated)  
- 🎨 Clean color-coded interface with ASCII branding  
- 📱 Optimized for Termux (Android)  
- 🔒 Privacy-focused (local execution)  
- 🆓 Completely free and open source (MIT License)  

---

# 🛠 Features

## 🌐 Domain Intelligence

- Complete DNS analysis (A, AAAA, MX, NS, TXT, CNAME, SOA)  
- Full WHOIS parsing  
- Email security checks (SPF, DMARC, DKIM, DNSSEC)  
- Security header detection (HSTS, CSP, X-Frame-Options)  
- TLS/SSL certificate inspection  
- Technology detection (Nginx, Apache, PHP, WordPress, etc.)  
- Blacklist checking (Spamhaus, SpamCop, SORBS, CBL)  
- Automated risk scoring (0–100)  

---

## 🔎 Subdomain Enumeration

- 250+ wordlist patterns  
- Certificate Transparency integration  
- 10 concurrent resolution threads  
- Automatic IP resolution  
- Discovery source tracking  

---

## 📧 Email Intelligence

- RFC-compliant format validation  
- MX record enumeration  
- Disposable email detection (100+ providers)  
- Gravatar profile verification  
- Breach intelligence integration  
- Reputation analysis  

---

## 👤 Username OSINT (20+ Platforms)

### Developer
GitHub, GitLab, Bitbucket, StackOverflow, Dev.to, HackerNews  

### Social
Twitter, Instagram, Facebook, LinkedIn, TikTok, Reddit, Telegram, Discord  

### Content
Medium, YouTube, Twitch, Pinterest, Patreon, Keybase  

---

## 📱 Phone Intelligence

- Validation via libphonenumber-js  
- Multiple formats (International, National, E.164, RFC3966)  
- Italian carrier detection (TIM, Vodafone, Wind Tre)  
- Location data (country, timezone, coordinates)  
- Number type classification  
- Social links (WhatsApp, Telegram, Signal, Viber)  
- Spam reference indicators  

---

## 🌍 IP Geolocation

- City, region, country  
- ISP and ASN detection  
- Reverse DNS lookup  
- VPN and blacklist references  

---

# 💻 Installation

## 📱 Termux (Android)

```bash
pkg update && pkg upgrade -y
pkg install nodejs git -y
termux-setup-storage

git clone https://github.com/u4622172004-png/nika-osint.git
cd nika-osint
npm install

chmod +x osint-ultra-max.js
chmod +x osint-menu-termux.sh

./osint-menu-termux.sh
```

---

## 🐧 Linux (Ubuntu/Debian)

```bash
sudo apt update && sudo apt install nodejs npm git -y

git clone https://github.com/u4622172004-png/nika-osint.git
cd nika-osint
npm install

chmod +x osint-ultra-max.js
chmod +x osint-menu.sh

./osint-menu.sh
```

---

## 🍎 macOS

```bash
brew install node git

git clone https://github.com/u4622172004-png/nika-osint.git
cd nika-osint
npm install

chmod +x osint-ultra-max.js
chmod +x osint-menu.sh

./osint-menu.sh
```

---

# ▶ Usage

## Interactive Menu

```bash
./osint-menu-termux.sh
./osint-menu.sh
```

Menu:

```
[1] Domain Intelligence
[2] Email Analysis
[3] Phone Lookup
[4] Username Search
[5] Subdomain Enumeration
[6] Full Report
[7] Info & Help
[0] Exit
```

---

## Command Line Examples

```bash
./osint-ultra-max.js --domain example.com
./osint-ultra-max.js --email test@example.com
./osint-ultra-max.js --phone +393331234567
./osint-ultra-max.js --username johndoe
./osint-ultra-max.js --help
```

Combined scan:

```bash
./osint-ultra-max.js --domain example.com --email admin@example.com --username admin
```

---

# ⚙ Advanced Features

- 10 parallel subdomain checks  
- Intelligent timeout handling  
- Rate-limited API calls  
- Graceful error handling  
- Network failure recovery  
- DNS timeout protection  

---

# 📊 Risk Scoring System

## Risk Factors

- Missing SPF: +15  
- Missing DMARC: +15  
- Missing HSTS: +10  
- Missing CSP: +10  
- Missing DNSSEC: +10  
- Certificate expiring (<30 days): +15  
- Blacklist presence: +20  
- Disposable email: +15  

## Risk Levels

| Score | Level    | Description                     |
|--------|----------|---------------------------------|
| 0–19   | LOW      | Good security posture           |
| 20–49  | MEDIUM   | Some security concerns          |
| 50–79  | HIGH     | Significant security issues     |
| 80+    | CRITICAL | Immediate action required       |

---

# ⚖ Legal & Ethics

This tool is intended for:

- Educational purposes  
- Authorized security research  
- Penetration testing with permission  
- Public OSINT investigations  
- Auditing your own infrastructure  

🚫 Prohibited uses:

- Unauthorized access attempts  
- Privacy violations  
- Harassment or stalking  
- Illegal surveillance  
- Malicious activity  

Users are solely responsible for compliance with applicable laws.

---

# 🧩 Troubleshooting

**Command not found**
```bash
chmod +x *.js *.sh
```

**Cannot find module**
```bash
npm install
```

**Network timeouts**
- Check your internet connection  
- Retry after a few minutes  

---

# 📁 Project Structure

```
nika-osint/
├── osint-ultra-max.js
├── osint-menu-termux.sh
├── osint-menu.sh
├── package.json
├── wordlists/
│   └── subdomains.txt
├── README.md
└── LICENSE
```

---

# 🔄 Updates

```bash
git pull origin main
npm install
```

---

# 🙌 Credits

Developed by **Kiwi & 777**

Powered by:

- libphonenumber-js  
- whois-json  
- axios  
- crt.sh  
- ipinfo.io  

---

# 📜 License

MIT License  
Copyright (c) 2024 Kiwi & hide 

---

```
NIKA OSINT ULTRA
Intelligence at your fingertips.

Use responsibly.
Respect privacy.
Follow the law.
```
