# NIKA OSINT Toolkit

     ███╗   ██╗ ██╗ ██╗  ██╗  █████╗   
     ████╗  ██║ ██║ ██║ ██╔╝ ██╔══██╗  
     ██╔██╗ ██║ ██║ █████╔╝  ███████║  
     ██║╚██╗██║ ██║ ██╔═██╗  ██╔══██║  
     ██║ ╚████║ ██║ ██║  ██╗ ██║  ██║  
     ╚═╝  ╚═══╝ ╚═╝ ╚═╝  ╚═╝ ╚═╝  ╚═╝  

**Advanced OSINT Intelligence Gathering Toolkit**

by 777 & Kiwi

---

## Features

### Domain Intelligence
- DNS Records (A, AAAA, MX, NS, TXT)
- WHOIS Information
- Security Headers Analysis
- TLS/SSL Certificate Validation
- SPF/DMARC/DNSSEC Check
- Risk Scoring System

### Subdomain Enumeration
- Wordlist Brute-force (250+ subdomains)
- Certificate Transparency (crt.sh)
- Automatic DNS Resolution
- Concurrent Scanning

### Email Analysis
- Format Validation
- MX Record Verification
- Gravatar Profile Lookup
- Domain Reputation

### Username OSINT
- Multi-platform Search
- GitHub, Reddit, Twitter, Instagram
- Medium, Pinterest, Dev.to
- Social Media Footprint

### Phone Intelligence
- Country Detection
- Carrier Identification
- Type Classification
- International Format

### IP Geolocation
- Location Data
- ISP Information
- Timezone Detection

---

## Platform Support

- Termux (Android 7.0+)
- Linux (Ubuntu, Debian, Arch)
- macOS (Intel & Apple Silicon)

---

## Quick Install

**Termux (Android)**

Install Termux from F-Droid: https://f-droid.org/packages/com.termux/

Then run:

    pkg update && pkg upgrade -y
    pkg install nodejs git -y
    git clone https://github.com/YOUR-USERNAME/nika-osint.git
    cd nika-osint
    bash install-termux.sh
    ./osint-menu-termux.sh

**Linux / macOS**

    git clone https://github.com/YOUR-USERNAME/nika-osint.git
    cd nika-osint
    npm install
    chmod +x osint-ultra-max.js
    chmod +x osint-menu.sh
    ./osint-menu.sh

---

## Usage

**Interactive Menu**

    ./osint-menu-termux.sh

**Direct Command Line**

    ./osint-ultra-max.js --domain example.com
    ./osint-ultra-max.js --email test@example.com
    ./osint-ultra-max.js --username johndoe
    ./osint-ultra-max.js --phone +393331234567

**Full reconnaissance**

    ./osint-ultra-max.js --domain example.com --email admin@example.com --username admin

---

## Output

**Terminal Output**
- Color-coded results
- Real-time scan progress
- Risk assessment
- Detailed findings

**Report Files**
- report.json - Structured data
- report.html - Visual interactive report

**View HTML report:**

Termux: termux-open report.html
Linux: xdg-open report.html
macOS: open report.html

---

## Requirements

**Node.js Packages**
- axios - HTTP client
- whois-json - WHOIS lookups
- libphonenumber-js - Phone parsing
- p-limit - Concurrency control

**System Requirements**
- Node.js >= 14.0.0
- npm >= 6.0.0
- Internet connection

---

## Risk Scoring

| Score | Level | Description |
|-------|-------|-------------|
| 0-19 | LOW | Good security posture |
| 20-49 | MEDIUM | Some concerns |
| 50-79 | HIGH | Significant issues |
| 80+ | CRITICAL | Immediate action needed |

**Risk Factors:**
- Missing SPF: +15 points
- Missing DMARC: +15 points
- Missing HSTS: +10 points
- Missing CSP: +10 points
- Missing DNSSEC: +10 points
- Expiring cert: +15 points

---

## Project Structure

    nika-osint/
    ├── osint-ultra-max.js
    ├── osint-menu-termux.sh
    ├── osint-menu.sh
    ├── package.json
    ├── install-termux.sh
    ├── install-global.sh
    ├── wordlists/
    │   └── subdomains.txt
    ├── README.md
    └── LICENSE

---

## Troubleshooting

**Command not found**

    chmod +x osint-ultra-max.js osint-menu-termux.sh

**Cannot find module**

    npm install

**Permission denied**

    chmod +x *.js *.sh

---

## Legal Disclaimer

**FOR EDUCATIONAL AND AUTHORIZED USE ONLY**

This tool is designed for:
- Educational purposes
- Authorized penetration testing
- Security research
- OSINT on public information

**PROHIBITED:**
- Unauthorized access
- Privacy violations
- Stalking or harassment
- Illegal surveillance

Users are responsible for complying with all laws.

---

## Contributing

Contributions welcome!

1. Fork the repository
2. Create feature branch
3. Commit changes
4. Push to branch
5. Open Pull Request

---

## Changelog

**v1.0.0 (2024)**
- Initial release
- Domain intelligence module
- Subdomain enumeration
- Email analysis
- Username footprinting
- Phone lookup
- Risk scoring system
- HTML/JSON reporting
- Interactive menu

---

## License

MIT License - see LICENSE file

---

## Authors

by kiwi & 777

Created for the OSINT community
Built for educational purposes

---

## Support

If you find this tool useful:
- Star the repository
- Report bugs
- Suggest features
- Contribute code

---

**Use responsibly. Respect privacy. Follow laws.**

     ███╗   ██╗ ██╗ ██╗  ██╗  █████╗   
     ████╗  ██║ ██║ ██║ ██╔╝ ██╔══██╗  
     ██╔██╗ ██║ ██║ █████╔╝  ███████║  
     ██║╚██╗██║ ██║ ██╔═██╗  ██╔══██║  
     ██║ ╚████║ ██║ ██║  ██╗ ██║  ██║  
     ╚═╝  ╚═══╝ ╚═╝ ╚═╝  ╚═╝ ╚═╝  ╚═╝  

NIKA OSINT - Intelligence at your fingertips
