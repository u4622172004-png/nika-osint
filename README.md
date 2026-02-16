# NIKA OSINT ULTRA

**Advanced Open Source Intelligence Gathering Toolkit**

*Developed by kiwi & 777*

[

![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)

](https://opensource.org/licenses/MIT)
[

![Node.js](https://img.shields.io/badge/Node.js-14+-green.svg)

](https://nodejs.org/)
[

![Platform](https://img.shields.io/badge/Platform-Termux%20|%20Linux%20|%20macOS-blue.svg)

](https://github.com/god-kiwi/nika-osint)

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Advanced Features](#advanced-features)
- [Risk Scoring](#risk-scoring)
- [Legal & Ethics](#legal--ethics)
- [Troubleshooting](#troubleshooting)
- [Credits](#credits)

---

## Overview

**NIKA OSINT ULTRA** is a comprehensive, terminal-based OSINT (Open Source Intelligence) toolkit designed for security researchers, penetration testers, and digital investigators. Built with Node.js, it provides real-time intelligence gathering across multiple domains.

### Why NIKA?

- **Lightning Fast** - Concurrent scanning with intelligent rate limiting
- **100% Terminal Output** - No files generated, all results displayed in real-time
- **Beautiful Interface** - Color-coded, organized output with ASCII art
- **Mobile Ready** - Optimized for Termux on Android devices
- **Privacy Focused** - All scanning done locally
- **Completely Free** - Open source with MIT license

---

## Features

### Domain Intelligence

- **Complete DNS Analysis**: A, AAAA, MX, NS, TXT, CNAME, SOA records
- **Full WHOIS Data**: Registrant name, organization, address, email, phone
- **Email Security**: SPF, DMARC, DKIM (multiple selectors), DNSSEC
- **Security Headers**: HSTS, CSP, X-Frame-Options, and more
- **TLS/SSL Certificate**: Issuer, expiry, protocol, cipher details
- **Technology Detection**: Nginx, Apache, PHP, WordPress, etc.
- **Blacklist Checking**: 4 major RBLs (Spamhaus, SpamCop, SORBS, CBL)
- **Risk Scoring**: Automated security assessment (0-100)

### Subdomain Enumeration

- **Wordlist Brute-Force**: 250+ common patterns
- **Certificate Transparency**: crt.sh integration
- **Concurrent Resolution**: 10 parallel threads
- **IP Resolution**: Automatic IP address discovery
- **Source Tracking**: Shows discovery method

### Email Intelligence

- **Format Validation**: RFC-compliant checking
- **MX Records**: Complete mail server enumeration
- **Disposable Detection**: 100+ temp email services
- **Gravatar Check**: Profile existence verification
- **Breach Intelligence**: Have I Been Pwned integration
- **Reputation Analysis**: Spam score indicators

### Username OSINT (20+ Platforms)

**Developer**: GitHub (API), GitLab, BitBucket, StackOverflow, Dev.to, HackerNews

**Social**: Twitter, Instagram, Facebook, LinkedIn, TikTok, Reddit (API), Telegram, Discord

**Content**: Medium, YouTube, Twitch, Pinterest, Patreon, Keybase

### Phone Intelligence

- **Validation**: libphonenumber-js powered
- **Multiple Formats**: International, National, E.164, RFC3966, URI
- **Carrier Detection**: Italian networks (TIM, Vodafone, Wind Tre)
- **Location**: Country, timezone, coordinates
- **Type Classification**: Mobile, Landline, VoIP, Toll-Free, etc.
- **Social Links**: WhatsApp, Telegram, Signal, Viber
- **Spam Check**: References to reputation services

### IP Geolocation

- **Location Data**: City, region, country, coordinates
- **Network Info**: ISP, ASN, hosting provider
- **Reverse DNS**: PTR record resolution
- **Security**: Blacklist checking, VPN detection references

---

## Installation

### Termux (Android)

```bash
# 1. Install Termux from F-Droid
# https://f-droid.org/packages/com.termux/

# 2. Update packages
pkg update && pkg upgrade -y

# 3. Install dependencies
pkg install nodejs git -y

# 4. Setup storage (optional)
termux-setup-storage

# 5. Clone repository
git clone https://github.com/god-kiwi/nika-osint.git
cd nika-osint

# 6. Install Node modules
npm install

# 7. Make executable
chmod +x osint-ultra-max.js
chmod +x osint-menu-termux.sh

# 8. Run
./osint-menu-termux.sh
Linux
# Ubuntu/Debian
sudo apt update && sudo apt install nodejs npm git -y

# Clone repository
git clone https://github.com/god-kiwi/nika-osint.git
cd nika-osint

# Install dependencies
npm install

# Make executable
chmod +x osint-ultra-max.js
chmod +x osint-menu.sh

# Run
./osint-menu.sh
macOS
# Install Homebrew (if needed)
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install Node.js
brew install node git

# Clone repository
git clone https://github.com/god-kiwi/nika-osint.git
cd nika-osint

# Install dependencies
npm install

# Make executable
chmod +x osint-ultra-max.js
chmod +x osint-menu.sh

# Run
./osint-menu.sh
Usage
Interactive Menu
# Launch menu
./osint-menu-termux.sh  # Termux
./osint-menu.sh         # Linux/macOS
Menu Options:
[1] Domain Intelligence
[2] Email Analysis
[3] Phone Lookup
[4] Username Search
[5] Subdomain Enumeration
[6] Full Report
[7] Info & Help
[0] Exit
Command Line
Domain Scan:
./osint-ultra-max.js --domain example.com
./osint-ultra-max.js example.com  # shortcut
Email Analysis:
./osint-ultra-max.js --email test@example.com
Phone Lookup:
./osint-ultra-max.js --phone +393331234567
Username Search:
./osint-ultra-max.js --username johndoe
Combined Scan:
./osint-ultra-max.js --domain example.com --email admin@example.com --username admin
Display Help:
./osint-ultra-max.js --help
./osint-ultra-max.js
Advanced Features
Custom Subdomains
Edit the wordlist to add your own patterns:
nano wordlists/subdomains.txt
Add custom entries:
vpn
internal
backup
staging2
dev2
Concurrent Scanning
10 parallel subdomain checks
Automatic timeout handling (5-15 seconds)
Rate-limited API calls
Non-blocking operations
Error Handling
Graceful degradation on failures
Detailed error messages
Network failure recovery
DNS timeout protection
Risk Scoring
Score Calculation
Risk Factors:
Missing SPF: +15 points
Missing DMARC: +15 points
Missing HSTS: +10 points
Missing CSP: +10 points
Missing DNSSEC: +10 points
Certificate expiring (<30 days): +15 points
Missing security headers: +5 points each
Large subdomain count (>10): +15 points
Blacklist presence: +20 points
Disposable email: +15 points
Risk Levels
Score
Level
Description
0-19
LOW
Good security posture
20-49
MEDIUM
Some security concerns
50-79
HIGH
Significant security issues
80+
CRITICAL
Immediate action required
Output Format
Terminal Output
All results are displayed in real-time with:
Color Coding: Green (good), Red (bad), Yellow (warning)
Organized Sections: Separated by category
ASCII Art: Beautiful headers and branding
Risk Assessment: Color-coded score display
Example Output
RISK: MEDIUM (35/100)

DOMAIN INTELLIGENCE

DNS:
   A: 93.184.216.34
   MX: mail.example.com (10)
   NS: ns1.example.com

WHOIS:
   Name: John Doe
   Organization: Example Corp
   Email: admin@example.com
   City: Los Angeles, CA
   Country: United States

Security:
   SPF: Valid
   DMARC: Configured (Policy: reject)
   DKIM: Found
   DNSSEC: Enabled
   HSTS: Present

TLS: 87 days
   Issuer: Let's Encrypt
   Protocol: TLSv1.3
Legal & Ethics
Important Notice
This tool is designed for:
Educational purposes
Authorized security research
Penetration testing with permission
OSINT on publicly available information
Domain security auditing (your own domains)
Prohibited Uses
Unauthorized access attempts
Privacy violations
Stalking or harassment
Illegal surveillance
Any malicious activities
Scanning domains without permission
Responsible Use
Always obtain proper authorization
Respect rate limits and Terms of Service
Follow applicable laws and regulations
Use for defensive security purposes
Report findings responsibly
Respect privacy and data protection laws
Users are solely responsible for compliance with all applicable laws.
Troubleshooting
Common Issues
Command not found
chmod +x osint-ultra-max.js
chmod +x osint-menu-termux.sh
Cannot find module
cd nika-osint
npm install
Permission denied
chmod +x *.js *.sh
Network timeouts
Check internet connection
Some domains may have rate limiting
Try again after a few minutes
WHOIS data unavailable
Many domains use privacy protection
This is normal and expected
Government/old domains may show full data
No subdomains found
Domain may not have subdomains
Try adding custom patterns to wordlist
Some domains block enumeration
Dependencies
Node.js >= 14.0.0
axios - HTTP client
whois-json - WHOIS lookups
libphonenumber-js - Phone number parsing
p-limit - Concurrency control
Project Structure
nika-osint/
├── osint-ultra-max.js        # Core scanning engine
├── osint-menu-termux.sh      # Termux interactive menu
├── osint-menu.sh             # Linux/macOS menu
├── package.json              # Node.js dependencies
├── wordlists/
│   └── subdomains.txt        # Subdomain wordlist (250+)
├── README.md                 # This file
└── LICENSE                   # MIT License
Updates
Stay Updated
cd nika-osint
git pull origin main
npm install
Version History
v2.0 ULTRA (Current)
20+ social media platforms
DKIM detection with multiple selectors
Italian carrier database
Enhanced phone analysis with social links
Blacklist checking (4 RBLs)
Technology detection
Disposable email detection
Gravatar profile verification
Complete WHOIS parsing
Risk scoring improvements
v1.0
Initial release
Basic domain/email/phone/username scanning
Credits
Developed by: kiwi & 777
Special Thanks:
Termux developers
Node.js community
Open source contributors
Powered by:
libphonenumber-js
whois-json
axios
crt.sh (Certificate Transparency)
ipinfo.io (IP Geolocation)
License
MIT License
Copyright (c) 2024 kiwi & 777
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
Support
If you find NIKA useful:
Star the repository
Report bugs via Issues
Suggest features
Submit pull requests
Share with others
Contact
GitHub Issues: https://github.com/god-kiwi/nika-osint/issues
Repository: https://github.com/god-kiwi/nika-osint
Quick Start Examples
Scan Your Own Domain
./osint-ultra-max.js --domain yourwebsite.com
Check Email Validity
./osint-ultra-max.js --email your.email@domain.com
Find Social Media Profiles
./osint-ultra-max.js --username yourusername
Phone Number Analysis
./osint-ultra-max.js --phone "+39 333 123 4567"
Complete Investigation
./osint-ultra-max.js --domain target.com --email admin@target.com --username targetuser
NIKA OSINT ULTRA - Intelligence at your fingertips
Use responsibly. Respect privacy. Follow laws.
by 777 & Kiwi
