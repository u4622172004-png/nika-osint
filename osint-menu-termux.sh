#!/bin/bash

# ============================================
# NIKA OSINT v7.0 - DARK HACKER MENU
# ============================================

R='\033[0;31m'
G='\033[0;32m'
Y='\033[1;33m'
W='\033[1;37m'
D='\033[0;90m'
NC='\033[0m'

show_banner() {
  clear
  echo -e "${R}"
  cat << "EOF"
    ███▄    █  ██▓ ██ ▄█▀ ▄▄▄      
    ██ ▀█   █ ▓██▒ ██▄█▒ ▒████▄    
   ▓██  ▀█ ██▒▒██▒▓███▄░ ▒██  ▀█▄  
   ▓██▒  ▐▌██▒░██░▓██ █▄ ░██▄▄▄▄██ 
   ▒██░   ▓██░░██░▒██▒ █▄ ▓█   ▓██▒
   ░ ▒░   ▒ ▒ ░▓  ▒ ▒▒ ▓▒ ▒▒   ▓▒█░
   ░ ░░   ░ ▒░ ▒ ░░ ░▒ ▒░  ▒   ▒▒ ░
      ░   ░ ░  ▒ ░░ ░░ ░   ░   ▒   
            ░  ░  ░  ░         ░  ░
EOF
  echo -e "${NC}"
  echo -e "${D}┌─────────────────────────────────────────────────────────┐${NC}"
  echo -e "${D}│${NC} ${W}OSINT${NC} ${D}Framework v7.0                    ${R}[ ${W}49${NC} ${R}Modules ]${NC} ${D}│${NC}"
  echo -e "${D}│${NC} ${D}Developed by${NC} ${W}kiwi${NC} ${D}&${NC} ${W}777${NC}                                   ${D}│${NC}"
  echo -e "${D}└─────────────────────────────────────────────────────────┘${NC}"
  echo ""
}

show_menu() {
  echo -e "${D}┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓${NC}"
  echo -e "${D}┃${NC} ${R}>>${NC} ${W}RECONNAISSANCE${NC}                                          ${D}┃${NC}"
  echo -e "${D}┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛${NC}"
  echo -e "   ${D}[${NC}${W}01${NC}${D}]${NC} Domain Intelligence         ${D}[${NC}${W}02${NC}${D}]${NC} Subdomain Enum"
  echo ""
  
  echo -e "${D}┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓${NC}"
  echo -e "${D}┃${NC} ${R}>>${NC} ${W}IDENTITY & CONTACTS${NC}                                    ${D}┃${NC}"
  echo -e "${D}┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛${NC}"
  echo -e "   ${D}[${NC}${W}03${NC}${D}]${NC} Email Analysis              ${D}[${NC}${W}04${NC}${D}]${NC} Phone Lookup"
  echo -e "   ${D}[${NC}${W}05${NC}${D}]${NC} Username Footprint          ${D}[${NC}${W}06${NC}${D}]${NC} Phone OSINT Pro"
  echo -e "   ${D}[${NC}${W}07${NC}${D}]${NC} Email Intelligence Pro      ${D}[${NC}${W}08${NC}${D}]${NC} Face Recognition"
  echo ""
  
  echo -e "${D}┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓${NC}"
  echo -e "${D}┃${NC} ${R}>>${NC} ${W}ADVANCED OSINT${NC}                                         ${D}┃${NC}"
  echo -e "${D}┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛${NC}"
  echo -e "   ${D}[${NC}${W}09${NC}${D}]${NC} Sherlock (50+ sites)        ${D}[${NC}${W}10${NC}${D}]${NC} Email Harvesting"
  echo -e "   ${D}[${NC}${W}11${NC}${D}]${NC} Reverse Image Search        ${D}[${NC}${W}12${NC}${D}]${NC} Geolocation"
  echo -e "   ${D}[${NC}${W}13${NC}${D}]${NC} Social Media Scraper        ${D}[${NC}${W}14${NC}${D}]${NC} MAC Lookup"
  echo -e "   ${D}[${NC}${W}15${NC}${D}]${NC} Metadata Extractor          ${D}[${NC}${W}16${NC}${D}]${NC} Dork Generator"
  echo -e "   ${D}[${NC}${W}17${NC}${D}]${NC} EXIF Mass Scanner           ${D}[${NC}${W}18${NC}${D}]${NC} Telegram OSINT"
  echo -e "   ${D}[${NC}${W}19${NC}${D}]${NC} Social Finder               ${D}[${NC}${W}20${NC}${D}]${NC} Messaging OSINT"
  echo ""
  
  echo -e "${D}┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓${NC}"
  echo -e "${D}┃${NC} ${R}>>${NC} ${W}SECURITY & THREAT INTEL${NC}                               ${D}┃${NC}"
  echo -e "${D}┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛${NC}"
  echo -e "   ${D}[${NC}${W}21${NC}${D}]${NC} Breach Monitor              ${D}[${NC}${W}22${NC}${D}]${NC} Breach Hunter"
  echo -e "   ${D}[${NC}${W}23${NC}${D}]${NC} Darkweb Scanner             ${D}[${NC}${W}24${NC}${D}]${NC} AI Risk Analyzer"
  echo -e "   ${D}[${NC}${W}25${NC}${D}]${NC} Crypto Tracker              ${D}[${NC}${W}26${NC}${D}]${NC} SSL/TLS Analyzer"
  echo -e "   ${D}[${NC}${W}27${NC}${D}]${NC} IOC Checker                 ${D}[${NC}${W}28${NC}${D}]${NC} GitHub Secrets"
  echo -e "   ${D}[${NC}${W}29${NC}${D}]${NC} Proxy/VPN Detector          ${D}[${NC}${W}30${NC}${D}]${NC} Hash Cracker"
  echo -e "   ${D}[${NC}${W}31${NC}${D}]${NC} Password Leak Checker"
  echo ""
  
  echo -e "${D}┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓${NC}"
  echo -e "${D}┃${NC} ${R}>>${NC} ${W}BUSINESS INTELLIGENCE${NC}                                 ${D}┃${NC}"
  echo -e "${D}┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛${NC}"
  echo -e "   ${D}[${NC}${W}32${NC}${D}]${NC} Company Intelligence        ${D}[${NC}${W}33${NC}${D}]${NC} Address OSINT"
  echo -e "   ${D}[${NC}${W}34${NC}${D}]${NC} Vehicle OSINT (VIN)         ${D}[${NC}${W}35${NC}${D}]${NC} BIN Lookup (Cards)"
  echo ""
  
  echo -e "${D}┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓${NC}"
  echo -e "${D}┃${NC} ${R}>>${NC} ${W}GAMING & LIFESTYLE${NC}                                    ${D}┃${NC}"
  echo -e "${D}┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛${NC}"
  echo -e "   ${D}[${NC}${W}36${NC}${D}]${NC} Gaming OSINT                ${D}[${NC}${W}37${NC}${D}]${NC} IMEI/Device Tracker"
  echo ""
  
  echo -e "${D}┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓${NC}"
  echo -e "${D}┃${NC} ${R}>>${NC} ${W}GEOINT & TRACKING${NC}                                     ${D}┃${NC}"
  echo -e "${D}┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛${NC}"
  echo -e "   ${D}[${NC}${W}38${NC}${D}]${NC} Satellite OSINT             ${D}[${NC}${W}39${NC}${D}]${NC} Reverse Geocoding"
  echo -e "   ${D}[${NC}${W}40${NC}${D}]${NC} Aviation OSINT              ${D}[${NC}${W}41${NC}${D}]${NC} Maritime OSINT"
  echo ""
  
  echo -e "${D}┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓${NC}"
  echo -e "${D}┃${NC} ${R}>>${NC} ${W}TOOLS & UTILITIES${NC}                                     ${D}┃${NC}"
  echo -e "${D}┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛${NC}"
  echo -e "   ${D}[${NC}${W}42${NC}${D}]${NC} IP Grabber Generator        ${D}[${NC}${W}43${NC}${D}]${NC} WiFi Analyzer"
  echo -e "   ${D}[${NC}${W}44${NC}${D}]${NC} QR Code Tools               ${D}[${NC}${W}45${NC}${D}]${NC} Secret Cracker"
  echo -e "   ${D}[${NC}${W}46${NC}${D}]${NC} Dork Search Pro             ${D}[${NC}${W}47${NC}${D}]${NC} TorBot OSINT"
  echo -e "   ${D}[${NC}${W}48${NC}${D}]${NC} Full OSINT Report"
  echo ""
  
  echo -e "${D}┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓${NC}"
  echo -e "${D}┃${NC} ${R}>>${NC} ${W}SYSTEM${NC}                                                 ${D}┃${NC}"
  echo -e "${D}┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛${NC}"
  echo -e "   ${D}[${NC}${W}99${NC}${D}]${NC} About & Info                ${D}[${NC}${W}00${NC}${D}]${NC} Exit"
  echo ""
  echo -ne "${R}┌──[${NC}${W}nika${NC}${R}@${NC}${W}osint${NC}${R}]─[${NC}${W}~${NC}${R}]\n└──╼${NC} ${W}\$${NC} "
}

run_module() {
  echo ""
  echo -e "${D}════════════════════════════════════════════════════════════${NC}"
  "$@"
  local status=$?
  echo -e "${D}════════════════════════════════════════════════════════════${NC}"
  echo ""
  if [ $status -eq 0 ]; then
    echo -e "${R}[${NC}${W}+${NC}${R}]${NC} Module executed successfully"
  else
    echo -e "${R}[${NC}${W}!${NC}${R}]${NC} Module exited with errors"
  fi
  echo ""
  echo -ne "${D}Press ${NC}${W}ENTER${NC}${D} to continue...${NC}"
  read
}

show_info() {
  clear
  show_banner
  echo -e "${D}┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓${NC}"
  echo -e "${D}┃${NC} ${W}SYSTEM INFORMATION${NC}                                         ${D}┃${NC}"
  echo -e "${D}┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛${NC}"
  echo ""
  echo -e "${R}[${NC}${W}#${NC}${R}]${NC} Framework    ${D}:${NC} NIKA OSINT v7.0"
  echo -e "${R}[${NC}${W}#${NC}${R}]${NC} Modules      ${D}:${NC} 49 active"
  echo -e "${R}[${NC}${W}#${NC}${R}]${NC} Platform     ${D}:${NC} Termux/Android"
  echo -e "${R}[${NC}${W}#${NC}${R}]${NC} Authors      ${D}:${NC} kiwi & 777"
  echo -e "${R}[${NC}${W}#${NC}${R}]${NC} Repository   ${D}:${NC} github.com/u4622172004-png/nika-osint"
  echo ""
  echo -e "${D}┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓${NC}"
  echo -e "${D}┃${NC} ${W}VERSION HISTORY${NC}                                            ${D}┃${NC}"
  echo -e "${D}┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛${NC}"
  echo ""
  echo -e "${W}v7.0${NC} ${D}→${NC} 49 modules total ${Y}(NEW!)${NC}"
  echo -e "${W}v6.0${NC} ${D}→${NC} WiFi, EXIF, phone, IOC, secrets, proxy, QR (7 modules)"
  echo -e "${W}v5.1${NC} ${D}→${NC} Breach hunter (1 module)"
  echo -e "${W}v5.0${NC} ${D}→${NC} MAC, metadata, crypto, SSL (5 modules)"
  echo -e "${W}v4.0${NC} ${D}→${NC} Darkweb, social, AI (5 modules)"
  echo -e "${W}v3.0${NC} ${D}→${NC} Base framework (5 modules)"
  echo ""
  echo -e "${D}┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓${NC}"
  echo -e "${D}┃${NC} ${W}NEW IN v7.0${NC}                                                ${D}┃${NC}"
  echo -e "${D}┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛${NC}"
  echo ""
  echo -e "${Y}[+]${NC} Email Intelligence Pro      ${Y}[+]${NC} Hash Cracker"
  echo -e "${Y}[+]${NC} Company Intelligence        ${Y}[+]${NC} Reverse Geocoding"
  echo -e "${Y}[+]${NC} Messaging App OSINT         ${Y}[+]${NC} Face Recognition"
  echo -e "${Y}[+]${NC} IMEI/Device Tracker         ${Y}[+]${NC} Gaming OSINT"
  echo -e "${Y}[+]${NC} Address OSINT               ${Y}[+]${NC} BIN Lookup"
  echo -e "${Y}[+]${NC} Password Checker            ${Y}[+]${NC} Satellite OSINT"
  echo -e "${Y}[+]${NC} Aviation OSINT              ${Y}[+]${NC} Maritime OSINT"
  echo ""
  echo -e "${D}┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓${NC}"
  echo -e "${D}┃${NC} ${W}MODULE CATEGORIES${NC}                                          ${D}┃${NC}"
  echo -e "${D}┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛${NC}"
  echo ""
  echo -e "${R}[${NC}${W}+${NC}${R}]${NC} Reconnaissance        ${D}:${NC} 2 modules"
  echo -e "${R}[${NC}${W}+${NC}${R}]${NC} Identity & Contacts   ${D}:${NC} 6 modules"
  echo -e "${R}[${NC}${W}+${NC}${R}]${NC} Advanced OSINT        ${D}:${NC} 12 modules"
  echo -e "${R}[${NC}${W}+${NC}${R}]${NC} Security & Threats    ${D}:${NC} 11 modules"
  echo -e "${R}[${NC}${W}+${NC}${R}]${NC} Business Intel        ${D}:${NC} 4 modules"
  echo -e "${R}[${NC}${W}+${NC}${R}]${NC} Gaming & Lifestyle    ${D}:${NC} 2 modules"
  echo -e "${R}[${NC}${W}+${NC}${R}]${NC} GEOINT & Tracking     ${D}:${NC} 4 modules"
  echo -e "${R}[${NC}${W}+${NC}${R}]${NC} Tools & Utilities     ${D}:${NC} 7 modules"
  echo -e "${R}[${NC}${W}+${NC}${R}]${NC} System                ${D}:${NC} 1 module"
  echo ""
  echo -ne "${D}Press ${NC}${W}ENTER${NC}${D} to return...${NC}"
  read
}

# Main loop
while true; do
  show_banner
  show_menu
  read choice
  
  case $choice in
    1|01)
      echo -ne "${R}┌──[${NC}${W}target${NC}${R}]${NC}\n${R}└──╼${NC} ${W}\$${NC} "
      read domain
      run_module node osint-ultra-max.js --domain "$domain"
      ;;
    2|02)
      echo -ne "${R}┌──[${NC}${W}domain${NC}${R}]${NC}\n${R}└──╼${NC} ${W}\$${NC} "
      read domain
      run_module node nmap-scan.js "$domain"
      ;;
    3|03)
      echo -ne "${R}┌──[${NC}${W}email${NC}${R}]${NC}\n${R}└──╼${NC} ${W}\$${NC} "
      read email
      run_module node osint-ultra-max.js --email "$email"
      ;;
    4|04)
      echo -ne "${R}┌──[${NC}${W}phone${NC}${R}]${NC}\n${R}└──╼${NC} ${W}\$${NC} "
      read phone
      run_module node osint-ultra-max.js --phone "$phone"
      ;;
    5|05)
      echo -ne "${R}┌──[${NC}${W}username${NC}${R}]${NC}\n${R}└──╼${NC} ${W}\$${NC} "
      read username
      run_module node osint-ultra-max.js --username "$username"
      ;;
    6|06)
      echo -ne "${R}┌──[${NC}${W}phone${NC}${R}]${NC}\n${R}└──╼${NC} ${W}\$${NC} "
      read phone
      run_module node phone-osint-pro.js "$phone"
      ;;
    7|07)
      echo -ne "${R}┌──[${NC}${W}email${NC}${R}]${NC}\n${R}└──╼${NC} ${W}\$${NC} "
      read email
      run_module node email-intel-pro.js "$email"
      ;;
    8|08)
      echo -ne "${R}┌──[${NC}${W}image${NC}${R}]${NC}\n${R}└──╼${NC} ${W}\$${NC} "
      read image
      run_module node face-recognition.js --image "$image"
      ;;
    9|09)
      echo -ne "${R}┌──[${NC}${W}username${NC}${R}]${NC}\n${R}└──╼${NC} ${W}\$${NC} "
      read username
      run_module node sherlock-search.js "$username"
      ;;
    10)
      echo -ne "${R}┌──[${NC}${W}domain${NC}${R}]${NC}\n${R}└──╼${NC} ${W}\$${NC} "
      read domain
      run_module node theharvester-search.js "$domain"
      ;;
    11)
      echo -ne "${R}┌──[${NC}${W}image${NC}${R}]${NC}\n${R}└──╼${NC} ${W}\$${NC} "
      read image
      run_module node reverse-image-search.js "$image"
      ;;
    12)
      echo -ne "${R}┌──[${NC}${W}target${NC}${R}]${NC}\n${R}└──╼${NC} ${W}\$${NC} "
      read target
      run_module node geo-tracker.js "$target"
      ;;
    13)
      echo -ne "${R}┌──[${NC}${W}profile${NC}${R}]${NC}\n${R}└──╼${NC} ${W}\$${NC} "
      read profile
      run_module node social-scraper.js "$profile"
      ;;
    14)
      echo -ne "${R}┌──[${NC}${W}mac${NC}${R}]${NC}\n${R}└──╼${NC} ${W}\$${NC} "
      read mac
      run_module node mac-lookup.js "$mac"
      ;;
    15)
      echo -ne "${R}┌──[${NC}${W}file${NC}${R}]${NC}\n${R}└──╼${NC} ${W}\$${NC} "
      read file
      run_module node metadata-extractor.js "$file"
      ;;
    16)
      echo -ne "${R}┌──[${NC}${W}domain${NC}${R}]${NC}\n${R}└──╼${NC} ${W}\$${NC} "
      read domain
      run_module node dork-generator.js "$domain"
      ;;
    17)
      echo -ne "${R}┌──[${NC}${W}directory${NC}${R}]${NC}\n${R}└──╼${NC} ${W}\$${NC} "
      read dir
      run_module node exif-mass-scanner.js "$dir"
      ;;
    18)
      echo -ne "${R}┌──[${NC}${W}username${NC}${R}]${NC}\n${R}└──╼${NC} ${W}\$${NC} "
      read username
      run_module node telegram-osint.js "$username"
      ;;
    19)
      echo -ne "${R}┌──[${NC}${W}username${NC}${R}]${NC}\n${R}└──╼${NC} ${W}\$${NC} "
      read username
      run_module node social-finder.js "$username"
      ;;
    20)
      echo -ne "${R}┌──[${NC}${W}identifier${NC}${R}]${NC}\n${R}└──╼${NC} ${W}\$${NC} "
      read identifier
      run_module node messaging-osint.js "$identifier"
      ;;
    21)
      echo -ne "${R}┌──[${NC}${W}email${NC}${R}]${NC}\n${R}└──╼${NC} ${W}\$${NC} "
      read email
      run_module node breach-monitor.js "$email"
      ;;
    22)
      echo -ne "${R}┌──[${NC}${W}email${NC}${R}]${NC}\n${R}└──╼${NC} ${W}\$${NC} "
      read email
      run_module node breach-hunter.js "$email"
      ;;
    23)
      echo -ne "${R}┌──[${NC}${W}keyword${NC}${R}]${NC}\n${R}└──╼${NC} ${W}\$${NC} "
      read keyword
      run_module node darkweb-scanner.js "$keyword"
      ;;
    24)
      echo -ne "${R}┌──[${NC}${W}target${NC}${R}]${NC}\n${R}└──╼${NC} ${W}\$${NC} "
      read target
      run_module node ai-analyzer.js "$target"
      ;;
    25)
      echo -ne "${R}┌──[${NC}${W}address${NC}${R}]${NC}\n${R}└──╼${NC} ${W}\$${NC} "
      read address
      run_module node crypto-tracker.js "$address"
      ;;
    26)
      echo -ne "${R}┌──[${NC}${W}domain${NC}${R}]${NC}\n${R}└──╼${NC} ${W}\$${NC} "
      read domain
      run_module node ssl-analyzer.js "$domain"
      ;;
    27)
      echo -ne "${R}┌──[${NC}${W}ioc${NC}${R}]${NC}\n${R}└──╼${NC} ${W}\$${NC} "
      read ioc
      run_module node ioc-checker.js "$ioc"
      ;;
    28)
      echo ""
      echo -e "${D}[${NC}${W}1${NC}${D}]${NC} Scan repository     ${D}[${NC}${W}2${NC}${D}]${NC} Generate search queries"
      echo -ne "${R}┌──[${NC}${W}mode${NC}${R}]${NC}\n${R}└──╼${NC} ${W}\$${NC} "
      read mode
      echo -ne "${R}┌──[${NC}${W}target${NC}${R}]${NC}\n${R}└──╼${NC} ${W}\$${NC} "
      read target
      if [ "$mode" == "2" ]; then
        run_module node github-secrets.js --search "$target"
      else
        run_module node github-secrets.js "$target"
      fi
      ;;
    29)
      echo -ne "${R}┌──[${NC}${W}ip${NC}${R}]${NC}\n${R}└──╼${NC} ${W}\$${NC} "
      read ip
      run_module node proxy-detector.js "$ip"
      ;;
    30)
      echo -ne "${R}┌──[${NC}${W}hash${NC}${R}]${NC}\n${R}└──╼${NC} ${W}\$${NC} "
      read hash
      run_module node hash-cracker.js "$hash"
      ;;
    31)
      echo -ne "${R}┌──[${NC}${W}password${NC}${R}]${NC}\n${R}└──╼${NC} ${W}\$${NC} "
      read password
      run_module node password-checker.js "$password"
      ;;
    32)
      echo -ne "${R}┌──[${NC}${W}company${NC}${R}]${NC}\n${R}└──╼${NC} ${W}\$${NC} "
      read company
      run_module node company-intelligence.js "$company"
      ;;
    33)
      echo -ne "${R}┌──[${NC}${W}address${NC}${R}]${NC}\n${R}└──╼${NC} ${W}\$${NC} "
      read address
      run_module node address-osint.js "$address"
      ;;
    34)
      echo -ne "${R}┌──[${NC}${W}vin/plate${NC}${R}]${NC}\n${R}└──╼${NC} ${W}\$${NC} "
      read vehicle
      run_module node vehicle-osint.js "$vehicle"
      ;;
    35)
      echo -ne "${R}┌──[${NC}${W}bin${NC}${R}]${NC}\n${R}└──╼${NC} ${W}\$${NC} "
      read bin
      run_module node bin-lookup.js "$bin"
      ;;
    36)
      echo -ne "${R}┌──[${NC}${W}gamertag${NC}${R}]${NC}\n${R}└──╼${NC} ${W}\$${NC} "
      read gamertag
      run_module node gaming-osint.js "$gamertag"
      ;;
    37)
      echo -ne "${R}┌──[${NC}${W}imei${NC}${R}]${NC}\n${R}└──╼${NC} ${W}\$${NC} "
      read imei
      run_module node imei-tracker.js "$imei"
      ;;
    38)
      echo -ne "${R}┌──[${NC}${W}coordinates${NC}${R}]${NC}\n${R}└──╼${NC} ${W}\$${NC} "
      read coords
      run_module node satellite-osint.js --coords "$coords"
      ;;
    39)
      echo -ne "${R}┌──[${NC}${W}coordinates${NC}${R}]${NC}\n${R}└──╼${NC} ${W}\$${NC} "
      read coords
      run_module node reverse-geocoding.js "$coords"
      ;;
    40)
      echo -ne "${R}┌──[${NC}${W}tail/flight${NC}${R}]${NC}\n${R}└──╼${NC} ${W}\$${NC} "
      read flight
      run_module node aviation-osint.js --tail "$flight"
      ;;
    41)
      echo -ne "${R}┌──[${NC}${W}vessel${NC}${R}]${NC}\n${R}└──╼${NC} ${W}\$${NC} "
      read vessel
      run_module node maritime-osint.js --vessel "$vessel"
      ;;
    42)
      echo ""
      echo -e "${D}Categories:${NC}"
      echo -e "${D}[${NC}${W}1${NC}${D}]${NC} YouTube     ${D}[${NC}${W}2${NC}${D}]${NC} Wikipedia   ${D}[${NC}${W}3${NC}${D}]${NC} News"
      echo -e "${D}[${NC}${W}4${NC}${D}]${NC} Telegram    ${D}[${NC}${W}5${NC}${D}]${NC} GitHub      ${D}[${NC}${W}6${NC}${D}]${NC} Reddit"
      echo -e "${D}[${NC}${W}7${NC}${D}]${NC} Spotify     ${D}[${NC}${W}8${NC}${D}]${NC} Instagram   ${D}[${NC}${W}9${NC}${D}]${NC} Random"
      echo -ne "${R}┌──[${NC}${W}category${NC}${R}]${NC}\n${R}└──╼${NC} ${W}\$${NC} "
      read c
      case $c in
        1) cat="youtube" ;;
        2) cat="wikipedia" ;;
        3) cat="news" ;;
        4) cat="telegram" ;;
        5) cat="github" ;;
        6) cat="reddit" ;;
        7) cat="spotify" ;;
        8) cat="instagram" ;;
        9) cat="random" ;;
        *) cat="random" ;;
      esac
      run_module node ip-grabber.js "$cat"
      ;;
    43)
      run_module node wifi-analyzer.js
      ;;
    44)
      echo -ne "${R}┌──[${NC}${W}image${NC}${R}]${NC}\n${R}└──╼${NC} ${W}\$${NC} "
      read img
      run_module node qr-tools.js "$img"
      ;;
    45)
      echo -ne "${R}┌──[${NC}${W}text${NC}${R}]${NC}\n${R}└──╼${NC} ${W}\$${NC} "
      read text
      run_module node secret-language-cracker.js "$text"
      ;;
    46)
      echo -ne "${R}┌──[${NC}${W}query${NC}${R}]${NC}\n${R}└──╼${NC} ${W}\$${NC} "
      read query
      run_module node dork-search-pro.js "$query"
      ;;
    47)
      echo -ne "${R}┌──[${NC}${W}query${NC}${R}]${NC}\n${R}└──╼${NC} ${W}\$${NC} "
      read query
      run_module node torbot-osint.js "$query"
      ;;
    48)
      echo ""
      echo -e "${D}[${NC}${W}1${NC}${D}]${NC} Person (Email/Phone/Username)"
      echo -e "${D}[${NC}${W}2${NC}${D}]${NC} Domain/Company"
      echo -e "${D}[${NC}${W}3${NC}${D}]${NC} Location (Coordinates)"
      echo -ne "${R}┌──[${NC}${W}type${NC}${R}]${NC}\n${R}└──╼${NC} ${W}\$${NC} "
      read report_type
      echo -ne "${R}┌──[${NC}${W}target${NC}${R}]${NC}\n${R}└──╼${NC} ${W}\$${NC} "
      read target
      
      echo -e "${D}[${NC}${W}*${NC}${D}]${NC} Generating comprehensive OSINT report..."
      echo ""
      
      case $report_type in
        1)
          echo -e "${R}[${NC}${W}+${NC}${R}]${NC} Running Email Intelligence..."
          node email-intel-pro.js "$target" --save 2>/dev/null
          echo -e "${R}[${NC}${W}+${NC}${R}]${NC} Running Breach Hunter..."
          node breach-hunter.js "$target" --save 2>/dev/null
          echo -e "${R}[${NC}${W}+${NC}${R}]${NC} Running Sherlock Search..."
          node sherlock-search.js "$target" --save 2>/dev/null
          echo -e "${R}[${NC}${W}+${NC}${R}]${NC} Running Social Finder..."
          node social-finder.js "$target" --save 2>/dev/null
          ;;
        2)
          echo -e "${R}[${NC}${W}+${NC}${R}]${NC} Running Domain Intelligence..."
          node osint-ultra-max.js --domain "$target" --save 2>/dev/null
          echo -e "${R}[${NC}${W}+${NC}${R}]${NC} Running Company Intelligence..."
          node company-intelligence.js "$target" --save 2>/dev/null
          echo -e "${R}[${NC}${W}+${NC}${R}]${NC} Running Email Harvesting..."
          node theharvester-search.js "$target" --save 2>/dev/null
          ;;
        3)
          echo -e "${R}[${NC}${W}+${NC}${R}]${NC} Running Reverse Geocoding..."
          node reverse-geocoding.js "$target" --save 2>/dev/null
          echo -e "${R}[${NC}${W}+${NC}${R}]${NC} Running Satellite OSINT..."
          node satellite-osint.js --coords "$target" --save 2>/dev/null
          ;;
      esac
      
      echo ""
      echo -e "${G}[${NC}${W}✓${NC}${G}]${NC} Reports generated in respective folders"
      echo ""
      echo -ne "${D}Press ${NC}${W}ENTER${NC}${D} to continue...${NC}"
      read
      ;;
    99)
      show_info
      ;;
    0|00)
      clear
      echo -e "${R}"
      cat << "EXITBANNER"
   ╔═══════════════════════════════════════╗
   ║                                       ║
   ║     SESSION TERMINATED                ║
   ║                                       ║
   ║     Thanks for using NIKA OSINT       ║
   ║                                       ║
   ║     Stay curious, stay safe! 🥝       ║
   ║                                       ║
   ╚═══════════════════════════════════════╝
EXITBANNER
      echo -e "${NC}"
      exit 0
      ;;
    *)
      echo -e "${R}[${NC}${W}!${NC}${R}]${NC} Invalid option"
      sleep 1
      ;;
  esac
done
