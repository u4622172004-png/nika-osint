#!/data/data/com.termux/files/usr/bin/bash

# ============================================
# NIKA OSINT ULTRA v3.0 - Complete Menu
# by kiwi & 777
# ============================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
GRAY='\033[0;90m'
NC='\033[0m'
BOLD='\033[1m'

show_banner() {
    clear
    echo -e "${RED}${BOLD}"
    echo "  ███╗   ██╗██╗██╗  ██╗ █████╗ "
    echo "  ████╗  ██║██║██║ ██╔╝██╔══██╗"
    echo "  ██╔██╗ ██║██║█████╔╝ ███████║"
    echo "  ██║╚██╗██║██║██╔═██╗ ██╔══██║"
    echo "  ██║ ╚████║██║██║  ██╗██║  ██║"
    echo "  ╚═╝  ╚═══╝╚═╝╚═╝  ╚═╝╚═╝  ╚═╝"
    echo -e "${NC}"
    echo -e "${MAGENTA}${BOLD}        🥝 OSINT ULTRA v3.0 🥝${NC}"
    echo -e "${CYAN}    Advanced Intelligence Gathering${NC}"
    echo -e "${GRAY}          by kiwi & 777${NC}"
    echo ""
    echo -e "${YELLOW}════════════════════════════════════════${NC}"
    echo ""
}

show_menu() {
    echo -e "${CYAN}${BOLD}┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓${NC}"
    echo -e "${CYAN}${BOLD}┃          🎯 MAIN MENU 🎯             ┃${NC}"
    echo -e "${CYAN}${BOLD}┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛${NC}"
    echo ""
    echo -e "${WHITE}${BOLD}  RECONNAISSANCE${NC}"
    echo -e "${GREEN}  [1]${NC} 🌐 Domain Intelligence      ${GRAY}(DNS, WHOIS, Security)${NC}"
    echo -e "${GREEN}  [2]${NC} 🔍 Subdomain Enumeration     ${GRAY}(Brute + CT logs)${NC}"
    echo -e "${GREEN}  [3]${NC} 🔓 Nmap Port Scan            ${GRAY}(8 scan types)${NC}"
    echo ""
    echo -e "${WHITE}${BOLD}  IDENTITY & CONTACTS${NC}"
    echo -e "${GREEN}  [4]${NC} 📧 Email Analysis            ${GRAY}(Breach + Reputation)${NC}"
    echo -e "${GREEN}  [5]${NC} 📱 Phone Lookup              ${GRAY}(45+ Auto Search)${NC}"
    echo -e "${GREEN}  [6]${NC} 👤 Username Footprint        ${GRAY}(25+ Platforms)${NC}"
    echo ""
    echo -e "${WHITE}${BOLD}  ADVANCED OSINT${NC}"
    echo -e "${GREEN}  [7]${NC} 🕵️  Sherlock Username Search  ${GRAY}(50+ Sites)${NC}"
    echo -e "${GREEN}  [8]${NC} 📧 Email Harvesting          ${GRAY}(TheHarvester)${NC}"
    echo -e "${GREEN}  [9]${NC} 🖼️  Reverse Image Search      ${GRAY}(9 Engines + GPS)${NC}"
    echo ""
    echo -e "${WHITE}${BOLD}  TOOLS & UTILITIES${NC}"
    echo -e "${GREEN} [10]${NC} 🎣 IP Grabber Generator      ${GRAY}(Grabify + More)${NC}"
    echo -e "${GREEN} [11]${NC} 📊 Full Report               ${GRAY}(All-in-One Scan)${NC}"
    echo ""
    echo -e "${YELLOW} [12]${NC} ℹ️  Info & Features"
    echo -e "${YELLOW}  [0]${NC} ❌ Exit"
    echo ""
    echo -e "${CYAN}┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄${NC}"
    echo -ne "${WHITE}${BOLD}  ➤ Select [0-12]: ${NC}"
}

domain_search() {
    clear
    show_banner
    echo -e "${GREEN}${BOLD}┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓${NC}"
    echo -e "${GREEN}${BOLD}┃      🌐 DOMAIN INTELLIGENCE         ┃${NC}"
    echo -e "${GREEN}${BOLD}┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛${NC}"
    echo ""
    echo -e "${CYAN}Features:${NC}"
    echo -e "  ${GRAY}•${NC} DNS Records (A, MX, NS, TXT, etc.)"
    echo -e "  ${GRAY}•${NC} WHOIS Information"
    echo -e "  ${GRAY}•${NC} Email Security (SPF, DMARC, DKIM)"
    echo -e "  ${GRAY}•${NC} Security Headers Analysis"
    echo -e "  ${GRAY}•${NC} TLS Certificate Info"
    echo -e "  ${GRAY}•${NC} Blacklist Check (7 lists)"
    echo -e "  ${GRAY}•${NC} Technology Detection"
    echo -e "  ${GRAY}•${NC} 50+ Google Dorks"
    echo -e "  ${GRAY}•${NC} Shodan, VirusTotal, CVE Search"
    echo ""
    echo -ne "${YELLOW}➤ Enter domain: ${NC}"
    read domain
    
    if [ -z "$domain" ]; then
        echo -e "${RED}✗ Invalid domain${NC}"
        sleep 2
        return
    fi
    
    echo ""
    echo -e "${CYAN}⏳ Scanning ${domain}...${NC}"
    echo ""
    
    if [ -f "osint-ultra-max.js" ]; then
        node osint-ultra-max.js --domain "$domain" --save
    else
        echo -e "${RED}✗ Core module not found${NC}"
    fi
    
    echo ""
    echo -e "${GREEN}✓ Results saved in ./reports/${NC}"
    echo ""
    read -p "Press ENTER to continue..."
}

subdomain_scan() {
    clear
    show_banner
    echo -e "${GREEN}${BOLD}┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓${NC}"
    echo -e "${GREEN}${BOLD}┃     🔍 SUBDOMAIN ENUMERATION        ┃${NC}"
    echo -e "${GREEN}${BOLD}┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛${NC}"
    echo ""
    echo -e "${CYAN}Features:${NC}"
    echo -e "  ${GRAY}•${NC} Brute-force with wordlist (100+ entries)"
    echo -e "  ${GRAY}•${NC} Certificate Transparency (crt.sh)"
    echo -e "  ${GRAY}•${NC} Automatic IP resolution"
    echo -e "  ${GRAY}•${NC} Source tracking"
    echo ""
    echo -ne "${YELLOW}➤ Enter domain: ${NC}"
    read domain
    
    if [ -z "$domain" ]; then
        echo -e "${RED}✗ Invalid domain${NC}"
        sleep 2
        return
    fi
    
    echo ""
    echo -e "${CYAN}⏳ Enumerating subdomains for ${domain}...${NC}"
    echo -e "${GRAY}   This may take 2-5 minutes...${NC}"
    echo ""
    
    if [ -f "osint-ultra-max.js" ]; then
        node osint-ultra-max.js --domain "$domain" --save
    else
        echo -e "${RED}✗ Core module not found${NC}"
    fi
    
    echo ""
    echo -e "${GREEN}✓ Results saved in ./reports/${NC}"
    echo ""
    read -p "Press ENTER to continue..."
}

nmap_scan() {
    clear
    show_banner
    echo -e "${GREEN}${BOLD}┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓${NC}"
    echo -e "${GREEN}${BOLD}┃        🔓 NMAP PORT SCAN            ┃${NC}"
    echo -e "${GREEN}${BOLD}┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛${NC}"
    echo ""
    echo -ne "${YELLOW}➤ Target (domain or IP): ${NC}"
    read target
    
    if [ -z "$target" ]; then
        echo -e "${RED}✗ Invalid target${NC}"
        sleep 2
        return
    fi
    
    echo ""
    echo -e "${CYAN}${BOLD}┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓${NC}"
    echo -e "${CYAN}${BOLD}┃        SELECT SCAN TYPE             ┃${NC}"
    echo -e "${CYAN}${BOLD}┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛${NC}"
    echo ""
    echo -e "${GREEN}  [1]${NC} 🚀 Basic            ${GRAY}(Service detection, ~2 min)${NC}"
    echo -e "${GREEN}  [2]${NC} ⚡ Fast             ${GRAY}(Top 100 ports, ~30 sec)${NC}"
    echo -e "${GREEN}  [3]${NC} 🔥 Vulnerability    ${GRAY}(CVE detection, ~5 min)${NC}"
    echo -e "${GREEN}  [4]${NC} 🔐 SSL/TLS          ${GRAY}(Certificate analysis, ~1 min)${NC}"
    echo -e "${GREEN}  [5]${NC} 🌐 Web Enumeration  ${GRAY}(HTTP info, ~2 min)${NC}"
    echo -e "${GREEN}  [6]${NC} 💥 Aggressive       ${GRAY}(OS + traceroute, ~5 min)${NC}"
    echo -e "${GREEN}  [7]${NC} 📡 Full Scan        ${GRAY}(All 65535 ports, ~30 min)${NC}"
    echo ""
    echo -ne "${YELLOW}➤ Select [1-7]: ${NC}"
    read scan_choice
    
    case $scan_choice in
        1) type="basic" ;;
        2) type="fast" ;;
        3) type="vuln" ;;
        4) type="ssl" ;;
        5) type="web" ;;
        6) type="aggressive" ;;
        7) type="full" ;;
        *) type="basic" ;;
    esac
    
    echo ""
    echo -e "${CYAN}⏳ Running ${type} scan on ${target}...${NC}"
    echo ""
    
    if [ -f "nmap-scan.js" ]; then
        node nmap-scan.js --type $type "$target" --save
    else
        echo -e "${RED}✗ nmap-scan.js not found${NC}"
    fi
    
    echo ""
    read -p "Press ENTER to continue..."
}

email_analysis() {
    clear
    show_banner
    echo -e "${GREEN}${BOLD}┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓${NC}"
    echo -e "${GREEN}${BOLD}┃        📧 EMAIL ANALYSIS            ┃${NC}"
    echo -e "${GREEN}${BOLD}┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛${NC}"
    echo ""
    echo -e "${CYAN}Features:${NC}"
    echo -e "  ${GRAY}•${NC} Format Validation"
    echo -e "  ${GRAY}•${NC} MX Records Check"
    echo -e "  ${GRAY}•${NC} Disposable Email Detection"
    echo -e "  ${GRAY}•${NC} Gravatar Profile Lookup"
    echo -e "  ${GRAY}•${NC} Breach Check (HaveIBeenPwned, DeHashed)"
    echo -e "  ${GRAY}•${NC} Paste Sites Search"
    echo -e "  ${GRAY}•${NC} 6+ Reputation Services"
    echo ""
    echo -ne "${YELLOW}➤ Enter email: ${NC}"
    read email
    
    if [ -z "$email" ]; then
        echo -e "${RED}✗ Invalid email${NC}"
        sleep 2
        return
    fi
    
    echo ""
    echo -e "${CYAN}⏳ Analyzing ${email}...${NC}"
    echo ""
    
    if [ -f "osint-ultra-max.js" ]; then
        node osint-ultra-max.js --email "$email" --save
    else
        echo -e "${RED}✗ Core module not found${NC}"
    fi
    
    echo ""
    echo -e "${GREEN}✓ Results saved in ./reports/${NC}"
    echo ""
    read -p "Press ENTER to continue..."
}

phone_lookup() {
    clear
    show_banner
    echo -e "${GREEN}${BOLD}┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓${NC}"
    echo -e "${GREEN}${BOLD}┃   📱 PHONE LOOKUP + AUTO SEARCH     ┃${NC}"
    echo -e "${GREEN}${BOLD}┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛${NC}"
    echo ""
    echo -e "${CYAN}Features:${NC}"
    echo -e "  ${GRAY}•${NC} Carrier Detection (Italy: TIM, Vodafone, Wind Tre)"
    echo -e "  ${GRAY}•${NC} Location & Timezone"
    echo -e "  ${GRAY}•${NC} Number Type (Mobile, Landline, VoIP)"
    echo -e "  ${GRAY}•${NC} Social Media (WhatsApp, Telegram, Signal)"
    echo -e "  ${GRAY}•${NC} Auto Search: 45+ Sources"
    echo ""
    echo -e "${YELLOW}Format: ${CYAN}+[country][number]${NC}"
    echo -e "${GRAY}Example: +393331234567${NC}"
    echo ""
    echo -ne "${YELLOW}➤ Enter phone: ${NC}"
    read phone
    
    if [ -z "$phone" ]; then
        echo -e "${RED}✗ Invalid phone number${NC}"
        sleep 2
        return
    fi
    
    echo ""
    echo -e "${CYAN}⏳ Analyzing + Searching 45+ sources...${NC}"
    echo ""
    
    if [ -f "osint-ultra-max.js" ]; then
        node osint-ultra-max.js --phone "$phone" --save
    else
        echo -e "${RED}✗ Core module not found${NC}"
    fi
    
    echo ""
    echo -e "${GREEN}✓ Results saved in ./reports/${NC}"
    echo ""
    read -p "Press ENTER to continue..."
}

username_search() {
    clear
    show_banner
    echo -e "${GREEN}${BOLD}┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓${NC}"
    echo -e "${GREEN}${BOLD}┃      👤 USERNAME FOOTPRINT          ┃${NC}"
    echo -e "${GREEN}${BOLD}┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛${NC}"
    echo ""
    echo -e "${CYAN}Search across 25+ platforms:${NC}"
    echo -e "  ${GRAY}•${NC} Social: GitHub, Reddit, Twitter, Instagram, TikTok"
    echo -e "  ${GRAY}•${NC} Professional: LinkedIn, Medium, DevTo"
    echo -e "  ${GRAY}•${NC} Media: YouTube, Twitch, Spotify, SoundCloud"
    echo -e "  ${GRAY}•${NC} Creative: Pinterest, Behance, Dribbble"
    echo -e "  ${GRAY}•${NC} Tech: GitLab, BitBucket, StackOverflow"
    echo ""
    echo -ne "${YELLOW}➤ Enter username: ${NC}"
    read username
    
    if [ -z "$username" ]; then
        echo -e "${RED}✗ Invalid username${NC}"
        sleep 2
        return
    fi
    
    echo ""
    echo -e "${CYAN}⏳ Searching 25+ platforms...${NC}"
    echo ""
    
    if [ -f "osint-ultra-max.js" ]; then
        node osint-ultra-max.js --username "$username" --save
    else
        echo -e "${RED}✗ Core module not found${NC}"
    fi
    
    echo ""
    echo -e "${GREEN}✓ Results saved in ./reports/${NC}"
    echo ""
    read -p "Press ENTER to continue..."
}

sherlock_search() {
    clear
    show_banner
    echo -e "${GREEN}${BOLD}┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓${NC}"
    echo -e "${GREEN}${BOLD}┃    🕵️  SHERLOCK USERNAME SEARCH      ┃${NC}"
    echo -e "${GREEN}${BOLD}┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛${NC}"
    echo ""
    echo -e "${CYAN}Search username across 50+ platforms:${NC}"
    echo -e "  ${GRAY}•${NC} Social: Facebook, Twitter, Instagram, TikTok, Pinterest"
    echo -e "  ${GRAY}•${NC} Professional: LinkedIn, AngelList, Crunchbase"
    echo -e "  ${GRAY}•${NC} Developer: GitHub, GitLab, StackOverflow, DevTo"
    echo -e "  ${GRAY}•${NC} Gaming: Steam, Twitch, Xbox, PlayStation, Roblox"
    echo -e "  ${GRAY}•${NC} Creative: Behance, Dribbble, SoundCloud, Spotify"
    echo -e "  ${GRAY}•${NC} And many more..."
    echo ""
    echo -ne "${YELLOW}➤ Enter username: ${NC}"
    read username
    
    if [ -z "$username" ]; then
        echo -e "${RED}✗ Invalid username${NC}"
        sleep 2
        return
    fi
    
    echo ""
    echo -e "${CYAN}⏳ Searching 50+ platforms for ${username}...${NC}"
    echo ""
    
    if [ -f "sherlock-search.js" ]; then
        node sherlock-search.js "$username" --save
    else
        echo -e "${RED}✗ sherlock-search.js not found${NC}"
    fi
    
    echo ""
    read -p "Press ENTER to continue..."
}

email_harvesting() {
    clear
    show_banner
    echo -e "${GREEN}${BOLD}┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓${NC}"
    echo -e "${GREEN}${BOLD}┃       📧 EMAIL HARVESTING           ┃${NC}"
    echo -e "${GREEN}${BOLD}┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛${NC}"
    echo ""
    echo -e "${CYAN}Features:${NC}"
    echo -e "  ${GRAY}•${NC} Extract emails from domain"
    echo -e "  ${GRAY}•${NC} Search engines (Google, Bing, LinkedIn)"
    echo -e "  ${GRAY}•${NC} Find subdomains"
    echo -e "  ${GRAY}•${NC} Discover hosts & IPs"
    echo -e "  ${GRAY}•${NC} Generate manual search queries"
    echo ""
    echo -ne "${YELLOW}➤ Enter domain: ${NC}"
    read domain
    
    if [ -z "$domain" ]; then
        echo -e "${RED}✗ Invalid domain${NC}"
        sleep 2
        return
    fi
    
    echo ""
    echo -e "${CYAN}⏳ Harvesting emails from ${domain}...${NC}"
    echo -e "${GRAY}   This may take 3-5 minutes...${NC}"
    echo ""
    
    if [ -f "theharvester-search.js" ]; then
        node theharvester-search.js "$domain" --save
    else
        echo -e "${RED}✗ theharvester-search.js not found${NC}"
    fi
    
    echo ""
    read -p "Press ENTER to continue..."
}

reverse_image_search() {
    clear
    show_banner
    echo -e "${GREEN}${BOLD}┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓${NC}"
    echo -e "${GREEN}${BOLD}┃     🖼️  REVERSE IMAGE SEARCH         ┃${NC}"
    echo -e "${GREEN}${BOLD}┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛${NC}"
    echo ""
    echo -e "${CYAN}Features:${NC}"
    echo -e "  ${GRAY}•${NC} 9 Search Engines (Google, Yandex, TinEye, etc.)"
    echo -e "  ${GRAY}•${NC} Extract GPS coordinates from metadata"
    echo -e "  ${GRAY}•${NC} Camera info, timestamps, software"
    echo -e "  ${GRAY}•${NC} Generate search URLs"
    echo ""
    echo -e "${CYAN}${BOLD}┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓${NC}"
    echo -e "${CYAN}${BOLD}┃        SELECT INPUT METHOD          ┃${NC}"
    echo -e "${CYAN}${BOLD}┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛${NC}"
    echo ""
    echo -e "${GREEN}  [1]${NC} 📁 Local File"
    echo -e "${GREEN}  [2]${NC} 🔗 Image URL"
    echo ""
    echo -ne "${YELLOW}➤ Select [1-2]: ${NC}"
    read input_choice
    
    if [ "$input_choice" == "1" ]; then
        echo ""
        echo -ne "${YELLOW}➤ Enter image path: ${NC}"
        read image_path
        
        if [ -z "$image_path" ] || [ ! -f "$image_path" ]; then
            echo -e "${RED}✗ Image file not found${NC}"
            sleep 2
            return
        fi
        
        echo ""
        echo -e "${CYAN}⏳ Analyzing image and generating search URLs...${NC}"
        echo ""
        
        if [ -f "reverse-image-search.js" ]; then
            node reverse-image-search.js --file "$image_path" --save results.json
        else
            echo -e "${RED}✗ reverse-image-search.js not found${NC}"
        fi
        
    elif [ "$input_choice" == "2" ]; then
        echo ""
        echo -ne "${YELLOW}➤ Enter image URL: ${NC}"
        read image_url
        
        if [ -z "$image_url" ]; then
            echo -e "${RED}✗ Invalid URL${NC}"
            sleep 2
            return
        fi
        
        echo ""
        echo -e "${CYAN}⏳ Generating search URLs...${NC}"
        echo ""
        
        if [ -f "reverse-image-search.js" ]; then
            node reverse-image-search.js --url "$image_url"
        else
            echo -e "${RED}✗ reverse-image-search.js not found${NC}"
        fi
    else
        echo -e "${RED}✗ Invalid choice${NC}"
        sleep 2
        return
    fi
    
    echo ""
    read -p "Press ENTER to continue..."
}

ip_grabber() {
    clear
    show_banner
    echo -e "${GREEN}${BOLD}┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓${NC}"
    echo -e "${GREEN}${BOLD}┃     🎣 IP GRABBER GENERATOR         ┃${NC}"
    echo -e "${GREEN}${BOLD}┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛${NC}"
    echo ""
    echo -e "${CYAN}${BOLD}┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓${NC}"
    echo -e "${CYAN}${BOLD}┃        SELECT URL CATEGORY          ┃${NC}"
    echo -e "${CYAN}${BOLD}┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛${NC}"
    echo ""
    echo -e "${GREEN}  [1]${NC} 📺 YouTube"
    echo -e "${GREEN}  [2]${NC} 📚 Wikipedia"
    echo -e "${GREEN}  [3]${NC} 📰 News Sites"
    echo -e "${GREEN}  [4]${NC} 💬 Telegram"
    echo -e "${GREEN}  [5]${NC} 💻 GitHub"
    echo -e "${GREEN}  [6]${NC} 🔴 Reddit"
    echo -e "${GREEN}  [7]${NC} 🎵 Spotify"
    echo -e "${GREEN}  [8]${NC} 📸 Instagram"
    echo -e "${GREEN}  [9]${NC} 🎲 Random"
    echo ""
    echo -ne "${YELLOW}➤ Select [1-9]: ${NC}"
    read cat_choice
    
    case $cat_choice in
        1) category="youtube" ;;
        2) category="wikipedia" ;;
        3) category="news" ;;
        4) category="telegram" ;;
        5) category="github" ;;
        6) category="reddit" ;;
        7) category="spotify" ;;
        8) category="instagram" ;;
        9) category="random" ;;
        *) category="random" ;;
    esac
    
    echo ""
    
    if [ -f "osint-ultra-max.js" ]; then
        node osint-ultra-max.js --grabber $category
    else
        echo -e "${RED}✗ Core module not found${NC}"
    fi
    
    echo ""
    read -p "Press ENTER to continue..."
}

full_report() {
    clear
    show_banner
    echo -e "${GREEN}${BOLD}┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓${NC}"
    echo -e "${GREEN}${BOLD}┃    📊 COMPREHENSIVE RECON SCAN      ┃${NC}"
    echo -e "${GREEN}${BOLD}┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛${NC}"
    echo ""
    echo -e "${CYAN}Combine multiple scans for complete intelligence${NC}"
    echo -e "${YELLOW}Leave blank to skip${NC}"
    echo ""
    echo -ne "${CYAN}➤ Domain: ${NC}"
    read domain
    echo -ne "${CYAN}➤ Email: ${NC}"
    read email
    echo -ne "${CYAN}➤ Phone: ${NC}"
    read phone
    echo -ne "${CYAN}➤ Username: ${NC}"
    read username
    
    if [ -z "$domain" ] && [ -z "$email" ] && [ -z "$phone" ] && [ -z "$username" ]; then
        echo ""
        echo -e "${RED}✗ At least one parameter required${NC}"
        sleep 2
        return
    fi
    
    echo ""
    echo -e "${CYAN}⏳ Generating comprehensive report...${NC}"
    echo ""
    
    if [ -f "osint-ultra-max.js" ]; then
        cmd="node osint-ultra-max.js --save"
        [ -n "$domain" ] && cmd="$cmd --domain $domain"
        [ -n "$email" ] && cmd="$cmd --email $email"
        [ -n "$phone" ] && cmd="$cmd --phone $phone"
        [ -n "$username" ] && cmd="$cmd --username $username"
        eval $cmd
    else
        echo -e "${RED}✗ Core module not found${NC}"
    fi
    
    echo ""
    echo -e "${GREEN}✓ Complete report saved in ./reports/${NC}"
    echo ""
    read -p "Press ENTER to continue..."
}

show_info() {
    clear
    show_banner
    echo -e "${CYAN}${BOLD}┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓${NC}"
    echo -e "${CYAN}${BOLD}┃         INFO & FEATURES             ┃${NC}"
    echo -e "${CYAN}${BOLD}┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛${NC}"
    echo ""
    echo -e "${GREEN}${BOLD}✨ NIKA OSINT ULTRA v3.0${NC}"
    echo ""
    echo -e "${YELLOW}${BOLD}NEW in v3.0:${NC}"
    echo -e "  ${GREEN}✓${NC} Phone Auto Search (45+ sources)"
    echo -e "  ${GREEN}✓${NC} IP Grabber Generator"
    echo -e "  ${GREEN}✓${NC} Nmap Integration (8 scan types)"
    echo -e "  ${GREEN}✓${NC} Sherlock Username Search (50+ sites)"
    echo -e "  ${GREEN}✓${NC} Email Harvesting (TheHarvester)"
    echo -e "  ${GREEN}✓${NC} Reverse Image Search (9 engines + GPS)"
    echo -e "  ${GREEN}✓${NC} Enhanced Google Dorks (50+)"
    echo -e "  ${GREEN}✓${NC} CVE Vulnerability Search"
    echo ""
    echo -e "${YELLOW}${BOLD}Core Features:${NC}"
    echo -e "  ${GRAY}•${NC} 150+ Intelligence Sources"
    echo -e "  ${GRAY}•${NC} Domain Intelligence (54+ checks)"
    echo -e "  ${GRAY}•${NC} Subdomain Enumeration"
    echo -e "  ${GRAY}•${NC} Email Analysis (12+ checks)"
    echo -e "  ${GRAY}•${NC} Phone Lookup + Auto Search"
    echo -e "  ${GRAY}•${NC} Username Search (25+ platforms)"
    echo -e "  ${GRAY}•${NC} Sherlock Search (50+ platforms)"
    echo -e "  ${GRAY}•${NC} IP Geolocation"
    echo -e "  ${GRAY}•${NC} Nmap Port Scanning"
    echo -e "  ${GRAY}•${NC} Auto-save Reports (JSON + TXT)"
    echo ""
    echo -e "${YELLOW}${BOLD}Reports Location:${NC}"
    echo -e "  ${CYAN}./reports/${NC}           ${GRAY}(OSINT scans)${NC}"
    echo -e "  ${CYAN}./nmap-reports/${NC}      ${GRAY}(Nmap scans)${NC}"
    echo -e "  ${CYAN}./sherlock-reports/${NC}  ${GRAY}(Sherlock searches)${NC}"
    echo -e "  ${CYAN}./harvester-reports/${NC} ${GRAY}(Email harvesting)${NC}"
    echo ""
    echo -e "${YELLOW}${BOLD}Authors:${NC}"
    echo -e "  ${MAGENTA}🥝 kiwi & 777${NC}"
    echo ""
    echo -e "${YELLOW}${BOLD}GitHub:${NC}"
    echo -e "  ${CYAN}https://github.com/u4622172004-png/nika-osint${NC}"
    echo ""
    echo -e "${RED}${BOLD}⚠️  LEGAL NOTICE:${NC}"
    echo -e "  ${GRAY}For authorized security research and${NC}"
    echo -e "  ${GRAY}educational purposes only.${NC}"
    echo ""
    read -p "Press ENTER to continue..."
}

main() {
    while true; do
        show_banner
        show_menu
        read choice
        
        case $choice in
            1) domain_search ;;
            2) subdomain_scan ;;
            3) nmap_scan ;;
            4) email_analysis ;;
            5) phone_lookup ;;
            6) username_search ;;
            7) sherlock_search ;;
            8) email_harvesting ;;
            9) reverse_image_search ;;
            10) ip_grabber ;;
            11) full_report ;;
            12) show_info ;;
            0) 
                clear
                echo ""
                echo -e "${MAGENTA}${BOLD}  ╔═══════════════════════════════════════╗${NC}"
                echo -e "${MAGENTA}${BOLD}  ║  🥝 Thanks for using NIKA OSINT! 🥝  ║${NC}"
                echo -e "${MAGENTA}${BOLD}  ╚═══════════════════════════════════════╝${NC}"
                echo ""
                echo -e "${CYAN}        Stay curious, stay safe! 🔐${NC}"
                echo ""
                sleep 1
                exit 0
                ;;
            *)
                echo ""
                echo -e "${RED}✗ Invalid option. Please select 0-12${NC}"
                sleep 1
                ;;
        esac
    done
}

main
