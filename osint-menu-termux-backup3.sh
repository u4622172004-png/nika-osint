#!/data/data/com.termux/files/usr/bin/bash

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
WHITE='\033[1;37m'
GRAY='\033[0;90m'
NC='\033[0m'
BOLD='\033[1m'
DIM='\033[2m'

# Gradient colors
RED1='\033[38;5;196m'
RED2='\033[38;5;160m'
ORANGE='\033[38;5;208m'
PINK='\033[38;5;205m'
PURPLE='\033[38;5;129m'
BLUE1='\033[38;5;39m'
GREEN1='\033[38;5;46m'
GREEN2='\033[38;5;40m'

show_banner() {
    clear
    echo ""
    echo -e "${RED1}          ███╗   ██╗██╗██╗  ██╗ █████╗ ${NC}"
    echo -e "${RED2}          ████╗  ██║██║██║ ██╔╝██╔══██╗${NC}"
    echo -e "${ORANGE}          ██╔██╗ ██║██║█████╔╝ ███████║${NC}"
    echo -e "${YELLOW}          ██║╚██╗██║██║██╔═██╗ ██╔══██║${NC}"
    echo -e "${GREEN1}          ██║ ╚████║██║██║  ██╗██║  ██║${NC}"
    echo -e "${GREEN2}          ╚═╝  ╚═══╝╚═╝╚═╝  ╚═╝╚═╝  ╚═╝${NC}"
    echo ""
    echo -e "          ${PINK}╔═══════════════════════════════════╗${NC}"
    echo -e "          ${PINK}║${NC}  ${CYAN}🥝 ${BOLD}${WHITE}OSINT ULTRA ${CYAN}v5.0 🥝${NC}  ${PINK}║${NC}"
    echo -e "          ${PINK}╚═══════════════════════════════════╝${NC}"
    echo ""
    echo -e "     ${DIM}${GRAY}┌─────────────────────────────────────────────┐${NC}"
    echo -e "     ${DIM}${GRAY}│${NC}  ${CYAN}Advanced Intelligence Gathering Toolkit${NC}  ${DIM}${GRAY}│${NC}"
    echo -e "     ${DIM}${GRAY}│${NC}     ${MAGENTA}21 Modules${NC} ${DIM}${GRAY}│ ${YELLOW}⚡ 150+ Sources${NC}     ${DIM}${GRAY}│${NC}"
    echo -e "     ${DIM}${GRAY}└─────────────────────────────────────────────┘${NC}"
    echo ""
}

show_menu() {
    echo -e "${PURPLE}╔═══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${PURPLE}║              ${BOLD}${WHITE}🎯  M A I N   M E N U  🎯${NC}                    ${PURPLE}║${NC}"
    echo -e "${PURPLE}╚═══════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    echo -e "${CYAN}┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓${NC}"
    echo -e "${CYAN}┃${NC} ${BOLD}${WHITE}🔍 RECONNAISSANCE${NC}                                          ${CYAN}┃${NC}"
    echo -e "${CYAN}┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛${NC}"
    echo -e "  ${GREEN1}[${WHITE}01${GREEN1}]${NC} ${BLUE1}🌐${NC} Domain Intelligence      ${DIM}${GRAY}DNS, WHOIS, Security${NC}"
    echo -e "  ${GREEN1}[${WHITE}02${GREEN1}]${NC} ${BLUE1}🔍${NC} Subdomain Enumeration    ${DIM}${GRAY}Brute + CT logs${NC}"
    echo ""
    
    echo -e "${ORANGE}┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓${NC}"
    echo -e "${ORANGE}┃${NC} ${BOLD}${WHITE}👤 IDENTITY & CONTACTS${NC}                                     ${ORANGE}┃${NC}"
    echo -e "${ORANGE}┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛${NC}"
    echo -e "  ${GREEN1}[${WHITE}03${GREEN1}]${NC} ${BLUE1}📧${NC} Email Analysis           ${DIM}${GRAY}Breach + Reputation${NC}"
    echo -e "  ${GREEN1}[${WHITE}04${GREEN1}]${NC} ${BLUE1}📱${NC} Phone Lookup             ${DIM}${GRAY}45+ Auto Search${NC}"
    echo -e "  ${GREEN1}[${WHITE}05${GREEN1}]${NC} ${BLUE1}👤${NC} Username Footprint       ${DIM}${GRAY}25+ Platforms${NC}"
    echo ""
    
    echo -e "${PINK}┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓${NC}"
    echo -e "${PINK}┃${NC} ${BOLD}${WHITE}🕵️  ADVANCED OSINT${NC}                                          ${PINK}┃${NC}"
    echo -e "${PINK}┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛${NC}"
    echo -e "  ${GREEN1}[${WHITE}06${GREEN1}]${NC} ${BLUE1}🕵️${NC}  Sherlock Search          ${DIM}${GRAY}50+ Sites${NC}"
    echo -e "  ${GREEN1}[${WHITE}07${GREEN1}]${NC} ${BLUE1}📧${NC} Email Harvesting         ${DIM}${GRAY}TheHarvester${NC}"
    echo -e "  ${GREEN1}[${WHITE}08${GREEN1}]${NC} ${BLUE1}🖼️${NC}  Reverse Image            ${DIM}${GRAY}9 Engines + GPS${NC}"
    echo -e "  ${GREEN1}[${WHITE}09${GREEN1}]${NC} ${BLUE1}🌍${NC} Geolocation Tracker      ${DIM}${GRAY}GPS from Images${NC}"
    echo -e "  ${GREEN1}[${WHITE}10${GREEN1}]${NC} ${BLUE1}📱${NC} Social Media Scraper     ${DIM}${GRAY}GitHub, Reddit, etc${NC}"
    echo -e "  ${GREEN1}[${WHITE}11${GREEN1}]${NC} ${BLUE1}🖥️${NC}  MAC Address Lookup       ${DIM}${GRAY}Device Identification${NC}"
    echo -e "  ${GREEN1}[${WHITE}12${GREEN1}]${NC} ${BLUE1}📸${NC} Metadata Extractor       ${DIM}${GRAY}Document Forensics${NC}"
    echo -e "  ${GREEN1}[${WHITE}13${GREEN1}]${NC} ${BLUE1}🔍${NC} Google Dork Generator    ${DIM}${GRAY}100+ Auto Dorks${NC}"
    echo ""
    
    echo -e "${RED1}┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓${NC}"
    echo -e "${RED1}┃${NC} ${BOLD}${WHITE}🛡️  SECURITY & THREATS${NC}                                      ${RED1}┃${NC}"
    echo -e "${RED1}┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛${NC}"
    echo -e "  ${GREEN1}[${WHITE}14${GREEN1}]${NC} ${BLUE1}🔓${NC} Breach Monitor           ${DIM}${GRAY}Check Data Leaks${NC}"
    echo -e "  ${GREEN1}[${WHITE}15${GREEN1}]${NC} ${BLUE1}🕸️${NC}  Darkweb Scanner          ${DIM}${GRAY}.onion Search${NC}"
    echo -e "  ${GREEN1}[${WHITE}16${GREEN1}]${NC} ${BLUE1}🤖${NC} AI Risk Analyzer         ${DIM}${GRAY}Intelligent Assessment${NC}"
    echo -e "  ${GREEN1}[${WHITE}17${GREEN1}]${NC} ${BLUE1}💰${NC} Crypto Tracker           ${DIM}${GRAY}BTC/ETH Wallets${NC}"
    echo -e "  ${GREEN1}[${WHITE}18${GREEN1}]${NC} ${BLUE1}🔒${NC} SSL/TLS Analyzer         ${DIM}${GRAY}Certificate Security${NC}"
    echo ""
    
    echo -e "${GREEN2}┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓${NC}"
    echo -e "${GREEN2}┃${NC} ${BOLD}${WHITE}🎣 TOOLS & UTILITIES${NC}                                       ${GREEN2}┃${NC}"
    echo -e "${GREEN2}┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛${NC}"
    echo -e "  ${GREEN1}[${WHITE}19${GREEN1}]${NC} ${BLUE1}🎣${NC} IP Grabber Generator     ${DIM}${GRAY}Grabify + More${NC}"
    echo -e "  ${GREEN1}[${WHITE}20${GREEN1}]${NC} ${BLUE1}📊${NC} Full OSINT Report        ${DIM}${GRAY}All-in-One Scan${NC}"
    echo ""
    
    echo -e "${YELLOW}┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓${NC}"
    echo -e "${YELLOW}┃${NC}  ${GREEN1}[${WHITE}21${GREEN1}]${NC} ${CYAN}ℹ️  Info & Features${NC}     ${GREEN1}[${WHITE}00${GREEN1}]${NC} ${RED}❌ Exit${NC}            ${YELLOW}┃${NC}"
    echo -e "${YELLOW}┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛${NC}"
    echo ""
    echo -e "  ${DIM}${GRAY}╭─────────────────────────────────────────────────────────╮${NC}"
    echo -ne "  ${DIM}${GRAY}│${NC} ${BOLD}${PINK}➤${NC} ${WHITE}Select option:${NC} "
}

show_loading() {
    local text="$1"
    echo ""
    echo -e "${CYAN}╔════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${NC}  ${YELLOW}⏳${NC} ${text}${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

show_input_prompt() {
    local prompt="$1"
    echo ""
    echo -e "${PURPLE}┌────────────────────────────────────────────────────────┐${NC}"
    echo -e "${PURPLE}│${NC} ${BOLD}${prompt}${NC}"
    echo -e "${PURPLE}└────────────────────────────────────────────────────────┘${NC}"
    echo -ne "  ${PINK}➤${NC} "
}

run_module() {
    cd "$HOME/nika-osint"
    "$@"
    echo ""
    echo -e "${DIM}${GRAY}Press ENTER to return to menu...${NC}"
    read
}

show_category_header() {
    local title="$1"
    local icon="$2"
    clear
    show_banner
    echo -e "${PINK}╔════════════════════════════════════════════════════════╗${NC}"
    echo -e "${PINK}║${NC}  ${icon} ${BOLD}${WHITE}${title}${NC}"
    echo -e "${PINK}╚════════════════════════════════════════════════════════╝${NC}"
}

main() {
    while true; do
        show_banner
        show_menu
        read choice
        
        case $choice in
            1|01)
                show_category_header "DOMAIN INTELLIGENCE" "🌐"
                show_input_prompt "Enter domain (e.g., example.com):"
                read domain
                [ -n "$domain" ] && run_module node osint-ultra-max.js --domain "$domain"
                ;;
            2|02)
                show_category_header "SUBDOMAIN ENUMERATION" "🔍"
                show_input_prompt "Enter domain:"
                read domain
                [ -n "$domain" ] && run_module node osint-ultra-max.js --domain "$domain"
                ;;
            3|03)
                show_category_header "EMAIL ANALYSIS" "📧"
                show_input_prompt "Enter email address:"
                read email
                [ -n "$email" ] && run_module node osint-ultra-max.js --email "$email"
                ;;
            4|04)
                show_category_header "PHONE LOOKUP" "📱"
                show_input_prompt "Enter phone number (+country code):"
                read phone
                [ -n "$phone" ] && run_module node osint-ultra-max.js --phone "$phone"
                ;;
            5|05)
                show_category_header "USERNAME FOOTPRINT" "👤"
                show_input_prompt "Enter username:"
                read user
                [ -n "$user" ] && run_module node osint-ultra-max.js --username "$user"
                ;;
            6|06)
                show_category_header "SHERLOCK USERNAME SEARCH" "🕵️"
                echo -e "\n  ${CYAN}➤ Searches 50+ social platforms${NC}\n"
                show_input_prompt "Enter username:"
                read user
                [ -n "$user" ] && run_module node sherlock-search.js "$user"
                ;;
            7|07)
                show_category_header "EMAIL HARVESTING" "📧"
                show_input_prompt "Enter domain:"
                read domain
                [ -n "$domain" ] && run_module node theharvester-search.js "$domain"
                ;;
            8|08)
                show_category_header "REVERSE IMAGE SEARCH" "🖼️"
                echo ""
                echo -e "  ${GREEN1}[1]${NC} Local Image File"
                echo -e "  ${GREEN1}[2]${NC} Image URL"
                echo ""
                show_input_prompt "Select option:"
                read ch
                if [ "$ch" == "1" ]; then
                    show_input_prompt "Enter image path:"
                    read path
                    [ -f "$path" ] && run_module node reverse-image-search.js --file "$path"
                elif [ "$ch" == "2" ]; then
                    show_input_prompt "Enter image URL:"
                    read url
                    [ -n "$url" ] && run_module node reverse-image-search.js --url "$url"
                fi
                ;;
            9|09)
                show_category_header "GEOLOCATION TRACKER" "🌍"
                echo -e "\n  ${CYAN}➤ Extract GPS coordinates from image metadata${NC}\n"
                show_input_prompt "Enter image path:"
                read path
                [ -f "$path" ] && run_module node geo-tracker.js "$path"
                ;;
            10)
                show_category_header "SOCIAL MEDIA SCRAPER" "📱"
                echo ""
                echo -e "  ${GREEN1}[1]${NC} All Platforms    ${GREEN1}[2]${NC} GitHub       ${GREEN1}[3]${NC} Reddit"
                echo -e "  ${GREEN1}[4]${NC} Instagram        ${GREEN1}[5]${NC} Twitter      ${GREEN1}[6]${NC} TikTok"
                echo ""
                show_input_prompt "Select platform:"
                read plat
                show_input_prompt "Enter username:"
                read user
                if [ -n "$user" ]; then
                    case $plat in
                        1) run_module node social-scraper.js "$user" ;;
                        2) run_module node social-scraper.js --platform github "$user" ;;
                        3) run_module node social-scraper.js --platform reddit "$user" ;;
                        4) run_module node social-scraper.js --platform instagram "$user" ;;
                        5) run_module node social-scraper.js --platform twitter "$user" ;;
                        6) run_module node social-scraper.js --platform tiktok "$user" ;;
                        *) run_module node social-scraper.js "$user" ;;
                    esac
                fi
                ;;
            11)
                show_category_header "MAC ADDRESS LOOKUP" "🖥️"
                echo -e "\n  ${CYAN}➤ Device identification from MAC address${NC}\n"
                show_input_prompt "Enter MAC address (XX:XX:XX:XX:XX:XX):"
                read mac
                [ -n "$mac" ] && run_module node mac-lookup.js "$mac" --online
                ;;
            12)
                show_category_header "METADATA EXTRACTOR" "📸"
                echo -e "\n  ${CYAN}➤ Extract hidden data from documents/images${NC}\n"
                show_input_prompt "Enter file path:"
                read path
                [ -f "$path" ] && run_module node metadata-extractor.js "$path"
                ;;
            13)
                show_category_header "GOOGLE DORK GENERATOR" "🔍"
                echo -e "\n  ${CYAN}➤ Generate 100+ search dorks automatically${NC}\n"
                show_input_prompt "Enter target domain:"
                read domain
                [ -n "$domain" ] && run_module node dork-generator.js "$domain"
                ;;
            14)
                show_category_header "BREACH MONITOR" "🔓"
                echo ""
                echo -e "  ${GREEN1}[1]${NC} Check Email Address"
                echo -e "  ${GREEN1}[2]${NC} Check Password Security"
                echo ""
                show_input_prompt "Select option:"
                read check_type
                if [ "$check_type" == "1" ]; then
                    show_input_prompt "Enter email:"
                    read email
                    [ -n "$email" ] && run_module node breach-monitor.js --email "$email"
                elif [ "$check_type" == "2" ]; then
                    run_module node breach-monitor.js --password
                fi
                ;;
            15)
                show_category_header "DARKWEB SCANNER" "🕸️"
                echo -e "\n  ${RED}⚠️  Use responsibly - Darkweb content can be dangerous${NC}\n"
                show_input_prompt "Enter search query:"
                read query
                [ -n "$query" ] && run_module node darkweb-scanner.js "$query"
                ;;
            16)
                show_category_header "AI RISK ANALYZER" "🤖"
                echo -e "\n  ${CYAN}➤ Analyze OSINT reports with AI-powered assessment${NC}\n"
                show_input_prompt "Enter report file path (JSON):"
                read file
                [ -f "$file" ] && run_module node ai-analyzer.js "$file"
                ;;
            17)
                show_category_header "CRYPTO TRACKER" "💰"
                echo -e "\n  ${CYAN}➤ Track Bitcoin and Ethereum wallets${NC}\n"
                show_input_prompt "Enter wallet address:"
                read addr
                [ -n "$addr" ] && run_module node crypto-tracker.js "$addr"
                ;;
            18)
                show_category_header "SSL/TLS ANALYZER" "🔒"
                echo -e "\n  ${CYAN}➤ Analyze certificate security and vulnerabilities${NC}\n"
                show_input_prompt "Enter domain:"
                read domain
                [ -n "$domain" ] && run_module node ssl-analyzer.js "$domain"
                ;;
            19)
                show_category_header "IP GRABBER GENERATOR" "🎣"
                echo ""
                echo -e "  ${GREEN1}[1]${NC} YouTube      ${GREEN1}[2]${NC} Wikipedia    ${GREEN1}[3]${NC} News"
                echo -e "  ${GREEN1}[4]${NC} Telegram     ${GREEN1}[5]${NC} GitHub       ${GREEN1}[6]${NC} Reddit"
                echo -e "  ${GREEN1}[7]${NC} Spotify      ${GREEN1}[8]${NC} Instagram    ${GREEN1}[9]${NC} Random"
                echo ""
                show_input_prompt "Select category:"
                read cat
                case $cat in
                    1) c="youtube" ;;
                    2) c="wikipedia" ;;
                    3) c="news" ;;
                    4) c="telegram" ;;
                    5) c="github" ;;
                    6) c="reddit" ;;
                    7) c="spotify" ;;
                    8) c="instagram" ;;
                    *) c="random" ;;
                esac
                run_module node osint-ultra-max.js --grabber $c
                ;;
            20)
                show_category_header "FULL OSINT REPORT" "📊"
                echo -e "\n  ${YELLOW}Leave fields blank to skip${NC}\n"
                show_input_prompt "Domain:"
                read d
                show_input_prompt "Email:"
                read e
                show_input_prompt "Phone:"
                read p
                show_input_prompt "Username:"
                read u
                
                cmd="node osint-ultra-max.js"
                [ -n "$d" ] && cmd="$cmd --domain $d"
                [ -n "$e" ] && cmd="$cmd --email $e"
                [ -n "$p" ] && cmd="$cmd --phone $p"
                [ -n "$u" ] && cmd="$cmd --username $u"
                
                if [ "$cmd" != "node osint-ultra-max.js" ]; then
                    run_module $cmd
                else
                    echo -e "${RED}✗ At least one parameter required${NC}"
                    sleep 2
                fi
                ;;
            21)
                clear
                show_banner
                echo -e "${CYAN}╔════════════════════════════════════════════════════════╗${NC}"
                echo -e "${CYAN}║${NC}         ${BOLD}${WHITE}ℹ️  NIKA OSINT ULTRA v5.0${NC}                      ${CYAN}║${NC}"
                echo -e "${CYAN}╚════════════════════════════════════════════════════════╝${NC}"
                echo ""
                echo -e "${YELLOW}${BOLD}✨ NEW IN v5.0 (5 NEW MODULES):${NC}"
                echo -e "  ${GREEN2}▸${NC} MAC Address Lookup ${DIM}${GRAY}(Device identification)${NC}"
                echo -e "  ${GREEN2}▸${NC} Metadata Extractor ${DIM}${GRAY}(Document forensics)${NC}"
                echo -e "  ${GREEN2}▸${NC} Google Dork Generator ${DIM}${GRAY}(100+ auto dorks)${NC}"
                echo -e "  ${GREEN2}▸${NC} Crypto Tracker ${DIM}${GRAY}(BTC/ETH wallets)${NC}"
                echo -e "  ${GREEN2}▸${NC} SSL/TLS Analyzer ${DIM}${GRAY}(Certificate security)${NC}"
                echo ""
                echo -e "${YELLOW}${BOLD}🔥 v4.0 MODULES:${NC}"
                echo -e "  ${GREEN2}▸${NC} Geolocation Tracker, Social Scraper, Breach Monitor"
                echo -e "  ${GREEN2}▸${NC} Darkweb Scanner, AI Risk Analyzer"
                echo ""
                echo -e "${YELLOW}${BOLD}🚀 TOTAL FEATURES:${NC}"
                echo -e "  ${BLUE1}▸${NC} 21 Powerful Modules"
                echo -e "  ${BLUE1}▸${NC} 150+ Intelligence Sources"
                echo -e "  ${BLUE1}▸${NC} Auto-save Reports (JSON + TXT)"
                echo -e "  ${BLUE1}▸${NC} Phone Auto Search (45+ sources)"
                echo -e "  ${BLUE1}▸${NC} Username Search (50+ platforms)"
                echo ""
                echo -e "${YELLOW}${BOLD}👥 AUTHORS:${NC}"
                echo -e "  ${PINK}🥝 kiwi & 777${NC}"
                echo ""
                echo -e "${YELLOW}${BOLD}📦 GITHUB:${NC}"
                echo -e "  ${CYAN}https://github.com/u4622172004-png/nika-osint${NC}"
                echo ""
                echo -e "${RED}${BOLD}⚠️  LEGAL NOTICE:${NC}"
                echo -e "  ${DIM}${GRAY}For authorized security research and${NC}"
                echo -e "  ${DIM}${GRAY}educational purposes only.${NC}"
                echo ""
                echo -e "${DIM}${GRAY}Press ENTER to return to menu...${NC}"
                read
                ;;
            0|00)
                clear
                echo ""
                echo -e "${PINK}╔═══════════════════════════════════════════════════════╗${NC}"
                echo -e "${PINK}║${NC}                                                       ${PINK}║${NC}"
                echo -e "${PINK}║${NC}     ${CYAN}🥝${NC} ${BOLD}${WHITE}Thanks for using NIKA OSINT!${NC} ${CYAN}🥝${NC}            ${PINK}║${NC}"
                echo -e "${PINK}║${NC}                                                       ${PINK}║${NC}"
                echo -e "${PINK}╚═══════════════════════════════════════════════════════╝${NC}"
                echo ""
                echo -e "           ${CYAN}Stay curious, stay safe! 🔐${NC}"
                echo ""
                echo -e "${DIM}${GRAY}        Developed with ❤️  by kiwi & 777${NC}"
                echo ""
                sleep 2
                exit 0
                ;;
            *)
                echo ""
                echo -e "${RED}✗ Invalid option. Please select 0-21${NC}"
                sleep 1
                ;;
        esac
    done
}

main
