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
    echo -e "${MAGENTA}${BOLD}     🥝 OSINT ULTRA v4.0 🥝${NC}"
    echo -e "${CYAN}  Advanced Intelligence Gathering${NC}"
    echo ""
}

show_menu() {
    echo -e "${CYAN}${BOLD}┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓${NC}"
    echo -e "${CYAN}${BOLD}┃        🎯 MAIN MENU 🎯               ┃${NC}"
    echo -e "${CYAN}${BOLD}┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛${NC}"
    echo ""
    echo -e "${WHITE}${BOLD}  🔍 RECONNAISSANCE${NC}"
    echo -e "${GREEN}  [1]${NC}  🌐 Domain Intelligence"
    echo -e "${GREEN}  [2]${NC}  🔍 Subdomain Enumeration"
    echo ""
    echo -e "${WHITE}${BOLD}  👤 IDENTITY & CONTACTS${NC}"
    echo -e "${GREEN}  [3]${NC}  📧 Email Analysis"
    echo -e "${GREEN}  [4]${NC}  📱 Phone Lookup"
    echo -e "${GREEN}  [5]${NC}  👤 Username Footprint"
    echo ""
    echo -e "${WHITE}${BOLD}  🕵️  ADVANCED OSINT${NC}"
    echo -e "${GREEN}  [6]${NC}  🕵️  Sherlock Search (50+ sites)"
    echo -e "${GREEN}  [7]${NC}  📧 Email Harvesting"
    echo -e "${GREEN}  [8]${NC}  🖼️  Reverse Image Search"
    echo -e "${GREEN}  [9]${NC}  🌍 Geolocation Tracker (GPS)"
    echo -e "${GREEN} [10]${NC}  📱 Social Media Scraper"
    echo ""
    echo -e "${WHITE}${BOLD}  🛡️  SECURITY & THREATS${NC}"
    echo -e "${GREEN} [11]${NC}  🔓 Breach Monitor"
    echo -e "${GREEN} [12]${NC}  🕸️  Darkweb Scanner"
    echo -e "${GREEN} [13]${NC}  🤖 AI Risk Analyzer"
    echo ""
    echo -e "${WHITE}${BOLD}  🎣 TOOLS${NC}"
    echo -e "${GREEN} [14]${NC}  🎣 IP Grabber Generator"
    echo -e "${GREEN} [15]${NC}  📊 Full OSINT Report"
    echo ""
    echo -e "${YELLOW} [16]${NC}  ℹ️  Info & Features"
    echo -e "${YELLOW}  [0]${NC}  ❌ Exit"
    echo ""
    echo -e "${CYAN}┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄${NC}"
    echo -ne "${WHITE}${BOLD}  ➤ Select [0-16]: ${NC}"
}

run_script() {
    cd "$HOME/nika-osint"
    "$@"
    echo ""
    read -p "Press ENTER to continue..."
}

main() {
    while true; do
        show_banner
        show_menu
        read choice
        
        case $choice in
            1)
                clear
                show_banner
                echo -e "${GREEN}${BOLD}🌐 DOMAIN INTELLIGENCE${NC}\n"
                echo -ne "${YELLOW}➤ Domain: ${NC}"
                read domain
                [ -n "$domain" ] && run_script node osint-ultra-max.js --domain "$domain" --save
                ;;
            2)
                clear
                show_banner
                echo -e "${GREEN}${BOLD}🔍 SUBDOMAIN ENUMERATION${NC}\n"
                echo -ne "${YELLOW}➤ Domain: ${NC}"
                read domain
                [ -n "$domain" ] && run_script node osint-ultra-max.js --domain "$domain" --save
                ;;
            3)
                clear
                show_banner
                echo -e "${GREEN}${BOLD}📧 EMAIL ANALYSIS${NC}\n"
                echo -ne "${YELLOW}➤ Email: ${NC}"
                read email
                [ -n "$email" ] && run_script node osint-ultra-max.js --email "$email" --save
                ;;
            4)
                clear
                show_banner
                echo -e "${GREEN}${BOLD}📱 PHONE LOOKUP${NC}\n"
                echo -ne "${YELLOW}➤ Phone (+country code): ${NC}"
                read phone
                [ -n "$phone" ] && run_script node osint-ultra-max.js --phone "$phone" --save
                ;;
            5)
                clear
                show_banner
                echo -e "${GREEN}${BOLD}👤 USERNAME FOOTPRINT${NC}\n"
                echo -ne "${YELLOW}➤ Username: ${NC}"
                read user
                [ -n "$user" ] && run_script node osint-ultra-max.js --username "$user" --save
                ;;
            6)
                clear
                show_banner
                echo -e "${GREEN}${BOLD}🕵️  SHERLOCK USERNAME SEARCH${NC}\n"
                echo -e "${CYAN}Search 50+ platforms${NC}\n"
                echo -ne "${YELLOW}➤ Username: ${NC}"
                read user
                [ -n "$user" ] && run_script node sherlock-search.js "$user" --save
                ;;
            7)
                clear
                show_banner
                echo -e "${GREEN}${BOLD}📧 EMAIL HARVESTING${NC}\n"
                echo -ne "${YELLOW}➤ Domain: ${NC}"
                read domain
                [ -n "$domain" ] && run_script node theharvester-search.js "$domain" --save
                ;;
            8)
                clear
                show_banner
                echo -e "${GREEN}${BOLD}🖼️  REVERSE IMAGE SEARCH${NC}\n"
                echo -e "${GREEN}[1]${NC} Local File  ${GREEN}[2]${NC} URL"
                echo -ne "${YELLOW}➤ Select: ${NC}"
                read ch
                if [ "$ch" == "1" ]; then
                    echo -ne "${YELLOW}➤ Image path: ${NC}"
                    read path
                    [ -f "$path" ] && run_script node reverse-image-search.js --file "$path"
                elif [ "$ch" == "2" ]; then
                    echo -ne "${YELLOW}➤ Image URL: ${NC}"
                    read url
                    [ -n "$url" ] && run_script node reverse-image-search.js --url "$url"
                fi
                ;;
            9)
                clear
                show_banner
                echo -e "${GREEN}${BOLD}🌍 GEOLOCATION TRACKER${NC}\n"
                echo -e "${CYAN}Extract GPS from image metadata${NC}\n"
                echo -ne "${YELLOW}➤ Image path: ${NC}"
                read path
                if [ -f "$path" ]; then
                    run_script node geo-tracker.js "$path" --save
                else
                    echo -e "${RED}✗ File not found${NC}"
                    sleep 2
                fi
                ;;
            10)
                clear
                show_banner
                echo -e "${GREEN}${BOLD}📱 SOCIAL MEDIA SCRAPER${NC}\n"
                echo -e "${CYAN}Platforms:${NC}"
                echo -e "${GREEN}[1]${NC} All Platforms  ${GREEN}[2]${NC} GitHub  ${GREEN}[3]${NC} Reddit"
                echo -e "${GREEN}[4]${NC} Instagram      ${GREEN}[5]${NC} Twitter ${GREEN}[6]${NC} TikTok"
                echo -ne "${YELLOW}➤ Select: ${NC}"
                read plat
                echo -ne "${YELLOW}➤ Username: ${NC}"
                read user
                if [ -n "$user" ]; then
                    case $plat in
                        1) run_script node social-scraper.js "$user" --save ;;
                        2) run_script node social-scraper.js --platform github "$user" --save ;;
                        3) run_script node social-scraper.js --platform reddit "$user" --save ;;
                        4) run_script node social-scraper.js --platform instagram "$user" --save ;;
                        5) run_script node social-scraper.js --platform twitter "$user" --save ;;
                        6) run_script node social-scraper.js --platform tiktok "$user" --save ;;
                        *) run_script node social-scraper.js "$user" --save ;;
                    esac
                fi
                ;;
            11)
                clear
                show_banner
                echo -e "${GREEN}${BOLD}🔓 BREACH MONITOR${NC}\n"
                echo -e "${CYAN}Check data leaks and breaches${NC}\n"
                echo -e "${GREEN}[1]${NC} Check Email  ${GREEN}[2]${NC} Check Password"
                echo -ne "${YELLOW}➤ Select: ${NC}"
                read check_type
                if [ "$check_type" == "1" ]; then
                    echo -ne "${YELLOW}➤ Email: ${NC}"
                    read email
                    [ -n "$email" ] && run_script node breach-monitor.js --email "$email" --save
                elif [ "$check_type" == "2" ]; then
                    run_script node breach-monitor.js --password
                fi
                ;;
            12)
                clear
                show_banner
                echo -e "${GREEN}${BOLD}🕸️  DARKWEB SCANNER${NC}\n"
                echo -e "${RED}⚠️  Use with caution${NC}\n"
                echo -ne "${YELLOW}➤ Search query: ${NC}"
                read query
                [ -n "$query" ] && run_script node darkweb-scanner.js "$query" --save
                ;;
            13)
                clear
                show_banner
                echo -e "${GREEN}${BOLD}🤖 AI RISK ANALYZER${NC}\n"
                echo -e "${CYAN}Analyze OSINT report with AI${NC}\n"
                echo -ne "${YELLOW}➤ Report file (JSON): ${NC}"
                read file
                if [ -f "$file" ]; then
                    run_script node ai-analyzer.js "$file"
                else
                    echo -e "${RED}✗ File not found${NC}"
                    sleep 2
                fi
                ;;
            14)
                clear
                show_banner
                echo -e "${GREEN}${BOLD}🎣 IP GRABBER GENERATOR${NC}\n"
                echo -e "${GREEN}[1]${NC} YouTube   ${GREEN}[2]${NC} Wikipedia ${GREEN}[3]${NC} News"
                echo -e "${GREEN}[4]${NC} Telegram  ${GREEN}[5]${NC} GitHub    ${GREEN}[6]${NC} Reddit"
                echo -e "${GREEN}[7]${NC} Spotify   ${GREEN}[8]${NC} Instagram ${GREEN}[9]${NC} Random"
                echo -ne "${YELLOW}➤ Select: ${NC}"
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
                run_script node osint-ultra-max.js --grabber $c
                ;;
            15)
                clear
                show_banner
                echo -e "${GREEN}${BOLD}📊 FULL OSINT REPORT${NC}\n"
                echo -e "${YELLOW}Leave blank to skip${NC}\n"
                echo -ne "${CYAN}➤ Domain: ${NC}"
                read d
                echo -ne "${CYAN}➤ Email: ${NC}"
                read e
                echo -ne "${CYAN}➤ Phone: ${NC}"
                read p
                echo -ne "${CYAN}➤ Username: ${NC}"
                read u
                
                cmd="node osint-ultra-max.js --save"
                [ -n "$d" ] && cmd="$cmd --domain $d"
                [ -n "$e" ] && cmd="$cmd --email $e"
                [ -n "$p" ] && cmd="$cmd --phone $p"
                [ -n "$u" ] && cmd="$cmd --username $u"
                
                if [ "$cmd" != "node osint-ultra-max.js --save" ]; then
                    run_script $cmd
                else
                    echo -e "${RED}✗ No input${NC}"
                    sleep 2
                fi
                ;;
            16)
                clear
                show_banner
                echo -e "${CYAN}${BOLD}ℹ️  NIKA OSINT ULTRA v4.0${NC}\n"
                echo -e "${YELLOW}${BOLD}NEW IN v4.0:${NC}"
                echo -e "  ${GREEN}✓${NC} Geolocation Tracker (GPS from images)"
                echo -e "  ${GREEN}✓${NC} Social Media Scraper (GitHub, Reddit, etc.)"
                echo -e "  ${GREEN}✓${NC} Breach Monitor (HaveIBeenPwned, etc.)"
                echo -e "  ${GREEN}✓${NC} Darkweb Scanner (.onion search)"
                echo -e "  ${GREEN}✓${NC} AI Risk Analyzer (intelligent assessment)\n"
                echo -e "${YELLOW}${BOLD}v3.0 FEATURES:${NC}"
                echo -e "  ${GREEN}✓${NC} Sherlock (50+ sites)"
                echo -e "  ${GREEN}✓${NC} Email Harvesting (TheHarvester)"
                echo -e "  ${GREEN}✓${NC} Reverse Image Search (9 engines)"
                echo -e "  ${GREEN}✓${NC} Phone Auto Search (45+ sources)"
                echo -e "  ${GREEN}✓${NC} IP Grabber Generator\n"
                echo -e "${YELLOW}${BOLD}CORE FEATURES:${NC}"
                echo -e "  ${GRAY}•${NC} 150+ Intelligence Sources"
                echo -e "  ${GRAY}•${NC} Domain Intelligence (54+ checks)"
                echo -e "  ${GRAY}•${NC} Subdomain Enumeration"
                echo -e "  ${GRAY}•${NC} Email Analysis (12+ checks)"
                echo -e "  ${GRAY}•${NC} Username Search (25+ platforms)"
                echo -e "  ${GRAY}•${NC} Auto-save Reports (JSON + TXT)\n"
                echo -e "${YELLOW}${BOLD}REPORTS SAVED IN:${NC}"
                echo -e "  ${CYAN}./reports/${NC}                (OSINT scans)"
                echo -e "  ${CYAN}./sherlock-reports/${NC}       (Sherlock)"
                echo -e "  ${CYAN}./harvester-reports/${NC}      (Email harvesting)"
                echo -e "  ${CYAN}./geo-reports/${NC}            (Geolocation)"
                echo -e "  ${CYAN}./social-scraper-reports/${NC} (Social media)"
                echo -e "  ${CYAN}./breach-monitor-reports/${NC} (Breaches)"
                echo -e "  ${CYAN}./darkweb-reports/${NC}        (Darkweb)"
                echo -e "  ${CYAN}./ai-analysis-reports/${NC}    (AI analysis)\n"
                echo -e "${YELLOW}${BOLD}AUTHORS:${NC}"
                echo -e "  ${MAGENTA}🥝 kiwi & 777${NC}\n"
                echo -e "${YELLOW}${BOLD}GITHUB:${NC}"
                echo -e "  ${CYAN}https://github.com/u4622172004-png/nika-osint${NC}\n"
                echo -e "${RED}${BOLD}⚠️  LEGAL NOTICE:${NC}"
                echo -e "  ${GRAY}For authorized security research and${NC}"
                echo -e "  ${GRAY}educational purposes only.${NC}\n"
                read -p "Press ENTER to continue..."
                ;;
            0)
                clear
                echo ""
                echo -e "${MAGENTA}${BOLD}  ╔═══════════════════════════════════════╗${NC}"
                echo -e "${MAGENTA}${BOLD}  ║  🥝 Thanks for using NIKA OSINT! 🥝  ║${NC}"
                echo -e "${MAGENTA}${BOLD}  ╚═══════════════════════════════════════╝${NC}"
                echo ""
                echo -e "${CYAN}    Stay curious, stay safe! 🔐${NC}"
                echo ""
                sleep 1
                exit 0
                ;;
            *)
                echo ""
                echo -e "${RED}✗ Invalid option${NC}"
                sleep 1
                ;;
        esac
    done
}

main
