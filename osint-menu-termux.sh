#!/data/data/com.termux/files/usr/bin/bash

# Colori ottimizzati per Termux
RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
NC='\033[0m'

# Banner con ASCII NIKA dettagliato
show_banner() {
    clear
    echo -e "${RED}"
    cat << "EOF"
╔═══════════════════════════════════════════════╗
║                                               ║
║   ███╗   ██╗ ██╗ ██╗  ██╗  █████╗            ║
║   ████╗  ██║ ██║ ██║ ██╔╝ ██╔══██╗            ║
║   ██╔██╗ ██║ ██║ █████╔╝  ███████║            ║
║   ██║╚██╗██║ ██║ ██╔═██╗  ██╔══██║            ║
║   ██║ ╚████║ ██║ ██║  ██╗ ██║  ██║            ║
║   ╚═╝  ╚═══╝ ╚═╝ ╚═╝  ╚═╝ ╚═╝  ╚═╝           ║
║                                               ║ 
║        ╔═══════════════════════════╗          ║
║        ║   OSINT TOOLKIT v1.0      ║          ║
║        ║   Intelligence Gathering  ║          ║
║        ╚═══════════════════════════╝          ║
║                                               ║
╚═══════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
    echo -e "${MAGENTA}           ╔════════════════════════╗${NC}"
    echo -e "${MAGENTA}           ║ created by kiwi & hide ║${NC}"
    echo -e "${MAGENTA}           ╚════════════════════════╝${NC}"
    echo -e "${CYAN}                 Termux Edition${NC}"
    echo ""
}

# Verifica dipendenze
check_dependencies() {
    local missing=()
    
    if ! command -v node &> /dev/null; then
        missing+=("nodejs")
    fi
    
    if [ ${#missing[@]} -ne 0 ]; then
        echo -e "${RED}[!] Dipendenze mancanti:${NC}"
        for dep in "${missing[@]}"; do
            echo -e "${YELLOW}  - $dep${NC}"
        done
        echo ""
        echo -e "${CYAN}[*] Installale con:${NC}"
        echo -e "pkg install ${missing[*]}"
        echo ""
        return 1
    fi
    return 0
}

# Menu principale
show_menu() {
    echo -e "${GREEN}╔═══════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║          NIKA OSINT TOOLKIT           ║${NC}"
    echo -e "${GREEN}╚═══════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${CYAN}┌─────────────────────────────────────┐${NC}"
    echo -e "${CYAN}│            SCAN MODULES             │${NC}"
    echo -e "${CYAN}└─────────────────────────────────────┘${NC}"
    echo ""
    echo -e "${YELLOW}[1]${NC} 🌐 ${CYAN}Domain Intelligence${NC}"
    echo -e "    └─ DNS, WHOIS, Security Headers"
    echo ""
    echo -e "${YELLOW}[2]${NC} 📧 ${CYAN}Email Analysis${NC}"
    echo -e "    └─ Validation, MX Records, Gravatar"
    echo ""
    echo -e "${YELLOW}[3]${NC} 📱 ${CYAN}Phone Lookup${NC}"
    echo -e "    └─ Carrier, Type, Country"
    echo ""
    echo -e "${YELLOW}[4]${NC} 👤 ${CYAN}Username Search${NC}"
    echo -e "    └─ Social Media Footprint"
    echo ""
    echo -e "${YELLOW}[5]${NC} 🔍 ${CYAN}Subdomain Enumeration${NC}"
    echo -e "    └─ Brute-force & Certificate Transparency"
    echo ""
    echo -e "${YELLOW}[6]${NC} 📊 ${CYAN}Full Report${NC}"
    echo -e "    └─ Multi-parameter Reconnaissance"
    echo ""
    echo -e "${CYAN}┌─────────────────────────────────────┐${NC}"
    echo -e "${CYAN}│              SYSTEM                 │${NC}"
    echo -e "${CYAN}└─────────────────────────────────────┘${NC}"
    echo ""
    echo -e "${YELLOW}[7]${NC} ℹ️  ${CYAN}Info & Help${NC}"
    echo -e "${YELLOW}[0]${NC} ❌ ${CYAN}Exit${NC}"
    echo ""
    echo -e "${MAGENTA}┌─────────────────────────────────────┐${NC}"
    echo -e "${MAGENTA}│    created NIKA by kiwi & hide      │${NC}"
    echo -e "${MAGENTA}└─────────────────────────────────────┘${NC}"
    echo ""
    echo -e -n "${CYAN}[NIKA]>${NC} "
}

# Funzione 1: Ricerca Dominio
domain_search() {
    clear
    show_banner
    echo -e "${GREEN}╔════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║      DOMAIN INTELLIGENCE SCAN         ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${CYAN}Target Information:${NC}"
    echo -n "  Domain (ex: google.com): "
    read domain
    
    if [ -z "$domain" ]; then
        echo -e "${RED}[!] Error: Invalid domain${NC}"
        sleep 2
        return
    fi
    
    echo ""
    echo -e "${YELLOW}[*] Initializing scan...${NC}"
    echo -e "${CYAN}    └─ DNS Resolution${NC}"
    echo -e "${CYAN}    └─ WHOIS Lookup${NC}"
    echo -e "${CYAN}    └─ Security Headers${NC}"
    echo -e "${CYAN}    └─ TLS Certificate${NC}"
    echo ""
    
    if [ -f "osint-ultra-max.js" ]; then
        node osint-ultra-max.js --domain "$domain"
    else
        echo -e "${RED}[!] Core module not found: osint-ultra-max.js${NC}"
    fi
    
    echo ""
    echo -e "${GREEN}[✓] Scan completed!${NC}"
    echo ""
    read -p "Press ENTER to continue..." -t 30
}

# Funzione 2: Email Analysis
email_analysis() {
    clear
    show_banner
    echo -e "${GREEN}╔════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║         EMAIL ANALYSIS SCAN           ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${CYAN}Target Information:${NC}"
    echo -n "  Email: "
    read email
    
    if [ -z "$email" ]; then
        echo -e "${RED}[!] Error: Invalid email${NC}"
        sleep 2
        return
    fi
    
    echo ""
    echo -e "${YELLOW}[*] Analyzing email...${NC}"
    echo -e "${CYAN}    └─ Format Validation${NC}"
    echo -e "${CYAN}    └─ MX Records Check${NC}"
    echo -e "${CYAN}    └─ Gravatar Lookup${NC}"
    echo ""
    
    if [ -f "osint-ultra-max.js" ]; then
        node osint-ultra-max.js --email "$email"
    else
        echo -e "${RED}[!] Core module not found${NC}"
    fi
    
    echo ""
    echo -e "${GREEN}[✓] Analysis completed!${NC}"
    echo ""
    read -p "Press ENTER to continue..." -t 30
}

# Funzione 3: Phone Lookup
phone_lookup() {
    clear
    show_banner
    echo -e "${GREEN}╔════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║         PHONE NUMBER LOOKUP           ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${CYAN}Target Information:${NC}"
    echo -e "${YELLOW}  Format: +[country code][number]${NC}"
    echo -e "${YELLOW}  Example: +393331234567${NC}"
    echo ""
    echo -n "  Phone: "
    read phone
    
    if [ -z "$phone" ]; then
        echo -e "${RED}[!] Error: Invalid phone number${NC}"
        sleep 2
        return
    fi
    
    echo ""
    echo -e "${YELLOW}[*] Analyzing phone number...${NC}"
    echo -e "${CYAN}    └─ Country Detection${NC}"
    echo -e "${CYAN}    └─ Carrier Identification${NC}"
    echo -e "${CYAN}    └─ Type Classification${NC}"
    echo ""
    
    if [ -f "osint-ultra-max.js" ]; then
        node osint-ultra-max.js --phone "$phone"
    else
        echo -e "${RED}[!] Core module not found${NC}"
    fi
    
    echo ""
    echo -e "${GREEN}[✓] Lookup completed!${NC}"
    echo ""
    read -p "Press ENTER to continue..." -t 30
}

# Funzione 4: Username Search
username_search() {
    clear
    show_banner
    echo -e "${GREEN}╔════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║       USERNAME FOOTPRINT SCAN         ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${CYAN}Target Information:${NC}"
    echo -n "  Username: "
    read username
    
    if [ -z "$username" ]; then
        echo -e "${RED}[!] Error: Invalid username${NC}"
        sleep 2
        return
    fi
    
    echo ""
    echo -e "${YELLOW}[*] Searching across platforms...${NC}"
    echo -e "${CYAN}    └─ GitHub${NC}"
    echo -e "${CYAN}    └─ Reddit${NC}"
    echo -e "${CYAN}    └─ Twitter${NC}"
    echo -e "${CYAN}    └─ Instagram${NC}"
    echo -e "${CYAN}    └─ Medium${NC}"
    echo ""
    
    if [ -f "osint-ultra-max.js" ]; then
        node osint-ultra-max.js --username "$username"
    else
        echo -e "${RED}[!] Core module not found${NC}"
    fi
    
    echo ""
    echo -e "${GREEN}[✓] Search completed!${NC}"
    echo ""
    read -p "Press ENTER to continue..." -t 30
}

# Funzione 5: Subdomain Scan
subdomain_scan() {
    clear
    show_banner
    echo -e "${GREEN}╔════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║       SUBDOMAIN ENUMERATION           ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${CYAN}Target Information:${NC}"
    echo -n "  Domain: "
    read domain
    
    if [ -z "$domain" ]; then
        echo -e "${RED}[!] Error: Invalid domain${NC}"
        sleep 2
        return
    fi
    
    echo ""
    echo -e "${YELLOW}[*] Enumerating subdomains...${NC}"
    echo -e "${CYAN}    └─ Wordlist Brute-force${NC}"
    echo -e "${CYAN}    └─ Certificate Transparency${NC}"
    echo -e "${CYAN}    └─ DNS Resolution${NC}"
    echo -e "${RED}    [!] This may take several minutes${NC}"
    echo ""
    
    if [ -f "osint-ultra-max.js" ]; then
        node osint-ultra-max.js --domain "$domain"
    else
        echo -e "${RED}[!] Core module not found${NC}"
    fi
    
    echo ""
    echo -e "${GREEN}[✓] Enumeration completed!${NC}"
    echo ""
    read -p "Press ENTER to continue..." -t 30
}

# Funzione 6: Full Report
full_report() {
    clear
    show_banner
    echo -e "${GREEN}╔════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║      COMPREHENSIVE RECONNAISSANCE     ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${CYAN}Target Information:${NC}"
    echo -e "${YELLOW}  (Leave blank to skip)${NC}"
    echo ""
    echo -n "  Domain: "
    read domain
    echo -n "  Username: "
    read username
    echo -n "  Email: "
    read email
    echo -n "  Phone: "
    read phone
    
    if [ -z "$domain" ] && [ -z "$username" ] && [ -z "$email" ] && [ -z "$phone" ]; then
        echo -e "${RED}[!] Error: At least one parameter required${NC}"
        sleep 2
        return
    fi
    
    echo ""
    echo -e "${YELLOW}[*] Generating comprehensive report...${NC}"
    echo ""
    
    if [ -f "osint-ultra-max.js" ]; then
        cmd="node osint-ultra-max.js"
        [ -n "$domain" ] && cmd="$cmd --domain $domain"
        [ -n "$username" ] && cmd="$cmd --username $username"
        [ -n "$email" ] && cmd="$cmd --email $email"
        [ -n "$phone" ] && cmd="$cmd --phone $phone"
        eval $cmd
    else
        echo -e "${RED}[!] Core module not found${NC}"
    fi
    
    echo ""
    echo -e "${GREEN}╔════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║      REPORT GENERATION COMPLETE       ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${CYAN}Output Files:${NC}"
    echo -e "  ${GREEN}→${NC} report.json"
    echo -e "  ${GREEN}→${NC} report.html"
    echo ""
    echo -e "${YELLOW}View HTML report:${NC} termux-open report.html"
    echo ""
    read -p "Press ENTER to continue..." -t 30
}

# Funzione 7: Info
show_info() {
    clear
    show_banner
    echo -e "${GREEN}╔════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║       INFORMATION & HELP              ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${CYAN}╔═══════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║   NIKA OSINT TOOLKIT                 ║${NC}"
    echo -e "${CYAN}╚═══════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${BLUE}📋 FEATURES:${NC}"
    echo ""
    echo -e "  ${GREEN}►${NC} Domain Intelligence"
    echo -e "    • DNS Records (A, MX, NS, TXT)"
    echo -e "    • WHOIS Information"
    echo -e "    • Security Headers Analysis"
    echo -e "    • TLS/SSL Certificate Check"
    echo -e "    • SPF/DMARC/DNSSEC Validation"
    echo ""
    echo -e "  ${GREEN}►${NC} Email Analysis"
    echo -e "    • Format Validation"
    echo -e "    • MX Record Verification"
    echo -e "    • Gravatar Profile Lookup"
    echo ""
    echo -e "  ${GREEN}►${NC} Phone Number Lookup"
    echo -e "    • Country Detection"
    echo -e "    • Carrier Identification"
    echo -e "    • Type Classification"
    echo ""
    echo -e "  ${GREEN}►${NC} Username OSINT"
    echo -e "    • Multi-platform Search"
    echo -e "    • Social Media Footprint"
    echo ""
    echo -e "  ${GREEN}►${NC} Subdomain Enumeration"
    echo -e "    • Wordlist Brute-force"
    echo -e "    • Certificate Transparency"
    echo ""
    echo -e "${YELLOW}⚠️  LEGAL NOTICE:${NC}"
    echo -e "  This tool is for educational purposes"
    echo -e "  and authorized OSINT research only."
    echo ""
    echo -e "${MAGENTA}📁 OUTPUT:${NC}"
    echo -e "  • report.json - Structured data"
    echo -e "  • report.html - Visual report"
    echo ""
    echo -e "${CYAN}📱 TERMUX:${NC}"
    echo -e "  • Directory: ~/osint-tool"
    echo -e "  • View report: termux-open report.html"
    echo ""
    echo -e "${GREEN}💾 CREDITS:${NC}"
    echo -e "  ${MAGENTA}  Developed by kiwi & hide${NC}"
    echo ""
    echo ""
    read -p "Press ENTER to continue..." -t 30
}

# Main loop
main() {
    # Verifica dipendenze
    if ! check_dependencies; then
        echo ""
        read -p "Press ENTER to exit..."
        exit 1
    fi
    
    while true; do
        show_banner
        show_menu
        read -t 60 choice
        
        case $choice in
            1) domain_search ;;
            2) email_analysis ;;
            3) phone_lookup ;;
            4) username_search ;;
            5) subdomain_scan ;;
            6) full_report ;;
            7) show_info ;;
            0) 
                clear
                echo ""
                echo -e "${RED}"
                cat << "EOF"
   ███╗   ██╗ ██╗ ██╗  ██╗  █████╗   
   ████╗  ██║ ██║ ██║ ██╔╝ ██╔══██╗  
   ██╔██╗ ██║ ██║ █████╔╝  ███████║  
   ██║╚██╗██║ ██║ ██╔═██╗  ██╔══██║  
   ██║ ╚████║ ██║ ██║  ██╗ ██║  ██║  
   ╚═╝  ╚═══╝ ╚═╝ ╚═╝  ╚═╝ ╚═╝  ╚═╝  
EOF
                echo -e "${NC}"
                echo -e "${MAGENTA}  Thanks for using NIKA OSINT!${NC}"
                echo -e "${MAGENTA}  created by kiwi & hide${NC}"
                echo ""
                exit 0
                ;;
            *)
                echo -e "${RED}[!] Invalid option${NC}"
                sleep 1
                ;;
        esac
    done
}

# Avvio
main
