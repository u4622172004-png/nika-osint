#!/data/data/com.termux/files/usr/bin/bash

echo "╔════════════════════════════════════════╗"
echo "║  OSINT Toolkit - Termux Installer     ║"
echo "╚════════════════════════════════════════╝"
echo ""

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}[*] Aggiornamento pacchetti...${NC}"
pkg update -y > /dev/null 2>&1
pkg upgrade -y > /dev/null 2>&1

echo -e "${CYAN}[*] Installazione Node.js...${NC}"
pkg install -y nodejs > /dev/null 2>&1

echo -e "${CYAN}[*] Installazione dipendenze npm...${NC}"
npm install

echo -e "${CYAN}[*] Configurazione permessi...${NC}"
chmod +x osint-ultra-max.js

echo -e "${CYAN}[*] Creazione alias...${NC}"
if ! grep -q "alias osint=" ~/.bashrc 2>/dev/null; then
    echo 'alias osint="node ~/osint-tool/osint-ultra-max.js"' >> ~/.bashrc
fi

echo ""
echo -e "${GREEN}✅ Installazione completata!${NC}"
echo ""
echo "Usa il tool con:"
echo "  ./osint-ultra-max.js --domain example.com"
echo ""
echo "O riavvia Termux e usa:"
echo "  osint --domain example.com"
echo ""
