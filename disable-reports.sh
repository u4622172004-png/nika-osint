#!/bin/bash

echo "🚫 Disabling report generation in ALL modules..."

# Lista di tutti i moduli
modules=(
    "osint-ultra-max.js"
    "nmap-scan.js"
    "sherlock-search.js"
    "theharvester-search.js"
    "reverse-image-search.js"
    "geo-tracker.js"
    "darkweb-scanner.js"
    "social-scraper.js"
    "breach-monitor.js"
    "ai-analyzer.js"
    "mac-lookup.js"
    "metadata-extractor.js"
    "dork-generator.js"
    "crypto-tracker.js"
    "ssl-analyzer.js"
)

for module in "${modules[@]}"; do
    if [ -f "$module" ]; then
        echo "  Processing $module..."
        
        # Backup
        cp "$module" "${module}.backup"
        
        # Commenta le chiamate a saveResults
        sed -i 's/^\(\s*\)saveResults(/\1\/\/ saveResults(/g' "$module"
        sed -i 's/if (saveResults_flag/if (false \&\& saveResults_flag/g' "$module"
        sed -i 's/if (save_flag/if (false \&\& save_flag/g' "$module"
        
        echo "    ✓ Done"
    fi
done

# Rimuovi --save dal menu
if [ -f "osint-menu-termux.sh" ]; then
    echo "  Processing menu..."
    cp osint-menu-termux.sh osint-menu-termux.sh.backup
    sed -i 's/ --save//g' osint-menu-termux.sh
    echo "    ✓ Done"
fi

# Rimuovi cartelle report esistenti
echo ""
echo "Removing existing report directories..."
rm -rf *-reports/

echo ""
echo "✅ Report generation DISABLED in all modules!"
echo ""
echo "📝 Backups saved as *.backup (to restore later if needed)"
echo ""
echo "To restore reports later, run:"
echo "  for f in *.backup; do mv \"\$f\" \"\${f%.backup}\"; done"

