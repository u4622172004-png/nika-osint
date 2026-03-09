#!/usr/bin/env node

const fs = require('fs');

// ============================================
// GOOGLE DORK GENERATOR - Advanced Search Automation
// ============================================

const DORK_CATEGORIES = {
  files: {
    name: 'File Discovery',
    templates: [
      'site:{target} filetype:pdf',
      'site:{target} filetype:doc',
      'site:{target} filetype:docx',
      'site:{target} filetype:xls',
      'site:{target} filetype:xlsx',
      'site:{target} filetype:ppt',
      'site:{target} filetype:txt',
      'site:{target} filetype:csv',
      'site:{target} filetype:sql',
      'site:{target} filetype:log',
      'site:{target} filetype:bak',
      'site:{target} filetype:conf',
      'site:{target} filetype:config',
      'site:{target} filetype:env',
      'site:{target} ext:xml',
      'site:{target} ext:json',
      'inurl:{target} filetype:pdf "confidential"',
      'inurl:{target} filetype:doc "internal use only"'
    ]
  },
  
  credentials: {
    name: 'Credential Leaks',
    templates: [
      'site:{target} intext:"password"',
      'site:{target} intext:"username"',
      'site:{target} intext:"admin"',
      'site:{target} intext:"login"',
      'site:{target} inurl:admin',
      'site:{target} inurl:login',
      'site:{target} inurl:password',
      'site:{target} "index of" "password.txt"',
      'site:{target} filetype:sql "password"',
      'site:{target} filetype:log "password"',
      'site:{target} ext:env "DB_PASSWORD"',
      'site:{target} ext:env "API_KEY"',
      'site:{target} "mysql_connect"',
      'site:{target} "pg_connect"',
      'inurl:{target} intext:"sql syntax near"'
    ]
  },
  
  sensitive: {
    name: 'Sensitive Information',
    templates: [
      'site:{target} intext:"confidential"',
      'site:{target} intext:"secret"',
      'site:{target} intext:"internal"',
      'site:{target} intext:"not for distribution"',
      'site:{target} intext:"ssn"',
      'site:{target} intext:"social security"',
      'site:{target} filetype:xls intext:"email"',
      'site:{target} filetype:csv intext:"email"',
      'site:{target} "index of" "backup"',
      'site:{target} "index of" "config"',
      'site:{target} "index of" "database"',
      'site:{target} intitle:"index of" "parent directory"',
      'site:{target} ext:bak',
      'site:{target} ext:old',
      'site:{target} ext:backup'
    ]
  },
  
  errors: {
    name: 'Error Messages & Debug',
    templates: [
      'site:{target} "fatal error"',
      'site:{target} "warning:"',
      'site:{target} "error:"',
      'site:{target} "exception"',
      'site:{target} "stack trace"',
      'site:{target} "syntax error"',
      'site:{target} "mysql error"',
      'site:{target} "ORA-" "error"',
      'site:{target} "SQL Server" "error"',
      'site:{target} intext:"Warning: mysql_connect()"',
      'site:{target} intext:"Error Message : Error loading"',
      'site:{target} "PHP Parse error"',
      'site:{target} "PHP Warning"',
      'site:{target} "PHP Error"'
    ]
  },
  
  admin: {
    name: 'Admin Panels',
    templates: [
      'site:{target} inurl:admin',
      'site:{target} inurl:administrator',
      'site:{target} inurl:login',
      'site:{target} inurl:cpanel',
      'site:{target} inurl:phpmyadmin',
      'site:{target} inurl:dashboard',
      'site:{target} inurl:wp-admin',
      'site:{target} inurl:wp-login',
      'site:{target} intitle:"admin panel"',
      'site:{target} intitle:"login"',
      'site:{target} intitle:"dashboard"',
      'site:{target} "powered by phpMyAdmin"',
      'site:{target} inurl:"/admin/login"',
      'site:{target} inurl:"/user/login"'
    ]
  },
  
  subdomains: {
    name: 'Subdomain Discovery',
    templates: [
      'site:*.{target}',
      'site:*.{target} -www',
      'site:dev.{target}',
      'site:staging.{target}',
      'site:test.{target}',
      'site:api.{target}',
      'site:admin.{target}',
      'site:mail.{target}',
      'site:ftp.{target}',
      'site:vpn.{target}',
      'site:portal.{target}',
      'site:beta.{target}'
    ]
  },
  
  technologies: {
    name: 'Technology Stack',
    templates: [
      'site:{target} "powered by"',
      'site:{target} "built with"',
      'site:{target} intext:"WordPress"',
      'site:{target} intext:"Joomla"',
      'site:{target} intext:"Drupal"',
      'site:{target} "Apache" "Server at"',
      'site:{target} "nginx"',
      'site:{target} "Microsoft-IIS"',
      'site:{target} ext:php',
      'site:{target} ext:asp',
      'site:{target} ext:jsp',
      'site:{target} ext:aspx'
    ]
  },
  
  social: {
    name: 'Social Media & Profiles',
    templates: [
      'site:linkedin.com "{target}"',
      'site:twitter.com "{target}"',
      'site:facebook.com "{target}"',
      'site:github.com "{target}"',
      'site:instagram.com "{target}"',
      'site:pinterest.com "{target}"',
      'site:reddit.com "{target}"',
      'site:youtube.com "{target}"',
      '"@{target}" site:linkedin.com',
      '"@{target}" site:twitter.com'
    ]
  },
  
  email: {
    name: 'Email Addresses',
    templates: [
      'site:{target} intext:"@{target}"',
      'site:{target} "email" | "e-mail"',
      'site:{target} "contact" intext:"@{target}"',
      '"@{target}" site:linkedin.com',
      '"@{target}" site:github.com',
      '"@{target}" filetype:pdf',
      '"@{target}" filetype:doc',
      '"@{target}" filetype:xls'
    ]
  },
  
  vulnerabilities: {
    name: 'Common Vulnerabilities',
    templates: [
      'site:{target} inurl:"/phpinfo.php"',
      'site:{target} inurl:"eval("',
      'site:{target} inurl:"exec("',
      'site:{target} inurl:"shell"',
      'site:{target} inurl:"cmd"',
      'site:{target} intext:"Index of /"',
      'site:{target} "parent directory"',
      'site:{target} intitle:"index of" ".git"',
      'site:{target} intitle:"index of" ".svn"',
      'site:{target} intitle:"index of" "backup"',
      'site:{target} ext:git',
      'site:{target} ext:svn',
      'site:{target} ".env"',
      'site:{target} "config.php"',
      'site:{target} "database.yml"'
    ]
  }
};

function generateDorks(target, categories = null) {
  const results = {
    target: target,
    timestamp: new Date().toISOString(),
    categories: {}
  };
  
  const categoriesToUse = categories || Object.keys(DORK_CATEGORIES);
  
  categoriesToUse.forEach(cat => {
    if (DORK_CATEGORIES[cat]) {
      const category = DORK_CATEGORIES[cat];
      const dorks = category.templates.map(template => 
        template.replace(/{target}/g, target)
      );
      
      results.categories[cat] = {
        name: category.name,
        count: dorks.length,
        dorks: dorks,
        searchUrls: dorks.map(dork => 
          `https://www.google.com/search?q=${encodeURIComponent(dork)}`
        )
      };
    }
  });
  
  return results;
}

function showBanner() {
  console.log("\x1b[31m");
  console.log("██████╗  ██████╗ ██████╗ ██╗  ██╗     ██████╗ ███████╗███╗   ██╗");
  console.log("██╔══██╗██╔═══██╗██╔══██╗██║ ██╔╝    ██╔════╝ ██╔════╝████╗  ██║");
  console.log("██║  ██║██║   ██║██████╔╝█████╔╝     ██║  ███╗█████╗  ██╔██╗ ██║");
  console.log("██║  ██║██║   ██║██╔══██╗██╔═██╗     ██║   ██║██╔══╝  ██║╚██╗██║");
  console.log("██████╔╝╚██████╔╝██║  ██║██║  ██╗    ╚██████╔╝███████╗██║ ╚████║");
  console.log("╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝     ╚═════╝ ╚══════╝╚═╝  ╚═══╝");
  console.log("\x1b[0m");
  console.log("\x1b[35m🥝 NIKA Google Dork Generator - Advanced Search Automation\x1b[0m");
  console.log("\x1b[33m⚠️  For authorized research only - Respect search engines ToS\x1b[0m\n");
}

function displayResults(data) {
  console.log("\n╔════════════════════════════════════════════════════════╗");
  console.log("║       🔍 GOOGLE DORK GENERATION RESULTS 🔍             ║");
  console.log("╚════════════════════════════════════════════════════════╝\n");
  
  console.log(`🎯 Target: \x1b[36m${data.target}\x1b[0m`);
  console.log(`📊 Categories: ${Object.keys(data.categories).length}`);
  
  const totalDorks = Object.values(data.categories).reduce((sum, cat) => sum + cat.count, 0);
  console.log(`🔢 Total Dorks: ${totalDorks}\n`);
  
  Object.entries(data.categories).forEach(([key, category]) => {
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
    console.log(`\x1b[36m${category.name} (${category.count} dorks)\x1b[0m`);
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
    
    category.dorks.forEach((dork, i) => {
      console.log(`${i + 1}. ${dork}`);
    });
    console.log('');
  });
  
  console.log("\x1b[33m💡 TIP: Copy dorks and paste into Google Search\x1b[0m");
  console.log("\x1b[33m💡 Use --save to export all dorks to file\x1b[0m\n");
}

function saveResults(data) {
  const dir = './dork-reports';
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, -5);
  const targetSafe = data.target.replace(/[^a-z0-9]/gi, '_');
  const jsonFile = `${dir}/${targetSafe}-${timestamp}.json`;
  const txtFile = jsonFile.replace('.json', '.txt');
  const urlsFile = `${dir}/${targetSafe}-${timestamp}-urls.txt`;
  
  // Save JSON
  fs.writeFileSync(jsonFile, JSON.stringify(data, null, 2));
  
  // Save TXT with dorks
  let txtContent = `═══════════════════════════════════════════════════════════
GOOGLE DORK GENERATOR REPORT
═══════════════════════════════════════════════════════════

Target: ${data.target}
Generated: ${new Date(data.timestamp).toLocaleString()}
Total Dorks: ${Object.values(data.categories).reduce((sum, cat) => sum + cat.count, 0)}
Categories: ${Object.keys(data.categories).length}

`;

  Object.entries(data.categories).forEach(([key, category]) => {
    txtContent += `═══════════════════════════════════════════════════════════
${category.name.toUpperCase()} (${category.count})
═══════════════════════════════════════════════════════════

`;
    category.dorks.forEach((dork, i) => {
      txtContent += `${i + 1}. ${dork}\n`;
    });
    txtContent += '\n';
  });
  
  fs.writeFileSync(txtFile, txtContent);
  
  // Save URLs file for easy clicking
  let urlsContent = `# Google Dork URLs for ${data.target}\n`;
  urlsContent += `# Generated: ${new Date(data.timestamp).toLocaleString()}\n\n`;
  
  Object.entries(data.categories).forEach(([key, category]) => {
    urlsContent += `# ${category.name}\n`;
    category.searchUrls.forEach(url => {
      urlsContent += `${url}\n`;
    });
    urlsContent += '\n';
  });
  
  fs.writeFileSync(urlsFile, urlsContent);
  
  console.log(`\x1b[32m✅ Results saved:\x1b[0m`);
  console.log(`   JSON: ${jsonFile}`);
  console.log(`   TXT: ${txtFile}`);
  console.log(`   URLs: ${urlsFile}\n`);
  
  console.log(`\x1b[33m💡 Open ${urlsFile} to click search links directly\x1b[0m\n`);
}

function showHelp() {
  showBanner();
  
  console.log("Usage: node dork-generator.js [OPTIONS] <target>\n");
  console.log("Options:");
  console.log("  --category <cat>  Generate only specific category");
  console.log("  --list            List available categories");
  console.log("  --save            Save results to file");
  console.log("  --help            Show this help\n");
  
  console.log("Available Categories:");
  Object.entries(DORK_CATEGORIES).forEach(([key, cat]) => {
    console.log(`  ${key.padEnd(20)} - ${cat.name}`);
  });
  console.log('');
  
  console.log("Examples:");
  console.log("  node dork-generator.js example.com");
  console.log("  node dork-generator.js example.com --save");
  console.log("  node dork-generator.js example.com --category credentials");
  console.log("  node dork-generator.js --list\n");
}

function main() {
  const args = process.argv.slice(2);
  
  if (args.includes('--help') || args.length === 0) {
    showHelp();
    process.exit(0);
  }
  
  if (args.includes('--list')) {
    showBanner();
    console.log("Available Categories:\n");
    Object.entries(DORK_CATEGORIES).forEach(([key, cat]) => {
      console.log(`\x1b[32m${key}\x1b[0m`);
      console.log(`  Name: ${cat.name}`);
      console.log(`  Dorks: ${cat.templates.length}`);
      console.log('');
    });
    process.exit(0);
  }
  
  let target = null;
  let category = null;
  let saveResults_flag = false;
  
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--category' && args[i + 1]) {
      category = [args[i + 1]];
      i++;
    } else if (args[i] === '--save') {
      saveResults_flag = true;
    } else if (!args[i].startsWith('--')) {
      target = args[i];
    }
  }
  
  if (!target) {
    console.log("\x1b[31m❌ No target specified!\x1b[0m\n");
    showHelp();
    process.exit(1);
  }
  
  showBanner();
  
  console.log(`⏳ Generating dorks for: ${target}...\n`);
  
  const results = generateDorks(target, category);
  
  displayResults(results);
  
  if (saveResults_flag) {
    saveResults(results);
  }
  
  console.log("\x1b[31m██████╗  ██████╗ ██████╗ ██╗  ██╗\x1b[0m");
  console.log("\x1b[35m🥝 Generation complete - by kiwi & 777\x1b[0m\n");
}

main();
