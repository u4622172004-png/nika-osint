#!/usr/bin/env node

const fs = require('fs');
const https = require('https');

// ============================================
// DORK SEARCH PRO - Advanced Dorking Database
// ============================================

const DORK_CATEGORIES = {
  admin: {
    name: 'Admin Panels & Login Pages',
    dorks: [
      'intitle:"Admin Panel" | intitle:"Administrator Login"',
      'inurl:admin | inurl:administrator | inurl:moderator',
      'inurl:login.php | inurl:admin.php | inurl:admin_login.php',
      'intitle:"Dashboard" inurl:admin',
      'inurl:/admin/index.php',
      'inurl:wp-admin',
      'inurl:administrator/index.php',
      'intitle:"phpMyAdmin" inurl:"index.php"',
      'intitle:"SquirrelMail" inurl:src/login.php',
      'inurl:"/admin/login.aspx"',
      'intitle:"cPanel" inurl:login',
      'inurl:webadmin | inurl:webmaster',
      'intext:"Powered by: AdminLTE"',
      'inurl:/admin/upload',
      'intitle:"Outlook Web App" inurl:owa',
      'site:*.edu inurl:admin',
      'site:*.gov inurl:admin',
      'inurl:admin intitle:login',
      'filetype:php inurl:"admin/login"',
      'inurl:administrator "welcome" | "bienvenue"'
    ]
  },
  
  sql: {
    name: 'SQL Injection & Database Errors',
    dorks: [
      'intext:"SQL syntax" | "MySQL server version" | "Warning: mysql"',
      'intext:"supplied argument is not a valid MySQL"',
      'inurl:index.php?id= intext:"You have an error in your SQL syntax"',
      'intext:"Microsoft OLE DB Provider for SQL Server"',
      'inurl:".php?id=" intext:"mysql_fetch"',
      'intext:"error in your SQL syntax"',
      'intext:"Warning: pg_connect()"',
      'intext:"PostgreSQL query failed"',
      'inurl:index.php?page= intext:"mysql"',
      'intext:"Microsoft SQL Native Client error"',
      'inurl:".php?cat=" intext:"mysql_query"',
      'intext:"Invalid SQL:" | "MySQL Error" | "ODBC Error"',
      'inurl:".php?categoryid=" intext:"mysql"',
      'inurl:".php?prodid=" intext:"mysql"',
      'intext:"mysqli_connect()"',
      'inurl:index.php?id= site:*.edu',
      'inurl:".php?newsid=" intext:"Warning: mysql"',
      'intext:"supplied argument is not a valid PostgreSQL"',
      'inurl:product.php?id= intext:"mysql"',
      'intext:"DB_Error" | "DB_Warning"'
    ]
  },
  
  files: {
    name: 'Exposed Files & Documents',
    dorks: [
      'filetype:pdf "confidential" | "not for distribution"',
      'filetype:xls | filetype:xlsx "password"',
      'filetype:doc | filetype:docx "confidential salary"',
      'filetype:sql "password" | "username"',
      'filetype:log inurl:password',
      'filetype:bak inurl:backup',
      'filetype:env "DB_PASSWORD"',
      'filetype:ini inurl:web.config',
      'ext:php intext:"$password =" | "$passwd ="',
      'filetype:txt "username" "password"',
      'filetype:csv "email" "password"',
      'filetype:xml "password" | "passwd"',
      'filetype:conf inurl:firewall',
      'filetype:cfg "password"',
      'ext:sql intext:INSERT INTO',
      'filetype:json "password" | "api_key"',
      'filetype:pem intext:"PRIVATE KEY"',
      'filetype:key intext:"BEGIN RSA PRIVATE KEY"',
      'ext:yml | ext:yaml "password:"',
      'filetype:config inurl:web.config'
    ]
  },
  
  cameras: {
    name: 'IP Cameras & DVR',
    dorks: [
      'inurl:/view/view.shtml',
      'inurl:ViewerFrame?Mode=',
      'intitle:"Live View / - AXIS"',
      'inurl:indexFrame.shtml Axis',
      'intitle:"EvoCam" inurl:webcam.html',
      'intitle:"Live NetSnap Cam-Server feed"',
      'intitle:"i-Catcher Console - Web Monitor"',
      'intitle:"Network Camera NetworkCamera"',
      'intitle:"Yawcam" inurl:8081',
      'inurl:view/viewer_index.shtml',
      'inurl:/eng/admin/adm_main.html',
      'intitle:"Blue Iris Login"',
      'inurl:/view.shtml',
      'intitle:"Camera Login" inurl:login.asp',
      'inurl:snapshot.jpg',
      'intitle:"IPCam Client" | "IP Camera"',
      'inurl:LvAppl intitle:liveapplet',
      'inurl:/h264_stream.cgi',
      'inurl:8080 intitle:"cam"',
      'inurl:"/cgi-bin/guestimage.html"'
    ]
  },
  
  logs: {
    name: 'Log Files & Error Pages',
    dorks: [
      'filetype:log inurl:access.log',
      'filetype:log inurl:error.log',
      'intitle:"Index of" "error.log"',
      'filetype:log "username" | "password"',
      'intitle:"Index of" inurl:ftp',
      'inurl:"/logs/access.log"',
      'filetype:log inurl:password',
      'intitle:"Index of /backup"',
      'filetype:bak intext:password',
      'inurl:".log" "username" "password"',
      'intitle:"Index of" ".log"',
      'filetype:log "PHP" "error"',
      'intitle:"index of" "debug.log"',
      'inurl:error_log',
      'filetype:log inurl:admin',
      'intitle:"Index of" "/logs/"',
      'filetype:log intext:"Exception"',
      'inurl:"/log/" "password"',
      'intitle:"Index of" "application.log"',
      'filetype:log inurl:mysql'
    ]
  },
  
  config: {
    name: 'Configuration Files',
    dorks: [
      'filetype:env "DB_PASSWORD"',
      'filetype:ini "password"',
      'ext:cfg "password" | "username"',
      'filetype:conf inurl:proftpd',
      'ext:properties "password"',
      'filetype:xml "ConnectionString"',
      'filetype:yaml "password:"',
      'filetype:toml "password"',
      'ext:cnf "password"',
      'filetype:config "ConnectionString"',
      'inurl:web.config "connectionString"',
      'filetype:ini "mysql"',
      'ext:yml "database:" "password:"',
      'filetype:json "password" | "secret"',
      'ext:conf inurl:nginx',
      'filetype:properties "jdbc"',
      'inurl:.env "APP_KEY"',
      'ext:config "appSettings"',
      'filetype:xml "jdbc"',
      'ext:ini "Database"'
    ]
  },
  
  github: {
    name: 'GitHub Secrets',
    dorks: [
      'filename:.env "DB_PASSWORD"',
      'filename:config.php "password"',
      'filename:.npmrc _auth',
      'filename:credentials "aws_access_key_id"',
      'filename:.git-credentials',
      'filename:wp-config.php "DB_PASSWORD"',
      'filename:.htpasswd',
      'filename:id_rsa or filename:id_dsa',
      'filename:.bash_history "password"',
      'filename:settings.py "SECRET_KEY"',
      'filename:.dockercfg auth',
      'filename:terraform.tfvars "password"',
      'filename:.config "api_key"',
      'HEROKU_API_KEY language:json',
      'HEROKU_API_KEY language:shell',
      'filename:filezilla.xml "Pass"',
      'filename:database.yml "password"',
      'filename:.ftpconfig',
      'filename:credentials.xml "password"',
      'filename:proftpdpasswd'
    ]
  },
  
  cloud: {
    name: 'Cloud & Buckets',
    dorks: [
      'site:s3.amazonaws.com "index.html of"',
      'site:s3.amazonaws.com inurl:backup',
      'site:blob.core.windows.net',
      'site:storage.googleapis.com',
      'site:s3.amazonaws.com filetype:pdf',
      'inurl:"s3.amazonaws.com/" "Bucket"',
      'site:s3.amazonaws.com inurl:uploads',
      'site:blob.core.windows.net "index of"',
      'site:digitaloceanspaces.com',
      'inurl:s3.amazonaws.com "logs"',
      'site:storage.googleapis.com "backup"',
      'site:s3.amazonaws.com filetype:sql',
      'site:amazonaws.com filetype:xls',
      'inurl:.s3.amazonaws.com',
      'site:s3.amazonaws.com "password"',
      'site:firebase.com',
      'site:firebaseio.com',
      'inurl:"storage.googleapis.com"',
      'site:s3.amazonaws.com filetype:env',
      'site:cloudfront.net'
    ]
  },
  
  iot: {
    name: 'IoT & Smart Devices',
    dorks: [
      'inurl:8080 intitle:"Amcrest"',
      'inurl:"/cgi-bin/login.cgi"',
      'intitle:"Raspberry Pi" inurl:8080',
      'intitle:"Home Assistant" inurl:8123',
      'inurl:"/api/config" "Home Assistant"',
      'intitle:"Router" inurl:login',
      'inurl:8081 intitle:"Home"',
      'intitle:"Printer" inurl:status',
      'inurl:631/printers',
      'intitle:"Tesla" inurl:login',
      'intitle:"Sonos" inurl:status',
      'intitle:"Phillips Hue"',
      'inurl:3000 intitle:"Grafana"',
      'inurl:9000 intitle:"Portainer"',
      'intitle:"Ubiquiti" inurl:manage',
      'inurl:8006 "Proxmox"',
      'intitle:"pfSense" inurl:status',
      'inurl:5000 intitle:"Synology"',
      'intitle:"QNAP" inurl:cgi-bin',
      'inurl:10000 intitle:"Webmin"'
    ]
  }
};

const ADVANCED_OPERATORS = {
  site: 'site:example.com - Search specific domain',
  inurl: 'inurl:admin - URL contains term',
  intitle: 'intitle:login - Title contains term',
  intext: 'intext:password - Body text contains term',
  filetype: 'filetype:pdf - Specific file type',
  ext: 'ext:php - File extension',
  cache: 'cache:example.com - Cached version',
  link: 'link:example.com - Pages linking to',
  related: 'related:example.com - Similar sites',
  info: 'info:example.com - Site info',
  define: 'define:term - Definition',
  stocks: 'stocks:AAPL - Stock info',
  map: 'map:location - Google maps',
  movie: 'movie:title - Movie info',
  weather: 'weather:city - Weather',
  source: 'source:name - News source',
  before: 'before:2024-01-01 - Before date',
  after: 'after:2023-01-01 - After date'
};

const SHODAN_DORKS = [
  'port:22 country:"US"',
  'port:3389 country:"US"',
  'port:445 os:"Windows"',
  'port:23 Telnet',
  'port:21 FTP',
  'port:80,443 country:"US" city:"New York"',
  'product:"Apache httpd"',
  'product:"nginx"',
  'product:"Microsoft IIS"',
  'port:27017 product:"MongoDB"',
  'port:3306 product:"MySQL"',
  'port:5432 product:"PostgreSQL"',
  'port:6379 product:"Redis"',
  'port:9200 product:"Elasticsearch"',
  'port:8080 "Jenkins"',
  'ssl.cert.subject.CN:"*.gov"',
  'port:1883 product:"Mosquitto"',
  'webcam',
  'default password',
  'http.title:"Dashboard"'
];

function showBanner() {
  console.log("\x1b[31m");
  console.log("██████╗  ██████╗ ██████╗ ██╗  ██╗    ███████╗███████╗ █████╗ ██████╗  ██████╗██╗  ██╗");
  console.log("██╔══██╗██╔═══██╗██╔══██╗██║ ██╔╝    ██╔════╝██╔════╝██╔══██╗██╔══██╗██╔════╝██║  ██║");
  console.log("██║  ██║██║   ██║██████╔╝█████╔╝     ███████╗█████╗  ███████║██████╔╝██║     ███████║");
  console.log("██║  ██║██║   ██║██╔══██╗██╔═██╗     ╚════██║██╔══╝  ██╔══██║██╔══██╗██║     ██╔══██║");
  console.log("██████╔╝╚██████╔╝██║  ██║██║  ██╗    ███████║███████╗██║  ██║██║  ██║╚██████╗██║  ██║");
  console.log("╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝    ╚══════╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝");
  console.log("                                                                                      ");
  console.log("██████╗ ██████╗  ██████╗                                                             ");
  console.log("██╔══██╗██╔══██╗██╔═══██╗                                                            ");
  console.log("██████╔╝██████╔╝██║   ██║                                                            ");
  console.log("██╔═══╝ ██╔══██╗██║   ██║                                                            ");
  console.log("██║     ██║  ██║╚██████╔╝                                                            ");
  console.log("╚═╝     ╚═╝  ╚═╝ ╚═════╝                                                             ");
  console.log("\x1b[0m");
  console.log("\x1b[35m🥝 NIKA Dork Search Pro - Advanced Dorking Database\x1b[0m");
  console.log("\x1b[33m⚠️  For authorized testing only - Use responsibly\x1b[0m\n");
}

function listCategories() {
  console.log("\n╔════════════════════════════════════════════════════════╗");
  console.log("║       📚 AVAILABLE DORK CATEGORIES 📚                  ║");
  console.log("╚════════════════════════════════════════════════════════╝\n");
  
  let index = 1;
  Object.entries(DORK_CATEGORIES).forEach(([key, cat]) => {
    console.log(`   ${index}. \x1b[32m${cat.name}\x1b[0m (${cat.dorks.length} dorks)`);
    index++;
  });
  
  console.log(`   ${index}. \x1b[32mShodan Dorks\x1b[0m (${SHODAN_DORKS.length} dorks)`);
  console.log(`   ${index + 1}. \x1b[32mAdvanced Operators\x1b[0m (${Object.keys(ADVANCED_OPERATORS).length} operators)`);
  console.log('');
}

function displayDorks(category, target = null) {
  const cat = DORK_CATEGORIES[category];
  
  console.log("\n╔════════════════════════════════════════════════════════╗");
  console.log(`║       🔍 ${cat.name.toUpperCase().padEnd(43)} ║`);
  console.log("╚════════════════════════════════════════════════════════╝\n");
  
  cat.dorks.forEach((dork, i) => {
    let finalDork = dork;
    
    if (target) {
      // Add target to dork
      if (dork.includes('site:')) {
        finalDork = dork;
      } else {
        finalDork = `${dork} site:${target}`;
      }
    }
    
    console.log(`${i + 1}. ${finalDork}`);
  });
  
  console.log(`\n\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m`);
  console.log(`\x1b[36m📊 QUICK SEARCH LINKS\x1b[0m`);
  console.log(`\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n`);
  
  // Show first 3 Google search links
  cat.dorks.slice(0, 3).forEach((dork, i) => {
    let finalDork = target ? `${dork} site:${target}` : dork;
    const encoded = encodeURIComponent(finalDork);
    console.log(`   Google ${i + 1}: https://www.google.com/search?q=${encoded}`);
  });
  
  console.log('');
}

function displayShodanDorks() {
  console.log("\n╔════════════════════════════════════════════════════════╗");
  console.log("║       🌐 SHODAN SEARCH DORKS 🌐                        ║");
  console.log("╚════════════════════════════════════════════════════════╝\n");
  
  SHODAN_DORKS.forEach((dork, i) => {
    console.log(`${i + 1}. ${dork}`);
  });
  
  console.log(`\n\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m`);
  console.log(`\x1b[36m🔗 SHODAN SEARCH\x1b[0m`);
  console.log(`\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n`);
  
  console.log(`   Shodan: https://www.shodan.io/`);
  console.log(`   Censys: https://search.censys.io/`);
  console.log(`   ZoomEye: https://www.zoomeye.org/`);
  console.log('');
}

function displayOperators() {
  console.log("\n╔════════════════════════════════════════════════════════╗");
  console.log("║       ⚙️  ADVANCED SEARCH OPERATORS ⚙️                  ║");
  console.log("╚════════════════════════════════════════════════════════╝\n");
  
  Object.entries(ADVANCED_OPERATORS).forEach(([op, desc]) => {
    console.log(`   \x1b[32m${op.padEnd(10)}\x1b[0m - ${desc}`);
  });
  
  console.log(`\n\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m`);
  console.log(`\x1b[36m💡 COMBO EXAMPLES\x1b[0m`);
  console.log(`\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n`);
  
  console.log('   site:example.com filetype:pdf');
  console.log('   intitle:"index of" inurl:backup');
  console.log('   intext:"password" filetype:log');
  console.log('   site:*.edu inurl:admin');
  console.log('   inurl:".php?id=" site:*.gov');
  console.log('');
}

function generateCustomDork(target, type) {
  const templates = {
    admin: [
      `site:${target} inurl:admin`,
      `site:${target} intitle:"Admin Panel"`,
      `site:${target} inurl:login.php`,
      `site:${target} inurl:administrator`
    ],
    files: [
      `site:${target} filetype:pdf`,
      `site:${target} filetype:doc | filetype:docx`,
      `site:${target} filetype:xls | filetype:xlsx`,
      `site:${target} filetype:sql`
    ],
    backup: [
      `site:${target} intitle:"index of" inurl:backup`,
      `site:${target} filetype:bak`,
      `site:${target} inurl:backup.zip`,
      `site:${target} filetype:sql inurl:backup`
    ],
    config: [
      `site:${target} filetype:env`,
      `site:${target} ext:cfg`,
      `site:${target} inurl:web.config`,
      `site:${target} filetype:ini`
    ],
    errors: [
      `site:${target} intext:"SQL syntax"`,
      `site:${target} intext:"Warning: mysql"`,
      `site:${target} intext:"error" | "warning"`,
      `site:${target} intitle:"Error"`
    ]
  };
  
  return templates[type] || templates.admin;
}

function saveResults(data) {
  const dir = './dork-search-reports';
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, -5);
  const filename = `${dir}/dorks-${data.category}-${timestamp}.txt`;
  
  let content = `═══════════════════════════════════════════════════════════
DORK SEARCH PRO - ${data.categoryName}
═══════════════════════════════════════════════════════════

Generated: ${new Date().toLocaleString()}
Target: ${data.target || 'N/A'}
Total Dorks: ${data.dorks.length}

`;

  data.dorks.forEach((dork, i) => {
    content += `${i + 1}. ${dork}\n`;
  });
  
  content += `\n═══════════════════════════════════════════════════════════
GOOGLE SEARCH LINKS (First 10)
═══════════════════════════════════════════════════════════\n\n`;

  data.dorks.slice(0, 10).forEach((dork, i) => {
    const encoded = encodeURIComponent(dork);
    content += `${i + 1}. https://www.google.com/search?q=${encoded}\n`;
  });
  
  fs.writeFileSync(filename, content);
  
  console.log(`\x1b[32m✅ Dorks saved to: ${filename}\x1b[0m\n`);
}

function showHelp() {
  showBanner();
  
  console.log("Usage: node dork-search-pro.js [OPTIONS]\n");
  console.log("Options:");
  console.log("  --list               List all categories");
  console.log("  --category <name>    Show dorks for category");
  console.log("  --target <domain>    Add target to dorks");
  console.log("  --shodan             Show Shodan dorks");
  console.log("  --operators          Show advanced operators");
  console.log("  --custom <target>    Generate custom dorks");
  console.log("  --save               Save results to file");
  console.log("  --help               Show this help\n");
  
  console.log("Categories:");
  console.log("  admin, sql, files, cameras, logs, config, github, cloud, iot\n");
  
  console.log("Examples:");
  console.log("  node dork-search-pro.js --list");
  console.log("  node dork-search-pro.js --category admin");
  console.log("  node dork-search-pro.js --category sql --target example.com");
  console.log("  node dork-search-pro.js --shodan");
  console.log("  node dork-search-pro.js --operators");
  console.log("  node dork-search-pro.js --custom example.com --save\n");
}

function main() {
  const args = process.argv.slice(2);
  
  if (args.length === 0 || args.includes('--help')) {
    showHelp();
    process.exit(0);
  }
  
  showBanner();
  
  if (args.includes('--list')) {
    listCategories();
    process.exit(0);
  }
  
  if (args.includes('--shodan')) {
    displayShodanDorks();
    process.exit(0);
  }
  
  if (args.includes('--operators')) {
    displayOperators();
    process.exit(0);
  }
  
  let category = null;
  let target = null;
  let saveFlag = false;
  let customFlag = false;
  
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--category') {
      category = args[i + 1];
      i++;
    } else if (args[i] === '--target') {
      target = args[i + 1];
      i++;
    } else if (args[i] === '--save') {
      saveFlag = true;
    } else if (args[i] === '--custom') {
      customFlag = true;
      target = args[i + 1];
      i++;
    }
  }
  
  if (customFlag && target) {
    console.log("\n╔════════════════════════════════════════════════════════╗");
    console.log("║       🎯 CUSTOM DORKS GENERATOR 🎯                     ║");
    console.log("╚════════════════════════════════════════════════════════╝\n");
    
    console.log(`Target: \x1b[36m${target}\x1b[0m\n`);
    
    const types = ['admin', 'files', 'backup', 'config', 'errors'];
    const allDorks = [];
    
    types.forEach(type => {
      console.log(`\x1b[32m${type.toUpperCase()}\x1b[0m`);
      const dorks = generateCustomDork(target, type);
      dorks.forEach((dork, i) => {
        console.log(`   ${i + 1}. ${dork}`);
        allDorks.push(dork);
      });
      console.log('');
    });
    
    if (saveFlag) {
      saveResults({
        category: 'custom',
        categoryName: 'Custom Generated Dorks',
        target: target,
        dorks: allDorks
      });
    }
    
    process.exit(0);
  }
  
  if (category) {
    if (!DORK_CATEGORIES[category]) {
      console.log(`\x1b[31m❌ Unknown category: ${category}\x1b[0m\n`);
      listCategories();
      process.exit(1);
    }
    
    displayDorks(category, target);
    
    if (saveFlag) {
      const dorks = DORK_CATEGORIES[category].dorks.map(d => 
        target ? `${d} site:${target}` : d
      );
      
      saveResults({
        category: category,
        categoryName: DORK_CATEGORIES[category].name,
        target: target,
        dorks: dorks
      });
    }
    
    process.exit(0);
  }
  
  console.log("\x1b[31m❌ No action specified!\x1b[0m\n");
  showHelp();
}

main();
