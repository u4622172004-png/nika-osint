#!/usr/bin/env node

const { exec } = require('child_process');
const { promisify } = require('util');
const execAsync = promisify(exec);
const fs = require('fs');

// ============================================
// GITHUB SECRETS SCANNER - Exposed Credentials Detector
// ============================================

const SECRET_PATTERNS = {
  'AWS Access Key': {
    pattern: /AKIA[0-9A-Z]{16}/g,
    severity: 'CRITICAL',
    description: 'AWS Access Key ID'
  },
  'AWS Secret Key': {
    pattern: /aws(.{0,20})?['\"][0-9a-zA-Z\/+]{40}['\"]/ gi,
    severity: 'CRITICAL',
    description: 'AWS Secret Access Key'
  },
  'Google API Key': {
    pattern: /AIza[0-9A-Za-z\\-_]{35}/g,
    severity: 'HIGH',
    description: 'Google API Key'
  },
  'Google OAuth': {
    pattern: /[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com/g,
    severity: 'HIGH',
    description: 'Google OAuth Client ID'
  },
  'GitHub Token': {
    pattern: /gh[pousr]_[0-9a-zA-Z]{36}/g,
    severity: 'CRITICAL',
    description: 'GitHub Personal Access Token'
  },
  'GitHub OAuth': {
    pattern: /[gG][iI][tT][hH][uU][bB].*['|"][0-9a-zA-Z]{35,40}['|"]/g,
    severity: 'HIGH',
    description: 'GitHub OAuth Token'
  },
  'Slack Token': {
    pattern: /xox[baprs]-([0-9a-zA-Z]{10,48})/g,
    severity: 'HIGH',
    description: 'Slack Token'
  },
  'Stripe API Key': {
    pattern: /sk_live_[0-9a-zA-Z]{24}/g,
    severity: 'CRITICAL',
    description: 'Stripe Live Secret Key'
  },
  'Stripe Restricted Key': {
    pattern: /rk_live_[0-9a-zA-Z]{24}/g,
    severity: 'HIGH',
    description: 'Stripe Restricted Key'
  },
  'Square Access Token': {
    pattern: /sq0atp-[0-9A-Za-z\-_]{22}/g,
    severity: 'CRITICAL',
    description: 'Square Access Token'
  },
  'Square OAuth Secret': {
    pattern: /sq0csp-[0-9A-Za-z\-_]{43}/g,
    severity: 'CRITICAL',
    description: 'Square OAuth Secret'
  },
  'PayPal/Braintree': {
    pattern: /access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}/g,
    severity: 'CRITICAL',
    description: 'PayPal/Braintree Access Token'
  },
  'Twilio API Key': {
    pattern: /SK[0-9a-fA-F]{32}/g,
    severity: 'HIGH',
    description: 'Twilio API Key'
  },
  'SendGrid API Key': {
    pattern: /SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}/g,
    severity: 'HIGH',
    description: 'SendGrid API Key'
  },
  'Mailgun API Key': {
    pattern: /key-[0-9a-zA-Z]{32}/g,
    severity: 'MEDIUM',
    description: 'Mailgun API Key'
  },
  'Mailchimp API Key': {
    pattern: /[0-9a-f]{32}-us[0-9]{1,2}/g,
    severity: 'MEDIUM',
    description: 'Mailchimp API Key'
  },
  'Heroku API Key': {
    pattern: /[hH][eE][rR][oO][kK][uU].*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}/gi,
    severity: 'HIGH',
    description: 'Heroku API Key'
  },
  'DigitalOcean Token': {
    pattern: /dop_v1_[a-f0-9]{64}/g,
    severity: 'HIGH',
    description: 'DigitalOcean Personal Access Token'
  },
  'Slack Webhook': {
    pattern: /https:\/\/hooks\.slack\.com\/services\/T[a-zA-Z0-9_]{8}\/B[a-zA-Z0-9_]{8}\/[a-zA-Z0-9_]{24}/g,
    severity: 'MEDIUM',
    description: 'Slack Webhook URL'
  },
  'Private SSH Key': {
    pattern: /-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----/g,
    severity: 'CRITICAL',
    description: 'Private SSH Key'
  },
  'Private PGP Key': {
    pattern: /-----BEGIN PGP PRIVATE KEY BLOCK-----/g,
    severity: 'CRITICAL',
    description: 'Private PGP Key'
  },
  'Generic API Key': {
    pattern: /[aA][pP][iI]_?[kK][eE][yY].*['|"][0-9a-zA-Z]{32,45}['|"]/g,
    severity: 'MEDIUM',
    description: 'Generic API Key'
  },
  'Generic Secret': {
    pattern: /[sS][eE][cC][rR][eE][tT].*['|"][0-9a-zA-Z]{32,45}['|"]/g,
    severity: 'MEDIUM',
    description: 'Generic Secret'
  },
  'Password in Code': {
    pattern: /[pP][aA][sS][sS][wW][oO][rR][dD].*['|"][^'|"]{8,}['|"]/g,
    severity: 'HIGH',
    description: 'Password in source code'
  },
  'Database URL': {
    pattern: /(postgres|mysql|mongodb):\/\/[^\s]+:[^\s]+@[^\s]+/gi,
    severity: 'CRITICAL',
    description: 'Database Connection String with credentials'
  },
  'JWT Token': {
    pattern: /eyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*/g,
    severity: 'MEDIUM',
    description: 'JSON Web Token'
  },
  'Generic Token': {
    pattern: /[tT][oO][kK][eE][nN].*['|"][0-9a-zA-Z\-_]{32,}['|"]/g,
    severity: 'MEDIUM',
    description: 'Generic Authentication Token'
  },
  'NPM Token': {
    pattern: /npm_[A-Za-z0-9]{36}/g,
    severity: 'HIGH',
    description: 'NPM Access Token'
  },
  'Docker Hub Token': {
    pattern: /dckr_pat_[a-zA-Z0-9_-]{40}/g,
    severity: 'HIGH',
    description: 'Docker Hub Access Token'
  },
  'Firebase': {
    pattern: /firebase.*['|"][0-9a-zA-Z\-_]{30,}['|"]/gi,
    severity: 'HIGH',
    description: 'Firebase API Key'
  },
  'Azure Client Secret': {
    pattern: /client_secret.*['|"][0-9a-zA-Z\-_~]{34,}['|"]/gi,
    severity: 'CRITICAL',
    description: 'Azure Client Secret'
  },
  'Cloudflare API Key': {
    pattern: /cloudflare.*['|"][0-9a-f]{37}['|"]/gi,
    severity: 'HIGH',
    description: 'Cloudflare API Key'
  }
};

async function searchGitHubRepo(repo, token) {
  try {
    console.log(`   Cloning repository: ${repo}...`);
    
    const repoName = repo.split('/').pop().replace('.git', '');
    const cloneDir = `/tmp/github-scan-${Date.now()}`;
    
    // Clone repo
    const cloneCmd = token 
      ? `git clone https://${token}@github.com/${repo} ${cloneDir}`
      : `git clone https://github.com/${repo} ${cloneDir}`;
    
    await execAsync(cloneCmd, { timeout: 60000 });
    
    // Scan files
    const secrets = await scanDirectory(cloneDir);
    
    // Cleanup
    await execAsync(`rm -rf ${cloneDir}`);
    
    return secrets;
  } catch (error) {
    return {
      error: error.message,
      available: false
    };
  }
}

async function scanDirectory(dir) {
  const secrets = [];
  
  async function scanDir(currentDir) {
    const files = fs.readdirSync(currentDir);
    
    for (const file of files) {
      const filePath = `${currentDir}/${file}`;
      const stat = fs.statSync(filePath);
      
      // Skip .git directory and large files
      if (file === '.git' || file === 'node_modules') continue;
      
      if (stat.isDirectory()) {
        await scanDir(filePath);
      } else if (stat.isFile() && stat.size < 1024 * 1024) { // Skip files > 1MB
        try {
          const content = fs.readFileSync(filePath, 'utf8');
          const fileSecrets = scanContent(content, filePath);
          secrets.push(...fileSecrets);
        } catch (e) {
          // Skip binary files or unreadable files
        }
      }
    }
  }
  
  await scanDir(dir);
  return secrets;
}

function scanContent(content, filePath) {
  const found = [];
  
  Object.entries(SECRET_PATTERNS).forEach(([name, config]) => {
    const matches = content.match(config.pattern);
    
    if (matches) {
      matches.forEach(match => {
        // Get line number
        const lines = content.substring(0, content.indexOf(match)).split('\n');
        const lineNumber = lines.length;
        const lineContent = content.split('\n')[lineNumber - 1];
        
        found.push({
          type: name,
          severity: config.severity,
          description: config.description,
          file: filePath,
          line: lineNumber,
          match: match.substring(0, 50) + (match.length > 50 ? '...' : ''), // Truncate for safety
          context: lineContent.trim().substring(0, 100)
        });
      });
    }
  });
  
  return found;
}

async function searchGitHubCode(query, token) {
  try {
    console.log(`   Searching GitHub code for: ${query}...`);
    
    if (!token) {
      return {
        source: 'GitHub Code Search',
        available: false,
        error: 'GitHub token required (set GITHUB_TOKEN env variable)',
        manualCheck: `https://github.com/search?type=code&q=${encodeURIComponent(query)}`
      };
    }
    
    const url = `https://api.github.com/search/code?q=${encodeURIComponent(query)}`;
    const cmd = `curl -s -H "Authorization: token ${token}" -H "Accept: application/vnd.github.v3+json" "${url}"`;
    
    const { stdout } = await execAsync(cmd, { timeout: 10000 });
    const data = JSON.parse(stdout);
    
    if (data.items) {
      return {
        source: 'GitHub Code Search',
        available: true,
        totalCount: data.total_count,
        items: data.items.slice(0, 10).map(item => ({
          name: item.name,
          path: item.path,
          repo: item.repository.full_name,
          url: item.html_url
        }))
      };
    }
    
    return {
      source: 'GitHub Code Search',
      available: true,
      found: false
    };
  } catch (error) {
    return {
      source: 'GitHub Code Search',
      available: false,
      error: error.message
    };
  }
}

function generateSearchQueries(target) {
  const queries = [
    `"${target}" password`,
    `"${target}" api_key`,
    `"${target}" secret`,
    `"${target}" token`,
    `"${target}" credentials`,
    `"${target}" AKIA`, // AWS
    `"${target}" sk_live`, // Stripe
    `"${target}" AIza`, // Google
    `"${target}" extension:env`,
    `"${target}" extension:config`,
    `"${target}" filename:.env`,
    `"${target}" filename:config`,
    `"${target}" filename:credentials`,
    `"${target}" remove_filter:blob`, // Search commits
    `org:${target} password`,
    `org:${target} api_key`
  ];
  
  return queries;
}

function assessRisk(secrets) {
  const severityCounts = {
    CRITICAL: 0,
    HIGH: 0,
    MEDIUM: 0,
    LOW: 0
  };
  
  secrets.forEach(secret => {
    severityCounts[secret.severity]++;
  });
  
  let score = severityCounts.CRITICAL * 25 + severityCounts.HIGH * 15 + severityCounts.MEDIUM * 5 + severityCounts.LOW * 2;
  score = Math.min(score, 100);
  
  let level;
  if (score >= 75 || severityCounts.CRITICAL > 0) level = 'CRITICAL';
  else if (score >= 50 || severityCounts.HIGH > 0) level = 'HIGH';
  else if (score >= 25) level = 'MEDIUM';
  else if (score > 0) level = 'LOW';
  else level = 'CLEAN';
  
  return {
    score: score,
    level: level,
    counts: severityCounts,
    total: secrets.length
  };
}

function showBanner() {
  console.log("\x1b[31m");
  console.log(" ██████╗ ██╗████████╗██╗  ██╗██╗   ██╗██████╗     ███████╗███████╗ ██████╗██████╗ ███████╗████████╗███████╗");
  console.log("██╔════╝ ██║╚══██╔══╝██║  ██║██║   ██║██╔══██╗    ██╔════╝██╔════╝██╔════╝██╔══██╗██╔════╝╚══██╔══╝██╔════╝");
  console.log("██║  ███╗██║   ██║   ███████║██║   ██║██████╔╝    ███████╗█████╗  ██║     ██████╔╝█████╗     ██║   ███████╗");
  console.log("██║   ██║██║   ██║   ██╔══██║██║   ██║██╔══██╗    ╚════██║██╔══╝  ██║     ██╔══██╗██╔══╝     ██║   ╚════██║");
  console.log("╚██████╔╝██║   ██║   ██║  ██║╚██████╔╝██████╔╝    ███████║███████╗╚██████╗██║  ██║███████╗   ██║   ███████║");
  console.log(" ╚═════╝ ╚═╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚═════╝     ╚══════╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚══════╝   ╚═╝   ╚══════╝");
  console.log("\x1b[0m");
  console.log("\x1b[35m🥝 NIKA GitHub Secrets Scanner - Exposed Credentials Detector\x1b[0m");
  console.log("\x1b[33m⚠️  For authorized security audits only - Handle secrets responsibly\x1b[0m\n");
}

function displayResults(data) {
  console.log("\n╔════════════════════════════════════════════════════════╗");
  console.log("║       🔐 GITHUB SECRETS SCAN RESULTS 🔐                ║");
  console.log("╚════════════════════════════════════════════════════════╝\n");
  
  if (data.repo) {
    console.log(`📦 Repository: \x1b[36m${data.repo}\x1b[0m\n`);
  } else if (data.target) {
    console.log(`🎯 Target: \x1b[36m${data.target}\x1b[0m\n`);
  }
  
  // Risk Assessment
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
  console.log("\x1b[36m⚠️  RISK ASSESSMENT\x1b[0m");
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
  
  const riskColor = {
    'CRITICAL': '\x1b[41m\x1b[37m',
    'HIGH': '\x1b[31m',
    'MEDIUM': '\x1b[33m',
    'LOW': '\x1b[32m',
    'CLEAN': '\x1b[32m'
  };
  
  console.log(`   Risk Level: ${riskColor[data.risk.level]}${data.risk.level}\x1b[0m`);
  console.log(`   Risk Score: ${data.risk.score}/100`);
  console.log(`   Total Secrets Found: ${data.risk.total}\n`);
  
  console.log('   Severity Breakdown:');
  console.log(`   CRITICAL: ${data.risk.counts.CRITICAL}`);
  console.log(`   HIGH: ${data.risk.counts.HIGH}`);
  console.log(`   MEDIUM: ${data.risk.counts.MEDIUM}`);
  console.log(`   LOW: ${data.risk.counts.LOW}\n`);
  
  // Secrets Found
  if (data.secrets && data.secrets.length > 0) {
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
    console.log("\x1b[36m🔓 EXPOSED SECRETS\x1b[0m");
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
    
    // Group by severity
    const bySeverity = {
      CRITICAL: [],
      HIGH: [],
      MEDIUM: [],
      LOW: []
    };
    
    data.secrets.forEach(secret => {
      bySeverity[secret.severity].push(secret);
    });
    
    // Display CRITICAL first
    Object.entries(bySeverity).forEach(([severity, secrets]) => {
      if (secrets.length > 0) {
        console.log(`   ${riskColor[severity]}[${severity}]\x1b[0m ${secrets.length} findings:\n`);
        
        secrets.slice(0, 5).forEach((secret, i) => {
          console.log(`   ${i + 1}. ${secret.type}`);
          console.log(`      File: ${secret.file}`);
          console.log(`      Line: ${secret.line}`);
          console.log(`      Match: ${secret.match}`);
          console.log('');
        });
        
        if (secrets.length > 5) {
          console.log(`   ... and ${secrets.length - 5} more ${severity} findings\n`);
        }
      }
    });
  }
  
  // Search Queries
  if (data.searchQueries) {
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
    console.log("\x1b[36m🔍 RECOMMENDED GITHUB SEARCHES\x1b[0m");
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
    
    data.searchQueries.slice(0, 8).forEach((query, i) => {
      console.log(`   ${i + 1}. ${query}`);
      console.log(`      https://github.com/search?type=code&q=${encodeURIComponent(query)}`);
      console.log('');
    });
    
    console.log(`   ... and ${data.searchQueries.length - 8} more queries (see report)\n`);
  }
  
  // Recommendations
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
  console.log("\x1b[36m💡 RECOMMENDATIONS\x1b[0m");
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
  
  if (data.risk.level === 'CRITICAL' || data.risk.level === 'HIGH') {
    console.log('   \x1b[31m🚨 CRITICAL - IMMEDIATE ACTION REQUIRED!\x1b[0m');
    console.log('   1. ROTATE all exposed credentials immediately');
    console.log('   2. Review commit history for exposure timeline');
    console.log('   3. Check for unauthorized access using exposed credentials');
    console.log('   4. Use BFG Repo-Cleaner or git-filter-repo to remove from history');
    console.log('   5. Enable GitHub secret scanning alerts');
    console.log('   6. Implement pre-commit hooks to prevent future leaks');
  } else if (data.risk.level === 'MEDIUM') {
    console.log('   \x1b[33m⚠️  MEDIUM RISK - ACTION RECOMMENDED\x1b[0m');
    console.log('   • Review and rotate exposed credentials');
    console.log('   • Remove secrets from repository');
    console.log('   • Use environment variables or secret managers');
  } else if (data.secrets.length > 0) {
    console.log('   \x1b[32m✓ Low risk findings\x1b[0m');
    console.log('   • Review flagged items for false positives');
    console.log('   • Consider implementing secret scanning in CI/CD');
  } else {
    console.log('   \x1b[32m✓ No secrets detected\x1b[0m');
    console.log('   • Continue monitoring with GitHub secret scanning');
    console.log('   • Implement automated scanning in development workflow');
  }
  
  console.log('\n   General Best Practices:');
  console.log('   • Use .gitignore to exclude sensitive files');
  console.log('   • Store secrets in environment variables');
  console.log('   • Use secret management tools (Vault, AWS Secrets Manager)');
  console.log('   • Enable GitHub secret scanning');
  console.log('   • Use pre-commit hooks (truffleHog, git-secrets)');
  console.log('');
}

function saveResults(data) {
  const dir = './github-secrets-reports';
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, -5);
  const targetSafe = (data.repo || data.target || 'scan').replace(/[^a-z0-9]/gi, '_');
  const jsonFile = `${dir}/${targetSafe}-${timestamp}.json`;
  const txtFile = jsonFile.replace('.json', '.txt');
  
  // Redact actual secret values in saved report
  const redactedData = JSON.parse(JSON.stringify(data));
  if (redactedData.secrets) {
    redactedData.secrets = redactedData.secrets.map(s => ({
      ...s,
      match: '[REDACTED]',
      context: '[REDACTED]'
    }));
  }
  
  fs.writeFileSync(jsonFile, JSON.stringify(redactedData, null, 2));
  
  let txtContent = `═══════════════════════════════════════════════════════════
GITHUB SECRETS SCANNER REPORT
═══════════════════════════════════════════════════════════

${data.repo ? `Repository: ${data.repo}` : `Target: ${data.target}`}
Scan Date: ${new Date(data.timestamp).toLocaleString()}

═══════════════════════════════════════════════════════════
RISK ASSESSMENT
═══════════════════════════════════════════════════════════

Risk Level: ${data.risk.level}
Risk Score: ${data.risk.score}/100
Total Secrets: ${data.risk.total}

Severity Breakdown:
CRITICAL: ${data.risk.counts.CRITICAL}
HIGH: ${data.risk.counts.HIGH}
MEDIUM: ${data.risk.counts.MEDIUM}
LOW: ${data.risk.counts.LOW}

═══════════════════════════════════════════════════════════
EXPOSED SECRETS
═══════════════════════════════════════════════════════════

`;

  if (data.secrets && data.secrets.length > 0) {
    data.secrets.forEach((secret, i) => {
      txtContent += `${i + 1}. [${secret.severity}] ${secret.type}\n`;
      txtContent += `   File: ${secret.file}\n`;
      txtContent += `   Line: ${secret.line}\n`;
      txtContent += `   Description: ${secret.description}\n`;
      txtContent += `   Match: [REDACTED FOR SECURITY]\n\n`;
    });
  } else {
    txtContent += 'No secrets detected.\n';
  }
  
  if (data.searchQueries) {
    txtContent += `\n═══════════════════════════════════════════════════════════
RECOMMENDED GITHUB SEARCHES
═══════════════════════════════════════════════════════════\n\n`;

    data.searchQueries.forEach((query, i) => {
      txtContent += `${i + 1}. ${query}\n`;
      txtContent += `   https://github.com/search?type=code&q=${encodeURIComponent(query)}\n\n`;
    });
  }
  
  fs.writeFileSync(txtFile, txtContent);
  
  console.log(`\x1b[32m✅ Results saved (secrets redacted):\x1b[0m`);
  console.log(`   JSON: ${jsonFile}`);
  console.log(`   TXT: ${txtFile}\n`);
}

function showHelp() {
  showBanner();
  
  console.log("Usage: node github-secrets.js [OPTIONS] <repo|target>\n");
  console.log("Modes:");
  console.log("  1. Scan Repository:  node github-secrets.js user/repo");
  console.log("  2. Generate Queries: node github-secrets.js --search target\n");
  console.log("Options:");
  console.log("  --search         Generate search queries instead of scanning");
  console.log("  --save           Save results to file");
  console.log("  --help           Show this help\n");
  
  console.log("Environment Variables:");
  console.log("  GITHUB_TOKEN     GitHub personal access token (optional but recommended)\n");
  
  console.log("Examples:");
  console.log("  node github-secrets.js user/repository");
  console.log("  node github-secrets.js --search company-name");
  console.log("  GITHUB_TOKEN=ghp_xxx node github-secrets.js user/repo --save\n");
  
  console.log("Detects:");
  console.log("  • AWS Keys, Google API Keys, GitHub Tokens");
  console.log("  • Stripe, PayPal, Square API Keys");
  console.log("  • Slack, Twilio, SendGrid Tokens");
  console.log("  • Private SSH/PGP Keys");
  console.log("  • Database Connection Strings");
  console.log("  • And 30+ more secret types\n");
}

async function main() {
  const args = process.argv.slice(2);
  
  if (args.includes('--help') || args.length === 0) {
    showHelp();
    process.exit(0);
  }
  
  let target = null;
  let searchMode = false;
  let saveResults_flag = false;
  
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--search') {
      searchMode = true;
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
  
  const token = process.env.GITHUB_TOKEN;
  
  let results;
  
  if (searchMode) {
    // Generate search queries
    console.log(`⏳ Generating search queries for: ${target}...\n`);
    
    results = {
      target: target,
      timestamp: new Date().toISOString(),
      mode: 'search',
      searchQueries: generateSearchQueries(target),
      secrets: [],
      risk: { score: 0, level: 'CLEAN', counts: {}, total: 0 }
    };
  } else {
    // Scan repository
    console.log(`⏳ Scanning repository: ${target}...\n`);
    
    const secrets = await searchGitHubRepo(target, token);
    
    if (secrets.error) {
      console.log(`\x1b[31m❌ Error: ${secrets.error}\x1b[0m\n`);
      process.exit(1);
    }
    
    results = {
      repo: target,
      timestamp: new Date().toISOString(),
      mode: 'scan',
      secrets: secrets,
      risk: assessRisk(secrets),
      searchQueries: null
    };
  }
  
  displayResults(results);
  
  if (saveResults_flag) {
    saveResults(results);
  }
  
  console.log("\x1b[31m ██████╗ ██╗████████╗██╗  ██╗██╗   ██╗██████╗\x1b[0m");
  console.log("\x1b[35m🥝 Scan complete - by kiwi & 777\x1b[0m\n");
}

main().catch(console.error);
