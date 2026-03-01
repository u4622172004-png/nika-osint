#!/usr/bin/env node

const fs = require('fs');

// ============================================
// AI ANALYZER - Intelligent threat assessment
// ============================================

function analyzeRiskScore(data) {
  let score = 0;
  const factors = [];
  
  // Check for breaches
  if (data.breaches && data.breaches.length > 0) {
    score += data.breaches.length * 15;
    factors.push({
      factor: 'Data Breaches',
      impact: data.breaches.length * 15,
      severity: 'HIGH',
      details: `Found in ${data.breaches.length} known breaches`
    });
  }
  
  // Check for exposed ports
  if (data.ports && data.ports.filter(p => p.state === 'open').length > 10) {
    score += 20;
    factors.push({
      factor: 'Excessive Open Ports',
      impact: 20,
      severity: 'MEDIUM',
      details: `${data.ports.filter(p => p.state === 'open').length} open ports detected`
    });
  }
  
  // Check for vulnerabilities
  if (data.vulnerabilities && data.vulnerabilities.length > 0) {
    score += data.vulnerabilities.length * 10;
    factors.push({
      factor: 'Known Vulnerabilities',
      impact: data.vulnerabilities.length * 10,
      severity: 'CRITICAL',
      details: `${data.vulnerabilities.length} CVEs identified`
    });
  }
  
  // Check for weak security headers
  if (data.securityHeaders) {
    const missing = Object.values(data.securityHeaders).filter(v => !v).length;
    if (missing > 3) {
      score += 15;
      factors.push({
        factor: 'Missing Security Headers',
        impact: 15,
        severity: 'MEDIUM',
        details: `${missing} security headers not implemented`
      });
    }
  }
  
  // Check for exposed emails
  if (data.emails && data.emails.length > 5) {
    score += 10;
    factors.push({
      factor: 'Email Exposure',
      impact: 10,
      severity: 'LOW',
      details: `${data.emails.length} email addresses publicly exposed`
    });
  }
  
  // Check for social media footprint
  if (data.socialMedia) {
    const platforms = Object.keys(data.socialMedia).length;
    if (platforms > 5) {
      score += 5;
      factors.push({
        factor: 'Large Digital Footprint',
        impact: 5,
        severity: 'LOW',
        details: `Presence on ${platforms} social platforms`
      });
    }
  }
  
  // Determine overall risk level
  let riskLevel;
  if (score >= 70) riskLevel = 'CRITICAL';
  else if (score >= 50) riskLevel = 'HIGH';
  else if (score >= 30) riskLevel = 'MEDIUM';
  else if (score >= 10) riskLevel = 'LOW';
  else riskLevel = 'MINIMAL';
  
  return {
    totalScore: Math.min(score, 100),
    riskLevel: riskLevel,
    factors: factors
  };
}

function generateRecommendations(analysis, data) {
  const recommendations = [];
  
  analysis.factors.forEach(factor => {
    switch(factor.factor) {
      case 'Data Breaches':
        recommendations.push({
          priority: 'URGENT',
          category: 'Security',
          action: 'Change all passwords immediately',
          details: 'Your credentials have been exposed in data breaches. Reset passwords on all affected accounts and enable 2FA.',
          impact: 'Prevents unauthorized account access'
        });
        break;
        
      case 'Known Vulnerabilities':
        recommendations.push({
          priority: 'URGENT',
          category: 'Infrastructure',
          action: 'Patch identified vulnerabilities',
          details: `${data.vulnerabilities.length} CVEs detected. Apply security patches immediately to prevent exploitation.`,
          impact: 'Reduces attack surface'
        });
        break;
        
      case 'Excessive Open Ports':
        recommendations.push({
          priority: 'HIGH',
          category: 'Network Security',
          action: 'Close unnecessary ports',
          details: 'Review all open ports and close those not required for operations. Implement firewall rules.',
          impact: 'Limits potential entry points'
        });
        break;
        
      case 'Missing Security Headers':
        recommendations.push({
          priority: 'MEDIUM',
          category: 'Web Security',
          action: 'Implement security headers',
          details: 'Add missing HTTP security headers: CSP, HSTS, X-Frame-Options, X-Content-Type-Options.',
          impact: 'Protects against common web attacks'
        });
        break;
        
      case 'Email Exposure':
        recommendations.push({
          priority: 'LOW',
          category: 'Privacy',
          action: 'Limit email exposure',
          details: 'Use contact forms instead of displaying email addresses. Consider using email aliases.',
          impact: 'Reduces spam and phishing attempts'
        });
        break;
        
      case 'Large Digital Footprint':
        recommendations.push({
          priority: 'LOW',
          category: 'Privacy',
          action: 'Review online presence',
          details: 'Audit all social media accounts. Remove or privatize accounts not actively used.',
          impact: 'Reduces information available to attackers'
        });
        break;
    }
  });
  
  // Add general recommendations
  recommendations.push({
    priority: 'ONGOING',
    category: 'General',
    action: 'Implement security monitoring',
    details: 'Set up continuous monitoring for breaches, vulnerabilities, and suspicious activity.',
    impact: 'Early detection of security incidents'
  });
  
  recommendations.push({
    priority: 'ONGOING',
    category: 'General',
    action: 'Regular security audits',
    details: 'Conduct quarterly security assessments to identify new vulnerabilities.',
    impact: 'Maintains security posture'
  });
  
  return recommendations.sort((a, b) => {
    const priority = { 'URGENT': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'ONGOING': 4 };
    return priority[a.priority] - priority[b.priority];
  });
}

function generateInsights(data) {
  const insights = [];
  
  // Technology stack analysis
  if (data.technologies) {
    const outdated = data.technologies.filter(t => t.version && t.version.includes('old'));
    if (outdated.length > 0) {
      insights.push({
        type: 'Technology',
        finding: 'Outdated Software Detected',
        description: `${outdated.length} technologies appear to be outdated and may contain known vulnerabilities.`,
        suggestion: 'Update to latest stable versions'
      });
    }
  }
  
  // Domain reputation
  if (data.domain) {
    if (data.blacklisted && data.blacklisted.length > 0) {
      insights.push({
        type: 'Reputation',
        finding: 'Domain Blacklisted',
        description: `Domain appears on ${data.blacklisted.length} blacklists.`,
        suggestion: 'Investigate and remediate cause of blacklisting'
      });
    }
  }
  
  // SSL/TLS configuration
  if (data.ssl) {
    if (data.ssl.grade && data.ssl.grade !== 'A+' && data.ssl.grade !== 'A') {
      insights.push({
        type: 'SSL/TLS',
        finding: 'Suboptimal SSL Configuration',
        description: `SSL Labs grade: ${data.ssl.grade}. Configuration could be improved.`,
        suggestion: 'Update SSL configuration to achieve A+ rating'
      });
    }
  }
  
  // Email security
  if (data.emailSecurity) {
    const issues = [];
    if (!data.emailSecurity.spf) issues.push('SPF');
    if (!data.emailSecurity.dmarc) issues.push('DMARC');
    if (!data.emailSecurity.dkim) issues.push('DKIM');
    
    if (issues.length > 0) {
      insights.push({
        type: 'Email Security',
        finding: 'Missing Email Authentication',
        description: `Missing: ${issues.join(', ')}. Emails may be spoofed.`,
        suggestion: 'Implement all email authentication protocols'
      });
    }
  }
  
  // Social engineering risk
  if (data.socialMedia && data.emails) {
    insights.push({
      type: 'Social Engineering',
      finding: 'High Information Disclosure',
      description: 'Significant amount of personal/organizational information publicly available.',
      suggestion: 'Review and minimize public information exposure'
    });
  }
  
  return insights;
}

function generateTimeline(data) {
  const events = [];
  
  if (data.domain && data.domain.created) {
    events.push({
      date: data.domain.created,
      event: 'Domain Registered',
      category: 'Infrastructure'
    });
  }
  
  if (data.breaches) {
    data.breaches.forEach(breach => {
      events.push({
        date: breach.breachDate,
        event: `Data Breach: ${breach.name}`,
        category: 'Security Incident',
        severity: 'HIGH'
      });
    });
  }
  
  if (data.vulnerabilities) {
    data.vulnerabilities.forEach(vuln => {
      events.push({
        date: new Date().toISOString().split('T')[0],
        event: `Vulnerability Detected: ${vuln.cve}`,
        category: 'Security',
        severity: 'CRITICAL'
      });
    });
  }
  
  return events.sort((a, b) => new Date(a.date) - new Date(b.date));
}

function showBanner() {
  console.log("\x1b[31m");
  console.log(" █████╗ ██╗     █████╗ ███╗   ██╗ █████╗ ██╗  ██╗   ██╗███████╗███████╗██████╗ ");
  console.log("██╔══██╗██║    ██╔══██╗████╗  ██║██╔══██╗██║  ╚██╗ ██╔╝╚══███╔╝██╔════╝██╔══██╗");
  console.log("███████║██║    ███████║██╔██╗ ██║███████║██║   ╚████╔╝   ███╔╝ █████╗  ██████╔╝");
  console.log("██╔══██║██║    ██╔══██║██║╚██╗██║██╔══██║██║    ╚██╔╝   ███╔╝  ██╔══╝  ██╔══██╗");
  console.log("██║  ██║██║    ██║  ██║██║ ╚████║██║  ██║███████╗██║   ███████╗███████╗██║  ██║");
  console.log("╚═╝  ╚═╝╚═╝    ╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝╚═╝   ╚══════╝╚══════╝╚═╝  ╚═╝");
  console.log("\x1b[0m");
  console.log("\x1b[35m🥝 NIKA AI Analyzer - Intelligent Security Assessment\x1b[0m");
  console.log("\x1b[33m⚠️  AI-powered risk analysis and recommendations\x1b[0m\n");
}

function displayAnalysis(analysis) {
  console.log("\n╔════════════════════════════════════════════════════════╗");
  console.log("║         🤖 AI ANALYSIS RESULTS 🤖                      ║");
  console.log("╚════════════════════════════════════════════════════════╝\n");
  
  // Risk Score
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
  console.log("\x1b[36m📊 RISK ASSESSMENT\x1b[0m");
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
  
  const riskColor = {
    'CRITICAL': '\x1b[41m\x1b[37m',
    'HIGH': '\x1b[31m',
    'MEDIUM': '\x1b[33m',
    'LOW': '\x1b[32m',
    'MINIMAL': '\x1b[32m'
  };
  
  console.log(`   Risk Score: ${riskColor[analysis.riskScore.riskLevel]}${analysis.riskScore.totalScore}/100\x1b[0m`);
  console.log(`   Risk Level: ${riskColor[analysis.riskScore.riskLevel]}${analysis.riskScore.riskLevel}\x1b[0m\n`);
  
  // Risk Factors
  if (analysis.riskScore.factors.length > 0) {
    console.log("   Risk Factors:");
    analysis.riskScore.factors.forEach((factor, i) => {
      const severityColor = {
        'CRITICAL': '\x1b[31m',
        'HIGH': '\x1b[33m',
        'MEDIUM': '\x1b[33m',
        'LOW': '\x1b[32m'
      };
      console.log(`\n   ${i + 1}. ${severityColor[factor.severity]}[${factor.severity}]\x1b[0m ${factor.factor}`);
      console.log(`      Impact: +${factor.impact} points`);
      console.log(`      ${factor.details}`);
    });
    console.log('');
  }
  
  // Recommendations
  console.log("\n\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
  console.log("\x1b[36m💡 RECOMMENDATIONS\x1b[0m");
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
  
  analysis.recommendations.forEach((rec, i) => {
    const priorityColor = {
      'URGENT': '\x1b[41m\x1b[37m',
      'HIGH': '\x1b[31m',
      'MEDIUM': '\x1b[33m',
      'LOW': '\x1b[32m',
      'ONGOING': '\x1b[36m'
    };
    
    console.log(`${i + 1}. ${priorityColor[rec.priority]}[${rec.priority}]\x1b[0m ${rec.action}`);
    console.log(`   Category: ${rec.category}`);
    console.log(`   Details: ${rec.details}`);
    console.log(`   Impact: ${rec.impact}\n`);
  });
  
  // Insights
  if (analysis.insights.length > 0) {
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
    console.log("\x1b[36m🔍 INSIGHTS\x1b[0m");
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
    
    analysis.insights.forEach((insight, i) => {
      console.log(`${i + 1}. [${insight.type}] ${insight.finding}`);
      console.log(`   ${insight.description}`);
      console.log(`   → ${insight.suggestion}\n`);
    });
  }
  
  // Timeline
  if (analysis.timeline && analysis.timeline.length > 0) {
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
    console.log("\x1b[36m📅 TIMELINE\x1b[0m");
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
    
    analysis.timeline.forEach(event => {
      const severityColor = event.severity === 'CRITICAL' ? '\x1b[31m' : event.severity === 'HIGH' ? '\x1b[33m' : '';
      console.log(`   ${event.date} - ${severityColor}${event.event}\x1b[0m`);
      console.log(`   Category: ${event.category}\n`);
    });
  }
}

function saveAnalysis(analysis, outputFile) {
  const dir = './ai-analysis-reports';
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, -5);
  const jsonFile = outputFile || `${dir}/analysis-${timestamp}.json`;
  const txtFile = jsonFile.replace('.json', '.txt');
  
  fs.writeFileSync(jsonFile, JSON.stringify(analysis, null, 2));
  
  let txtContent = `═══════════════════════════════════════════════════════════
AI SECURITY ANALYSIS REPORT
═══════════════════════════════════════════════════════════

Generated: ${new Date().toLocaleString()}

═══════════════════════════════════════════════════════════
RISK ASSESSMENT
═══════════════════════════════════════════════════════════

Risk Score: ${analysis.riskScore.totalScore}/100
Risk Level: ${analysis.riskScore.riskLevel}

Risk Factors:
`;

  analysis.riskScore.factors.forEach((factor, i) => {
    txtContent += `\n${i + 1}. [${factor.severity}] ${factor.factor}\n`;
    txtContent += `   Impact: +${factor.impact} points\n`;
    txtContent += `   ${factor.details}\n`;
  });
  
  txtContent += `\n═══════════════════════════════════════════════════════════
RECOMMENDATIONS
═══════════════════════════════════════════════════════════\n\n`;

  analysis.recommendations.forEach((rec, i) => {
    txtContent += `${i + 1}. [${rec.priority}] ${rec.action}\n`;
    txtContent += `   Category: ${rec.category}\n`;
    txtContent += `   ${rec.details}\n`;
    txtContent += `   Impact: ${rec.impact}\n\n`;
  });
  
  if (analysis.insights.length > 0) {
    txtContent += `═══════════════════════════════════════════════════════════
INSIGHTS
═══════════════════════════════════════════════════════════\n\n`;

    analysis.insights.forEach((insight, i) => {
      txtContent += `${i + 1}. [${insight.type}] ${insight.finding}\n`;
      txtContent += `   ${insight.description}\n`;
      txtContent += `   Suggestion: ${insight.suggestion}\n\n`;
    });
  }
  
  fs.writeFileSync(txtFile, txtContent);
  
  console.log(`\n\x1b[32m✅ Analysis saved:\x1b[0m`);
  console.log(`   JSON: ${jsonFile}`);
  console.log(`   TXT: ${txtFile}\n`);
}

function showHelp() {
  showBanner();
  
  console.log("Usage: node ai-analyzer.js [OPTIONS] <input-file>\n");
  console.log("Options:");
  console.log("  --output <file>      Save analysis to specific file");
  console.log("  --help               Show this help\n");
  
  console.log("Examples:");
  console.log("  node ai-analyzer.js report.json");
  console.log("  node ai-analyzer.js report.json --output analysis.json\n");
  
  console.log("\x1b[33mInput file should be JSON from NIKA OSINT scans\x1b[0m\n");
}

async function main() {
  const args = process.argv.slice(2);
  
  if (args.includes('--help') || args.length === 0) {
    showHelp();
    process.exit(0);
  }
  
  let inputFile = null;
  let outputFile = null;
  
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--output' && args[i + 1]) {
      outputFile = args[i + 1];
      i++;
    } else if (!args[i].startsWith('--')) {
      inputFile = args[i];
    }
  }
  
  if (!inputFile) {
    console.log("\x1b[31m❌ No input file specified!\x1b[0m\n");
    showHelp();
    process.exit(1);
  }
  
  if (!fs.existsSync(inputFile)) {
    console.log(`\x1b[31m❌ File not found: ${inputFile}\x1b[0m\n`);
    process.exit(1);
  }
  
  showBanner();
  
  console.log(`⏳ Analyzing ${inputFile}...\n`);
  
  const data = JSON.parse(fs.readFileSync(inputFile, 'utf8'));
  
  const analysis = {
    timestamp: new Date().toISOString(),
    inputFile: inputFile,
    riskScore: analyzeRiskScore(data),
    recommendations: [],
    insights: generateInsights(data),
    timeline: generateTimeline(data)
  };
  
  analysis.recommendations = generateRecommendations(analysis.riskScore, data);
  
  displayAnalysis(analysis);
  
  saveAnalysis(analysis, outputFile);
  
  console.log("\x1b[31m █████╗ ██╗\x1b[0m");
  console.log("\x1b[35m🥝 Analysis complete - by kiwi & 777\x1b[0m\n");
}

main().catch(console.error);
