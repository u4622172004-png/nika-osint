#!/usr/bin/env node

const https = require('https');
const fs = require('fs');

// ============================================
// COMPANY INTELLIGENCE - Business OSINT
// ============================================

const COMPANY_REGISTRIES = {
  global: {
    opencorporates: {
      name: 'OpenCorporates',
      url: 'https://opencorporates.com/',
      search: 'https://opencorporates.com/companies?q=',
      coverage: 'Global (200+ million companies)',
      data: ['Company name', 'Number', 'Status', 'Officers', 'Address', 'Filings'],
      cost: 'Free/API available',
      api: true
    }
  },
  usa: {
    sec: {
      name: 'SEC EDGAR',
      url: 'https://www.sec.gov/edgar/searchedgar/companysearch.html',
      search: 'https://www.sec.gov/cgi-bin/browse-edgar?company=',
      coverage: 'USA (Public companies)',
      data: ['10-K', '10-Q', '8-K', 'Proxy statements', 'Ownership'],
      cost: 'Free',
      api: true
    },
    delaware: {
      name: 'Delaware Division of Corporations',
      url: 'https://icis.corp.delaware.gov/Ecorp/EntitySearch/NameSearch.aspx',
      coverage: 'Delaware (Many US companies)',
      data: ['Entity name', 'File number', 'Status', 'Type'],
      cost: 'Free'
    },
    california: {
      name: 'California Business Search',
      url: 'https://businesssearch.sos.ca.gov/',
      coverage: 'California',
      data: ['Entity info', 'Status', 'Agent', 'Filings'],
      cost: 'Free'
    }
  },
  uk: {
    companieshouse: {
      name: 'Companies House',
      url: 'https://www.gov.uk/government/organisations/companies-house',
      search: 'https://find-and-update.company-information.service.gov.uk/',
      coverage: 'UK',
      data: ['Company number', 'Directors', 'Accounts', 'Charges', 'PSC'],
      cost: 'Free',
      api: true
    }
  },
  eu: {
    eubusiness: {
      name: 'EU Business Register',
      url: 'https://www.ebr.org/',
      coverage: 'European Union',
      data: ['Company data across EU countries'],
      cost: 'Paid'
    }
  }
};

const FINANCIAL_DATA = {
  crunchbase: {
    name: 'Crunchbase',
    url: 'https://www.crunchbase.com/',
    search: 'https://www.crunchbase.com/search/organizations/field/organizations/',
    features: ['Funding', 'Investors', 'Acquisitions', 'Leadership', 'Competitors'],
    focus: 'Startups and tech companies',
    cost: 'Free/Premium'
  },
  pitchbook: {
    name: 'PitchBook',
    url: 'https://pitchbook.com/',
    features: ['Private equity', 'Venture capital', 'M&A data'],
    cost: 'Paid/Subscription'
  },
  bloomberg: {
    name: 'Bloomberg',
    url: 'https://www.bloomberg.com/',
    features: ['Financial news', 'Stock data', 'Company profiles'],
    cost: 'Free news/Paid terminal'
  },
  dnb: {
    name: 'Dun & Bradstreet',
    url: 'https://www.dnb.com/',
    features: ['Credit reports', 'DUNS number', 'Risk assessment'],
    cost: 'Paid'
  }
};

const PEOPLE_SEARCH = {
  linkedin: {
    name: 'LinkedIn',
    url: 'https://www.linkedin.com/',
    search: company => `https://www.linkedin.com/search/results/people/?keywords=${encodeURIComponent(company)}`,
    features: ['Employees', 'Executives', 'Job titles', 'Connections'],
    cost: 'Free/Premium'
  },
  rocketreach: {
    name: 'RocketReach',
    url: 'https://rocketreach.co/',
    features: ['Email finder', 'Phone numbers', 'Social profiles'],
    cost: 'Paid'
  },
  hunter: {
    name: 'Hunter.io',
    url: 'https://hunter.io/',
    features: ['Email patterns', 'Domain search', 'Email verification'],
    cost: 'Free tier/Paid'
  }
};

const NEWS_MONITORING = {
  google: {
    name: 'Google News',
    search: company => `https://news.google.com/search?q=${encodeURIComponent(company)}`,
    features: ['News articles', 'Press releases', 'Recent mentions']
  },
  crunchbase_news: {
    name: 'Crunchbase News',
    url: 'https://news.crunchbase.com/',
    features: ['Startup news', 'Funding announcements', 'M&A']
  },
  businesswire: {
    name: 'Business Wire',
    url: 'https://www.businesswire.com/',
    features: ['Press releases', 'Company announcements']
  }
};

const TECH_STACK = {
  builtwith: {
    name: 'BuiltWith',
    url: 'https://builtwith.com/',
    search: domain => `https://builtwith.com/${domain}`,
    features: ['Technology stack', 'Analytics', 'Hosting', 'CMS'],
    cost: 'Free/Paid'
  },
  wappalyzer: {
    name: 'Wappalyzer',
    url: 'https://www.wappalyzer.com/',
    features: ['Web technologies', 'Browser extension', 'API'],
    cost: 'Free/Paid'
  },
  similartech: {
    name: 'SimilarTech',
    url: 'https://www.similartech.com/',
    features: ['Technology adoption', 'Market share', 'Competitors'],
    cost: 'Free/Paid'
  }
};

const DOMAIN_TOOLS = {
  whois: {
    name: 'WHOIS Lookup',
    search: domain => `https://who.is/whois/${domain}`,
    features: ['Domain registration', 'Registrant info', 'DNS records']
  },
  dnsdumpster: {
    name: 'DNSDumpster',
    url: 'https://dnsdumpster.com/',
    features: ['DNS records', 'Subdomains', 'Network mapping']
  },
  securitytrails: {
    name: 'SecurityTrails',
    url: 'https://securitytrails.com/',
    features: ['DNS history', 'WHOIS history', 'Subdomain discovery'],
    cost: 'Free tier/Paid'
  }
};

function showBanner() {
  console.log("\x1b[31m");
  console.log(" ██████╗ ██████╗ ███╗   ███╗██████╗  █████╗ ███╗   ██╗██╗   ██╗");
  console.log("██╔════╝██╔═══██╗████╗ ████║██╔══██╗██╔══██╗████╗  ██║╚██╗ ██╔╝");
  console.log("██║     ██║   ██║██╔████╔██║██████╔╝███████║██╔██╗ ██║ ╚████╔╝ ");
  console.log("██║     ██║   ██║██║╚██╔╝██║██╔═══╝ ██╔══██║██║╚██╗██║  ╚██╔╝  ");
  console.log("╚██████╗╚██████╔╝██║ ╚═╝ ██║██║     ██║  ██║██║ ╚████║   ██║   ");
  console.log(" ╚═════╝ ╚═════╝ ╚═╝     ╚═╝╚═╝     ╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝   ");
  console.log("                                                                 ");
  console.log("██╗███╗   ██╗████████╗███████╗██╗     ██╗     ██╗ ██████╗ ███████╗███╗   ██╗ ██████╗███████╗");
  console.log("██║████╗  ██║╚══██╔══╝██╔════╝██║     ██║     ██║██╔════╝ ██╔════╝████╗  ██║██╔════╝██╔════╝");
  console.log("██║██╔██╗ ██║   ██║   █████╗  ██║     ██║     ██║██║  ███╗█████╗  ██╔██╗ ██║██║     █████╗  ");
  console.log("██║██║╚██╗██║   ██║   ██╔══╝  ██║     ██║     ██║██║   ██║██╔══╝  ██║╚██╗██║██║     ██╔══╝  ");
  console.log("██║██║ ╚████║   ██║   ███████╗███████╗███████╗██║╚██████╔╝███████╗██║ ╚████║╚██████╗███████╗");
  console.log("╚═╝╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚══════╝╚══════╝╚═╝ ╚═════╝ ╚══════╝╚═╝  ╚═══╝ ╚═════╝╚══════╝");
  console.log("\x1b[0m");
  console.log("\x1b[35m🥝 NIKA Company Intelligence - Business OSINT\x1b[0m");
  console.log("\x1b[33m⚠️  For authorized business research only\x1b[0m\n");
}

function parseInput(input) {
  const parsed = {
    query: input,
    type: 'unknown',
    company: null,
    domain: null
  };
  
  // Check if domain
  if (input.includes('.') && !input.includes(' ')) {
    parsed.type = 'domain';
    parsed.domain = input.toLowerCase();
    parsed.company = input.split('.')[0];
  } else {
    parsed.type = 'company';
    parsed.company = input;
  }
  
  return parsed;
}

function generateSearchLinks(data) {
  console.log('   [1/6] Generating search links...');
  
  const encoded = encodeURIComponent(data.company);
  const links = {};
  
  // Global registries
  links.opencorporates = `${COMPANY_REGISTRIES.global.opencorporates.search}${encoded}`;
  
  // USA
  links.sec = `${COMPANY_REGISTRIES.usa.sec.search}${encoded}`;
  links.delaware = COMPANY_REGISTRIES.usa.delaware.url;
  links.california = COMPANY_REGISTRIES.usa.california.url;
  
  // UK
  links.companieshouse = COMPANY_REGISTRIES.uk.companieshouse.search;
  
  // Financial
  links.crunchbase = `${FINANCIAL_DATA.crunchbase.search}${encoded}`;
  links.bloomberg = `https://www.bloomberg.com/search?query=${encoded}`;
  
  // People
  links.linkedin = PEOPLE_SEARCH.linkedin.search(data.company);
  links.hunter = `https://hunter.io/search/${data.domain || data.company}`;
  
  // News
  links.googlenews = NEWS_MONITORING.google.search(data.company);
  
  // Domain (if available)
  if (data.domain) {
    links.builtwith = TECH_STACK.builtwith.search(data.domain);
    links.whois = DOMAIN_TOOLS.whois.search(data.domain);
    links.dnsdumpster = DOMAIN_TOOLS.dnsdumpster.url;
  }
  
  return links;
}

function generateGoogleDorks(company) {
  console.log('   [2/6] Generating Google dorks...');
  
  return [
    `"${company}" site:linkedin.com/company`,
    `"${company}" filetype:pdf`,
    `"${company}" "annual report" OR "10-K" OR "financial statements"`,
    `"${company}" "press release" OR "announcement"`,
    `"${company}" site:crunchbase.com`,
    `"${company}" "employee" OR "staff" OR "team"`,
    `"${company}" "founder" OR "CEO" OR "executive"`,
    `"${company}" "acquisition" OR "merger" OR "funding"`,
    `"${company}" site:sec.gov`,
    `"${company}" "careers" OR "jobs" OR "hiring"`,
    `"${company}" "contact" OR "email" OR "phone"`,
    `"${company}" inurl:about OR inurl:team`
  ];
}

function getDataPoints(company) {
  console.log('   [3/6] Identifying data collection points...');
  
  return {
    basic: [
      'Legal company name',
      'Registration number',
      'Incorporation date',
      'Company type (LLC, Inc, Ltd, etc)',
      'Jurisdiction/State',
      'Registered address',
      'Status (Active/Dissolved)'
    ],
    financial: [
      'Annual revenue',
      'Funding rounds',
      'Investors',
      'Valuation',
      'Stock price (if public)',
      'Financial statements',
      'Credit rating'
    ],
    people: [
      'Directors/Officers',
      'Shareholders',
      'Key executives',
      'Employee count',
      'Former employees',
      'Board members'
    ],
    operations: [
      'Industry/Sector',
      'Products/Services',
      'Subsidiaries',
      'Parent company',
      'Competitors',
      'Partners',
      'Customers'
    ],
    digital: [
      'Website domain',
      'Email pattern',
      'Technology stack',
      'Social media accounts',
      'IP addresses',
      'DNS records'
    ],
    legal: [
      'Lawsuits',
      'Regulatory filings',
      'Trademarks',
      'Patents',
      'Licenses',
      'Compliance issues'
    ]
  };
}

function getInvestigationWorkflow() {
  console.log('   [4/6] Preparing investigation workflow...');
  
  return {
    phase1: {
      name: 'Initial Discovery',
      steps: [
        'Search OpenCorporates for global presence',
        'Check local registry (Companies House, SEC, etc)',
        'Verify company exists and is active',
        'Note registration number and date'
      ]
    },
    phase2: {
      name: 'Financial Research',
      steps: [
        'Check SEC EDGAR for public filings',
        'Search Crunchbase for funding info',
        'Review financial news on Bloomberg',
        'Look for annual reports and 10-Ks'
      ]
    },
    phase3: {
      name: 'People Intelligence',
      steps: [
        'LinkedIn company page for employees',
        'Directors from company registry',
        'Hunter.io for email patterns',
        'RocketReach for executive contacts'
      ]
    },
    phase4: {
      name: 'Digital Footprint',
      steps: [
        'WHOIS lookup for domain info',
        'BuiltWith for technology stack',
        'DNSDumpster for subdomains',
        'Social media presence audit'
      ]
    },
    phase5: {
      name: 'News & Reputation',
      steps: [
        'Google News for recent mentions',
        'Press release archives',
        'Industry publications',
        'Reddit/forum discussions'
      ]
    },
    phase6: {
      name: 'Network Mapping',
      steps: [
        'Subsidiaries and parent companies',
        'Partner relationships',
        'Competitor analysis',
        'Supply chain connections'
      ]
    }
  };
}

function getComplianceChecks() {
  console.log('   [5/6] Preparing compliance checklists...');
  
  return {
    sanctions: [
      'OFAC Sanctions List (USA)',
      'EU Sanctions List',
      'UN Sanctions List',
      'Country-specific lists'
    ],
    pep: [
      'Politically Exposed Persons check',
      'Director PEP screening',
      'Beneficial owner checks'
    ],
    aml: [
      'Anti-Money Laundering checks',
      'Source of funds',
      'Transaction monitoring'
    ],
    legal: [
      'Litigation history',
      'Regulatory actions',
      'Bankruptcy filings',
      'Tax liens'
    ]
  };
}

function generateRecommendations(data) {
  console.log('   [6/6] Generating recommendations...');
  
  const recs = [];
  
  if (data.type === 'domain') {
    recs.push('💡 Domain provided - Include WHOIS and DNS analysis');
    recs.push('💡 Check BuiltWith for technology stack');
    recs.push('💡 Use Hunter.io to find email patterns');
  }
  
  recs.push('💡 Start with OpenCorporates for global registry search');
  recs.push('💡 Check local registry based on jurisdiction');
  recs.push('💡 LinkedIn for employee and executive intelligence');
  recs.push('💡 Google dorks for leaked documents and mentions');
  recs.push('💡 Monitor news sources for recent developments');
  
  return recs;
}

function displayResults(data) {
  console.log("\n╔════════════════════════════════════════════════════════╗");
  console.log("║       🏢 COMPANY INTELLIGENCE REPORT 🏢                ║");
  console.log("╚════════════════════════════════════════════════════════╝\n");
  
  console.log(`🔍 Query: \x1b[36m${data.query}\x1b[0m`);
  console.log(`   Type: ${data.type === 'domain' ? 'Domain' : 'Company Name'}\n`);
  
  // Search Links
  console.log("\x1b[36m┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓\x1b[0m");
  console.log("\x1b[36m┃                  QUICK SEARCH LINKS                  ┃\x1b[0m");
  console.log("\x1b[36m┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛\x1b[0m\n");
  
  console.log(`   OpenCorporates:      ${data.searchLinks.opencorporates}`);
  console.log(`   SEC EDGAR:           ${data.searchLinks.sec}`);
  console.log(`   Companies House:     ${data.searchLinks.companieshouse}`);
  console.log(`   Crunchbase:          ${data.searchLinks.crunchbase}`);
  console.log(`   LinkedIn:            ${data.searchLinks.linkedin}`);
  console.log(`   Google News:         ${data.searchLinks.googlenews}\n`);
  
  if (data.domain) {
    console.log('   \x1b[32mDomain-specific:\x1b[0m');
    console.log(`   BuiltWith:           ${data.searchLinks.builtwith}`);
    console.log(`   WHOIS:               ${data.searchLinks.whois}`);
    console.log(`   Hunter.io:           ${data.searchLinks.hunter}\n`);
  }
  
  // Company Registries
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
  console.log("\x1b[36m📋 COMPANY REGISTRIES\x1b[0m");
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
  
  console.log('   \x1b[32mGlobal:\x1b[0m');
  Object.entries(COMPANY_REGISTRIES.global).forEach(([key, reg]) => {
    console.log(`      • ${reg.name}: ${reg.url}`);
    console.log(`        Coverage: ${reg.coverage}`);
  });
  console.log('');
  
  console.log('   \x1b[32mUSA:\x1b[0m');
  Object.entries(COMPANY_REGISTRIES.usa).forEach(([key, reg]) => {
    console.log(`      • ${reg.name}: ${reg.url}`);
  });
  console.log('');
  
  console.log('   \x1b[32mUK:\x1b[0m');
  Object.entries(COMPANY_REGISTRIES.uk).forEach(([key, reg]) => {
    console.log(`      • ${reg.name}: ${reg.url}`);
  });
  console.log('');
  
  // Financial Data
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
  console.log("\x1b[36m💰 FINANCIAL DATA SOURCES\x1b[0m");
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
  
  Object.entries(FINANCIAL_DATA).forEach(([key, source]) => {
    console.log(`   \x1b[32m${source.name}\x1b[0m (${source.cost})`);
    console.log(`      ${source.url}`);
    console.log(`      Features: ${source.features.join(', ')}\n`);
  });
  
  // Data Collection Points
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
  console.log("\x1b[36m📊 DATA COLLECTION POINTS\x1b[0m");
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
  
  Object.entries(data.dataPoints).forEach(([category, points]) => {
    console.log(`   \x1b[32m${category.charAt(0).toUpperCase() + category.slice(1)}:\x1b[0m`);
    points.forEach(point => {
      console.log(`      • ${point}`);
    });
    console.log('');
  });
  
  // Google Dorks
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
  console.log("\x1b[36m🔍 GOOGLE DORKS (First 6)\x1b[0m");
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
  
  data.googleDorks.slice(0, 6).forEach((dork, i) => {
    console.log(`   ${i + 1}. ${dork}`);
  });
  console.log(`\n   ... and ${data.googleDorks.length - 6} more dorks\n`);
  
  // Investigation Workflow
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
  console.log("\x1b[36m🔬 INVESTIGATION WORKFLOW\x1b[0m");
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
  
  Object.entries(data.workflow).forEach(([phase, details]) => {
    console.log(`   \x1b[32m${details.name}:\x1b[0m`);
    details.steps.forEach(step => {
      console.log(`      • ${step}`);
    });
    console.log('');
  });
  
  // Compliance
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
  console.log("\x1b[36m⚖️  COMPLIANCE CHECKS\x1b[0m");
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
  
  Object.entries(data.compliance).forEach(([category, checks]) => {
    console.log(`   \x1b[32m${category.toUpperCase()}:\x1b[0m`);
    checks.forEach(check => {
      console.log(`      • ${check}`);
    });
    console.log('');
  });
  
  // Recommendations
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
  console.log("\x1b[36m💡 RECOMMENDATIONS\x1b[0m");
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
  
  data.recommendations.forEach(rec => {
    console.log(`   ${rec}`);
  });
  console.log('');
}

function saveReport(data) {
  const dir = './company-intel-reports';
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, -5);
  const safeName = data.company.replace(/[^a-zA-Z0-9]/g, '-').substring(0, 50);
  const filename = `${dir}/company-${safeName}-${timestamp}.txt`;
  
  let content = `═══════════════════════════════════════════════════════════
COMPANY INTELLIGENCE REPORT
═══════════════════════════════════════════════════════════

Query: ${data.query}
Type: ${data.type}
Date: ${new Date().toLocaleString()}

SEARCH LINKS:
OpenCorporates: ${data.searchLinks.opencorporates}
SEC EDGAR: ${data.searchLinks.sec}
Crunchbase: ${data.searchLinks.crunchbase}
LinkedIn: ${data.searchLinks.linkedin}

GOOGLE DORKS:
${data.googleDorks.join('\n')}

DATA COLLECTION POINTS:
${Object.entries(data.dataPoints).map(([cat, points]) => 
  `${cat.toUpperCase()}:\n${points.map(p => `  • ${p}`).join('\n')}`
).join('\n\n')}

INVESTIGATION WORKFLOW:
${Object.entries(data.workflow).map(([phase, details]) =>
  `${details.name}:\n${details.steps.map(s => `  • ${s}`).join('\n')}`
).join('\n\n')}
`;

  fs.writeFileSync(filename, content);
  console.log(`\x1b[32m✅ Report saved: ${filename}\x1b[0m\n`);
}

function showHelp() {
  showBanner();
  
  console.log("Usage: node company-intelligence.js <company|domain> [--save]\n");
  console.log("Options:");
  console.log("  --save               Save report to file");
  console.log("  --help               Show this help\n");
  
  console.log("Examples:");
  console.log("  node company-intelligence.js \"Acme Corporation\"");
  console.log("  node company-intelligence.js acme.com");
  console.log("  node company-intelligence.js \"Tesla Inc\" --save\n");
}

function main() {
  const args = process.argv.slice(2);
  
  if (args.length === 0 || args.includes('--help')) {
    showHelp();
    process.exit(0);
  }
  
  showBanner();
  
  let query = null;
  let saveFlag = false;
  
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--save') {
      saveFlag = true;
    } else if (!args[i].startsWith('--')) {
      query = args[i];
    }
  }
  
  if (!query) {
    console.log("\x1b[31m❌ No company/domain specified!\x1b[0m\n");
    showHelp();
    process.exit(1);
  }
  
  console.log(`⏳ Researching: ${query}...\n`);
  
  const parsed = parseInput(query);
  
  const results = {
    timestamp: new Date().toISOString(),
    query: query,
    type: parsed.type,
    company: parsed.company,
    domain: parsed.domain,
    searchLinks: generateSearchLinks(parsed),
    googleDorks: generateGoogleDorks(parsed.company),
    dataPoints: getDataPoints(parsed.company),
    workflow: getInvestigationWorkflow(),
    compliance: getComplianceChecks(),
    recommendations: generateRecommendations(parsed)
  };
  
  displayResults(results);
  
  if (saveFlag) {
    saveReport(results);
  }
  
  console.log("\x1b[31m ██████╗ ██████╗ ███╗   ███╗██████╗  █████╗ ███╗   ██╗██╗   ██╗\x1b[0m");
  console.log("\x1b[35m🥝 Research complete - by kiwi & 777\x1b[0m\n");
}

main();
