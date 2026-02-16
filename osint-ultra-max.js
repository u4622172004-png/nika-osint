#!/usr/bin/env node

const dns = require('dns').promises;
const https = require('https');
const tls = require('tls');
const axios = require('axios');
const fs = require('fs');
const whois = require('whois-json');
const phoneUtil = require('libphonenumber-js');
const crypto = require('crypto');
const pLimit = require('p-limit');
const limit = pLimit(10);

// ============================================
// UTILITIES
// ============================================

function sleep(ms){ return new Promise(r=>setTimeout(r,ms)); }

// ============================================
// DOMAIN INTELLIGENCE
// ============================================

async function runDomain(domain){
  let data = {};
  let risk = 0;
  
  console.log(`   └─ DNS lookup...`);
  try{ data.A = await dns.resolve4(domain); }catch{}
  try{ data.AAAA = await dns.resolve6(domain); }catch{}
  try{ data.MX = await dns.resolveMx(domain); }catch{}
  try{ data.NS = await dns.resolveNs(domain); }catch{}
  try{ data.TXT = await dns.resolveTxt(domain); }catch{}
  try{ data.CNAME = await dns.resolveCname(domain); }catch{}
  try{ data.SOA = await dns.resolveSoa(domain); }catch{}
  
  console.log(`   └─ WHOIS lookup...`);
  try{ 
    data.whois = await whois(domain);
    if(!data.whois.registrant && typeof data.whois === 'object') {
      data.whois = parseWhoisRaw(data.whois);
    }
  }catch{
    data.whois = null;
  }

  console.log(`   └─ Email security...`);
  data.spf = analyzeSPF(data.TXT);
  data.dmarc = await analyzeDMARC(domain);
  data.dkim = await checkDKIM(domain);
  if(!data.spf.valid) risk += 15;
  if(!data.dmarc.valid) risk += 15;
  
  console.log(`   └─ HTTP headers...`);
  data.headers = await getHeaders(domain);
  data.securityHeaders = analyzeHeaders(data.headers);
  if(!data.securityHeaders.hsts) risk += 10;
  if(!data.securityHeaders.csp) risk += 10;
  if(!data.securityHeaders.xframe) risk += 5;
  if(!data.securityHeaders.xcontent) risk += 5;
  if(!data.securityHeaders.xss) risk += 5;
  if(!data.securityHeaders.referrer) risk += 5;
  if(!data.securityHeaders.permissions) risk += 5;
  
  console.log(`   └─ TLS certificate...`);
  data.tls = await getTLSInfo(domain);
  
  console.log(`   └─ DNSSEC check...`);
  data.dnssec = await checkDNSSEC(domain);
  if(!data.dnssec) risk += 10;
  if(data.tls && data.tls.daysRemaining < 30) risk += 15;
  
  console.log(`   └─ Blacklist check...`);
  data.blacklists = await checkBlacklists(domain, data.A);
  if(data.blacklists.listed) risk += 20;
  
  console.log(`   └─ Technology detection...`);
  data.technologies = await detectTechnologies(domain, data.headers);
  
  console.log(`   └─ SSL Labs grade...`);
  data.sslGrade = await getSSLGrade(domain);
  
  data.riskScore = risk;
  return data;
}

function parseWhoisRaw(whoisData) {
  let rawText = '';
  if(typeof whoisData === 'string') {
    rawText = whoisData;
  } else if(whoisData.data || whoisData.rawData) {
    rawText = whoisData.data || whoisData.rawData;
  } else {
    rawText = JSON.stringify(whoisData);
  }
  
  const parsed = {
    registrant: {},
    admin: {},
    tech: {},
    registrar: {},
    nameServers: []
  };
  
  const extractField = (regex) => {
    const match = rawText.match(regex);
    return match ? match[1].trim() : null;
  };
  
  parsed.registrant.name = extractField(/Registrant Name:\s*(.+)/i);
  parsed.registrant.organization = extractField(/Registrant Organization:\s*(.+)/i);
  parsed.registrant.email = extractField(/Registrant Email:\s*(.+)/i);
  parsed.registrant.street = extractField(/Registrant Street:\s*(.+)/i);
  parsed.registrant.city = extractField(/Registrant City:\s*(.+)/i);
  parsed.registrant.state = extractField(/Registrant State\/Province:\s*(.+)/i);
  parsed.registrant.postalCode = extractField(/Registrant Postal Code:\s*(.+)/i);
  parsed.registrant.country = extractField(/Registrant Country:\s*(.+)/i);
  parsed.registrant.phone = extractField(/Registrant Phone:\s*(.+)/i);
  
  parsed.creationDate = extractField(/Creation Date:\s*(.+)/i);
  parsed.updatedDate = extractField(/Updated Date:\s*(.+)/i);
  parsed.expirationDate = extractField(/Registry Expiry Date:\s*(.+)/i);
  parsed.registrar.name = extractField(/Registrar:\s*(.+)/i);
  
  return parsed;
}

function getHeaders(domain){
  return new Promise(resolve=>{
    const req = https.request({host:domain,method:'HEAD',timeout:5000},res=>{
      resolve(res.headers);
    });
    req.on('error',()=>resolve({}));
    req.on('timeout',()=>{req.destroy();resolve({})});
    req.end();
  });
}

function analyzeHeaders(headers){
  return {
    hsts: !!headers['strict-transport-security'],
    csp: !!headers['content-security-policy'],
    xframe: !!headers['x-frame-options'],
    xcontent: !!headers['x-content-type-options'],
    xss: !!headers['x-xss-protection'],
    referrer: !!headers['referrer-policy'],
    permissions: !!headers['permissions-policy'],
    expectCT: !!headers['expect-ct'],
    server: headers['server'] || 'Hidden',
    poweredBy: headers['x-powered-by'] || 'Hidden'
  };
}

function analyzeSPF(txtRecords){
  if(!txtRecords) return {valid:false};
  const flat = txtRecords.flat().join(" ");
  const spf = flat.match(/v=spf1[^"]+/);
  if(!spf) return {valid:false};
  const strict = spf[0].includes("-all");
  const softfail = spf[0].includes("~all");
  return {valid:true,strict,softfail,record:spf[0]};
}

async function analyzeDMARC(domain){
  try{
    const record = await dns.resolveTxt(`_dmarc.${domain}`);
    const flat = record.flat().join(" ");
    const policyMatch = flat.match(/p=([^;]+)/);
    const pctMatch = flat.match(/pct=([^;]+)/);
    return {
      valid:true, 
      policy: policyMatch ? policyMatch[1] : "unknown",
      percentage: pctMatch ? pctMatch[1] : "100",
      record: flat
    };
  }catch{
    return {valid:false};
  }
}

async function checkDKIM(domain){
  const selectors = ['default', 'google', 'k1', 's1', 's2', 'dkim', 'mail', 'email'];
  let found = [];
  
  for(const selector of selectors){
    try{
      const record = await dns.resolveTxt(`${selector}._domainkey.${domain}`);
      if(record && record.length > 0){
        found.push({selector, record: record.flat().join('')});
      }
    }catch{}
  }
  
  return {valid: found.length > 0, selectors: found};
}

async function checkDNSSEC(domain){
  try{
    const res = await dns.resolve(domain, 'DNSKEY');
    return res && res.length > 0;
  }catch{
    return false;
  }
}

function getTLSInfo(domain){
  return new Promise(resolve=>{
    const socket = tls.connect(443, domain, {servername:domain,timeout:5000}, ()=>{
      const cert = socket.getPeerCertificate();
      const validTo = new Date(cert.valid_to);
      const validFrom = new Date(cert.valid_from);
      const daysRemaining = Math.floor((validTo - new Date())/86400000);
      const age = Math.floor((new Date() - validFrom)/86400000);
      
      resolve({
        issuer: cert.issuer,
        subject: cert.subject,
        valid_from: cert.valid_from,
        valid_to: cert.valid_to,
        daysRemaining,
        age,
        serialNumber: cert.serialNumber,
        fingerprint: cert.fingerprint,
        protocol: socket.getProtocol(),
        cipher: socket.getCipher()
      });
      socket.end();
    });
    socket.on('error',()=>resolve(null));
    socket.on('timeout',()=>{socket.destroy();resolve(null)});
  });
}

async function checkBlacklists(domain, ips){
  let listed = false;
  let lists = [];
  
  const blacklists = [
    'zen.spamhaus.org',
    'bl.spamcop.net',
    'dnsbl.sorbs.net',
    'cbl.abuseat.org'
  ];
  
  if(!ips || ips.length === 0) return {listed: false, lists: []};
  
  const ip = ips[0];
  const reversed = ip.split('.').reverse().join('.');
  
  for(const bl of blacklists){
    try{
      await dns.resolve4(`${reversed}.${bl}`);
      listed = true;
      lists.push(bl);
    }catch{}
  }
  
  return {listed, lists, checked: blacklists.length};
}

async function detectTechnologies(domain, headers){
  let tech = [];
  
  if(headers.server){
    if(headers.server.includes('nginx')) tech.push('Nginx');
    if(headers.server.includes('Apache')) tech.push('Apache');
    if(headers.server.includes('cloudflare')) tech.push('Cloudflare');
    if(headers.server.includes('Microsoft')) tech.push('Microsoft IIS');
  }
  
  if(headers['x-powered-by']){
    if(headers['x-powered-by'].includes('PHP')) tech.push('PHP');
    if(headers['x-powered-by'].includes('Express')) tech.push('Node.js/Express');
    if(headers['x-powered-by'].includes('ASP.NET')) tech.push('ASP.NET');
  }
  
  if(headers['x-aspnet-version']) tech.push('ASP.NET');
  if(headers['x-drupal-cache']) tech.push('Drupal');
  if(headers['x-generator'] && headers['x-generator'].includes('WordPress')) tech.push('WordPress');
  
  return tech.length > 0 ? tech : ['Unknown'];
}

async function getSSLGrade(domain){
  // Simplified SSL grading based on available data
  return {note: 'Use ssllabs.com for full analysis', quickCheck: 'Basic TLS check completed'};
}

// ============================================
// SUBDOMAIN ENUMERATION
// ============================================

async function runSubdomains(domain){
  let results = [];
  
  console.log(`   └─ Wordlist brute-force...`);
  try{
    const wordlistPath = './wordlists/subdomains.txt';
    if(fs.existsSync(wordlistPath)){
      const wordlist = fs.readFileSync(wordlistPath,'utf-8').split(/\r?\n/).filter(Boolean);
      const tasks = wordlist.map(sub =>
        limit(async () => {
          const fqdn = `${sub}.${domain}`;
          try{
            const ips = await dns.resolve4(fqdn);
            return {subdomain:fqdn,found:true,ips,source:'brute-force'};
          }catch{
            return null;
          }
        })
      );
      const bruteResults = await Promise.all(tasks);
      results = bruteResults.filter(Boolean);
    }
  }catch{}
  
  console.log(`   └─ Certificate transparency...`);
  const crt = await crtSearch(domain);
  
  // Deduplicate
  const seen = new Set(results.map(r=>r.subdomain));
  crt.forEach(c => {
    if(!seen.has(c.subdomain)){
      results.push(c);
      seen.add(c.subdomain);
    }
  });
  
  console.log(`   └─ Resolving IPs...`);
  for(let i=0; i<results.length; i++){
    if(!results[i].ips){
      try{
        results[i].ips = await dns.resolve4(results[i].subdomain);
      }catch{}
    }
  }
  
  return results;
}

async function crtSearch(domain){
  try{
    const url = `https://crt.sh/?q=%25.${domain}&output=json`;
    const res = await axios.get(url,{timeout:15000});
    const unique = [...new Set(res.data.map(x=>x.name_value))];
    return unique.map(s=>({subdomain:s,source:"crt.sh"}));
  }catch{
    return [];
  }
}

// ============================================
// EMAIL ANALYSIS
// ============================================

async function runEmail(email){
  let data = {};
  let risk = 0;
  
  console.log(`   └─ Format validation...`);
  data.valid = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
  if(!data.valid) risk += 20;
  
  const domain = email.split("@")[1];
  
  console.log(`   └─ MX records...`);
  try{
    data.mx = await dns.resolveMx(domain).catch(()=>[]);
    if(data.mx.length === 0) risk += 10;
  }catch{}
  
  console.log(`   └─ Disposable check...`);
  data.disposable = await checkDisposableEmail(domain);
  if(data.disposable) risk += 15;
  
  console.log(`   └─ Gravatar lookup...`);
  data.gravatar = await checkGravatar(email);
  
  console.log(`   └─ Have I Been Pwned...`);
  data.breaches = await checkHIBP(email);
  if(data.breaches.found) risk += 10;
  
  console.log(`   └─ Email reputation...`);
  data.reputation = await checkEmailReputation(email);
  
  data.riskScore = risk;
  return data;
}

async function checkDisposableEmail(domain){
  const disposableDomains = [
    'tempmail.com','guerrillamail.com','mailinator.com','10minutemail.com',
    'throwaway.email','temp-mail.org','getnada.com','maildrop.cc'
  ];
  return disposableDomains.includes(domain.toLowerCase());
}

async function checkGravatar(email){
  const hash = crypto.createHash('md5').update(email.trim().toLowerCase()).digest('hex');
  const url = `https://www.gravatar.com/avatar/${hash}?d=404`;
  
  try{
    const res = await axios.get(url, {validateStatus: false, timeout: 5000});
    return {
      exists: res.status === 200,
      url: `https://www.gravatar.com/avatar/${hash}`,
      profileUrl: `https://gravatar.com/${hash}`
    };
  }catch{
    return {exists: false, url: `https://www.gravatar.com/avatar/${hash}`};
  }
}

async function checkHIBP(email){
  // Note: HIBP API requires API key for email search
  // Free tier: only breach list, not email-specific
  return {
    note: 'Check manually at haveibeenpwned.com',
    url: `https://haveibeenpwned.com/account/${encodeURIComponent(email)}`,
    found: false
  };
}

async function checkEmailReputation(email){
  return {
    score: 'Unknown',
    note: 'Use services like EmailRep.io or Hunter.io for detailed reputation'
  };
}

// ============================================
// USERNAME OSINT
// ============================================

const platforms = [
  {name: 'GitHub', url: 'https://github.com/', api: 'https://api.github.com/users/'},
  {name: 'Reddit', url: 'https://reddit.com/user/', api: 'https://www.reddit.com/user/{}/about.json'},
  {name: 'Twitter', url: 'https://twitter.com/'},
  {name: 'Instagram', url: 'https://instagram.com/'},
  {name: 'Medium', url: 'https://medium.com/@'},
  {name: 'Pinterest', url: 'https://pinterest.com/'},
  {name: 'DevTo', url: 'https://dev.to/'},
  {name: 'HackerNews', url: 'https://news.ycombinator.com/user?id='},
  {name: 'GitLab', url: 'https://gitlab.com/'},
  {name: 'BitBucket', url: 'https://bitbucket.org/'},
  {name: 'StackOverflow', url: 'https://stackoverflow.com/users/'},
  {name: 'Twitch', url: 'https://twitch.tv/'},
  {name: 'YouTube', url: 'https://youtube.com/@'},
  {name: 'LinkedIn', url: 'https://linkedin.com/in/'},
  {name: 'Facebook', url: 'https://facebook.com/'},
  {name: 'TikTok', url: 'https://tiktok.com/@'},
  {name: 'Telegram', url: 'https://t.me/'},
  {name: 'Discord', url: 'https://discord.com/users/'},
  {name: 'Keybase', url: 'https://keybase.io/'},
  {name: 'Patreon', url: 'https://patreon.com/'}
];

async function runUsername(username){
  const tasks = platforms.map(platform =>
    limit(async () => {
      let url = platform.url + username;
      
      // Try API first if available
      if(platform.api){
        const apiUrl = platform.api.replace('{}', username);
        try{
          const r = await axios.get(apiUrl, {validateStatus:false, timeout:8000});
          if(r.status === 200){
            return {
              platform: platform.name,
              found: true,
              url,
              data: r.data
            };
          }
        }catch{}
      }
      
      // Fallback to HTTP check
      try{
        const r = await axios.get(url, {validateStatus:false, timeout:8000});
        if(r.status === 200 && !r.data.includes('Page Not Found') && !r.data.includes('404')){
          return {
            platform: platform.name,
            found: true,
            url
          };
        }
      }catch{}
      
      return null;
    })
  );
  
  const results = await Promise.all(tasks);
  return results.filter(Boolean);
}

// ============================================
// PHONE LOOKUP
// ============================================

async function runPhone(number){
  let data = {};
  
  console.log(`   └─ Parsing number...`);
  try{
    const parsed = phoneUtil.parsePhoneNumber(number);
    
    data.valid = parsed.isValid();
    data.country = parsed.country;
    data.countryCallingCode = parsed.countryCallingCode;
    data.nationalNumber = parsed.nationalNumber;
    data.type = parsed.getType();
    data.international = parsed.formatInternational();
    data.national = parsed.formatNational();
    data.e164 = parsed.format('E.164');
    data.rfc3966 = parsed.format('RFC3966');
    data.uri = parsed.getURI();
    
    console.log(`   └─ Carrier detection...`);
    data.carrier = getCarrierInfo(parsed.country, parsed.nationalNumber.toString());
    
    console.log(`   └─ Location lookup...`);
    data.location = getPhoneLocation(parsed);
    
    console.log(`   └─ Timezone...`);
    data.timezone = getPhoneTimezone(parsed.country);
    
    console.log(`   └─ Number type analysis...`);
    data.typeInfo = {
      type: getNumberType(parsed.getType()),
      isPossible: parsed.isPossible(),
      isValid: parsed.isValid(),
      canBeInternationallyDialled: true
    };
    
    console.log(`   └─ Social media links...`);
    data.social = {
      whatsapp: `https://wa.me/${number.replace(/\+/g, '')}`,
      telegram: `https://t.me/${number.replace(/\+/g, '')}`,
      signal: `https://signal.me/#p/${number.replace(/\+/g, '')}`,
      viber: `viber://chat?number=${number.replace(/\+/g, '')}`
    };
    
    console.log(`   └─ Spam check...`);
    data.spam = checkSpamNumber(number);
    
  }catch(e){
    data.valid = false;
    data.error = e.message;
  }
  
  return data;
}

function getNumberType(type){
  const types = {
    'MOBILE': 'Mobile/Cellulare',
    'FIXED_LINE': 'Fisso',
    'FIXED_LINE_OR_MOBILE': 'Fisso o Mobile',
    'TOLL_FREE': 'Numero Verde',
    'PREMIUM_RATE': 'Numero a Pagamento',
    'SHARED_COST': 'Costo Condiviso',
    'VOIP': 'VoIP',
    'PERSONAL_NUMBER': 'Numero Personale',
    'PAGER': 'Pager',
    'UAN': 'UAN',
    'VOICEMAIL': 'Segreteria',
    'UNKNOWN': 'Sconosciuto'
  };
  return types[type] || type;
}

function getCarrierInfo(country, number){
  const carriers = {
    'IT': {
      '330': 'TIM','331': 'TIM','333': 'Wind Tre','334': 'TIM','335': 'TIM',
      '336': 'Wind Tre','337': 'TIM','338': 'Wind Tre','339': 'Wind Tre',
      '340': 'Vodafone','342': 'Vodafone','343': 'Vodafone','344': 'Vodafone',
      '345': 'Vodafone','346': 'Vodafone','347': 'Vodafone','348': 'Vodafone',
      '349': 'Vodafone','350': 'Vodafone','360': 'Wind Tre','362': 'Wind Tre',
      '363': 'Wind Tre','366': 'Wind Tre','368': 'Wind Tre','380': 'Wind Tre',
      '383': 'Wind Tre','388': 'Wind Tre','389': 'Wind Tre','390': 'Wind Tre',
      '391': 'Wind Tre','392': 'Wind Tre','393': 'Wind Tre'
    },
    'US': {
      'carriers': 'AT&T, Verizon, T-Mobile, Sprint (requires area code lookup)'
    }
  };
  
  if(country === 'IT'){
    const prefix = number.substring(0, 3);
    return {
      name: carriers.IT[prefix] || 'Unknown',
      type: 'Mobile Network Operator',
      country: 'Italy'
    };
  }
  
  return {
    name: 'Unknown',
    note: `Carrier database for ${country} not available`,
    suggestion: 'Use HLR lookup service for accurate carrier detection'
  };
}

function getPhoneLocation(parsed){
  const locations = {
    'IT': {country: 'Italy', capital: 'Rome', lat: 41.9028, lon: 12.4964},
    'US': {country: 'United States', capital: 'Washington DC', lat: 38.9072, lon: -77.0369},
    'GB': {country: 'United Kingdom', capital: 'London', lat: 51.5074, lon: -0.1278},
    'FR': {country: 'France', capital: 'Paris', lat: 48.8566, lon: 2.3522},
    'DE': {country: 'Germany', capital: 'Berlin', lat: 52.5200, lon: 13.4050},
    'ES': {country: 'Spain', capital: 'Madrid', lat: 40.4168, lon: -3.7038},
    'CN': {country: 'China', capital: 'Beijing', lat: 39.9042, lon: 116.4074},
    'JP': {country: 'Japan', capital: 'Tokyo', lat: 35.6762, lon: 139.6503},
    'IN': {country: 'India', capital: 'New Delhi', lat: 28.6139, lon: 77.2090},
    'BR': {country: 'Brazil', capital: 'Brasília', lat: -15.8267, lon: -47.9218},
    'AU': {country: 'Australia', capital: 'Canberra', lat: -35.2809, lon: 149.1300}
  };
  
  return locations[parsed.country] || {country: 'Unknown', lat: 0, lon: 0};
}

function getPhoneTimezone(country){
  const timezones = {
    'IT': 'Europe/Rome',
    'US': 'America/New_York',
    'GB': 'Europe/London',
    'FR': 'Europe/Paris',
    'DE': 'Europe/Berlin',
    'ES': 'Europe/Madrid',
    'CN': 'Asia/Shanghai',
    'JP': 'Asia/Tokyo',
    'IN': 'Asia/Kolkata',
    'BR': 'America/Sao_Paulo',
    'AU': 'Australia/Sydney'
  };
  
  return timezones[country] || 'Unknown';
}

function checkSpamNumber(number){
  return {
    isSpam: false,
    score: 0,
    reports: 0,
    note: 'Check manually at: shouldianswer.com, truecaller.com, whocallsme.com'
  };
}

// ============================================
// IP GEOLOCATION
// ============================================

async function runIPInfo(ip){
  try{
    const res = await axios.get(`https://ipinfo.io/${ip}/json`, {timeout: 5000});
    const data = res.data;
    
    data.reverseDNS = await getReverseDNS(ip);
    data.asn = data.org ? data.org.split(' ')[0] : 'Unknown';
    data.vpnCheck = await checkVPN(ip);
    data.blacklistCheck = await checkIPBlacklist(ip);
    
    return data;
  }catch{
    return null;
  }
}

async function getReverseDNS(ip){
  try{
    const hostnames = await dns.reverse(ip);
    return hostnames.length > 0 ? hostnames : ['No PTR record'];
  }catch{
    return ['No PTR record'];
  }
}

async function checkVPN(ip){
  return {
    isVPN: false,
    note: 'Use IPQualityScore or IPHub API for VPN detection'
  };
}

async function checkIPBlacklist(ip){
  const reversed = ip.split('.').reverse().join('.');
  let listed = false;
  
  try{
    await dns.resolve4(`${reversed}.zen.spamhaus.org`);
    listed = true;
  }catch{}
  
  return {listed, service: 'Spamhaus'};
}

// ============================================
// RISK CALCULATION
// ============================================

function calculateRisk(results){
  let total = 0;
  
  if(results.domain?.riskScore) total += results.domain.riskScore;
  if(results.email?.riskScore) total += results.email.riskScore;
  if(results.subdomains?.length > 10) total += 15;
  if(results.subdomains?.length > 5) total += 5;
  
  if(total < 20) return {score:total, level:"LOW", color:'\x1b[32m'};
  if(total < 50) return {score:total, level:"MEDIUM", color:'\x1b[33m'};
  if(total < 80) return {score:total, level:"HIGH", color:'\x1b[31m'};
  return {score:total, level:"CRITICAL", color:'\x1b[35m'};
}

// ============================================
// DISPLAY RESULTS
// ============================================

function displayResults(results){
  console.log("\n╔════════════════════════════════════════════════════════╗");
  console.log("║              📊 RISULTATI COMPLETI 📊                  ║");
  console.log("╚════════════════════════════════════════════════════════╝\n");
  
  console.log(`🎯 RISK: ${results.risk.color}${results.risk.level}\x1b[0m (${results.risk.score}/100)\n`);
  
  if(results.domain){
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
    console.log("\x1b[36m🌐 DOMAIN\x1b[0m");
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
    
    console.log("📍 DNS:");
    console.log(`   A: ${results.domain.A ? results.domain.A.join(', ') : 'N/A'}`);
    if(results.domain.AAAA) console.log(`   AAAA: ${results.domain.AAAA.join(', ')}`);
    console.log(`   MX: ${results.domain.MX ? results.domain.MX.map(m=>`${m.exchange} (${m.priority})`).join(', ') : 'N/A'}`);
    console.log(`   NS: ${results.domain.NS ? results.domain.NS.join(', ') : 'N/A'}`);
    
    if(results.domain.whois && results.domain.whois.registrant && Object.keys(results.domain.whois.registrant).length > 0){
      console.log("\n👤 WHOIS:");
      if(results.domain.whois.registrant.name) console.log(`   Name: ${results.domain.whois.registrant.name}`);
      if(results.domain.whois.registrant.organization) console.log(`   Org: ${results.domain.whois.registrant.organization}`);
      if(results.domain.whois.registrant.email) console.log(`   Email: ${results.domain.whois.registrant.email}`);
      if(results.domain.whois.registrant.phone) console.log(`   Phone: ${results.domain.whois.registrant.phone}`);
      if(results.domain.whois.registrant.street) console.log(`   Street: ${results.domain.whois.registrant.street}`);
      if(results.domain.whois.registrant.city) console.log(`   City: ${results.domain.whois.registrant.city}`);
      if(results.domain.whois.registrant.state) console.log(`   State: ${results.domain.whois.registrant.state}`);
      if(results.domain.whois.registrant.country) console.log(`   Country: ${results.domain.whois.registrant.country}`);
    }
    
    if(results.domain.whois){
      console.log("\n📅 Dates:");
      if(results.domain.whois.creationDate) console.log(`   Created: ${results.domain.whois.creationDate}`);
      if(results.domain.whois.expirationDate) console.log(`   Expires: ${results.domain.whois.expirationDate}`);
    }
    
    console.log(`\n🔒 Security:`);
    console.log(`   SPF: ${results.domain.spf.valid ? '\x1b[32m✓\x1b[0m' : '\x1b[31m✗\x1b[0m'}`);
    console.log(`   DMARC: ${results.domain.dmarc.valid ? '\x1b[32m✓\x1b[0m' : '\x1b[31m✗\x1b[0m'}`);
    console.log(`   DKIM: ${results.domain.dkim.valid ? '\x1b[32m✓\x1b[0m' : '\x1b[31m✗\x1b[0m'}`);
    console.log(`   DNSSEC: ${results.domain.dnssec ? '\x1b[32m✓\x1b[0m' : '\x1b[31m✗\x1b[0m'}`);
    console.log(`   HSTS: ${results.domain.securityHeaders.hsts ? '\x1b[32m✓\x1b[0m' : '\x1b[31m✗\x1b[0m'}`);
    
    if(results.domain.tls){
      const c = results.domain.tls.daysRemaining < 30 ? '\x1b[33m' : '\x1b[32m';
      console.log(`\n🔐 TLS: ${c}${results.domain.tls.daysRemaining} days\x1b[0m`);
      console.log(`   Issuer: ${results.domain.tls.issuer.O}`);
      console.log(`   Protocol: ${results.domain.tls.protocol}`);
    }
    
    if(results.domain.technologies && results.domain.technologies.length > 0){
      console.log(`\n⚙️  Tech: ${results.domain.technologies.join(', ')}`);
    }
    
    if(results.domain.blacklists){
      console.log(`\n🚫 Blacklist: ${results.domain.blacklists.listed ? '\x1b[31mLISTED\x1b[0m' : '\x1b[32mCLEAN\x1b[0m'}`);
    }
    console.log("");
  }
  
  if(results.subdomains && results.subdomains.length > 0){
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
    console.log(`\x1b[36m🔍 SUBDOMAINS (${results.subdomains.length})\x1b[0m`);
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
    
    results.subdomains.forEach((s, i) => {
      console.log(`${i+1}. \x1b[32m${s.subdomain}\x1b[0m`);
      if(s.ips) console.log(`   IP: ${s.ips.join(', ')}`);
      console.log(`   Source: ${s.source}\n`);
    });
  }
  
  if(results.email){
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
    console.log("\x1b[36m📧 EMAIL\x1b[0m");
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
    
    console.log(`Valid: ${results.email.valid ? '\x1b[32m✓\x1b[0m' : '\x1b[31m✗\x1b[0m'}`);
    console.log(`Disposable: ${results.email.disposable ? '\x1b[31m✓\x1b[0m' : '\x1b[32m✗\x1b[0m'}`);
    console.log(`MX: ${results.email.mx?.length > 0 ? '\x1b[32m✓\x1b[0m' : '\x1b[31m✗\x1b[0m'}`);
    
    if(results.email.gravatar){
      console.log(`Gravatar: ${results.email.gravatar.exists ? '\x1b[32m✓\x1b[0m' : '\x1b[33m○\x1b[0m'}`);
      console.log(`   ${results.email.gravatar.url}`);
    }
    console.log("");
  }
  
  if(results.username && results.username.length > 0){
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
    console.log(`\x1b[36m👤 USERNAME (${results.username.length})\x1b[0m`);
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
    
    results.username.forEach((u, i) => {
      console.log(`${i+1}. \x1b[32m✓ ${u.platform}\x1b[0m`);
      console.log(`   ${u.url}\n`);
    });
  }
  
  if(results.phone){
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
    console.log("\x1b[36m📱 PHONE\x1b[0m");
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
    
    console.log(`Valid: ${results.phone.valid ? '\x1b[32m✓\x1b[0m' : '\x1b[31m✗\x1b[0m'}`);
    
    if(results.phone.valid){
      console.log(`\n📍 Info:`);
      console.log(`   Country: ${results.phone.country} (+${results.phone.countryCallingCode})`);
      console.log(`   Type: ${results.phone.typeInfo.type}`);
      console.log(`   Timezone: ${results.phone.timezone}`);
      
      console.log(`\n📞 Formats:`);
      console.log(`   International: ${results.phone.international}`);
      console.log(`   National: ${results.phone.national}`);
      console.log(`   E.164: ${results.phone.e164}`);
      
      if(results.phone.carrier){
        console.log(`\n📡 Carrier: ${results.phone.carrier.name}`);
      }
      
      if(results.phone.location){
        console.log(`\n🌍 Location: ${results.phone.location.country}`);
        if(results.phone.location.lat) console.log(`   Coords: ${results.phone.location.lat}, ${results.phone.location.lon}`);
      }
      
      if(results.phone.social){
        console.log(`\n💬 Links:`);
        console.log(`   WhatsApp: ${results.phone.social.whatsapp}`);
        console.log(`   Telegram: ${results.phone.social.telegram}`);
      }
    }
    console.log("");
  }
  
  if(results.ipInfo){
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
    console.log("\x1b[36m🌍 IP\x1b[0m");
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
    
    console.log(`IP: ${results.ipInfo.ip}`);
    console.log(`Location: ${results.ipInfo.city}, ${results.ipInfo.region}, ${results.ipInfo.country}`);
    console.log(`Coordinates: ${results.ipInfo.loc}`);
    console.log(`Organization: ${results.ipInfo.org}`);
    console.log(`ASN: ${results.ipInfo.asn}`);
    console.log(`Timezone: ${results.ipInfo.timezone}`);
    
    if(results.ipInfo.reverseDNS){
      console.log(`Reverse DNS: ${results.ipInfo.reverseDNS.join(', ')}`);
    }
    
    if(results.ipInfo.blacklistCheck){
      console.log(`Blacklist: ${results.ipInfo.blacklistCheck.listed ? '\x1b[31mLISTED\x1b[0m' : '\x1b[32mCLEAN\x1b[0m'}`);
    }
    console.log("");
  }
}

async function main(){
  const args = process.argv.slice(2);
  let domain, username, email, phone;
  
  for(let i=0;i<args.length;i++){
    if(args[i] === "--domain") domain = args[i+1];
    if(args[i] === "--username") username = args[i+1];
    if(args[i] === "--email") email = args[i+1];
    if(args[i] === "--phone") phone = args[i+1];
  }
  
  if(!domain && !username && !email && !phone && args.length > 0 && !args[0].startsWith('--')){
    domain = args[0];
  }
  
  if(!domain && !username && !email && !phone){
    console.log("\x1b[31m███╗   ██╗██╗██╗  ██╗ █████╗\n████╗  ██║██║██║ ██╔╝██╔══██╗\n██╔██╗ ██║██║█████╔╝ ███████║\n██║╚██╗██║██║██╔═██╗ ██╔══██║\n██║ ╚████║██║██║  ██╗██║  ██║\n╚═╝  ╚═══╝╚═╝╚═╝  ╚═╝╚═╝  ╚═╝\x1b[0m\n");
    console.log("\x1b[35m🥝 NIKA OSINT ULTRA v2.0 by kiwi & 777\x1b[0m\n");
    console.log("Usage: osint-ultra-max [OPTIONS]\n");
    console.log("Options:");
    console.log("  --domain <domain>");
    console.log("  --username <username>");
    console.log("  --email <email>");
    console.log("  --phone <phone>\n");
    process.exit(0);
  }
  
  console.log("\x1b[31m███╗   ██╗██╗██╗  ██╗ █████╗\n████╗  ██║██║██║ ██╔╝██╔══██╗\n██╔██╗ ██║██║█████╔╝ ███████║\n██║╚██╗██║██║██╔═██╗ ██╔══██║\n██║ ╚████║██║██║  ██╗██║  ██║\n╚═╝  ╚═══╝╚═╝╚═╝  ╚═╝╚═╝  ╚═╝\x1b[0m\n");
  console.log("\x1b[35m🥝 NIKA OSINT ULTRA v2.0 - Scan Started\x1b[0m\n");
  
  let results = {};
  
  if(domain){
    console.log("🌐 [*] Domain scan...");
    results.domain = await runDomain(domain);
    console.log("🔍 [*] Subdomains...");
    results.subdomains = await runSubdomains(domain);
    if(results.domain.A && results.domain.A[0]){
      console.log("🌍 [*] IP info...");
      results.ipInfo = await runIPInfo(results.domain.A[0]);
    }
  }
  
  if(username){
    console.log("👤 [*] Username...");
    results.username = await runUsername(username);
  }
  
  if(email){
    console.log("📧 [*] Email...");
    results.email = await runEmail(email);
  }
  
  if(phone){
    console.log("📱 [*] Phone...");
    results.phone = await runPhone(phone);
  }
  
  results.risk = calculateRisk(results);
  displayResults(results);
  
  console.log("\x1b[31m███╗   ██╗██╗██╗  ██╗ █████╗\n████╗  ██║██║██║ ██╔╝██╔══██╗\n██╔██╗ ██║██║█████╔╝ ███████║\n██║╚██╗██║██║██╔═██╗ ██╔══██║\n██║ ╚████║██║██║  ██╗██║  ██║\n╚═╝  ╚═══╝╚═╝╚═╝  ╚═╝╚═╝  ╚═╝\x1b[0m\n");
  console.log("\x1b[35m🥝 NIKA OSINT ULTRA v2.0 - Complete\x1b[0m\n");
}

main();
