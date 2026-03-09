#!/usr/bin/env node

const dns = require('dns').promises;
const https = require('https');
const http = require('http');
const tls = require('tls');
const axios = require('axios');
const fs = require('fs');
const path = require('path');
const whois = require('whois-json');
const phoneUtil = require('libphonenumber-js');
const crypto = require('crypto');
const pLimit = require('p-limit');
const { exec } = require('child_process');
const { promisify } = require('util');
const execAsync = promisify(exec);
const limit = pLimit(10);

const CONFIG = {
  SHODAN_API_KEY: process.env.SHODAN_API_KEY || '',
  VIRUSTOTAL_API_KEY: process.env.VIRUSTOTAL_API_KEY || '',
  SAVE_RESULTS: false,
  TIMEOUT: 10000,
  REPORTS_DIR: './reports'
};

function sleep(ms){ return new Promise(r=>setTimeout(r,ms)); }

function timestamp() {
  return new Date().toISOString().replace(/[:.]/g, '-').slice(0, -5);
}

async function ensureDir(dir) {
  try {
    await fs.promises.mkdir(dir, { recursive: true });
  } catch (e) {}
}

function generateGoogleDorks(domain) {
  return [
    `site:${domain} filetype:pdf`,
    `site:${domain} filetype:doc OR filetype:docx`,
    `site:${domain} filetype:xls OR filetype:xlsx`,
    `site:${domain} filetype:ppt OR filetype:pptx`,
    `site:${domain} filetype:txt`,
    `site:${domain} filetype:csv`,
    `site:${domain} filetype:sql`,
    `site:${domain} filetype:db`,
    `site:${domain} filetype:env`,
    `site:${domain} filetype:log`,
    `site:${domain} filetype:bak`,
    `site:${domain} filetype:conf OR filetype:config`,
    `site:${domain} inurl:admin`,
    `site:${domain} inurl:login`,
    `site:${domain} inurl:dashboard`,
    `site:${domain} inurl:portal`,
    `site:${domain} inurl:upload`,
    `site:${domain} inurl:backup`,
    `site:${domain} inurl:api`,
    `site:${domain} inurl:wp-admin`,
    `site:${domain} inurl:wp-login`,
    `site:${domain} inurl:phpmyadmin`,
    `site:${domain} inurl:cpanel`,
    `site:${domain} intitle:"index of"`,
    `site:${domain} intitle:"index of /" backup`,
    `site:${domain} intitle:"index of /" passwords`,
    `site:${domain} intext:"powered by"`,
    `site:${domain} intext:"api key"`,
    `site:${domain} intext:"api_key"`,
    `site:${domain} intext:"password"`,
    `site:${domain} intext:"secret"`,
    `site:${domain} intext:"token"`,
    `site:${domain} intext:"access_token"`,
    `site:${domain} intext:"private key"`,
    `site:${domain} intext:"BEGIN RSA PRIVATE KEY"`,
    `site:${domain} intext:"smtp"`,
    `site:${domain} intext:"ftp"`,
    `site:${domain} intext:"database"`,
    `"${domain}" site:pastebin.com`,
    `"${domain}" site:paste2.org`,
    `"${domain}" site:ideone.com`,
    `"${domain}" site:codebeautify.org`,
    `"${domain}" site:codepen.io`,
    `"${domain}" site:jsfiddle.net`,
    `"${domain}" site:github.com`,
    `"${domain}" site:gitlab.com`,
    `"${domain}" site:bitbucket.org`,
    `"${domain}" site:gist.github.com`,
    `"${domain}" site:stackoverflow.com`,
    `"${domain}" site:trello.com`,
    `"${domain}" site:scribd.com`,
    `"${domain}" ext:sql intext:password`,
    `"${domain}" ext:xml intext:password`,
    `"${domain}" ext:json intext:password`
  ];
}

async function searchShodan(ip) {
  if (!CONFIG.SHODAN_API_KEY) return { available: false, message: 'Set SHODAN_API_KEY env' };
  try {
    const url = `https://api.shodan.io/shodan/host/${ip}?key=${CONFIG.SHODAN_API_KEY}`;
    const res = await axios.get(url, { timeout: 10000 });
    return {
      available: true,
      ip: res.data.ip_str,
      organization: res.data.org,
      os: res.data.os,
      ports: res.data.ports || [],
      services: (res.data.data || []).map(s => ({ port: s.port, product: s.product, version: s.version })),
      vulnerabilities: res.data.vulns || [],
      hostnames: res.data.hostnames || [],
      city: res.data.city,
      country: res.data.country_name,
      isp: res.data.isp,
      asn: res.data.asn,
      tags: res.data.tags || []
    };
  } catch (e) {
    return { available: false, error: e.message };
  }
}

async function checkVirusTotal(domain) {
  if (!CONFIG.VIRUSTOTAL_API_KEY) return { available: false };
  try {
    const url = `https://www.virustotal.com/vtapi/v2/domain/report?apikey=${CONFIG.VIRUSTOTAL_API_KEY}&domain=${domain}`;
    const res = await axios.get(url, { timeout: 10000 });
    return {
      available: true,
      detected_urls: (res.data.detected_urls || []).length,
      detected_samples: (res.data.detected_communicating_samples || []).length,
      categories: res.data.categories || {},
      reputation: res.data.reputation || 0,
      whois_timestamp: res.data.whois_timestamp
    };
  } catch {
    return { available: false };
  }
}

async function searchCVE(technology) {
  try {
    const url = `https://cve.circl.lu/api/search/${encodeURIComponent(technology)}`;
    const res = await axios.get(url, { timeout: 5000 });
    return (res.data || []).slice(0, 5).map(cve => ({
      id: cve.id,
      summary: cve.summary ? cve.summary.substring(0, 150) + '...' : 'No summary',
      cvss: cve.cvss || 'N/A'
    }));
  } catch {
    return [];
  }
}

async function checkWebArchive(domain) {
  try {
    const url = `http://archive.org/wayback/available?url=${domain}`;
    const res = await axios.get(url, { timeout: 5000 });
    if (res.data.archived_snapshots && res.data.archived_snapshots.closest) {
      return {
        available: true,
        url: res.data.archived_snapshots.closest.url,
        timestamp: res.data.archived_snapshots.closest.timestamp,
        status: res.data.archived_snapshots.closest.status
      };
    }
    return { available: false };
  } catch {
    return { available: false };
  }
}

async function searchGitHub(query) {
  try {
    const url = `https://api.github.com/search/repositories?q=${encodeURIComponent(query)}&sort=stars&per_page=5`;
    const res = await axios.get(url, { 
      timeout: 5000,
      headers: { 'User-Agent': 'NIKA-OSINT' }
    });
    return (res.data.items || []).map(repo => ({
      name: repo.full_name,
      description: repo.description,
      stars: repo.stargazers_count,
      url: repo.html_url,
      language: repo.language
    }));
  } catch {
    return [];
  }
}

function getDNSHistory(domain) {
  return {
    note: 'DNS history requires SecurityTrails API key',
    url: `https://securitytrails.com/domain/${domain}/history/a`
  };
}

function searchCensys(domain) {
  return {
    note: 'Censys search requires API key',
    url: `https://search.censys.io/search?resource=hosts&q=${domain}`
  };
}

async function checkAlienVault(domain) {
  try {
    const url = `https://otx.alienvault.com/api/v1/indicators/domain/${domain}/general`;
    const res = await axios.get(url, { timeout: 5000 });
    return {
      available: true,
      pulse_count: res.data.pulse_info?.count || 0,
      url: `https://otx.alienvault.com/indicator/domain/${domain}`
    };
  } catch {
    return { available: false };
  }
}

function getEmailHunterUrl(domain) {
  return `https://hunter.io/search/${domain}`;
}

function getLinkedInUrl(domain) {
  const company = domain.split('.')[0];
  return `https://www.linkedin.com/search/results/companies/?keywords=${company}`;
}

function getCrunchbaseUrl(domain) {
  const company = domain.split('.')[0];
  return `https://www.crunchbase.com/textsearch?q=${company}`;
}

async function searchCertSpotter(domain) {
  try {
    const url = `https://api.certspotter.com/v1/issuances?domain=${domain}&include_subdomains=true&expand=dns_names`;
    const res = await axios.get(url, { timeout: 10000 });
    return (res.data || []).slice(0, 10).map(cert => ({
      dns_names: cert.dns_names || [],
      issuer: cert.issuer?.name || 'Unknown'
    }));
  } catch {
    return [];
  }
}

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
  try{ data.CAA = await dns.resolve(domain, 'CAA'); }catch{}
  
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
  data.bimi = await checkBIMI(domain);
  if(!data.spf.valid) risk += 15;
  if(!data.dmarc.valid) risk += 15;
  
  console.log(`   └─ Security headers...`);
  data.headers = await getHeaders(domain);
  data.securityHeaders = analyzeHeaders(data.headers);
  if(!data.securityHeaders.hsts) risk += 10;
  if(!data.securityHeaders.csp) risk += 10;
  
  console.log(`   └─ TLS certificate...`);
  data.tls = await getTLSInfo(domain);
  
  console.log(`   └─ DNSSEC check...`);
  data.dnssec = await checkDNSSEC(domain);
  if(!data.dnssec) risk += 10;
  
  console.log(`   └─ Blacklist check...`);
  data.blacklists = await checkBlacklists(domain, data.A);
  if(data.blacklists.listed) risk += 20;
  
  console.log(`   └─ Technology detection...`);
  data.technologies = await detectTechnologies(domain, data.headers);
  
  console.log(`   └─ Google dorks...`);
  data.googleDorks = generateGoogleDorks(domain);
  
  console.log(`   └─ Web archive...`);
  data.webArchive = await checkWebArchive(domain);
  
  console.log(`   └─ AlienVault OTX...`);
  data.alienVault = await checkAlienVault(domain);
  
  console.log(`   └─ GitHub search...`);
  data.github = await searchGitHub(domain);
  
  if(data.A && data.A[0]){
    console.log(`   └─ Shodan...`);
    data.shodan = await searchShodan(data.A[0]);
  }
  
  console.log(`   └─ VirusTotal...`);
  data.virusTotal = await checkVirusTotal(domain);
  
  console.log(`   └─ Certificate search...`);
  data.certspotter = await searchCertSpotter(domain);
  
  if(data.technologies && data.technologies.length > 0) {
    console.log(`   └─ CVE search...`);
    data.cves = {};
    for(const tech of data.technologies.slice(0, 3)) {
      data.cves[tech] = await searchCVE(tech);
      await sleep(500);
    }
  }
  
  data.resources = {
    emailHunter: getEmailHunterUrl(domain),
    linkedin: getLinkedInUrl(domain),
    crunchbase: getCrunchbaseUrl(domain),
    dnsHistory: getDNSHistory(domain),
    censys: searchCensys(domain)
  };
  
  data.riskScore = risk;
  return data;
}

async function checkBIMI(domain) {
  try {
    const record = await dns.resolveTxt(`default._bimi.${domain}`);
    return { valid: true, record: record.flat().join('') };
  } catch {
    return { valid: false };
  }
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
    const req = https.request({host:domain,method:'HEAD',timeout:CONFIG.TIMEOUT},res=>{
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
    poweredBy: headers['x-powered-by'] || 'Hidden',
    setCookie: !!headers['set-cookie'],
    cors: !!headers['access-control-allow-origin']
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
  const selectors = ['default', 'google', 'k1', 's1', 's2', 'dkim', 'mail', 'email', 'selector1', 'selector2', 'dkim1', 'dkim2'];
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
    const socket = tls.connect(443, domain, {servername:domain,timeout:CONFIG.TIMEOUT}, ()=>{
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
        fingerprint256: cert.fingerprint256,
        protocol: socket.getProtocol(),
        cipher: socket.getCipher(),
        bits: cert.bits
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
    'cbl.abuseat.org',
    'b.barracudacentral.org',
    'dnsbl-1.uceprotect.net',
    'bl.blocklist.de'
  ];
  
  if(!ips || ips.length === 0) return {listed: false, lists: [], checked: blacklists.length};
  
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
    const server = headers.server.toLowerCase();
    if(server.includes('nginx')) tech.push('Nginx');
    if(server.includes('apache')) tech.push('Apache');
    if(server.includes('cloudflare')) tech.push('Cloudflare');
    if(server.includes('microsoft-iis')) tech.push('Microsoft IIS');
    if(server.includes('litespeed')) tech.push('LiteSpeed');
    if(server.includes('openresty')) tech.push('OpenResty');
  }
  
  if(headers['x-powered-by']){
    const powered = headers['x-powered-by'];
    if(powered.includes('PHP')) tech.push('PHP');
    if(powered.includes('Express')) tech.push('Node.js/Express');
    if(powered.includes('ASP.NET')) tech.push('ASP.NET');
    if(powered.includes('Next.js')) tech.push('Next.js');
  }
  
  if(headers['x-aspnet-version']) tech.push('ASP.NET');
  if(headers['x-drupal-cache']) tech.push('Drupal');
  if(headers['x-generator']) {
    if(headers['x-generator'].includes('WordPress')) tech.push('WordPress');
    if(headers['x-generator'].includes('Joomla')) tech.push('Joomla');
  }
  
  return tech.length > 0 ? tech : ['Unknown'];
}
// ============================================
// SUBDOMAIN ENUMERATION
// ============================================

async function runSubdomains(domain){
  let results = [];
  
  console.log(`   └─ Brute-force scan...`);
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
  
  console.log(`   └─ Certificate transparency (crt.sh)...`);
  const crt = await crtSearch(domain);
  
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
// EMAIL ANALYSIS (ENHANCED)
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
  
  console.log(`   └─ Data breach check...`);
  data.breaches = {
    haveibeenpwned: `https://haveibeenpwned.com/account/${encodeURIComponent(email)}`,
    dehashed: `https://www.dehashed.com/search?query=${encodeURIComponent(email)}`,
    leakcheck: `https://leakcheck.io/`
  };
  
  console.log(`   └─ Paste sites...`);
  data.pasteSites = [
    `https://www.google.com/search?q=site:pastebin.com+"${email}"`,
    `https://www.google.com/search?q=site:gist.github.com+"${email}"`,
    `https://www.google.com/search?q=site:ghostbin.com+"${email}"`,
    `https://www.google.com/search?q=site:ideone.com+"${email}"`
  ];
  
  data.reputationServices = getEmailReputationUrls(email);
  
  data.riskScore = risk;
  return data;
}

async function checkDisposableEmail(domain){
  const disposableDomains = [
    'tempmail.com','guerrillamail.com','mailinator.com','10minutemail.com',
    'throwaway.email','temp-mail.org','getnada.com','maildrop.cc','sharklasers.com',
    'guerillamail.info','grr.la','guerillamail.biz','guerillamail.com','guerillamail.de',
    'guerrillamail.net','guerrillamail.org','guerrillamailblock.com','pokemail.net',
    'spam4.me','trashmail.com','yopmail.com','emailondeck.com','fakeinbox.com',
    'mailnesia.com','tempinbox.com','throwawaymail.com'
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

function getEmailReputationUrls(email) {
  return {
    emailrep: `https://emailrep.io/${email}`,
    hunter: `https://hunter.io/email-verifier`,
    neverbounce: `https://neverbounce.com/`,
    zerobounce: `https://www.zerobounce.net/`,
    emailchecker: `https://email-checker.net/check`,
    verifalia: `https://verifalia.com/validate-email`
  };
}

// ============================================
// USERNAME OSINT (EXTENDED)
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
  {name: 'Patreon', url: 'https://patreon.com/'},
  {name: 'Gravatar', url: 'https://gravatar.com/'},
  {name: 'Behance', url: 'https://www.behance.net/'},
  {name: 'Dribbble', url: 'https://dribbble.com/'},
  {name: 'Vimeo', url: 'https://vimeo.com/'},
  {name: 'SoundCloud', url: 'https://soundcloud.com/'}
];

async function runUsername(username){
  console.log(`   └─ Searching platforms...`);
  const tasks = platforms.map(platform =>
    limit(async () => {
      let url = platform.url + username;
      
      if(platform.api){
        const apiUrl = platform.api.replace('{}', username);
        try{
          const r = await axios.get(apiUrl, {validateStatus:false, timeout:8000});
          if(r.status === 200){
            return {platform: platform.name, found: true, url};
          }
        }catch{}
      }
      
      try{
        const r = await axios.get(url, {validateStatus:false, timeout:8000});
        if(r.status === 200 && !r.data.includes('Page Not Found') && !r.data.includes('404')){
          return {platform: platform.name, found: true, url};
        }
      }catch{}
      
      return null;
    })
  );
  
  const results = await Promise.all(tasks);
  const found = results.filter(Boolean);
  
  const additionalSearches = getSocialSearchUrls(username);
  
  return { found, additionalSearches };
}

function getSocialSearchUrls(username) {
  return {
    google: `https://www.google.com/search?q="${username}"`,
    duckduckgo: `https://duckduckgo.com/?q="${username}"`,
    yandex: `https://yandex.com/search/?text="${username}"`,
    bing: `https://www.bing.com/search?q="${username}"`,
    namechk: `https://namechk.com/?s=${username}`,
    knowem: `https://knowem.com/checkusernames.php?u=${username}`,
    namecheckup: `https://namecheckup.com/${username}`,
    socialcatfish: `https://socialcatfish.com/`,
    pipl: `https://pipl.com/search/?q=${username}`,
    spokeo: `https://www.spokeo.com/${username}`
  };
}

// ============================================
// PHONE AUTO SEARCH (NEW!)
// ============================================

function generatePhoneSearches(phone) {
  const cleanPhone = phone.replace(/\D/g, '');
  const withPlus = phone.startsWith('+') ? phone : '+' + cleanPhone;
  
  return {
    // Search engines
    google: `https://www.google.com/search?q="${phone}"`,
    googleClean: `https://www.google.com/search?q=${cleanPhone}`,
    bing: `https://www.bing.com/search?q="${phone}"`,
    duckduckgo: `https://duckduckgo.com/?q="${phone}"`,
    yandex: `https://yandex.com/search/?text="${phone}"`,
    
    // Social media
    facebook: `https://www.facebook.com/search/people/?q=${phone}`,
    linkedin: `https://www.linkedin.com/search/results/people/?keywords=${phone}`,
    instagram: `https://www.instagram.com/explore/tags/${cleanPhone}/`,
    twitter: `https://twitter.com/search?q="${phone}"`,
    tiktok: `https://www.tiktok.com/search?q=${phone}`,
    
    // Messaging
    telegram: `https://t.me/${cleanPhone}`,
    whatsapp: `https://wa.me/${cleanPhone}`,
    signal: `https://signal.me/#p/${cleanPhone}`,
    viber: `viber://chat?number=${cleanPhone}`,
    
    // Reputation services
    truecaller: `https://www.truecaller.com/search/int/${phone}`,
    sync: `https://www.sync.me/search/?query=${phone}`,
    numverify: `https://numverify.com/`,
    phonevalidator: `https://www.phonevalidator.com/index.aspx`,
    
    // Spam check services
    shouldianswer: `https://www.shouldianswer.com/phone-number/${cleanPhone}`,
    whocallsme: `https://whocallsme.com/${cleanPhone}`,
    whocalld: `https://whocalld.com/+${cleanPhone}`,
    tellows: `https://www.tellows.com/num/${cleanPhone}`,
    spamcalls: `https://www.spamcalls.net/en/number/${cleanPhone}`,
    callapp: `https://callapp.com/search/${cleanPhone}`,
    showcaller: `https://www.showcaller.com/`,
    
    // People search
    pipl: `https://pipl.com/search/?q=${phone}`,
    spokeo: `https://www.spokeo.com/${phone}`,
    whitepages: `https://www.whitepages.com/phone/${cleanPhone}`,
    the411: `https://www.411.com/phone/${cleanPhone}`,
    
    // Italy specific
    paginebianche: `https://www.paginebianche.it/ricerca?qs=${cleanPhone}`,
    paginegialle: `https://www.paginegialle.it/ricerca/${cleanPhone}`,
    tuttocitta: `https://www.tuttocitta.it/cerca/${cleanPhone}`,
    
    // International directories
    trueyellow: `https://www.trueyellow.com/search?q=${phone}`,
    yellowpages: `https://www.yellowpages.com/search?search_terms=${phone}`,
    
    // OSINT databases
    intelx: `https://intelx.io/?s=${phone}`,
    
    // Breach databases
    dehashed: `https://www.dehashed.com/search?query=${phone}`,
    leakcheck: `https://leakcheck.io/`,
    snusbase: `https://snusbase.com/`,
    
    // Reverse lookup
    reversephonelookup: `https://www.reversephonelookup.com/number/${cleanPhone}/`,
    spydialer: `https://www.spydialer.com/default.aspx`,
    
    // Carrier lookup
    freecarrierlookup: `https://freecarrierlookup.com/`,
    carrierlookup: `https://www.carrierlookup.com/`,
    
    // Additional
    thatsthem: `https://thatsthem.com/phone/${cleanPhone}`,
    fastpeoplesearch: `https://www.fastpeoplesearch.com/phone/${cleanPhone}`,
    truepeoplesearch: `https://www.truepeoplesearch.com/results?phoneno=${cleanPhone}`
  };
}

async function autoSearchPhone(phone) {
  const searches = generatePhoneSearches(phone);
  
  try {
    const cleanPhone = phone.replace(/\D/g, '');
    const res = await axios.get(`https://www.google.com/search?q="${cleanPhone}"`, {
      timeout: 5000,
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
      }
    });
    
    const hasResults = !res.data.includes('did not match any documents') && 
                       !res.data.includes('No results found');
    
    searches.googleResultsFound = hasResults;
  } catch {
    searches.googleResultsFound = 'unknown';
  }
  
  return searches;
}

// ============================================
// PHONE LOOKUP (ULTRA ENHANCED WITH AUTO SEARCH)
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
    
    data.typeInfo = {
      type: getNumberType(parsed.getType()),
      isPossible: parsed.isPossible(),
      isValid: parsed.isValid()
    };
    
    data.social = {
      whatsapp: `https://wa.me/${number.replace(/\+/g, '')}`,
      telegram: `https://t.me/${number.replace(/\+/g, '')}`,
      signal: `https://signal.me/#p/${number.replace(/\+/g, '')}`,
      viber: `viber://chat?number=${number.replace(/\+/g, '')}`
    };
    
    console.log(`   └─ Reputation services...`);
    data.reputationServices = getPhoneReputationUrls(number);
    
    console.log(`   └─ Auto search online...`);
    data.autoSearch = await autoSearchPhone(number);
    
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
    suggestion: 'Use HLR lookup service for carrier detection'
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

function getPhoneReputationUrls(number) {
  return {
    truecaller: `https://www.truecaller.com/search/int/${number}`,
    numverify: `https://numverify.com/`,
    phonevalidator: `https://www.phonevalidator.com/`,
    shouldianswer: `https://www.shouldianswer.com/phone-number/${number}`,
    sync: `https://www.sync.me/`,
    whocallsme: `https://whocallsme.com/${number.replace(/\D/g, '')}`,
    whocalld: `https://whocalld.com/+${number.replace(/\D/g, '')}`,
    spamcalls: `https://www.spamcalls.net/en/number/${number.replace(/\D/g, '')}`,
    tellows: `https://www.tellows.com/num/${number.replace(/\D/g, '')}`
  };
}
// ============================================
// IP GEOLOCATION (ENHANCED)
// ============================================

async function runIPInfo(ip){
  try{
    const res = await axios.get(`https://ipinfo.io/${ip}/json`, {timeout: 5000});
    const data = res.data;
    
    data.reverseDNS = await getReverseDNS(ip);
    data.asn = data.org ? data.org.split(' ')[0] : 'Unknown';
    data.blacklistCheck = await checkIPBlacklist(ip);
    
    data.ipapi = `https://ipapi.co/${ip}/json/`;
    data.abuseipdb = `https://www.abuseipdb.com/check/${ip}`;
    data.shodan = `https://www.shodan.io/host/${ip}`;
    data.censys = `https://search.censys.io/hosts/${ip}`;
    
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

async function checkIPBlacklist(ip){
  const reversed = ip.split('.').reverse().join('.');
  let listed = false;
  const lists = [];
  
  const blacklists = ['zen.spamhaus.org', 'bl.spamcop.net', 'cbl.abuseat.org'];
  
  for(const bl of blacklists){
    try{
      await dns.resolve4(`${reversed}.${bl}`);
      listed = true;
      lists.push(bl);
    }catch{}
  }
  
  return {listed, lists, checked: blacklists.length};
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
  if(results.domain?.shodan?.vulnerabilities?.length > 0) total += 25;
  if(results.domain?.blacklists?.listed) total += 20;
  
  if(total < 20) return {score:total, level:"LOW", color:'\x1b[32m'};
  if(total < 50) return {score:total, level:"MEDIUM", color:'\x1b[33m'};
  if(total < 80) return {score:total, level:"HIGH", color:'\x1b[31m'};
  return {score:total, level:"CRITICAL", color:'\x1b[35m'};
}

// ============================================
// SAVE RESULTS
// ============================================

async function saveResults(results, target) {
  if (!CONFIG.SAVE_RESULTS) return;
  
  const dir = CONFIG.REPORTS_DIR;
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  
  const ts = timestamp();
  const filename = `${target.replace(/[^a-z0-9]/gi, '_')}-${ts}`;
  
  const jsonPath = `${dir}/${filename}.json`;
  fs.writeFileSync(jsonPath, JSON.stringify(results, null, 2));
  console.log(`\n\x1b[32m[✓] Saved: ${jsonPath}\x1b[0m`);
  
  const txtPath = `${dir}/${filename}.txt`;
  let txtContent = `═══════════════════════════════════════════════════════════
NIKA OSINT ULTRA v3.0 - COMPLETE REPORT
═══════════════════════════════════════════════════════════

Target: ${target}
Date: ${new Date().toISOString()}
Risk Level: ${results.risk.level} (${results.risk.score}/100)

═══════════════════════════════════════════════════════════
FULL DATA
═══════════════════════════════════════════════════════════

${JSON.stringify(results, null, 2)}
`;
  fs.writeFileSync(txtPath, txtContent);
  console.log(`\x1b[32m[✓] Saved: ${txtPath}\x1b[0m`);
}

// ============================================
// DISPLAY RESULTS (SAME INTERFACE)
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
      if(results.domain.whois.registrant.city) console.log(`   City: ${results.domain.whois.registrant.city}, ${results.domain.whois.registrant.country}`);
    }
    
    if(results.domain.whois){
      console.log("\n📅 Dates:");
      if(results.domain.whois.creationDate) console.log(`   Created: ${results.domain.whois.creationDate}`);
      if(results.domain.whois.expirationDate) console.log(`   Expires: ${results.domain.whois.expirationDate}`);
    }
    
    console.log(`\n🔒 Security:`);
    console.log(`   SPF: ${results.domain.spf.valid ? '\x1b[32m✓\x1b[0m' : '\x1b[31m✗\x1b[0m'}`);
    console.log(`   DMARC: ${results.domain.dmarc.valid ? '\x1b[32m✓\x1b[0m' : '\x1b[31m✗\x1b[0m'}`);
    console.log(`   DKIM: ${results.domain.dkim.valid ? `\x1b[32m✓ (${results.domain.dkim.selectors.length} selectors)\x1b[0m` : '\x1b[31m✗\x1b[0m'}`);
    console.log(`   DNSSEC: ${results.domain.dnssec ? '\x1b[32m✓\x1b[0m' : '\x1b[31m✗\x1b[0m'}`);
    console.log(`   HSTS: ${results.domain.securityHeaders.hsts ? '\x1b[32m✓\x1b[0m' : '\x1b[31m✗\x1b[0m'}`);
    console.log(`   CSP: ${results.domain.securityHeaders.csp ? '\x1b[32m✓\x1b[0m' : '\x1b[31m✗\x1b[0m'}`);
    
    if(results.domain.tls){
      const c = results.domain.tls.daysRemaining < 30 ? '\x1b[33m' : '\x1b[32m';
      console.log(`\n🔐 TLS: ${c}${results.domain.tls.daysRemaining} days\x1b[0m`);
      console.log(`   Issuer: ${results.domain.tls.issuer.O}`);
      console.log(`   Protocol: ${results.domain.tls.protocol}`);
      console.log(`   Cipher: ${results.domain.tls.cipher.name}`);
    }
    
    if(results.domain.technologies){
      console.log(`\n⚙️  Tech: ${results.domain.technologies.join(', ')}`);
    }
    
    if(results.domain.blacklists){
      console.log(`\n🚫 Blacklist: ${results.domain.blacklists.listed ? '\x1b[31mLISTED on '+results.domain.blacklists.lists.join(', ')+'\x1b[0m' : '\x1b[32mCLEAN\x1b[0m'} (checked ${results.domain.blacklists.checked} lists)`);
    }
    
    if(results.domain.shodan && results.domain.shodan.available){
      console.log(`\n🔥 Shodan:`);
      if(results.domain.shodan.ports.length > 0) console.log(`   Open Ports: ${results.domain.shodan.ports.join(', ')}`);
      if(results.domain.shodan.vulnerabilities && results.domain.shodan.vulnerabilities.length > 0){
        console.log(`   \x1b[31m⚠️  Vulnerabilities: ${results.domain.shodan.vulnerabilities.length}\x1b[0m`);
      }
      if(results.domain.shodan.os) console.log(`   OS: ${results.domain.shodan.os}`);
    }
    
    if(results.domain.virusTotal && results.domain.virusTotal.available){
      console.log(`\n🦠 VirusTotal:`);
      console.log(`   Detected URLs: ${results.domain.virusTotal.detected_urls}`);
      console.log(`   Reputation: ${results.domain.virusTotal.reputation}`);
    }
    
    if(results.domain.webArchive && results.domain.webArchive.available){
      console.log(`\n📚 Web Archive: Available (${results.domain.webArchive.timestamp})`);
    }
    
    if(results.domain.alienVault && results.domain.alienVault.available){
      console.log(`\n👽 AlienVault OTX: ${results.domain.alienVault.pulse_count} pulses`);
    }
    
    if(results.domain.github && results.domain.github.length > 0){
      console.log(`\n💻 GitHub: ${results.domain.github.length} repositories found`);
    }
    
    if(results.domain.googleDorks && results.domain.googleDorks.length > 0){
      console.log(`\n🔎 Google Dorks: ${results.domain.googleDorks.length} queries generated`);
      console.log(`   (use --save to export all dorks)`);
    }
    
    if(results.domain.cves && Object.keys(results.domain.cves).length > 0){
      let totalCVEs = 0;
      Object.values(results.domain.cves).forEach(cves => totalCVEs += cves.length);
      if(totalCVEs > 0){
        console.log(`\n🔓 CVEs Found: ${totalCVEs} vulnerabilities`);
        console.log(`   (use --save to see details)`);
      }
    }
    
    console.log("");
  }
  
  if(results.subdomains && results.subdomains.length > 0){
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
    console.log(`\x1b[36m🔍 SUBDOMAINS (${results.subdomains.length})\x1b[0m`);
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
    
    results.subdomains.slice(0, 20).forEach((s, i) => {
      console.log(`${i+1}. \x1b[32m${s.subdomain}\x1b[0m`);
      if(s.ips) console.log(`   IP: ${s.ips.join(', ')}`);
      console.log(`   Source: ${s.source}\n`);
    });
    
    if(results.subdomains.length > 20){
      console.log(`... and ${results.subdomains.length - 20} more (use --save to see all)\n`);
    }
  }
  
  if(results.email){
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
    console.log("\x1b[36m📧 EMAIL\x1b[0m");
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
    
    console.log(`Valid: ${results.email.valid ? '\x1b[32m✓\x1b[0m' : '\x1b[31m✗\x1b[0m'}`);
    console.log(`Disposable: ${results.email.disposable ? '\x1b[31m✓ YES\x1b[0m' : '\x1b[32m✗ No\x1b[0m'}`);
    console.log(`MX: ${results.email.mx?.length > 0 ? '\x1b[32m✓ '+results.email.mx.length+' servers\x1b[0m' : '\x1b[31m✗ None\x1b[0m'}`);
    
    if(results.email.gravatar){
      console.log(`\n🖼️  Gravatar: ${results.email.gravatar.exists ? '\x1b[32m✓ Profile exists\x1b[0m' : '○ No profile'}`);
      if(results.email.gravatar.exists) console.log(`   ${results.email.gravatar.profileUrl}`);
    }
    
    if(results.email.breaches){
      console.log(`\n🔓 Breach Check:`);
      console.log(`   HaveIBeenPwned: ${results.email.breaches.haveibeenpwned}`);
      console.log(`   (use --save to see all breach check services)`);
    }
    
    if(results.email.pasteSites && results.email.pasteSites.length > 0){
      console.log(`\n📄 Paste Sites: ${results.email.pasteSites.length} search queries`);
      console.log(`   (use --save to export all links)`);
    }
    
    console.log("");
  }
  
  if(results.username){
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
    console.log(`\x1b[36m👤 USERNAME (${results.username.found.length}/${platforms.length})\x1b[0m`);
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
    
    results.username.found.forEach((u, i) => {
      console.log(`${i+1}. \x1b[32m✓ ${u.platform}\x1b[0m`);
      console.log(`   ${u.url}\n`);
    });
    
    if(results.username.additionalSearches){
      console.log(`🔎 Additional searches: ${Object.keys(results.username.additionalSearches).length} engines`);
      console.log(`   (use --save to export all search links)`);
    }
    
    console.log("");
  }
  
  if(results.phone){
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
    console.log("\x1b[36m📱 PHONE\x1b[0m");
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
    
    console.log(`Valid: ${results.phone.valid ? '\x1b[32m✓ Yes\x1b[0m' : '\x1b[31m✗ No\x1b[0m'}`);
    
    if(results.phone.valid){
      console.log(`\n📍 Info:`);
      console.log(`   Country: ${results.phone.country} (+${results.phone.countryCallingCode})`);
      console.log(`   Type: ${results.phone.typeInfo.type}`);
      console.log(`   Timezone: ${results.phone.timezone}`);
      
      console.log(`\n📞 Formats:`);
      console.log(`   International: ${results.phone.international}`);
      console.log(`   National: ${results.phone.national}`);
      console.log(`   E.164: ${results.phone.e164}`);
      console.log(`   RFC3966: ${results.phone.rfc3966}`);
      
      if(results.phone.carrier){
        console.log(`\n📡 Carrier: ${results.phone.carrier.name}`);
        if(results.phone.carrier.type) console.log(`   Type: ${results.phone.carrier.type}`);
      }
      
      if(results.phone.location){
        console.log(`\n🌍 Location: ${results.phone.location.country}`);
        if(results.phone.location.capital) console.log(`   Capital: ${results.phone.location.capital}`);
        if(results.phone.location.lat) console.log(`   Coords: ${results.phone.location.lat}, ${results.phone.location.lon}`);
      }
      
      if(results.phone.social){
        console.log(`\n💬 Social:`);
        console.log(`   WhatsApp: ${results.phone.social.whatsapp}`);
        console.log(`   Telegram: ${results.phone.social.telegram}`);
        console.log(`   Signal: ${results.phone.social.signal}`);
      }
      
      if(results.phone.autoSearch){
        console.log(`\n🔎 Auto Search (${Object.keys(results.phone.autoSearch).length - 1} sources):`);
        
        if(results.phone.autoSearch.googleResultsFound === true) {
          console.log(`   Google: \x1b[32m✓ Results found!\x1b[0m`);
        } else if(results.phone.autoSearch.googleResultsFound === false) {
          console.log(`   Google: \x1b[33m○ No results\x1b[0m`);
        }
        
        console.log(`\n   📱 Social Media:`);
        console.log(`      Facebook: ${results.phone.autoSearch.facebook}`);
        console.log(`      Instagram: ${results.phone.autoSearch.instagram}`);
        console.log(`      LinkedIn: ${results.phone.autoSearch.linkedin}`);
        
        console.log(`\n   🔍 Search Engines:`);
        console.log(`      Google: ${results.phone.autoSearch.google}`);
        console.log(`      Bing: ${results.phone.autoSearch.bing}`);
        
        console.log(`\n   🇮🇹 Italy Specific:`);
        console.log(`      Pagine Bianche: ${results.phone.autoSearch.paginebianche}`);
        console.log(`      Pagine Gialle: ${results.phone.autoSearch.paginegialle}`);
        
        console.log(`\n   🚫 Spam Check:`);
        console.log(`      Truecaller: ${results.phone.autoSearch.truecaller}`);
        console.log(`      Tellows: ${results.phone.autoSearch.tellows}`);
        
        console.log(`\n   (use --save to see all ${Object.keys(results.phone.autoSearch).length - 1} search links)`);
      }
    }
    
    console.log("");
  }
  
  if(results.ipInfo){
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
    console.log("\x1b[36m🌍 IP INTELLIGENCE\x1b[0m");
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
    
    console.log(`IP: ${results.ipInfo.ip}`);
    console.log(`Location: ${results.ipInfo.city}, ${results.ipInfo.region}, ${results.ipInfo.country}`);
    console.log(`Coordinates: ${results.ipInfo.loc}`);
    console.log(`ISP: ${results.ipInfo.org}`);
    console.log(`ASN: ${results.ipInfo.asn}`);
    console.log(`Timezone: ${results.ipInfo.timezone}`);
    
    if(results.ipInfo.reverseDNS){
      console.log(`Reverse DNS: ${results.ipInfo.reverseDNS.join(', ')}`);
    }
    
    if(results.ipInfo.blacklistCheck){
      console.log(`Blacklist: ${results.ipInfo.blacklistCheck.listed ? '\x1b[31mLISTED on '+results.ipInfo.blacklistCheck.lists.join(', ')+'\x1b[0m' : '\x1b[32mCLEAN\x1b[0m'}`);
    }
    
    console.log(`\n🔗 Additional Tools:`);
    console.log(`   Shodan: ${results.ipInfo.shodan}`);
    console.log(`   AbuseIPDB: ${results.ipInfo.abuseipdb}`);
    console.log(`   (use --save to see all links)`);
    
    console.log("");
  }
}

// ============================================
// MAIN
// ============================================

async function main(){
  const args = process.argv.slice(2);
  let domain, username, email, phone;
  
  for(let i=0;i<args.length;i++){
    if(args[i] === "--domain") domain = args[i+1];
    if(args[i] === "--username") username = args[i+1];
    if(args[i] === "--email") email = args[i+1];
    if(args[i] === "--phone") phone = args[i+1];
    if(args[i] === "--save") CONFIG.SAVE_RESULTS = true;
  }
  
  if(!domain && !username && !email && !phone && args.length > 0 && !args[0].startsWith('--')){
    domain = args[0];
  }
  
  if(!domain && !username && !email && !phone){
    console.log("\x1b[31m███╗   ██╗██╗██╗  ██╗ █████╗\n████╗  ██║██║██║ ██╔╝██╔══██╗\n██╔██╗ ██║██║█████╔╝ ███████║\n██║╚██╗██║██║██╔═██╗ ██╔══██║\n██║ ╚████║██║██║  ██╗██║  ██║\n╚═╝  ╚═══╝╚═╝╚═╝  ╚═╝╚═╝  ╚═╝\x1b[0m\n");
    console.log("\x1b[35m🥝 NIKA OSINT ULTRA v3.0 + PHONE AUTO SEARCH by kiwi & 777\x1b[0m\n");
    console.log("Usage: osint-ultra-max [OPTIONS]\n");
    console.log("Options:");
    console.log("  --domain <domain>      Domain intelligence + subdomains");
    console.log("  --username <username>  Social media footprint (25+ platforms)");
    console.log("  --email <email>        Email analysis + breach check");
    console.log("  --phone <phone>        Phone lookup + AUTO SEARCH (45+ sources)");
    console.log("  --save                 Save complete results to files\n");
    console.log("Examples:");
    console.log("  ./osint-ultra-max.js --domain example.com --save");
    console.log("  ./osint-ultra-max.js --email test@example.com");
    console.log("  ./osint-ultra-max.js --phone +393331234567 --save\n");
    console.log("NEW Phone Features:");
    console.log("  ✓ Auto search across 45+ sources");
    console.log("  ✓ Social media (Facebook, Instagram, LinkedIn, Twitter, TikTok)");
    console.log("  ✓ Search engines (Google, Bing, DuckDuckGo, Yandex)");
    console.log("  ✓ Italy directories (Pagine Bianche, Pagine Gialle, Tuttocittà)");
    console.log("  ✓ Spam check (Truecaller, Tellows, ShouldIAnswer, etc.)");
    console.log("  ✓ People search (Pipl, Spokeo, WhitePages, 411)");
    console.log("  ✓ Breach databases (DeHashed, LeakCheck, Snusbase)");
    console.log("  ✓ OSINT databases (IntelX)\n");
    console.log("API Keys (optional):");
    console.log("  export SHODAN_API_KEY='your_key'");
    console.log("  export VIRUSTOTAL_API_KEY='your_key'\n");
    process.exit(0);
  }
  
  console.log("\x1b[31m███╗   ██╗██╗██╗  ██╗ █████╗\n████╗  ██║██║██║ ██╔╝██╔══██╗\n██╔██╗ ██║██║█████╔╝ ███████║\n██║╚██╗██║██║██╔═██╗ ██╔══██║\n██║ ╚████║██║██║  ██╗██║  ██║\n╚═╝  ╚═══╝╚═╝╚═╝  ╚═╝╚═╝  ╚═╝\x1b[0m\n");
  console.log("\x1b[35m🥝 NIKA OSINT ULTRA v3.0 - Scan Started\x1b[0m\n");
  
  let results = {};
  
  if(domain){
    console.log("🌐 [*] Domain Intelligence...");
    results.domain = await runDomain(domain);
    console.log("🔍 [*] Subdomain Enumeration...");
    results.subdomains = await runSubdomains(domain);
    if(results.domain.A && results.domain.A[0]){
      console.log("🌍 [*] IP Intelligence...");
      results.ipInfo = await runIPInfo(results.domain.A[0]);
    }
  }
  
  if(username){
    console.log("👤 [*] Username OSINT...");
    results.username = await runUsername(username);
  }
  
  if(email){
    console.log("📧 [*] Email Analysis...");
    results.email = await runEmail(email);
  }
  
  if(phone){
    console.log("📱 [*] Phone Lookup + Auto Search...");
    results.phone = await runPhone(phone);
  }
  
  results.risk = calculateRisk(results);
  displayResults(results);
  
  if(CONFIG.SAVE_RESULTS){
    const target = domain || username || email || phone;
    await saveResults(results, target);
  }
  
  console.log("\x1b[31m███╗   ██╗██╗██╗  ██╗ █████╗\n████╗  ██║██║██║ ██╔╝██╔══██╗\n██╔██╗ ██║██║█████╔╝ ███████║\n██║╚██╗██║██║██╔═██╗ ██╔══██║\n██║ ╚████║██║██║  ██╗██║  ██║\n╚═╝  ╚═══╝╚═╝╚═╝  ╚═╝╚═╝  ╚═╝\x1b[0m\n");
  console.log("\x1b[35m🥝 NIKA OSINT ULTRA v3.0 + PHONE AUTO SEARCH - Complete\x1b[0m");
  console.log("\x1b[35m       by kiwi & 777\x1b[0m\n");
}

main();
