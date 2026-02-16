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

function sleep(ms){ return new Promise(r=>setTimeout(r,ms)); }

async function runDomain(domain){
  let data = {};
  let risk = 0;
  try{ data.A = await dns.resolve4(domain); }catch{}
  try{ data.AAAA = await dns.resolve6(domain); }catch{}
  try{ data.MX = await dns.resolveMx(domain); }catch{}
  try{ data.NS = await dns.resolveNs(domain); }catch{}
  try{ data.TXT = await dns.resolveTxt(domain); }catch{}
  
  try{ 
    data.whois = await whois(domain);
    if(!data.whois.registrant && typeof data.whois === 'object') {
      data.whois = parseWhoisRaw(data.whois);
    }
  }catch{
    console.log('\x1b[33m[!] WHOIS data unavailable or privacy protected\x1b[0m');
    data.whois = null;
  }

  data.spf = analyzeSPF(data.TXT);
  data.dmarc = await analyzeDMARC(domain);
  if(!data.spf.valid) risk += 15;
  if(!data.dmarc.valid) risk += 15;
  data.headers = await getHeaders(domain);
  data.securityHeaders = analyzeHeaders(data.headers);
  if(!data.securityHeaders.hsts) risk += 10;
  if(!data.securityHeaders.csp) risk += 10;
  if(!data.securityHeaders.xframe) risk += 5;
  if(!data.securityHeaders.xcontent) risk += 5;
  if(!data.securityHeaders.xss) risk += 5;
  if(!data.securityHeaders.referrer) risk += 5;
  if(!data.securityHeaders.permissions) risk += 5;
  data.tls = await getTLSInfo(domain);
  data.dnssec = await checkDNSSEC(domain);
  if(!data.dnssec) risk += 10;
  if(data.tls && data.tls.daysRemaining < 30) risk += 15;
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
  
  const nameMatch = rawText.match(/Registrant Name:\s*(.+)/i);
  if(nameMatch) parsed.registrant.name = nameMatch[1].trim();
  
  const orgMatch = rawText.match(/Registrant Organization:\s*(.+)/i);
  if(orgMatch) parsed.registrant.organization = orgMatch[1].trim();
  
  const emailMatch = rawText.match(/Registrant Email:\s*(.+)/i);
  if(emailMatch) parsed.registrant.email = emailMatch[1].trim();
  
  const streetMatch = rawText.match(/Registrant Street:\s*(.+)/i);
  if(streetMatch) parsed.registrant.street = streetMatch[1].trim();
  
  const cityMatch = rawText.match(/Registrant City:\s*(.+)/i);
  if(cityMatch) parsed.registrant.city = cityMatch[1].trim();
  
  const stateMatch = rawText.match(/Registrant State\/Province:\s*(.+)/i);
  if(stateMatch) parsed.registrant.state = stateMatch[1].trim();
  
  const postalMatch = rawText.match(/Registrant Postal Code:\s*(.+)/i);
  if(postalMatch) parsed.registrant.postalCode = postalMatch[1].trim();
  
  const countryMatch = rawText.match(/Registrant Country:\s*(.+)/i);
  if(countryMatch) parsed.registrant.country = countryMatch[1].trim();
  
  const phoneMatch = rawText.match(/Registrant Phone:\s*(.+)/i);
  if(phoneMatch) parsed.registrant.phone = phoneMatch[1].trim();
  
  const createdMatch = rawText.match(/Creation Date:\s*(.+)/i);
  if(createdMatch) parsed.creationDate = createdMatch[1].trim();
  
  const updatedMatch = rawText.match(/Updated Date:\s*(.+)/i);
  if(updatedMatch) parsed.updatedDate = updatedMatch[1].trim();
  
  const expiresMatch = rawText.match(/Registry Expiry Date:\s*(.+)/i);
  if(expiresMatch) parsed.expirationDate = expiresMatch[1].trim();
  
  const registrarMatch = rawText.match(/Registrar:\s*(.+)/i);
  if(registrarMatch) parsed.registrar.name = registrarMatch[1].trim();
  
  return parsed;
}

function getHeaders(domain){
  return new Promise(resolve=>{
    const req = https.request({host:domain,method:'HEAD'},res=>{
      resolve(res.headers);
    });
    req.on('error',()=>resolve({}));
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
    expectCT: !!headers['expect-ct']
  };
}

function analyzeSPF(txtRecords){
  if(!txtRecords) return {valid:false};
  const flat = txtRecords.flat().join(" ");
  const spf = flat.match(/v=spf1[^"]+/);
  if(!spf) return {valid:false};
  const strict = spf[0].includes("-all");
  return {valid:true,strict};
}

async function analyzeDMARC(domain){
  try{
    const record = await dns.resolveTxt(`_dmarc.${domain}`);
    const flat = record.flat().join(" ");
    const policyMatch = flat.match(/p=([^;]+)/);
    return {valid:true, policy: policyMatch ? policyMatch[1] : "unknown"};
  }catch{
    return {valid:false};
  }
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
    const socket = tls.connect(443, domain, {servername:domain}, ()=>{
      const cert = socket.getPeerCertificate();
      const validTo = new Date(cert.valid_to);
      const daysRemaining = Math.floor((validTo - new Date())/86400000);
      resolve({
        issuer: cert.issuer,
        subject: cert.subject,
        valid_from: cert.valid_from,
        valid_to: cert.valid_to,
        daysRemaining
      });
      socket.end();
    });
    socket.on('error',()=>resolve(null));
  });
}

async function runSubdomains(domain){
  let results = [];
  try{
    const wordlistPath = './wordlists/subdomains.txt';
    if(fs.existsSync(wordlistPath)){
      const wordlist = fs.readFileSync(wordlistPath,'utf-8').split(/\r?\n/).filter(Boolean);
      const tasks = wordlist.map(sub =>
        limit(async () => {
          const fqdn = `${sub}.${domain}`;
          try{
            const ips = await dns.resolve4(fqdn);
            return {subdomain:fqdn,found:true,ips};
          }catch{
            return null;
          }
        })
      );
      const bruteResults = await Promise.all(tasks);
      results = bruteResults.filter(Boolean);
    }
  }catch{}
  const crt = await crtSearch(domain);
  results = results.concat(crt);
  return results;
}

async function crtSearch(domain){
  try{
    const url = `https://crt.sh/?q=%25.${domain}&output=json`;
    const res = await axios.get(url,{timeout:10000});
    const unique = [...new Set(res.data.map(x=>x.name_value))];
    return unique.map(s=>({subdomain:s,source:"crt.sh"}));
  }catch{
    return [];
  }
}

async function runEmail(email){
  let data = {};
  let risk = 0;
  data.valid = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
  if(!data.valid) risk += 20;
  try{
    const domain = email.split("@")[1];
    data.mx = await dns.resolveMx(domain).catch(()=>[]);
    if(data.mx.length === 0) risk += 10;
  }catch{}
  data.gravatar = `https://www.gravatar.com/avatar/${crypto.createHash('md5').update(email.trim().toLowerCase()).digest('hex')}`;
  data.riskScore = risk;
  return data;
}

const platforms = [
  "https://github.com/",
  "https://reddit.com/user/",
  "https://medium.com/@",
  "https://pinterest.com/",
  "https://instagram.com/",
  "https://twitter.com/",
  "https://dev.to/"
];

async function runUsername(username){
  const tasks = platforms.map(base =>
    limit(async () => {
      const url = base + username;
      try{
        const r = await axios.get(url,{validateStatus:false,timeout:8000});
        if(r.status === 200){
          return {platform:base,found:true,url};
        }
      }catch{}
      return null;
    })
  );
  const results = await Promise.all(tasks);
  return results.filter(Boolean);
}

function runPhone(number){
  try{
    const parsed = phoneUtil.parsePhoneNumber(number);
    return {
      valid: parsed.isValid(),
      country: parsed.country,
      type: parsed.getType(),
      international: parsed.formatInternational(),
      national: parsed.formatNational()
    };
  }catch{
    return {valid:false};
  }
}

async function runIPInfo(ip){
  try{
    const res = await axios.get(`https://ipinfo.io/${ip}/json`);
    return res.data;
  }catch{
    return null;
  }
}

function calculateRisk(results){
  let total = 0;
  if(results.domain?.riskScore) total += results.domain.riskScore;
  if(results.email?.riskScore) total += results.email.riskScore;
  if(results.subdomains?.length > 5) total += 10;
  if(total < 20) return {score:total,level:"LOW"};
  if(total < 50) return {score:total,level:"MEDIUM"};
  if(total < 80) return {score:total,level:"HIGH"};
  return {score:total,level:"CRITICAL"};
}

function displayResults(results){
  console.log("\n╔════════════════════════════════════════════════════════╗");
  console.log("║                  RISULTATI COMPLETI                    ║");
  console.log("╚════════════════════════════════════════════════════════╝\n");
  
  const riskColor = {'LOW':'\x1b[32m','MEDIUM':'\x1b[33m','HIGH':'\x1b[31m','CRITICAL':'\x1b[35m'};
  const color = riskColor[results.risk.level] || '\x1b[0m';
  console.log(`🎯 RISK: ${color}${results.risk.level}\x1b[0m (${results.risk.score}/100)\n`);
  
  if(results.domain){
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
    console.log("\x1b[36m🌐 DOMAIN INTELLIGENCE\x1b[0m");
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
    
    console.log("📍 DNS Records:");
    console.log(`   A Records: ${results.domain.A ? results.domain.A.join(', ') : 'N/A'}`);
    console.log(`   AAAA Records: ${results.domain.AAAA ? results.domain.AAAA.join(', ') : 'N/A'}`);
    console.log(`   MX Records: ${results.domain.MX ? results.domain.MX.map(m=>m.exchange + ' (priority: ' + m.priority + ')').join(', ') : 'N/A'}`);
    console.log(`   NS Records: ${results.domain.NS ? results.domain.NS.join(', ') : 'N/A'}`);
    
    if(results.domain.whois) {
      console.log("\n👤 WHOIS Information:");
      
      if(results.domain.whois.registrant && Object.keys(results.domain.whois.registrant).length > 0) {
        console.log("\n   📋 Registrant (Domain Owner):");
        if(results.domain.whois.registrant.name) 
          console.log(`      Name: ${results.domain.whois.registrant.name}`);
        if(results.domain.whois.registrant.organization) 
          console.log(`      Organization: ${results.domain.whois.registrant.organization}`);
        if(results.domain.whois.registrant.email) 
          console.log(`      Email: ${results.domain.whois.registrant.email}`);
        if(results.domain.whois.registrant.phone) 
          console.log(`      Phone: ${results.domain.whois.registrant.phone}`);
        if(results.domain.whois.registrant.street) 
          console.log(`      Street: ${results.domain.whois.registrant.street}`);
        if(results.domain.whois.registrant.city) 
          console.log(`      City: ${results.domain.whois.registrant.city}`);
        if(results.domain.whois.registrant.state) 
          console.log(`      State/Province: ${results.domain.whois.registrant.state}`);
        if(results.domain.whois.registrant.postalCode) 
          console.log(`      Postal Code: ${results.domain.whois.registrant.postalCode}`);
        if(results.domain.whois.registrant.country) 
          console.log(`      Country: ${results.domain.whois.registrant.country}`);
      }
      
      if(results.domain.whois.admin && Object.keys(results.domain.whois.admin).length > 0) {
        console.log("\n   🔧 Admin Contact:");
        if(results.domain.whois.admin.name) 
          console.log(`      Name: ${results.domain.whois.admin.name}`);
        if(results.domain.whois.admin.organization) 
          console.log(`      Organization: ${results.domain.whois.admin.organization}`);
        if(results.domain.whois.admin.email) 
          console.log(`      Email: ${results.domain.whois.admin.email}`);
        if(results.domain.whois.admin.phone) 
          console.log(`      Phone: ${results.domain.whois.admin.phone}`);
      }
      
      if(results.domain.whois.tech && Object.keys(results.domain.whois.tech).length > 0) {
        console.log("\n   ⚙️  Tech Contact:");
        if(results.domain.whois.tech.name) 
          console.log(`      Name: ${results.domain.whois.tech.name}`);
        if(results.domain.whois.tech.organization) 
          console.log(`      Organization: ${results.domain.whois.tech.organization}`);
        if(results.domain.whois.tech.email) 
          console.log(`      Email: ${results.domain.whois.tech.email}`);
      }
      
      console.log("\n   📅 Domain Dates:");
      if(results.domain.whois.creationDate) 
        console.log(`      Created: ${results.domain.whois.creationDate}`);
      if(results.domain.whois.updatedDate) 
        console.log(`      Updated: ${results.domain.whois.updatedDate}`);
      if(results.domain.whois.expirationDate) 
        console.log(`      Expires: ${results.domain.whois.expirationDate}`);
      
      if(results.domain.whois.registrar && Object.keys(results.domain.whois.registrar).length > 0) {
        console.log("\n   🏢 Registrar:");
        if(results.domain.whois.registrar.name) 
          console.log(`      Name: ${results.domain.whois.registrar.name}`);
        if(results.domain.whois.registrar.url) 
          console.log(`      URL: ${results.domain.whois.registrar.url}`);
      }
      
      if(results.domain.whois.nameServers && results.domain.whois.nameServers.length > 0) {
        console.log("\n   🖥️  Name Servers:");
        results.domain.whois.nameServers.forEach((ns, i) => {
          console.log(`      ${i + 1}. ${ns}`);
        });
      }
    }
    
    console.log("\n🔒 Email Security:");
    console.log(`   SPF: ${results.domain.spf.valid ? '\x1b[32m✓ Valid\x1b[0m' : '\x1b[31m✗ Missing\x1b[0m'}`);
    if(results.domain.spf.valid) {
      console.log(`        Policy: ${results.domain.spf.strict ? 'Strict (-all)' : 'Soft (~all)'}`);
    }
    console.log(`   DMARC: ${results.domain.dmarc.valid ? '\x1b[32m✓ Configured\x1b[0m' : '\x1b[31m✗ Not Configured\x1b[0m'}`);
    if(results.domain.dmarc.valid) {
      console.log(`          Policy: ${results.domain.dmarc.policy}`);
    }
    console.log(`   DNSSEC: ${results.domain.dnssec ? '\x1b[32m✓ Enabled\x1b[0m' : '\x1b[31m✗ Disabled\x1b[0m'}`);
    
    console.log("\n🛡️  Security Headers:");
    console.log(`   HSTS: ${results.domain.securityHeaders.hsts ? '\x1b[32m✓ Present\x1b[0m' : '\x1b[31m✗ Missing\x1b[0m'}`);
    console.log(`   Content-Security-Policy: ${results.domain.securityHeaders.csp ? '\x1b[32m✓ Present\x1b[0m' : '\x1b[31m✗ Missing\x1b[0m'}`);
    console.log(`   X-Frame-Options: ${results.domain.securityHeaders.xframe ? '\x1b[32m✓ Present\x1b[0m' : '\x1b[31m✗ Missing\x1b[0m'}`);
    console.log(`   X-Content-Type-Options: ${results.domain.securityHeaders.xcontent ? '\x1b[32m✓ Present\x1b[0m' : '\x1b[31m✗ Missing\x1b[0m'}`);
    console.log(`   X-XSS-Protection: ${results.domain.securityHeaders.xss ? '\x1b[32m✓ Present\x1b[0m' : '\x1b[31m✗ Missing\x1b[0m'}`);
    console.log(`   Referrer-Policy: ${results.domain.securityHeaders.referrer ? '\x1b[32m✓ Present\x1b[0m' : '\x1b[31m✗ Missing\x1b[0m'}`);
    console.log(`   Permissions-Policy: ${results.domain.securityHeaders.permissions ? '\x1b[32m✓ Present\x1b[0m' : '\x1b[31m✗ Missing\x1b[0m'}`);
    
    if(results.domain.tls) {
      console.log("\n🔐 TLS Certificate:");
      console.log(`   Issuer: ${results.domain.tls.issuer.O || 'Unknown'}`);
      console.log(`   Valid From: ${results.domain.tls.valid_from}`);
      console.log(`   Valid Until: ${results.domain.tls.valid_to}`);
      const tlsColor = results.domain.tls.daysRemaining < 30 ? '\x1b[33m' : '\x1b[32m';
      console.log(`   Days Remaining: ${tlsColor}${results.domain.tls.daysRemaining} days\x1b[0m`);
    }
    console.log("");
  }
  
  if(results.subdomains && results.subdomains.length > 0){
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
    console.log(`\x1b[36m🔍 SUBDOMAINS FOUND (${results.subdomains.length} total)\x1b[0m`);
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
    
    results.subdomains.forEach((s, index) => {
      console.log(`${index + 1}. \x1b[32m${s.subdomain}\x1b[0m`);
      if(s.ips && s.ips.length > 0) {
        console.log(`   IP: ${s.ips.join(', ')}`);
      }
      console.log(`   Source: ${s.source || 'brute-force'}`);
      console.log("");
    });
  }
  
  if(results.email){
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
    console.log("\x1b[36m📧 EMAIL ANALYSIS\x1b[0m");
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
    
    console.log(`Format Valid: ${results.email.valid ? '\x1b[32m✓ Yes\x1b[0m' : '\x1b[31m✗ No\x1b[0m'}`);
    console.log(`MX Records: ${results.email.mx?.length > 0 ? '\x1b[32m✓ Present\x1b[0m' : '\x1b[31m✗ Missing\x1b[0m'}`);
    if(results.email.mx && results.email.mx.length > 0) {
      console.log("\nMX Servers:");
      results.email.mx.forEach((mx, i) => {
        console.log(`   ${i + 1}. ${mx.exchange} (priority: ${mx.priority})`);
      });
    }
    console.log(`\nGravatar: ${results.email.gravatar}`);
    console.log("");
  }
  
  if(results.username && results.username.length > 0){
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
    console.log(`\x1b[36m👤 USERNAME FOOTPRINT (${results.username.length} platforms found)\x1b[0m`);
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
    
    results.username.forEach((u, index) => {
      const platform = u.platform.replace('https://','').split('/')[0];
      console.log(`${index + 1}. \x1b[32m✓ ${platform}\x1b[0m`);
      console.log(`   ${u.url}`);
      console.log("");
    });
  }
  
  if(results.phone){
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
    console.log("\x1b[36m📱 PHONE ANALYSIS\x1b[0m");
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
    
    console.log(`Valid: ${results.phone.valid ? '\x1b[32m✓ Yes\x1b[0m' : '\x1b[31m✗ No\x1b[0m'}`);
    if(results.phone.country) console.log(`Country: ${results.phone.country}`);
    if(results.phone.type) console.log(`Type: ${results.phone.type}`);
    if(results.phone.international) console.log(`International Format: ${results.phone.international}`);
    if(results.phone.national) console.log(`National Format: ${results.phone.national}`);
    console.log("");
  }
  
  if(results.ipInfo){
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
    console.log("\x1b[36m🌍 IP GEOLOCATION\x1b[0m");
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
    
    console.log(`IP Address: ${results.ipInfo.ip}`);
    console.log(`Location: ${results.ipInfo.city}, ${results.ipInfo.region}, ${results.ipInfo.country}`);
    console.log(`ISP: ${results.ipInfo.org || 'Unknown'}`);
    console.log(`Timezone: ${results.ipInfo.timezone || 'Unknown'}`);
    if(results.ipInfo.loc) console.log(`Coordinates: ${results.ipInfo.loc}`);
    console.log("");
  }
}

async function main(){
  const args = process.argv.slice(2);
  let domain, username, email, phone;
  for(let i=0;i<args.length;i++){
    if(args[i] === "--domain") domain = args[i+1];
    if(args[i] === "--username") username = args[i
+1];
    if(args[i] === "--email") email = args[i+1];
    if(args[i] === "--phone") phone = args[i+1];
  }
  if(!domain && !username && !email && !phone && args.length > 0 && !args[0].startsWith('--')){
    domain = args[0];
  }
  if(!domain && !username && !email && !phone){
    console.log("\x1b[31m");
    console.log("███╗   ██╗██╗██╗  ██╗ █████╗ ");
    console.log("████╗  ██║██║██║ ██╔╝██╔══██╗");
    console.log("██╔██╗ ██║██║█████╔╝ ███████║");
    console.log("██║╚██╗██║██║██╔═██╗ ██╔══██║");
    console.log("██║ ╚████║██║██║  ██╗██║  ██║");
    console.log("╚═╝  ╚═══╝╚═╝╚═╝  ╚═╝╚═╝  ╚═╝");
    console.log("\x1b[0m");
    console.log("\x1b[35m         🥝 by kiwi & 777\x1b[0m\n");
    console.log("Usage: osint-ultra-max [OPTIONS]\n");
    console.log("Options:");
    console.log("  --domain <domain>      Domain scan");
    console.log("  --username <username>  Username search");
    console.log("  --email <email>        Email analysis");
    console.log("  --phone <phone>        Phone lookup\n");
    console.log("Examples:");
    console.log("  osint-ultra-max --domain example.com");
    console.log("  osint-ultra-max --email test@example.com\n");
    process.exit(0);
  }
  console.log("\x1b[31m");
  console.log("███╗   ██╗██╗██╗  ██╗ █████╗ ");
  console.log("████╗  ██║██║██║ ██╔╝██╔══██╗");
  console.log("██╔██╗ ██║██║█████╔╝ ███████║");
  console.log("██║╚██╗██║██║██╔═██╗ ██╔══██║");
  console.log("██║ ╚████║██║██║  ██╗██║  ██║");
  console.log("╚═╝  ╚═══╝╚═╝╚═╝  ╚═╝╚═╝  ╚═╝");
  console.log("\x1b[0m");
  console.log("\x1b[35m    🥝 by kiwi & 777 - Scan Started\x1b[0m\n");
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
    console.log("👤 [*] Username search...");
    results.username = await runUsername(username);
  }
  if(email){
    console.log("📧 [*] Email analysis...");
    results.email = await runEmail(email);
  }
  if(phone){
    console.log("📱 [*] Phone analysis...");
    results.phone = runPhone(phone);
  }
  results.risk = calculateRisk(results);
  displayResults(results);
  console.log("\x1b[31m");
  console.log("███╗   ██╗██╗██╗  ██╗ █████╗ ");
  console.log("████╗  ██║██║██║ ██╔╝██╔══██╗");
  console.log("██╔██╗ ██║██║█████╔╝ ███████║");
  console.log("██║╚██╗██║██║██╔═██╗ ██╔══██║");
  console.log("██║ ╚████║██║██║  ██╗██║  ██║");
  console.log("╚═╝  ╚═══╝╚═╝╚═╝  ╚═╝╚═╝  ╚═╝");
  console.log("\x1b[0m");
  console.log("\x1b[35m    🥝 by kiwi & 777 - Scan Complete\x1b[0m\n");
}

main();
