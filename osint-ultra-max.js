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
  try{ data.whois = await whois(domain); }catch{}
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

function generateReport(data){
  fs.writeFileSync("report.json",JSON.stringify(data,null,2));
  const html = `<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>NIKA OSINT Report</title>
<style>body{background:#0d1117;color:#58a6ff;font-family:monospace;padding:20px}
h1{color:#7ee787;text-align:center}h2{color:#58a6ff;border-bottom:2px solid #58a6ff}
.section{background:#161b22;margin:20px 0;padding:20px;border-radius:6px}
.risk-LOW{background:#238636;color:#fff;padding:10px;border-radius:6px;display:inline-block}
.risk-MEDIUM{background:#d29922;color:#fff;padding:10px;border-radius:6px;display:inline-block}
.risk-HIGH{background:#da3633;color:#fff;padding:10px;border-radius:6px;display:inline-block}
.risk-CRITICAL{background:#8b0000;color:#fff;padding:10px;border-radius:6px;display:inline-block}
table{width:100%;border-collapse:collapse}td,th{border:1px solid #30363d;padding:10px}
th{background:#21262d;color:#7ee787}.good{color:#7ee787}.bad{color:#f85149}
.footer{text-align:center;margin-top:30px;color:#7ee787;font-size:1.2em}</style></head><body>
<h1>🔍 NIKA OSINT Report</h1>
<div class="section" style="text-align:center">
<h2>Risk Assessment</h2>
<div class="risk-${data.risk.level}">${data.risk.level} RISK</div>
<p>Risk Score: <strong>${data.risk.score}/100</strong></p></div>
${data.domain ? `<div class="section"><h2>🌐 Domain</h2><table>
<tr><td>IP</td><td>${data.domain.A ? data.domain.A.join(', ') : 'N/A'}</td></tr>
<tr><td>MX</td><td>${data.domain.MX ? data.domain.MX.map(m=>m.exchange).join(', ') : 'N/A'}</td></tr>
<tr><td>SPF</td><td class="${data.domain.spf.valid?'good':'bad'}">${data.domain.spf.valid?'✓':'✗'}</td></tr>
<tr><td>DMARC</td><td class="${data.domain.dmarc.valid?'good':'bad'}">${data.domain.dmarc.valid?'✓':'✗'}</td></tr>
<tr><td>DNSSEC</td><td class="${data.domain.dnssec?'good':'bad'}">${data.domain.dnssec?'✓':'✗'}</td></tr>
<tr><td>HSTS</td><td class="${data.domain.securityHeaders.hsts?'good':'bad'}">${data.domain.securityHeaders.hsts?'✓':'✗'}</td></tr>
</table></div>` : ''}
${data.subdomains && data.subdomains.length > 0 ? `<div class="section"><h2>🔍 Subdomains (${data.subdomains.length})</h2><ul>
${data.subdomains.slice(0,20).map(s=>`<li>${s.subdomain}</li>`).join('')}</ul></div>` : ''}
${data.email ? `<div class="section"><h2>📧 Email</h2><table>
<tr><td>Valid</td><td class="${data.email.valid?'good':'bad'}">${data.email.valid?'✓':'✗'}</td></tr>
<tr><td>MX Records</td><td class="${data.email.mx?.length>0?'good':'bad'}">${data.email.mx?.length>0?'✓':'✗'}</td></tr>
</table></div>` : ''}
${data.username && data.username.length > 0 ? `<div class="section"><h2>👤 Username (${data.username.length})</h2><ul>
${data.username.map(u=>`<li><a href="${u.url}" style="color:#58a6ff">${u.platform.replace('https://','').split('/')[0]}</a></li>`).join('')}
</ul></div>` : ''}
${data.phone ? `<div class="section"><h2>📱 Phone</h2><table>
<tr><td>Valid</td><td class="${data.phone.valid?'good':'bad'}">${data.phone.valid?'✓':'✗'}</td></tr>
${data.phone.country ? `<tr><td>Country</td><td>${data.phone.country}</td></tr>` : ''}
${data.phone.type ? `<tr><td>Type</td><td>${data.phone.type}</td></tr>` : ''}
</table></div>` : ''}
${data.ipInfo ? `<div class="section"><h2>🌍 IP Info</h2><table>
<tr><td>Location</td><td>${data.ipInfo.city}, ${data.ipInfo.country}</td></tr>
<tr><td>ISP</td><td>${data.ipInfo.org || 'Unknown'}</td></tr>
</table></div>` : ''}
<div class="footer">
███╗   ██╗██╗██╗  ██╗ █████╗<br>
████╗  ██║██║██║ ██╔╝██╔══██╗<br>
██╔██╗ ██║██║█████╔╝ ███████║<br>
██║╚██╗██║██║██╔═██╗ ██╔══██║<br>
██║ ╚████║██║██║  ██╗██║  ██║<br>
╚═╝  ╚═══╝╚═╝╚═╝  ╚═╝╚═╝  ╚═╝<br>
🥝 by kiwi & 777
</div>
</body></html>`;
  fs.writeFileSync("report.html",html);
}

function displayResults(results){
  console.log("\n╔════════════════════════════════════════════════════════╗");
  console.log("║                  RISULTATI SCAN                        ║");
  console.log("╚════════════════════════════════════════════════════════╝\n");
  const riskColor = {'LOW':'\x1b[32m','MEDIUM':'\x1b[33m','HIGH':'\x1b[31m','CRITICAL':'\x1b[35m'};
  const color = riskColor[results.risk.level] || '\x1b[0m';
  console.log(`🎯 RISK: ${color}${results.risk.level}\x1b[0m (${results.risk.score}/100)\n`);
  if(results.domain){
    console.log("\x1b[36m🌐 DOMAIN:\x1b[0m");
    console.log(`   IP: ${results.domain.A ? results.domain.A.join(', ') : 'N/A'}`);
    console.log(`   MX: ${results.domain.MX ? results.domain.MX.map(m=>m.exchange).join(', ') : 'N/A'}`);
    console.log(`   SPF: ${results.domain.spf.valid ? '\x1b[32m✓\x1b[0m' : '\x1b[31m✗\x1b[0m'}`);
    console.log(`   DMARC: ${results.domain.dmarc.valid ? '\x1b[32m✓\x1b[0m' : '\x1b[31m✗\x1b[0m'}`);
    console.log(`   DNSSEC: ${results.domain.dnssec ? '\x1b[32m✓\x1b[0m' : '\x1b[31m✗\x1b[0m'}`);
    console.log(`   HSTS: ${results.domain.securityHeaders.hsts ? '\x1b[32m✓\x1b[0m' : '\x1b[31m✗\x1b[0m'}`);
    if(results.domain.tls) console.log(`   TLS: ${results.domain.tls.daysRemaining} days`);
    console.log("");
  }
  if(results.subdomains && results.subdomains.length > 0){
    console.log(`\x1b[36m🔍 SUBDOMAINS (${results.subdomains.length}):\x1b[0m`);
    results.subdomains.slice(0, 10).forEach(s => console.log(`   \x1b[32m✓\x1b[0m ${s.subdomain}`));
    if(results.subdomains.length > 10) console.log(`   \x1b[33m... +${results.subdomains.length - 10} more\x1b[0m`);
    console.log("");
  }
  if(results.email){
    console.log("\x1b[36m📧 EMAIL:\x1b[0m");
    console.log(`   Valid: ${results.email.valid ? '\x1b[32m✓\x1b[0m' : '\x1b[31m✗\x1b[0m'}`);
    console.log(`   MX: ${results.email.mx?.length > 0 ? '\x1b[32m✓\x1b[0m' : '\x1b[31m✗\x1b[0m'}`);
    console.log("");
  }
  if(results.username && results.username.length > 0){
    console.log(`\x1b[36m👤 USERNAME (${results.username.length}):\x1b[0m`);
    results.username.forEach(u => console.log(`   \x1b[32m✓\x1b[0m ${u.platform.replace('https://','').split('/')[0]}`));
    console.log("");
  }
  if(results.phone){
    console.log("\x1b[36m📱 PHONE:\x1b[0m");
    console.log(`   Valid: ${results.phone.valid ? '\x1b[32m✓\x1b[0m' : '\x1b[31m✗\x1b[0m'}`);
    if(results.phone.country) console.log(`   Country: ${results.phone.country}`);
    if(results.phone.type) console.log(`   Type: ${results.phone.type}`);
    console.log("");
  }
  if(results.ipInfo){
    console.log("\x1b[36m🌍 IP:\x1b[0m");
    console.log(`   ${results.ipInfo.city}, ${results.ipInfo.country}`);
    console.log(`   ${results.ipInfo.org || 'Unknown'}`);
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
  console.log("📊 [*] Generating reports...");
  generateReport(results);
  console.log("\n✓ report.json\n✓ report.html\n");
  console.log("\x1b[31m");
  console.log("███╗   ██╗██╗██╗  ██╗ █████╗ ");
  console.log("████╗  ██║██║██║ ██╔╝██╔══██╗");
  console.log("██╔██╗ ██║██║█████╔╝ ███████║");
  console.log("██║╚██╗██║██║██╔═██╗ ██╔══██║");
  console.log("██║ ╚████║██║██║  ██╗██║  ██║");
  console.log("╚═╝  ╚═══╝╚═╝╚═╝  ╚═╝╚═╝  ╚═╝");
  console.log("\x1b[0m");
  console.log("\x1b[35m    🥝 by kiwi & 777\x1b[0m\n");
}

main();
