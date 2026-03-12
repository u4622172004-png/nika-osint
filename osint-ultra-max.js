#!/usr/bin/env node

const { exec } = require('child_process');
const { promisify } = require('util');
const execAsync = promisify(exec);
const fs = require('fs');

async function performWhoisLookup(domain) {
  console.log('   [1/6] Performing WHOIS lookup...');
  
  try {
    // Usa whois di sistema
    const { stdout } = await execAsync(`whois ${domain}`, { 
      timeout: 20000,
      maxBuffer: 1024 * 1024 
    });
    
    return parseWhoisRaw(stdout, domain);
  } catch (error) {
    return {
      available: false,
      error: 'WHOIS lookup failed',
      rawData: error.stdout || ''
    };
  }
}

function parseWhoisRaw(raw, domain) {
  const result = {
    available: true,
    domain: domain,
    registrar: extractField(raw, ['Registrar:', 'Registrar Name:', 'Sponsoring Registrar:']),
    registrant: {
      name: extractField(raw, ['Registrant Name:', 'Registrant:', 'Name:']),
      organization: extractField(raw, ['Registrant Organization:', 'Organization:', 'Registrant Org:']),
      street: extractField(raw, ['Registrant Street:', 'Street:', 'Address:']),
      city: extractField(raw, ['Registrant City:', 'City:']),
      state: extractField(raw, ['Registrant State/Province:', 'State:', 'Province:']),
      postalCode: extractField(raw, ['Registrant Postal Code:', 'Postal Code:', 'Zip:']),
      country: extractField(raw, ['Registrant Country:', 'Country:']),
      email: extractField(raw, ['Registrant Email:', 'Email:', 'E-mail:']),
      phone: extractField(raw, ['Registrant Phone:', 'Phone:', 'Tel:']),
      fax: extractField(raw, ['Registrant Fax:', 'Fax:'])
    },
    admin: {
      name: extractField(raw, ['Admin Name:', 'Administrative Contact Name:']),
      organization: extractField(raw, ['Admin Organization:', 'Administrative Contact Organization:']),
      street: extractField(raw, ['Admin Street:', 'Administrative Contact Street:']),
      city: extractField(raw, ['Admin City:', 'Administrative Contact City:']),
      state: extractField(raw, ['Admin State/Province:', 'Administrative Contact State:']),
      postalCode: extractField(raw, ['Admin Postal Code:', 'Administrative Contact Postal Code:']),
      country: extractField(raw, ['Admin Country:', 'Administrative Contact Country:']),
      email: extractField(raw, ['Admin Email:', 'Administrative Contact Email:']),
      phone: extractField(raw, ['Admin Phone:', 'Administrative Contact Phone:']),
      fax: extractField(raw, ['Admin Fax:', 'Administrative Contact Fax:'])
    },
    tech: {
      name: extractField(raw, ['Tech Name:', 'Technical Contact Name:']),
      organization: extractField(raw, ['Tech Organization:', 'Technical Contact Organization:']),
      street: extractField(raw, ['Tech Street:', 'Technical Contact Street:']),
      city: extractField(raw, ['Tech City:', 'Technical Contact City:']),
      state: extractField(raw, ['Tech State/Province:', 'Technical Contact State:']),
      postalCode: extractField(raw, ['Tech Postal Code:', 'Technical Contact Postal Code:']),
      country: extractField(raw, ['Tech Country:', 'Technical Contact Country:']),
      email: extractField(raw, ['Tech Email:', 'Technical Contact Email:']),
      phone: extractField(raw, ['Tech Phone:', 'Technical Contact Phone:']),
      fax: extractField(raw, ['Tech Fax:', 'Technical Contact Fax:'])
    },
    dates: {
      created: extractField(raw, ['Creation Date:', 'Created:', 'Created On:', 'Registration Time:']),
      updated: extractField(raw, ['Updated Date:', 'Updated:', 'Last Updated:', 'Modified:']),
      expires: extractField(raw, ['Expiry Date:', 'Expiration Date:', 'Expires:', 'Expire Date:'])
    },
    nameservers: extractMultiple(raw, ['Name Server:', 'Nameserver:', 'nserver:']),
    status: extractMultiple(raw, ['Domain Status:', 'Status:']),
    dnssec: extractField(raw, ['DNSSEC:', 'DNSSEC Status:'])
  };
  
  return result;
}

function extractField(text, patterns) {
  for (let pattern of patterns) {
    const regex = new RegExp(`${pattern}\\s*(.+)`, 'i');
    const match = text.match(regex);
    if (match && match[1]) {
      return match[1].trim();
    }
  }
  return null;
}

function extractMultiple(text, patterns) {
  const results = [];
  const lines = text.split('\n');
  
  for (let line of lines) {
    for (let pattern of patterns) {
      if (new RegExp(pattern, 'i').test(line)) {
        const value = line.split(/:/)[1];
        if (value) {
          const cleaned = value.trim();
          if (cleaned && !results.includes(cleaned)) {
            results.push(cleaned);
          }
        }
      }
    }
  }
  
  return results;
}

async function getDNSRecords(domain) {
  console.log('   [2/6] Fetching DNS records...');
  
  const records = { A: [], MX: [], NS: [], TXT: [] };
  
  try {
    const { stdout } = await execAsync(`nslookup -type=A ${domain} 8.8.8.8`, { timeout: 5000 });
    const matches = stdout.match(/Address: ([\d.]+)/g);
    if (matches) {
      records.A = matches.map(m => m.replace('Address: ', '')).filter(ip => ip !== '8.8.8.8');
    }
  } catch (e) {}
  
  try {
    const { stdout } = await execAsync(`nslookup -type=MX ${domain} 8.8.8.8`, { timeout: 5000 });
    const matches = stdout.match(/mail exchanger = \d+ (.+)/g);
    if (matches) {
      records.MX = matches.map(m => m.replace(/mail exchanger = \d+ /, '').trim());
    }
  } catch (e) {}
  
  try {
    const { stdout } = await execAsync(`nslookup -type=NS ${domain} 8.8.8.8`, { timeout: 5000 });
    const matches = stdout.match(/nameserver = (.+)/g);
    if (matches) {
      records.NS = matches.map(m => m.replace('nameserver = ', '').trim());
    }
  } catch (e) {}
  
  return records;
}

async function getGeolocation(ip) {
  console.log('   [3/6] Getting geolocation...');
  
  return new Promise((resolve) => {
    const https = require('https');
    https.get(`https://ipapi.co/${ip}/json/`, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          const geo = JSON.parse(data);
          resolve({
            ip: geo.ip || ip,
            city: geo.city || 'Unknown',
            region: geo.region || 'Unknown',
            country: geo.country_name || 'Unknown',
            latitude: geo.latitude || 'N/A',
            longitude: geo.longitude || 'N/A',
            isp: geo.org || 'Unknown',
            asn: geo.asn || 'Unknown'
          });
        } catch (e) {
          resolve({
            ip: ip,
            city: 'Unknown',
            region: 'Unknown',
            country: 'Unknown',
            latitude: 'N/A',
            longitude: 'N/A',
            isp: 'Unknown',
            asn: 'Unknown'
          });
        }
      });
    }).on('error', () => {
      resolve({
        ip: ip,
        error: 'Geolocation failed'
      });
    });
  });
}

async function checkSSL(domain) {
  console.log('   [4/6] Checking SSL certificate...');
  try {
    const { stdout } = await execAsync(`timeout 8 openssl s_client -connect ${domain}:443 -servername ${domain} 2>/dev/null </dev/null | openssl x509 -noout -text 2>/dev/null`, { timeout: 10000 });
    return {
      issuer: extractField(stdout, ['Issuer:']),
      subject: extractField(stdout, ['Subject:']),
      validFrom: extractField(stdout, ['Not Before:']),
      validTo: extractField(stdout, ['Not After :'])
    };
  } catch (e) {
    return { error: 'SSL check failed' };
  }
}

async function checkSubdomains(domain) {
  console.log('   [5/6] Enumerating subdomains...');
  const subs = ['www', 'mail', 'ftp', 'admin', 'blog', 'shop', 'api'];
  const found = [];
  
  for (let sub of subs) {
    try {
      const { stdout } = await execAsync(`nslookup ${sub}.${domain} 8.8.8.8 2>/dev/null`, { timeout: 2000 });
      if (stdout.includes('Address:') && !stdout.includes('NXDOMAIN')) {
        found.push(`${sub}.${domain}`);
      }
    } catch (e) {}
  }
  
  return found;
}

async function getTechStack(domain) {
  console.log('   [6/6] Detecting technology...');
  try {
    const { stdout } = await execAsync(`curl -s -I https://${domain} 2>/dev/null | head -15`, { timeout: 8000 });
    return {
      server: extractField(stdout, ['Server:']),
      framework: extractField(stdout, ['X-Powered-By:'])
    };
  } catch (e) {
    return { error: 'Tech detection failed' };
  }
}

function showBanner() {
  console.log("\x1b[31m");
  console.log("███╗   ██╗██╗██╗  ██╗ █████╗     ██████╗ ███████╗██╗███╗   ██╗████████╗");
  console.log("████╗  ██║██║██║ ██╔╝██╔══██╗   ██╔═══██╗██╔════╝██║████╗  ██║╚══██╔══╝");
  console.log("██╔██╗ ██║██║█████╔╝ ███████║   ██║   ██║███████╗██║██╔██╗ ██║   ██║   ");
  console.log("██║╚██╗██║██║██╔═██╗ ██╔══██║   ██║   ██║╚════██║██║██║╚██╗██║   ██║   ");
  console.log("██║ ╚████║██║██║  ██╗██║  ██║   ╚██████╔╝███████║██║██║ ╚████║   ██║   ");
  console.log("╚═╝  ╚═══╝╚═╝╚═╝  ╚═╝╚═╝  ╚═╝    ╚═════╝ ╚══════╝╚═╝╚═╝  ╚═══╝   ╚═╝   ");
  console.log("\x1b[0m");
  console.log("\x1b[35m🥝 NIKA OSINT - Domain Intelligence\x1b[0m\n");
}

function displayResults(data) {
  console.log("\n╔════════════════════════════════════════════════════════╗");
  console.log("║       🌐 DOMAIN INTELLIGENCE REPORT 🌐                 ║");
  console.log("╚════════════════════════════════════════════════════════╝\n");
  
  console.log(`🎯 Domain: \x1b[36m${data.domain}\x1b[0m\n`);
  
  if (data.whois?.available) {
    console.log("\x1b[36m┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓\x1b[0m");
    console.log("\x1b[36m┃                  WHOIS INFORMATION                   ┃\x1b[0m");
    console.log("\x1b[36m┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛\x1b[0m\n");
    
    if (data.whois.registrar) console.log(`   Registrar:           ${data.whois.registrar}`);
    if (data.whois.dates.created) console.log(`   Created:             ${data.whois.dates.created}`);
    if (data.whois.dates.updated) console.log(`   Updated:             ${data.whois.dates.updated}`);
    if (data.whois.dates.expires) console.log(`   Expires:             ${data.whois.dates.expires}`);
    console.log('');
    
    const r = data.whois.registrant;
    if (r.name || r.organization) {
      console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
      console.log("\x1b[36m👤 REGISTRANT\x1b[0m");
      console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
      
      if (r.name) console.log(`   Name:                ${r.name}`);
      if (r.organization) console.log(`   Organization:        ${r.organization}`);
      if (r.street) console.log(`   Street:              ${r.street}`);
      if (r.city) console.log(`   City:                ${r.city}`);
      if (r.state) console.log(`   State:               ${r.state}`);
      if (r.postalCode) console.log(`   Postal Code:         ${r.postalCode}`);
      if (r.country) console.log(`   Country:             ${r.country}`);
      if (r.email) console.log(`   Email:               ${r.email}`);
      if (r.phone) console.log(`   Phone:               ${r.phone}`);
      console.log('');
    }
    
    const a = data.whois.admin;
    if (a.name || a.organization) {
      console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
      console.log("\x1b[36m👨‍💼 ADMIN CONTACT\x1b[0m");
      console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
      
      if (a.name) console.log(`   Name:                ${a.name}`);
      if (a.organization) console.log(`   Organization:        ${a.organization}`);
      if (a.street) console.log(`   Street:              ${a.street}`);
      if (a.city) console.log(`   City:                ${a.city}`);
      if (a.email) console.log(`   Email:               ${a.email}`);
      if (a.phone) console.log(`   Phone:               ${a.phone}`);
      console.log('');
    }
    
    const t = data.whois.tech;
    if (t.name || t.organization) {
      console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
      console.log("\x1b[36m🔧 TECHNICAL CONTACT\x1b[0m");
      console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
      
      if (t.name) console.log(`   Name:                ${t.name}`);
      if (t.organization) console.log(`   Organization:        ${t.organization}`);
      if (t.street) console.log(`   Street:              ${t.street}`);
      if (t.city) console.log(`   City:                ${t.city}`);
      if (t.email) console.log(`   Email:               ${t.email}`);
      if (t.phone) console.log(`   Phone:               ${t.phone}`);
      console.log('');
    }
    
    if (data.whois.nameservers.length > 0) {
      console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
      console.log("\x1b[36m🖥️  NAME SERVERS\x1b[0m");
      console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
      
      data.whois.nameservers.forEach((ns, i) => console.log(`   ${i + 1}. ${ns}`));
      console.log('');
    }
  }
  
  if (data.dns) {
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
    console.log("\x1b[36m📡 DNS RECORDS\x1b[0m");
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
    
    if (data.dns.A?.length) console.log(`   A Records:           ${data.dns.A.join(', ')}`);
    if (data.dns.MX?.length) console.log(`   MX Records:          ${data.dns.MX.join(', ')}`);
    if (data.dns.NS?.length) console.log(`   NS Records:          ${data.dns.NS.join(', ')}`);
    console.log('');
  }
  
  if (data.geolocation && !data.geolocation.error) {
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
    console.log("\x1b[36m🌍 SERVER LOCATION\x1b[0m");
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
    
    console.log(`   IP:                  ${data.geolocation.ip}`);
    console.log(`   Location:            ${data.geolocation.city}, ${data.geolocation.region}, ${data.geolocation.country}`);
    console.log(`   ISP:                 ${data.geolocation.isp}`);
    console.log('');
  }
  
  if (data.subdomains?.length) {
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
    console.log("\x1b[36m🔗 SUBDOMAINS\x1b[0m");
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
    
    data.subdomains.forEach((s, i) => console.log(`   ${i + 1}. ${s}`));
    console.log('');
  }
}

async function main() {
  const args = process.argv.slice(2);
  
  if (!args.length || args.includes('--help')) {
    showBanner();
    console.log("Usage: node osint-ultra-max.js --domain <domain>\n");
    process.exit(0);
  }
  
  let domain = null;
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--domain') domain = args[i + 1];
  }
  
  if (!domain) {
    console.log("\x1b[31m❌ No domain!\x1b[0m\n");
    process.exit(1);
  }
  
  showBanner();
  console.log(`⏳ Analyzing: ${domain}...\n`);
  
  const data = {
    domain,
    timestamp: new Date().toISOString(),
    whois: await performWhoisLookup(domain),
    dns: await getDNSRecords(domain),
    ssl: await checkSSL(domain),
    subdomains: await checkSubdomains(domain),
    tech: await getTechStack(domain),
    geolocation: null
  };
  
  if (data.dns?.A?.[0]) {
    data.geolocation = await getGeolocation(data.dns.A[0]);
  }
  
  displayResults(data);
  
  console.log("\x1b[31m███╗   ██╗██╗██╗  ██╗ █████╗\x1b[0m");
  console.log("\x1b[35m🥝 Complete - by kiwi & 777\x1b[0m\n");
}

main().catch(console.error);
