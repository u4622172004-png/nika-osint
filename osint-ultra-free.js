#!/usr/bin/env node
const dns = require('dns').promises;
const https = require('https');
const axios = require('axios');
const fs = require('fs');
const whois = require('whois-json');
const phoneUtil = require('libphonenumber-js');
const crypto = require('crypto');

/* ===============================
DOMAIN MODULE
================================ */
async function runDomain(domain){
  let data={};
  try{data.A=await dns.resolve4(domain);}catch{}
  try{data.MX=await dns.resolveMx(domain);}catch{}
  try{data.NS=await dns.resolveNs(domain);}catch{}
  try{data.TXT=await dns.resolveTxt(domain);}catch{}
  try{data.whois=await whois(domain);}catch{}
  data.headers=await getHeaders(domain);
  return data;
}

function getHeaders(domain){
  return new Promise(resolve=>{
    const req=https.request({host:domain,method:'HEAD'},res=>resolve(res.headers));
    req.on('error',()=>resolve({}));
    req.end();
  });
}

/* ===============================
SUBDOMAIN MODULE
================================ */
async function runSubdomains(domain){
  const wordlist=fs.readFileSync('./wordlists/subdomains.txt','utf-8').split(/\r?\n/);
  const results=[];
  for(const sub of wordlist){
    const fqdn=`${sub}.${domain}`;
    try{
      const ips=await dns.resolve4(fqdn);
      results.push({subdomain:fqdn,found:true,ips});
    }catch{
      results.push({subdomain:fqdn,found:false});
    }
  }
  return results;
}

/* ===============================
EMAIL MODULE
================================ */
async function runEmail(email){
  let data={};
  data.valid=/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
  try{
    const domain=email.split("@")[1];
    data.mx=await dns.resolveMx(domain).catch(()=>[]);
  }catch{}
  data.gravatar=`https://www.gravatar.com/avatar/${crypto.createHash('md5').update(email.trim().toLowerCase()).digest('hex')}`;
  return data;
}

/* ===============================
USERNAME MODULE
================================ */
const platforms=[
  "https://github.com/",
  "https://reddit.com/user/",
  "https://medium.com/@",
  "https://pinterest.com/",
  "https://instagram.com/",
  "https://twitter.com/"
];

async function runUsername(username){
  const results=[];
  for(const base of platforms){
    const url=base+username;
    try{
      const r=await axios.get(url,{validateStatus:false});
      results.push({platform:base,found:r.status===200,url});
    }catch{
      results.push({platform:base,found:false});
    }
  }
  return results;
}

/* ===============================
PHONE MODULE
================================ */
function runPhone(number){
  try{
    const parsed=phoneUtil.parsePhoneNumber(number);
    return {
      valid:parsed.isValid(),
      country:parsed.country,
      carrier:parsed.carrier,
      lineType:parsed.getType()
    };
  }catch{
    return {valid:false};
  }
}

/* ===============================
REPORT GENERATOR
================================ */
function generateReport(data){
  fs.writeFileSync("report.json",JSON.stringify(data,null,2));
  const html=`<html><head><title>OSINT Report</title>
<style>body{font-family:monospace;background:#111;color:#0f0;padding:20px;}h1{color:#00ff99;}pre{background:#000;padding:15px;border:1px solid #0f0;}</style>
</head><body><h1>OSINT Ultra-Free Report</h1><pre>${JSON.stringify(data,null,2)}</pre></body></html>`;
  fs.writeFileSync("report.html",html);
}

/* ===============================
MAIN
================================ */
async function main(){
  const targetDomain=process.argv[2];
  const targetUsername=process.argv[3];
  const targetEmail=process.argv[4];
  const targetPhone=process.argv[5];

  if(!targetDomain && !targetUsername && !targetEmail && !targetPhone){
    console.log("Usage: node osint-ultra-free.js <domain> <username> <email> <phone>");
    process.exit();
  }

  const results={};

  if(targetDomain){
    console.log("[*] Running domain intelligence...");
    results.domain=await runDomain(targetDomain);
    console.log("[*] Running subdomain enumeration...");
    results.subdomains=await runSubdomains(targetDomain);
  }
  if(targetUsername){
    console.log("[*] Running username footprint...");
    results.username=await runUsername(targetUsername);
  }
  if(targetEmail){
    console.log("[*] Running email check...");
    results.email=await runEmail(targetEmail);
  }
  if(targetPhone){
    console.log("[*] Running phone check...");
    results.phone=runPhone(targetPhone);
  }

  generateReport(results);
  console.log("[+] Report generated: report.json + report.html");
}

main();
