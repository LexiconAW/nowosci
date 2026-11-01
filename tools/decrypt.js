#!/usr/bin/env node
// Odszyfrowuje index.html z powrotem do źródłowego HTML. Użycie: SITE_PASSWORD=... node tools/decrypt.js index.html wyjście.html
const fs=require("fs"),c=require("crypto");
const h=fs.readFileSync(process.argv[2],"utf8");
const m=h.match(/const D=\{s:"([^"]+)",i:"([^"]+)",c:"([^"]+)",n:(\d+)\}/);
const b=x=>Buffer.from(x,"base64");
const key=c.pbkdf2Sync(process.env.SITE_PASSWORD,b(m[1]),+m[4],32,"sha256");
const ct=b(m[3]);const d=c.createDecipheriv("aes-256-gcm",key,b(m[2]));
d.setAuthTag(ct.subarray(ct.length-16));
fs.writeFileSync(process.argv[3],Buffer.concat([d.update(ct.subarray(0,ct.length-16)),d.final()]));
