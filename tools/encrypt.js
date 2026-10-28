#!/usr/bin/env node
// Szyfruje stronę HTML hasłem: PBKDF2-SHA256 (600 000 iteracji) + AES-256-GCM.
// Wynik to samodzielna strona, która odszyfrowuje treść w przeglądarce (Web Crypto API).
// Użycie: node tools/encrypt.js <wejście.html> <wyjście.html>   (hasło w zmiennej SITE_PASSWORD)
const fs = require("fs");
const crypto = require("crypto");

const [, , input, output] = process.argv;
const password = process.env.SITE_PASSWORD;
if (!input || !output || !password) {
  console.error("Użycie: SITE_PASSWORD=... node tools/encrypt.js wejście.html wyjście.html");
  process.exit(1);
}
const ITER = 600000;
const plain = fs.readFileSync(input);
// Sól jest stała (tools/salt.b64), żeby „Zapamiętaj na tym urządzeniu” działało także po cotygodniowych aktualizacjach.
const path = require("path");
const saltFile = path.join(__dirname, "salt.b64");
let salt;
if (fs.existsSync(saltFile)) salt = Buffer.from(fs.readFileSync(saltFile, "utf8").trim(), "base64");
else { salt = crypto.randomBytes(16); fs.writeFileSync(saltFile, salt.toString("base64") + "\n"); }
const iv = crypto.randomBytes(12);
const key = crypto.pbkdf2Sync(password, salt, ITER, 32, "sha256");
const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
const ct = Buffer.concat([cipher.update(plain), cipher.final(), cipher.getAuthTag()]);
const b64 = (b) => b.toString("base64");

const page = `<!doctype html>
<html lang="pl">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>Nowości wydawnicze w Polsce</title>
<style>
:root{--bg:#f3f5f3;--paper:#fff;--ink:#18221e;--muted:#5a6a63;--line:#d6ded9;--accent:#1f5e4a;--err:#9b2f2f}
@media (prefers-color-scheme:dark){:root{--bg:#111715;--paper:#18201d;--ink:#e4ebe7;--muted:#97a8a0;--line:#2c3833;--accent:#6fc2a2;--err:#e08a7e;color-scheme:dark}}
*{box-sizing:border-box}
html,body{height:100%}
body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif;display:grid;place-items:center;padding:16px}
form{background:var(--paper);border:1px solid var(--line);border-radius:6px;padding:28px;width:100%;max-width:360px;display:grid;gap:14px}
h1{font:700 22px/1.2 Georgia,"Times New Roman",serif;margin:0}
p{margin:0;color:var(--muted);font-size:14px}
input[type=password]{font:inherit;padding:9px 11px;border:1px solid var(--line);border-radius:4px;background:var(--bg);color:var(--ink);width:100%}
label{display:flex;gap:8px;align-items:center;font-size:13px}
button{font:inherit;font-weight:600;padding:9px;border:0;border-radius:4px;background:var(--accent);color:var(--paper);cursor:pointer}
button:disabled{opacity:.6;cursor:wait}
.err{color:var(--err);font-size:13px;min-height:1.2em}
:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
</style>
</head>
<body>
<form id="f">
  <h1>Nowości wydawnicze w Polsce</h1>
  <p>Wpisz hasło, aby otworzyć wyszukiwarkę.</p>
  <input type="password" id="pw" autocomplete="current-password" aria-label="Hasło" placeholder="Hasło" required autofocus>
  <label><input type="checkbox" id="rem"> Zapamiętaj na tym urządzeniu</label>
  <button id="go" type="submit">Otwórz</button>
  <div class="err" id="err" role="alert"></div>
</form>
<script>
const D={s:"${b64(salt)}",i:"${b64(iv)}",c:"${b64(ct)}",n:${ITER}};
const K="nowosci-klucz-"+D.s;
const u=b=>Uint8Array.from(atob(b),c=>c.charCodeAt(0));
async function open(raw){
  const key=await crypto.subtle.importKey("raw",raw,"AES-GCM",false,["decrypt"]);
  const pt=await crypto.subtle.decrypt({name:"AES-GCM",iv:u(D.i)},key,u(D.c));
  const html=new TextDecoder().decode(pt);
  document.open();document.write(html);document.close();
}
async function derive(pw){
  const base=await crypto.subtle.importKey("raw",new TextEncoder().encode(pw),"PBKDF2",false,["deriveBits"]);
  return new Uint8Array(await crypto.subtle.deriveBits({name:"PBKDF2",hash:"SHA-256",salt:u(D.s),iterations:D.n},base,256));
}
(async()=>{try{const s=localStorage.getItem(K);if(s)await open(u(s));}catch(e){try{localStorage.removeItem(K)}catch(_){}}})();
document.getElementById("f").addEventListener("submit",async e=>{
  e.preventDefault();const b=document.getElementById("go"),er=document.getElementById("err");
  b.disabled=true;b.textContent="Sprawdzam…";er.textContent="";
  try{
    const raw=await derive(document.getElementById("pw").value);
    if(document.getElementById("rem").checked){try{localStorage.setItem(K,btoa(String.fromCharCode(...raw)))}catch(_){}}
    await open(raw);
  }catch(_){er.textContent="Nieprawidłowe hasło. Spróbuj jeszcze raz.";b.disabled=false;b.textContent="Otwórz";}
});
</script>
</body>
</html>
`;
fs.writeFileSync(output, page);
console.log(`Zaszyfrowano ${plain.length} B → ${output} (${page.length} B)`);
