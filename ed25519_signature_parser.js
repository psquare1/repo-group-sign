#!/usr/bin/env node
/* verify_sshsig_standalone.js  —  pure-JS OpenSSH “SSHSIG” verifier
 *
 * Hard-coded inputs:
 *   SIG_TEXT     – the detached signature in ASCII-armored format
 *   MESSAGE_TEXT – the exact message that was signed
 *
 * No files are read or written.
 */

"use strict";
const crypto = require("crypto");

// ──── ⇩⇩⇩  PUT YOUR DATA HERE  ⇩⇩⇩ ───────────────────────────────────────────
const SIG_TEXT = `
-----BEGIN SSH SIGNATURE-----
U1NIU0lHAAAAAQAAADMAAAALc3NoLWVkMjU1MTkAAAAgnWXtFXVQ4Aw9CU/cyP10dlnGG1
9a3OEMBVt8hP5+YVsAAAAEZmlsZQAAAAAAAAAGc2hhNTEyAAAAUwAAAAtzc2gtZWQyNTUx
OQAAAEA1JM2XODdWCunfw/5v4RjSj1ki+SjAuc/orl/4jJS5oIGBObAJFaAVy12RCXoDgq
/o0EPNa4it/7dEfIRM3asG
-----END SSH SIGNATURE-----
`.trim();

const MESSAGE_TEXT = `Hello, World\n`;   // or whatever was actually signed
// ─────────────────────────────────────────────────────────────────────────────

// ═════════════════════════════ SSH “string” helpers ══════════════════════════
function readSSHString(buf, off = 0) {
  if (off + 4 > buf.length) throw new Error("truncated SSH string length");
  const ln = buf.readUInt32BE(off);
  const start = off + 4;
  const end   = start + ln;
  if (end > buf.length) throw new Error("truncated SSH string payload");
  return { data: buf.slice(start, end), off: end };
}

function writeSSHString(payload) {
  const len = Buffer.alloc(4); len.writeUInt32BE(payload.length, 0);
  return Buffer.concat([len, payload]);
}

// ═════════════════════ minimal Ed25519 verifier (pure JS) ═════════════════════
const q = (1n << 255n) - 19n;
const l = (1n << 252n) + 27742317777372353535851937790883648493n;

const d = ((-121665n * modInv(121666n)) % q + q) % q;
const I = modPow(2n, (q - 1n) / 4n);

function modPow(base, exp, m = q) {
  let res = 1n;
  base %= m;
  while (exp) {
    if (exp & 1n) res = (res * base) % m;
    base = (base * base) % m;
    exp >>= 1n;
  }
  return res;
}
function modInv(x) { return modPow(x, q - 2n); }
function bytesLEtoBigInt(b) { return [...b].reverse().reduce((n, v) => (n << 8n) + BigInt(v), 0n); }

function xRecover(y) {
  const xx = ((y * y - 1n) * modInv(d * y * y + 1n)) % q;
  let x = modPow(xx, (q + 3n) / 8n);
  if ((x * x - xx) % q) x = (x * I) % q;
  if (x & 1n) x = q - x;
  return x;
}
function unpack(P) {
  if (P.length !== 32) throw new Error("bad point length");
  const y = bytesLEtoBigInt(P) & ((1n << 255n) - 1n);
  const x = xRecover(y);
  const sign = (P[31] >> 7) & 1;
  return [(sign ? q - x : x) % q, y];
}
function add(P, Q) {
  const [x1,y1] = P, [x2,y2] = Q;
  const inv = modInv(1n + d * x1 * x2 * y1 * y2);
  const x3  = ((x1*y2 + x2*y1) * inv) % q;
  const y3  = ((y1*y2 + x1*x2) * modInv(1n - d * x1 * x2 * y1 * y2)) % q;
  return [x3, y3];
}
function dbl(P) { return add(P, P); }
function scalarMult(P, e) {
  let Q = null;
  for (let i=255;i>=0;--i){
    if (Q) Q = dbl(Q);
    if ((e >> BigInt(i)) & 1n) Q = Q ? add(Q, P) : P;
  }
  return Q;
}
const B = [
  15112221349535400772501151409588531511454012693041857206046113283949847762202n,
  46316835694926478169428394003475163141307993866256225615783033603165251855960n
];
function ed25519Verify(pub, msg, sig) {
  if (pub.length!==32||sig.length!==64) return false;
  const Renc=sig.subarray(0,32), Senc=sig.subarray(32);
  console.log(`R: ${Renc.toString("hex")}`);
  console.log(`S: ${Senc.toString("hex")}`);
  let R,A; try { R=unpack(Renc); A=unpack(pub); } catch{ return false; }
  const S=bytesLEtoBigInt(Senc); if (S>=l) return false;
  const h=bytesLEtoBigInt(
    crypto.createHash("sha512").update(Buffer.concat([Renc,pub,msg])).digest()
  )%l;
  const SB = scalarMult(B,S);
  const RplushA = add(R, scalarMult(A,h));
  return SB[0]===RplushA[0] && SB[1]===RplushA[1];
}

// ═════════════════════ SSHSIG parsing & verification ══════════════════════════
function parseSSHSig(armoredText) {
  const lines = armoredText.split(/\r?\n/).map(l=>l.trim()).filter(Boolean);
  const bodyB64 = lines.filter(l=>!l.startsWith("-----")).join("");
  const blob = Buffer.from(bodyB64,"base64");
  if (!blob.slice(0,6).equals(Buffer.from("SSHSIG"))) throw Error("bad header");
  let off=6;
  const vers = blob.readUInt32BE(off); off+=4;
  const pkRaw  = readSSHString(blob,off); off=pkRaw.off;
  const nsRaw  = readSSHString(blob,off); off=nsRaw.off;
  const resvd  = readSSHString(blob,off); off=resvd.off;
  const hAlg   = readSSHString(blob,off); off=hAlg.off;
  const sigRaw = readSSHString(blob,off); off=sigRaw.off;
  if (off!==blob.length) throw Error("trailing bytes");

  const pkAlg  = readSSHString(pkRaw.data,0);
  const pkBytes= readSSHString(pkRaw.data,pkAlg.off);
  const sgAlg  = readSSHString(sigRaw.data,0);
  const sgBytes= readSSHString(sigRaw.data,sgAlg.off);

  const parsed={
    version:vers,
    namespace:nsRaw.data,
    hash_alg:hAlg.data,
    pk_alg:pkAlg.data,
    pk_bytes:pkBytes.data,
    sig_alg:sgAlg.data,
    sig_bytes:sgBytes.data,
  };
  console.log("== SSHSIG fields ==");
  for (const [k,v] of Object.entries(parsed)){
    const pretty=Buffer.isBuffer(v) && /^[ -~]*$/.test(v.toString())?
                 `"${v.toString()}"`:"0x"+(Buffer.isBuffer(v)?v.toString("hex"):v);
    console.log(`${k.padEnd(10)}: ${pretty}`);
  }
  return parsed;
}

function verifySSHSig(armoredSig, message) {
  const parsed = parseSSHSig(armoredSig);
  const msgBuf = Buffer.from(message, "utf8");

  // 1. hash message
  const hname = parsed.hash_alg.toString();
  if (hname!=="sha512"&&hname!=="sha256") throw Error("unsupported hash");
  const digest = crypto.createHash(hname).update(msgBuf).digest();

  // 2. rebuild wrapper
  const wrapper = Buffer.concat([
    Buffer.from("SSHSIG"),
    writeSSHString(parsed.namespace),
    writeSSHString(Buffer.alloc(0)),
    writeSSHString(parsed.hash_alg),
    writeSSHString(digest),
  ]);

  console.log("digest(message):", digest.toString("hex"));
  console.log("digest from sig:", parsed.sig_bytes       // R||S already split
            .slice(0,0)); // placeholder just to keep syntax; we'll inspect R later


  // 3. verify
  if (!parsed.sig_alg.equals(Buffer.from("ssh-ed25519")) ||
      !parsed.pk_alg .equals(Buffer.from("ssh-ed25519")))
    throw Error("only Ed25519 supported here");
  return ed25519Verify(parsed.pk_bytes, wrapper, parsed.sig_bytes);
}

// ═══════════════════════ main ════════════════════════════════════════════════
(function main(){
  const ok = verifySSHSig(SIG_TEXT, MESSAGE_TEXT);
  console.log(ok ? "✓ VALID" : "✗ FAILED");
})();
