#!/usr/bin/env node
/* verify_sshsig_standalone.js
 * ---------------------------
 * Pure-JS verifier for OpenSSH detached signatures (“SSHSIG” files).
 *
 * Usage
 * =====
 *   node verify_sshsig_standalone.js        # looks for content.sig & message.txt
 *
 * If the signature is valid it prints “✓ VALID”, otherwise “✗ FAILED”.
 */

"use strict";

const fs     = require("fs");
const path   = require("path");
const crypto = require("crypto");


const SIG_TEXT = `
    -----BEGIN SSH SIGNATURE-----
U1NIU0lHAAAAAQAAADMAAAALc3NoLWVkMjU1MTkAAAAgnWXtFXVQ4Aw9CU/cyP10dlnGG1
9a3OEMBVt8hP5+YVsAAAAEZmlsZQAAAAAAAAAGc2hhNTEyAAAAUwAAAAtzc2gtZWQyNTUx
OQAAAEA1JM2XODdWCunfw/5v4RjSj1ki+SjAuc/orl/4jJS5oIGBObAJFaAVy12RCXoDgq
/o0EPNa4it/7dEfIRM3asG
-----END SSH SIGNATURE-----
 `.trim();
const msg    = "Hello, World\n";

// ═════════════════════════════ SSH “string” helpers ═══════════════════════════
function readSSHString(buf, off = 0) {
  if (off + 4 > buf.length) throw new Error("truncated SSH string length");
  const ln = buf.readUInt32BE(off);
  const start = off + 4;
  const end   = start + ln;
  if (end > buf.length) throw new Error("truncated SSH string payload");
  return { data: buf.slice(start, end), off: end };
}

function writeSSHString(payload) {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(payload.length, 0);
  return Buffer.concat([len, payload]);
}

// ═════════════════════ minimal Ed25519 verifier (pure JS) ═════════════════════
// Adapted from the same ref10 public-domain source as the Python version.

const q = (1n << 255n) - 19n;
const l = (1n << 252n) + 27742317777372353535851937790883648493n; // group order

function mod(a, m = q) {
  const res = a % m;
  return res >= 0n ? res : res + m;
}

function modPow(base, exp, m = q) {                // fast (binary) mod-pow
  let result = 1n;
  base = mod(base, m);
  while (exp > 0n) {
    if (exp & 1n) result = mod(result * base, m);
    base = mod(base * base, m);
    exp >>= 1n;
  }
  return result;
}

function inv(x) {                         // modular inverse via Fermat
  return modPow(x, q - 2n);
}

// curve constants
const d = mod(-121665n * inv(121666n));
const I = modPow(2n, (q - 1n) / 4n);

// helpers for (un)packing/scalar math
function bytesToBigIntLE(buf) {
  let v = 0n;
  for (let i = buf.length - 1; i >= 0; --i) {
    v = (v << 8n) + BigInt(buf[i]);
  }
  return v;
}

function xRecover(y) {
  const xx = mod((y * y - 1n) * inv(d * y * y + 1n));
  let x = modPow(xx, (q + 3n) / 8n);
  if (mod(x * x - xx) !== 0n) x = mod(x * I);
  if (x & 1n) x = q - x;
  return x;
}

function edUnpack(P) {
  if (P.length !== 32) throw new Error("bad point length");
  const y = bytesToBigIntLE(P) & ((1n << 255n) - 1n);
  const x = xRecover(y);
  const sign = (P[31] >> 7) & 1;
  if ((x & 1n) !== BigInt(sign)) return [mod(q - x), y];
  return [x, y];
}

function edAdd(P, Q) {
  const [x1, y1] = P, [x2, y2] = Q;
  const x3 = mod((x1 * y2 + x2 * y1) * inv(1n + d * x1 * x2 * y1 * y2));
  const y3 = mod((y1 * y2 + x1 * x2) * inv(1n - d * x1 * x2 * y1 * y2));
  return [x3, y3];
}

function edDouble(P) {
  return edAdd(P, P);
}

function scalarMult(P, e) {
  let Q = null;
  for (let i = 255; i >= 0; --i) {
    if (Q) Q = edDouble(Q);
    if ((e >> BigInt(i)) & 1n) Q = Q ? edAdd(Q, P) : P;
  }
  return Q;
}

// basepoint in affine coordinates
const B = [
  15112221349535400772501151409588531511454012693041857206046113283949847762202n,
  46316835694926478169428394003475163141307993866256225615783033603165251855960n,
];

function ed25519Verify(pubBytes, msg, sigBytes) {
  if (pubBytes.length !== 32 || sigBytes.length !== 64) return false;

  const Renc = sigBytes.slice(0, 32);
  const Senc = sigBytes.slice(32);

  console.log(`R: ${Renc.toString("hex")}`);
  console.log(`S: ${Senc.toString("hex")}`);

  let R, A;
  try {
    R = edUnpack(Renc);
    A = edUnpack(pubBytes);
  } catch (e) { return false; }

  const S = bytesToBigIntLE(Senc);
  if (S >= l) return false;

  const hBytes = crypto.createHash("sha512")
                       .update(Buffer.concat([Renc, pubBytes, msg]))
                       .digest();
  const h = bytesToBigIntLE(hBytes) % l;

  const SB        = scalarMult(B, S);
  const hA        = scalarMult(A, h);
  const RplushA   = edAdd(R, hA);
  return SB[0] === RplushA[0] && SB[1] === RplushA[1];
}

// pretty-printer for field dumps
function pretty(val) {
  if (Buffer.isBuffer(val)) {
    const txt = val.toString("utf8");
    if (/^[\x20-\x7E]*$/.test(txt)) return `"${txt}"`;
    return "0x" + val.toString("hex");
  }
  return String(val);
}

// ═════════════════════ SSHSIG parsing & verification ══════════════════════════
function parseSSHSig(pth) {
    // 2.  Everything else is unchanged – just work from SIG_TEXT
    const armourLines = SIG_TEXT
      .split(/\r?\n/)          // break into lines
      .map(l => l.trim())      // strip whitespace
      .filter(Boolean);        // drop empty lines
  const bodyB64 = armourLines.filter(l => !l.startsWith("-----")).join("");
  const blob    = Buffer.from(bodyB64, "base64");

  if (!blob.slice(0, 6).equals(Buffer.from("SSHSIG"))) {
    throw new Error("Not an SSHSIG blob");
  }
  let off = 6;

  const version = blob.readUInt32BE(off); off += 4;

  const pkRaw   = readSSHString(blob, off);   off = pkRaw.off;
  const nsRaw   = readSSHString(blob, off);   off = nsRaw.off;
  const resvd   = readSSHString(blob, off);   off = resvd.off;
  const hAlg    = readSSHString(blob, off);   off = hAlg.off;
  const sigRaw  = readSSHString(blob, off);   off = sigRaw.off;
  if (off !== blob.length) throw new Error("Trailing bytes in SSHSIG");

  const pkAlg   = readSSHString(pkRaw.data, 0);
  const pkBytes = readSSHString(pkRaw.data, pkAlg.off);

  const sigAlg  = readSSHString(sigRaw.data, 0);
  const sigBytes= readSSHString(sigRaw.data, sigAlg.off);

  const parsed = {
    version,
    namespace: nsRaw.data,
    hash_alg : hAlg.data,
    pk_alg   : pkAlg.data,
    pk_bytes : pkBytes.data,
    sig_alg  : sigAlg.data,
    sig_bytes: sigBytes.data,
  };

  console.log("== SSHSIG fields ==");
  for (const [k, v] of Object.entries(parsed)) {
    console.log(`${k.padEnd(10)}: ${pretty(v)}`);
  }
  return parsed;
}

function verifySSHSig(sigPath, msgPath) {
  const parsed = parseSSHSig(sigPath);

  // step-1: recompute digest(message) with declared hash
  const hname  = parsed.hash_alg.toString();
  if (hname !== "sha512" && hname !== "sha256") {
    throw new Error(`unsupported hash ${hname}`);
  }
  const digest = crypto.createHash(hname).update(msg).digest();

  // step-2: rebuild the wrapper that got signed
  const wrapper = Buffer.concat([
    Buffer.from("SSHSIG"),
    writeSSHString(parsed.namespace),
    writeSSHString(Buffer.alloc(0)),          // reserved
    writeSSHString(parsed.hash_alg),
    writeSSHString(digest),
  ]);
  console.log("digest(message):", digest.toString("hex"));
  // step-3: verify according to algorithm
  if (!parsed.sig_alg.equals(Buffer.from("ssh-ed25519")) ||
      !parsed.pk_alg .equals(Buffer.from("ssh-ed25519"))) {
    throw new Error("this standalone verifier only supports Ed25519");
  }
  return ed25519Verify(parsed.pk_bytes, wrapper, parsed.sig_bytes);
}

function buildVerifyContext(
    sigText = SIG_TEXT,
    message = msg
  ) {
    // ── 1. parse the signature block ───────────────────────────────────────────
    const parsed = (function parse(sigTxt) {
      const armourLines = sigTxt
        .split(/\r?\n/)               // break into lines
        .map(l => l.trim())
        .filter(Boolean);
  
      const bodyB64 = armourLines
        .filter(l => !l.startsWith("-----"))
        .join("");
      const blob = Buffer.from(bodyB64, "base64");
      if (!blob.slice(0, 6).equals(Buffer.from("SSHSIG")))
        throw new Error("Not an SSHSIG blob");
  
      let off = 6;
      const version = blob.readUInt32BE(off); off += 4;
      const pkRaw   = readSSHString(blob, off);   off = pkRaw.off;
      const nsRaw   = readSSHString(blob, off);   off = nsRaw.off;
      const resvd   = readSSHString(blob, off);   off = resvd.off;
      const hAlg    = readSSHString(blob, off);   off = hAlg.off;
      const sigRaw  = readSSHString(blob, off);   off = sigRaw.off;
      if (off !== blob.length) throw new Error("Trailing bytes in SSHSIG");
  
      const pkAlg   = readSSHString(pkRaw.data, 0);
      const pkBytes = readSSHString(pkRaw.data, pkAlg.off);
      const sigAlg  = readSSHString(sigRaw.data, 0);
      const sigBytes= readSSHString(sigRaw.data, sigAlg.off);
  
      return {
        version,
        namespace : nsRaw.data,
        hash_alg  : hAlg.data,
        pk_alg    : pkAlg.data,
        pk_bytes  : pkBytes.data,
        sig_alg   : sigAlg.data,
        sig_bytes : sigBytes.data,
      };
    })(sigText);
  
    // ── 2. split R || S ────────────────────────────────────────────────────────
    if (parsed.sig_bytes.length !== 64)
      throw new Error(`unexpected sig length ${parsed.sig_bytes.length}`);
    const R_enc = parsed.sig_bytes.slice(0, 32);
    const S_enc = parsed.sig_bytes.slice(32);
  
    // ── 3. hash(message) with declared hash ────────────────────────────────────
    const msgBuf = Buffer.isBuffer(message)
                 ? message
                 : Buffer.from(message, "utf8");
    const hname  = parsed.hash_alg.toString();
    if (hname !== "sha512" && hname !== "sha256")
      throw new Error(`unsupported hash ${hname}`);
    const digest = crypto.createHash(hname).update(msgBuf).digest();
  
    // ── 4. rebuild the SSHSIG “wrapper” that was signed ────────────────────────
    const wrapper = Buffer.concat([
      Buffer.from("SSHSIG"),
      writeSSHString(parsed.namespace),
      writeSSHString(Buffer.alloc(0)),   // reserved
      writeSSHString(parsed.hash_alg),
      writeSSHString(digest),
    ]);
  
    // ── 5. compute h = SHA-512(R || A || wrapper) mod ℓ ───────────────────────
    const hBytes = crypto.createHash("sha512")
                         .update(Buffer.concat([R_enc, parsed.pk_bytes, wrapper]))
                         .digest();
    const h = bytesToBigIntLE(hBytes) % l;
  
    return { ...parsed, R_enc, S_enc, digest, wrapper, h };
  }
  
  
// ═══════════════════════════════════ main ═════════════════════════════════════
(function main() {
  const sigFile = path.resolve("content.sig");
  const msgFile = path.resolve("message.txt");

  const ok = verifySSHSig(sigFile, msgFile);
  console.log(buildVerifyContext());
  console.log(ok ? "✓ VALID" : "✗ FAILED");
})();
