#!/usr/bin/env node
/* build_verify_context.js  –  minimal helpers to dissect an SSHSIG and
 *                            compute the Ed25519 “h” scalar.
 *
 * Hard-coded inputs below are just examples; replace at will.
 */
"use strict";
const crypto = require("crypto");

/* ─────── hard-coded demo data ─────────────────────────────────────────────── */
const SIG_TEXT = `-----BEGIN SSH SIGNATURE-----
U1NIU0lHAAAAAQAAADMAAAALc3NoLWVkMjU1MTkAAAAgnWXtFXVQ4Aw9CU/cyP10dlnGG1
9a3OEMBVt8hP5+YVsAAAAEZmlsZQAAAAAAAAAGc2hhNTEyAAAAUwAAAAtzc2gtZWQyNTUx
OQAAAEA1JM2XODdWCunfw/5v4RjSj1ki+SjAuc/orl/4jJS5oIGBObAJFaAVy12RCXoDgq
/o0EPNa4it/7dEfIRM3asG
-----END SSH SIGNATURE-----`.trim();

const MESSAGE = "Hello, World\n";               // ← exactly what was signed

/* ─────── constants & tiny helpers ─────────────────────────────────────────── */
const l = (1n << 252n) + 27742317777372353535851937790883648493n; // Ed25519 ℓ

function readSSHString(buf, off = 0) {
  if (off + 4 > buf.length) throw new Error("truncated SSH string length");
  const len   = buf.readUInt32BE(off);
  const start = off + 4;
  const end   = start + len;
  if (end > buf.length) throw new Error("truncated SSH string payload");
  return { data: buf.slice(start, end), off: end };
}

function writeSSHString(payload) {
  const hdr = Buffer.alloc(4);
  hdr.writeUInt32BE(payload.length, 0);
  return Buffer.concat([hdr, payload]);
}

function bytesLEtoBigInt(buf) {
  let n = 0n;
  for (let i = buf.length - 1; i >= 0; --i) n = (n << 8n) + BigInt(buf[i]);
  return n;
}

/* ─────── master helper ────────────────────────────────────────────────────── */
/**
 * buildVerifyContext
 * ------------------
 * Parse an ASCII-armoured SSHSIG, recompute all pieces needed for
 * Ed25519 verification, and return them in one object.
 *
 * @param {string|Buffer} sigText  – entire SSHSIG block (BEGIN/END lines)
 * @param {string|Buffer} message  – original message bytes
 * @returns {{
 *   version:number, namespace:Buffer, hash_alg:Buffer,
 *   pk_alg:Buffer, pk_bytes:Buffer,
 *   sig_alg:Buffer, sig_bytes:Buffer,
 *   R_enc:Buffer, S_enc:Buffer,
 *   digest:Buffer, wrapper:Buffer,
 *   h:BigInt
 * }}
 */
function buildVerifyContext(sigText = SIG_TEXT, message = MESSAGE) {
  /* 1. Parse outer SSHSIG structure ---------------------------------------- */
  const lines   = sigText.split(/\r?\n/).map(l => l.trim()).filter(Boolean);
  const bodyB64 = lines.filter(l => !l.startsWith("-----")).join("");
  const blob    = Buffer.from(bodyB64, "base64");

  if (!blob.slice(0, 6).equals(Buffer.from("SSHSIG")))
    throw new Error("Not an SSHSIG blob");
  let off = 6;

  const version = blob.readUInt32BE(off); off += 4;
  const pkRaw   = readSSHString(blob, off);   off = pkRaw.off;
  const nsRaw   = readSSHString(blob, off);   off = nsRaw.off;
  const _resvd  = readSSHString(blob, off);   off = _resvd.off;
  const hAlg    = readSSHString(blob, off);   off = hAlg.off;
  const sigRaw  = readSSHString(blob, off);   off = sigRaw.off;
  if (off !== blob.length) throw new Error("Trailing bytes in SSHSIG");

  const pkAlg   = readSSHString(pkRaw.data, 0);
  const pkBytes = readSSHString(pkRaw.data, pkAlg.off);
  const sgAlg   = readSSHString(sigRaw.data, 0);
  const sgBytes = readSSHString(sigRaw.data, sgAlg.off);

  /* 2. Split Ed25519 signature into R || S --------------------------------- */
  if (sgBytes.data.length !== 64)
    throw new Error(`bad sig length ${sgBytes.data.length} (expected 64)`);
  const R_enc = sgBytes.data.slice(0, 32);
  const S_enc = sgBytes.data.slice(32);

  /* 3. digest(message) with declared hash ---------------------------------- */
  const msgBuf = Buffer.isBuffer(message) ? message : Buffer.from(message, "utf8");
  const hname  = hAlg.data.toString();
  if (hname !== "sha512" && hname !== "sha256")
    throw new Error(`unsupported hash ${hname}`);
  const digest = crypto.createHash(hname).update(msgBuf).digest();

  /* 4. Rebuild signed `wrapper` -------------------------------------------- */
  const wrapper = Buffer.concat([
    Buffer.from("SSHSIG"),
    writeSSHString(nsRaw.data),
    writeSSHString(Buffer.alloc(0)),       // reserved
    writeSSHString(hAlg.data),
    writeSSHString(digest),
  ]);

  /* 5. Compute h = SHA-512(R || A || wrapper) mod ℓ ------------------------ */
  const hBytes = crypto.createHash("sha512")
                       .update(Buffer.concat([R_enc, pkBytes.data, wrapper]))
                       .digest();
  const h = bytesLEtoBigInt(hBytes) % l;

  return {
    version,
    namespace : nsRaw.data,
    hash_alg  : hAlg.data,
    pk_alg    : pkAlg.data,
    pk_bytes  : pkBytes.data,
    sig_alg   : sgAlg.data,
    sig_bytes : sgBytes.data,
    R_enc,
    S_enc,
    digest,
    wrapper,
    h
  };
}

/* ─────── quick demo (run `node build_verify_context.js`) ─────────────────── */
if (require.main === module) {
  const ctx = buildVerifyContext();
  console.log("R_enc:", ctx.R_enc.toString("hex"));
  console.log("S_enc:", ctx.S_enc.toString("hex"));
  console.log("digest(message):", ctx.digest.toString("hex"));
  console.log("h:", ctx.h.toString(16));
}
