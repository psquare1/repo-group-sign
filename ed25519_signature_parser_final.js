#!/usr/bin/env node
/* build_verify_context.js  –  minimal helpers to dissect an SSHSIG and
 *                            compute the Ed25519 "h" scalar.
 *
 * Hard-coded inputs below are just examples; replace at will.
 */
"use strict";
const { assert } = require("console");
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
function buildVerifyContext(sigText, message = MESSAGE) {
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

const p = (1n << 255n) - 19n; // Ed25519 prime modulus

/**
 * decodePoint
 * -----------
 * Convert the encoded data of a point to a point on the twisted Edwards elliptic curve.
 *
 * @param {Buffer} encodedPoint - 32-byte buffer representing the encoded point.
 * @returns {{ x: BigInt, y: BigInt }} - Object containing x and y coordinates as BigInts.
 */
function decodePoint(encodedPoint) {
  if (encodedPoint.length !== 32) {
    throw new Error("Invalid encoded point length (expected 32 bytes)");
  }

  const d = mod(-121665n * modInverse(121666n)); // Curve parameter d

  const y = bytesLEtoBigInt(encodedPoint) & ((1n << 255n) - 1n); // Extract y-coordinate
  const xSign = (bytesLEtoBigInt(encodedPoint) >> 255n) & 1n; // Extract sign of x

  const ySquared = mod(y * y);
  const u = mod(ySquared - 1n);
  const v = mod(d * ySquared + 1n + p); // Adjusted for -x^2 in the curve equation

  const xSquared = mod(u * modInverse(v));
  let x = modSqrt(xSquared);

  if ((x % 2n) !== xSign) {
    x = p - x; // Adjust x based on its sign
  }

  return { x, y };
}

/**
 * mod
 * ---
 * Compute n mod p, ensuring correct behavior for negative numbers.
 *
 * @param {BigInt} n - Number to take modulo.
 * @param {BigInt} p - Modulus.
 * @returns {BigInt} - Result of n mod p.
 */
function mod(n) {
  const result = n % p;
  if (result < 0) {
    return result + p;
  }
  return result;
}

/**
 * modInverse
 * ----------
 * Compute the modular inverse of a number using the extended Euclidean algorithm.
 *
 * @param {BigInt} a - Number to find the modular inverse of.
 * @param {BigInt} p - Modulus (must be a prime number).
 * @returns {BigInt} - Modular inverse of a mod p.
 */
function modInverse(a) {
    if (p <= 0n) {
      throw new Error("Modulus must be positive");
    }

    let t = 0n, newT = 1n;
    let r = p, newR = mod(a);

    while (newR !== 0n) {
      const quotient = r / newR;

      [t, newT] = [newT, t - quotient * newT];
      [r, newR] = [newR, r - quotient * newR];
    }

    if (r > 1n) {
      throw new Error("a is not invertible");
    }

    if (t < 0n) {
      t += p;
    }

    return t;
}

/**
 * modExp
 * ------
 * Compute modular exponentiation: (base^exp) % mod.
 * Handles negative base and exponent using the "mod()" function.
 *
 * @param {BigInt} base - The base number.
 * @param {BigInt} exp - The exponent.
 * @param {BigInt} mod - The modulus.
 * @returns {BigInt} - Result of (base^exp) % mod.
 */
function modExp(base, exp) {
  if (p <= 0n) {
    throw new Error("Modulus must be positive");
  }

  base = mod(base); // Ensure base is within the modulus range
  let result = 1n;

  while (exp > 0n) {
    if (exp % 2n === 1n) {
      result = mod(result * base);
    }
    base = mod(base * base);
    exp /= 2n;
  }

  return result;
}

/**
 * modSqrt
 * -------
 * Compute the modular square root of a number modulo a prime p,
 * where p ≡ 5 (mod 8). Uses the Tonelli-Shanks-like method for primes of this form.
 *
 * @param {BigInt} n - The number to find the square root of.
 * @param {BigInt} p - The prime modulus (must satisfy p ≡ 5 mod 8).
 * @returns {BigInt} - Modular square root of n modulo p.
 */
function modSqrt(n) {
  n = mod(n); // Ensure n is within the modulus range

  const sqrtMinusOne = modExp(2n, (p - 1n) / 4n); // sqrt(-1) modulo p
  const exp = (p + 3n) / 8n;
  let root = modExp(n, exp);

  if (mod(root * root) !== n) {
    root = mod(root * sqrtMinusOne); // Use sqrt(-1) if the first root is incorrect
  }

  if (mod(root * root) !== n) {
    throw new Error("No square root exists for the given n modulo p");
  }

  return root < (p - root) ? root : (p - root);
}

/**
 * convertToMontgomery
 * -------------------
 * Convert a point from the twisted Edwards curve to the Montgomery curve.
 *
 * The twisted Edwards curve equation is: -x^2 + y^2 = 1 + d * x^2 * y^2 (mod p)
 * The Montgomery curve equation is: By^2 = x^3 + Ax^2 + x (mod p)
 *
 * @param {BigInt} xEdwards - x-coordinate on the Edwards curve.
 * @param {BigInt} yEdwards - y-coordinate on the Edwards curve.
 * @returns {{ x: BigInt, y: BigInt }} - Coordinates on the Montgomery curve.
 */
function convertToMontgomery(xEdwards, yEdwards) {
  const u = mod((1n + yEdwards) * modInverse(1n - yEdwards));
  const v = mod(u * modInverse(xEdwards) * -modSqrt(-486664n));

  return { x: u, y: v };
}

/**
 * convertToWeierstrass
 * ---------------------
 * Convert a point from the Montgomery curve to the Weierstrass curve.
 *
 * The Montgomery curve equation is: By^2 = x^3 + Ax^2 + x (mod p)
 * The Weierstrass curve equation is: y^2 = x^3 + ax + b (mod p)
 *
 * @param {BigInt} xMontgomery - x-coordinate on the Montgomery curve.
 * @param {BigInt} yMontgomery - y-coordinate on the Montgomery curve.
 * @returns {{ x: BigInt, y: BigInt }} - Coordinates on the Weierstrass curve.
 */
function convertToWeierstrass(xMontgomery, yMontgomery) {
  const A = 486662n; // Montgomery curve parameter

  const xWeierstrass = mod(xMontgomery + A*modInverse(3n));
  const yWeierstrass = yMontgomery;

  return { x: xWeierstrass, y: yWeierstrass };
}

/**
 * isPointOnEdwardsCurve
 * ---------------
 * Check if a given point (x, y) lies on the twisted Edwards curve used in Ed25519.
 *
 * The curve equation is: -x^2 + y^2 = 1 + d * x^2 * y^2 (mod p)
 *
 * @param {BigInt} x - x-coordinate of the point.
 * @param {BigInt} y - y-coordinate of the point.
 * @returns {boolean} - True if the point lies on the curve, false otherwise.
 */
function isPointOnEdwardsCurve(x, y) {
  const d = mod(-121665n * modInverse(121666n)); // Curve parameter d

  const xSquared = mod(x * x);
  const ySquared = mod(y * y);

  const leftSide = mod(-xSquared + ySquared);
  const rightSide = mod(1n + d * xSquared * ySquared);

  return leftSide === rightSide;
}

/**
 * isPointOnMontgomeryCurve
 * -------------------------
 * Check if a given point (x, y) lies on the Montgomery curve used in Ed25519.
 *
 * The curve equation is: By^2 = x^3 + Ax^2 + x (mod p)
 *
 * @param {BigInt} x - x-coordinate of the point.
 * @param {BigInt} y - y-coordinate of the point.
 * @returns {boolean} - True if the point lies on the curve, false otherwise.
 */
function isPointOnMontgomeryCurve(x, y) {
  const A = 486662n; // Montgomery curve parameter
  const B = 1n;      // Montgomery curve parameter

  const ySquared = mod(y * y);
  const xCubed = mod(x * x * x);
  const xSquared = mod(A * x * x);

  const leftSide = mod(B * ySquared);
  const rightSide = mod(xCubed + xSquared + x);

  return leftSide === rightSide;
}

/**
 * isPointOnWeierstrassCurve
 * ---------------------------
 * Check if a given point (x, y) lies on the Weierstrass curve.
 *
 * The curve equation is: y^2 = x^3 + ax + b (mod p)
 *
 * @param {BigInt} x - x-coordinate of the point.
 * @param {BigInt} y - y-coordinate of the point.
 * @returns {boolean} - True if the point lies on the curve, false otherwise.
 */
function isPointOnWeierstrassCurve(x, y) {
  // Transformation parameters for converting Montgomery to Weierstrass
  const a = 19298681539552699237261830834781317975544997444273427339909597334573241639236n; // Weierstrass curve parameter a
  const b = 55751746669818908907645289078257140818241103727901012315294400837956729358436n; // Weierstrass curve parameter b

  const ySquared = mod(y * y);
  const xCubed = mod(x * x * x);
  const ax = mod(a * x);

  const leftSide = ySquared;
  const rightSide = mod(xCubed + ax + b);

  return leftSide === rightSide;
}

const basePointEdwards = {
  x: 15112221349535400772501151409588531511454012693041857206046113283949847762202n,
  y: 46316835694926478169428394003475163141307993866256225615783033603165251855960n
}

/**
 * invertPointWeierstrass
 * -----------------------
 * Compute the inverse of a point on the Weierstrass curve.
 *
 * The curve equation is: y^2 = x^3 + ax + b (mod p)
 *
 * @param {{ x: BigInt, y: BigInt }} P - Point on the curve.
 * @returns {{ x: BigInt, y: BigInt }} - Inverted point.
 */
function invertPointWeierstrass(P) {
  return { x: P.x, y: mod(-P.y) };
}

/**
 * addPointsWeierstrass
 * ---------------------
 * Perform point addition on the Weierstrass curve.
 *
 * The curve equation is: y^2 = x^3 + ax + b (mod p)
 *
 * @param {{ x: BigInt, y: BigInt }} P - First point on the curve.
 * @param {{ x: BigInt, y: BigInt }} Q - Second point on the curve.
 * @returns {{ x: BigInt, y: BigInt }} - Resulting point after addition.
 */
function addPointsWeierstrass(P, Q) {
  const a = 19298681539552699237261830834781317975544997444273427339909597334573241639236n; // Weierstrass curve parameter a

  if (P.x === Q.x && P.y === Q.y) {
    // Point doubling
    const slope = mod((3n * P.x * P.x + a) * modInverse(2n * P.y));
    const xR = mod(slope * slope - 2n * P.x);
    const yR = mod(slope * (P.x - xR) - P.y);
    return { x: xR, y: yR };
  } else {
    // Point addition
    const slope = mod((Q.y - P.y) * modInverse(Q.x - P.x));
    const xR = mod(slope * slope - P.x - Q.x);
    const yR = mod(slope * (P.x - xR) - P.y);
    return { x: xR, y: yR };
  }
}

/**
 * scalarMultiplyWeierstrass
 * --------------------------
 * Perform scalar multiplication on the Weierstrass curve.
 *
 * The curve equation is: y^2 = x^3 + ax + b (mod p)
 *
 * @param {BigInt} k - Scalar multiplier.
 * @param {{ x: BigInt, y: BigInt }} P - Point on the curve.
 * @returns {{ x: BigInt, y: BigInt }} - Resulting point after scalar multiplication.
 */
function scalarMultiplyWeierstrass(k, P) {
  let result = null; // "Point at infinity"
  let current = P;

  while (k > 0n) {
    if (k % 2n === 1n) {
      result = result ? addPointsWeierstrass(result, current) : current;
    }
    current = addPointsWeierstrass(current, current); // Point doubling
    k /= 2n;
  }

  return result;
}

function reduceToCurveMultiplication(signature) {
  const ctx = buildVerifyContext(signature);
  let R_enc = ctx.R_enc;
  let R = decodePoint(R_enc);

  let s_enc = ctx.S_enc;
  let s = bytesLEtoBigInt(s_enc);
  
  let pk_enc = ctx.pk_bytes;
  let pk = decodePoint(pk_enc);

  let h = ctx.h;
  //console.log("Computed h as BigInt:", h);

  let R_montgomery = convertToMontgomery(R.x, R.y);
  let pk_montgomery = convertToMontgomery(pk.x, pk.y);
  let R_weierstrass = convertToWeierstrass(R_montgomery.x, R_montgomery.y);
  let pk_weierstrass = convertToWeierstrass(pk_montgomery.x, pk_montgomery.y);
  //console.log("Public key as Weierstrass curve point:", pk_weierstrass);

  let B = basePointEdwards;
  let B_montgomery = convertToMontgomery(B.x, B.y);
  let B_weierstrass = convertToWeierstrass(B_montgomery.x, B_montgomery.y);
  const sB_weierstrass = scalarMultiplyWeierstrass(s, B_weierstrass);

  // should satisfy sB = R + hA
  return {
    s: s,
    R: R_weierstrass,
    h: h,
    A: pk_weierstrass,
  }
}

/**
 * split256BitInteger
 * -------------------
 * Split a 256-bit integer into an array of four 64-bit integers.
 *
 * @param {BigInt} n - The 256-bit integer to split.
 * @returns {BigInt[]} - Array of four 64-bit integers.
 */
function split256BitInteger(n) {
  const mask64 = (1n << 64n) - 1n; // Mask to extract 64 bits
  const parts = [];

  for (let i = 0; i < 4; i++) {
    parts.push(n & mask64); // Extract the lowest 64 bits
    n >>= 64n; // Shift right by 64 bits
  }

  return parts;
}

/* ─────── quick demo (run `node build_verify_context.js`) ─────────────────── */
if (require.main === module) {
  const {s, R, h, A} = reduceToCurveMultiplication(SIG_TEXT);
  console.log("Signature scalar (s):", split256BitInteger(s));
  console.log("R point on Weierstrass curve:", [split256BitInteger(R.x), split256BitInteger(R.y)]);
  console.log("h:", split256BitInteger(h));
  console.log("Public key point on Weierstrass curve:", [split256BitInteger(A.x), split256BitInteger(A.y)]);
  // verify that sB = R + hA
  let B = basePointEdwards;
  let B_montgomery = convertToMontgomery(B.x, B.y);
  let B_weierstrass = convertToWeierstrass(B_montgomery.x, B_montgomery.y);
  const sB_weierstrass = scalarMultiplyWeierstrass(s, B_weierstrass);
  const R_plus_hA = addPointsWeierstrass(R, scalarMultiplyWeierstrass(h, A));
  console.log("sB:", sB_weierstrass);
  console.log("R + hA:", R_plus_hA);
  console.log("Verification:", sB_weierstrass.x === R_plus_hA.x && sB_weierstrass.y === R_plus_hA.y);
}