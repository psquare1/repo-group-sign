function parseRSAPublicKey(keyString) {
    const parts = keyString.trim().split(/\s+/);
    if (parts.length < 2 || parts[0] !== "ssh-rsa") {
        throw new Error("Invalid key format: Keys must begin with 'ssh-rsa'");
    }
    const keyData = atob(parts[1]);
    // Helper to read big-endian 4-byte int
    function readUint32(bytes, offset) {
        return (
            (bytes[offset] << 24) |
            (bytes[offset + 1] << 16) |
            (bytes[offset + 2] << 8) |
            (bytes[offset + 3])
        ) >>> 0;
    }
    // Convert string to byte array
    const bytes = [];
    for (let i = 0; i < keyData.length; i++) {
        bytes.push(keyData.charCodeAt(i));
    }
    let offset = 0;
    // Read "ssh-rsa"
    const typeLen = readUint32(bytes, offset);
    offset += 4;
    const type = String.fromCharCode(...bytes.slice(offset, offset + typeLen));
    offset += typeLen;
    if (type !== "ssh-rsa") {
        throw new Error("Not an ssh-rsa key: Key format not recognized");
    }
    // Read exponent
    const eLen = readUint32(bytes, offset);
    offset += 4 + eLen;
    // Read modulus
    const nLen = readUint32(bytes, offset);
    offset += 4;
    const nBytes = bytes.slice(offset, offset + nLen);
    // Convert modulus bytes to hex string
    let hex = "";
    for (let b of nBytes) {
        hex += b.toString(16).padStart(2, "0");
    }
    // Convert hex to BigInt
    const modulus = BigInt("0x" + hex);
    return modulus;
}

function splitBigIntToChunks(bigint, chunkBits = 120, numChunks = 35) {
    const chunks = [];
    const mask = (1n << BigInt(chunkBits)) - 1n;
    for (let i = 0n; i < BigInt(numChunks); i++) {
        chunks.push(String((bigint & (mask << (i * BigInt(chunkBits)))) >> (i * BigInt(chunkBits))));
    }
    return chunks;
}

// helper: SHA-512 via Web Crypto
async function sha512(data) {
  // data: ArrayBuffer or TypedArray
  const hashBuffer = await crypto.subtle.digest('SHA-512', data);
  return new Uint8Array(hashBuffer);
}

// helper: encode a JS string to UTF-8 bytes
function str2bytes(str) {
  return new TextEncoder().encode(str);
}

// helper: pack an SSH string (4-byte BE length + data)
function sshString(bytes) {
  const len = bytes.length;
  const out = new Uint8Array(4 + len);
  // write length big-endian
  out[0] = (len >>> 24) & 0xff;
  out[1] = (len >>> 16) & 0xff;
  out[2] = (len >>> 8 ) & 0xff;
  out[3] = (len       ) & 0xff;
  out.set(bytes, 4);
  return out;
}

// helper: concat many Uint8Arrays
function concat(...arrays) {
  const totalLen = arrays.reduce((sum, a) => sum + a.length, 0);
  const out = new Uint8Array(totalLen);
  let offset = 0;
  for (const arr of arrays) {
    out.set(arr, offset);
    offset += arr.length;
  }
  return out;
}

// helper: hex string → Uint8Array
function hex2bytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substr(2*i, 2), 16);
  }
  return bytes;
}

// helper: Uint8Array → hex string
function bytes2hex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

// converts text message to BigInt m
async function messageToBigInt(msgStr) {
  const msgBytes    = str2bytes(msgStr);
  const MAGIC       = str2bytes('SSHSIG');
  const NAMESPACE   = str2bytes('file');
  const HASHALG     = str2bytes('sha512');
  const k           = 512;  // modulus length in bytes
  
  // 1) inner hash: H1 = SHA512(msg)
  const H1 = await sha512(msgBytes);

  // 2) wrapper = MAGIC || sshString(NAMESPACE) || sshString(empty) || sshString(HASHALG) || sshString(H1)
  const wrapper = concat(
    MAGIC,
    sshString(NAMESPACE),
    sshString(new Uint8Array(0)),
    sshString(HASHALG),
    sshString(H1)
  );

  // 3) digestInfo prefix for SHA-512 (ASN.1 DER header)
  const digestinfoPrefix = hex2bytes('3051300d060960864801650304020305000440');

  // 4) outer hash: H2 = SHA512(wrapper)
  const H2 = await sha512(wrapper);

  // 5) digestinfo = prefix || H2
  const digestinfo = concat(digestinfoPrefix, H2);

  // 6) build EM = 0x00‖0x01‖PS‖0x00‖digestinfo
  const psLen = k - 3 - digestinfo.length;
  const PS    = new Uint8Array(psLen).fill(0xff);
  const EM    = concat(
    new Uint8Array([0x00, 0x01]),
    PS,
    new Uint8Array([0x00]),
    digestinfo
  );

  let output = BigInt("0x" + bytes2hex(EM));
  console.log(typeof output);
  return output;
}

function parseSSHSignature(b64) {
    // Decode Base64 to a Uint8Array
    const binStr = atob(b64);
    const buf = new Uint8Array(binStr.length);
    for (let i = 0; i < binStr.length; i++) {
      buf[i] = binStr.charCodeAt(i);
    }
    const dv = new DataView(buf.buffer);
  
    let offset = 0;
    // 1) Check the ASCII magic "SSHSIG"
    const magic = String.fromCharCode(...buf.slice(0, 6));
    if (magic !== "SSHSIG") {
      throw new Error("Invalid SSHSIG magic; expected 'SSHSIG'");
    }
    offset += 6;
  
    // 2) Read version (uint32)
    const version = dv.getUint32(offset, false);
    offset += 4;
    if (version !== 1) {
      throw new Error("Unsupported SSHSIG version " + version);
    }
  
    // 3) Read an SSH string: publickey
    const readString = () => {
      const len = dv.getUint32(offset, false);
      offset += 4;
      const bytes = buf.slice(offset, offset + len);
      offset += len;
      return bytes;
    };
    const publickeyBlob = readString();
  
    // 4) Skip namespace, reserved, and hash_algorithm
    readString(); // namespace
    readString(); // reserved
    readString(); // hash_algorithm
  
    // 5) Read the signature field (itself an SSH string)
    const sigBlob = readString();
  
    // --- Now parse publickeyBlob as an SSH-encoded "ssh-rsa" key:
    //    string    "ssh-rsa"
    //    mpint     e
    //    mpint     n
    const pkDv = new DataView(publickeyBlob.buffer);
    let pkOff = 0;
    // skip the algorithm name
    const nameLen = pkDv.getUint32(pkOff, false);
    pkOff += 4 + nameLen;
    // skip the exponent e mpint
    const eLen = pkDv.getUint32(pkOff, false);
    pkOff += 4 + eLen;
    // read the modulus n mpint
    const nLen = pkDv.getUint32(pkOff, false);
    pkOff += 4;
    const nBytes = publickeyBlob.slice(pkOff, pkOff + nLen);
    
    const publicKey = bytesToBigInt(nBytes);
  
    // --- Now parse the sigBlob as:
    //    string   sig-algo (e.g. "rsa-sha2-512")
    //    string   mpint signature
    const sDv = new DataView(sigBlob.buffer);
    let sOff = 0;
    const algoLen = sDv.getUint32(sOff, false);
    sOff += 4 + algoLen;
    const sigLen = sDv.getUint32(sOff, false);
    sOff += 4;
    const sigBytes = sigBlob.slice(sOff, sOff + sigLen);
    const signature = bytesToBigInt(sigBytes);
  
    return { signature, publicKey };
  
    // Helper: big-endian bytes → BigInt
    function bytesToBigInt(bytes) {
      let hex = [];
      for (let b of bytes) {
        hex.push(b.toString(16).padStart(2, "0"));
      }
      return BigInt("0x" + hex.join(""));
    }
}

// Make all helper functions available globally
window.parseRSAPublicKey = parseRSAPublicKey;
window.splitBigIntToChunks = splitBigIntToChunks;
window.sha512 = sha512;
window.str2bytes = str2bytes;
window.sshString = sshString;
window.concat = concat;
window.hex2bytes = hex2bytes;
window.bytes2hex = bytes2hex;
window.messageToBigInt = messageToBigInt;
window.parseSSHSignature = parseSSHSignature;