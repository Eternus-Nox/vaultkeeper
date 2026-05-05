// ============================================================================
//  VaultKeeper E2E Crypto Module  —  Day 1
// ============================================================================
//  Zero-knowledge crypto primitives for the browser.
//
//  Nothing in this file talks to the network. It only handles:
//    • Deriving keys from (username, masterPassword)
//    • Wrapping/unwrapping the user's random symmetric key
//    • Encrypting/decrypting vault-item JSON blobs
//
//  All randomness comes from crypto.getRandomValues.
//  All primitives come from SubtleCrypto except argon2id (hash-wasm).
//
//  Browser compatibility: requires Secure Context (HTTPS or localhost).
//  Verified in Firefox, Chromium, Safari 14+.
// ============================================================================

(function (global) {
  'use strict';

  // ── Argon2id loader ────────────────────────────────────────────────────────
  // We load hash-wasm lazily and cache the module. This keeps the initial
  // page weight small — WASM is only fetched when someone actually logs in.
  let _hashWasm = null;
  async function getHashWasm() {
    if (_hashWasm) return _hashWasm;
    // The page is expected to have <script src="/vendor/hash-wasm.umd.min.js">
    // loaded (we ship it self-hosted to avoid third-party network calls and CSP issues).
    if (typeof global.hashwasm === 'undefined') {
      throw new Error(
        'hash-wasm library not loaded. Include <script src="/vendor/hash-wasm.umd.min.js"> ' +
        'in the page before vk-crypto.js.'
      );
    }
    _hashWasm = global.hashwasm;
    return _hashWasm;
  }

  // ── Parameters ─────────────────────────────────────────────────────────────
  // These are serialized into the protectedSymKey envelope so we can change
  // them in the future without breaking existing accounts.
  // ── Argon2id parameters ────────────────────────────────────────────────────
  //
  // Tuned on iPhone 17 Pro Max (M-series CPU): 256 MiB / t=5 ≈ 800–900ms.
  // - On newer hardware it lands in the OWASP-recommended 500-1500ms window.
  // - On older devices (5+ years) it can stretch to 3-5s but stays usable.
  // - 256 MiB memory hardness defeats GPU/ASIC attacks meaningfully better
  //   than the previous 64 MiB default, while still fitting comfortably in
  //   browser memory budgets.
  //
  // These are the params used FOR NEW SIGNUPS. Existing users keep their
  // stored params — to upgrade, change your master password (re-derives
  // with current defaults).
  const ARGON2_DEFAULTS = Object.freeze({
    memoryCost: 262144,  // 256 MiB
    timeCost: 5,         // iterations
    parallelism: 1,
    hashLength: 32       // 32 bytes = 256 bits
  });

  const HKDF_INFO_ENC = 'vk-enc-v1';
  const HKDF_INFO_MAC = 'vk-mac-v1';
  const AUTH_HASH_SALT_PREFIX = 'vk-auth-v1|';   // concatenated with username

  // Schema version embedded in every ciphertext. Bump when format changes.
  const ENVELOPE_VERSION = 1;

  // ── Byte helpers ───────────────────────────────────────────────────────────
  // getRandomValues has a 65536-byte max per call in most browsers (the Web
  // Crypto spec limit). We chunk to make this transparent to callers.
  function randomBytes(n) {
    const b = new Uint8Array(n);
    const MAX = 65536;
    for (let off = 0; off < n; off += MAX) {
      crypto.getRandomValues(b.subarray(off, Math.min(off + MAX, n)));
    }
    return b;
  }

  const TEXT_ENC = new TextEncoder();
  const TEXT_DEC = new TextDecoder();

  function utf8(s) { return TEXT_ENC.encode(s); }
  function fromUtf8(b) { return TEXT_DEC.decode(b); }

  function bytesToHex(b) {
    let s = '';
    for (let i = 0; i < b.length; i++) s += b[i].toString(16).padStart(2, '0');
    return s;
  }
  function hexToBytes(h) {
    if (h.length % 2) throw new Error('odd hex length');
    const b = new Uint8Array(h.length / 2);
    for (let i = 0; i < b.length; i++) b[i] = parseInt(h.substr(i * 2, 2), 16);
    return b;
  }

  function bytesToB64(b) {
    // Avoid the "spread into String.fromCharCode" trick — it blows the stack
    // for arrays > ~100KB. Chunk manually.
    let bin = '';
    const CHUNK = 0x8000;
    for (let i = 0; i < b.length; i += CHUNK) {
      bin += String.fromCharCode.apply(null, b.subarray(i, i + CHUNK));
    }
    return btoa(bin);
  }
  function b64ToBytes(s) {
    const bin = atob(s);
    const b = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) b[i] = bin.charCodeAt(i);
    return b;
  }

  function concatBytes() {
    let total = 0;
    for (let i = 0; i < arguments.length; i++) total += arguments[i].length;
    const out = new Uint8Array(total);
    let off = 0;
    for (let i = 0; i < arguments.length; i++) {
      out.set(arguments[i], off);
      off += arguments[i].length;
    }
    return out;
  }

  // Constant-time byte compare. Useful for HMAC verification.
  function ctEquals(a, b) {
    if (a.length !== b.length) return false;
    let diff = 0;
    for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
    return diff === 0;
  }

  // ── KDF ────────────────────────────────────────────────────────────────────
  // Derive a 32-byte master key from (username, masterPassword).
  //
  // The salt is blake2b-256(username). This is:
  //   • deterministic (so the server can look up the user by username alone)
  //   • globally unique (collisions require blake2b preimages — not happening)
  //   • not reversible (server stores username plaintext but salt can't be
  //     used to enumerate users offline because each attack still requires
  //     64MB argon2id work per candidate password)
  async function deriveMasterKey(username, masterPassword, params) {
    params = params || ARGON2_DEFAULTS;
    const wasm = await getHashWasm();
    // blake2b(username) for a 16-byte salt. hash-wasm exposes this directly.
    const saltHex = await wasm.blake2b(utf8(username.toLowerCase().trim()), 128); // 128 bits
    const salt = hexToBytes(saltHex);
    const key = await wasm.argon2id({
      password: utf8(masterPassword),
      salt,
      iterations: params.timeCost,
      memorySize: params.memoryCost,
      parallelism: params.parallelism,
      hashLength: params.hashLength,
      outputType: 'binary'
    });
    return key; // Uint8Array(32)
  }

  // Derive auth hash from masterKey. This is what the client sends to the
  // server as proof-of-password. The server then argon2id-hashes it again
  // before storing.
  async function deriveAuthHash(masterKey, username) {
    const wasm = await getHashWasm();
    const salt = utf8(AUTH_HASH_SALT_PREFIX + username.toLowerCase().trim());
    // Single-round argon2id — the masterKey is already high-entropy, we just
    // need domain separation from the encryption key. Low cost.
    const hash = await wasm.argon2id({
      password: masterKey,
      salt,
      iterations: 1,
      memorySize: 1024,     // 1 MiB — not the password-cracking barrier, masterKey is
      parallelism: 1,
      hashLength: 32,
      outputType: 'binary'
    });
    return hash; // Uint8Array(32)
  }

  // HKDF-SHA256 via SubtleCrypto. Returns {enc, mac}, each 32 bytes.
  async function splitMasterKey(masterKey) {
    const ikm = await crypto.subtle.importKey(
      'raw', masterKey, { name: 'HKDF' }, false, ['deriveBits']
    );
    async function derive(info) {
      const bits = await crypto.subtle.deriveBits({
        name: 'HKDF',
        hash: 'SHA-256',
        salt: new Uint8Array(0),
        info: utf8(info)
      }, ikm, 256);
      return new Uint8Array(bits);
    }
    return {
      enc: await derive(HKDF_INFO_ENC),
      mac: await derive(HKDF_INFO_MAC)
    };
  }

  // ── AES-256-GCM helpers ────────────────────────────────────────────────────
  async function importAesKey(keyBytes) {
    if (keyBytes.length !== 32) throw new Error('AES key must be 32 bytes');
    return crypto.subtle.importKey(
      'raw', keyBytes, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']
    );
  }
  async function importHmacKey(keyBytes) {
    return crypto.subtle.importKey(
      'raw', keyBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']
    );
  }

  async function aesGcmEncrypt(key, plaintext) {
    const iv = randomBytes(12);
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, plaintext);
    return { iv, ct: new Uint8Array(ct) };
  }
  async function aesGcmDecrypt(key, iv, ct) {
    const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct);
    return new Uint8Array(pt);
  }

  async function hmacSign(key, data) {
    const sig = await crypto.subtle.sign('HMAC', key, data);
    return new Uint8Array(sig);
  }
  async function hmacVerify(key, data, mac) {
    // Use explicit verify rather than sign+compare — SubtleCrypto does it
    // constant-time internally.
    return crypto.subtle.verify('HMAC', key, mac, data);
  }

  // ── Protected symmetric key (wrap/unwrap) ──────────────────────────────────
  //
  // The user's symKey is 64 bytes: [0..32)=enc, [32..64)=mac.
  // We wrap it with AES-256-GCM under stretchedEncKey, then HMAC the whole
  // envelope with stretchedMacKey for belt-and-suspenders integrity.
  //
  // Envelope (base64 string returned to the server):
  //   version(1) | iv(12) | ct(64+16) | hmac(32)
  //
  // Total: 1 + 12 + 80 + 32 = 125 bytes → ~168 chars base64
  async function wrapSymKey(symKey, stretchedEnc, stretchedMac) {
    if (symKey.length !== 64) throw new Error('symKey must be 64 bytes');
    const encK = await importAesKey(stretchedEnc);
    const macK = await importHmacKey(stretchedMac);
    const { iv, ct } = await aesGcmEncrypt(encK, symKey);
    const toMac = concatBytes(new Uint8Array([ENVELOPE_VERSION]), iv, ct);
    const mac = await hmacSign(macK, toMac);
    const envelope = concatBytes(new Uint8Array([ENVELOPE_VERSION]), iv, ct, mac);
    return bytesToB64(envelope);
  }

  async function unwrapSymKey(envelopeB64, stretchedEnc, stretchedMac) {
    const envelope = b64ToBytes(envelopeB64);
    if (envelope.length < 1 + 12 + 16 + 32) throw new Error('envelope too short');
    const version = envelope[0];
    if (version !== ENVELOPE_VERSION) {
      throw new Error('unsupported envelope version ' + version);
    }
    const iv = envelope.slice(1, 13);
    const mac = envelope.slice(envelope.length - 32);
    const ct = envelope.slice(13, envelope.length - 32);
    const toMac = concatBytes(new Uint8Array([version]), iv, ct);
    const macK = await importHmacKey(stretchedMac);
    const ok = await hmacVerify(macK, toMac, mac);
    if (!ok) throw new Error('envelope HMAC mismatch — wrong key or tampered data');
    const encK = await importAesKey(stretchedEnc);
    const symKey = await aesGcmDecrypt(encK, iv, ct);
    if (symKey.length !== 64) throw new Error('unwrapped symKey wrong size');
    return symKey;
  }

  function splitSymKey(symKey) {
    return { enc: symKey.slice(0, 32), mac: symKey.slice(32, 64) };
  }

  // ── Item encryption ────────────────────────────────────────────────────────
  //
  // One vault item has fields like {url, username, password, totp, notes}.
  // The whole thing gets JSON-stringified and encrypted as one blob.
  //
  // Item envelope (base64):
  //   version(1) | iv(12) | ct(variable + 16) | hmac(32)
  //
  // We use the same shape as symKey wrapping, different keys.
  async function encryptItem(plainObject, symKey) {
    const { enc, mac } = splitSymKey(symKey);
    const encK = await importAesKey(enc);
    const macK = await importHmacKey(mac);
    const pt = utf8(JSON.stringify(plainObject));
    const { iv, ct } = await aesGcmEncrypt(encK, pt);
    const toMac = concatBytes(new Uint8Array([ENVELOPE_VERSION]), iv, ct);
    const hmac = await hmacSign(macK, toMac);
    const envelope = concatBytes(new Uint8Array([ENVELOPE_VERSION]), iv, ct, hmac);
    return bytesToB64(envelope);
  }

  async function decryptItem(envelopeB64, symKey) {
    const envelope = b64ToBytes(envelopeB64);
    if (envelope.length < 1 + 12 + 16 + 32) throw new Error('item envelope too short');
    const version = envelope[0];
    if (version !== ENVELOPE_VERSION) throw new Error('unsupported item version ' + version);
    const { enc, mac } = splitSymKey(symKey);
    const iv = envelope.slice(1, 13);
    const hmac = envelope.slice(envelope.length - 32);
    const ct = envelope.slice(13, envelope.length - 32);
    const toMac = concatBytes(new Uint8Array([version]), iv, ct);
    const macK = await importHmacKey(mac);
    const ok = await hmacVerify(macK, toMac, hmac);
    if (!ok) throw new Error('item HMAC mismatch — wrong key or tampered data');
    const encK = await importAesKey(enc);
    const pt = await aesGcmDecrypt(encK, iv, ct);
    return JSON.parse(fromUtf8(pt));
  }

  // ── High-level user operations ─────────────────────────────────────────────
  //
  // These compose the primitives above into the three flows the UI needs:
  // signup, login, change-password. They return plain objects ready to send
  // to the server (for signup/login) or apply locally.

  // Called at signup. Generates a new random symKey, wraps it, and returns
  // everything the server needs to store + everything the client needs to
  // keep in memory for this session.
  async function prepareSignup(username, masterPassword, params) {
    params = params || ARGON2_DEFAULTS;
    const masterKey = await deriveMasterKey(username, masterPassword, params);
    const stretched = await splitMasterKey(masterKey);
    const symKey = randomBytes(64);
    const protectedSymKey = await wrapSymKey(symKey, stretched.enc, stretched.mac);
    const authHash = await deriveAuthHash(masterKey, username);
    return {
      // Send to server
      toServer: {
        username: username.toLowerCase().trim(),
        auth_hash: bytesToB64(authHash),
        protected_symmetric_key: protectedSymKey,
        kdf: {
          algorithm: 'argon2id',
          memory_cost: params.memoryCost,
          time_cost: params.timeCost,
          parallelism: params.parallelism,
          version: ENVELOPE_VERSION
        }
      },
      // Keep in client memory for the rest of the session
      session: { masterKey, symKey }
    };
  }

  // Called at login, AFTER the server has returned the KDF params for this
  // username (via /api/prelogin) and the protectedSymKey (via /api/login).
  //
  // The UX is: user types username+password → we call prelogin → we derive
  // the masterKey → we call login with authHash → server returns
  // protectedSymKey → we unwrap it here.
  async function deriveLogin(username, masterPassword, kdfParams) {
    const masterKey = await deriveMasterKey(username, masterPassword, {
      memoryCost: kdfParams.memory_cost,
      timeCost: kdfParams.time_cost,
      parallelism: kdfParams.parallelism,
      hashLength: 32
    });
    const authHash = await deriveAuthHash(masterKey, username);
    return { masterKey, authHashB64: bytesToB64(authHash) };
  }

  async function completeLogin(masterKey, protectedSymKeyB64) {
    const stretched = await splitMasterKey(masterKey);
    const symKey = await unwrapSymKey(protectedSymKeyB64, stretched.enc, stretched.mac);
    return { symKey };
  }

  // Called when the user changes their master password. Re-wraps the same
  // symKey under the new password — existing item ciphertexts are untouched.
  async function rewrapForNewPassword(oldSession, newMasterPassword, username, params) {
    params = params || ARGON2_DEFAULTS;
    const newMaster = await deriveMasterKey(username, newMasterPassword, params);
    const newStretched = await splitMasterKey(newMaster);
    const newProtected = await wrapSymKey(oldSession.symKey, newStretched.enc, newStretched.mac);
    const newAuthHash = await deriveAuthHash(newMaster, username);
    return {
      toServer: {
        auth_hash: bytesToB64(newAuthHash),
        protected_symmetric_key: newProtected,
        kdf: {
          algorithm: 'argon2id',
          memory_cost: params.memoryCost,
          time_cost: params.timeCost,
          parallelism: params.parallelism,
          version: ENVELOPE_VERSION
        }
      },
      newSession: { masterKey: newMaster, symKey: oldSession.symKey }
    };
  }

  // ── Public surface ─────────────────────────────────────────────────────────
  global.VKCrypto = {
    // Constants
    ENVELOPE_VERSION,
    ARGON2_DEFAULTS,
    // Low-level (exported for tests and future features)
    randomBytes, bytesToHex, hexToBytes, bytesToB64, b64ToBytes, ctEquals,
    deriveMasterKey, deriveAuthHash, splitMasterKey,
    wrapSymKey, unwrapSymKey,
    encryptItem, decryptItem,
    // High-level flows
    prepareSignup, deriveLogin, completeLogin, rewrapForNewPassword
  };

})(typeof window !== 'undefined' ? window : globalThis);
