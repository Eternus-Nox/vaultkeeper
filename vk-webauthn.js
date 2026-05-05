// ────────────────────────────────────────────────────────────────────────
// vk-webauthn.js — WebAuthn (passkey / Face ID / Touch ID / Hello) module.
//
// Adds passkey-based unlock to VaultKeeper while preserving zero-knowledge:
//
//   • The passkey lives in the device's secure hardware (Secure Enclave on
//     iOS, TPM on Windows, etc). Server never sees the private key.
//   • The user's symKey (the random 64-byte vault key) is encrypted with a
//     DEK derived from the passkey's PRF output. Server stores the
//     ciphertext; only the passkey can unwrap it.
//   • Server can't decrypt without the PRF output. Passkey can't decrypt
//     without the server-stored ciphertext. Both are required.
//
// Endpoints (all under /api/auth/webauthn):
//   POST   /register-options   — challenge for credential creation
//   POST   /register           — finalize registration + store encrypted blob
//   POST   /login-options      — challenge + allowCredentials for assertion
//                                (or no allowCredentials for discoverable)
//   POST   /login              — verify assertion, return JWT + encrypted blob
//   GET    /list               — list user's enrolled credentials
//   DELETE /:credentialId      — remove a credential
//
// We use @simplewebauthn/server only to GENERATE registration / authentication
// options (challenge + structure). All VERIFICATION is done manually with
// Node's crypto module, because @simplewebauthn/server v11 has a known
// strict-validation issue that rejects RP-IDs / base64url fields that
// actually validate correctly when checked manually. Manual verification is
// straightforward enough that it's safer than fighting the library.
// ────────────────────────────────────────────────────────────────────────

const {
  generateRegistrationOptions,
  generateAuthenticationOptions,
} = require('@simplewebauthn/server');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

const RP_NAME = process.env.WEBAUTHN_RP_NAME || 'VaultKeeper';

// Challenges expire after 5 minutes. Stored in DB so they survive restarts.
const CHALLENGE_TTL_MS = 5 * 60 * 1000;


// ──── COSE EC2 P-256 → SPKI conversion ─────────────────────────────────
//
// WebAuthn returns the credential's public key in COSE format. To verify
// signatures with Node's crypto module we need it in SPKI/DER. COSE EC2
// P-256 keys are CBOR maps with: 1=2 (kty=EC2), 3=-7 (alg=ES256),
// -1=1 (crv=P-256), -2=X(32B), -3=Y(32B). We do a tiny CBOR parse to
// extract X and Y, then assemble a fixed SPKI envelope.
function coseEcdsaToSpki(coseBuf) {
  try {
    const buf = Buffer.from(coseBuf);
    let i = 0;
    const initial = buf[i++];
    if ((initial >> 5) !== 5) return null; // not a CBOR map

    let mapLen = initial & 0x1f;
    if (mapLen === 24) mapLen = buf[i++];
    else if (mapLen === 25) { mapLen = buf.readUInt16BE(i); i += 2; }

    let x = null, y = null;
    for (let n = 0; n < mapLen; n++) {
      // Parse key (signed int)
      const keyByte = buf[i++];
      const keyMajor = keyByte >> 5;
      let keyVal;
      if (keyMajor === 0) {
        keyVal = keyByte & 0x1f;
        if (keyVal === 24) keyVal = buf[i++];
      } else if (keyMajor === 1) {
        let v = keyByte & 0x1f;
        if (v === 24) v = buf[i++];
        keyVal = -1 - v;
      } else return null;

      // Parse value
      const valByte = buf[i++];
      const valMajor = valByte >> 5;
      if (valMajor === 0 || valMajor === 1) {
        let v = valByte & 0x1f;
        if (v === 24) i++; // 1-byte uint
      } else if (valMajor === 2) {
        let bsLen = valByte & 0x1f;
        if (bsLen === 24) bsLen = buf[i++];
        else if (bsLen === 25) { bsLen = buf.readUInt16BE(i); i += 2; }
        const bytes = buf.slice(i, i + bsLen);
        i += bsLen;
        if (keyVal === -2) x = bytes;
        else if (keyVal === -3) y = bytes;
      } else return null;
    }
    if (!x || !y || x.length !== 32 || y.length !== 32) return null;

    // Build SPKI for ECDSA P-256:
    //   SEQ { SEQ { OID ecPublicKey, OID prime256v1 } BITSTRING { 04||X||Y } }
    const algSeq = Buffer.concat([
      Buffer.from([0x30, 0x13]),
      Buffer.from('06072A8648CE3D0201', 'hex'),     // OID 1.2.840.10045.2.1
      Buffer.from('06082A8648CE3D030107', 'hex'),  // OID 1.2.840.10045.3.1.7
    ]);
    const point = Buffer.concat([Buffer.from([0x04]), x, y]); // 65 bytes
    const bitString = Buffer.concat([
      Buffer.from([0x03, point.length + 1, 0x00]),
      point,
    ]);
    const inner = Buffer.concat([algSeq, bitString]);
    return Buffer.concat([
      Buffer.from([0x30, 0x82, (inner.length >> 8) & 0xff, inner.length & 0xff]),
      inner,
    ]);
  } catch {
    return null;
  }
}


// ──── Configuration helpers ────────────────────────────────────────────

function getRpId(req) {
  if (process.env.WEBAUTHN_RP_ID) return process.env.WEBAUTHN_RP_ID;
  return (req.headers.host || 'localhost').split(':')[0];
}

function getOrigin(req) {
  if (process.env.WEBAUTHN_ORIGIN) return process.env.WEBAUTHN_ORIGIN;
  return `${req.protocol}://${req.headers.host || 'localhost'}`;
}


// ──── Schema migration ────────────────────────────────────────────────

async function ensureSchema(pool) {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS webauthn_credentials (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      credential_id TEXT UNIQUE NOT NULL,
      public_key TEXT NOT NULL,
      counter BIGINT NOT NULL DEFAULT 0,
      device_name TEXT,
      transports TEXT[],
      encrypted_blob TEXT NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      last_used_at TIMESTAMPTZ
    );
    CREATE INDEX IF NOT EXISTS idx_webauthn_user
      ON webauthn_credentials(user_id);

    CREATE TABLE IF NOT EXISTS webauthn_challenges (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      challenge TEXT UNIQUE NOT NULL,
      kind TEXT NOT NULL CHECK (kind IN ('registration', 'authentication')),
      expires_at TIMESTAMPTZ NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS idx_webauthn_challenge
      ON webauthn_challenges(challenge);
    CREATE INDEX IF NOT EXISTS idx_webauthn_challenge_expires
      ON webauthn_challenges(expires_at);
  `);
}

async function cleanupExpiredChallenges(pool) {
  await pool.query(`DELETE FROM webauthn_challenges WHERE expires_at < NOW()`);
}


// ──── Challenge helpers ────────────────────────────────────────────────

async function storeChallenge(pool, userId, challenge, kind) {
  await pool.query(
    `INSERT INTO webauthn_challenges (user_id, challenge, kind, expires_at)
     VALUES ($1, $2, $3, $4)`,
    [userId, challenge, kind, new Date(Date.now() + CHALLENGE_TTL_MS)]
  );
}

async function consumeChallenge(pool, challenge, kind) {
  const result = await pool.query(
    `DELETE FROM webauthn_challenges
     WHERE challenge = $1 AND kind = $2 AND expires_at > NOW()
     RETURNING user_id`,
    [challenge, kind]
  );
  return result.rows[0] || null;
}


// ──── Manual verification ──────────────────────────────────────────────
//
// Both registration and authentication go through the same checks. The
// authenticator's response is bound to:
//   • the challenge we issued (replay protection)
//   • the origin where the request was made (phishing protection)
//   • our RP ID via SHA-256 hash in authData (origin pinning)
// Plus, for authentication, the assertion signature is verified against
// the stored public key (proves possession of the private key).

function verifyClientData(clientDataJSONB64, expectedChallenge, expectedOrigin, expectedType) {
  const json = Buffer.from(clientDataJSONB64, 'base64').toString('utf8');
  const data = JSON.parse(json);
  if (data.type !== expectedType) {
    return { ok: false, reason: 'wrong_type', got: data.type };
  }
  if (data.challenge !== expectedChallenge) {
    return { ok: false, reason: 'challenge_mismatch' };
  }
  if (data.origin !== expectedOrigin) {
    return { ok: false, reason: 'origin_mismatch', got: data.origin };
  }
  return { ok: true };
}

function verifyRpIdHash(rpIdHash, expectedRPID) {
  const expected = crypto.createHash('sha256').update(expectedRPID).digest();
  return expected.equals(rpIdHash);
}

// Parse the WebAuthn `authData` byte string. Layout:
//   rpIdHash (32) + flags (1) + counter (4) [+ AAGUID (16) + credIdLen (2)
//   + credId + pubKeyCBOR + extensions] when flags bit 0x40 is set.
function parseAuthData(authData) {
  if (authData.length < 37) return null;
  return {
    rpIdHash: authData.slice(0, 32),
    flags: authData[32],
    counter: authData.readUInt32BE(33),
    raw: authData,
  };
}

// Pull authData from a CBOR-encoded attestationObject. attestationObject
// is a CBOR map with key "authData" (text-string) → byte-string. We do a
// shallow scan rather than full CBOR decode — the byte string after the
// "authData" marker is unambiguously identifiable.
function extractAuthDataFromAttestation(attObjB64) {
  const buf = Buffer.from(attObjB64, 'base64');
  const marker = Buffer.from('authData');
  const idx = buf.indexOf(marker);
  if (idx < 0) return null;

  // After "authData" comes a CBOR byte-string header.
  // 0x40-0x57 = small (length encoded in low 5 bits)
  // 0x58 = 1-byte length follows
  // 0x59 = 2-byte length follows (big-endian)
  const hdr = buf[idx + marker.length];
  let dataStart, dataLen;
  if (hdr === 0x58) {
    dataLen = buf[idx + marker.length + 1];
    dataStart = idx + marker.length + 2;
  } else if (hdr === 0x59) {
    dataLen = buf.readUInt16BE(idx + marker.length + 1);
    dataStart = idx + marker.length + 3;
  } else if (hdr >= 0x40 && hdr <= 0x57) {
    dataLen = hdr & 0x1f;
    dataStart = idx + marker.length + 1;
  } else {
    return null;
  }
  return buf.slice(dataStart, dataStart + dataLen);
}

// Parse credentialId + COSE public key out of the attested-credential
// data section of authData (only present at registration time).
function extractAttestedCredential(authData) {
  if (!(authData[32] & 0x40)) return null; // no AT bit
  if (authData.length < 55) return null;
  const credIdLen = authData.readUInt16BE(53);
  if (authData.length < 55 + credIdLen) return null;
  const credentialID = authData.slice(55, 55 + credIdLen);
  const credentialPublicKey = authData.slice(55 + credIdLen);
  return { credentialID, credentialPublicKey };
}


// ──── Routes ──────────────────────────────────────────────────────────

function mount(app, { pool, auth, ah, JWT_SECRET, authLimiter }) {

  // ── Registration: enroll a new passkey for an authenticated user ──

  app.post('/api/auth/webauthn/register-options', auth, ah(async (req, res) => {
    const userId = req.user.id;
    const username = req.user.username;

    const existing = await pool.query(
      `SELECT credential_id, transports FROM webauthn_credentials WHERE user_id = $1`,
      [userId]
    );

    const options = await generateRegistrationOptions({
      rpName: RP_NAME,
      rpID: getRpId(req),
      userID: Buffer.from(String(userId)),
      userName: username,
      userDisplayName: username,
      timeout: 60_000,
      attestationType: 'none',
      excludeCredentials: existing.rows.map(r => ({
        id: r.credential_id,
        transports: r.transports || ['internal'],
      })),
      authenticatorSelection: {
        authenticatorAttachment: 'platform',
        userVerification: 'required',
        residentKey: 'preferred',
      },
      extensions: { prf: {} },
      supportedAlgorithmIDs: [-7, -257],
    });

    await storeChallenge(pool, userId, options.challenge, 'registration');
    res.json(options);
  }));

  app.post('/api/auth/webauthn/register', auth, ah(async (req, res) => {
    const userId = req.user.id;
    const { credential, deviceName, encryptedBlob } = req.body || {};

    if (!credential || !encryptedBlob) {
      return res.status(400).json({ error: 'missing_fields' });
    }

    // Parse clientDataJSON to extract the challenge, then validate
    let parsedClient;
    try {
      parsedClient = JSON.parse(
        Buffer.from(credential.response.clientDataJSON, 'base64').toString('utf8')
      );
    } catch {
      return res.status(400).json({ error: 'bad_client_data' });
    }

    const challengeRow = await consumeChallenge(pool, parsedClient.challenge, 'registration');
    if (!challengeRow || challengeRow.user_id !== userId) {
      return res.status(400).json({ error: 'invalid_challenge' });
    }

    const expectedOrigin = getOrigin(req);
    const expectedRPID = getRpId(req);

    // Origin / type / challenge check
    const cdCheck = verifyClientData(
      credential.response.clientDataJSON,
      parsedClient.challenge,
      expectedOrigin,
      'webauthn.create'
    );
    if (!cdCheck.ok) {
      return res.status(400).json({ error: 'client_data_invalid', reason: cdCheck.reason });
    }

    // Extract authData from CBOR attestationObject
    const authData = extractAuthDataFromAttestation(credential.response.attestationObject);
    if (!authData) {
      return res.status(400).json({ error: 'bad_attestation_object' });
    }
    const parsedAuth = parseAuthData(authData);
    if (!parsedAuth) {
      return res.status(400).json({ error: 'bad_auth_data' });
    }

    // RP ID hash check (origin pinning)
    if (!verifyRpIdHash(parsedAuth.rpIdHash, expectedRPID)) {
      return res.status(400).json({ error: 'rpid_mismatch' });
    }

    // User Verification flag (Face ID / Touch ID / PIN happened)
    if (!(parsedAuth.flags & 0x04)) {
      return res.status(400).json({ error: 'user_verification_required' });
    }

    // Extract the credential ID + public key from the attested data
    const attested = extractAttestedCredential(authData);
    if (!attested) {
      return res.status(400).json({ error: 'no_attested_credential' });
    }

    // Validate the encrypted blob structure (we can't decrypt — by design)
    let blobObj;
    try {
      blobObj = JSON.parse(encryptedBlob);
      if (!blobObj.v || !blobObj.ciphertext || !blobObj.iv) {
        throw new Error('missing_fields');
      }
    } catch {
      return res.status(400).json({ error: 'bad_blob' });
    }

    const credIdStr = attested.credentialID.toString('base64url');
    const pubKeyStr = attested.credentialPublicKey.toString('base64');
    const transports = Array.isArray(credential.response?.transports)
      ? credential.response.transports
      : ['internal'];

    await pool.query(
      `INSERT INTO webauthn_credentials
        (user_id, credential_id, public_key, counter, device_name, transports, encrypted_blob)
       VALUES ($1, $2, $3, $4, $5, $6, $7)`,
      [userId, credIdStr, pubKeyStr, parsedAuth.counter,
       (deviceName || 'Device').slice(0, 100),
       transports, encryptedBlob]
    );

    res.json({ ok: true, credentialId: credIdStr });
  }));


  // ── Authentication: log in with a passkey ──

  app.post('/api/auth/webauthn/login-options', authLimiter, ah(async (req, res) => {
    const { username } = req.body || {};

    // No username → discoverable credentials mode (used by Conditional UI
    // / passkey autofill on iOS). The browser picks the credential from
    // the user's available passkeys for this RP.
    if (!username) {
      const options = await generateAuthenticationOptions({
        rpID: getRpId(req),
        timeout: 60_000,
        userVerification: 'required',
        extensions: { prf: {} },
      });
      // user_id NULL on the challenge row → can be claimed by any user.
      await pool.query(
        `INSERT INTO webauthn_challenges (user_id, challenge, kind, expires_at)
         VALUES (NULL, $1, $2, $3)`,
        [options.challenge, 'authentication',
         new Date(Date.now() + CHALLENGE_TTL_MS)]
      );
      return res.json(options);
    }

    // Username given → return options scoped to that user's credentials
    const userQ = await pool.query(
      `SELECT id FROM users WHERE username = $1`,
      [username]
    );
    if (!userQ.rows[0]) {
      return res.status(404).json({ error: 'no_passkeys' });
    }
    const userId = userQ.rows[0].id;

    const credsQ = await pool.query(
      `SELECT credential_id, transports FROM webauthn_credentials WHERE user_id = $1`,
      [userId]
    );
    if (!credsQ.rows.length) {
      return res.status(404).json({ error: 'no_passkeys' });
    }

    const options = await generateAuthenticationOptions({
      rpID: getRpId(req),
      timeout: 60_000,
      allowCredentials: credsQ.rows.map(r => ({
        id: r.credential_id,
        transports: r.transports || ['internal'],
      })),
      userVerification: 'required',
      extensions: { prf: {} },
    });

    await storeChallenge(pool, userId, options.challenge, 'authentication');
    res.json(options);
  }));

  app.post('/api/auth/webauthn/login', authLimiter, ah(async (req, res) => {
    const { username, credential } = req.body || {};
    if (!credential) {
      return res.status(400).json({ error: 'missing_credential' });
    }

    let parsedClient;
    try {
      parsedClient = JSON.parse(
        Buffer.from(credential.response.clientDataJSON, 'base64').toString('utf8')
      );
    } catch {
      return res.status(400).json({ error: 'bad_client_data' });
    }

    // Find the credential by ID — this also tells us which user it belongs to.
    // For discoverable credentials (no username sent) this is how we identify
    // the user.
    const credId = credential.id || credential.rawId;
    const credQ = await pool.query(
      `SELECT c.credential_id, c.public_key, c.counter, c.encrypted_blob,
              c.user_id, u.username, u.token_version
       FROM webauthn_credentials c
       JOIN users u ON u.id = c.user_id
       WHERE c.credential_id = $1`,
      [credId]
    );
    if (!credQ.rows[0]) {
      return res.status(401).json({ error: 'unknown_credential' });
    }
    const cred = credQ.rows[0];

    // If a username was provided (legacy/explicit flow), verify it matches
    if (username && username !== cred.username) {
      return res.status(401).json({ error: 'username_mismatch' });
    }

    // Validate + consume the challenge
    const challengeRow = await consumeChallenge(pool, parsedClient.challenge, 'authentication');
    if (!challengeRow) {
      return res.status(400).json({ error: 'invalid_challenge' });
    }
    if (challengeRow.user_id !== null && challengeRow.user_id !== cred.user_id) {
      return res.status(400).json({ error: 'challenge_user_mismatch' });
    }

    const expectedOrigin = getOrigin(req);
    const expectedRPID = getRpId(req);

    // Origin / type / challenge check
    const cdCheck = verifyClientData(
      credential.response.clientDataJSON,
      parsedClient.challenge,
      expectedOrigin,
      'webauthn.get'
    );
    if (!cdCheck.ok) {
      return res.status(401).json({ error: 'client_data_invalid', reason: cdCheck.reason });
    }

    // Parse authData
    const authDataBuf = Buffer.from(credential.response.authenticatorData, 'base64');
    const parsedAuth = parseAuthData(authDataBuf);
    if (!parsedAuth) {
      return res.status(401).json({ error: 'bad_auth_data' });
    }

    // RP ID hash check
    if (!verifyRpIdHash(parsedAuth.rpIdHash, expectedRPID)) {
      return res.status(401).json({ error: 'rpid_mismatch' });
    }

    // User Verification flag
    if (!(parsedAuth.flags & 0x04)) {
      return res.status(401).json({ error: 'user_verification_required' });
    }

    // Anti-replay counter. Only enforce monotonic increase if
    // the authenticator actually maintains a counter (some don't, in which
    // case both stored and new counter remain 0).
    const newCounter = parsedAuth.counter;
    const oldCounter = Number(cred.counter);
    if (newCounter !== 0 && newCounter <= oldCounter) {
      return res.status(401).json({ error: 'counter_replay' });
    }

    // Verify the assertion signature.
    // signature is over: authData || sha256(clientDataJSON)
    const cdjsonBuf = Buffer.from(credential.response.clientDataJSON, 'base64');
    const cdjsonHash = crypto.createHash('sha256').update(cdjsonBuf).digest();
    const signedData = Buffer.concat([authDataBuf, cdjsonHash]);
    const sigBuf = Buffer.from(credential.response.signature, 'base64');

    const cosePubKey = Buffer.from(cred.public_key, 'base64');
    const spki = coseEcdsaToSpki(cosePubKey);
    if (!spki) {
      return res.status(500).json({ error: 'pubkey_parse_failed' });
    }

    const verifier = crypto.createVerify('sha256');
    verifier.update(signedData);
    const sigOK = verifier.verify(
      { key: spki, format: 'der', type: 'spki' },
      sigBuf
    );
    if (!sigOK) {
      return res.status(401).json({ error: 'bad_signature' });
    }

    // Update counter + last-used timestamp
    await pool.query(
      `UPDATE webauthn_credentials
       SET counter = $1, last_used_at = NOW()
       WHERE credential_id = $2`,
      [newCounter, cred.credential_id]
    );
    await pool.query(
      `UPDATE users SET last_login_at = NOW() WHERE id = $1`,
      [cred.user_id]
    );

    // Issue JWT and return the encrypted blob (client-side will decrypt
    // with the PRF-derived DEK to recover the symKey)
    const token = jwt.sign(
      { id: cred.user_id, username: cred.username, tv: cred.token_version },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({
      token,
      username: cred.username,
      encryptedBlob: cred.encrypted_blob,
    });
  }));


  // ── Management ──

  app.get('/api/auth/webauthn/list', auth, ah(async (req, res) => {
    const result = await pool.query(
      `SELECT credential_id, device_name, created_at, last_used_at
       FROM webauthn_credentials
       WHERE user_id = $1
       ORDER BY created_at DESC`,
      [req.user.id]
    );
    res.json({ credentials: result.rows });
  }));

  app.delete('/api/auth/webauthn/:credentialId', auth, ah(async (req, res) => {
    const result = await pool.query(
      `DELETE FROM webauthn_credentials
       WHERE user_id = $1 AND credential_id = $2`,
      [req.user.id, req.params.credentialId]
    );
    if (result.rowCount === 0) {
      return res.status(404).json({ error: 'not_found' });
    }
    res.json({ ok: true });
  }));
}


module.exports = {
  mount,
  ensureSchema,
  cleanupExpiredChallenges,
};
