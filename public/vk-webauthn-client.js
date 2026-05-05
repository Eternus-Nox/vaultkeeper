// ────────────────────────────────────────────────────────────────────────
// vk-webauthn-client.js — client-side Face ID / passkey integration
//
// Pairs with vk-webauthn.js on the server. See that file's header for the
// full architectural rationale.
//
// Public surface:
//
//   VK_WebAuthn.isSupported()
//     → boolean. True if the browser exposes WebAuthn AND a platform
//       authenticator is available.
//
//   VK_WebAuthn.isPRFSupported()
//     → boolean. True after a registration if the PRF extension worked
//       (we can't know synchronously without trying).
//
//   await VK_WebAuthn.enroll({ stretchedEnc, stretchedMac, deviceName })
//     → Registers a new passkey for the currently-logged-in user. The
//       given stretched keys (already in memory from the password unlock
//       session) are encrypted under a DEK derived from the passkey's
//       PRF output. The encrypted blob is sent to the server along with
//       the credential.
//
//   await VK_WebAuthn.unlock({ username })
//     → Performs a Face ID assertion, retrieves the encrypted blob from
//       the server, decrypts it with the PRF-derived DEK, and returns
//       { token, stretchedEnc, stretchedMac } ready to feed back into
//       the existing vault unlock flow.
//
//   await VK_WebAuthn.list() / await VK_WebAuthn.remove(credentialId)
//     → Management for the Settings UI.
// ────────────────────────────────────────────────────────────────────────

(function () {
  'use strict';

  // ──── Base64url helpers ────────────────────────────────────────────────
  // WebAuthn uses base64url. Web Crypto wants ArrayBuffers. Convert.

  function b64urlToBytes(str) {
    const pad = '='.repeat((4 - (str.length % 4)) % 4);
    const b64 = (str + pad).replace(/-/g, '+').replace(/_/g, '/');
    const bin = atob(b64);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return bytes;
  }

  function bytesToB64url(bytes) {
    const arr = bytes instanceof ArrayBuffer ? new Uint8Array(bytes) : bytes;
    let bin = '';
    for (let i = 0; i < arr.length; i++) bin += String.fromCharCode(arr[i]);
    return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  function bytesToB64(bytes) {
    const arr = bytes instanceof ArrayBuffer ? new Uint8Array(bytes) : bytes;
    let bin = '';
    for (let i = 0; i < arr.length; i++) bin += String.fromCharCode(arr[i]);
    return btoa(bin);
  }

  function b64ToBytes(str) {
    const bin = atob(str);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return bytes;
  }

  // ──── Convert SimpleWebAuthn-style options to WebAuthn API form ────────
  // The server uses @simplewebauthn/server which returns base64url strings.
  // The browser API expects BufferSources for challenge/credential IDs.

  function decodeRegistrationOptions(opts) {
    return {
      ...opts,
      challenge: b64urlToBytes(opts.challenge).buffer,
      user: {
        ...opts.user,
        id: b64urlToBytes(opts.user.id).buffer,
      },
      excludeCredentials: (opts.excludeCredentials || []).map(c => ({
        ...c,
        id: b64urlToBytes(c.id).buffer,
      })),
    };
  }

  function decodeAssertionOptions(opts) {
    return {
      ...opts,
      challenge: b64urlToBytes(opts.challenge).buffer,
      allowCredentials: (opts.allowCredentials || []).map(c => ({
        ...c,
        id: b64urlToBytes(c.id).buffer,
      })),
    };
  }

  // Convert a navigator.credentials.create() result → SimpleWebAuthn form
  function encodeRegistrationCredential(cred) {
    const r = cred.response;
    return {
      id: cred.id,
      rawId: bytesToB64url(cred.rawId),
      type: cred.type,
      response: {
        clientDataJSON: bytesToB64url(r.clientDataJSON),
        attestationObject: bytesToB64url(r.attestationObject),
        transports: typeof r.getTransports === 'function' ? r.getTransports() : [],
      },
      clientExtensionResults: cred.getClientExtensionResults?.() || {},
      authenticatorAttachment: cred.authenticatorAttachment,
    };
  }

  function encodeAssertionCredential(cred) {
    const r = cred.response;
    return {
      id: cred.id,
      rawId: bytesToB64url(cred.rawId),
      type: cred.type,
      response: {
        clientDataJSON: bytesToB64url(r.clientDataJSON),
        authenticatorData: bytesToB64url(r.authenticatorData),
        signature: bytesToB64url(r.signature),
        userHandle: r.userHandle ? bytesToB64url(r.userHandle) : null,
      },
      clientExtensionResults: cred.getClientExtensionResults?.() || {},
      authenticatorAttachment: cred.authenticatorAttachment,
    };
  }

  // ──── PRF + AES-GCM key derivation ─────────────────────────────────────
  //
  // The PRF extension lets us extract a stable 32-byte secret from each
  // assertion. We feed that secret into HKDF to derive an AES-GCM key,
  // which we use to encrypt/decrypt the stretched keys blob.

  // A constant input we send to the PRF on every assertion. The
  // authenticator hashes (input || credential-secret) deterministically,
  // so we always get the same output for the same credential.
  const PRF_INPUT_BYTES = new Uint8Array([
    0x76, 0x6b, 0x70, 0x72, 0x66, 0x76, 0x31, 0x00,  // "vkprfv1\0"
    0x76, 0x61, 0x75, 0x6c, 0x74, 0x6b, 0x65, 0x65,  // "vaultkee"
    0x70, 0x65, 0x72, 0x2e, 0x70, 0x72, 0x66, 0x2e,  // "per.prf."
    0x64, 0x65, 0x6b, 0x2e, 0x76, 0x31, 0x00, 0x00,  // "dek.v1\0\0"
  ]);

  async function deriveDekFromPrf(prfOutput) {
    // prfOutput is an ArrayBuffer from clientExtensionResults.prf.results.first
    const ikm = await crypto.subtle.importKey(
      'raw', prfOutput, { name: 'HKDF' }, false, ['deriveKey']
    );
    return await crypto.subtle.deriveKey(
      {
        name: 'HKDF',
        hash: 'SHA-256',
        salt: new Uint8Array(0),
        info: new TextEncoder().encode('vaultkeeper.passkey.dek.v1'),
      },
      ikm,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  }

  async function encryptBlob(dek, payload) {
    // payload: { stretchedEnc, stretchedMac } as base64 strings
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const plaintext = new TextEncoder().encode(JSON.stringify(payload));
    const ct = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      dek,
      plaintext
    );
    return {
      v: 1,
      ciphertext: bytesToB64(ct),
      iv: bytesToB64(iv),
    };
  }

  async function decryptBlob(dek, blob) {
    if (blob.v !== 1) throw new Error('unsupported_blob_version');
    const ct = b64ToBytes(blob.ciphertext);
    const iv = b64ToBytes(blob.iv);
    const pt = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv },
      dek,
      ct
    );
    return JSON.parse(new TextDecoder().decode(pt));
  }

  // ──── Capability detection ─────────────────────────────────────────────

  function isSupported() {
    return typeof window !== 'undefined'
      && !!window.PublicKeyCredential
      && typeof navigator.credentials?.create === 'function';
  }

  async function isPlatformAuthenticatorAvailable() {
    if (!isSupported()) return false;
    try {
      return await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
    } catch {
      return false;
    }
  }

  // ──── Registration flow ────────────────────────────────────────────────

  async function enroll({ token, symKey, deviceName }) {
    if (!isSupported()) throw new Error('webauthn_unsupported');
    if (!symKey) throw new Error('missing_symkey');

    // 1. Get options from server (challenge, RP info, etc.)
    const optsRes = await fetch('/api/auth/webauthn/register-options', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`,
      },
    });
    if (!optsRes.ok) {
      const msg = await optsRes.text().catch(() => 'unknown');
      throw new Error(`register_options_failed: ${msg}`);
    }
    const opts = await optsRes.json();

    // 2. Inject PRF extension salt (we control the salt; same value at
    //    registration and assertion ⇒ same PRF output)
    opts.extensions = opts.extensions || {};
    opts.extensions.prf = { eval: { first: PRF_INPUT_BYTES.buffer } };

    // 3. Browser prompts for Face ID, creates credential
    const credential = await navigator.credentials.create({
      publicKey: decodeRegistrationOptions(opts),
    });
    if (!credential) throw new Error('credential_creation_cancelled');

    const ext = credential.getClientExtensionResults?.() || {};
    const prfFirst = ext.prf?.results?.first;
    if (!prfFirst) {
      // PRF didn't work — iOS pre-17 or Android without PRF support.
      // Without PRF we can't do zero-knowledge passkey unlock. Bail.
      throw new Error('prf_not_supported');
    }

    // 4. Derive DEK from PRF, encrypt the symKey
    const dek = await deriveDekFromPrf(prfFirst);
    // symKey is a Uint8Array(64). Convert to base64 for JSON transport.
    const symKeyB64 = bytesToB64(symKey);
    const blob = await encryptBlob(dek, { symKey: symKeyB64 });

    // 5. Send credential + blob to server
    const regRes = await fetch('/api/auth/webauthn/register', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({
        credential: encodeRegistrationCredential(credential),
        deviceName: deviceName || 'Device',
        encryptedBlob: JSON.stringify(blob),
      }),
    });
    if (!regRes.ok) {
      const msg = await regRes.text().catch(() => 'unknown');
      throw new Error(`register_failed: ${msg}`);
    }
    return await regRes.json();
  }

  // ──── Authentication flow ──────────────────────────────────────────────

  async function unlock({ username }) {
    if (!isSupported()) throw new Error('webauthn_unsupported');

    // 1. Get options. If username is omitted, server returns options for
    //    discoverable credentials (no allowCredentials list).
    const optsRes = await fetch('/api/auth/webauthn/login-options', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(username ? { username } : {}),
    });
    if (!optsRes.ok) {
      if (optsRes.status === 404) throw new Error('no_passkeys_for_user');
      throw new Error(`login_options_failed`);
    }
    const opts = await optsRes.json();

    // 2. Inject PRF salt (same one as registration)
    opts.extensions = opts.extensions || {};
    opts.extensions.prf = { eval: { first: PRF_INPUT_BYTES.buffer } };

    // 3. Browser prompts for Face ID, returns assertion
    const assertion = await navigator.credentials.get({
      publicKey: decodeAssertionOptions(opts),
    });
    if (!assertion) throw new Error('assertion_cancelled');

    const ext = assertion.getClientExtensionResults?.() || {};
    const prfFirst = ext.prf?.results?.first;
    if (!prfFirst) throw new Error('prf_not_available');

    // 4. Send assertion to server, get JWT + encrypted blob
    const loginRes = await fetch('/api/auth/webauthn/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username: username || undefined,
        credential: encodeAssertionCredential(assertion),
      }),
    });
    if (!loginRes.ok) {
      throw new Error(`login_failed: ${loginRes.status}`);
    }
    const data = await loginRes.json();

    // 5. Decrypt blob with PRF-derived DEK
    const dek = await deriveDekFromPrf(prfFirst);
    const blob = JSON.parse(data.encryptedBlob);
    const payload = await decryptBlob(dek, blob);

    return {
      token: data.token,
      username: data.username || username,
      symKey: b64ToBytes(payload.symKey),
    };
  }

  // ──── Conditional UI / discoverable autofill ───────────────────────────
  //
  // On iOS 18+ and recent Safari, calling navigator.credentials.get with
  // mediation: 'conditional' arms a passive WebAuthn assertion in the
  // background. When the user taps a form field with autocomplete that
  // includes "webauthn", iOS shows a passkey suggestion in the autofill
  // bar above the keyboard. Selecting it triggers Face ID.
  //
  // We start it once on page load. Aborts cleanly on form submit.

  let _conditionalAbort = null;

  async function startConditionalUI(onSuccess) {
    if (!isSupported()) return false;
    if (typeof PublicKeyCredential.isConditionalMediationAvailable !== 'function') return false;
    try {
      const available = await PublicKeyCredential.isConditionalMediationAvailable();
      if (!available) return false;
    } catch {
      return false;
    }

    // Cancel any previous conditional UI session
    if (_conditionalAbort) {
      try { _conditionalAbort.abort(); } catch {}
    }
    _conditionalAbort = new AbortController();

    try {
      // Get discoverable options (no username)
      const optsRes = await fetch('/api/auth/webauthn/login-options', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({}),
      });
      if (!optsRes.ok) return false;
      const opts = await optsRes.json();
      opts.extensions = opts.extensions || {};
      opts.extensions.prf = { eval: { first: PRF_INPUT_BYTES.buffer } };

      const assertion = await navigator.credentials.get({
        publicKey: decodeAssertionOptions(opts),
        mediation: 'conditional',
        signal: _conditionalAbort.signal,
      });
      if (!assertion) return false;

      const ext = assertion.getClientExtensionResults?.() || {};
      const prfFirst = ext.prf?.results?.first;
      if (!prfFirst) {
        console.error('[Passkey] conditional UI: PRF unavailable');
        return false;
      }

      const loginRes = await fetch('/api/auth/webauthn/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          credential: encodeAssertionCredential(assertion),
        }),
      });
      if (!loginRes.ok) return false;
      const data = await loginRes.json();

      const dek = await deriveDekFromPrf(prfFirst);
      const blob = JSON.parse(data.encryptedBlob);
      const payload = await decryptBlob(dek, blob);

      const result = {
        token: data.token,
        username: data.username,
        symKey: b64ToBytes(payload.symKey),
      };
      if (typeof onSuccess === 'function') onSuccess(result);
      return result;
    } catch (err) {
      if (err.name === 'AbortError') return false;
      console.error('[Passkey] conditional UI failed:', err);
      return false;
    }
  }

  function abortConditionalUI() {
    if (_conditionalAbort) {
      try { _conditionalAbort.abort(); } catch {}
      _conditionalAbort = null;
    }
  }

  // ──── Management ───────────────────────────────────────────────────────

  async function list({ token }) {
    const res = await fetch('/api/auth/webauthn/list', {
      headers: { Authorization: `Bearer ${token}` },
    });
    if (!res.ok) throw new Error('list_failed');
    const { credentials } = await res.json();
    return credentials;
  }

  async function remove({ token, credentialId }) {
    const res = await fetch(
      `/api/auth/webauthn/${encodeURIComponent(credentialId)}`,
      {
        method: 'DELETE',
        headers: { Authorization: `Bearer ${token}` },
      }
    );
    if (!res.ok) throw new Error('remove_failed');
    return await res.json();
  }

  // ──── Public API ───────────────────────────────────────────────────────

  window.VK_WebAuthn = {
    isSupported,
    isPlatformAuthenticatorAvailable,
    enroll,
    unlock,
    list,
    remove,
    startConditionalUI,
    abortConditionalUI,
  };
})();
