// ═══════════════════════════════════════════════════════════════════════════
//  VaultKeeper E2E — Crypto Worker
// ═══════════════════════════════════════════════════════════════════════════
//  Runs argon2id in a dedicated thread so the UI doesn't freeze during the
//  ~500ms key-derivation cost. Receives request objects via postMessage,
//  replies with result or error.
//
//  Uses classic-worker-style importScripts (works everywhere; module workers
//  have worse browser compatibility).
//
//  Message contract:
//    in:  { op: 'ping' }                              → out: { op: 'result', requestId }
//    in:  { op: 'prepareSignup', username, password, kdfParams, requestId }
//         → out: { op: 'result', requestId, authHashB64, protectedSymKeyB64,
//                  symKey:ArrayBuffer, masterKey:ArrayBuffer, kdf }
//    in:  { op: 'deriveLogin', username, password, kdfParams, requestId }
//         → out: { op: 'result', requestId, authHashB64, masterKey:ArrayBuffer }
//    in:  { op: 'completeLogin', masterKey:ArrayBuffer, protectedSymKeyB64, requestId }
//         → out: { op: 'result', requestId, symKey:ArrayBuffer }
//    on error, always: { op: 'error', requestId, error: string }
// ═══════════════════════════════════════════════════════════════════════════

'use strict';

importScripts('/vendor/hash-wasm.umd.min.js');
importScripts('/vk-crypto.js');

// Sanity check
if (typeof VKCrypto === 'undefined' || typeof hashwasm === 'undefined') {
  self.postMessage({ op: 'error', requestId: 0, error: 'Worker failed to load dependencies' });
}

self.onmessage = async (e) => {
  const msg = e.data || {};
  const requestId = msg.requestId;
  try {
    switch (msg.op) {
      case 'ping': {
        self.postMessage({ op: 'result', requestId });
        return;
      }

      case 'prepareSignup': {
        const { username, password, kdfParams } = msg;
        const r = await VKCrypto.prepareSignup(username, password, kdfParams);
        // r.toServer has { username, auth_hash, protected_symmetric_key, kdf }
        // r.session has { masterKey, symKey } as Uint8Array

        // Transfer the key buffers so we don't copy big Uint8Arrays across the
        // worker boundary. The worker's copy is zero-length after transfer.
        const masterKey = r.session.masterKey.buffer;
        const symKey = r.session.symKey.buffer;
        self.postMessage({
          op: 'result',
          requestId,
          authHashB64: r.toServer.auth_hash,
          protectedSymKeyB64: r.toServer.protected_symmetric_key,
          symKey,
          masterKey,
          kdf: r.toServer.kdf,
        }, [masterKey, symKey]);
        return;
      }

      case 'deriveLogin': {
        const { username, password, kdfParams } = msg;
        const r = await VKCrypto.deriveLogin(username, password, {
          memory_cost: kdfParams.memoryCost,
          time_cost: kdfParams.timeCost,
          parallelism: kdfParams.parallelism,
        });
        // r has { masterKey, authHashB64 }
        const masterKey = r.masterKey.buffer;
        self.postMessage({
          op: 'result',
          requestId,
          authHashB64: r.authHashB64,
          masterKey,
        }, [masterKey]);
        return;
      }

      case 'completeLogin': {
        const { masterKey, protectedSymKeyB64 } = msg;
        // masterKey arrives as ArrayBuffer (transferred from main thread)
        const mkBytes = new Uint8Array(masterKey);
        const r = await VKCrypto.completeLogin(mkBytes, protectedSymKeyB64);
        // r has { symKey }
        const symKey = r.symKey.buffer;
        // Zero our copy of masterKey
        mkBytes.fill(0);
        self.postMessage({
          op: 'result',
          requestId,
          symKey,
        }, [symKey]);
        return;
      }

      default:
        self.postMessage({ op: 'error', requestId, error: 'Unknown op: ' + msg.op });
    }
  } catch (err) {
    self.postMessage({
      op: 'error',
      requestId,
      error: err?.message || String(err),
    });
  }
};
