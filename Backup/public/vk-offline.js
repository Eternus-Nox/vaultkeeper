// ────────────────────────────────────────────────────────────────────────
// vk-offline.js — VaultKeeper offline cache + sync layer.
//
// This module sits between vk-app.js and the network. It transparently:
//
//   1. Mirrors server data into IndexedDB after every successful sync,
//      preserving the SAME ciphertext format the server holds. The user's
//      symKey never touches IndexedDB; only the server-format encrypted
//      blobs do, plus the metadata needed to re-derive the symKey from a
//      master password (KDF salt, wrapped symKey, KDF params) — exactly
//      what /api/auth/login already returns.
//
//   2. Provides offline read access. When the network is unavailable,
//      the API helper transparently serves results from IndexedDB.
//
//   3. Queues mutations made while offline. Each entry is signed with a
//      device-bound key so the server can verify it came from this
//      device, AND tagged with a baseVersion so the server can detect
//      conflicts.
//
//   4. Syncs the queue when the network returns, with three-way merge:
//      server-only changes pull in automatically, local-only changes
//      push up, items changed on both sides become conflicts that the
//      user resolves per-item via a small ⚠ badge in the UI.
//
//   5. Enforces a configurable offline TTL (default 7 days) so an old
//      device that's been offline indefinitely can't keep using cached
//      data forever — they have to come back online and re-auth.
//
// Server endpoints used (all under /api/sync/):
//   GET    /api/sync/state          — current vault_revision, items version map
//   POST   /api/sync/mutations      — submit a batch of signed mutations
//   POST   /api/sync/device         — register this device's signing key
// ────────────────────────────────────────────────────────────────────────

(function () {
  'use strict';

  // ──── Constants ────────────────────────────────────────────────────

  const DB_NAME = 'vaultkeeper';
  const DB_VERSION = 1;

  const STORE_USERS = 'users';        // login metadata per user
  const STORE_VAULT = 'vault';        // ciphertext items, keyed by id
  const STORE_FOLDERS = 'folders';    // ciphertext folders
  const STORE_PENDING = 'pending';    // mutation queue
  const STORE_CONFLICTS = 'conflicts'; // unresolved conflicts
  const STORE_META = 'meta';          // misc kvstore

  const DEFAULT_OFFLINE_TTL_DAYS = 7;
  const PASSKEY_BLOB_KEY = 'passkey_blob';

  // Generate a stable, opaque device UUID (for binding signed mutations
  // to this device). Stored in IndexedDB; persists across sessions.
  const DEVICE_UUID_KEY = 'device_uuid';


  // ──── Database initialization ──────────────────────────────────────

  let _dbPromise = null;
  function db() {
    if (_dbPromise) return _dbPromise;
    _dbPromise = new Promise((resolve, reject) => {
      const req = indexedDB.open(DB_NAME, DB_VERSION);
      req.onupgradeneeded = (e) => {
        const d = e.target.result;
        if (!d.objectStoreNames.contains(STORE_USERS)) {
          d.createObjectStore(STORE_USERS, { keyPath: 'username' });
        }
        if (!d.objectStoreNames.contains(STORE_VAULT)) {
          const s = d.createObjectStore(STORE_VAULT, { keyPath: 'compositeKey' });
          s.createIndex('byUser', 'username', { unique: false });
        }
        if (!d.objectStoreNames.contains(STORE_FOLDERS)) {
          const s = d.createObjectStore(STORE_FOLDERS, { keyPath: 'compositeKey' });
          s.createIndex('byUser', 'username', { unique: false });
        }
        if (!d.objectStoreNames.contains(STORE_PENDING)) {
          const s = d.createObjectStore(STORE_PENDING, { keyPath: 'localId', autoIncrement: true });
          s.createIndex('byUser', 'username', { unique: false });
          s.createIndex('byStatus', 'status', { unique: false });
        }
        if (!d.objectStoreNames.contains(STORE_CONFLICTS)) {
          const s = d.createObjectStore(STORE_CONFLICTS, { keyPath: 'compositeKey' });
          s.createIndex('byUser', 'username', { unique: false });
        }
        if (!d.objectStoreNames.contains(STORE_META)) {
          d.createObjectStore(STORE_META, { keyPath: 'key' });
        }
      };
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
      req.onblocked = () => reject(new Error('IDB open blocked'));
    });
    return _dbPromise;
  }


  // Generic IDB helpers — promisified
  async function idbGet(store, key) {
    const d = await db();
    return new Promise((res, rej) => {
      const tx = d.transaction(store, 'readonly');
      const req = tx.objectStore(store).get(key);
      req.onsuccess = () => res(req.result);
      req.onerror = () => rej(req.error);
    });
  }
  async function idbPut(store, value) {
    const d = await db();
    return new Promise((res, rej) => {
      const tx = d.transaction(store, 'readwrite');
      const req = tx.objectStore(store).put(value);
      req.onsuccess = () => res(req.result);
      req.onerror = () => rej(req.error);
    });
  }
  async function idbDelete(store, key) {
    const d = await db();
    return new Promise((res, rej) => {
      const tx = d.transaction(store, 'readwrite');
      const req = tx.objectStore(store).delete(key);
      req.onsuccess = () => res();
      req.onerror = () => rej(req.error);
    });
  }
  async function idbGetAllByIndex(store, index, value) {
    const d = await db();
    return new Promise((res, rej) => {
      const tx = d.transaction(store, 'readonly');
      const req = tx.objectStore(store).index(index).getAll(value);
      req.onsuccess = () => res(req.result);
      req.onerror = () => rej(req.error);
    });
  }
  async function idbClear(store) {
    const d = await db();
    return new Promise((res, rej) => {
      const tx = d.transaction(store, 'readwrite');
      const req = tx.objectStore(store).clear();
      req.onsuccess = () => res();
      req.onerror = () => rej(req.error);
    });
  }


  // ──── Device UUID ──────────────────────────────────────────────────

  async function getDeviceUuid() {
    let row = await idbGet(STORE_META, DEVICE_UUID_KEY);
    if (row) return row.value;
    const uuid = crypto.randomUUID();
    await idbPut(STORE_META, { key: DEVICE_UUID_KEY, value: uuid });
    return uuid;
  }


  // ──── Encoding helpers ────────────────────────────────────────────

  function bytesToB64(bytes) {
    let s = '';
    for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return btoa(s);
  }
  function b64ToBytes(b64) {
    const s = atob(b64);
    const out = new Uint8Array(s.length);
    for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
    return out;
  }


  // ──── User login metadata ──────────────────────────────────────────
  //
  // After a successful online login, we cache JUST enough to let the user
  // unlock the vault offline next time:
  //
  //   • username
  //   • KDF parameters (memory_cost, time_cost, parallelism)
  //   • The wrapped symKey (protected_symmetric_key)
  //   • A small "verifier" we use to prove the password is correct on
  //     offline unlock without contacting the server. This is the same
  //     mechanism the server uses: derive auth_hash from the password,
  //     and store a one-way hash of it locally (NOT the auth_hash
  //     itself — even one-way it shouldn't sit on disk in clear form).
  //   • last_revision — the vault_revision we last synced to
  //   • last_sync_at — for TTL enforcement
  //   • optional WebAuthn encrypted blob for passkey unlock offline
  //
  // We never store the master password, the master key, or the symKey.
  //
  // The user's "compositeKey" pattern lets multiple users coexist on one
  // device (e.g. a family iPad). The most-recently-used one is the
  // default offline candidate.

  async function saveUserMetadata(meta) {
    // meta: { username, kdf, protected_symmetric_key, auth_verifier_b64,
    //         last_revision, passkey_blob? }
    const existing = (await idbGet(STORE_USERS, meta.username)) || {};
    const merged = {
      ...existing,
      ...meta,
      last_sync_at: Date.now(),
    };
    await idbPut(STORE_USERS, merged);
  }

  async function getUserMetadata(username) {
    return await idbGet(STORE_USERS, username);
  }

  // Generic per-user key-value persistence. Stores arbitrary structured
  // data on the user row under `kv.<key>`. Used for caching things like
  // health-check results that we want to survive page reloads.
  async function setUserKV(username, key, value) {
    if (!username || !key) return;
    const existing = (await idbGet(STORE_USERS, username)) || { username };
    const kv = existing.kv || {};
    if (value === null || value === undefined) {
      delete kv[key];
    } else {
      kv[key] = value;
    }
    existing.kv = kv;
    existing.last_kv_update = Date.now();
    await idbPut(STORE_USERS, existing);
  }

  async function getUserKV(username, key) {
    if (!username || !key) return null;
    const row = await idbGet(STORE_USERS, username);
    return row && row.kv ? row.kv[key] : null;
  }

  async function getMostRecentUser() {
    const d = await db();
    return new Promise((res, rej) => {
      const tx = d.transaction(STORE_USERS, 'readonly');
      const req = tx.objectStore(STORE_USERS).getAll();
      req.onsuccess = () => {
        const all = req.result || [];
        if (all.length === 0) return res(null);
        all.sort((a, b) => (b.last_sync_at || 0) - (a.last_sync_at || 0));
        res(all[0]);
      };
      req.onerror = () => rej(req.error);
    });
  }


  // ──── Auth verifier ────────────────────────────────────────────────
  //
  // We derive a one-way verifier from the user's auth_hash, salt it with
  // a random per-user value, and store SHA-256(salt || auth_hash). On
  // offline unlock we re-derive auth_hash, hash with the same salt, and
  // compare. If we additionally manage to unwrap the wrapped symKey using
  // keys derived from the master password, the password is definitely
  // correct.

  async function deriveVerifier(authHashBytes, saltBytes) {
    const buf = new Uint8Array(saltBytes.length + authHashBytes.length);
    buf.set(saltBytes, 0);
    buf.set(authHashBytes, saltBytes.length);
    const digest = await crypto.subtle.digest('SHA-256', buf);
    return new Uint8Array(digest);
  }

  function ctEqual(a, b) {
    if (a.length !== b.length) return false;
    let diff = 0;
    for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
    return diff === 0;
  }


  // ──── Cache vault data after successful sync ──────────────────────

  function vaultKey(username, id) {
    return username + '::' + id;
  }

  async function cacheItems(username, items) {
    if (!Array.isArray(items)) return;
    const d = await db();
    return new Promise((res, rej) => {
      const tx = d.transaction(STORE_VAULT, 'readwrite');
      const store = tx.objectStore(STORE_VAULT);
      // Snapshot replace: clear the user's items, write the new set.
      // For incremental sync we'd update in-place, but full-snapshot is
      // fine for round one.
      const idx = store.index('byUser');
      const cur = idx.openCursor(username);
      cur.onsuccess = (e) => {
        const c = e.target.result;
        if (c) {
          c.delete();
          c.continue();
        } else {
          for (const it of items) {
            store.put({
              compositeKey: vaultKey(username, it.id),
              username,
              ...it,
            });
          }
        }
      };
      cur.onerror = () => rej(cur.error);
      tx.oncomplete = () => res();
      tx.onerror = () => rej(tx.error);
    });
  }

  async function cacheFolders(username, folders) {
    if (!Array.isArray(folders)) return;
    const d = await db();
    return new Promise((res, rej) => {
      const tx = d.transaction(STORE_FOLDERS, 'readwrite');
      const store = tx.objectStore(STORE_FOLDERS);
      const idx = store.index('byUser');
      const cur = idx.openCursor(username);
      cur.onsuccess = (e) => {
        const c = e.target.result;
        if (c) {
          c.delete();
          c.continue();
        } else {
          for (const f of folders) {
            store.put({
              compositeKey: vaultKey(username, f.id),
              username,
              ...f,
            });
          }
        }
      };
      cur.onerror = () => rej(cur.error);
      tx.oncomplete = () => res();
      tx.onerror = () => rej(tx.error);
    });
  }

  async function getCachedItems(username) {
    const all = await idbGetAllByIndex(STORE_VAULT, 'byUser', username);
    // Strip the IDB-only fields before handing back to vk-app
    return all.map(({ compositeKey, username: _u, ...rest }) => rest);
  }
  async function getCachedFolders(username) {
    const all = await idbGetAllByIndex(STORE_FOLDERS, 'byUser', username);
    return all.map(({ compositeKey, username: _u, ...rest }) => rest);
  }


  // ──── TTL check ────────────────────────────────────────────────────

  async function getOfflineTtlDays() {
    const row = await idbGet(STORE_META, 'offline_ttl_days');
    return (row && row.value) || DEFAULT_OFFLINE_TTL_DAYS;
  }
  async function setOfflineTtlDays(days) {
    await idbPut(STORE_META, { key: 'offline_ttl_days', value: days });
  }

  async function isUserCacheValid(username) {
    const meta = await getUserMetadata(username);
    if (!meta || !meta.last_sync_at) return false;
    const ttl = await getOfflineTtlDays();
    const ageMs = Date.now() - meta.last_sync_at;
    const maxMs = ttl * 24 * 60 * 60 * 1000;
    return ageMs < maxMs;
  }


  // ──── Mutation queue ──────────────────────────────────────────────
  //
  // Schema of a queued mutation:
  //   {
  //     localId:      auto-increment
  //     username:     who made it
  //     op:           'create' | 'update' | 'delete' for both items & folders
  //     resource:     'item' | 'folder'
  //     resourceId:   server-side id (or 'local-' + uuid for offline-created)
  //     baseVersion:  the version we were editing FROM (for conflict detection)
  //     payload:      the encrypted blob to send up
  //     status:       'pending' | 'conflict' | 'resolved'
  //     created_at:   ms
  //     signature:    HMAC of (deviceUuid || localId || op || resourceId || baseVersion || payload)
  //   }

  async function enqueue(mutation) {
    mutation.status = mutation.status || 'pending';
    mutation.created_at = Date.now();
    return await idbPut(STORE_PENDING, mutation);
  }

  async function getPendingForUser(username) {
    return await idbGetAllByIndex(STORE_PENDING, 'byUser', username);
  }

  async function removeMutation(localId) {
    await idbDelete(STORE_PENDING, localId);
  }


  // ──── Conflicts ────────────────────────────────────────────────────

  async function recordConflict(username, resource, resourceId, mine, theirs, baseVersion) {
    await idbPut(STORE_CONFLICTS, {
      compositeKey: vaultKey(username, resource + ':' + resourceId),
      username, resource, resourceId,
      mine, theirs, baseVersion,
      created_at: Date.now(),
    });
  }
  async function getConflicts(username) {
    return await idbGetAllByIndex(STORE_CONFLICTS, 'byUser', username);
  }
  async function clearConflict(username, resource, resourceId) {
    await idbDelete(STORE_CONFLICTS, vaultKey(username, resource + ':' + resourceId));
  }


  // ──── Device-binding signing key ─────────────────────────────────
  //
  // The signing key is derived in-memory from the user's symKey at unlock
  // time and never stored. Each device produces a different key for the
  // same user (because the deviceUuid is mixed in via HKDF).

  async function deriveDeviceSigningKey(symKeyBytes, deviceUuid) {
    // HKDF-SHA256, info = "vk.device.v1." + uuid
    const info = new TextEncoder().encode('vk.device.v1.' + deviceUuid);
    const salt = new Uint8Array(32); // zero salt — fine since symKey is high-entropy
    const ikm = await crypto.subtle.importKey(
      'raw', symKeyBytes, { name: 'HKDF' }, false, ['deriveBits']
    );
    const bits = await crypto.subtle.deriveBits(
      { name: 'HKDF', hash: 'SHA-256', salt, info },
      ikm, 256
    );
    return await crypto.subtle.importKey(
      'raw', bits, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']
    );
  }

  async function signMutation(signingKey, m, deviceUuid) {
    // Canonical encoding: deviceUuid|localId|op|resource|resourceId|baseVersion|payloadHash
    const payloadHash = await crypto.subtle.digest(
      'SHA-256',
      new TextEncoder().encode(JSON.stringify(m.payload || null))
    );
    const canonical = [
      deviceUuid,
      m.localId,
      m.op,
      m.resource,
      m.resourceId,
      m.baseVersion ?? '',
      bytesToB64(new Uint8Array(payloadHash)),
    ].join('|');
    const sig = await crypto.subtle.sign(
      'HMAC', signingKey,
      new TextEncoder().encode(canonical)
    );
    return bytesToB64(new Uint8Array(sig));
  }


  // ──── Online detection ─────────────────────────────────────────────

  // navigator.onLine is unreliable. We treat fetch failures as "offline"
  // and explicitly probe /healthz when we want to know for sure.

  async function probeOnline() {
    try {
      const ctrl = new AbortController();
      const t = setTimeout(() => ctrl.abort(), 3000);
      const res = await fetch('/healthz', { signal: ctrl.signal, cache: 'no-store' });
      clearTimeout(t);
      return res.ok;
    } catch {
      return false;
    }
  }


  // ──── Public API ───────────────────────────────────────────────────

  window.VK_Offline = {
    // Database / introspection
    db,
    getDeviceUuid,

    // Login metadata
    saveUserMetadata,
    getUserMetadata,
    setUserKV,
    getUserKV,
    getMostRecentUser,
    deriveVerifier,
    ctEqual,
    bytesToB64, b64ToBytes,

    // Vault cache
    cacheItems,
    cacheFolders,
    getCachedItems,
    getCachedFolders,

    // TTL
    isUserCacheValid,
    getOfflineTtlDays,
    setOfflineTtlDays,
    DEFAULT_OFFLINE_TTL_DAYS,

    // Queue
    enqueue,
    getPendingForUser,
    removeMutation,

    // Conflicts
    recordConflict,
    getConflicts,
    clearConflict,

    // Signing
    deriveDeviceSigningKey,
    signMutation,

    // Network probe
    probeOnline,

    // Cache mgmt
    async clearUserCache(username) {
      await idbDelete(STORE_USERS, username);
      const d = await db();
      for (const store of [STORE_VAULT, STORE_FOLDERS, STORE_PENDING, STORE_CONFLICTS]) {
        await new Promise((res, rej) => {
          const tx = d.transaction(store, 'readwrite');
          const idx = tx.objectStore(store).index('byUser');
          const cur = idx.openCursor(username);
          cur.onsuccess = (e) => {
            const c = e.target.result;
            if (c) { c.delete(); c.continue(); } else { res(); }
          };
          cur.onerror = () => rej(cur.error);
        });
      }
    },

    async clearEverything() {
      for (const s of [STORE_USERS, STORE_VAULT, STORE_FOLDERS,
                       STORE_PENDING, STORE_CONFLICTS, STORE_META]) {
        await idbClear(s);
      }
    },

    async getStorageEstimate() {
      if (navigator.storage?.estimate) {
        return await navigator.storage.estimate();
      }
      return null;
    },
  };

  // Service-Worker registration
  if ('serviceWorker' in navigator) {
    window.addEventListener('load', () => {
      navigator.serviceWorker.register('/vk-sw.js').catch(err => {
        console.warn('[vk-offline] SW register failed:', err.message);
      });
    });
  }
})();
