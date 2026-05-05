'use strict';

// ═══════════════════════════════════════════════════════════════════════════
//  VaultKeeper E2E Client — Day 3b (UI polish)
//  Full vault application. Loaded after vk-crypto.js and hash-wasm.
// ═══════════════════════════════════════════════════════════════════════════

// ── Config ────────────────────────────────────────────────────────────────
const SIGNUP_KDF_PARAMS = Object.freeze({
  memoryCost: 262144, timeCost: 5, parallelism: 1, hashLength: 32,
});
const LOCK_TIMEOUT_MINUTES_DEFAULT = 15;
const CLIPBOARD_CLEAR_SECONDS_DEFAULT = 30;
const SCHEMA_VERSION = 1;  // stamped into every encrypted item

const VALID_ITEM_TYPES = ['login', 'card', 'note', 'identity'];
const FOLDER_COLORS = [
  '#01696f', '#0ea5e9', '#22c55e', '#eab308',
  '#f97316', '#ef4444', '#ec4899', '#a855f7', '#64748b',
];

// ── State (in-memory only) ────────────────────────────────────────────────
const state = {
  // Auth
  token: null,
  username: null,
  symKey: null,           // Uint8Array(64)
  prefs: {},              // server prefs (theme, clipboard_clear_seconds, etc.)

  // Data
  items: [],              // decrypted items: {id, type, folder_id, favorite, data:{...}, created_at, updated_at}
  folders: [],            // decrypted folders: {id, name, color, created_at}

  // UI
  view: 'all',            // 'all' | 'favorites' | 'login' | 'card' | 'note' | 'identity' | 'folder:ID' | 'generator' | 'health' | 'settings'
  search: '',
  selectedItemId: null,   // for detail panel on desktop

  // Lock timer
  lockTimeout: LOCK_TIMEOUT_MINUTES_DEFAULT,
  _lockTimer: null,
  _clipboardTimer: null,

  // Health prefetch cache. Populated by prefetchHealthData() ~3s after login.
  // Cleared on logout/lock and on any vault item mutation.
  // Shape: { twoFAState, pwnedMap, computedAt: ms } | null
  healthCache: null,
  _healthPrefetchTimer: null,

  // Offline mode. When true, api() routes reads from IndexedDB cache and
  // mutations into the pending queue. Flipped by loadEverything when the
  // network fails, by doOfflineLogin, and by the sync engine on reconnect.
  offline: false,
};

// ── Utilities ─────────────────────────────────────────────────────────────
const $ = (s, root=document) => root.querySelector(s);
const $$ = (s, root=document) => Array.from(root.querySelectorAll(s));

function escHtml(s) {
  if (s == null) return '';
  return String(s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}
function showEl(el) { (typeof el === 'string' ? $(el) : el).classList.remove('hidden'); }
function hideEl(el) { (typeof el === 'string' ? $(el) : el).classList.add('hidden'); }

function showToast(msg, kind = 'info') {
  const stack = $('#toast-stack') || (() => {
    const s = document.createElement('div');
    s.id = 'toast-stack';
    document.body.appendChild(s);
    return s;
  })();
  const el = document.createElement('div');
  el.className = 'toast toast-' + kind;
  el.textContent = msg;
  stack.appendChild(el);
  requestAnimationFrame(() => el.classList.add('visible'));
  setTimeout(() => {
    el.classList.remove('visible');
    setTimeout(() => el.remove(), 300);
  }, 3500);
}

function formatDate(secs) {
  if (!secs) return '';
  const d = new Date(secs * 1000);
  return d.toLocaleDateString(undefined, { year:'numeric', month:'short', day:'numeric' });
}

function renderIcons(/* root */) {
  // Lucide v0+ does not expose scoped root in a stable way, so we just
  // rescan the whole document after each render. It's fast enough.
  if (typeof lucide !== 'undefined') lucide.createIcons();
}

// ── API helper ────────────────────────────────────────────────────────────
async function api(method, path, body, opts2 = {}) {
  // Offline mode: short-circuit everything. GETs serve from cache (handled
  // by loadFromCache, not here). Mutations get queued via vk-offline.
  if (state.offline) {
    return await offlineApi(method, path, body);
  }

  const opts = { method, headers: { 'Content-Type': 'application/json' } };
  if (state.token) opts.headers['Authorization'] = 'Bearer ' + state.token;
  if (body !== undefined && body !== null && method !== 'GET' && method !== 'HEAD') {
    opts.body = JSON.stringify(body);
  }
  let res;
  try {
    res = await fetch(path, opts);
  } catch (netErr) {
    // Network failure mid-session. If we have cached data, flip to offline
    // mode and serve from cache.
    if (window.VK_Offline && state.username
        && await window.VK_Offline.isUserCacheValid(state.username)) {
      console.warn('[api] network failed, switching to offline mode');
      state.offline = true;
      if (typeof updateOfflineIndicator === 'function') updateOfflineIndicator();
      return await offlineApi(method, path, body);
    }
    throw netErr;
  }
  let data;
  try { data = await res.json(); } catch { data = null; }
  if (!res.ok) {
    const err = new Error(data?.error || ('HTTP ' + res.status));
    err.status = res.status;
    err.data = data;
    // Special: 401 means session expired — kick to auth screen.
    // Caller can opt out (e.g. delete-account passes skipAuthRedirect because
    // 401 there means "wrong password", not "expired session").
    if (res.status === 401 && state.token && !opts2.skipAuthRedirect) {
      console.warn('[api] 401 received, forcing logout');
      clearSession();
      showAuth();
      showToast('Session expired. Please log in again.', 'info');
    }
    throw err;
  }
  return data;
}

// Offline replay path. GET requests are served from IndexedDB.
// Mutations are queued for sync when network returns.
async function offlineApi(method, path, body) {
  if (!window.VK_Offline || !state.username) {
    throw new Error('Offline mode unavailable');
  }
  const O = window.VK_Offline;

  // ── READS ──
  if (method === 'GET') {
    if (path === '/api/vault') return await O.getCachedItems(state.username);
    if (path === '/api/folders') return await O.getCachedFolders(state.username);
    if (path === '/api/prefs') {
      const meta = await O.getUserMetadata(state.username);
      return (meta && meta.prefs) || {};
    }
    // Unknown read — fail gracefully
    throw new Error('Cannot perform this action while offline');
  }

  // ── MUTATIONS ──
  // Map the URL pattern to a (resource, op, resourceId) so we can queue it.
  const m = parseMutationPath(method, path);
  if (!m) {
    throw new Error('Cannot perform this action while offline');
  }

  // Apply the mutation optimistically to the local cache so the UI
  // reflects it immediately. The queued op will replay against the server
  // on reconnect.
  await applyOptimistic(m.resource, m.op, m.resourceId, body);

  // Sign + enqueue
  await queueMutation(m.resource, m.op, m.resourceId, body);

  // Mimic the shape the server would have returned. Most callers only
  // care about ok/200 with maybe an id back; for create ops we synthesize
  // a "local-" prefixed id which sync will reconcile to the real server id
  // later.
  if (m.op === 'create') {
    return { id: m.resourceId, _offline: true };
  }
  return { ok: true, _offline: true };
}

function parseMutationPath(method, path) {
  // /api/vault            POST/PUT
  // /api/vault/:id        PUT/DELETE
  // /api/folders          POST
  // /api/folders/:id      PUT/DELETE
  // /api/prefs            PUT
  let m;
  if ((m = path.match(/^\/api\/vault\/(\d+|local-[\w-]+)$/))) {
    return { resource: 'item', resourceId: m[1],
             op: method === 'DELETE' ? 'delete' : 'update' };
  }
  if (path === '/api/vault' && method === 'POST') {
    return { resource: 'item', resourceId: 'local-' + crypto.randomUUID(),
             op: 'create' };
  }
  if ((m = path.match(/^\/api\/folders\/(\d+|local-[\w-]+)$/))) {
    return { resource: 'folder', resourceId: m[1],
             op: method === 'DELETE' ? 'delete' : 'update' };
  }
  if (path === '/api/folders' && method === 'POST') {
    return { resource: 'folder', resourceId: 'local-' + crypto.randomUUID(),
             op: 'create' };
  }
  if (path === '/api/prefs' && method === 'PUT') {
    return { resource: 'prefs', resourceId: '_', op: 'update' };
  }
  return null;
}

async function applyOptimistic(resource, op, resourceId, body) {
  const O = window.VK_Offline;
  const username = state.username;
  if (resource === 'prefs') {
    // Update prefs directly in user metadata
    const meta = (await O.getUserMetadata(username)) || { username };
    meta.prefs = body || {};
    await O.saveUserMetadata(meta);
    return;
  }
  // For items + folders we mutate the in-IDB ciphertext store so subsequent
  // GET reads reflect the change.
  // We need access to the raw store — go through the public API by
  // re-fetching everything, modifying, and saving back. Slow but simple.
  if (resource === 'item') {
    const all = await O.getCachedItems(username);
    if (op === 'delete') {
      const filtered = all.filter(r => String(r.id) !== String(resourceId));
      await O.cacheItems(username, filtered);
    } else if (op === 'create') {
      const row = {
        id: resourceId,
        encrypted_data: body.encrypted_data,
        type: body.type, folder_id: body.folder_id, favorite: body.favorite,
        version: 0,
        created_at: Math.floor(Date.now() / 1000),
        updated_at: Math.floor(Date.now() / 1000),
      };
      await O.cacheItems(username, [...all, row]);
    } else if (op === 'update') {
      const updated = all.map(r => {
        if (String(r.id) !== String(resourceId)) return r;
        return {
          ...r,
          encrypted_data: body.encrypted_data ?? r.encrypted_data,
          type: body.type ?? r.type,
          folder_id: body.folder_id !== undefined ? body.folder_id : r.folder_id,
          favorite: body.favorite !== undefined ? body.favorite : r.favorite,
          updated_at: Math.floor(Date.now() / 1000),
        };
      });
      await O.cacheItems(username, updated);
    }
  } else if (resource === 'folder') {
    const all = await O.getCachedFolders(username);
    if (op === 'delete') {
      const filtered = all.filter(r => String(r.id) !== String(resourceId));
      await O.cacheFolders(username, filtered);
    } else if (op === 'create') {
      const row = {
        id: resourceId,
        encrypted_name: body.encrypted_name,
        color: body.color,
        created_at: Math.floor(Date.now() / 1000),
      };
      await O.cacheFolders(username, [...all, row]);
    } else if (op === 'update') {
      const updated = all.map(r => {
        if (String(r.id) !== String(resourceId)) return r;
        return {
          ...r,
          encrypted_name: body.encrypted_name ?? r.encrypted_name,
          color: body.color !== undefined ? body.color : r.color,
        };
      });
      await O.cacheFolders(username, updated);
    }
  }
}

async function queueMutation(resource, op, resourceId, body) {
  const O = window.VK_Offline;
  // Find baseVersion for update/delete (so server can detect conflicts)
  let baseVersion = null;
  if (op !== 'create' && resource === 'item') {
    const all = await O.getCachedItems(state.username);
    const row = all.find(r => String(r.id) === String(resourceId));
    baseVersion = row?.version ?? null;
  }
  const m = {
    username: state.username,
    op, resource, resourceId,
    baseVersion,
    payload: body || null,
  };
  await O.enqueue(m);
}

// ── Worker ────────────────────────────────────────────────────────────────
let _worker = null;
let _workerReqId = 0;
const _workerPending = new Map();

function getWorker() {
  if (_worker) return _worker;
  _worker = new Worker('/vk-crypto-worker.js');
  _worker.onmessage = (e) => {
    const msg = e.data || {};
    const pending = _workerPending.get(msg.requestId);
    if (!pending) return;
    _workerPending.delete(msg.requestId);
    clearTimeout(pending.timer);
    if (msg.op === 'error') pending.reject(new Error(msg.error || 'Worker error'));
    else pending.resolve(msg);
  };
  _worker.onerror = (e) => {
    console.error('[worker] onerror:', e.message || e);
    for (const [, p] of _workerPending) {
      clearTimeout(p.timer); p.reject(new Error('Crypto worker failed: ' + (e.message || 'unknown')));
    }
    _workerPending.clear();
    _worker = null;
  };
  return _worker;
}

function callWorker(op, payload, timeoutMs = 10000) {
  return callWorkerTransfer(op, payload, undefined, timeoutMs);
}

function callWorkerTransfer(op, payload, transferList, timeoutMs = 10000) {
  const w = getWorker();
  const requestId = ++_workerReqId;
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      _workerPending.delete(requestId);
      reject(new Error('Crypto operation timed out'));
    }, timeoutMs);
    _workerPending.set(requestId, { resolve, reject, timer });
    if (transferList && transferList.length) w.postMessage({ op, requestId, ...payload }, transferList);
    else w.postMessage({ op, requestId, ...payload });
  });
}

// ── Item encryption/decryption ────────────────────────────────────────────
// Items are {v, type, data:{...}} stringified, encrypted with AES-GCM+HMAC
// under state.symKey, then base64-encoded. The server sees only the base64.

async function encryptItemData(data) {
  if (!state.symKey) throw new Error('Not unlocked');
  // encryptItem handles JSON.stringify internally — pass the object directly.
  const envelope = { v: SCHEMA_VERSION, data };
  return await VKCrypto.encryptItem(envelope, state.symKey);
}

async function decryptItemData(encryptedB64) {
  if (!state.symKey) throw new Error('Not unlocked');
  // decryptItem returns the JSON-parsed object directly.
  const envelope = await VKCrypto.decryptItem(encryptedB64, state.symKey);
  if (envelope && envelope.v !== SCHEMA_VERSION) {
    console.warn('[crypto] Item has schema v=' + envelope.v + ', expected ' + SCHEMA_VERSION);
  }
  return (envelope && envelope.data) || {};
}

// encryptItem / decryptItem JSON-serialize their first argument internally,
// so we pass the name as a plain string (it will round-trip as a string).
async function encryptFolderName(name) {
  return await VKCrypto.encryptItem(String(name), state.symKey);
}
async function decryptFolderName(encryptedB64) {
  const out = await VKCrypto.decryptItem(encryptedB64, state.symKey);
  return typeof out === 'string' ? out : String(out);
}

// ═══════════════════════════════════════════════════════════════════════════
//  AUTH FLOWS
// ═══════════════════════════════════════════════════════════════════════════

async function doSignup(username, password) {
  const derived = await callWorker('prepareSignup', {
    username, password, kdfParams: SIGNUP_KDF_PARAMS,
  }, 20000);
  const resp = await api('POST', '/api/auth/signup', {
    username,
    auth_hash: derived.authHashB64,
    protected_symmetric_key: derived.protectedSymKeyB64,
    kdf: derived.kdf,
  });
  state.token = resp.token;
  state.username = resp.username;
  state.symKey = new Uint8Array(derived.symKey);
  new Uint8Array(derived.masterKey).fill(0);
}

async function doLogin(username, password) {
  const pre = await api('POST', '/api/auth/prelogin', { username });
  const kdfParams = {
    memoryCost: pre.kdf.memory_cost,
    timeCost: pre.kdf.time_cost,
    parallelism: pre.kdf.parallelism,
    hashLength: 32,
  };
  const derived = await callWorker('deriveLogin', { username, password, kdfParams }, 20000);
  const login = await api('POST', '/api/auth/login', {
    username, auth_hash: derived.authHashB64,
  });
  const unwrapped = await callWorkerTransfer('completeLogin', {
    masterKey: derived.masterKey,
    protectedSymKeyB64: login.protected_symmetric_key,
  }, [derived.masterKey], 5000);
  state.token = login.token;
  state.username = login.username;
  state.symKey = new Uint8Array(unwrapped.symKey);

  // Save offline-unlock metadata. We need to be able to verify the user's
  // master password later WITHOUT contacting the server, so we derive a
  // verifier from the auth_hash (one-way) and store it salted.
  if (window.VK_Offline) {
    try {
      const O = window.VK_Offline;
      const salt = crypto.getRandomValues(new Uint8Array(16));
      const authHashBytes = O.b64ToBytes(derived.authHashB64);
      const verifier = await O.deriveVerifier(authHashBytes, salt);
      await O.saveUserMetadata({
        username,
        kdf: pre.kdf,
        protected_symmetric_key: login.protected_symmetric_key,
        auth_verifier_salt_b64: O.bytesToB64(salt),
        auth_verifier_hash_b64: O.bytesToB64(verifier),
      });
    } catch (e) {
      console.warn('[doLogin] could not save offline metadata:', e.message);
    }
  }
}

// Unlock the vault from cached metadata, with no network. Verifies the
// password by:
//   1. Deriving auth_hash from username+password locally (same KDF that
//      the server normally validates against).
//   2. Hashing it with the per-user salt and comparing against the
//      stored verifier (constant-time).
//   3. As a defense-in-depth check, attempting to unwrap the cached
//      protected_symmetric_key. If it succeeds (HMAC verifies), the
//      password is definitely correct — there's no way to fake it.
//
// Sets state.symKey + state.username on success. state.token stays null
// in offline mode; the api() helper detects this and short-circuits to
// the cache.
async function doOfflineLogin(username, password) {
  if (!window.VK_Offline) throw new Error('Offline cache unavailable');
  const O = window.VK_Offline;

  const meta = await O.getUserMetadata(username);
  if (!meta) throw new Error('No cached vault for this user');

  const valid = await O.isUserCacheValid(username);
  if (!valid) throw new Error('Cache expired — please reconnect to log in');

  if (!meta.kdf || !meta.protected_symmetric_key
      || !meta.auth_verifier_salt_b64 || !meta.auth_verifier_hash_b64) {
    throw new Error('Cache is incomplete — please reconnect to log in');
  }

  const kdfParams = {
    memoryCost: meta.kdf.memory_cost,
    timeCost: meta.kdf.time_cost,
    parallelism: meta.kdf.parallelism,
    hashLength: 32,
  };

  // Step 1: derive the auth hash locally, exactly as a server login would.
  const derived = await callWorker(
    'deriveLogin', { username, password, kdfParams }, 20000
  );

  // Step 2: verifier check (cheap, fails fast on wrong password)
  const salt = O.b64ToBytes(meta.auth_verifier_salt_b64);
  const authHashBytes = O.b64ToBytes(derived.authHashB64);
  const computedVerifier = await O.deriveVerifier(authHashBytes, salt);
  const expectedVerifier = O.b64ToBytes(meta.auth_verifier_hash_b64);
  if (!O.ctEqual(computedVerifier, expectedVerifier)) {
    new Uint8Array(derived.masterKey).fill(0);
    throw new Error('Wrong master password');
  }

  // Step 3: actually unwrap the symKey. completeLogin internally HMACs the
  // wrapped blob and rejects if the MAC fails, so this is the
  // cryptographically-strong check.
  let unwrapped;
  try {
    unwrapped = await callWorkerTransfer('completeLogin', {
      masterKey: derived.masterKey,
      protectedSymKeyB64: meta.protected_symmetric_key,
    }, [derived.masterKey], 5000);
  } catch (e) {
    throw new Error('Wrong master password');
  }

  state.token = null;          // no JWT — offline mode
  state.username = username;
  state.symKey = new Uint8Array(unwrapped.symKey);
  state.offline = true;
}

async function doChangePassword(currentPw, newPw, kdfOverride) {
  // 1. Derive current master + auth hash (need to validate with server)
  const pre = await api('POST', '/api/auth/prelogin', { username: state.username });
  const currentKdf = {
    memoryCost: pre.kdf.memory_cost,
    timeCost: pre.kdf.time_cost,
    parallelism: pre.kdf.parallelism,
    hashLength: 32,
  };
  const currentDerived = await callWorker('deriveLogin', {
    username: state.username, password: currentPw, kdfParams: currentKdf,
  }, 20000);

  // 2. Derive new master + wrap the EXISTING symKey under it. If a custom
  // KDF override is provided (e.g. from the Encryption strength settings),
  // use that; otherwise the current SIGNUP_KDF_PARAMS defaults apply.
  const targetKdf = kdfOverride || SIGNUP_KDF_PARAMS;
  const newDerived = await callWorker('deriveLogin', {
    username: state.username, password: newPw, kdfParams: targetKdf,
  }, 60000);  // longer timeout — high-mem KDF on slow devices can take seconds
  // newDerived.masterKey is an ArrayBuffer; wrap as Uint8Array so VKCrypto
  // can work with it.
  const newMasterBytes = new Uint8Array(newDerived.masterKey);
  const newAuthHashB64 = newDerived.authHashB64;

  // Split the new master into stretched enc/mac keys, then re-wrap the
  // existing symKey. wrapSymKey's signature is (symKey, stretchedEnc, stretchedMac).
  const newStretched = await VKCrypto.splitMasterKey(newMasterBytes);
  const newProtectedSymKey = await VKCrypto.wrapSymKey(
    state.symKey, newStretched.enc, newStretched.mac
  );
  const newKdf = {
    memory_cost: targetKdf.memoryCost,
    time_cost: targetKdf.timeCost,
    parallelism: targetKdf.parallelism,
  };

  // Zero key material
  new Uint8Array(currentDerived.masterKey).fill(0);
  newMasterBytes.fill(0);
  newStretched.enc.fill(0);
  newStretched.mac.fill(0);

  // 3. Send the change
  await api('POST', '/api/auth/change-password', {
    current_auth_hash: currentDerived.authHashB64,
    new_auth_hash: newAuthHashB64,
    new_protected_symmetric_key: newProtectedSymKey,
    new_kdf: newKdf,
  });

  // 4. Server invalidated our token. Log back in with new creds.
  // We can't just re-use newDerived.masterKey because we zeroed it. Easiest:
  // do a full login flow.
  await doLogin(state.username, newPw);
}

function clearSession() {
  state.token = null;
  state.username = null;
  if (state.symKey) state.symKey.fill(0);
  state.symKey = null;
  state.items = [];
  state.folders = [];
  state.prefs = {};
  state.view = 'all';
  state.search = '';
  state.selectedItemId = null;
  state.healthCache = null;
  if (state._lockTimer) { clearTimeout(state._lockTimer); state._lockTimer = null; }
  if (state._clipboardTimer) { clearTimeout(state._clipboardTimer); state._clipboardTimer = null; }
  if (state._healthPrefetchTimer) { clearTimeout(state._healthPrefetchTimer); state._healthPrefetchTimer = null; }
}

// ═══════════════════════════════════════════════════════════════════════════
//  DATA LOADING
// ═══════════════════════════════════════════════════════════════════════════

async function loadEverything() {
  // Try the network first. If it fails AND we have a cached vault for this
  // user, fall back to cached data and flag the app as offline.
  try {
    // Hold raw rows for caching after decrypt succeeds, so cacheLatestSync
    // doesn't have to re-fetch them. loadItems/loadFolders both write to
    // state._lastRaw* so we can pick them up below without a second round trip.
    state._lastRawItems = null;
    state._lastRawFolders = null;
    await Promise.all([loadFolders(), loadItems(), loadPrefs()]);
    applyPrefs();
    state.offline = false;
    // After a successful sync, mirror everything to IndexedDB so the next
    // cold start works offline. Do this in the background — even if it
    // fails, the user already has decrypted data on screen.
    if (window.VK_Offline) {
      cacheLatestSync().catch(e => {
        console.warn('[cacheLatestSync] background cache failed:', e.message);
      });
    }
  } catch (e) {
    // Offline fallback. Only attempt if we have cached data.
    if (window.VK_Offline && state.username) {
      const meta = await window.VK_Offline.getUserMetadata(state.username);
      const valid = await window.VK_Offline.isUserCacheValid(state.username);
      if (meta && valid) {
        console.warn('[loadEverything] network failed, falling back to cache');
        state.offline = true;
        await loadFromCache();
        applyPrefs();
        if (typeof updateOfflineIndicator === 'function') updateOfflineIndicator();
        return;
      }
      if (meta && !valid) {
        showToast('Offline cache expired — please reconnect to sync.', 'error');
      }
    }
    // Re-throw with a more useful message if it's a Safari "Load failed"
    // (which is its generic name for any fetch error). Otherwise pass through.
    const msg = String(e?.message || e);
    if (msg === 'Load failed' || msg === 'Failed to fetch') {
      const friendlier = new Error('Network error — could not reach the server. Check your connection.');
      friendlier.cause = e;
      throw friendlier;
    }
    throw e;
  }
}

// Mirror the most recently fetched server data into IndexedDB so we can
// open the app offline next time. Uses the raw rows that loadItems and
// loadFolders stashed on state, so we don't make extra network calls.
// We store the SERVER-FORMAT ENCRYPTED rows, not the decrypted ones.
// The symKey is never written to disk.
async function cacheLatestSync() {
  if (!state.username) return;
  if (!window.VK_Offline) return;
  try {
    if (Array.isArray(state._lastRawItems)) {
      await window.VK_Offline.cacheItems(state.username, state._lastRawItems);
    }
    if (Array.isArray(state._lastRawFolders)) {
      await window.VK_Offline.cacheFolders(state.username, state._lastRawFolders);
    }
    // Stash login metadata so offline unlock works next time.
    if (typeof state._lastLoginMeta === 'object' && state._lastLoginMeta) {
      await window.VK_Offline.saveUserMetadata({
        username: state.username,
        ...state._lastLoginMeta,
      });
    }
  } catch (e) {
    // Non-fatal — cache is a nice-to-have, not a requirement
    console.warn('[cacheLatestSync] failed:', e.message);
  }
}

// Decrypt cached ciphertext locally. Same code path as the network load,
// just sourced from IndexedDB instead of /api/vault.
async function loadFromCache() {
  const username = state.username;
  const [rawItems, rawFolders] = await Promise.all([
    window.VK_Offline.getCachedItems(username),
    window.VK_Offline.getCachedFolders(username),
  ]);

  // Decrypt items in parallel
  state.items = await Promise.all(
    rawItems.map(async (row) => {
      try {
        const data = await decryptItemData(row.encrypted_data);
        return {
          id: row.id, type: row.type, folder_id: row.folder_id,
          favorite: row.favorite, data,
          created_at: row.created_at, updated_at: row.updated_at,
        };
      } catch {
        return {
          id: row.id, type: row.type, folder_id: row.folder_id,
          favorite: row.favorite,
          data: { name: '(decryption failed)', _broken: true },
          created_at: row.created_at, updated_at: row.updated_at,
        };
      }
    })
  );

  // Decrypt folders in parallel
  state.folders = await Promise.all(
    rawFolders.map(async (row) => {
      try {
        const name = await decryptFolderName(row.encrypted_name);
        return { id: row.id, name, color: row.color, created_at: row.created_at };
      } catch {
        return { id: row.id, name: '(encrypted)', color: row.color, created_at: row.created_at };
      }
    })
  );

  // Local prefs from cache
  try {
    const prefsRow = await window.VK_Offline.getUserMetadata(username);
    state.prefs = (prefsRow && prefsRow.prefs) || {};
  } catch {
    state.prefs = {};
  }
}

async function loadItems() {
  const raw = await api('GET', '/api/vault');
  // Stash raw rows so cacheLatestSync can write them to IndexedDB
  // without a second round-trip.
  state._lastRawItems = raw;

  // Decrypt all items in parallel. Each decrypt is independent and the
  // browser's WebCrypto runs them concurrently. For a 100-item vault
  // this drops the load from ~150ms (sequential) to ~20ms (parallel).
  const decryptedRaw = await Promise.all(
    raw.map(async (row) => {
      try {
        const data = await decryptItemData(row.encrypted_data);
        return {
          id: row.id,
          type: row.type,
          folder_id: row.folder_id,
          favorite: row.favorite,
          data,
          created_at: row.created_at,
          updated_at: row.updated_at,
        };
      } catch (e) {
        console.error('[loadItems] Failed to decrypt item', row.id, e.message);
        return {
          id: row.id, type: row.type, folder_id: row.folder_id,
          favorite: row.favorite, data: { name: '(decryption failed)', _broken: true },
          created_at: row.created_at, updated_at: row.updated_at,
        };
      }
    })
  );
  state.items = decryptedRaw;
}

async function loadFolders() {
  const raw = await api('GET', '/api/folders');
  state._lastRawFolders = raw;
  state.folders = await Promise.all(
    raw.map(async (row) => {
      try {
        const name = await decryptFolderName(row.encrypted_name);
        return { id: row.id, name, color: row.color, created_at: row.created_at };
      } catch (e) {
        console.error('[loadFolders] Failed to decrypt folder', row.id, e.message);
        return { id: row.id, name: '(encrypted)', color: row.color, created_at: row.created_at };
      }
    })
  );
}

async function loadPrefs() {
  try {
    state.prefs = await api('GET', '/api/prefs') || {};
  } catch (e) {
    console.warn('[loadPrefs]', e.message);
    state.prefs = {};
  }
}

function applyPrefs() {
  // Theme
  const theme = state.prefs.theme || localStorage.getItem('vk_theme') || 'dark';
  document.documentElement.setAttribute('data-theme', theme);
  try { localStorage.setItem('vk_theme', theme); } catch {}
  // Auto-lock
  if (Number.isInteger(state.prefs.lock_timeout_minutes)) {
    state.lockTimeout = state.prefs.lock_timeout_minutes;
  }
}

// ═══════════════════════════════════════════════════════════════════════════
//  AUTO-LOCK
// ═══════════════════════════════════════════════════════════════════════════

function resetLockTimer() {
  if (state._lockTimer) clearTimeout(state._lockTimer);
  if (!state.symKey) return;
  state._lockTimer = setTimeout(() => {
    showToast('Session locked due to inactivity', 'info');
    doLogout(false);
  }, state.lockTimeout * 60_000);
}

function installActivityListeners() {
  ['keydown', 'click', 'touchstart', 'scroll'].forEach(evt => {
    window.addEventListener(evt, resetLockTimer, { passive: true, capture: true });
  });
}

// ═══════════════════════════════════════════════════════════════════════════
//  VIEW ROUTER + RENDERING
// ═══════════════════════════════════════════════════════════════════════════

function showAuth() {
  hideEl('#app-shell');
  showEl('#auth-screen');
  document.body.classList.add('auth-active');
  $('#login-username')?.focus();
}

async function showApp() {
  hideEl('#auth-screen');
  showEl('#app-shell');
  document.body.classList.remove('auth-active');
  $('#app-username').textContent = state.username;
  // Load data
  try {
    await loadEverything();
  } catch (e) {
    console.error('[showApp] load failed:', e);
    showToast('Failed to load vault: ' + e.message, 'error');
    return;
  }
  resetLockTimer();
  updateBottomNav(state.view);
  renderAll();
  updateOfflineIndicator();

  // Schedule the health prefetch a few seconds after app loads — gives
  // the UI time to settle and avoids hammering the API on a quick
  // login-then-logout cycle. The prefetch runs entirely in the
  // background; if the user opens Health before it finishes, the
  // health page will use whatever's ready and pick up the rest live.
  schedulePrefetchHealth();
}

// Show / hide the offline banner based on state.offline. Wired up to
// the Retry button which probes the network and triggers a re-sync if
// the connection is back.
function updateOfflineIndicator() {
  const banner = document.getElementById('offline-banner');
  if (!banner) return;
  if (state.offline) {
    banner.classList.remove('hidden');
  } else {
    banner.classList.add('hidden');
  }
}

// Try to reconnect. If the network is back AND we have a (possibly
// expired) token, swap back to online mode and reload data. If the token
// is gone (offline-only login), the user has to log in again to get one.
async function attemptReconnect() {
  if (!window.VK_Offline) return;
  const btn = document.getElementById('offline-banner-retry');
  if (btn) { btn.disabled = true; btn.textContent = 'Checking…'; }
  try {
    const online = await window.VK_Offline.probeOnline();
    if (!online) {
      showToast('Still offline.', 'info');
      return;
    }
    // We're back online. If we have a token, refresh data. If we don't
    // (offline-only login), prompt the user to log in again to establish
    // a session — we keep them in offline mode meanwhile so they can
    // still use the cache.
    if (state.token) {
      state.offline = false;
      try {
        await loadEverything();
        renderAll();
        // Drain any pending offline mutations now that we're back online.
        // Conflicts surface as items with a ⚠ badge for the user to fix.
        if (window.VK_OfflineSync) {
          window.VK_OfflineSync.drainQueue()
            .then(summary => {
              if (summary && summary.sent > 0) {
                // Refresh the UI so newly-synced creates pick up real ids
                loadEverything().then(renderAll).catch(() => {});
              }
            })
            .catch(e => console.warn('[reconnect] drain failed:', e.message));
        }
        showToast('Reconnected.', 'success');
      } catch (e) {
        state.offline = true;
        showToast('Reconnect failed: ' + e.message, 'error');
      }
    } else {
      showToast('Reconnected. Sign in again to sync changes.', 'info');
    }
  } finally {
    updateOfflineIndicator();
    if (btn) {
      btn.disabled = false;
      btn.textContent = 'Retry';
    }
  }
}

function schedulePrefetchHealth() {
  if (state._healthPrefetchTimer) clearTimeout(state._healthPrefetchTimer);
  state._healthPrefetchTimer = setTimeout(() => {
    state._healthPrefetchTimer = null;
    prefetchHealthData().catch(e => console.warn('[prefetch] failed:', e.message));
  }, 3000);
}

function doLogout(explicit) {
  clearSession();
  showAuth();
  if (explicit) showToast('Signed out', 'success');
  $('#login-password') && ($('#login-password').value = '');
}

function renderAll() {
  renderSidebar();
  renderMain();
}

// ── Sidebar (desktop: left panel; mobile: in hamburger menu) ──
function renderSidebar() {
  const sidebar = $('#sidebar');
  if (!sidebar) return;

  const counts = {
    all: state.items.length,
    favorites: state.items.filter(i => i.favorite).length,
    login: state.items.filter(i => i.type === 'login').length,
    card: state.items.filter(i => i.type === 'card').length,
    note: state.items.filter(i => i.type === 'note').length,
    identity: state.items.filter(i => i.type === 'identity').length,
  };

  const foldersHtml = state.folders.map(f => {
    const c = state.items.filter(i => i.folder_id === f.id).length;
    const active = state.view === 'folder:' + f.id ? ' active' : '';
    return `<div class="folder-row${active}">
      <button class="side-link folder-link" data-view="folder:${f.id}">
        <span class="side-dot" style="background:${escHtml(f.color || '#64748b')}"></span>
        <span class="side-label">${escHtml(f.name)}</span>
        <span class="side-count">${c}</span>
      </button>
      <button class="folder-edit-btn" data-folder-edit="${f.id}" title="Edit folder" aria-label="Edit folder">
        <i data-lucide="pencil" width="12" height="12"></i>
      </button>
      <button class="folder-del-btn" data-folder-del="${f.id}" title="Delete folder" aria-label="Delete folder">
        <i data-lucide="trash-2" width="12" height="12"></i>
      </button>
    </div>`;
  }).join('');

  const sideLink = (view, icon, label, count) => {
    const active = state.view === view ? ' active' : '';
    return `<button class="side-link${active}" data-view="${view}">
      <i data-lucide="${icon}" width="16" height="16"></i>
      <span class="side-label">${label}</span>
      <span class="side-count">${count}</span>
    </button>`;
  };

  sidebar.innerHTML = `
    <div class="side-section">
      ${sideLink('all', 'layout-grid', 'All items', counts.all)}
      ${sideLink('favorites', 'star', 'Favorites', counts.favorites)}
    </div>
    <div class="side-section">
      <div class="side-head">Types</div>
      ${sideLink('login', 'key-round', 'Logins', counts.login)}
      ${sideLink('card', 'credit-card', 'Cards', counts.card)}
      ${sideLink('note', 'file-text', 'Notes', counts.note)}
      ${sideLink('identity', 'user', 'Identities', counts.identity)}
    </div>
    <div class="side-section">
      <div class="side-head">
        Folders
        <button class="side-head-add" id="btn-new-folder" title="New folder">
          <i data-lucide="plus" width="14" height="14"></i>
        </button>
      </div>
      ${foldersHtml || '<div class="side-empty">No folders yet</div>'}
    </div>
    <div class="side-section">
      <div class="side-head">Tools</div>
      ${sideLink('generator', 'shuffle', 'Generator', '')}
      ${sideLink('health', 'shield-check', 'Health', '')}
      ${sideLink('settings', 'settings', 'Settings', '')}
    </div>
  `;
  renderIcons(sidebar);
  $$('.side-link', sidebar).forEach(btn => {
    btn.addEventListener('click', () => {
      setView(btn.dataset.view);
    });
  });
  $('#btn-new-folder', sidebar)?.addEventListener('click', () => openFolderDialog());
  $$('[data-folder-edit]', sidebar).forEach(btn => {
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      openFolderDialog(parseInt(btn.dataset.folderEdit, 10));
    });
  });
  $$('[data-folder-del]', sidebar).forEach(btn => {
    btn.addEventListener('click', async (e) => {
      e.stopPropagation();
      const id = parseInt(btn.dataset.folderDel, 10);
      const folder = state.folders.find(f => f.id === id);
      if (!folder) return;
      const itemCount = state.items.filter(i => i.folder_id === id).length;
      const msg = itemCount
        ? `Delete folder "${folder.name}"? ${itemCount} item${itemCount===1?'':'s'} will become unfiled.`
        : `Delete folder "${folder.name}"?`;
      if (!confirm(msg)) return;
      try {
        await api('DELETE', '/api/folders/' + id);
        state.folders = state.folders.filter(f => f.id !== id);
        state.items.forEach(i => { if (i.folder_id === id) i.folder_id = null; });
        if (state.view === 'folder:' + id) state.view = 'all';
        renderAll();
        showToast('Folder deleted', 'success');
      } catch (err) {
        showToast('Failed: ' + err.message, 'error');
      }
    });
  });
}

function setView(view) {
  stopTotpTicker();
  // Save current view's scroll position before switching away. We
  // restore it if the user comes back to the same view, and reset to 0
  // for views they haven't visited yet — so each tab has independent
  // scroll state instead of inheriting the previous tab's scrollTop.
  const main = $('#main-pane');
  const currentScroller = main && main.querySelector('.pane-scroll');
  if (currentScroller && state.view) {
    state._scrollByView = state._scrollByView || {};
    state._scrollByView[state.view] = currentScroller.scrollTop;
  }
  state.view = view;
  state.selectedItemId = null;
  // Collapse mobile menu after nav
  $('#sidebar')?.classList.remove('mobile-open');
  $('#sidebar-overlay')?.classList.remove('visible');
  // Update bottom-nav active state
  updateBottomNav(view);
  renderAll();
  // Restore previous scroll for this view (or 0 if first visit). Done
  // after renderAll() so the DOM is laid out and scrollHeight is real.
  // Use rAF so the assignment happens after the browser has a chance to
  // paint the new content.
  requestAnimationFrame(() => {
    const m = $('#main-pane');
    const newScroller = m && m.querySelector('.pane-scroll');
    if (!newScroller) return;
    const saved = (state._scrollByView && state._scrollByView[view]) || 0;
    newScroller.scrollTop = saved;
  });
}

function updateBottomNav(view) {
  const bnavView = view === 'all' || view === 'favorites' ? 'all'
                 : view === 'generator' ? 'generator'
                 : view === 'health' ? 'health'
                 : view === 'settings' ? 'settings'
                 : view.startsWith('folder:') || ['login','card','note','identity'].includes(view) ? 'all'
                 : null;
  $$('#bottom-nav .bottom-nav-btn').forEach(btn => {
    btn.classList.toggle('active', btn.dataset.bnav === bnavView);
  });
}

// ── Main pane ──
function renderMain() {
  const main = $('#main-pane');
  if (!main) return;

  // Tools panes
  if (state.view === 'generator') return renderGenerator(main);
  if (state.view === 'health')    return renderHealth(main);
  if (state.view === 'settings')  return renderSettings(main);

  // List-based views
  renderList(main);
}

function itemsForCurrentView() {
  const v = state.view;
  let filtered;
  if (v === 'all')             filtered = state.items.slice();
  else if (v === 'favorites')  filtered = state.items.filter(i => i.favorite);
  else if (v.startsWith('folder:')) {
    const id = parseInt(v.slice('folder:'.length), 10);
    filtered = state.items.filter(i => i.folder_id === id);
  }
  else if (VALID_ITEM_TYPES.includes(v)) filtered = state.items.filter(i => i.type === v);
  else filtered = state.items.slice();

  if (state.search) {
    const q = state.search.toLowerCase();
    filtered = filtered.filter(i => {
      const d = i.data || {};
      return (d.name && d.name.toLowerCase().includes(q)) ||
             (d.username && d.username.toLowerCase().includes(q)) ||
             (d.url && d.url.toLowerCase().includes(q)) ||
             (d.notes && d.notes.toLowerCase().includes(q));
    });
  }

  // Sort: favorites first, then name, then updated_at desc
  filtered.sort((a, b) => {
    if (a.favorite !== b.favorite) return a.favorite ? -1 : 1;
    const an = (a.data.name || '').toLowerCase();
    const bn = (b.data.name || '').toLowerCase();
    if (an !== bn) return an < bn ? -1 : 1;
    return (b.updated_at || 0) - (a.updated_at || 0);
  });
  return filtered;
}

function viewTitle() {
  const v = state.view;
  if (v === 'all') return 'All items';
  if (v === 'favorites') return 'Favorites';
  if (v === 'login') return 'Logins';
  if (v === 'card') return 'Cards';
  if (v === 'note') return 'Notes';
  if (v === 'identity') return 'Identities';
  if (v.startsWith('folder:')) {
    const f = state.folders.find(f => f.id === parseInt(v.slice('folder:'.length), 10));
    return f ? f.name : 'Folder';
  }
  return 'Vault';
}

function renderList(main) {
  const items = itemsForCurrentView();
  const title = viewTitle();

  const rowsHtml = items.length ? items.map(i => renderItemRow(i)).join('') : `
    <div class="empty-state" style="padding:48px 16px;text-align:center">
      <div class="empty-icon"><i data-lucide="inbox" width="40" height="40"></i></div>
      <p style="color:var(--text-m);margin-top:12px">
        ${state.search ? 'No items match your search' : 'No items yet'}
      </p>
      ${!state.search ? `<button class="btn btn-primary" id="btn-new-item-empty" style="margin-top:16px">
        <i data-lucide="plus" width="16" height="16"></i>
        New item
      </button>` : ''}
    </div>
  `;

  // Fast path: if the list-header already exists in the DOM (meaning the
  // user is just typing in the search box), only swap the item-list
  // contents instead of blowing away the whole pane. This preserves
  // search input focus + cursor and avoids re-rendering 100+ icons on
  // every keystroke.
  const existingItemList = main.querySelector('.item-list');
  const existingHeader = main.querySelector('.list-header .list-title');
  if (existingItemList && existingHeader && existingHeader.textContent === title) {
    existingItemList.innerHTML = rowsHtml;
    renderIcons(existingItemList);
    wireListRows(main);
    return;
  }

  main.innerHTML = `
    <div class="list-header">
      <h2 class="list-title">${escHtml(title)}</h2>
      <div class="list-actions">
        <div class="search-wrap">
          <i data-lucide="search" width="14" height="14"></i>
          <input type="search" id="search-input" placeholder="Search…" value="${escHtml(state.search)}" />
        </div>
        <button class="btn btn-primary btn-sm" id="btn-new-item">
          <i data-lucide="plus" width="14" height="14"></i>
          <span>New</span>
        </button>
      </div>
    </div>
    <div class="pane-scroll">
      <div class="item-list">
        ${rowsHtml}
      </div>
      <div id="detail-pane"></div>
    </div>
  `;

  renderIcons(main);

  // Wire up search — using a debounced re-render so fast typing doesn't
  // do work it'll just throw away. Keystroke updates state.search
  // immediately for visual feedback; the actual list re-render is
  // coalesced into a single rAF.
  const search = $('#search-input', main);
  let pending = false;
  search.addEventListener('input', (e) => {
    state.search = e.target.value;
    if (pending) return;
    pending = true;
    requestAnimationFrame(() => {
      pending = false;
      renderList(main);
      const newSearch = $('#search-input', main);
      if (newSearch && document.activeElement !== newSearch) {
        newSearch.focus();
        newSearch.setSelectionRange(state.search.length, state.search.length);
      }
    });
  });
  $('#btn-new-item', main)?.addEventListener('click', () => openItemEditor(null));
  $('#btn-new-item-empty', main)?.addEventListener('click', () => openItemEditor(null));

  wireListRows(main);
}

function wireListRows(main) {
  // Use event delegation so we don't attach 100 individual listeners
  // every time the list re-renders.
  const list = main.querySelector('.item-list');
  if (!list || list._delegated) return;
  list._delegated = true;
  list.addEventListener('click', (e) => {
    const card = e.target.closest('.item-card');
    if (!card || !list.contains(card)) return;
    const id = parseInt(card.dataset.id, 10);
    if (!Number.isNaN(id)) {
      state.selectedItemId = id;
      openItemDetail(id);
    }
  });
}

function iconForType(type) {
  return { login:'key-round', card:'credit-card', note:'file-text', identity:'user' }[type] || 'file';
}

function renderItemRow(item) {
  const d = item.data || {};
  const name = d.name || '(unnamed)';
  const subtitle = d.username || d.number || d.email || '';
  const starHtml = item.favorite
    ? `<i data-lucide="star" width="14" height="14" class="item-fav-indicator"></i>`
    : '';
  return `
    <button class="item-card" data-id="${item.id}">
      <span class="item-icon"><i data-lucide="${iconForType(item.type)}" width="16" height="16"></i></span>
      <span class="item-text">
        <span class="item-name">${escHtml(name)}</span>
        ${subtitle ? `<span class="item-sub">${escHtml(subtitle)}</span>` : ''}
      </span>
      ${starHtml}
    </button>
  `;
}

// ═══════════════════════════════════════════════════════════════════════════
//  ITEM DETAIL / EDIT
// ═══════════════════════════════════════════════════════════════════════════

async function openItemDetail(id) {
  const item = state.items.find(i => i.id === id);
  if (!item) return;
  state.selectedItemId = id;
  const folder = state.folders.find(f => f.id === item.folder_id);
  const folderTag = folder
    ? `<span class="detail-sub" style="margin-top:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:100%"><span class="side-dot" style="background:${escHtml(folder.color || '#64748b')};flex-shrink:0"></span><span style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${escHtml(folder.name)}</span></span>`
    : '';
  const titleHtml = `
    <div style="display:flex;align-items:center;gap:10px;flex:1;min-width:0">
      <span class="item-icon" style="width:32px;height:32px"><i data-lucide="${iconForType(item.type)}" width="16" height="16"></i></span>
      <div style="min-width:0;flex:1">
        <div style="font-size:15px;font-weight:600;color:var(--text);overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${escHtml(item.data.name || '(unnamed)')}</div>
        ${folderTag}
      </div>
    </div>
  `;
  openModal({
    title: titleHtml,
    titleHtml: true,  // tell openModal not to escape this — we built it
    body: renderItemDetailBody(item),
    footer: `
      <button class="btn btn-danger" data-action="delete" title="Delete">
        <i data-lucide="trash-2" width="14" height="14"></i> Delete
      </button>
      <div style="flex:1"></div>
      <button class="btn btn-ghost" data-action="close">Close</button>
      <button class="btn btn-primary" data-action="edit">
        <i data-lucide="pencil" width="14" height="14"></i> Edit
      </button>
    `,
    onMount: (modal) => wireItemDetailModal(modal, item),
    onClose: () => { stopTotpTicker(); state.selectedItemId = null; },
  });
}

function renderItemDetailBody(item) {
  const d = item.data || {};
  const fields = [];
  if (item.type === 'login') {
    fields.push(['Username', d.username, 'username']);
    fields.push(['Password', d.password, 'password']);
    if (d.totp) fields.push(['TOTP', null, 'totp']);
    fields.push(['URL', d.url, 'url']);
    fields.push(['Notes', d.notes, 'notes']);
  } else if (item.type === 'card') {
    fields.push(['Cardholder', d.cardholder, 'cardholder']);
    fields.push(['Number', d.number, 'number']);
    fields.push(['Expiry', d.expiry, 'expiry']);
    fields.push(['CVV', d.cvv, 'cvv']);
    fields.push(['PIN', d.pin, 'pin']);
    fields.push(['Notes', d.notes, 'notes']);
  } else if (item.type === 'note') {
    fields.push(['Content', d.content, 'content']);
  } else if (item.type === 'identity') {
    fields.push(['Full name', d.fullname, 'fullname']);
    fields.push(['Email', d.email, 'email']);
    fields.push(['Phone', d.phone, 'phone']);
    fields.push(['Address', d.address, 'address']);
    fields.push(['Notes', d.notes, 'notes']);
  }
  const fieldsHtml = fields
    .filter(([label, value, key]) => {
      if (key === 'totp') return !!d.totp;
      return value !== undefined && value !== null && value !== '';
    })
    .map(([label, value, key]) => {
      if (key === 'totp') {
        return `<div class="detail-field" data-key="totp">
          <div class="detail-field-label">${escHtml(label)}</div>
          <div class="detail-field-value">
            <span class="totp-code" id="totp-code-${item.id}">—</span>
            <span class="totp-progress"><span class="totp-progress-bar" id="totp-bar-${item.id}"></span></span>
            <button class="btn-icon btn-ghost copy-btn" data-copy-totp="1" title="Copy"><i data-lucide="copy" width="14" height="14"></i></button>
          </div>
        </div>`;
      }
      if (key === 'password' || key === 'cvv' || key === 'pin' || key === 'number') {
        return `<div class="detail-field" data-key="${escHtml(key)}">
          <div class="detail-field-label">${escHtml(label)}</div>
          <div class="detail-field-value">
            <span class="masked" data-value="${escHtml(value || '')}">••••••••</span>
            <button class="btn-icon btn-ghost reveal-btn" title="Show"><i data-lucide="eye" width="14" height="14"></i></button>
            <button class="btn-icon btn-ghost copy-btn" data-copy="${escHtml(value || '')}" title="Copy"><i data-lucide="copy" width="14" height="14"></i></button>
          </div>
        </div>`;
      }
      if (key === 'url' && value) {
        return `<div class="detail-field">
          <div class="detail-field-label">${escHtml(label)}</div>
          <div class="detail-field-value">
            <a href="${escHtml(value.startsWith('http') ? value : 'https://' + value)}" target="_blank" rel="noopener noreferrer" class="detail-link">${escHtml(value)}</a>
            <button class="btn-icon btn-ghost copy-btn" data-copy="${escHtml(value)}" title="Copy"><i data-lucide="copy" width="14" height="14"></i></button>
          </div>
        </div>`;
      }
      if (key === 'notes' || key === 'content' || key === 'address') {
        return `<div class="detail-field">
          <div class="detail-field-label">${escHtml(label)}</div>
          <div class="detail-field-value" style="white-space:pre-wrap;word-break:break-word">${escHtml(value)}</div>
        </div>`;
      }
      return `<div class="detail-field">
        <div class="detail-field-label">${escHtml(label)}</div>
        <div class="detail-field-value">
          <span>${escHtml(value)}</span>
          <button class="btn-icon btn-ghost copy-btn" data-copy="${escHtml(value)}" title="Copy"><i data-lucide="copy" width="14" height="14"></i></button>
        </div>
      </div>`;
    }).join('');
  return `<div class="detail-fields" style="margin-top:0">${fieldsHtml || '<div style="color:var(--text-m);padding:8px">No details</div>'}</div>`;
}

function wireItemDetailModal(modal, item) {
  $$('.reveal-btn', modal).forEach(btn => {
    btn.addEventListener('click', () => {
      const masked = btn.parentElement.querySelector('.masked');
      if (!masked) return;
      const val = masked.dataset.value;
      if (masked.textContent.startsWith('•')) {
        masked.textContent = val;
        btn.querySelector('i')?.setAttribute('data-lucide', 'eye-off');
      } else {
        masked.textContent = '••••••••';
        btn.querySelector('i')?.setAttribute('data-lucide', 'eye');
      }
      renderIcons();
    });
  });
  $$('.copy-btn', modal).forEach(btn => {
    btn.addEventListener('click', () => {
      if (btn.dataset.copyTotp) {
        const code = $('#totp-code-' + item.id)?.textContent;
        if (code && /^\d/.test(code)) copyWithClear(code.replace(/\s/g, ''));
      } else {
        copyWithClear(btn.dataset.copy || '');
      }
    });
  });
  modal.querySelector('[data-action="close"]')?.addEventListener('click', () => closeModal());
  modal.querySelector('[data-action="edit"]')?.addEventListener('click', () => {
    closeModal();
    openItemEditor(item.id);
  });
  modal.querySelector('[data-action="delete"]')?.addEventListener('click', () => {
    deleteItemConfirm(item.id);
    // deleteItemConfirm closes via renderAll; if user cancels, modal stays open
  });

  // TOTP: start rotating if present
  if (item.data.totp) startTotpTicker(item);
}

async function toggleFavorite(id) {
  const item = state.items.find(i => i.id === id);
  if (!item) return;
  const newFav = !item.favorite;
  try {
    await api('PATCH', '/api/vault/' + id + '/favorite', { favorite: newFav });
    item.favorite = newFav;
    renderAll();
  } catch (e) {
    showToast('Failed to update favorite', 'error');
  }
}

async function deleteItemConfirm(id) {
  const item = state.items.find(i => i.id === id);
  if (!item) return;
  const name = item.data.name || 'this item';

  // Type-specific labels so the warning matches what the user sees in the UI.
  const TYPE_LABELS = {
    login:    { noun: 'login',    article: 'this login' },
    note:     { noun: 'note',     article: 'this note' },
    card:     { noun: 'card',     article: 'this card' },
    identity: { noun: 'identity', article: 'this identity' },
  };
  const label = TYPE_LABELS[item.type] || { noun: 'item', article: 'this item' };

  // Open a confirm modal on top of any existing modal (detail modal stays open behind)
  openModal({
    title: `Move ${label.noun} to Trash`,
    body: `
      <p style="font-size:14px;color:var(--text);margin:0 0 12px">
        Move <strong>${escHtml(name)}</strong> to the Trash?
      </p>
      <p style="font-size:13px;color:var(--text-m);margin:0 0 6px">
        This ${escHtml(label.noun)} will stay in <strong>Trash</strong> for 6 months,
        and you can restore it from Settings → Recently deleted any time before then.
      </p>
      <p style="font-size:12px;color:var(--text-f);margin:0">
        After 6 months it will be deleted permanently and cannot be recovered.
      </p>
    `,
    footer: `
      <button class="btn btn-ghost" data-action="cancel">Cancel</button>
      <button class="btn btn-danger" data-action="confirm">
        <i data-lucide="trash-2" width="14" height="14"></i> Move to Trash
      </button>
    `,
    onMount: (modal) => {
      modal.querySelector('[data-action="cancel"]').addEventListener('click', () => closeModal());
      modal.querySelector('[data-action="confirm"]').addEventListener('click', async () => {
        const btn = modal.querySelector('[data-action="confirm"]');
        btn.disabled = true;
        try {
          await api('DELETE', '/api/vault/' + id);
          state.items = state.items.filter(i => i.id !== id);
          invalidateHealthCache();
          if (state.selectedItemId === id) state.selectedItemId = null;
          // Close BOTH the confirm modal AND the detail modal if it's open behind us.
          closeModal();
          if (_modalStack.length) closeModal();
          renderAll();
          showToast('Moved to Trash', 'success');
        } catch (e) {
          btn.disabled = false;
          showToast('Failed: ' + e.message, 'error');
        }
      });
    },
  });
}

// ═══════════════════════════════════════════════════════════════════════════
//  ITEM EDITOR
// ═══════════════════════════════════════════════════════════════════════════

function openItemEditor(id) {
  const existing = id ? state.items.find(i => i.id === id) : null;
  const type = existing?.type || 'login';
  openModal({
    title: existing ? 'Edit item' : 'New item',
    body: renderItemEditorBody(existing, type),
    footer: `
      <button class="btn btn-ghost" data-action="cancel">Cancel</button>
      <button class="btn btn-primary" data-action="save">Save</button>
    `,
    onMount: (modal) => wireItemEditor(modal, existing),
  });
}

function renderItemEditorBody(item, currentType) {
  const d = item?.data || {};
  const typeOptions = VALID_ITEM_TYPES.map(t =>
    `<option value="${t}"${t === currentType ? ' selected' : ''}>${t}</option>`
  ).join('');
  const folderOptions = ['<option value="">(no folder)</option>']
    .concat(state.folders.map(f => `<option value="${f.id}"${item?.folder_id === f.id ? ' selected':''}>${escHtml(f.name)}</option>`))
    .join('');

  // Type-specific fields
  const loginFields = `
    <div class="form-group">
      <label class="form-label">Username</label>
      <input class="form-input" name="username" value="${escHtml(d.username || '')}" />
    </div>
    <div class="form-group">
      <label class="form-label">Password</label>
      <div class="form-input-wrapper">
        <input class="form-input" type="password" name="password" value="${escHtml(d.password || '')}" />
        <button type="button" class="btn-icon input-action" data-gen-toggle="1" title="Generator"><i data-lucide="shuffle" width="14" height="14"></i></button>
        <button type="button" class="btn-icon input-action" data-reveal-input="1" title="Show/hide"><i data-lucide="eye" width="14" height="14"></i></button>
      </div>
      <div class="inline-gen hidden" id="inline-gen">
        <div class="inline-gen-header">
          <strong>Password generator</strong>
          <button type="button" class="btn-icon btn-ghost" data-gen-close="1" title="Close"><i data-lucide="x" width="14" height="14"></i></button>
        </div>
        <div class="inline-gen-output">
          <code id="inline-gen-output">—</code>
          <button type="button" class="btn btn-secondary btn-sm" data-gen-regen="1"><i data-lucide="shuffle" width="14" height="14"></i> Regenerate</button>
          <button type="button" class="btn btn-primary btn-sm" data-gen-use="1">Use this</button>
        </div>
        <div class="inline-gen-strength">
          <span class="muted" id="inline-gen-strength-label">Strength: —</span>
          <div class="gen-strength-bar"><div class="gen-strength-fill" id="inline-gen-strength-bar"></div></div>
        </div>
        <div class="inline-gen-controls">
          <label class="form-label">Length: <span id="inline-gen-len-val">20</span></label>
          <input type="range" min="8" max="256" value="20" id="inline-gen-len" />
          <label class="gen-toggle"><input type="checkbox" checked data-igen-opt="upper"> Uppercase (A-Z)</label>
          <label class="gen-toggle"><input type="checkbox" checked data-igen-opt="lower"> Lowercase (a-z)</label>
          <label class="gen-toggle"><input type="checkbox" checked data-igen-opt="digits"> Digits (0-9)</label>
          <label class="gen-toggle"><input type="checkbox" checked data-igen-opt="symbols"> Symbols (!@#...)</label>
        </div>
      </div>
    </div>
    <div class="form-group">
      <label class="form-label">URL</label>
      <input class="form-input" name="url" value="${escHtml(d.url || '')}" placeholder="https://example.com" />
    </div>
    <div class="form-group">
      <label class="form-label">TOTP secret (optional)</label>
      <input class="form-input" name="totp" value="${escHtml(d.totp || '')}" placeholder="base32 secret (ignore spaces)" />
      <p class="form-hint">Usually shown under the QR code during 2FA setup.</p>
    </div>
    <div class="form-group">
      <label class="form-label">Notes</label>
      <textarea class="form-textarea" name="notes" rows="3">${escHtml(d.notes || '')}</textarea>
    </div>
  `;
  const cardFields = `
    <div class="form-group"><label class="form-label">Cardholder</label><input class="form-input" name="cardholder" value="${escHtml(d.cardholder || '')}" /></div>
    <div class="form-group"><label class="form-label">Number</label><input class="form-input" name="number" value="${escHtml(d.number || '')}" inputmode="numeric" /></div>
    <div class="form-row">
      <div class="form-group" style="flex:1"><label class="form-label">Expiry</label><input class="form-input" name="expiry" value="${escHtml(d.expiry || '')}" placeholder="MM/YY" /></div>
      <div class="form-group" style="flex:1"><label class="form-label">CVV</label><input class="form-input" type="password" name="cvv" value="${escHtml(d.cvv || '')}" /></div>
    </div>
    <div class="form-group"><label class="form-label">PIN</label><input class="form-input" type="password" name="pin" value="${escHtml(d.pin || '')}" /></div>
    <div class="form-group"><label class="form-label">Notes</label><textarea class="form-textarea" name="notes" rows="2">${escHtml(d.notes || '')}</textarea></div>
  `;
  const noteFields = `
    <div class="form-group"><label class="form-label">Content</label><textarea class="form-textarea" name="content" rows="10">${escHtml(d.content || '')}</textarea></div>
  `;
  const identityFields = `
    <div class="form-group"><label class="form-label">Full name</label><input class="form-input" name="fullname" value="${escHtml(d.fullname || '')}" /></div>
    <div class="form-group"><label class="form-label">Email</label><input class="form-input" name="email" value="${escHtml(d.email || '')}" /></div>
    <div class="form-group"><label class="form-label">Phone</label><input class="form-input" name="phone" value="${escHtml(d.phone || '')}" /></div>
    <div class="form-group"><label class="form-label">Address</label><textarea class="form-textarea" name="address" rows="3">${escHtml(d.address || '')}</textarea></div>
    <div class="form-group"><label class="form-label">Notes</label><textarea class="form-textarea" name="notes" rows="2">${escHtml(d.notes || '')}</textarea></div>
  `;
  const fieldsByType = { login: loginFields, card: cardFields, note: noteFields, identity: identityFields };

  return `
    <form id="item-edit-form">
      <div class="form-row">
        <div class="form-group" style="flex:2">
          <label class="form-label">Name</label>
          <input class="form-input" name="name" value="${escHtml(d.name || '')}" required />
        </div>
        <div class="form-group" style="flex:1">
          <label class="form-label">Type</label>
          <select class="form-select" name="type"${item ? ' disabled' : ''}>${typeOptions}</select>
        </div>
      </div>
      <div id="type-specific">${fieldsByType[currentType]}</div>
      <div class="form-row">
        <div class="form-group" style="flex:1">
          <label class="form-label">Folder</label>
          <select class="form-select" name="folder_id">${folderOptions}</select>
        </div>
        <div class="form-group" style="flex:0 0 auto;align-self:flex-end;padding-bottom:6px">
          <label class="gen-toggle" style="cursor:pointer">
            <input type="checkbox" name="favorite"${item?.favorite ? ' checked' : ''}>
            Favorite
          </label>
        </div>
      </div>
    </form>
  `;
}

function wireItemEditor(modal, existing) {
  const form = $('#item-edit-form', modal);
  const typeSelect = form.querySelector('select[name="type"]');
  const typeSpecific = $('#type-specific', modal);

  // Re-render type-specific fields when type changes (only valid on new items)
  typeSelect?.addEventListener('change', () => {
    const t = typeSelect.value;
    const tmp = document.createElement('div');
    tmp.innerHTML = renderItemEditorBody(null, t);
    typeSpecific.innerHTML = $('#type-specific', tmp).innerHTML;
    renderIcons(typeSpecific);
    wirePasswordGenerators(typeSpecific);
  });

  wirePasswordGenerators(form);

  modal.querySelector('[data-action="cancel"]').addEventListener('click', () => closeModal());
  modal.querySelector('[data-action="save"]').addEventListener('click', async (e) => {
    e.preventDefault();
    const fd = new FormData(form);
    const type = existing ? existing.type : (fd.get('type') || 'login');
    const data = {};
    for (const [k, v] of fd.entries()) {
      if (k === 'type' || k === 'folder_id' || k === 'favorite') continue;
      data[k] = v;
    }
    const folderRaw = fd.get('folder_id');
    const folder_id = folderRaw ? parseInt(folderRaw, 10) : null;
    const favorite = fd.get('favorite') === 'on';
    // Strip TOTP whitespace
    if (data.totp) data.totp = data.totp.replace(/\s+/g, '').toUpperCase();
    if (!data.name || !data.name.trim()) {
      showToast('Name is required', 'error'); return;
    }
    const btn = modal.querySelector('[data-action="save"]');
    btn.disabled = true;
    try {
      const encryptedB64 = await encryptItemData(data);
      if (existing) {
        await api('PUT', '/api/vault/' + existing.id, {
          type, folder_id, favorite, encrypted_data: encryptedB64
        });
        existing.data = data;
        existing.folder_id = folder_id;
        existing.favorite = favorite;
        existing.updated_at = Math.floor(Date.now() / 1000);
      } else {
        const resp = await api('POST', '/api/vault', {
          type, folder_id, favorite,
          encrypted_data: encryptedB64,
        });
        state.items.push({
          id: resp.id, type, folder_id, favorite,
          data, created_at: resp.created_at, updated_at: resp.updated_at,
        });
      }
      invalidateHealthCache();
      closeModal();
      renderAll();
      showToast(existing ? 'Updated' : 'Created', 'success');
    } catch (e) {
      console.error(e);
      showToast('Save failed: ' + e.message, 'error');
      btn.disabled = false;
    }
  });
}

function wirePasswordGenerators(root) {
  $$('[data-reveal-input]', root).forEach(btn => {
    btn.addEventListener('click', () => {
      const input = btn.parentElement.querySelector('input');
      if (!input) return;
      input.type = input.type === 'password' ? 'text' : 'password';
      const icon = btn.querySelector('i');
      icon?.setAttribute('data-lucide', input.type === 'password' ? 'eye' : 'eye-off');
      renderIcons(btn);
    });
  });

  // Inline generator panel toggling
  const genPanel = $('#inline-gen', root);
  const opts = { length: 20, upper: true, lower: true, digits: true, symbols: true };
  let currentPw = '';

  function refresh() {
    currentPw = generatePassword(opts);
    const out = $('#inline-gen-output', root);
    if (out) out.textContent = currentPw;
    const s = passwordStrength(currentPw);
    const lab = $('#inline-gen-strength-label', root);
    if (lab) lab.textContent = `Strength: ${s.label} (≈${s.entropy} bits)`;
    const bar = $('#inline-gen-strength-bar', root);
    if (bar) {
      bar.style.width = ((s.score / 4) * 100) + '%';
      bar.style.background = ['#ef4444','#f97316','#eab308','#22c55e','#01696f'][s.score];
    }
  }

  $$('[data-gen-toggle]', root).forEach(btn => {
    btn.addEventListener('click', () => {
      if (!genPanel) return;
      const wasHidden = genPanel.classList.contains('hidden');
      genPanel.classList.toggle('hidden');
      if (wasHidden && !currentPw) refresh();
    });
  });
  $$('[data-gen-close]', root).forEach(btn => {
    btn.addEventListener('click', () => genPanel?.classList.add('hidden'));
  });
  $$('[data-gen-regen]', root).forEach(btn => {
    btn.addEventListener('click', () => refresh());
  });
  $$('[data-gen-use]', root).forEach(btn => {
    btn.addEventListener('click', () => {
      const input = root.querySelector('input[name="password"]');
      if (input && currentPw) {
        input.type = 'text';  // reveal
        input.value = currentPw;
        // small visual feedback
        input.style.boxShadow = '0 0 0 2px var(--success, #22c55e)';
        setTimeout(() => input.style.boxShadow = '', 600);
        genPanel?.classList.add('hidden');
      }
    });
  });
  const lenSlider = $('#inline-gen-len', root);
  lenSlider?.addEventListener('input', (e) => {
    opts.length = parseInt(e.target.value, 10);
    const lv = $('#inline-gen-len-val', root);
    if (lv) lv.textContent = e.target.value;
  });
  lenSlider?.addEventListener('change', () => refresh());
  $$('[data-igen-opt]', root).forEach(inp => {
    inp.addEventListener('change', () => {
      opts[inp.dataset.igenOpt] = inp.checked;
      refresh();
    });
  });
}

// ═══════════════════════════════════════════════════════════════════════════
//  PASSWORD GENERATOR
// ═══════════════════════════════════════════════════════════════════════════

function generatePassword(opts = {}) {
  const length = Math.max(8, Math.min(256, opts.length || 20));
  const charsets = [];
  if (opts.upper !== false) charsets.push('ABCDEFGHIJKLMNOPQRSTUVWXYZ');
  if (opts.lower !== false) charsets.push('abcdefghijklmnopqrstuvwxyz');
  if (opts.digits !== false) charsets.push('0123456789');
  if (opts.symbols) charsets.push('!@#$%^&*()-_=+[]{};:,.<>?');
  if (!charsets.length) charsets.push('abcdefghijklmnopqrstuvwxyz');
  const all = charsets.join('');
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  let out = '';
  // Ensure at least one of each chosen class
  for (const cs of charsets) {
    const b = new Uint8Array(1);
    crypto.getRandomValues(b);
    out += cs[b[0] % cs.length];
  }
  for (let i = out.length; i < length; i++) {
    out += all[bytes[i] % all.length];
  }
  // Shuffle
  const arr = out.split('');
  for (let i = arr.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [arr[i], arr[j]] = [arr[j], arr[i]];
  }
  return arr.join('');
}

function passwordStrength(pw) {
  if (!pw) return { score: 0, label: 'empty' };
  let entropy = 0;
  const hasLower = /[a-z]/.test(pw);
  const hasUpper = /[A-Z]/.test(pw);
  const hasDigit = /[0-9]/.test(pw);
  const hasSym = /[^a-zA-Z0-9]/.test(pw);
  let pool = 0;
  if (hasLower) pool += 26;
  if (hasUpper) pool += 26;
  if (hasDigit) pool += 10;
  if (hasSym)   pool += 32;
  entropy = pw.length * Math.log2(Math.max(pool, 2));
  let label = 'weak', score = 0;
  if (entropy >= 80) { label = 'excellent'; score = 4; }
  else if (entropy >= 60) { label = 'strong'; score = 3; }
  else if (entropy >= 40) { label = 'ok'; score = 2; }
  else if (entropy >= 25) { label = 'weak'; score = 1; }
  else { label = 'very weak'; score = 0; }
  return { score, label, entropy: Math.round(entropy) };
}

// ── Password generation history ──────────────────────────────────────
// We encrypt locally then send only the ciphertext. Server sees only an
// opaque blob.
async function storePasswordHistory(password, opts) {
  console.log('[pwhist] storePasswordHistory called, len=' + (password?.length || 0));
  if (!password) { console.log('[pwhist] no password, bailing'); return; }
  if (!state.symKey) { console.log('[pwhist] no symKey, bailing'); return; }
  if (state.offline) {
    console.log('[pwhist] offline, skipping');
    // No queueing for password history — it's a convenience, not a
    // critical record. If we're offline the user can come back later
    // and it'll be in their next generated batch.
    return;
  }
  try {
    const blob = await encryptItemData({
      password,
      length: password.length,
      classes: {
        upper:   !!(opts && opts.upper),
        lower:   !!(opts && opts.lower),
        digits:  !!(opts && opts.digits),
        symbols: !!(opts && opts.symbols),
      },
    });
    console.log('[pwhist] encrypted, posting (blob len=' + blob.length + ')');
    const resp = await api('POST', '/api/password-history', { encrypted_data: blob });
    console.log('[pwhist] saved id=' + resp?.id);
  } catch (e) {
    console.error('[pwhist] store failed:', e.message, e);
    // Surface the error so the user knows the history isn't being saved.
    // Use a non-blocking toast at the bottom.
    try { showToast('History save failed: ' + e.message, 'error'); } catch {}
  }
}

async function loadPasswordHistory() {
  if (!state.token) return [];
  try {
    const rows = await api('GET', '/api/password-history');
    if (!Array.isArray(rows)) return [];
    const out = [];
    for (const r of rows) {
      try {
        const data = await decryptItemData(r.encrypted_data);
        out.push({
          id: r.id,
          created_at: r.created_at,
          password: data.password || '',
          length: data.length || (data.password || '').length,
          classes: data.classes || {},
        });
      } catch {}
    }
    return out;
  } catch (e) {
    console.warn('[pwhist] load failed:', e.message);
    return [];
  }
}


function renderGenerator(main) {
  const opts = main._genOpts = main._genOpts || { length:20, upper:true, lower:true, digits:true, symbols:true };
  const pw = main._genPw = main._genPw || generatePassword(opts);
  const s = passwordStrength(pw);
  main.innerHTML = `
    <div class="list-header"><h2 class="list-title">Password generator</h2></div>
    <div class="pane-scroll">
      <div class="gen-card">
        <div class="generator-output">
          <code id="gen-output">${escHtml(pw)}</code>
          <div style="display:flex;gap:8px;flex-wrap:wrap">
            <button class="btn btn-secondary btn-sm" id="gen-regen"><i data-lucide="shuffle" width="14" height="14"></i> Regenerate</button>
            <button class="btn btn-primary btn-sm" id="gen-copy"><i data-lucide="copy" width="14" height="14"></i> Copy</button>
          </div>
        </div>
        <div class="gen-strength">
          <div class="gen-strength-label">Strength: <strong id="gen-strength-text">${escHtml(s.label)}</strong> (<span id="gen-strength-bits">≈${s.entropy} bits</span>)</div>
          <div class="gen-strength-bar"><div class="gen-strength-fill" id="gen-strength-fill" style="width:${(s.score/4)*100}%;background:${['#ef4444','#f97316','#eab308','#22c55e','#01696f'][s.score]}"></div></div>
        </div>
        <div class="gen-controls">
          <label class="form-label">Length: <span id="len-val">${opts.length}</span></label>
          <input type="range" min="8" max="256" value="${opts.length}" id="gen-len" />
          <label class="gen-toggle"><input type="checkbox" ${opts.upper?'checked':''} data-opt="upper"> Uppercase (A-Z)</label>
          <label class="gen-toggle"><input type="checkbox" ${opts.lower?'checked':''} data-opt="lower"> Lowercase (a-z)</label>
          <label class="gen-toggle"><input type="checkbox" ${opts.digits?'checked':''} data-opt="digits"> Digits (0-9)</label>
          <label class="gen-toggle"><input type="checkbox" ${opts.symbols?'checked':''} data-opt="symbols"> Symbols (!@#...)</label>
        </div>
        <div style="margin-top:18px;padding-top:14px;border-top:1px solid var(--divider,#2a2927);">
          <button class="btn btn-ghost btn-sm" id="gen-history">
            <i data-lucide="history" width="14" height="14"></i> View generation history
          </button>
          <p style="margin:8px 0 0;font-size:11.5px;color:var(--text-f,#888);line-height:1.5">
            Every password you copy is saved here for 6 months in case you forget to save it as an item.
          </p>
        </div>
      </div>
    </div>
  `;
  renderIcons(main);

  // Update password + strength UI in-place. Avoids the full innerHTML
  // re-render on every regen which destroys event listeners and causes
  // the brief "black screen" the user reported when scrubbing the slider.
  function applyNewPw(pw) {
    main._genPw = pw;
    const s = passwordStrength(pw);
    const colors = ['#ef4444','#f97316','#eab308','#22c55e','#01696f'];
    const out = $('#gen-output', main);
    if (out) out.textContent = pw;
    const t = $('#gen-strength-text', main);
    if (t) t.textContent = s.label;
    const b = $('#gen-strength-bits', main);
    if (b) b.textContent = '≈' + s.entropy + ' bits';
    const f = $('#gen-strength-fill', main);
    if (f) {
      f.style.width = (s.score / 4 * 100) + '%';
      f.style.background = colors[s.score];
    }
  }

  const regen = () => applyNewPw(generatePassword(main._genOpts));

  $('#gen-regen', main).addEventListener('click', regen);
  $('#gen-copy', main).addEventListener('click', () => {
    const pw = main._genPw;
    copyWithClear(pw);
    storePasswordHistory(pw, main._genOpts).catch(() => {});
  });
  $('#gen-history', main).addEventListener('click', openPasswordHistoryModal);

  // Slider input updates the LENGTH label live; debounced regen on
  // change so we don't generate 256-char passwords mid-scrub on every
  // pixel of slider travel.
  $('#gen-len', main).addEventListener('input', (e) => {
    main._genOpts.length = parseInt(e.target.value, 10);
    $('#len-val', main).textContent = e.target.value;
  });
  $('#gen-len', main).addEventListener('change', regen);
  $$('[data-opt]', main).forEach(inp => {
    inp.addEventListener('change', () => {
      main._genOpts[inp.dataset.opt] = inp.checked;
      regen();
    });
  });
}

async function openPasswordHistoryModal() {
  openModal({
    title: 'Password generation history',
    body: '<div id="pwhist-body" style="min-height:120px;display:flex;align-items:center;justify-content:center;color:var(--text-m);font-size:13px;">Loading…</div>',
    footer: `
      <button class="btn btn-danger" data-action="clear" style="margin-right:auto">Clear all</button>
      <button class="btn btn-ghost" data-action="close">Close</button>
    `,
    onMount: async (modal) => {
      modal.querySelector('[data-action="close"]').addEventListener('click', () => closeModal());
      modal.querySelector('[data-action="clear"]').addEventListener('click', async () => {
        if (!confirm('Permanently delete all password generation history? This cannot be undone.')) return;
        try {
          await api('DELETE', '/api/password-history');
          showToast('History cleared', 'success');
          closeModal();
        } catch (e) {
          showToast('Failed: ' + e.message, 'error');
        }
      });
      const body = modal.querySelector('#pwhist-body');
      try {
        const list = await loadPasswordHistory();
        if (!list.length) {
          body.innerHTML = `
            <div style="text-align:center;padding:24px 0;color:var(--text-m);font-size:13px;line-height:1.6">
              <i data-lucide="history" width="32" height="32" style="opacity:0.3;display:block;margin:0 auto 10px"></i>
              No password history yet.<br/>
              Passwords you copy from the generator will appear here.
            </div>
          `;
          renderIcons(body);
          return;
        }
        body.style.cssText = 'min-height:auto';
        body.innerHTML = `
          <div style="font-size:12px;color:var(--text-m);margin-bottom:12px;line-height:1.5">
            ${list.length} password${list.length === 1 ? '' : 's'} from the last 6 months.
            Tap one to copy. Entries auto-delete after 6 months.
          </div>
          <div id="pwhist-list" style="display:flex;flex-direction:column;gap:8px;max-height:50vh;overflow-y:auto;"></div>
        `;
        const listEl = body.querySelector('#pwhist-list');
        for (const entry of list) {
          const row = document.createElement('div');
          row.style.cssText = `
            display:flex;align-items:center;gap:8px;
            background:rgba(255,255,255,0.02);
            border:1px solid var(--divider,#2a2927);
            border-radius:8px;padding:10px 12px;
          `;
          const ago = relativeTime(entry.created_at);
          row.innerHTML = `
            <code style="flex:1;min-width:0;font-size:12px;font-family:var(--mono);color:var(--primary);overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${escHtml(entry.password)}</code>
            <span style="font-size:11px;color:var(--text-f);white-space:nowrap;flex-shrink:0">${escHtml(ago)}</span>
            <button class="btn btn-ghost btn-icon" data-act="copy" title="Copy" style="flex-shrink:0">
              <i data-lucide="copy" width="14" height="14"></i>
            </button>
            <button class="btn btn-ghost btn-icon" data-act="delete" title="Delete" style="flex-shrink:0;color:var(--danger,#e06080)">
              <i data-lucide="x" width="14" height="14"></i>
            </button>
          `;
          row.querySelector('[data-act="copy"]').addEventListener('click', () => {
            copyWithClear(entry.password);
          });
          row.querySelector('[data-act="delete"]').addEventListener('click', async () => {
            try {
              await api('DELETE', '/api/password-history/' + entry.id);
              row.remove();
              const remaining = listEl.children.length;
              if (remaining === 0) {
                openPasswordHistoryModal();  // re-render empty state
                closeModal();
              }
            } catch (e) {
              showToast('Failed: ' + e.message, 'error');
            }
          });
          listEl.appendChild(row);
        }
        renderIcons(body);
      } catch (e) {
        body.innerHTML = `<div style="color:var(--danger,#e06080);text-align:center">Failed to load: ${escHtml(e.message)}</div>`;
      }
    },
  });
}

function relativeTime(epochSec) {
  if (!epochSec) return '';
  const sec = Math.max(0, Date.now() / 1000 - epochSec);
  if (sec < 60) return 'just now';
  if (sec < 3600) return Math.floor(sec / 60) + 'm ago';
  if (sec < 86400) return Math.floor(sec / 3600) + 'h ago';
  if (sec < 86400 * 30) return Math.floor(sec / 86400) + 'd ago';
  if (sec < 86400 * 365) return Math.floor(sec / (86400 * 30)) + 'mo ago';
  return Math.floor(sec / (86400 * 365)) + 'y ago';
}

// ── Trash / Recently Deleted ──────────────────────────────────────────
async function openTrashModal() {
  openModal({
    title: 'Recently deleted',
    body: '<div id="trash-body" style="min-height:120px;display:flex;align-items:center;justify-content:center;color:var(--text-m);font-size:13px;">Loading…</div>',
    footer: `
      <button class="btn btn-danger" data-action="empty" style="margin-right:auto">Empty Trash</button>
      <button class="btn btn-ghost" data-action="close">Close</button>
    `,
    onMount: async (modal) => {
      modal.querySelector('[data-action="close"]').addEventListener('click', () => closeModal());
      modal.querySelector('[data-action="empty"]').addEventListener('click', async () => {
        if (!confirm('Permanently delete ALL items in the Trash? This cannot be undone.')) return;
        try {
          const r = await api('DELETE', '/api/vault/trash');
          showToast('Trash emptied (' + (r.purged || 0) + ' item' + (r.purged === 1 ? '' : 's') + ')', 'success');
          closeModal();
        } catch (e) {
          showToast('Failed: ' + e.message, 'error');
        }
      });
      await renderTrashList(modal);
    },
  });
}

async function renderTrashList(modal) {
  const body = modal.querySelector('#trash-body');
  if (!body) return;
  let trash;
  try {
    trash = await api('GET', '/api/vault/trash');
  } catch (e) {
    body.innerHTML = `<div style="color:var(--danger,#e06080);text-align:center">Failed to load: ${escHtml(e.message)}</div>`;
    return;
  }
  if (!Array.isArray(trash) || trash.length === 0) {
    body.innerHTML = `
      <div style="text-align:center;padding:24px 0;color:var(--text-m);font-size:13px;line-height:1.6">
        <i data-lucide="trash-2" width="32" height="32" style="opacity:0.3;display:block;margin:0 auto 10px"></i>
        Trash is empty.<br/>
        Deleted items will appear here for 6 months before being permanently removed.
      </div>
    `;
    renderIcons(body);
    return;
  }
  body.style.cssText = 'min-height:auto';
  body.innerHTML = `
    <div style="font-size:12px;color:var(--text-m);margin-bottom:12px;line-height:1.5">
      ${trash.length} item${trash.length === 1 ? '' : 's'} in Trash. Items auto-delete 6 months after they're trashed.
    </div>
    <div id="trash-list" style="display:flex;flex-direction:column;gap:8px;max-height:55vh;overflow-y:auto;"></div>
  `;
  const listEl = body.querySelector('#trash-list');

  // Decrypt names client-side
  const TYPE_ICON = { login: 'key', note: 'sticky-note', card: 'credit-card', identity: 'user' };
  for (const item of trash) {
    let data = {};
    try { data = await decryptItemData(item.encrypted_data); } catch {}
    const name = data.name || '(unnamed)';
    const sub = data.username || data.number || data.email || '';

    const trashedAgo = relativeTime(item.deleted_at);
    const purgeIn = item.deleted_at
      ? Math.max(0, Math.ceil(180 - (Date.now()/1000 - item.deleted_at) / 86400))
      : null;
    const purgeText = purgeIn === 0 ? 'Purges soon' :
                      purgeIn === 1 ? 'Purges in 1 day' :
                      purgeIn != null ? 'Purges in ' + purgeIn + ' days' : '';

    const row = document.createElement('div');
    row.style.cssText = `
      display:flex;align-items:center;gap:12px;
      background:rgba(255,255,255,0.02);
      border:1px solid var(--divider,#2a2927);
      border-radius:8px;padding:12px 14px;
    `;
    row.innerHTML = `
      <span style="display:inline-flex;align-items:center;justify-content:center;width:32px;height:32px;border-radius:8px;background:rgba(255,255,255,0.04);flex-shrink:0">
        <i data-lucide="${TYPE_ICON[item.type] || 'file'}" width="16" height="16"></i>
      </span>
      <div style="flex:1;min-width:0">
        <div style="font-size:14px;color:var(--text);overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${escHtml(name)}</div>
        <div style="font-size:11px;color:var(--text-f);margin-top:2px;display:flex;gap:8px;flex-wrap:wrap">
          ${sub ? `<span style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:100%">${escHtml(sub)}</span><span>·</span>` : ''}
          <span>Trashed ${escHtml(trashedAgo)}</span>
          ${purgeText ? `<span>·</span><span style="color:var(--warning,#d4824a)">${escHtml(purgeText)}</span>` : ''}
        </div>
      </div>
      <div style="display:flex;gap:4px;flex-shrink:0">
        <button class="btn btn-ghost btn-icon" data-act="restore" title="Restore">
          <i data-lucide="rotate-ccw" width="14" height="14"></i>
        </button>
        <button class="btn btn-ghost btn-icon" data-act="purge" title="Delete forever" style="color:var(--danger,#e06080)">
          <i data-lucide="x" width="14" height="14"></i>
        </button>
      </div>
    `;
    row.querySelector('[data-act="restore"]').addEventListener('click', async () => {
      try {
        await api('POST', '/api/vault/' + item.id + '/restore');
        row.remove();
        showToast('Restored', 'success');
        await loadEverything();
        renderAll();
        // If list is now empty, re-render
        if (listEl.children.length === 0) await renderTrashList(modal);
      } catch (e) {
        showToast('Failed to restore: ' + e.message, 'error');
      }
    });
    row.querySelector('[data-act="purge"]').addEventListener('click', async () => {
      if (!confirm('Permanently delete "' + name + '"? This cannot be undone.')) return;
      try {
        await api('DELETE', '/api/vault/' + item.id + '/purge');
        row.remove();
        showToast('Permanently deleted', 'success');
        if (listEl.children.length === 0) await renderTrashList(modal);
      } catch (e) {
        showToast('Failed: ' + e.message, 'error');
      }
    });
    listEl.appendChild(row);
  }
  renderIcons(body);
}


// ═══════════════════════════════════════════════════════════════════════════
//  COPY TO CLIPBOARD (with auto-clear)
// ═══════════════════════════════════════════════════════════════════════════

async function copyWithClear(text) {
  if (!text) return;
  try {
    await navigator.clipboard.writeText(text);
  } catch (e) {
    console.warn('[copy] clipboard.writeText failed:', e.message);
    showToast('Could not copy to clipboard', 'error');
    return;
  }
  const clearSec = state.prefs.clipboard_clear_seconds ?? CLIPBOARD_CLEAR_SECONDS_DEFAULT;
  showToast(clearSec ? `Copied — clears in ${clearSec}s` : 'Copied', 'success');
  if (state._clipboardTimer) clearTimeout(state._clipboardTimer);
  if (clearSec > 0) {
    state._clipboardTimer = setTimeout(async () => {
      try {
        // Best-effort clear: write empty string. Only works if our tab still has focus.
        await navigator.clipboard.writeText('');
      } catch { /* expected if tab lost focus */ }
      state._clipboardTimer = null;
    }, clearSec * 1000);
  }
}

// ═══════════════════════════════════════════════════════════════════════════
//  TOTP (rotating code display)
// ═══════════════════════════════════════════════════════════════════════════

async function generateTotp(secretBase32, timeStep = 30, digits = 6) {
  // Decode base32
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const clean = secretBase32.replace(/=+$/, '').toUpperCase().replace(/[^A-Z2-7]/g, '');
  const bits = clean.split('').map(c => alphabet.indexOf(c).toString(2).padStart(5, '0')).join('');
  const bytes = new Uint8Array(Math.floor(bits.length / 8));
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(bits.substr(i * 8, 8), 2);
  }
  // HMAC-SHA1 of current time counter
  const counter = Math.floor(Date.now() / 1000 / timeStep);
  const counterBytes = new Uint8Array(8);
  new DataView(counterBytes.buffer).setBigUint64(0, BigInt(counter));
  const key = await crypto.subtle.importKey('raw', bytes, { name:'HMAC', hash:'SHA-1' }, false, ['sign']);
  const sig = new Uint8Array(await crypto.subtle.sign('HMAC', key, counterBytes));
  const offset = sig[sig.length - 1] & 0x0f;
  const binary = ((sig[offset] & 0x7f) << 24) | ((sig[offset+1] & 0xff) << 16) |
                 ((sig[offset+2] & 0xff) << 8)  | (sig[offset+3] & 0xff);
  const code = (binary % Math.pow(10, digits)).toString().padStart(digits, '0');
  const secondsInto = (Date.now() / 1000) % timeStep;
  return { code, secondsLeft: Math.ceil(timeStep - secondsInto), progress: secondsInto / timeStep };
}

let _totpTicker = null;
function startTotpTicker(item) {
  stopTotpTicker();
  const codeEl = $('#totp-code-' + item.id);
  const barEl = $('#totp-bar-' + item.id);
  if (!codeEl || !barEl) return;
  const tick = async () => {
    try {
      const { code, progress } = await generateTotp(item.data.totp);
      if (codeEl) codeEl.textContent = code.slice(0, 3) + ' ' + code.slice(3);
      if (barEl) barEl.style.width = ((1 - progress) * 100) + '%';
    } catch (e) {
      if (codeEl) codeEl.textContent = 'invalid';
    }
  };
  tick();
  _totpTicker = setInterval(tick, 1000);
}
function stopTotpTicker() {
  if (_totpTicker) { clearInterval(_totpTicker); _totpTicker = null; }
}

// ═══════════════════════════════════════════════════════════════════════════
//  FOLDER DIALOG
// ═══════════════════════════════════════════════════════════════════════════

function openFolderDialog(existingId) {
  const existing = existingId ? state.folders.find(f => f.id === existingId) : null;
  const swatches = FOLDER_COLORS.map(c =>
    `<button type="button" class="color-swatch${c === (existing?.color || FOLDER_COLORS[0]) ? ' active' : ''}" data-color="${c}" style="background:${c}"></button>`
  ).join('');
  openModal({
    title: existing ? 'Rename folder' : 'New folder',
    body: `
      <form id="folder-form">
        <div class="form-group">
          <label class="form-label">Name</label>
          <input class="form-input" name="name" value="${escHtml(existing?.name || '')}" required autofocus />
        </div>
        <div class="form-group">
          <label class="form-label">Color</label>
          <div class="color-swatches">${swatches}</div>
          <input type="hidden" name="color" value="${escHtml(existing?.color || FOLDER_COLORS[0])}" />
        </div>
      </form>
    `,
    footer: `
      ${existing ? `<button class="btn btn-danger" data-action="delete" style="margin-right:auto">Delete</button>` : ''}
      <button class="btn btn-ghost" data-action="cancel">Cancel</button>
      <button class="btn btn-primary" data-action="save">Save</button>
    `,
    onMount: (modal) => {
      $$('.color-swatch', modal).forEach(sw => {
        sw.addEventListener('click', () => {
          $$('.color-swatch', modal).forEach(s => s.classList.remove('active'));
          sw.classList.add('active');
          $('input[name="color"]', modal).value = sw.dataset.color;
        });
      });
      modal.querySelector('[data-action="cancel"]').addEventListener('click', () => closeModal());
      modal.querySelector('[data-action="save"]').addEventListener('click', async (e) => {
        e.preventDefault();
        const form = $('#folder-form', modal);
        const name = form.name.value.trim();
        const color = form.color.value;
        if (!name) { showToast('Name required', 'error'); return; }
        try {
          const enc = await encryptFolderName(name);
          if (existing) {
            await api('PUT', '/api/folders/' + existing.id, { encrypted_name: enc, color });
            existing.name = name; existing.color = color;
          } else {
            const resp = await api('POST', '/api/folders', { encrypted_name: enc, color });
            state.folders.push({ id: resp.id, name, color, created_at: resp.created_at });
          }
          closeModal();
          renderAll();
          showToast('Folder saved', 'success');
        } catch (err) { showToast('Failed: ' + err.message, 'error'); }
      });
      modal.querySelector('[data-action="delete"]')?.addEventListener('click', async () => {
        if (!confirm(`Delete folder "${existing.name}"? Items inside will become unfiled.`)) return;
        try {
          await api('DELETE', '/api/folders/' + existing.id);
          state.folders = state.folders.filter(f => f.id !== existing.id);
          state.items.forEach(i => { if (i.folder_id === existing.id) i.folder_id = null; });
          if (state.view === 'folder:' + existing.id) state.view = 'all';
          closeModal();
          renderAll();
          showToast('Folder deleted', 'success');
        } catch (err) { showToast('Failed: ' + err.message, 'error'); }
      });
    },
  });
}

// ═══════════════════════════════════════════════════════════════════════════
//  HEALTH REPORT (client-side)
// ═══════════════════════════════════════════════════════════════════════════

// Health cache TTL — 7 days. Per user request: "Even if the health check
// has to check once a week for pwned passwords and 2fa checking. You can
// keep the information cached until update." Cached results live in
// IndexedDB so they survive app reloads. Invalidated on any item mutation
// via invalidateHealthCache().
const HEALTH_CACHE_TTL_MS = 7 * 24 * 60 * 60 * 1000;

async function saveHealthCacheToIDB(cache) {
  if (!window.VK_Offline || !state.username) return;
  try {
    // pwnedMap is a Map (id → {pwned, count}); flatten for storage
    const pwnedObj = {};
    if (cache.pwnedMap instanceof Map) {
      for (const [k, v] of cache.pwnedMap.entries()) {
        pwnedObj[k] = v;
      }
    }
    await window.VK_Offline.setUserKV(state.username, 'healthCache', {
      twoFAState: cache.twoFAState,
      pwnedObj,
      computedAt: cache.computedAt,
    });
  } catch (e) {
    console.warn('[health] persist failed:', e.message);
  }
}

async function loadHealthCacheFromIDB() {
  if (!window.VK_Offline || !state.username) return null;
  try {
    const row = await window.VK_Offline.getUserKV(state.username, 'healthCache');
    if (!row) return null;
    if (!row.computedAt || Date.now() - row.computedAt > HEALTH_CACHE_TTL_MS) {
      return null;  // expired
    }
    const m = new Map();
    for (const [k, v] of Object.entries(row.pwnedObj || {})) {
      m.set(k, v);
    }
    return {
      twoFAState: row.twoFAState,
      pwnedMap: m,
      computedAt: row.computedAt,
    };
  } catch (e) {
    console.warn('[health] load failed:', e.message);
    return null;
  }
}

// Prefetch 2FA + pwned in background after login. Cached on state.healthCache
// so the Health page can render instantly when the user clicks it.
//
// Caller responsibility: invalidateHealthCache() on any vault mutation
// (item create/update/delete, password change, lock/logout).
async function prefetchHealthData() {
  // Only prefetch logged-in users with at least one login item.
  if (!state.token || !state.symKey) return;
  const logins = state.items.filter(i => i.type === 'login' && i.data.password);
  if (!logins.length) return;
  // Skip if already cached in memory
  if (state.healthCache) return;

  // Try IDB cache first — avoids hitting HIBP + 2fa.directory APIs at all
  // when we have a recent enough result.
  const persisted = await loadHealthCacheFromIDB();
  if (persisted) {
    state.healthCache = persisted;
    console.log('[prefetch] health data restored from cache (' +
      Math.round((Date.now() - persisted.computedAt) / 86400000) + 'd old)');
    if (state.view === 'health') {
      const main = $('#main-pane');
      if (main) renderHealth(main);
    }
    return;
  }

  const no2faRaw = logins.filter(i => !i.data.totp);
  const t0 = performance.now();
  // Run 2FA + pwned in parallel
  const [twoFAState, pwnedMap] = await Promise.all([
    classifyTwoFASupport(no2faRaw).catch((e) => {
      console.warn('[prefetch] 2FA classify failed:', e.message);
      return { loading: false, supported: [], unsupported: [], unknown: no2faRaw, error: e.message };
    }),
    checkPwnedBatch(logins).catch((e) => {
      console.warn('[prefetch] pwned check failed:', e.message);
      return new Map();
    }),
  ]);
  state.healthCache = {
    twoFAState,
    pwnedMap,
    computedAt: Date.now(),
  };
  console.log(`[prefetch] health data ready in ${Math.round(performance.now() - t0)}ms`);

  // Persist to IDB so we don't hit the network APIs again for ~7 days.
  saveHealthCacheToIDB(state.healthCache).catch(() => {});

  // If the user is already viewing Health when prefetch finishes, re-render
  // so they see the data without having to navigate away and back.
  if (state.view === 'health') {
    const main = $('#main-pane');
    if (main) renderHealth(main);
  }
}

function invalidateHealthCache() {
  state.healthCache = null;
  // Also drop the IDB copy so the next prefetch fetches fresh data.
  if (window.VK_Offline && state.username) {
    window.VK_Offline.setUserKV(state.username, 'healthCache', null).catch(() => {});
  }
}

async function renderHealth(main) {
  main.innerHTML = `
    <div class="list-header">
      <h2 class="list-title">Vault health</h2>
      <div class="list-actions">
        <button class="btn btn-secondary btn-sm" id="btn-health-refresh" title="Re-check health">
          <i data-lucide="refresh-cw" width="14" height="14"></i>
        </button>
      </div>
    </div>
    <div class="pane-scroll">
      <div id="health-body" class="health-body"><div class="muted" style="padding:24px">Analyzing…</div></div>
    </div>
  `;
  const body = $('#health-body', main);
  $('#btn-health-refresh', main)?.addEventListener('click', () => {
    invalidateHealthCache();
    renderHealth(main);
  });

  try {
    const logins = state.items.filter(i => i.type === 'login' && i.data.password);
    if (!logins.length) {
      body.innerHTML = '<div class="empty-state" style="padding:48px 24px"><div class="empty-icon"><i data-lucide="shield-check" width="40" height="40"></i></div><p style="color:var(--text-m);margin-top:12px">Add a login item with a password to see health analysis.</p></div>';
      renderIcons();
      return;
    }

    // Weak passwords (entropy <= 1, i.e. very weak / weak)
    const weak = logins.filter(i => passwordStrength(i.data.password).score <= 1);

    // Reused passwords
    const byPw = new Map();
    for (const i of logins) {
      const key = i.data.password;
      if (!byPw.has(key)) byPw.set(key, []);
      byPw.get(key).push(i);
    }
    const allReusedGroups = [...byPw.values()].filter(group => group.length > 1);
    const reusedGroupsLocal = allReusedGroups.filter(g => g.every(i => isLocalUrl(i.data.url)));
    const reusedGroupsExternal = allReusedGroups.filter(g => !g.every(i => isLocalUrl(i.data.url)));
    const reusedItemsExternal = reusedGroupsExternal.flat();
    const reusedItemsLocal = reusedGroupsLocal.flat();

    const no2faRaw = logins.filter(i => !i.data.totp);

    // Render with all-loading state. Inputs are guaranteed-defined.
    const baseArgs = {
      logins, weak,
      reusedGroupsExternal, reusedGroupsLocal,
      reusedItemsExternal, reusedItemsLocal,
    };
    function paint(extra) {
      try {
        body.innerHTML = renderHealthSummary({ ...baseArgs, ...extra });
        renderIcons();
        wireHealthBody(body);
      } catch (e) {
        console.error('[health] paint failed:', e);
        body.innerHTML = '<div style="padding:24px;color:var(--error)">Health render error: ' + escHtml(e.message) + '</div>';
      }
    }
    // If we have a prefetched cache, use it immediately and skip the fetch.
    // Cache is invalidated on vault mutations, so anything cached is current.
    if (state.healthCache) {
      paint({
        pwnedMap: state.healthCache.pwnedMap,
        twoFAState: state.healthCache.twoFAState,
      });
      return;
    }

    // No cache — fall back to fetching now (with the loading-spinner UX).
    paint({
      pwnedMap: null,
      twoFAState: { loading: true, supported: [], unsupported: [], unknown: no2faRaw },
    });

    // Run 2FA + pwned in parallel — they're independent and shouldn't block each other.
    let twoFAState = { loading: true, supported: [], unsupported: [], unknown: no2faRaw };
    let pwnedMap = null;
    let pwnedProgress = { done: 0, total: 0 };

    const tfaPromise = (async () => {
      try {
        twoFAState = await classifyTwoFASupport(no2faRaw);
      } catch (e) {
        console.warn('[health] 2FA-check failed:', e.message);
        twoFAState = { loading: false, supported: [], unsupported: [], unknown: no2faRaw, error: e.message };
      }
      paint({ pwnedMap, pwnedProgress, twoFAState });
    })();

    const pwnedPromise = (async () => {
      try {
        pwnedMap = await checkPwnedBatch(logins, (done, total) => {
          pwnedProgress = { done, total };
          paint({ pwnedMap: null, pwnedProgress, twoFAState });
        });
      } catch (e) {
        console.warn('[health] pwned check failed:', e.message);
        pwnedMap = new Map();
      }
      paint({ pwnedMap, pwnedProgress, twoFAState });
    })();

    await Promise.allSettled([tfaPromise, pwnedPromise]);
    paint({ pwnedMap: pwnedMap || new Map(), pwnedProgress, twoFAState });

    // Save into cache so subsequent visits this session are instant.
    state.healthCache = {
      twoFAState,
      pwnedMap: pwnedMap || new Map(),
      computedAt: Date.now(),
    };
  } catch (e) {
    console.error('[health] renderHealth threw:', e);
    body.innerHTML = '<div style="padding:24px;color:var(--error)">Health analyzer failed: ' + escHtml(e.message) + '</div>';
  }
}

// True if a URL points to a local-network host (IP address, .local, .lan,
// .internal, .home, .home.arpa, or localhost). These are typically devices
// on the user's own network — printers, routers, NAS, dev servers — where
// reusing a password is often a deliberate choice and shouldn't ding the
// vault health score.
function isLocalUrl(url) {
  if (!url || typeof url !== 'string') return false;
  let s = url.trim().toLowerCase();
  if (!s) return false;
  if (!/^https?:\/\//.test(s)) s = 'https://' + s;
  let host;
  try { host = new URL(s).hostname; } catch { return false; }
  if (host.startsWith('www.')) host = host.slice(4);
  if (host === 'localhost' || host === '127.0.0.1' || host === '::1') return true;
  // IPv4
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) {
    const parts = host.split('.').map(n => parseInt(n, 10));
    if (parts.some(p => p > 255)) return false;
    // RFC1918 private ranges + link-local + loopback
    if (parts[0] === 10) return true;
    if (parts[0] === 127) return true;
    if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
    if (parts[0] === 192 && parts[1] === 168) return true;
    if (parts[0] === 169 && parts[1] === 254) return true;
    // Public IP — not local. Treat as a real site (rare but possible).
    return false;
  }
  // IPv6: URL parser returns hostname wrapped in brackets, e.g. "[fc00::1]".
  // Strip those before checking. fc00::/7 = unique local, fe80::/10 = link-local
  if (host.startsWith('[') && host.endsWith(']')) {
    const v6 = host.slice(1, -1);
    if (v6 === '::1') return true;
    if (/^f[cd]/i.test(v6)) return true;
    if (/^fe[89ab]/i.test(v6)) return true;
    return false;
  }
  // mDNS / common LAN suffixes
  if (host.endsWith('.local')) return true;
  if (host.endsWith('.lan')) return true;
  if (host.endsWith('.internal')) return true;
  if (host.endsWith('.home')) return true;
  if (host.endsWith('.home.arpa')) return true;
  if (host.endsWith('.intranet')) return true;
  if (host.endsWith('.private')) return true;
  return false;
}

// Extract a domain from a URL string, or null if it's unparseable.
// Strips "www." prefix to canonicalize.
function extractDomain(url) {
  if (!url || typeof url !== 'string') return null;
  let s = url.trim().toLowerCase();
  if (!s) return null;
  if (!/^https?:\/\//.test(s)) s = 'https://' + s;
  try {
    const u = new URL(s);
    let host = u.hostname;
    if (host.startsWith('www.')) host = host.slice(4);
    if (!/^[a-z0-9.\-]+$/.test(host)) return null;
    return host;
  } catch {
    return null;
  }
}

// Group logins by their site's 2FA support status.
async function classifyTwoFASupport(loginsWithoutTotp) {
  const supported = [];   // site supports 2FA, user hasn't enabled it
  const unsupported = []; // site doesn't offer 2FA — legit no-2FA
  const unknown = [];     // no URL or domain not in directory

  // Bucket items by their extractable domain
  const domains = new Set();
  const itemsByDomain = new Map();
  for (const item of loginsWithoutTotp) {
    const dom = extractDomain(item.data.url);
    if (!dom) {
      unknown.push(item);
      continue;
    }
    domains.add(dom);
    if (!itemsByDomain.has(dom)) itemsByDomain.set(dom, []);
    itemsByDomain.get(dom).push(item);
  }

  if (!domains.size) {
    return { loading: false, supported, unsupported, unknown };
  }

  let results;
  try {
    const resp = await api('POST', '/api/2fa-check', { domains: [...domains] });
    results = resp.results || {};
  } catch (e) {
    console.warn('[health] 2FA-check failed:', e.message);
    // On failure, surface everything as unknown
    return {
      loading: false,
      supported, unsupported,
      unknown: [...unknown, ...itemsByDomain.values()].flat(),
      error: e.message,
    };
  }

  for (const [domain, items] of itemsByDomain) {
    const r = results[domain];
    if (!r || !r.listed) {
      unknown.push(...items);
    } else if (r.supports) {
      // Attach the metadata to each item for rendering
      for (const item of items) {
        item._tfaMeta = { methods: r.methods, documentation: r.documentation };
      }
      supported.push(...items);
    } else {
      unsupported.push(...items);
    }
  }

  return { loading: false, supported, unsupported, unknown };
}

function wireHealthBody(body) {
  $$('[data-fix-id]', body).forEach(btn => {
    btn.addEventListener('click', () => {
      const id = parseInt(btn.dataset.fixId, 10);
      openItemEditor(id);
    });
  });
}

async function checkPwnedBatch(logins, onProgress) {
  // Computes SHA-1 of each password, groups by 5-char prefix, hits our
  // /api/pwned-check proxy (which relays to HIBP) once per prefix.
  // Prefix lookups run in parallel with a concurrency cap so we don't
  // block on a sequential round-trip per password.
  const map = new Map();
  const prefixes = new Map();
  for (const item of logins) {
    const pw = item.data.password;
    const hash = await sha1Hex(pw);
    const prefix = hash.slice(0, 5).toUpperCase();
    const suffix = hash.slice(5).toUpperCase();
    if (!prefixes.has(prefix)) prefixes.set(prefix, []);
    prefixes.get(prefix).push({ item, suffix });
  }

  const tasks = [...prefixes.entries()];
  const total = tasks.length;
  if (!total) return map;
  let done = 0;
  const CONCURRENCY = 8;

  async function processOne(prefix, list) {
    try {
      const resp = await api('POST', '/api/pwned-check', { prefix });
      const lines = (resp.body || '').split('\n');
      const bySuffix = new Map();
      for (const line of lines) {
        const [sfx, count] = line.trim().split(':');
        if (sfx) bySuffix.set(sfx.toUpperCase(), parseInt(count || '0', 10));
      }
      for (const { item, suffix } of list) {
        if (bySuffix.has(suffix)) map.set(item.id, bySuffix.get(suffix));
      }
    } catch (e) {
      console.warn('[health] pwned-check failed for prefix ' + prefix + ':', e.message);
    } finally {
      done++;
      if (onProgress) onProgress(done, total);
    }
  }

  // Worker-pool pattern: each worker pulls from the task list until empty.
  let cursor = 0;
  async function worker() {
    while (cursor < tasks.length) {
      const idx = cursor++;
      const [prefix, list] = tasks[idx];
      await processOne(prefix, list);
    }
  }
  const workers = Array.from({ length: Math.min(CONCURRENCY, tasks.length) }, () => worker());
  await Promise.all(workers);
  return map;
}

async function sha1Hex(s) {
  const buf = new TextEncoder().encode(s);
  const digest = await crypto.subtle.digest('SHA-1', buf);
  return Array.from(new Uint8Array(digest)).map(b => b.toString(16).padStart(2, '0')).join('');
}

function renderHealthSummary({
  logins, weak,
  reusedGroupsExternal, reusedGroupsLocal,
  reusedItemsExternal, reusedItemsLocal,
  pwnedMap, pwnedProgress, twoFAState
}) {
  const total = logins.length;
  const pwned = pwnedMap ? [...pwnedMap.keys()] : [];
  const checking = pwnedMap === null;
  twoFAState = twoFAState || { loading: true, supported: [], unsupported: [], unknown: [] };
  const tfaLoading = twoFAState.loading;
  const tfaAvailable = twoFAState.supported || [];
  const tfaUnknown = twoFAState.unknown || [];

  // Score: weighted by issue type.
  //   pwned     × 2.0   — leaked passwords are worst
  //   reused    × 1.5   — but ONLY for groups that aren't all local-network
  //   weak      × 1.0
  //   2FA off   × 1.0   — where the site supports it but user hasn't enabled
  //
  // Local-only reused groups (printers, NAS, routers, etc.) are excluded:
  // reusing a password across LAN devices is often a deliberate convenience
  // choice and isn't the same risk as reusing on public services.
  const pwnedCount = pwned.length;
  const issuesForScore =
      pwnedCount * 2
    + reusedItemsExternal.length * 1.5
    + weak.length
    + tfaAvailable.length;
  const score = Math.max(0, Math.min(100, Math.round(100 - (issuesForScore / Math.max(total, 1)) * 50)));

  const fixBtn = (id) => `<button class="btn btn-sm btn-secondary health-fix-btn" data-fix-id="${id}"><i data-lucide="wrench" width="12" height="12"></i> Fix</button>`;

  // Top stat cards
  const stat = (icon, label, count, color, display) => `
    <div class="health-stat-card" style="--stat-color:${color}">
      <div class="health-stat-icon"><i data-lucide="${icon}" width="18" height="18"></i></div>
      <div class="health-stat-num">${display !== undefined ? display : count}</div>
      <div class="health-stat-label">${label}</div>
    </div>
  `;

  const sectionRow = (item, badge) => `
    <div class="health-row">
      <div class="health-row-info">
        <div class="health-row-icon"><i data-lucide="${iconForType(item.type)}" width="14" height="14"></i></div>
        <div>
          <div class="health-row-name">${escHtml(item.data.name || '(unnamed)')}</div>
          ${item.data.username ? `<div class="health-row-sub">${escHtml(item.data.username)}</div>` : ''}
        </div>
      </div>
      <div style="display:flex;align-items:center;gap:8px">
        ${badge || ''}
        ${fixBtn(item.id)}
      </div>
    </div>
  `;

  return `
    <div class="health-overview">
      <div class="health-score-card">
        <div class="health-score-ring" style="--score:${score}">
          <span class="health-score-num">${score}</span>
          <span class="health-score-text">%</span>
        </div>
        <div style="flex:1">
          <div class="health-score-label">Vault health score</div>
          <div class="health-score-desc">Based on password strength, reuse, and known breaches across ${total} login${total===1?'':'s'}.</div>
        </div>
      </div>

      <div class="health-stats-grid">
        ${stat('alert-triangle', 'Weak', weak.length, 'var(--warning)')}
        ${stat('copy', 'Reused', reusedItemsExternal.length, 'var(--warning)')}
        ${stat('alert-octagon', 'Pwned', pwnedCount, 'var(--error)',
          checking ? (pwnedProgress && pwnedProgress.total
            ? `<span style="font-size:14px;color:var(--text-f)">${pwnedProgress.done}<span style="opacity:0.5">/${pwnedProgress.total}</span></span>`
            : '<span style="font-size:14px;color:var(--text-f)">…</span>')
          : undefined)}
        ${stat('shield-off', 'Missing 2FA', tfaAvailable.length, 'var(--text-f)',
          tfaLoading ? '<span style="font-size:14px;color:var(--text-f)">…</span>' : undefined)}
      </div>
    </div>

    ${pwnedCount ? `
      <div class="health-section">
        <div class="health-section-title">
          <span><i data-lucide="alert-octagon" width="14" height="14" style="vertical-align:-2px;color:var(--error)"></i> Pwned passwords</span>
          <span class="muted" style="font-weight:400;font-size:12px">Found in data breaches</span>
        </div>
        <div class="health-rows">
          ${pwned.map(id => {
            const i = state.items.find(x => x.id === id);
            if (!i) return '';
            const count = pwnedMap.get(id);
            const badge = `<span class="badge badge-error">${count.toLocaleString()} leak${count===1?'':'s'}</span>`;
            return sectionRow(i, badge);
          }).join('')}
        </div>
      </div>
    ` : ''}

    ${reusedGroupsExternal.length ? `
      <div class="health-section">
        <div class="health-section-title">
          <span><i data-lucide="copy" width="14" height="14" style="vertical-align:-2px;color:var(--warning)"></i> Reused passwords</span>
          <span class="muted" style="font-weight:400;font-size:12px">${reusedGroupsExternal.length} group${reusedGroupsExternal.length===1?'':'s'}</span>
        </div>
        <div class="health-rows">
          ${reusedGroupsExternal.map((group) => `
            <div class="health-group-block">
              <div class="health-group-label">Same password used in ${group.length} accounts</div>
              ${group.map(i => sectionRow(i, '')).join('')}
            </div>
          `).join('')}
        </div>
      </div>
    ` : ''}

    ${reusedGroupsLocal.length ? `
      <div class="health-section">
        <div class="health-section-title">
          <span><i data-lucide="server" width="14" height="14" style="vertical-align:-2px;color:var(--text-f)"></i> Reused on local network</span>
          <span class="muted" style="font-weight:400;font-size:12px">Not counted in score</span>
        </div>
        <div style="font-size:12px;color:var(--text-m);margin-bottom:8px">
          These passwords are reused, but every item points to an IP address or local-network host (printers, NAS, routers, dev servers). Sharing one password across LAN devices is usually a deliberate choice, so it isn't penalized. If any of these are actually public services, set a unique password.
        </div>
        <div class="health-rows">
          ${reusedGroupsLocal.map((group) => `
            <div class="health-group-block">
              <div class="health-group-label">Same password used in ${group.length} local devices</div>
              ${group.map(i => sectionRow(i, `<span class="badge" style="background:var(--surface-off);color:var(--text-m);font-weight:500">local</span>`)).join('')}
            </div>
          `).join('')}
        </div>
      </div>
    ` : ''}

    ${weak.length ? `
      <div class="health-section">
        <div class="health-section-title">
          <span><i data-lucide="alert-triangle" width="14" height="14" style="vertical-align:-2px;color:var(--warning)"></i> Weak passwords</span>
          <span class="muted" style="font-weight:400;font-size:12px">Low entropy</span>
        </div>
        <div class="health-rows">
          ${weak.map(i => sectionRow(i, '<span class="badge badge-warning">weak</span>')).join('')}
        </div>
      </div>
    ` : ''}

    ${tfaAvailable.length ? `
      <div class="health-section">
        <div class="health-section-title">
          <span><i data-lucide="shield-off" width="14" height="14" style="vertical-align:-2px;color:var(--warning)"></i> 2FA available, not enabled</span>
          <span class="muted" style="font-weight:400;font-size:12px">${tfaAvailable.length} site${tfaAvailable.length===1?'':'s'} support${tfaAvailable.length===1?'s':''} 2FA</span>
        </div>
        <div class="health-rows">
          ${tfaAvailable.slice(0, 50).map(i => {
            const docLink = i._tfaMeta?.documentation
              ? `<a href="${escHtml(i._tfaMeta.documentation)}" target="_blank" rel="noopener noreferrer" class="badge" style="background:var(--primary-hl);color:var(--primary);text-decoration:none">Setup guide</a>`
              : '';
            return sectionRow(i, docLink);
          }).join('')}
          ${tfaAvailable.length > 50 ? `<div class="health-row" style="justify-content:center;color:var(--text-m)">+ ${tfaAvailable.length - 50} more</div>` : ''}
        </div>
        <div class="health-attribution">2FA support data from <a href="https://2fa.directory/" target="_blank" rel="noopener noreferrer">2fa.directory</a></div>
      </div>
    ` : ''}

    ${tfaUnknown.length && !tfaLoading ? `
      <div class="health-section">
        <div class="health-section-title">
          <span><i data-lucide="help-circle" width="14" height="14" style="vertical-align:-2px;color:var(--text-f)"></i> 2FA status unknown</span>
          <span class="muted" style="font-weight:400;font-size:12px">${tfaUnknown.length} login${tfaUnknown.length===1?'':'s'}</span>
        </div>
        <div style="font-size:12px;color:var(--text-m);margin-bottom:8px">
          Either no URL is set, or the site isn't in our 2FA directory. Add a URL to the item, or check the site's security settings yourself.
        </div>
        <div class="health-rows">
          ${tfaUnknown.slice(0, 30).map(i => sectionRow(i, '')).join('')}
          ${tfaUnknown.length > 30 ? `<div class="health-row" style="justify-content:center;color:var(--text-m)">+ ${tfaUnknown.length - 30} more</div>` : ''}
        </div>
      </div>
    ` : ''}

    ${!pwnedCount && !reusedGroupsExternal.length && !weak.length && !tfaAvailable.length ? `
      <div class="health-section" style="text-align:center;padding:40px 20px">
        <i data-lucide="shield-check" width="48" height="48" style="color:var(--success);margin-bottom:12px"></i>
        <div style="font-size:16px;font-weight:600;margin-bottom:6px">Your vault looks healthy</div>
        <div class="muted">No weak, reused, or compromised passwords detected.</div>
      </div>
    ` : ''}
  `;
}

// ═══════════════════════════════════════════════════════════════════════════
//  SETTINGS / EXPORT / PASSWORD CHANGE
// ═══════════════════════════════════════════════════════════════════════════

function renderSettings(main) {
  const theme = document.documentElement.getAttribute('data-theme') || 'dark';
  const clearSec = state.prefs.clipboard_clear_seconds ?? CLIPBOARD_CLEAR_SECONDS_DEFAULT;
  main.innerHTML = `
    <div class="list-header"><h2 class="list-title">Settings</h2></div>
    <div class="pane-scroll">
    <div style="padding:16px;max-width:600px">
      <div class="health-section">
        <div class="health-section-title">Appearance</div>
        <div class="form-group">
          <label class="form-label">Theme</label>
          <select class="form-select" id="set-theme">
            <option value="dark"${theme==='dark'?' selected':''}>Dark</option>
            <option value="light"${theme==='light'?' selected':''}>Light</option>
            <option value="oled"${theme==='oled'?' selected':''}>OLED Black</option>
          </select>
        </div>
      </div>
      <div class="health-section">
        <div class="health-section-title">Security</div>
        <div class="form-group">
          <label class="form-label">Auto-lock after (minutes)</label>
          <input class="form-input" id="set-lock" type="number" min="1" max="240" value="${state.lockTimeout}" />
        </div>
        <div class="form-group">
          <label class="form-label">Clipboard auto-clear (seconds, 0 = disabled)</label>
          <input class="form-input" id="set-clip" type="number" min="0" max="300" value="${clearSec}" />
        </div>
        <button class="btn btn-primary" id="set-save-sec">Save</button>
      </div>
      <div class="health-section">
        <div class="health-section-title">Master password</div>
        <button class="btn btn-secondary" id="btn-change-pw">Change master password</button>
      </div>
      <div class="health-section">
        <div class="health-section-title">Offline cache</div>
        <p class="form-hint">When you're online, your encrypted vault is cached on this device so it works offline. Cache trusts this device for a configurable number of days, then requires you to reconnect and log in again.</p>
        <div class="form-group">
          <label class="form-label">Trust this device offline for (days)</label>
          <input class="form-input" id="set-offline-ttl" type="number" min="1" max="90" value="7" />
        </div>
        <div id="offline-cache-stats" style="font-size:13px;color:var(--text-m,#888);margin:8px 0 12px;line-height:1.5"></div>
        <button class="btn btn-secondary" id="set-save-offline" style="margin-right:8px">Save</button>
        <button class="btn btn-ghost" id="set-clear-cache">Clear offline cache</button>
      </div>
      <div class="health-section">
        <div class="health-section-title">Import</div>
        <p class="form-hint">Import passwords from another password manager. Items are encrypted client-side before being saved.</p>
        <button class="btn btn-secondary" id="btn-import">Import vault from another manager</button>
      </div>
      <div class="health-section">
        <div class="health-section-title">Recently deleted</div>
        <p class="form-hint">Items moved to Trash stay here for 6 months, then are deleted permanently. Restore an item to bring it back to your vault.</p>
        <div id="trash-stats" style="font-size:13px;color:var(--text-m,#888);margin:8px 0 12px;line-height:1.5">Loading…</div>
        <button class="btn btn-secondary" id="btn-view-trash">
          <i data-lucide="trash-2" width="14" height="14"></i> View Trash
        </button>
      </div>
      <div class="health-section">
        <div class="health-section-title">Export</div>
        <p class="form-hint">Decrypted JSON only you hold. Store securely.</p>
        <button class="btn btn-secondary" id="btn-export-decrypted">Download decrypted JSON</button>
        <button class="btn btn-ghost" id="btn-export-encrypted" style="margin-left:8px">Download encrypted archive</button>
      </div>
      <div class="health-section">
        <div class="health-section-title">Encryption strength</div>
        <p class="form-hint">
          Tune how hard it is to brute-force your master password. Stronger
          settings make every login take longer on every device.
        </p>
        <div id="kdf-current" style="font-size:12px;color:var(--text-m,#888);margin:8px 0 16px;font-family:var(--mono,monospace)">
          Current: loading…
        </div>

        <label class="form-label" style="display:flex;justify-content:space-between;align-items:baseline">
          <span>Memory</span>
          <span id="kdf-mem-val" style="font-family:var(--mono,monospace);font-size:12px;color:var(--primary)">256 MiB</span>
        </label>
        <input type="range" id="kdf-mem" min="64" max="256" step="32" value="256" style="width:100%;margin:6px 0 4px" />
        <div style="display:flex;justify-content:space-between;font-family:var(--mono,monospace);font-size:10px;color:var(--text-f,#666)">
          <span>64</span><span>128</span><span>192</span><span>256</span>
        </div>

        <label class="form-label" style="display:flex;justify-content:space-between;align-items:baseline;margin-top:14px">
          <span>Iterations</span>
          <span id="kdf-iter-val" style="font-family:var(--mono,monospace);font-size:12px;color:var(--primary)">5</span>
        </label>
        <input type="range" id="kdf-iter" min="3" max="8" step="1" value="5" style="width:100%;margin:6px 0 4px" />
        <div style="display:flex;justify-content:space-between;font-family:var(--mono,monospace);font-size:10px;color:var(--text-f,#666)">
          <span>3</span><span>4</span><span>5</span><span>6</span><span>7</span><span>8</span>
        </div>

        <div style="display:flex;gap:8px;margin-top:16px;flex-wrap:wrap">
          <button class="btn btn-secondary btn-sm" id="btn-kdf-test">
            <i data-lucide="timer" width="14" height="14"></i> Test
          </button>
          <button class="btn btn-secondary btn-sm" id="btn-kdf-recommend">
            <i data-lucide="wand-2" width="14" height="14"></i> Recommend
          </button>
          <button class="btn btn-primary btn-sm" id="btn-kdf-apply">
            <i data-lucide="check" width="14" height="14"></i> Apply
          </button>
        </div>

        <div id="kdf-result" style="margin-top:12px;font-size:13px;line-height:1.5;color:var(--text-m,#888);min-height:20px"></div>

        <p class="form-hint" style="margin-top:14px">
          <strong>Test</strong> measures how long these settings take to derive
          your key on this device. <strong>Recommend</strong> auto-tunes for
          ~800ms (the security sweet spot). <strong>Apply</strong> re-encrypts
          your vault with the new settings — you'll need to enter your master
          password.
        </p>
      </div>
      <div class="health-section danger-zone">
        <div class="health-section-title" style="color:var(--error)">
          <span><i data-lucide="alert-octagon" width="14" height="14" style="vertical-align:-2px"></i> Danger zone</span>
        </div>
        <p class="form-hint">Permanently delete your account and all vault data. This cannot be undone.</p>
        <button class="btn btn-danger" id="btn-delete-account">
          <i data-lucide="trash-2" width="14" height="14"></i> Delete account
        </button>
      </div>
    </div>
    </div>
  `;
  renderIcons(main);

  $('#set-theme', main).addEventListener('change', async (e) => {
    const t = e.target.value;
    document.documentElement.setAttribute('data-theme', t);
    try { localStorage.setItem('vk_theme', t); } catch {}
    try { await api('PATCH', '/api/prefs', { theme: t }); state.prefs.theme = t; } catch {}
  });
  $('#set-save-sec', main).addEventListener('click', async () => {
    const lock = parseInt($('#set-lock', main).value, 10);
    const clip = parseInt($('#set-clip', main).value, 10);
    if (lock >= 1 && lock <= 240) {
      state.lockTimeout = lock;
      resetLockTimer();
    }
    if (clip >= 0 && clip <= 300) {
      state.prefs.clipboard_clear_seconds = clip;
      try { await api('PATCH', '/api/prefs', { clipboard_clear_seconds: clip }); } catch {}
    }
    showToast('Settings saved', 'success');
  });
  $('#btn-change-pw', main).addEventListener('click', () => openPasswordChangeDialog());

  // Offline cache settings
  if (window.VK_Offline) {
    (async () => {
      try {
        const ttl = await window.VK_Offline.getOfflineTtlDays();
        const ttlInput = $('#set-offline-ttl', main);
        if (ttlInput) ttlInput.value = ttl;

        // Stats display
        const statsEl = $('#offline-cache-stats', main);
        if (statsEl) {
          const meta = await window.VK_Offline.getUserMetadata(state.username);
          const lastSync = meta?.last_sync_at
            ? new Date(meta.last_sync_at).toLocaleString()
            : 'never';
          let parts = ['Last synced: ' + lastSync];
          try {
            const est = await window.VK_Offline.getStorageEstimate();
            if (est && est.usage) {
              parts.push('Cache size: ' + Math.round(est.usage / 1024) + ' KB');
            }
          } catch {}
          const pending = await window.VK_Offline.getPendingForUser(state.username);
          if (pending.length) {
            parts.push(pending.length + ' pending mutation(s)');
          }
          const conflicts = await window.VK_Offline.getConflicts(state.username);
          if (conflicts.length) {
            parts.push('<span style="color:var(--warning,#d4824a)">⚠ ' + conflicts.length + ' unresolved conflict(s)</span>');
          }
          statsEl.innerHTML = parts.join(' · ');
        }
      } catch (e) {
        console.warn('[settings] offline stats:', e.message);
      }
    })();

    $('#set-save-offline', main).addEventListener('click', async () => {
      const ttl = parseInt($('#set-offline-ttl', main).value, 10);
      if (ttl >= 1 && ttl <= 90) {
        await window.VK_Offline.setOfflineTtlDays(ttl);
        showToast('Offline TTL saved', 'success');
      } else {
        showToast('TTL must be between 1 and 90 days', 'error');
      }
    });

    $('#set-clear-cache', main).addEventListener('click', async () => {
      if (!confirm('Clear the offline cache for this device? You will need to be online to log in again, and any unsynced offline changes will be lost.')) return;
      try {
        await window.VK_Offline.clearUserCache(state.username);
        showToast('Offline cache cleared', 'info');
      } catch (e) {
        showToast('Failed to clear cache: ' + e.message, 'error');
      }
    });
  }

  $('#btn-import', main).addEventListener('click', () => openImportDialog());
  $('#btn-view-trash', main).addEventListener('click', () => openTrashModal());

  // Pre-load the trash count for the stats line
  (async () => {
    const statsEl = $('#trash-stats', main);
    if (!statsEl) return;
    try {
      const trash = await api('GET', '/api/vault/trash');
      const n = Array.isArray(trash) ? trash.length : 0;
      statsEl.textContent = n === 0
        ? 'Trash is empty.'
        : n + ' item' + (n === 1 ? '' : 's') + ' currently in Trash.';
    } catch {
      statsEl.textContent = '';
    }
  })();

  $('#btn-export-decrypted', main).addEventListener('click', () => doExportDecrypted());
  $('#btn-export-encrypted', main).addEventListener('click', () => doExportEncrypted());

  // ── Encryption strength controls ─────────────────────────────────────────
  // Show current params from the server prelogin response
  (async () => {
    try {
      const pre = await api('POST', '/api/auth/prelogin', { username: state.username });
      const cur = $('#kdf-current', main);
      if (cur) {
        cur.textContent = 'Current: ' + (pre.kdf.memory_cost / 1024) + ' MiB · ' +
                          pre.kdf.time_cost + ' iterations';
      }
    } catch {}
  })();

  // Live label updates on slider change
  const memSlider = $('#kdf-mem', main);
  const memLbl = $('#kdf-mem-val', main);
  const iterSlider = $('#kdf-iter', main);
  const iterLbl = $('#kdf-iter-val', main);
  memSlider?.addEventListener('input', () => { memLbl.textContent = memSlider.value + ' MiB'; });
  iterSlider?.addEventListener('input', () => { iterLbl.textContent = iterSlider.value; });

  function getKdfFromSliders() {
    return {
      memoryCost: parseInt(memSlider.value, 10) * 1024,  // MiB → KiB
      timeCost: parseInt(iterSlider.value, 10),
      parallelism: 1,
      hashLength: 32,
    };
  }

  async function benchmarkKdf(params) {
    // Use a fresh worker call with throwaway test inputs. Doesn't touch
    // the user's vault or master password.
    const t0 = performance.now();
    await callWorker('deriveLogin', {
      username: '__bench__', password: '__bench__', kdfParams: params,
    }, 60000);
    return performance.now() - t0;
  }

  $('#btn-kdf-test', main)?.addEventListener('click', async () => {
    const btn = $('#btn-kdf-test', main);
    const result = $('#kdf-result', main);
    btn.disabled = true; btn.textContent = 'Testing…';
    result.style.color = 'var(--text-m,#888)';
    result.textContent = 'Running benchmark on this device…';
    try {
      const ms = await benchmarkKdf(getKdfFromSliders());
      const verdict = ms < 500 ? '⚠ too fast — increase memory or iterations'
                    : ms < 1500 ? '✓ good — sweet spot'
                    : ms < 2500 ? '⚠ slow — usable but logins will feel laggy'
                    : '✗ too slow — pick weaker params';
      const color = ms < 500 ? 'var(--gold,#eab308)'
                  : ms < 1500 ? 'var(--success,#22c55e)'
                  : ms < 2500 ? 'var(--gold,#eab308)' : 'var(--error,#ef4444)';
      result.style.color = color;
      result.textContent = '~' + Math.round(ms) + 'ms on this device — ' + verdict;
    } catch (e) {
      result.style.color = 'var(--error,#ef4444)';
      result.textContent = 'Benchmark failed: ' + e.message;
    } finally {
      btn.disabled = false; btn.innerHTML = '<i data-lucide="timer" width="14" height="14"></i> Test';
      renderIcons(btn);
    }
  });

  $('#btn-kdf-recommend', main)?.addEventListener('click', async () => {
    const btn = $('#btn-kdf-recommend', main);
    const result = $('#kdf-result', main);
    btn.disabled = true; btn.textContent = 'Tuning…';
    result.style.color = 'var(--text-m,#888)';
    result.textContent = 'Auto-tuning for ~800ms target…';

    // Sweep memory at fixed t=5 (the recommended iteration count) and find
    // the memory size that lands closest to 800ms target on this device.
    // Bail early if a sample already exceeds 1200ms.
    const TARGET = 800;
    const candidates = [64, 128, 192, 256];  // MiB
    let best = null;
    try {
      for (const mib of candidates) {
        result.textContent = `Auto-tuning for ~800ms target… testing ${mib} MiB…`;
        const ms = await benchmarkKdf({
          memoryCost: mib * 1024, timeCost: 5, parallelism: 1, hashLength: 32,
        });
        const score = Math.abs(ms - TARGET);
        if (!best || score < best.score) best = { mib, ms, score };
        if (ms > 1200) break;  // already past target on this device, stop
      }
      if (!best) throw new Error('no benchmark sample completed');
      memSlider.value = best.mib;
      iterSlider.value = 5;
      memLbl.textContent = best.mib + ' MiB';
      iterLbl.textContent = '5';
      result.style.color = 'var(--success,#22c55e)';
      result.textContent = `Recommended: ${best.mib} MiB · 5 iterations · ~${Math.round(best.ms)}ms on this device. Tap Apply to save.`;
    } catch (e) {
      result.style.color = 'var(--error,#ef4444)';
      result.textContent = 'Auto-tune failed: ' + e.message;
    } finally {
      btn.disabled = false; btn.innerHTML = '<i data-lucide="wand-2" width="14" height="14"></i> Recommend';
      renderIcons(btn);
    }
  });

  $('#btn-kdf-apply', main)?.addEventListener('click', () => {
    const params = getKdfFromSliders();
    openKdfApplyDialog(params);
  });

  $('#btn-delete-account', main)?.addEventListener('click', () => openDeleteAccountDialog());
}

// Master-password prompt that re-derives the user's key with new KDF
// params and re-wraps the symmetric key on the server. Reuses the
// change-password endpoint with newPw === currentPw.
function openKdfApplyDialog(newKdfParams) {
  const memMib = newKdfParams.memoryCost / 1024;
  openModal({
    title: 'Apply new encryption strength',
    body: `
      <p style="margin:0 0 12px;font-size:14px;color:var(--text);line-height:1.5">
        About to re-encrypt your vault with stronger settings:
      </p>
      <div style="background:var(--surface-off,rgba(255,255,255,0.03));border:1px solid var(--divider);border-radius:6px;padding:10px 12px;margin-bottom:14px;font-family:var(--mono,monospace);font-size:12px">
        ${memMib} MiB · ${newKdfParams.timeCost} iterations
      </div>
      <p style="margin:0 0 12px;font-size:13px;color:var(--text-m,#888);line-height:1.5">
        Enter your current master password to confirm. Your vault content
        won't change — only the key derivation parameters.
      </p>
      <div class="form-group">
        <label class="form-label">Master password</label>
        <input class="form-input" id="kdf-apply-pw" type="password" autocomplete="current-password" />
      </div>
      <div id="kdf-apply-error" style="color:var(--error,#ef4444);font-size:13px;margin-top:8px;display:none"></div>
    `,
    footer: `
      <button class="btn btn-ghost" id="kdf-apply-cancel">Cancel</button>
      <button class="btn btn-primary" id="kdf-apply-confirm">Apply</button>
    `,
    onMount(modalRoot) {
      $('#kdf-apply-pw', modalRoot)?.focus();
      $('#kdf-apply-cancel', modalRoot)?.addEventListener('click', () => closeModal());
      $('#kdf-apply-confirm', modalRoot)?.addEventListener('click', async () => {
        const btn = $('#kdf-apply-confirm', modalRoot);
        const err = $('#kdf-apply-error', modalRoot);
        const pw = $('#kdf-apply-pw', modalRoot)?.value;
        if (!pw) {
          err.textContent = 'Enter your master password.';
          err.style.display = 'block';
          return;
        }
        err.style.display = 'none';
        btn.disabled = true;
        btn.textContent = 'Re-encrypting…';
        try {
          // Use change-password with same-password — server endpoint
          // accepts that and just re-wraps with the new KDF.
          await doChangePassword(pw, pw, newKdfParams);
          closeModal();
          showToast('Encryption strength updated', 'success');
          // Re-render Settings so the "Current:" line updates
          if (state.view === 'settings') renderAll();
        } catch (e) {
          err.textContent = e.message || 'Failed — check your password and try again.';
          err.style.display = 'block';
          btn.disabled = false;
          btn.textContent = 'Apply';
        }
      });
    }
  });
}

function openPasswordChangeDialog() {
  openModal({
    title: 'Change master password',
    body: `
      <form id="pwch-form">
        <div class="form-group">
          <label class="form-label">Current master password</label>
          <input class="form-input" type="password" name="current" required autofocus autocomplete="current-password" />
        </div>
        <div class="form-group">
          <label class="form-label">New master password</label>
          <input class="form-input" type="password" name="new" minlength="12" required autocomplete="new-password" />
          <p class="form-hint">At least 12 characters. This encrypts your vault — if you forget it, nothing can recover it.</p>
        </div>
        <div class="form-group">
          <label class="form-label">Confirm new</label>
          <input class="form-input" type="password" name="confirm" required autocomplete="new-password" />
        </div>
        <div class="form-error hidden" id="pwch-err"></div>
      </form>
    `,
    footer: `
      <button class="btn btn-ghost" data-action="cancel">Cancel</button>
      <button class="btn btn-primary" data-action="save">Change</button>
    `,
    onMount: (modal) => {
      modal.querySelector('[data-action="cancel"]').addEventListener('click', () => closeModal());
      modal.querySelector('[data-action="save"]').addEventListener('click', async (e) => {
        e.preventDefault();
        const form = $('#pwch-form', modal);
        const cur = form.current.value;
        const newPw = form.new.value;
        const conf = form.confirm.value;
        const err = $('#pwch-err', modal);
        err.classList.add('hidden'); err.textContent = '';
        if (newPw.length < 12) { err.textContent = 'New password must be at least 12 characters'; err.classList.remove('hidden'); return; }
        if (newPw !== conf) { err.textContent = 'New passwords do not match'; err.classList.remove('hidden'); return; }
        const btn = modal.querySelector('[data-action="save"]');
        btn.disabled = true;
        try {
          await doChangePassword(cur, newPw);
          closeModal();
          showToast('Password changed', 'success');
        } catch (e2) {
          err.textContent = 'Failed: ' + (e2.message || 'unknown');
          err.classList.remove('hidden');
          btn.disabled = false;
        }
      });
    }
  });
}

function openDeleteAccountDialog() {
  openModal({
    title: 'Delete account',
    body: `
      <div style="background:var(--error-hl);color:var(--error);border-radius:var(--r-md);padding:12px 14px;margin-bottom:16px;font-size:13px;line-height:1.5">
        <strong>This will permanently delete your account and ALL vault data.</strong>
        <ul style="margin:8px 0 0;padding-left:20px">
          <li>All ${state.items.length} item${state.items.length===1?'':'s'} will be erased</li>
          <li>All ${state.folders.length} folder${state.folders.length===1?'':'s'} will be erased</li>
          <li>You will be signed out and unable to log in</li>
          <li>This cannot be undone</li>
        </ul>
      </div>
      <p class="form-hint" style="margin:0 0 8px">
        If you want a backup first, cancel and use Settings → Export.
      </p>
      <div class="form-group">
        <label class="form-label">Confirm with your master password</label>
        <input class="form-input" id="del-acct-pw" type="password" autocomplete="current-password" placeholder="Master password" />
      </div>
      <div id="del-acct-err" class="form-error hidden"></div>
    `,
    footer: `
      <button class="btn btn-ghost" data-action="cancel">Cancel</button>
      <button class="btn btn-danger" data-action="confirm">
        <span class="btn-label"><i data-lucide="trash-2" width="14" height="14"></i> Permanently delete</span>
      </button>
    `,
    onMount: (modal) => {
      const pwInput = $('#del-acct-pw', modal);
      const err = $('#del-acct-err', modal);
      const cancelBtn = modal.querySelector('[data-action="cancel"]');
      const confirmBtn = modal.querySelector('[data-action="confirm"]');
      pwInput.focus();
      cancelBtn.addEventListener('click', () => closeModal());
      confirmBtn.addEventListener('click', async () => {
        const pw = pwInput.value;
        err.classList.add('hidden');
        if (!pw) {
          err.textContent = 'Please enter your master password.';
          err.classList.remove('hidden');
          return;
        }
        confirmBtn.disabled = true;
        cancelBtn.disabled = true;
        const label = confirmBtn.querySelector('.btn-label');
        if (label) label.innerHTML = '<i data-lucide="loader-circle" width="14" height="14" class="spin-icon"></i> Deleting…';
        renderIcons(modal);
        try {
          await doDeleteAccount(pw);
          // doDeleteAccount handles closing the modal and signing out.
        } catch (e) {
          confirmBtn.disabled = false;
          cancelBtn.disabled = false;
          if (label) label.innerHTML = '<i data-lucide="trash-2" width="14" height="14"></i> Permanently delete';
          renderIcons(modal);
          err.textContent = 'Failed: ' + (e.message || 'unknown');
          err.classList.remove('hidden');
        }
      });
      // Enter submits
      pwInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') { e.preventDefault(); confirmBtn.click(); }
      });
    },
  });
}

async function doDeleteAccount(currentPw) {
  // Re-derive the current auth_hash from the password using the stored
  // KDF params. We can't reuse anything from the session — masterKey is
  // already zeroed. Use prelogin to get the params, then deriveLogin.
  const pre = await api('POST', '/api/auth/prelogin', { username: state.username });
  const kdfParams = {
    memoryCost: pre.kdf.memory_cost,
    timeCost: pre.kdf.time_cost,
    parallelism: pre.kdf.parallelism,
    hashLength: 32,
  };
  const derived = await callWorker('deriveLogin', {
    username: state.username, password: currentPw, kdfParams,
  }, 20000);
  // Zero masterKey immediately — we don't need it
  new Uint8Array(derived.masterKey).fill(0);

  // Server verifies authHash via bcrypt and then deletes.
  // Use skipAuthRedirect: a 401 here means "wrong password", not "expired".
  await api('DELETE', '/api/auth/account', {
    current_auth_hash: derived.authHashB64,
  }, { skipAuthRedirect: true });

  // Close dialog + sign out + show toast
  closeModal();
  showToast('Account permanently deleted', 'success');
  // Sign out: clear all session state, show auth screen
  clearSession();
  showAuth();
}

function doExportDecrypted() {
  const out = {
    format: 'vaultkeeper-decrypted-v1',
    exported_at: new Date().toISOString(),
    username: state.username,
    folders: state.folders.map(f => ({ id:f.id, name:f.name, color:f.color })),
    items: state.items.map(i => ({ id:i.id, type:i.type, folder_id:i.folder_id, favorite:i.favorite, data:i.data })),
  };
  downloadJson(out, 'vaultkeeper-decrypted-' + new Date().toISOString().slice(0,10) + '.json');
}

async function doExportEncrypted() {
  try {
    const data = await api('GET', '/api/export');
    downloadJson(data, 'vaultkeeper-encrypted-' + new Date().toISOString().slice(0,10) + '.json');
  } catch (e) { showToast('Export failed: ' + e.message, 'error'); }
}

function downloadJson(obj, filename) {
  const blob = new Blob([JSON.stringify(obj, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = filename;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

// ═══════════════════════════════════════════════════════════════════════════
//  IMPORT
// ═══════════════════════════════════════════════════════════════════════════

function openImportDialog() {
  if (typeof VKImport === 'undefined') {
    showToast('Import module not loaded', 'error');
    return;
  }
  const formats = VKImport.listFormats();
  const fmtOpts = formats.map(f =>
    `<option value="${f.key}">${escHtml(f.name)}</option>`
  ).join('');
  openModal({
    title: 'Import vault',
    body: `
      <p class="form-hint" style="margin-bottom:14px">
        Import passwords from another password manager. The file is parsed
        in your browser; nothing is uploaded until you confirm. Each item
        is encrypted with your master key before being saved.
      </p>
      <div class="form-group">
        <label class="form-label">Source format</label>
        <select class="form-select" id="imp-format">${fmtOpts}</select>
      </div>
      <div class="form-group">
        <label class="form-label">Export file</label>
        <input class="form-input" type="file" id="imp-file" accept=".json,.csv,.txt" />
        <p class="form-hint" id="imp-format-hint">Pick the file your password manager exported.</p>
      </div>
      <div id="imp-preview" class="hidden" style="margin-top:16px;background:var(--surface-off);border-radius:var(--r-md);padding:14px"></div>
      <div id="imp-error" class="form-error hidden"></div>
      <div id="imp-progress" class="hidden" style="margin-top:16px">
        <div style="font-size:12px;color:var(--text-m);margin-bottom:6px" id="imp-progress-label">Importing…</div>
        <div class="gen-strength-bar"><div class="gen-strength-fill" id="imp-progress-bar" style="background:var(--primary)"></div></div>
      </div>
    `,
    footer: `
      <button class="btn btn-ghost" data-action="cancel">Cancel</button>
      <button class="btn btn-primary" data-action="import" disabled>Preview</button>
    `,
    onMount: (modal) => wireImportDialog(modal),
  });
}

function wireImportDialog(modal) {
  const formatSel = $('#imp-format', modal);
  const fileInput = $('#imp-file', modal);
  const hintEl    = $('#imp-format-hint', modal);
  const previewEl = $('#imp-preview', modal);
  const errEl     = $('#imp-error', modal);
  const progEl    = $('#imp-progress', modal);
  const progBar   = $('#imp-progress-bar', modal);
  const progLabel = $('#imp-progress-label', modal);
  const importBtn = modal.querySelector('[data-action="import"]');
  const cancelBtn = modal.querySelector('[data-action="cancel"]');

  let parsed = null;       // { items, folders }
  let phase = 'select';    // 'select' | 'preview' | 'importing' | 'done'

  function setError(msg) {
    if (msg) { errEl.textContent = msg; errEl.classList.remove('hidden'); }
    else     { errEl.textContent = ''; errEl.classList.add('hidden'); }
  }

  function updateHint() {
    const fmt = formatSel.value;
    const adapter = VKImport.listFormats().find(f => f.key === fmt);
    const ext = adapter?.ext || '.json';
    fileInput.accept = ext + (ext === '.json' ? ',.txt' : ',.txt');
    hintEl.textContent = `Pick the ${adapter?.name || ''} file (${ext}).`;
  }

  formatSel.addEventListener('change', () => {
    updateHint();
    parsed = null;
    previewEl.classList.add('hidden');
    importBtn.disabled = true;
    importBtn.textContent = 'Preview';
    phase = 'select';
    setError('');
  });
  updateHint();

  fileInput.addEventListener('change', async () => {
    setError('');
    parsed = null;
    previewEl.classList.add('hidden');
    importBtn.disabled = true;
    importBtn.textContent = 'Preview';
    phase = 'select';

    const file = fileInput.files[0];
    if (!file) return;
    if (file.size > 50 * 1024 * 1024) {
      setError('File is too large (>50 MB).');
      return;
    }
    try {
      const text = await file.text();
      parsed = VKImport.parse(formatSel.value, text);
      // Render preview
      const counts = parsed.items.reduce((acc, i) => {
        acc[i.type] = (acc[i.type] || 0) + 1;
        return acc;
      }, {});
      previewEl.innerHTML = `
        <div style="font-size:13px;font-weight:600;margin-bottom:8px">Found in file:</div>
        <div style="display:flex;flex-direction:column;gap:4px;font-size:13px;color:var(--text-m)">
          <div>Total items: <strong style="color:var(--text)">${parsed.items.length}</strong></div>
          ${Object.entries(counts).map(([t, c]) => `<div>&nbsp;&nbsp;${t}: ${c}</div>`).join('')}
          <div>Folders: <strong style="color:var(--text)">${parsed.folders.length}</strong></div>
        </div>
      `;
      previewEl.classList.remove('hidden');
      importBtn.disabled = false;
      importBtn.textContent = `Import ${parsed.items.length} items`;
      phase = 'preview';
    } catch (e) {
      console.error('[import] parse failed:', e);
      setError('Could not parse: ' + (e.message || 'unknown error'));
    }
  });

  importBtn.addEventListener('click', async () => {
    if (!parsed || phase !== 'preview') return;
    phase = 'importing';
    importBtn.disabled = true;
    cancelBtn.disabled = true;
    formatSel.disabled = true;
    fileInput.disabled = true;
    setError('');
    progEl.classList.remove('hidden');

    let createdFolders = 0;
    let createdItems = 0;
    let failedItems = 0;
    const folderNameToId = new Map();

    // Existing folders (don't duplicate)
    for (const f of state.folders) folderNameToId.set(f.name, f.id);

    try {
      // Create new folders first (skip those that already exist)
      const newFolders = parsed.folders.filter(f => !folderNameToId.has(f.name));
      progLabel.textContent = `Creating ${newFolders.length} folder${newFolders.length===1?'':'s'}…`;
      for (let i = 0; i < newFolders.length; i++) {
        const f = newFolders[i];
        try {
          const enc = await encryptFolderName(f.name);
          const resp = await api('POST', '/api/folders', { encrypted_name: enc, color: f.color || null });
          state.folders.push({ id: resp.id, name: f.name, color: f.color || null, created_at: resp.created_at });
          folderNameToId.set(f.name, resp.id);
          createdFolders++;
        } catch (e) {
          console.warn('[import] folder create failed:', f.name, e.message);
        }
        progBar.style.width = `${((i + 1) / Math.max(newFolders.length, 1)) * 30}%`;  // first 30% = folders
      }

      // Then items
      const total = parsed.items.length;
      progLabel.textContent = `Importing ${total} item${total===1?'':'s'}…`;
      for (let i = 0; i < total; i++) {
        const it = parsed.items[i];
        try {
          const enc = await encryptItemData(it.data);
          const folder_id = it.folder_name ? (folderNameToId.get(it.folder_name) || null) : null;
          const resp = await api('POST', '/api/vault', {
            type: it.type, folder_id, favorite: it.favorite, encrypted_data: enc,
          });
          state.items.push({
            id: resp.id, type: it.type, folder_id, favorite: it.favorite,
            data: it.data, created_at: resp.created_at, updated_at: resp.updated_at,
          });
          createdItems++;
        } catch (e) {
          console.warn('[import] item create failed:', it.data?.name, e.message);
          failedItems++;
        }
        progBar.style.width = `${30 + ((i + 1) / Math.max(total, 1)) * 70}%`;
        progLabel.textContent = `Importing ${i + 1}/${total}…`;
      }

      // Done
      progBar.style.width = '100%';
      progLabel.textContent = 'Done.';
      phase = 'done';
      cancelBtn.disabled = false;
      cancelBtn.textContent = 'Close';
      importBtn.classList.add('hidden');
      invalidateHealthCache();
      const summary = `Imported ${createdItems} item${createdItems===1?'':'s'}` +
        (createdFolders ? `, ${createdFolders} folder${createdFolders===1?'':'s'}` : '') +
        (failedItems ? ` (${failedItems} failed)` : '');
      showToast(summary, failedItems ? 'info' : 'success');
      renderAll();
    } catch (e) {
      console.error('[import] aborted:', e);
      setError('Import failed: ' + (e.message || 'unknown'));
      phase = 'preview';
      importBtn.disabled = false;
      cancelBtn.disabled = false;
      formatSel.disabled = false;
      fileInput.disabled = false;
    }
  });

  cancelBtn.addEventListener('click', () => closeModal());
}

// ═══════════════════════════════════════════════════════════════════════════
//  MODAL
// ═══════════════════════════════════════════════════════════════════════════

let _modalStack = [];
function openModal({ title, titleHtml, body, footer, onMount, onClose }) {
  const modal = document.createElement('div');
  modal.className = 'modal-backdrop';
  modal._onClose = onClose;
  const titleStr = titleHtml ? title : escHtml(title);
  modal.innerHTML = `
    <div class="modal-card" role="dialog" aria-modal="true">
      <div class="modal-header">
        <div class="modal-title" style="display:flex;align-items:center;flex:1;min-width:0">${titleStr}</div>
        <button class="btn-icon btn-ghost modal-close" aria-label="Close"><i data-lucide="x" width="18" height="18"></i></button>
      </div>
      <div class="modal-body">${body}</div>
      <div class="modal-footer">${footer || ''}</div>
    </div>
  `;
  document.body.appendChild(modal);
  _modalStack.push(modal);
  renderIcons();
  modal.querySelector('.modal-close').addEventListener('click', () => closeModal());
  modal.addEventListener('click', (e) => { if (e.target === modal) closeModal(); });
  if (onMount) onMount(modal);
  // Animate in
  requestAnimationFrame(() => modal.classList.add('open'));
}

function closeModal() {
  const modal = _modalStack.pop();
  if (!modal) return;
  modal.classList.remove('open');
  stopTotpTicker();
  if (typeof modal._onClose === 'function') {
    try { modal._onClose(); } catch (e) { console.warn('[modal] onClose threw:', e); }
  }
  setTimeout(() => modal.remove(), 200);
}

// ═══════════════════════════════════════════════════════════════════════════
//  AUTH FORM HANDLERS (same as 3a, refactored slightly)
// ═══════════════════════════════════════════════════════════════════════════

function wireAuthForms() {
  $$('#auth-tabs .tab-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const tab = btn.dataset.tab;
      $$('#auth-tabs .tab-btn').forEach(b => b.classList.toggle('active', b === btn));
      if (tab === 'login') { showEl('#login-form'); hideEl('#signup-form'); $('#login-username').focus(); }
      else { hideEl('#login-form'); showEl('#signup-form'); $('#signup-username').focus(); }
      ['#login-error', '#signup-error'].forEach(s => { const e = $(s); if (e) { e.textContent=''; e.classList.add('hidden'); }});
    });
  });

  const wirePwToggle = (btnId, inputId) => {
    const btn = $('#' + btnId);
    btn?.addEventListener('click', () => {
      const input = $('#' + inputId);
      input.type = input.type === 'password' ? 'text' : 'password';
      const icon = btn.querySelector('i');
      if (icon) { icon.setAttribute('data-lucide', input.type === 'password' ? 'eye' : 'eye-off'); renderIcons(btn); }
    });
  };
  wirePwToggle('login-toggle-pw', 'login-password');
  wirePwToggle('signup-toggle-pw', 'signup-password');

  $('#login-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const err = $('#login-error'); err.textContent=''; err.classList.add('hidden');
    const u = $('#login-username').value.trim();
    const p = $('#login-password').value;
    if (!u || !p) { err.textContent='Enter username and password'; err.classList.remove('hidden'); return; }
    const btn = $('#login-submit'); btn.disabled = true;
    btn.querySelector('.btn-label')?.classList.add('hidden');
    btn.querySelector('.btn-spinner')?.classList.remove('hidden');
    try {
      // Try online first.
      try {
        await doLogin(u, p);
      } catch (netErr) {
        // If it's a real auth failure, surface that. If it's a network
        // failure AND we have a cached vault for this user, offer offline
        // login instead.
        const isNetwork = !netErr.status; // status set by api() on HTTP errors
        if (!isNetwork) throw netErr;

        if (window.VK_Offline) {
          const meta = await window.VK_Offline.getUserMetadata(u);
          if (meta) {
            const valid = await window.VK_Offline.isUserCacheValid(u);
            if (!valid) {
              err.textContent = 'Offline cache expired — please connect to the internet to log in.';
              err.classList.remove('hidden');
              return;
            }
            // Offline path
            await doOfflineLogin(u, p);
            $('#login-password').value = '';
            await showApp();
            showToast('Offline mode — changes will sync when you reconnect.', 'info');
            return;
          }
        }
        // No cache → user must connect at least once
        err.textContent = 'No connection and no cached vault — connect to log in for the first time.';
        err.classList.remove('hidden');
        return;
      }
      $('#login-password').value = '';
      await showApp();
    } catch (e2) {
      err.textContent = e2.status === 401 ? 'Invalid username or master password' : (e2.message || 'Login failed');
      err.classList.remove('hidden');
    } finally {
      btn.disabled = false;
      btn.querySelector('.btn-label')?.classList.remove('hidden');
      btn.querySelector('.btn-spinner')?.classList.add('hidden');
    }
  });

  $('#signup-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const err = $('#signup-error'); err.textContent=''; err.classList.add('hidden');
    const u = $('#signup-username').value.trim();
    const p = $('#signup-password').value;
    const c = $('#signup-confirm').value;
    if (!u || !p) { err.textContent='All fields required'; err.classList.remove('hidden'); return; }
    if (!/^[a-z0-9._-]{2,50}$/i.test(u)) { err.textContent='Username: 2–50 chars, letters/numbers/. _ -'; err.classList.remove('hidden'); return; }
    if (p.length < 12) { err.textContent='Master password must be at least 12 characters'; err.classList.remove('hidden'); return; }
    if (p !== c) { err.textContent='Passwords do not match'; err.classList.remove('hidden'); return; }
    const btn = $('#signup-submit'); btn.disabled = true;
    btn.querySelector('.btn-label')?.classList.add('hidden');
    btn.querySelector('.btn-spinner')?.classList.remove('hidden');
    try {
      await doSignup(u, p);
      $('#signup-password').value = ''; $('#signup-confirm').value = '';
      showToast('Vault created', 'success');
      await showApp();
    } catch (e2) {
      err.textContent = e2.message || 'Signup failed';
      err.classList.remove('hidden');
    } finally {
      btn.disabled = false;
      btn.querySelector('.btn-label')?.classList.remove('hidden');
      btn.querySelector('.btn-spinner')?.classList.add('hidden');
    }
  });
}

// ═══════════════════════════════════════════════════════════════════════════
//  BOOT
// ═══════════════════════════════════════════════════════════════════════════

async function boot() {
  try {
    renderIcons();
    installActivityListeners();
    wireAuthForms();

    // App-shell wiring (these elements exist in DOM but app-shell is hidden until login)
    $('#btn-logout').addEventListener('click', () => doLogout(true));
    $('#btn-lock').addEventListener('click', () => { doLogout(false); showToast('Vault locked', 'info'); });

    // Hamburger menu — opens sidebar drawer on mobile
    const overlay = $('#sidebar-overlay');
    $('#btn-menu-mobile')?.addEventListener('click', () => {
      $('#sidebar')?.classList.toggle('mobile-open');
      overlay?.classList.toggle('visible');
    });
    overlay?.addEventListener('click', () => {
      $('#sidebar')?.classList.remove('mobile-open');
      overlay.classList.remove('visible');
    });

    // Bottom-nav buttons
    $$('#bottom-nav .bottom-nav-btn').forEach(btn => {
      btn.addEventListener('click', () => setView(btn.dataset.bnav));
    });
    $('#bnav-add')?.addEventListener('click', () => openItemEditor(null));

    // Offline indicator: retry button + browser online/offline events
    $('#offline-banner-retry')?.addEventListener('click', attemptReconnect);
    window.addEventListener('online', () => {
      if (state.offline) attemptReconnect();
    });
    window.addEventListener('offline', () => {
      if (state.username && !state.offline) {
        state.offline = true;
        updateOfflineIndicator();
      }
    });

    if (typeof VKCrypto === 'undefined') {
      const err = $('#login-error');
      if (err) { err.textContent='Crypto module failed to load. Reload the page.'; err.classList.remove('hidden'); }
      return;
    }
    try { await callWorker('ping', {}, 5000); }
    catch(e) { console.warn('[vk-app] worker ping failed:', e.message); }
    showAuth();
  } catch (e) {
    console.error('[vk-app] boot() threw:', e);
    alert('VaultKeeper boot failed: ' + e.message + '\n\nSee browser console for details.');
  }
}

document.addEventListener('DOMContentLoaded', boot);
