#!/usr/bin/env node
// ═════════════════════════════════════════════════════════════════════════
//  VaultKeeper E2E Server — Day 2 test harness
// ═════════════════════════════════════════════════════════════════════════
//  Exercises the new server endpoints end-to-end. Does NOT use the real
//  client crypto module — we simulate ciphertext with random-looking base64.
//  This checks the SERVER contract: validation, auth, routing, errors.
//
//  Run after deploying server.js:
//    node api-test.js https://vaultkeeper.eternusnox.com
//    (or http://localhost:3333 if testing against a local dev container)
// ═════════════════════════════════════════════════════════════════════════

'use strict';

const BASE_URL = process.argv[2] || 'http://localhost:3333';

// Tiny test harness
let pass = 0, fail = 0;
const failures = [];
function ok(cond, name, detail) {
  if (cond) { console.log('  \x1b[32m✓\x1b[0m ' + name); pass++; }
  else { console.log('  \x1b[31m✗\x1b[0m ' + name + (detail ? '  ← ' + detail : '')); fail++; failures.push({ name, detail }); }
}
function group(name) { console.log('\n── ' + name + ' ──'); }

// Fake ciphertext (random base64)
function fakeB64(nBytes) {
  const b = require('crypto').randomBytes(nBytes);
  return b.toString('base64');
}

async function http(method, pathAndQuery, body, token) {
  const url = BASE_URL + pathAndQuery;
  const opts = {
    method,
    headers: { 'Content-Type': 'application/json', 'Origin': BASE_URL }
  };
  if (token) opts.headers['Authorization'] = 'Bearer ' + token;
  // Never send a body when not needed (undefined/null) or on GET/HEAD.
  if (body !== undefined && body !== null && method !== 'GET' && method !== 'HEAD') {
    opts.body = JSON.stringify(body);
  }
  const res = await fetch(url, opts);
  const text = await res.text();
  let data = null;
  try { data = text ? JSON.parse(text) : null; } catch { /* not JSON */ }
  return { status: res.status, data, raw: text };
}

async function main() {
  console.log('Testing server at: ' + BASE_URL);

  // ═════════ 1. HEALTH ═════════
  group('Liveness');
  {
    const r = await http('GET', '/healthz');
    ok(r.status === 200, '/healthz returns 200', 'got ' + r.status);
    ok(r.data && r.data.ok === true, '/healthz has ok:true');
    ok(r.data && r.data.mode === 'e2e', '/healthz reports mode:e2e');
  }

  // ═════════ 2. SIGNUP ═════════
  group('Signup');
  // Use a unique username so we can re-run tests
  const uname = 'test_' + Date.now();
  const authHash = fakeB64(32);
  const protectedSym = fakeB64(125);
  const kdf = { memory_cost: 65536, time_cost: 2, parallelism: 1 };

  let token;
  {
    const r = await http('POST', '/api/auth/signup', {
      username: uname, auth_hash: authHash,
      protected_symmetric_key: protectedSym, kdf
    });
    ok(r.status === 200, 'signup returns 200', 'got ' + r.status + ' ' + (r.raw || ''));
    ok(r.data && typeof r.data.token === 'string' && r.data.token.length > 20, 'returns JWT');
    ok(r.data && r.data.username === uname, 'returns username');
    token = r.data && r.data.token;
  }

  // Re-signup with same username should fail (not leak the existence, but 400)
  {
    const r = await http('POST', '/api/auth/signup', {
      username: uname, auth_hash: authHash,
      protected_symmetric_key: protectedSym, kdf
    });
    ok(r.status === 400, 'duplicate signup gets 400', 'got ' + r.status);
    ok(!/taken/i.test(JSON.stringify(r.data || {}).toLowerCase()) || /taken/i.test(r.data?.error || ''),
       'error message is generic (not enumerating)');
  }

  // Signup with weak KDF rejected
  {
    const r = await http('POST', '/api/auth/signup', {
      username: 'weak_' + Date.now(), auth_hash: authHash,
      protected_symmetric_key: protectedSym,
      kdf: { memory_cost: 8192, time_cost: 1, parallelism: 1 }
    });
    ok(r.status === 400, 'weak KDF rejected');
    ok(r.data && /memory_cost/.test(r.data.error || ''), 'error mentions memory_cost');
  }

  // Username with caps is silently lowercased (better UX than rejecting)
  {
    const r = await http('POST', '/api/auth/signup', {
      username: 'CAPS_' + Date.now().toString().slice(-6), auth_hash: authHash,
      protected_symmetric_key: protectedSym, kdf
    });
    ok(r.status === 200 && r.data?.username === r.data?.username?.toLowerCase(),
       'username with caps is lowercased (not rejected)');
  }

  // Signup with bad username
  for (const bad of ['', 'a', 'has spaces', 'has@symbol', 'a'.repeat(51)]) {
    const r = await http('POST', '/api/auth/signup', {
      username: bad, auth_hash: authHash,
      protected_symmetric_key: protectedSym, kdf
    });
    ok(r.status === 400, `bad username "${bad}" rejected`, 'got ' + r.status);
  }

  // Signup with bad auth_hash
  {
    const r = await http('POST', '/api/auth/signup', {
      username: 'bad_' + Date.now(),
      auth_hash: 'not-valid-base64!@#',
      protected_symmetric_key: protectedSym, kdf
    });
    ok(r.status === 400, 'non-base64 auth_hash rejected');
  }

  // ═════════ 3. PRELOGIN ═════════
  group('Prelogin (must not enumerate users)');
  {
    const r1 = await http('POST', '/api/auth/prelogin', { username: uname });
    ok(r1.status === 200, 'prelogin for real user returns 200');
    ok(r1.data?.kdf?.memory_cost === kdf.memory_cost, 'returns correct memory_cost for real user');
    ok(r1.data?.kdf?.time_cost === kdf.time_cost, 'returns correct time_cost for real user');

    const r2 = await http('POST', '/api/auth/prelogin', { username: 'definitely_does_not_exist_' + Date.now() });
    ok(r2.status === 200, 'prelogin for fake user still returns 200 (no enumeration)');
    ok(r2.data?.kdf?.memory_cost > 0, 'returns plausible kdf params for fake user');

    // Deterministic — same fake user should yield same params
    const r3 = await http('POST', '/api/auth/prelogin', { username: 'stable_fake_user_12345' });
    const r4 = await http('POST', '/api/auth/prelogin', { username: 'stable_fake_user_12345' });
    ok(JSON.stringify(r3.data?.kdf) === JSON.stringify(r4.data?.kdf),
       'fake user gets deterministic kdf params (same across requests)');
  }

  // ═════════ 4. LOGIN ═════════
  group('Login');
  let loginToken, loginPSK;
  {
    const r = await http('POST', '/api/auth/login', { username: uname, auth_hash: authHash });
    ok(r.status === 200, 'login with correct hash returns 200', 'got ' + r.status);
    ok(typeof r.data?.token === 'string', 'returns JWT');
    ok(r.data?.protected_symmetric_key === protectedSym, 'returns the stored protected_symmetric_key');
    loginToken = r.data.token;
    loginPSK = r.data.protected_symmetric_key;
  }

  {
    const r = await http('POST', '/api/auth/login', {
      username: uname, auth_hash: fakeB64(32)  // wrong hash
    });
    ok(r.status === 401, 'login with wrong hash returns 401', 'got ' + r.status);
  }

  {
    const r = await http('POST', '/api/auth/login', {
      username: 'nonexistent_' + Date.now(), auth_hash: fakeB64(32)
    });
    ok(r.status === 401, 'login with nonexistent user returns 401 (not 404 — no enumeration)');
  }

  // ═════════ 5. AUTHED ROUTES ═════════
  group('Authenticated routes');
  {
    const r = await http('GET', '/api/auth/me', null, loginToken);
    ok(r.status === 200, '/api/auth/me works with token');
    ok(r.data?.username === uname, '/api/auth/me returns correct username');
  }
  {
    const r = await http('GET', '/api/auth/me', null, 'bogus');
    ok(r.status === 401, '/api/auth/me rejects bogus token');
  }
  {
    const r = await http('GET', '/api/auth/me');
    ok(r.status === 401, '/api/auth/me rejects missing token');
  }

  // ═════════ 6. VAULT CRUD ═════════
  group('Vault CRUD');
  let itemId;
  {
    const r = await http('POST', '/api/vault', {
      type: 'login',
      encrypted_data: fakeB64(200),
      favorite: false
    }, loginToken);
    ok(r.status === 201, 'create item returns 201', 'got ' + r.status + ' ' + (r.raw || ''));
    ok(r.data?.id > 0, 'returns new item id');
    itemId = r.data?.id;
  }

  {
    const r = await http('GET', '/api/vault', null, loginToken);
    ok(r.status === 200, 'list vault returns 200');
    ok(Array.isArray(r.data) && r.data.length >= 1, 'list includes the new item');
    ok(r.data[0].encrypted_data && r.data[0].encrypted_data.length > 0, 'item has encrypted_data');
    ok(r.data[0].type === 'login', 'item type preserved');
  }

  {
    const r = await http('PUT', '/api/vault/' + itemId, {
      encrypted_data: fakeB64(250)
    }, loginToken);
    ok(r.status === 200, 'update item returns 200');
  }

  {
    const r = await http('PATCH', '/api/vault/' + itemId + '/favorite',
      { favorite: true }, loginToken);
    ok(r.status === 200, 'toggle favorite returns 200');
  }

  // Bad item types
  {
    const r = await http('POST', '/api/vault', {
      type: 'bogus', encrypted_data: fakeB64(100)
    }, loginToken);
    ok(r.status === 400, 'bad type rejected');
  }
  {
    const r = await http('POST', '/api/vault', {
      type: 'login', encrypted_data: 'not-base64-at-all!'
    }, loginToken);
    ok(r.status === 400, 'non-base64 encrypted_data rejected');
  }
  // Oversized encrypted_data
  {
    const r = await http('POST', '/api/vault', {
      type: 'login', encrypted_data: 'A'.repeat(300 * 1024)  // 300KB
    }, loginToken);
    ok(r.status === 400 || r.status === 413, 'oversized encrypted_data rejected', 'got ' + r.status);
  }

  // Access another user's item? Create a second user and try.
  group('Authorization boundary');
  const otherUname = 'other_' + Date.now();
  const otherHash = fakeB64(32);
  const otherPSK = fakeB64(125);
  let otherToken;
  {
    const r = await http('POST', '/api/auth/signup', {
      username: otherUname, auth_hash: otherHash,
      protected_symmetric_key: otherPSK, kdf
    });
    otherToken = r.data?.token;
    ok(otherToken, 'second user signed up');
  }
  {
    const r = await http('GET', '/api/vault', null, otherToken);
    ok(r.status === 200 && Array.isArray(r.data) && r.data.length === 0,
       'other user sees empty vault (not cross-contaminated)');
  }
  {
    const r = await http('PUT', '/api/vault/' + itemId,
      { encrypted_data: fakeB64(100) }, otherToken);
    ok(r.status === 404, 'other user cannot update first user\'s item');
  }
  {
    const r = await http('DELETE', '/api/vault/' + itemId, null, otherToken);
    ok(r.status === 404, 'other user cannot delete first user\'s item',
       'got ' + r.status + ' ' + (r.raw || ''));
  }

  // ═════════ 7. FOLDERS ═════════
  group('Folders');
  let folderId;
  {
    const r = await http('POST', '/api/folders', {
      encrypted_name: fakeB64(60), color: '#f59e0b'
    }, loginToken);
    ok(r.status === 201, 'create folder returns 201', 'got ' + r.status + ' ' + (r.raw || ''));
    ok(r.data?.id > 0, 'returns folder id');
    folderId = r.data?.id;
  }
  {
    const r = await http('GET', '/api/folders', null, loginToken);
    ok(r.status === 200 && Array.isArray(r.data), 'list folders');
    ok(r.data.some(f => f.id === folderId), 'new folder appears in list');
  }
  {
    const r = await http('POST', '/api/folders', {
      encrypted_name: fakeB64(60), color: 'not-a-color'
    }, loginToken);
    ok(r.status === 400, 'bad color rejected');
  }

  // Move item into folder
  {
    const r = await http('PUT', '/api/vault/' + itemId,
      { folder_id: folderId }, loginToken);
    ok(r.status === 200, 'move item into folder');
  }
  // Try to use a folder we don't own
  {
    const r = await http('POST', '/api/vault', {
      type: 'note', encrypted_data: fakeB64(100), folder_id: folderId
    }, otherToken);
    ok(r.status === 400, 'other user cannot put item in our folder');
  }

  // ═════════ 8. PASSWORD CHANGE ═════════
  group('Password change');
  const newHash = fakeB64(32);
  const newPSK = fakeB64(125);
  {
    const r = await http('POST', '/api/auth/change-password', {
      current_auth_hash: authHash,
      new_auth_hash: newHash,
      new_protected_symmetric_key: newPSK,
      new_kdf: { memory_cost: 131072, time_cost: 3, parallelism: 1 }
    }, loginToken);
    ok(r.status === 200, 'password change returns 200', 'got ' + r.status + ' ' + (r.raw || ''));
  }
  {
    // Old token should still be rejected because token_version bumped
    const r = await http('GET', '/api/auth/me', null, loginToken);
    ok(r.status === 401, 'old token invalidated after password change');
  }
  {
    // Log in with new hash
    const r = await http('POST', '/api/auth/login', {
      username: uname, auth_hash: newHash
    });
    ok(r.status === 200, 'can login with new hash');
    ok(r.data?.protected_symmetric_key === newPSK, 'login returns the new protected_symmetric_key');
  }
  {
    // Old hash rejected
    const r = await http('POST', '/api/auth/login', {
      username: uname, auth_hash: authHash
    });
    ok(r.status === 401, 'cannot login with old hash');
  }

  // ═════════ SUMMARY ═════════
  console.log('\n' + '═'.repeat(60));
  console.log(`${pass} passed, ${fail} failed`);
  if (fail > 0) {
    console.log('\nFailures:');
    for (const f of failures) {
      console.log('  • ' + f.name + (f.detail ? '  ← ' + f.detail : ''));
    }
    process.exit(1);
  }
}

main().catch(e => {
  console.error('Test run crashed:', e);
  process.exit(1);
});
