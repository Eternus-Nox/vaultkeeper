'use strict';

// ═══════════════════════════════════════════════════════════════════════════
//  VaultKeeper — Import Adapters
// ═══════════════════════════════════════════════════════════════════════════
//
//  Each adapter parses a vendor's export into our canonical internal shape:
//
//    { items: [{ type, folder_name, favorite, data: { name, ... } }, ...],
//      folders: [{ name, color }, ...] }
//
//  Folders are referenced by NAME, not ID — the importer creates them
//  on demand and links items by name.
//
//  Item data fields by type:
//    login    → { name, username, password, url, totp, notes }
//    card     → { name, cardholder, number, expiry, cvv, pin, notes }
//    note     → { name, content }
//    identity → { name, fullname, email, phone, address, notes }
//
//  Adapters return null/throw on totally invalid input so the UI can
//  show "Couldn't recognize this file as <format>" cleanly.
// ═══════════════════════════════════════════════════════════════════════════

window.VKImport = (function() {

  // ── Tiny CSV parser (RFC 4180-ish) ──────────────────────────────────────
  // Returns array of rows; first row is treated as header by callers.
  function parseCSV(text) {
    const rows = [];
    let row = [];
    let field = '';
    let i = 0;
    let inQuotes = false;
    text = text.replace(/^\uFEFF/, ''); // strip BOM
    while (i < text.length) {
      const c = text[i];
      if (inQuotes) {
        if (c === '"' && text[i+1] === '"') { field += '"'; i += 2; continue; }
        if (c === '"') { inQuotes = false; i++; continue; }
        field += c; i++;
      } else {
        if (c === '"') { inQuotes = true; i++; continue; }
        if (c === ',') { row.push(field); field = ''; i++; continue; }
        if (c === '\r') { i++; continue; }
        if (c === '\n') { row.push(field); rows.push(row); row = []; field = ''; i++; continue; }
        field += c; i++;
      }
    }
    if (field !== '' || row.length) { row.push(field); rows.push(row); }
    return rows;
  }

  function csvHeaderMap(headerRow) {
    const m = {};
    headerRow.forEach((h, idx) => { m[h.trim().toLowerCase()] = idx; });
    return m;
  }

  function pickFirst(obj, keys) {
    for (const k of keys) if (obj[k] !== undefined && obj[k] !== null && obj[k] !== '') return obj[k];
    return '';
  }

  function safeStr(v) { return v == null ? '' : String(v); }

  // ── Bitwarden JSON ──────────────────────────────────────────────────────
  // Format: https://bitwarden.com/help/article/encrypted-export/ (unencrypted)
  // {
  //   "encrypted": false,
  //   "folders": [{id, name}],
  //   "items": [{
  //     id, name, type (1=login, 2=secureNote, 3=card, 4=identity),
  //     favorite, folderId, notes,
  //     login: { username, password, totp, uris: [{uri}] },
  //     card: { cardholderName, number, code, expMonth, expYear },
  //     identity: { firstName, middleName, lastName, email, phone, address1, ... }
  //   }]
  // }
  function importBitwarden(text) {
    let json;
    try { json = JSON.parse(text); }
    catch (e) { throw new Error('Not valid JSON'); }
    if (!json.items || !Array.isArray(json.items)) {
      throw new Error('Not a Bitwarden export (missing "items")');
    }
    if (json.encrypted === true) {
      throw new Error('This Bitwarden export is encrypted. Export with "Account-restricted" or "Password-protected" disabled.');
    }

    // Folder ID → name
    const folderMap = new Map();
    const folders = [];
    for (const f of (json.folders || [])) {
      if (!f.name) continue;
      folderMap.set(f.id, f.name);
      folders.push({ name: f.name, color: null });
    }

    const items = [];
    for (const it of json.items) {
      const folder_name = it.folderId ? folderMap.get(it.folderId) || null : null;
      const favorite = !!it.favorite;
      const name = safeStr(it.name) || '(unnamed)';
      const notes = safeStr(it.notes);

      switch (it.type) {
        case 1: { // login
          const login = it.login || {};
          const url = (login.uris && login.uris[0] && login.uris[0].uri) || '';
          items.push({
            type: 'login', folder_name, favorite,
            data: {
              name,
              username: safeStr(login.username),
              password: safeStr(login.password),
              url: safeStr(url),
              totp: extractTotpSecret(login.totp),
              notes,
            }
          });
          break;
        }
        case 2: { // secure note
          items.push({
            type: 'note', folder_name, favorite,
            data: { name, content: notes },
          });
          break;
        }
        case 3: { // card
          const c = it.card || {};
          let expiry = '';
          if (c.expMonth && c.expYear) {
            const yr = String(c.expYear).slice(-2);
            const mo = String(c.expMonth).padStart(2, '0');
            expiry = `${mo}/${yr}`;
          }
          items.push({
            type: 'card', folder_name, favorite,
            data: {
              name,
              cardholder: safeStr(c.cardholderName),
              number: safeStr(c.number),
              expiry,
              cvv: safeStr(c.code),
              pin: '',
              notes,
            }
          });
          break;
        }
        case 4: { // identity
          const id = it.identity || {};
          const fullname = [id.firstName, id.middleName, id.lastName].filter(Boolean).join(' ');
          const address = [id.address1, id.address2, id.address3, id.city, id.state, id.postalCode, id.country].filter(Boolean).join(', ');
          items.push({
            type: 'identity', folder_name, favorite,
            data: {
              name,
              fullname,
              email: safeStr(id.email),
              phone: safeStr(id.phone),
              address,
              notes,
            }
          });
          break;
        }
        default: {
          // Unknown type → import as note with the raw fields
          items.push({
            type: 'note', folder_name, favorite,
            data: { name, content: notes || JSON.stringify(it).slice(0, 4000) },
          });
        }
      }
    }
    return { items, folders };
  }

  // ── 1Password JSON (1Password 8 export) ─────────────────────────────────
  // 1Password 8's "Unencrypted JSON" export has shape:
  // {
  //   "accounts": [{
  //     "vaults": [{
  //       "name": "Personal",
  //       "items": [{
  //         "uuid", "favIndex", "categoryUuid",
  //         "overview": { "title", "url", "urls" },
  //         "details": {
  //           "fields": [{ "designation": "username|password", "value" }],
  //           "loginFields": [...],
  //           "sections": [{ "fields": [{ "title", "value" }] }],
  //           "notesPlain": "..."
  //         }
  //       }]
  //     }]
  //   }]
  // }
  // category UUIDs (selected): 001 (Login), 002 (Credit Card), 003 (Note),
  //                            004 (Identity), 005 (Password), 110 (Server)
  function import1Password(text) {
    let json;
    try { json = JSON.parse(text); }
    catch (e) { throw new Error('Not valid JSON'); }
    if (!json.accounts || !Array.isArray(json.accounts)) {
      throw new Error('Not a 1Password 8 export (missing "accounts")');
    }

    const folders = [];
    const seenFolderNames = new Set();
    const items = [];

    for (const acc of json.accounts) {
      for (const vault of (acc.vaults || [])) {
        const folder_name = vault.name && vault.name !== 'Personal' ? vault.name : null;
        if (folder_name && !seenFolderNames.has(folder_name)) {
          folders.push({ name: folder_name, color: null });
          seenFolderNames.add(folder_name);
        }
        for (const it of (vault.items || [])) {
          const ov = it.overview || {};
          const det = it.details || {};
          const cat = it.categoryUuid;
          const name = safeStr(ov.title) || '(unnamed)';
          const favorite = !!it.favIndex;
          // Build a flat field map from designation/title → value
          const fields = {};
          for (const f of (det.fields || [])) {
            const k = (f.designation || f.title || '').toLowerCase();
            if (k && f.value) fields[k] = f.value;
          }
          for (const f of (det.loginFields || [])) {
            const k = (f.designation || f.name || '').toLowerCase();
            if (k && f.value) fields[k] = f.value;
          }
          for (const sect of (det.sections || [])) {
            for (const f of (sect.fields || [])) {
              const k = (f.title || f.name || '').toLowerCase();
              if (k && (f.value !== undefined && f.value !== null)) {
                // f.value may be {string: "..."} or {totp: "..."}
                const v = typeof f.value === 'object'
                  ? (f.value.string || f.value.totp || f.value.text || JSON.stringify(f.value))
                  : f.value;
                if (v) fields[k] = String(v);
              }
            }
          }
          const notes = safeStr(det.notesPlain);
          const url = safeStr(ov.url || (Array.isArray(ov.urls) && ov.urls[0] && ov.urls[0].url));

          if (cat === '001' || cat === '005') { // login / password
            items.push({
              type: 'login', folder_name, favorite,
              data: {
                name,
                username: pickFirst(fields, ['username', 'email', 'user']),
                password: pickFirst(fields, ['password']),
                url,
                totp: extractTotpSecret(pickFirst(fields, ['one-time password', 'otp', 'totp'])),
                notes,
              }
            });
          } else if (cat === '002') { // credit card
            items.push({
              type: 'card', folder_name, favorite,
              data: {
                name,
                cardholder: pickFirst(fields, ['cardholder name', 'cardholder']),
                number: pickFirst(fields, ['number', 'cc-number']),
                expiry: pickFirst(fields, ['expiry date', 'expiration', 'expiry']),
                cvv: pickFirst(fields, ['verification number', 'cvv', 'cvv2', 'security code']),
                pin: pickFirst(fields, ['pin']),
                notes,
              }
            });
          } else if (cat === '003') { // secure note
            items.push({
              type: 'note', folder_name, favorite,
              data: { name, content: notes },
            });
          } else if (cat === '004') { // identity
            items.push({
              type: 'identity', folder_name, favorite,
              data: {
                name,
                fullname: pickFirst(fields, ['full name', 'name']) || [fields['first name'], fields['last name']].filter(Boolean).join(' '),
                email: pickFirst(fields, ['email', 'default']),
                phone: pickFirst(fields, ['phone', 'cell', 'mobile']),
                address: pickFirst(fields, ['address']) ||
                  [fields['street'], fields['city'], fields['state'], fields['zip']].filter(Boolean).join(', '),
                notes,
              }
            });
          } else {
            // Unknown / Server / API Credential / etc → import as login if it has password, else note
            if (fields.password || fields.username) {
              items.push({
                type: 'login', folder_name, favorite,
                data: {
                  name,
                  username: pickFirst(fields, ['username', 'email', 'user']),
                  password: pickFirst(fields, ['password']),
                  url,
                  totp: extractTotpSecret(pickFirst(fields, ['totp', 'otp'])),
                  notes: notes + (Object.keys(fields).filter(k => !['username','password','email','totp','otp'].includes(k)).length
                    ? '\n\n' + Object.entries(fields).filter(([k]) => !['username','password','email','totp','otp'].includes(k)).map(([k,v]) => `${k}: ${v}`).join('\n')
                    : ''),
                }
              });
            } else {
              items.push({
                type: 'note', folder_name, favorite,
                data: { name, content: notes || Object.entries(fields).map(([k,v]) => `${k}: ${v}`).join('\n') },
              });
            }
          }
        }
      }
    }
    return { items, folders };
  }

  // ── LastPass CSV ────────────────────────────────────────────────────────
  // Format: url,username,password,totp,extra,name,grouping,fav
  //   - grouping is the folder name (may be empty)
  //   - extra is "notes" content
  //   - rows starting url=http://sn... are secure notes
  //   - fav = 1 if favorite
  function importLastPass(text) {
    const rows = parseCSV(text);
    if (rows.length < 2) throw new Error('CSV is empty or has no data rows');
    const hdr = csvHeaderMap(rows[0]);
    if (hdr.url === undefined || hdr.username === undefined || hdr.password === undefined) {
      throw new Error('Not a LastPass CSV (missing url/username/password columns)');
    }

    const folders = [];
    const seenFolders = new Set();
    const items = [];

    for (let r = 1; r < rows.length; r++) {
      const row = rows[r];
      if (row.every(c => !c || !c.trim())) continue;

      const url = safeStr(row[hdr.url]).trim();
      const username = safeStr(row[hdr.username]);
      const password = safeStr(row[hdr.password]);
      const totp = hdr.totp !== undefined ? extractTotpSecret(safeStr(row[hdr.totp])) : '';
      const extra = hdr.extra !== undefined ? safeStr(row[hdr.extra]) : '';
      const name = (hdr.name !== undefined ? safeStr(row[hdr.name]) : '') || '(unnamed)';
      const grouping = hdr.grouping !== undefined ? safeStr(row[hdr.grouping]).trim() : '';
      const fav = hdr.fav !== undefined ? safeStr(row[hdr.fav]) === '1' : false;

      if (grouping && !seenFolders.has(grouping)) {
        folders.push({ name: grouping, color: null });
        seenFolders.add(grouping);
      }

      const isSecureNote = url.startsWith('http://sn');
      if (isSecureNote) {
        // LastPass secure notes encode their type and fields in `extra`.
        // For credit cards: "NoteType:Credit Card\nName on Card:...\n..."
        // We try to parse common patterns; otherwise treat as a plain note.
        const card = extractLastPassCard(extra);
        if (card) {
          items.push({
            type: 'card', folder_name: grouping || null, favorite: fav,
            data: { name, ...card }
          });
        } else {
          items.push({
            type: 'note', folder_name: grouping || null, favorite: fav,
            data: { name, content: extra }
          });
        }
      } else {
        items.push({
          type: 'login', folder_name: grouping || null, favorite: fav,
          data: { name, username, password, url, totp, notes: extra }
        });
      }
    }
    return { items, folders };
  }

  function extractLastPassCard(extra) {
    if (!/NoteType:\s*Credit Card/i.test(extra)) return null;
    const get = (label) => {
      const m = extra.match(new RegExp(label + ':\\s*([^\\n]*)', 'i'));
      return m ? m[1].trim() : '';
    };
    return {
      cardholder: get('Name on Card'),
      number: get('Number'),
      expiry: [get('Expiration Month'), get('Expiration Year')].filter(Boolean).join('/').replace(/^,|,$/g, ''),
      cvv: get('Security Code'),
      pin: '',
      notes: get('Notes'),
    };
  }

  // ── Enpass JSON ─────────────────────────────────────────────────────────
  // Format: { "items": [{
  //   "title", "category", "subtitle", "favorite",
  //   "fields": [{ "label", "value", "type", "deleted", "sensitive" }],
  //   "note": "...",
  //   "folders": ["folderUuid"]   (refers to top-level "folders" array)
  // }],
  //   "folders": [{ "uuid", "title" }] }
  // Strip otpauth:// URIs down to the raw base32 secret. Enpass and some
  // other apps store TOTP as a full provisioning URI; our TOTP generator
  // only understands raw base32. Returns the input unchanged if it doesn't
  // look like an otpauth URI.
  function extractTotpSecret(value) {
    if (!value) return '';
    const v = String(value).trim();
    if (!/^otpauth:\/\//i.test(v)) return v;
    try {
      // URL parser handles otpauth scheme on most modern browsers/Node.
      // Fall back to regex if it doesn't.
      const u = new URL(v);
      const s = u.searchParams.get('secret');
      if (s) return s;
    } catch { /* fall through */ }
    const m = v.match(/[?&]secret=([A-Z2-7=]+)/i);
    return m ? m[1] : v;
  }

  function importEnpass(text) {
    let json;
    try { json = JSON.parse(text); }
    catch (e) { throw new Error('Not valid JSON'); }
    if (!json.items || !Array.isArray(json.items)) {
      throw new Error('Not an Enpass export (missing "items")');
    }

    const folderMap = new Map();
    const folders = [];
    for (const f of (json.folders || [])) {
      if (!f.title) continue;
      folderMap.set(f.uuid, f.title);
      folders.push({ name: f.title, color: null });
    }

    const items = [];
    for (const it of json.items) {
      const name = safeStr(it.title) || '(unnamed)';
      const favorite = !!it.favorite;
      const category = (it.category || '').toLowerCase();
      const folder_name = (it.folders && it.folders[0] && folderMap.get(it.folders[0])) || null;
      const notes = safeStr(it.note);

      // Build a map keyed by lowercase label, AND separately track totp
      // secrets by the canonical Enpass field type. Field types are more
      // reliable than user-edited labels.
      const fieldMap = {};
      let totpFromType = '';
      for (const f of (it.fields || [])) {
        if (f.deleted) continue;
        const k = safeStr(f.label).toLowerCase();
        const v = safeStr(f.value);
        const t = safeStr(f.type).toLowerCase();
        if (t === 'totp' && v) totpFromType = extractTotpSecret(v);
        if (k && v) fieldMap[k] = v;
      }

      // For TOTP, prefer the type-based detection over label matching.
      // If type didn't catch it, fall back to a label search and normalize.
      const totp = totpFromType || extractTotpSecret(
        pickFirst(fieldMap, ['totp', 'one-time password', 'otp', '2fa', '2fa secret', 'authenticator'])
      );

      if (category === 'login' || category === 'password') {
        items.push({
          type: 'login', folder_name, favorite,
          data: {
            name,
            username: pickFirst(fieldMap, ['username', 'email', 'user', 'login']),
            password: pickFirst(fieldMap, ['password']),
            url: pickFirst(fieldMap, ['url', 'website']),
            totp,
            notes,
          }
        });
      } else if (category === 'creditcard' || category === 'credit card') {
        items.push({
          type: 'card', folder_name, favorite,
          data: {
            name,
            cardholder: pickFirst(fieldMap, ['cardholder', 'name on card', 'holder']),
            number: pickFirst(fieldMap, ['number', 'card number']),
            expiry: pickFirst(fieldMap, ['expiry date', 'expiry', 'expiration']),
            cvv: pickFirst(fieldMap, ['cvc', 'cvv', 'verification number', 'security code']),
            pin: pickFirst(fieldMap, ['pin']),
            notes,
          }
        });
      } else if (category === 'note' || category === 'secure note') {
        items.push({
          type: 'note', folder_name, favorite,
          data: { name, content: notes }
        });
      } else if (category === 'identity') {
        items.push({
          type: 'identity', folder_name, favorite,
          data: {
            name,
            fullname: pickFirst(fieldMap, ['full name', 'name']),
            email: pickFirst(fieldMap, ['email']),
            phone: pickFirst(fieldMap, ['phone', 'mobile']),
            address: pickFirst(fieldMap, ['address']),
            notes,
          }
        });
      } else {
        // Unknown category — fit as login if we have a password, else note
        if (fieldMap.password) {
          items.push({
            type: 'login', folder_name, favorite,
            data: {
              name,
              username: pickFirst(fieldMap, ['username', 'email']),
              password: fieldMap.password,
              url: pickFirst(fieldMap, ['url', 'website']),
              totp,
              notes: notes + (Object.keys(fieldMap).length
                ? '\n\n' + Object.entries(fieldMap).filter(([k]) => !['username','password','email','url','website','totp','otp'].includes(k)).map(([k,v]) => `${k}: ${v}`).join('\n')
                : ''),
            }
          });
        } else {
          const extras = Object.entries(fieldMap).map(([k,v]) => `${k}: ${v}`).join('\n');
          items.push({
            type: 'note', folder_name, favorite,
            data: { name, content: notes ? notes + (extras ? '\n\n' + extras : '') : extras },
          });
        }
      }
    }
    return { items, folders };
  }

  // ── Generic CSV ─────────────────────────────────────────────────────────
  // We accept any CSV with at minimum a "name" or "title" column. Common
  // column names for username/password/url/notes are recognised.
  function importGenericCSV(text) {
    const rows = parseCSV(text);
    if (rows.length < 2) throw new Error('CSV is empty or has no data rows');
    const hdr = csvHeaderMap(rows[0]);
    const idx = (...candidates) => {
      for (const c of candidates) if (hdr[c] !== undefined) return hdr[c];
      return -1;
    };
    const nameIdx = idx('name', 'title', 'site', 'service');
    if (nameIdx < 0) throw new Error('CSV must have a "name", "title", "site", or "service" column');

    const userIdx = idx('username', 'user', 'login', 'email');
    const passIdx = idx('password', 'pass', 'pwd');
    const urlIdx = idx('url', 'website', 'uri');
    const totpIdx = idx('totp', 'otp', '2fa');
    const notesIdx = idx('notes', 'note', 'comment', 'comments', 'description');
    const folderIdx = idx('folder', 'group', 'grouping', 'category');

    const folders = [];
    const seen = new Set();
    const items = [];

    for (let r = 1; r < rows.length; r++) {
      const row = rows[r];
      if (row.every(c => !c || !c.trim())) continue;
      const name = safeStr(row[nameIdx]).trim() || '(unnamed)';
      const username = userIdx >= 0 ? safeStr(row[userIdx]) : '';
      const password = passIdx >= 0 ? safeStr(row[passIdx]) : '';
      const url = urlIdx >= 0 ? safeStr(row[urlIdx]) : '';
      const totp = totpIdx >= 0 ? extractTotpSecret(safeStr(row[totpIdx])) : '';
      const notes = notesIdx >= 0 ? safeStr(row[notesIdx]) : '';
      const folder = folderIdx >= 0 ? safeStr(row[folderIdx]).trim() : '';

      if (folder && !seen.has(folder)) {
        folders.push({ name: folder, color: null });
        seen.add(folder);
      }

      // If no password and no username, treat as a note
      if (!password && !username) {
        items.push({
          type: 'note', folder_name: folder || null, favorite: false,
          data: { name, content: notes }
        });
      } else {
        items.push({
          type: 'login', folder_name: folder || null, favorite: false,
          data: { name, username, password, url, totp, notes },
        });
      }
    }
    return { items, folders };
  }

  // ── Public API ──────────────────────────────────────────────────────────
  const ADAPTERS = {
    bitwarden: { name: 'Bitwarden (JSON)', parse: importBitwarden, ext: '.json' },
    onepassword: { name: '1Password (JSON, v8)', parse: import1Password, ext: '.json' },
    lastpass: { name: 'LastPass (CSV)', parse: importLastPass, ext: '.csv' },
    enpass: { name: 'Enpass (JSON)', parse: importEnpass, ext: '.json' },
    csv: { name: 'Generic CSV', parse: importGenericCSV, ext: '.csv' },
  };

  function listFormats() {
    return Object.entries(ADAPTERS).map(([key, a]) => ({ key, name: a.name, ext: a.ext }));
  }

  function parse(format, text) {
    const adapter = ADAPTERS[format];
    if (!adapter) throw new Error('Unknown format: ' + format);
    return adapter.parse(text);
  }

  return { listFormats, parse };
})();
