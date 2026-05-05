// ────────────────────────────────────────────────────────────────────────
// vk-offline-conflicts.js — Stage 4 conflict UI.
//
// When the sync drainer finds that a queued offline mutation would
// overwrite a server change made by another device, it stores the
// conflict in IndexedDB rather than blindly applying. This module:
//
//   1. Polls for conflicts and renders a small ⚠ badge on each
//      conflicting item row.
//   2. Opens a resolution dialog when the user taps the badge,
//      side-by-siding their offline edit against the server's current
//      state and asking which to keep.
//   3. Shows an unobtrusive banner at the top when one or more
//      conflicts are unresolved, with a quick link to fix them.
//
// Approach: this module never edits vk-app.js's DOM directly. It uses
// a 500ms tick to find item-card elements and decorate them with badges
// based on the current conflict set. It tears the badges back off when
// conflicts are resolved.
// ────────────────────────────────────────────────────────────────────────

(function () {
  'use strict';

  if (!window.VK_Offline) return;
  const VKO = window.VK_Offline;


  function getState() {
    try { if (typeof state !== 'undefined' && state) return state; } catch {}
    return window.state || null;
  }
  function callShowToast(msg, kind) {
    try { if (typeof showToast === 'function') return showToast(msg, kind); } catch {}
    if (typeof window.showToast === 'function') return window.showToast(msg, kind);
  }


  // ──── Conflict cache ───────────────────────────────────────────────

  // Memoize the conflict set per tick so we don't hit IDB on every
  // badge-injection scan.
  let _conflictsForUser = null;
  let _conflictsLastFetch = 0;

  async function getCurrentConflicts() {
    const s = getState();
    if (!s?.username) return [];
    const now = Date.now();
    if (_conflictsForUser && (now - _conflictsLastFetch) < 2000) {
      return _conflictsForUser;
    }
    try {
      _conflictsForUser = await VKO.getConflicts(s.username);
    } catch {
      _conflictsForUser = [];
    }
    _conflictsLastFetch = now;
    return _conflictsForUser;
  }

  function invalidateConflictCache() {
    _conflictsForUser = null;
    _conflictsLastFetch = 0;
  }


  // ──── Top banner ───────────────────────────────────────────────────

  let _banner = null;

  function ensureBanner() {
    if (_banner) return _banner;
    _banner = document.createElement('div');
    _banner.id = 'conflicts-banner';
    _banner.style.cssText =
      'position:fixed;top:0;left:0;right:0;z-index:999;' +
      'padding:8px 14px;font-size:13px;font-weight:500;font-family:inherit;' +
      'display:none;background:linear-gradient(180deg,#3a2510,#2a1808);' +
      'color:#f4c97e;border-bottom:1px solid #4a3315;text-align:center;' +
      'cursor:pointer;backdrop-filter:blur(10px);';
    _banner.addEventListener('click', () => {
      // Open the first unresolved conflict
      getCurrentConflicts().then(conflicts => {
        if (conflicts.length > 0) openResolutionDialog(conflicts[0]);
      });
    });
    document.body.appendChild(_banner);
    return _banner;
  }

  async function refreshBanner() {
    const conflicts = await getCurrentConflicts();
    const b = ensureBanner();
    if (conflicts.length === 0) {
      b.style.display = 'none';
      return;
    }
    b.style.display = 'block';
    const word = conflicts.length === 1 ? 'conflict' : 'conflicts';
    b.innerHTML =
      '⚠ ' + conflicts.length + ' sync ' + word +
      ' need attention &nbsp;·&nbsp; ' +
      '<span style="text-decoration:underline">Tap to resolve</span>';
  }


  // ──── Per-item badges ──────────────────────────────────────────────

  async function decorateBadges() {
    const conflicts = await getCurrentConflicts();
    const conflictByItemId = new Map();
    for (const c of conflicts) {
      if (c.resource === 'item') conflictByItemId.set(String(c.resourceId), c);
    }

    // Find all item-card buttons and add/remove badges as needed
    const cards = document.querySelectorAll('.item-card[data-id]');
    for (const card of cards) {
      const id = card.getAttribute('data-id');
      const conflict = conflictByItemId.get(String(id));
      const existing = card.querySelector('.conflict-badge');
      if (conflict && !existing) {
        injectBadge(card, conflict);
      } else if (!conflict && existing) {
        existing.remove();
      }
    }
  }

  function injectBadge(card, conflict) {
    const badge = document.createElement('span');
    badge.className = 'conflict-badge';
    badge.title = 'This item has a sync conflict. Tap to resolve.';
    badge.style.cssText =
      'display:inline-flex;align-items:center;justify-content:center;' +
      'width:22px;height:22px;border-radius:50%;' +
      'background:rgba(244,201,126,0.15);color:#f4c97e;' +
      'font-size:13px;font-weight:600;flex-shrink:0;margin-left:6px;' +
      'border:1px solid rgba(244,201,126,0.35);cursor:pointer;';
    badge.textContent = '⚠';
    badge.addEventListener('click', (e) => {
      e.preventDefault();
      e.stopPropagation();
      openResolutionDialog(conflict);
    });
    card.appendChild(badge);
  }


  // ──── Resolution dialog ────────────────────────────────────────────

  function openResolutionDialog(conflict) {
    // Decrypt both sides client-side so we can show readable previews
    // alongside the raw payloads.
    const myPayload = conflict.mine || {};
    const theirPayload = conflict.theirs || null;

    const mine = describePayload(myPayload, 'Your offline edit');
    const theirs = theirPayload
      ? describePayload(theirPayload, 'What\'s on the server now')
      : '<div class="conflict-side-empty">Item was deleted on the server</div>';

    // Build a simple modal — we don't depend on vk-app.js's openModal
    // because we want this to also work if the dialog needs to appear
    // while another modal is open.
    const overlay = document.createElement('div');
    overlay.id = 'conflict-overlay';
    overlay.style.cssText =
      'position:fixed;inset:0;background:rgba(0,0,0,0.7);z-index:1100;' +
      'display:flex;align-items:center;justify-content:center;padding:20px;' +
      'backdrop-filter:blur(6px);';

    const dialog = document.createElement('div');
    dialog.style.cssText =
      'background:var(--surface,#181716);color:var(--text,#e8e6e3);' +
      'border:1px solid var(--border,#3a3937);border-radius:12px;' +
      'max-width:540px;width:100%;max-height:80vh;overflow-y:auto;' +
      'padding:24px;font-family:inherit;box-shadow:0 30px 80px rgba(0,0,0,0.5);';

    dialog.innerHTML =
      '<div style="display:flex;align-items:center;gap:10px;margin-bottom:6px">' +
      '<span style="display:inline-flex;align-items:center;justify-content:center;' +
      'width:28px;height:28px;border-radius:50%;background:rgba(244,201,126,0.15);' +
      'color:#f4c97e;font-weight:600">⚠</span>' +
      '<h2 style="margin:0;font-size:18px;font-weight:600">Sync conflict</h2>' +
      '</div>' +
      '<p style="margin:0 0 18px;font-size:13.5px;color:var(--text-m,#888);line-height:1.5">' +
      'You changed this ' + escHtml(conflict.resource) +
      ' offline, and another device also changed it before you reconnected. ' +
      'Pick which version to keep.' +
      '</p>' +

      '<div class="conflict-card conflict-card-mine">' +
      '<div class="conflict-side-label">YOUR VERSION (offline)</div>' +
      '<div class="conflict-side-content">' + mine + '</div>' +
      '</div>' +

      '<div class="conflict-card conflict-card-theirs">' +
      '<div class="conflict-side-label">SERVER VERSION (other device)</div>' +
      '<div class="conflict-side-content">' + theirs + '</div>' +
      '</div>' +

      '<div style="display:flex;gap:8px;margin-top:18px;flex-wrap:wrap">' +
      '<button class="btn btn-primary" id="conflict-keep-mine" style="flex:1;min-width:140px">' +
      'Keep my version' +
      '</button>' +
      '<button class="btn btn-secondary" id="conflict-keep-theirs" style="flex:1;min-width:140px">' +
      'Keep server version' +
      '</button>' +
      '</div>' +
      '<button class="btn btn-ghost" id="conflict-cancel" style="width:100%;margin-top:8px">' +
      'Decide later' +
      '</button>' +

      '<style>' +
      '.conflict-card{background:rgba(255,255,255,0.02);' +
      'border:1px solid var(--border,#3a3937);border-radius:8px;' +
      'padding:14px 16px;margin-bottom:12px}' +
      '.conflict-side-label{font-family:monospace;font-size:10px;' +
      'letter-spacing:0.1em;color:var(--text-f,#888);margin-bottom:8px}' +
      '.conflict-side-content{font-size:13px;line-height:1.5;color:var(--text)}' +
      '.conflict-side-content .field{display:flex;gap:8px;padding:3px 0}' +
      '.conflict-side-content .field-key{color:var(--text-m,#888);' +
      'min-width:80px;font-size:11px}' +
      '.conflict-side-content .field-val{flex:1;word-break:break-word}' +
      '.conflict-side-empty{font-style:italic;color:var(--text-m,#888);font-size:13px}' +
      '.conflict-card-mine{border-left:3px solid var(--primary,#4da8b0)}' +
      '.conflict-card-theirs{border-left:3px solid #f4c97e}' +
      '</style>';

    overlay.appendChild(dialog);
    document.body.appendChild(overlay);

    // Wire buttons
    dialog.querySelector('#conflict-keep-mine').addEventListener('click', async (e) => {
      const btn = e.currentTarget;
      btn.disabled = true; btn.textContent = 'Pushing…';
      try {
        await window.VK_OfflineSync.resolveConflict(conflict.compositeKey, 'keep_mine');
        invalidateConflictCache();
        await refreshBanner();
        // Trigger app to reload data so the resolution is reflected
        if (typeof loadEverything === 'function') {
          loadEverything().then(() => {
            if (typeof renderAll === 'function') renderAll();
          }).catch(() => {});
        }
        closeDialog();
      } catch (err) {
        btn.disabled = false; btn.textContent = 'Keep my version';
        callShowToast('Push failed: ' + err.message, 'error');
      }
    });

    dialog.querySelector('#conflict-keep-theirs').addEventListener('click', async (e) => {
      const btn = e.currentTarget;
      btn.disabled = true; btn.textContent = 'Saving…';
      try {
        await window.VK_OfflineSync.resolveConflict(conflict.compositeKey, 'keep_theirs');
        invalidateConflictCache();
        await refreshBanner();
        if (typeof loadEverything === 'function') {
          loadEverything().then(() => {
            if (typeof renderAll === 'function') renderAll();
          }).catch(() => {});
        }
        closeDialog();
      } catch (err) {
        btn.disabled = false; btn.textContent = 'Keep server version';
        callShowToast('Failed: ' + err.message, 'error');
      }
    });

    dialog.querySelector('#conflict-cancel').addEventListener('click', closeDialog);
    overlay.addEventListener('click', (e) => {
      if (e.target === overlay) closeDialog();
    });

    function closeDialog() {
      overlay.remove();
    }
  }


  // ──── Payload preview ──────────────────────────────────────────────
  //
  // Both sides are stored as the same encrypted blob format the server
  // uses. We try to decrypt readable fields so the user can compare,
  // but if decryption fails we show a "different ciphertext" hint.

  function describePayload(payload, _label) {
    // payload typically has .encrypted (base64) and .iv. The decrypted
    // content is JSON like { name, username, password, notes, ... }.
    // We can't decrypt synchronously here without more plumbing — this
    // is a synchronous renderer. We render whatever metadata we have
    // visible: type, folder_id, favorite, and an "encrypted content
    // differs" hint.

    const fields = [];
    const visible = ['type', 'folder_id', 'favorite'];
    for (const k of visible) {
      if (payload[k] !== undefined && payload[k] !== null) {
        fields.push(
          '<div class="field">' +
          '<span class="field-key">' + escHtml(k) + '</span>' +
          '<span class="field-val">' + escHtml(String(payload[k])) + '</span>' +
          '</div>'
        );
      }
    }
    if (payload.updated_at) {
      const ts = new Date(payload.updated_at).toLocaleString();
      fields.push(
        '<div class="field">' +
        '<span class="field-key">updated</span>' +
        '<span class="field-val">' + escHtml(ts) + '</span>' +
        '</div>'
      );
    }
    if (payload.encrypted_data || payload.data) {
      fields.push(
        '<div class="field" style="margin-top:6px;border-top:1px dashed var(--border,#3a3937);padding-top:8px">' +
        '<span class="field-val" style="color:var(--text-m,#888);font-style:italic;font-size:12px">' +
        'Encrypted content (' + (
          (payload.encrypted_data || payload.data).length || '?'
        ) + ' bytes)' +
        '</span></div>'
      );
    }

    if (fields.length === 0) {
      return '<div class="conflict-side-empty">Encrypted blob (no readable metadata)</div>';
    }
    return fields.join('');
  }


  // ──── Helpers ──────────────────────────────────────────────────────

  function escHtml(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g,
      c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'})[c]);
  }


  // ──── Polling tick ─────────────────────────────────────────────────

  async function tick() {
    const s = getState();
    if (!s || !s.token || !s.username) return;
    await refreshBanner();
    await decorateBadges();
  }

  // Refresh after sync events
  document.addEventListener('vk:reconnected', () => {
    setTimeout(() => { invalidateConflictCache(); tick(); }, 2000);
  });

  // Tick every 1s while the app is in foreground
  setInterval(tick, 1000);
  tick();


  // ──── Public surface ───────────────────────────────────────────────

  window.VK_OfflineConflicts = {
    refresh: () => { invalidateConflictCache(); return tick(); },
    open: openResolutionDialog,
  };
})();
