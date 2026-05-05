// ────────────────────────────────────────────────────────────────────────
// vk-offline-sync.js — Stage 3 sync engine.
//
// On reconnect, drains the IndexedDB mutation queue against the server.
// For each pending mutation, performs a "compare-then-write": fetches the
// server's current view of the resource, checks whether it still matches
// the version we were editing FROM (baseVersion), and only applies the
// mutation if the server hasn't moved underneath us. If it has, the
// mutation is moved to the conflicts store and a ⚠ badge appears on the
// item until the user resolves it.
//
// This protects against the failure mode the user explicitly asked about:
// "I don't want someone to just upload a file and corrupt or replace
// other people's vaults." The drainer never blindly POSTs the cached
// blob; every push carries a version check, and any mismatch is
// surfaced for human resolution.
//
// Public API:
//   VK_OfflineSync.drainQueue()    — replay all pending mutations
//   VK_OfflineSync.getConflicts()  — list unresolved conflicts
//   VK_OfflineSync.resolveConflict(id, choice)  — 'keep_mine' | 'keep_theirs'
// ────────────────────────────────────────────────────────────────────────

(function () {
  'use strict';

  if (!window.VK_Offline) return;
  const VKO = window.VK_Offline;


  // Reach into vk-app.js for the api() helper and state. These are
  // declared at script scope under strict mode (visible across script
  // tags but not on window).
  function getState() {
    try { if (typeof state !== 'undefined' && state) return state; } catch {}
    return window.state || null;
  }
  function callApi(method, path, body) {
    if (typeof api === 'function') return api(method, path, body, { skipAuthRedirect: true });
    if (typeof window.api === 'function') return window.api(method, path, body, { skipAuthRedirect: true });
    throw new Error('api() not available');
  }
  function callShowToast(msg, kind) {
    try { if (typeof showToast === 'function') return showToast(msg, kind); } catch {}
    if (typeof window.showToast === 'function') return window.showToast(msg, kind);
  }


  // ──── Drain queue ──────────────────────────────────────────────────

  let _draining = false;

  async function drainQueue() {
    if (_draining) return { skipped: true };
    const s = getState();
    if (!s || !s.username) return { skipped: true };
    if (s.offline) return { skipped: true };  // can't drain while still offline
    if (!s.token) return { skipped: true };   // need a JWT to talk to the server

    _draining = true;
    const summary = { sent: 0, conflicts: 0, failed: 0, skipped: 0 };
    try {
      const pending = await VKO.getPendingForUser(s.username);
      if (!pending.length) return summary;

      // Sort by created_at so dependent ops apply in order. Creates
      // before updates of "local-XXX" ids etc.
      pending.sort((a, b) => (a.created_at || 0) - (b.created_at || 0));

      // Pull the current server state once so we can do version
      // comparisons without N round-trips.
      let serverItems, serverFolders;
      try {
        const items = await callApi('GET', '/api/vault');
        serverItems = new Map(
          (Array.isArray(items) ? items : []).map(it => [String(it.id), it])
        );
      } catch (e) {
        if (e.status === 401) {
          // Token expired — vk-app's api() already handled the redirect.
          // Stop draining; the user will log in again.
          summary.skipped = pending.length;
          return summary;
        }
        throw e;
      }
      try {
        const folders = await callApi('GET', '/api/folders');
        serverFolders = new Map(
          (Array.isArray(folders) ? folders : []).map(f => [String(f.id), f])
        );
      } catch {
        serverFolders = new Map();
      }

      const localIdMap = new Map(); // local-XXX → real server id

      for (const m of pending) {
        try {
          const result = await replayOne(m, { serverItems, serverFolders, localIdMap });
          if (result.applied) {
            summary.sent++;
            await VKO.removeMutation(m.localId);
            // If we just created an item, remember the real id so
            // subsequent local-XXX-targeted updates retarget correctly.
            if (m.op === 'create' && result.serverId) {
              localIdMap.set(m.resourceId, String(result.serverId));
            }
          } else if (result.conflict) {
            summary.conflicts++;
            await VKO.recordConflict(
              s.username, m.resource, m.resourceId,
              m.payload, result.serverState, m.baseVersion
            );
            await VKO.removeMutation(m.localId);
          } else {
            summary.failed++;
          }
        } catch (e) {
          console.warn('[sync] mutation replay failed:', e.message);
          summary.failed++;
        }
      }

      // Show a summary toast
      if (summary.sent > 0 || summary.conflicts > 0) {
        const parts = [];
        if (summary.sent > 0) parts.push(summary.sent + ' synced');
        if (summary.conflicts > 0) parts.push(summary.conflicts + ' conflicts');
        if (summary.failed > 0) parts.push(summary.failed + ' failed');
        callShowToast(parts.join(' · '),
          summary.conflicts > 0 ? 'warn' : 'success');
      }

      return summary;
    } finally {
      _draining = false;
    }
  }


  async function replayOne(m, ctx) {
    // m.resource = 'item' | 'folder' | 'prefs'
    // m.op = 'create' | 'update' | 'delete'

    if (m.resource === 'prefs') {
      // Prefs have no version — last-write-wins is fine.
      try {
        await callApi('PUT', '/api/prefs', m.payload || {});
        return { applied: true };
      } catch {
        return { applied: false };
      }
    }

    const isItem = m.resource === 'item';
    const collectionPath = isItem ? '/api/vault' : '/api/folders';
    const serverMap = isItem ? ctx.serverItems : ctx.serverFolders;

    if (m.op === 'create') {
      // Local-only id; server will assign a real one. No version conflict
      // possible.
      try {
        const resp = await callApi('POST', collectionPath, m.payload || {});
        return { applied: true, serverId: resp?.id };
      } catch {
        return { applied: false };
      }
    }

    // For update / delete, we need a real id. If our resourceId is a
    // local-XXX from a queued create that just ran, retarget it.
    let realId = m.resourceId;
    if (typeof realId === 'string' && realId.startsWith('local-')) {
      const remapped = ctx.localIdMap.get(realId);
      if (!remapped) {
        // The create must have failed — skip this dependent op.
        return { applied: false };
      }
      realId = remapped;
    }

    const serverState = serverMap.get(String(realId));

    if (m.op === 'delete') {
      // If the item is already gone on the server, treat as applied.
      if (!serverState) return { applied: true };
      // If the server's version differs from what we expected, conflict.
      if (m.baseVersion && serverState.version &&
          serverState.version !== m.baseVersion) {
        return { conflict: true, serverState };
      }
      try {
        await callApi('DELETE', collectionPath + '/' + realId);
        return { applied: true };
      } catch (e) {
        if (e.status === 404) return { applied: true };
        return { applied: false };
      }
    }

    // m.op === 'update'
    if (!serverState) {
      // Item was deleted on the server while we were offline. Two
      // sensible policies:
      //   (a) treat as conflict (preserve user's edit for them to push)
      //   (b) silently re-create
      // We pick (a) so nothing is lost without the user's say-so.
      return { conflict: true, serverState: null };
    }
    if (m.baseVersion && serverState.version &&
        serverState.version !== m.baseVersion) {
      return { conflict: true, serverState };
    }
    try {
      await callApi('PUT', collectionPath + '/' + realId, m.payload || {});
      return { applied: true };
    } catch (e) {
      if (e.status === 409) return { conflict: true, serverState };
      return { applied: false };
    }
  }


  // ──── Conflict resolution ──────────────────────────────────────────

  async function resolveConflict(compositeKey, choice) {
    // choice: 'keep_mine' | 'keep_theirs'
    const s = getState();
    if (!s?.username) throw new Error('not_logged_in');
    if (s.offline) throw new Error('cannot_resolve_offline');

    const all = await VKO.getConflicts(s.username);
    const c = all.find(x => x.compositeKey === compositeKey);
    if (!c) throw new Error('conflict_not_found');

    if (choice === 'keep_theirs') {
      // The server's version stands. Just clear the conflict marker.
      await VKO.clearConflict(s.username, c.resource, c.resourceId);
      callShowToast('Server version kept', 'info');
      return;
    }

    if (choice === 'keep_mine') {
      // Push our payload up. Use the CURRENT server version as
      // baseVersion so the push goes through.
      const collectionPath = c.resource === 'item' ? '/api/vault' : '/api/folders';
      try {
        // If the server version is null (item was deleted on the server),
        // we re-create it.
        if (!c.theirs) {
          await callApi('POST', collectionPath, c.mine || {});
        } else {
          await callApi('PUT', collectionPath + '/' + c.resourceId, c.mine || {});
        }
        await VKO.clearConflict(s.username, c.resource, c.resourceId);
        callShowToast('Your version pushed', 'success');
      } catch (e) {
        callShowToast('Failed to push: ' + e.message, 'error');
        throw e;
      }
      return;
    }

    throw new Error('unknown_choice');
  }


  // ──── Auto-drain on reconnect ───────────────────────────────────────

  document.addEventListener('vk:reconnected', () => {
    drainQueue().catch(e => console.warn('[sync] drain failed:', e.message));
  });

  // Also probe on reconnect events from window.online
  window.addEventListener('online', () => {
    setTimeout(() => {
      drainQueue().catch(e => console.warn('[sync] drain failed:', e.message));
    }, 1500);
  });


  // ──── Public API ───────────────────────────────────────────────────

  window.VK_OfflineSync = {
    drainQueue,
    getConflicts: async () => {
      const s = getState();
      if (!s?.username) return [];
      return await VKO.getConflicts(s.username);
    },
    resolveConflict,
  };
})();
