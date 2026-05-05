// ────────────────────────────────────────────────────────────────────────
// vk-webauthn-integration.js — passkey UI hooks for VaultKeeper.
//
// Pairs with vk-webauthn-client.js (low-level WebAuthn API wrapper) and
// vk-webauthn.js on the server. Wires three things into the existing app
// without modifying vk-app.js:
//
//   1. Lock-screen button — when a passkey is enrolled and we have a
//      hint for the user, hide the username/password form and show only
//      "Unlock with Passkey" + a small "Use master password instead"
//      link as an escape hatch. Auto-triggers the passkey prompt once
//      per session so iOS shows Face ID immediately.
//
//   2. Settings panel — adds a "Passkey" section to the Settings screen
//      with the list of enrolled devices, an Enable / Replace passkey
//      button, and a Remove button per device.
//
//   3. iOS conditional UI — arms a passive WebAuthn assertion so the
//      passkey shows up in iOS's autofill bar above the keyboard.
//
// Strategy: a 500ms polling tick that idempotently injects/updates the
// UI based on what's currently visible. The Settings screen is rendered
// dynamically into innerHTML, so re-injection is required on every nav.
// ────────────────────────────────────────────────────────────────────────

(function () {
  'use strict';

  // vk-app.js declares `state` and `showApp` at top level under strict
  // mode. They're visible across script tags but NOT attached to window.
  // These getters try the bare identifier first, then fall back to window.
  function getState() {
    try { if (typeof state !== 'undefined' && state) return state; } catch {}
    return window.state || null;
  }
  async function callShowApp() {
    try {
      if (typeof showApp !== 'undefined' && typeof showApp === 'function') {
        return await showApp();
      }
    } catch {}
    if (typeof window.showApp === 'function') return await window.showApp();
    throw new Error('showApp not accessible');
  }


  // Per-device hint of "this user has a passkey on this device". Just the
  // username — no secrets. Used to decide whether to show the passkey
  // button on the lock screen without round-tripping to the server first.
  const HINT_KEY = 'vk_webauthn_user';
  function getHint() {
    try { return localStorage.getItem(HINT_KEY) || null; } catch { return null; }
  }
  function setHint(u) {
    try {
      if (u) localStorage.setItem(HINT_KEY, u);
      else localStorage.removeItem(HINT_KEY);
    } catch {}
  }


  // Cache the platform-authenticator capability check so we don't hit it
  // every 500ms tick.
  let _platformAvail = null;
  async function platformAvailable() {
    if (_platformAvail !== null) return _platformAvail;
    try {
      _platformAvail = await window.VK_WebAuthn.isPlatformAuthenticatorAvailable();
    } catch {
      _platformAvail = false;
    }
    return _platformAvail;
  }


  // ──── Toast ────────────────────────────────────────────────────────

  function toast(msg, kind) {
    try {
      const stack = document.getElementById('toast-stack');
      if (stack) {
        const t = document.createElement('div');
        t.className = 'toast toast-' + (kind || 'info');
        t.textContent = msg;
        t.style.cssText =
          'background:var(--surface-2,#2a2826);color:var(--text,#fff);' +
          'padding:12px 16px;border-radius:8px;margin:8px;' +
          'box-shadow:0 4px 12px rgba(0,0,0,.3);max-width:90vw;';
        stack.appendChild(t);
        setTimeout(() => t.remove(), 3500);
        return;
      }
    } catch {}
    alert(msg);
  }


  // ──── Lock-screen button ───────────────────────────────────────────

  // Cache server-side passkey lookups by username so we don't ping the
  // server on every keystroke.
  const _serverChecks = new Map();
  async function checkServerHasPasskey(username) {
    if (_serverChecks.has(username)) return _serverChecks.get(username);
    try {
      const res = await fetch('/api/auth/webauthn/login-options', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username }),
      });
      const has = res.ok;
      _serverChecks.set(username, has);
      return has;
    } catch {
      _serverChecks.set(username, false);
      return false;
    }
  }


  // Tracks whether the user explicitly dismissed the passkey UI in
  // favor of the master-password form. While true, the polling tick
  // will not re-inject the passkey button, so the user's "Use master
  // password instead" choice sticks until they reload the page.
  let _userDismissedPasskey = false;

  async function injectLoginButton() {
    if (!window.VK_WebAuthn?.isSupported()) return;
    if (!await platformAvailable()) return;
    if (_userDismissedPasskey) return;  // user explicitly chose master pw

    // Don't inject if we're already authenticated. This protects against
    // the auth-screen briefly being visible during the post-unlock UI
    // transition, which would otherwise auto-fire the passkey prompt
    // immediately after a successful login.
    const s = getState();
    if (s && s.token) return;

    const loginForm = document.getElementById('login-form');
    if (!loginForm) return;
    if (document.getElementById('faceid-login-btn')) return;

    // Try the local hint first, then fall back to checking whatever the
    // username field currently has (typed or auto-filled by iOS)
    let username = getHint();
    if (!username) {
      const userInput = document.getElementById('login-username');
      const typed = userInput?.value?.trim();
      if (typed && typed.length >= 2 && await checkServerHasPasskey(typed)) {
        username = typed;
        setHint(typed);
      }
    }
    if (!username) return;

    const btn = document.createElement('button');
    btn.id = 'faceid-login-btn';
    btn.type = 'button';
    btn.className = 'btn btn-primary btn-lg btn-block';
    btn.style.cssText = 'margin-bottom:14px;display:flex;align-items:center;justify-content:center;gap:10px;font-weight:600;';
    btn.innerHTML =
      '<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="flex-shrink:0">' +
      '<path d="M3 7V5a2 2 0 0 1 2-2h2"></path>' +
      '<path d="M17 3h2a2 2 0 0 1 2 2v2"></path>' +
      '<path d="M21 17v2a2 2 0 0 1-2 2h-2"></path>' +
      '<path d="M7 21H5a2 2 0 0 1-2-2v-2"></path>' +
      '<path d="M8 11v.01"></path>' +
      '<path d="M16 11v.01"></path>' +
      '<path d="M9 16a4 4 0 0 0 6 0"></path></svg>' +
      '<span>Unlock with Passkey (' + escapeHtml(username) + ')</span>';
    btn.addEventListener('click', () => doPasskeyLogin(username, btn));
    loginForm.insertBefore(btn, loginForm.firstChild);

    // Hide the username/password form fields. Clicking "Use master
    // password instead" reveals them again AND latches the dismissal
    // so the polling tick stops re-injecting.
    hidePasswordForm(loginForm);

    const fallback = document.createElement('button');
    fallback.id = 'faceid-fallback-link';
    fallback.type = 'button';
    fallback.style.cssText =
      'background:none;border:none;color:var(--text-f,#888);' +
      'font-size:13px;text-decoration:underline;cursor:pointer;' +
      'display:block;margin:0 auto 14px;padding:8px;';
    fallback.textContent = 'Use master password instead';
    fallback.addEventListener('click', () => {
      _userDismissedPasskey = true;     // stop re-injection on next tick
      // Abort any in-flight conditional UI so a passkey prompt can't
      // pop up while the user types their master password
      if (_conditionalArmed) {
        try { window.VK_WebAuthn.abortConditionalUI?.(); } catch {}
        _conditionalArmed = false;
      }
      showPasswordForm(loginForm);
      btn.remove();
      fallback.remove();
      // Focus the username field for immediate typing
      setTimeout(() => {
        document.getElementById('login-username')?.focus();
      }, 50);
    });
    loginForm.insertBefore(fallback, btn.nextSibling);

    // Auto-trigger the passkey prompt once per username per session so
    // iOS shows Face ID immediately. Tracked across this page lifetime
    // so cancel-and-retry doesn't loop.
    if (!_autoTriggered.has(username)) {
      _autoTriggered.add(username);
      setTimeout(() => {
        // Bail if anything has changed by the time the timer fires —
        // user may have logged in another way, dismissed passkey, or the
        // button might have been removed.
        const s = getState();
        if (s && s.token) return;
        if (_userDismissedPasskey) return;
        if (!document.body.contains(btn)) return;
        if (btn.disabled) return;
        doPasskeyLogin(username, btn);
      }, 300);
    }
  }
  const _autoTriggered = new Set();


  // Hide the form-group divs and submit button. We mark them with a
  // data attribute rather than removing them so we can put them back if
  // the user clicks "Use master password instead".
  function hidePasswordForm(loginForm) {
    const elements = loginForm.querySelectorAll(
      '.form-group, button[type="submit"]'
    );
    for (const el of elements) {
      if (el.id === 'faceid-login-btn' ||
          el.id === 'faceid-fallback-link') continue;
      el.dataset.faceidHidden = '1';
      el.style.display = 'none';
    }
  }
  function showPasswordForm(loginForm) {
    const elements = loginForm.querySelectorAll('[data-faceid-hidden="1"]');
    for (const el of elements) {
      el.style.display = '';
      delete el.dataset.faceidHidden;
    }
  }

  // Tears down the passkey UI and restores the master password form.
  // Called when we detect we've gone offline so the user can sign in
  // against the local cache without fighting a re-injection loop.
  function removePasskeyUI() {
    const btn = document.getElementById('faceid-login-btn');
    const fallback = document.getElementById('faceid-fallback-link');
    const loginForm = document.getElementById('login-form');
    if (btn) btn.remove();
    if (fallback) fallback.remove();
    if (loginForm) showPasswordForm(loginForm);
  }


  // Re-entry guard: prevents two passkey prompts from chasing each other
  // (e.g. button click + auto-trigger setTimeout firing within 300ms).
  let _loginInProgress = false;

  async function doPasskeyLogin(username, btn) {
    // Already authenticated? Don't re-prompt.
    const sBefore = getState();
    if (sBefore && sBefore.token) return;
    if (_loginInProgress) return;
    _loginInProgress = true;

    if (btn) {
      btn.disabled = true;
      const sp = btn.querySelector('span');
      if (sp) sp.textContent = 'Authenticating…';
    }
    try {
      const { token, symKey } = await window.VK_WebAuthn.unlock({ username });
      const s = getState();
      if (!s) throw new Error('app_state_unavailable');

      // Race protection: if something else already populated state.token
      // while our prompt was up, drop our result rather than racing.
      if (s.token) return;

      s.token = token;
      s.username = username;
      s.symKey = new Uint8Array(symKey);

      try {
        await callShowApp();
      } catch (uiErr) {
        toast('Unlocked but UI failed: ' + uiErr.message, 'error');
      }
    } catch (err) {
      const msg = String(err.message || err);
      // Silent on user cancel
      if (msg.includes('cancelled') || msg.includes('NotAllowed')) {
        // user cancelled — say nothing
      } else if (msg.includes('no_passkeys')) {
        setHint(null);
        toast('No passkey enrolled for this user. Use master password.', 'error');
        if (btn) btn.remove();
        document.getElementById('faceid-fallback-link')?.click();
      } else if (
        // Network-class errors: passkey requires the server, but the
        // user can still sign in with their master password against
        // the local offline cache. Reveal the form, latch the dismiss
        // so the polling tick doesn't put the passkey button back, and
        // tell the user what to do next.
        msg.includes('Failed to fetch') ||
        msg.includes('failed to load') ||
        msg.includes('NetworkError') ||
        msg.includes('Network request failed') ||
        msg.includes('Load failed')
      ) {
        _userDismissedPasskey = true;
        removePasskeyUI();
        toast('Passkey needs internet. Sign in with your master password.', 'info');
        setTimeout(() => {
          document.getElementById('login-username')?.focus();
        }, 80);
      } else {
        toast('Passkey failed: ' + msg, 'error');
      }
    } finally {
      _loginInProgress = false;
      if (btn && document.body.contains(btn)) {
        btn.disabled = false;
        const sp = btn.querySelector('span');
        if (sp) sp.textContent = 'Unlock with Passkey (' + username + ')';
      }
    }
  }


  // ──── iOS Conditional UI / passkey autofill ────────────────────────

  // Arms a passive WebAuthn assertion. When user taps a field with
  // autocomplete that includes "webauthn", iOS shows a passkey suggestion
  // in the autofill bar above the keyboard. Selecting it triggers Face ID.

  let _conditionalArmed = false;
  async function armConditionalUI() {
    if (_conditionalArmed) return;
    if (!window.VK_WebAuthn?.startConditionalUI) return;
    if (!await platformAvailable()) return;

    // Don't arm conditional UI if we're already logged in. If a previous
    // arm is still in-flight when login succeeds, the resolved assertion
    // would otherwise re-trigger the unlock flow over the live session.
    const sBefore = getState();
    if (sBefore && sBefore.token) return;

    _conditionalArmed = true;

    try {
      const result = await window.VK_WebAuthn.startConditionalUI();
      if (!result) {
        _conditionalArmed = false;
        return;
      }

      // Re-check token AFTER the assertion resolves. If the user has
      // since logged in by another means (master password), drop the
      // assertion result on the floor instead of re-running showApp().
      const s = getState();
      if (!s) {
        toast('App not ready, tap the Passkey button', 'warn');
        return;
      }
      if (s.token) {
        // Already logged in via another path — discard.
        return;
      }
      s.token = result.token;
      s.username = result.username;
      s.symKey = new Uint8Array(result.symKey);
      setHint(result.username);

      try {
        await callShowApp();
      } catch (uiErr) {
        toast('Unlocked but UI failed: ' + uiErr.message, 'error');
      }
    } catch {
      _conditionalArmed = false;
    }
  }


  // Re-check passkey-availability for the username field on each input —
  // injects the button when iOS autofill or manual typing reveals a
  // username with an enrolled passkey.
  function watchUsernameField() {
    const input = document.getElementById('login-username');
    if (!input || input.dataset.faceidWatch) return;
    input.dataset.faceidWatch = '1';
    let timer = null;
    const onChange = () => {
      clearTimeout(timer);
      timer = setTimeout(() => { injectLoginButton().catch(() => {}); }, 400);
    };
    input.addEventListener('input', onChange);
    input.addEventListener('change', onChange);
    input.addEventListener('blur', onChange);
  }


  // ──── Settings panel ───────────────────────────────────────────────

  function findSettingsContainer() {
    // The Settings screen is recognized by a .list-title with text "Settings"
    const titles = document.querySelectorAll('.list-title');
    for (const t of titles) {
      if (t.textContent.trim() === 'Settings') {
        const main = document.getElementById('main-pane');
        if (!main) return null;
        const content = main.querySelector(
          'div[style*="max-width:600px"], div[style*="max-width: 600px"]'
        );
        return content || main;
      }
    }
    return null;
  }

  async function injectSettingsPanel() {
    if (!window.VK_WebAuthn?.isSupported()) return;
    if (!await platformAvailable()) return;
    if (!getState()?.token) return;

    const container = findSettingsContainer();
    if (!container) return;
    if (container.querySelector('#faceid-settings-panel')) return;

    const panel = document.createElement('div');
    panel.id = 'faceid-settings-panel';
    panel.className = 'health-section';
    panel.innerHTML =
      '<div class="health-section-title">Passkey</div>' +
      '<p class="form-hint" style="margin-top:0">' +
      'Sign in and auto-unlock with a passkey (Face ID, Touch ID, or Windows Hello). ' +
      'The encrypted vault key is stored on the server, but only your passkey can decrypt it (zero-knowledge).' +
      '</p>' +
      '<div id="faceid-status" style="margin:12px 0;font-size:13px;color:var(--text-f,#888);">Loading…</div>' +
      '<div id="faceid-device-list" style="display:flex;flex-direction:column;gap:8px;margin-bottom:12px;"></div>' +
      '<button class="btn btn-primary" id="faceid-enroll-btn" type="button">Enable Passkey</button>';

    // Position right after the "Master password" section
    const masterPwBtn = container.querySelector('#btn-change-pw');
    const masterPwSection = masterPwBtn ? masterPwBtn.closest('.health-section') : null;
    if (masterPwSection && masterPwSection.parentNode === container) {
      masterPwSection.insertAdjacentElement('afterend', panel);
    } else {
      container.appendChild(panel);
    }

    document.getElementById('faceid-enroll-btn').addEventListener('click', enrollPasskey);
    refreshDeviceList();
  }

  async function refreshDeviceList() {
    const list = document.getElementById('faceid-device-list');
    const status = document.getElementById('faceid-status');
    const enrollBtn = document.getElementById('faceid-enroll-btn');
    if (!list || !getState()?.token) return;

    try {
      const creds = await window.VK_WebAuthn.list({ token: getState().token });
      list.innerHTML = '';
      if (!creds || creds.length === 0) {
        if (status) status.textContent = 'No passkey enrolled yet.';
        if (enrollBtn) enrollBtn.textContent = 'Enable Passkey';
        return;
      }
      if (status) status.textContent = creds.length + ' device(s) enrolled:';
      if (enrollBtn) enrollBtn.textContent = 'Replace passkey';

      for (const c of creds) {
        const row = document.createElement('div');
        row.style.cssText =
          'display:flex;align-items:center;justify-content:space-between;' +
          'padding:10px 12px;background:var(--surface,#181716);' +
          'border:1px solid var(--divider,#2e2b29);border-radius:8px;';
        const lastUsed = c.last_used_at
          ? new Date(c.last_used_at).toLocaleDateString()
          : 'never';
        row.innerHTML =
          '<div style="flex:1;min-width:0;">' +
          '<div style="font-size:13px;font-weight:500;">' +
          escapeHtml(c.device_name || 'Device') + '</div>' +
          '<div style="font-size:11px;color:var(--text-f,#888);margin-top:2px;">' +
          'Added ' + new Date(c.created_at).toLocaleDateString() +
          ' · Last used ' + lastUsed + '</div></div>' +
          '<button type="button" class="btn btn-ghost" ' +
          'style="padding:6px 10px;font-size:12px;color:var(--danger,#e55);" ' +
          'data-cred="' + escapeAttr(c.credential_id) + '">Remove</button>';
        row.querySelector('[data-cred]').addEventListener('click', async (e) => {
          const credId = e.currentTarget.getAttribute('data-cred');
          if (!confirm('Remove this passkey?')) return;
          try {
            await window.VK_WebAuthn.remove({
              token: getState().token, credentialId: credId,
            });
            const remaining = await window.VK_WebAuthn.list({ token: getState().token });
            if (!remaining || remaining.length === 0) setHint(null);
            await refreshDeviceList();
            toast('Passkey removed', 'success');
          } catch (err) {
            toast('Failed to remove: ' + err.message, 'error');
          }
        });
        list.appendChild(row);
      }
    } catch {
      if (status) {
        status.textContent = 'Failed to load passkey devices.';
        status.style.color = 'var(--danger,#e55)';
      }
    }
  }

  async function enrollPasskey() {
    const s = getState();
    if (!s?.token || !s?.symKey || !s?.username) {
      toast('Please unlock your vault first.', 'error');
      return;
    }
    const btn = document.getElementById('faceid-enroll-btn');

    // If a passkey is already enrolled, confirm + remove it first
    let replacing = false;
    try {
      const existing = await window.VK_WebAuthn.list({ token: s.token });
      if (existing && existing.length > 0) {
        const ok = confirm(
          'A passkey is already enrolled (' +
          existing.map(c => c.device_name || 'Device').join(', ') +
          ').\n\nReplace it with a new one on this device?'
        );
        if (!ok) return;
        replacing = true;
      }
    } catch {}

    if (btn) {
      btn.disabled = true;
      btn.textContent = 'Creating passkey…';
    }
    try {
      if (replacing) {
        try {
          const all = await window.VK_WebAuthn.list({ token: s.token });
          for (const c of (all || [])) {
            await window.VK_WebAuthn.remove({
              token: s.token,
              credentialId: c.credential_id,
            });
          }
        } catch {}
      }

      await window.VK_WebAuthn.enroll({
        token: s.token,
        symKey: s.symKey,
        deviceName: guessDeviceName(),
      });
      setHint(s.username);
      toast(replacing ? 'Passkey replaced' : 'Passkey enabled', 'success');
      await refreshDeviceList();
    } catch (err) {
      const msg = String(err.message || err);
      if (msg.includes('cancelled') || msg.includes('NotAllowed')) {
        // silent
      } else if (msg.includes('prf_not_supported')) {
        toast('Device does not support passkey PRF (requires iOS 18+ or modern Android/Windows).', 'error');
      } else {
        toast('Enrollment failed: ' + msg, 'error');
      }
    } finally {
      if (btn) {
        btn.disabled = false;
        const list = document.getElementById('faceid-device-list');
        btn.textContent = list && list.children.length > 0
          ? 'Replace passkey' : 'Enable Passkey';
      }
    }
  }

  function guessDeviceName() {
    const ua = navigator.userAgent || '';
    if (/iPhone/i.test(ua)) return 'iPhone';
    if (/iPad/i.test(ua)) return 'iPad';
    if (/Mac/i.test(ua)) return 'Mac';
    if (/Android/i.test(ua)) return 'Android';
    if (/Windows/i.test(ua)) return 'Windows';
    return 'Device';
  }


  // ──── Helpers ──────────────────────────────────────────────────────

  function escapeHtml(s) {
    return String(s || '').replace(/[&<>"']/g, c => ({
      '&': '&amp;', '<': '&lt;', '>': '&gt;',
      '"': '&quot;', "'": '&#39;',
    })[c]);
  }
  function escapeAttr(s) { return escapeHtml(s); }


  // ──── Polling tick ─────────────────────────────────────────────────

  // Track the last time we observed the server reachable. If we haven't
  // seen a successful response in the last few seconds, we assume the
  // network is unavailable and skip passkey attempts (which would just
  // fail with "failed to load"). The app's own api() helper sets this
  // when it succeeds; we also probe lazily below.
  let _lastNetSuccessAt = 0;
  let _lastNetProbeAt = 0;
  const NET_FRESH_MS = 8000;     // consider "online" if recent success
  const PROBE_INTERVAL = 5000;   // probe at most every 5s

  async function isNetworkAvailable() {
    if (Date.now() - _lastNetSuccessAt < NET_FRESH_MS) return true;
    // navigator.onLine returning false is reliable; returning true is not.
    if (navigator.onLine === false) return false;
    const s = getState();
    if (s && s.offline) return false;
    // Probe sparingly
    const now = Date.now();
    if (now - _lastNetProbeAt < PROBE_INTERVAL) return false;
    _lastNetProbeAt = now;
    try {
      const ctrl = new AbortController();
      const t = setTimeout(() => ctrl.abort(), 2500);
      const res = await fetch('/healthz', {
        signal: ctrl.signal, cache: 'no-store', method: 'GET',
      });
      clearTimeout(t);
      if (res.ok) {
        _lastNetSuccessAt = Date.now();
        return true;
      }
      return false;
    } catch {
      return false;
    }
  }

  async function tick() {
    if (!window.VK_WebAuthn || !window.VK_WebAuthn.isSupported()) return;
    if (!await platformAvailable()) return;

    // If we're offline, the passkey login server endpoint is unreachable
    // and any attempt will fail with "failed to load". Don't bother
    // trying — let the user fall back to the master password form which
    // works fully offline against the local cache.
    const online = await isNetworkAvailable();
    if (!online) {
      // If we previously injected the passkey button but lost network,
      // remove it so the master password form is usable. Don't latch
      // _userDismissedPasskey here — when network returns, we want
      // passkey back as an option.
      removePasskeyUI();
      return;
    }

    const auth = document.getElementById('auth-screen');
    const authVisible = auth && !auth.classList.contains('hidden')
      && getComputedStyle(auth).display !== 'none';
    if (authVisible) {
      // Don't inject the passkey UI if the user explicitly dismissed it
      if (_userDismissedPasskey) return;
      // Don't inject if we're already authenticated (auth-screen may
      // briefly flicker visible during the post-unlock UI transition).
      const s = getState();
      if (s && s.token) {
        removePasskeyUI();
        if (_conditionalArmed) {
          try { window.VK_WebAuthn.abortConditionalUI?.(); } catch {}
          _conditionalArmed = false;
        }
        return;
      }
      watchUsernameField();
      injectLoginButton();
      armConditionalUI();
      return;
    }

    // Auth screen not visible. Make sure lingering passkey UI and any
    // armed conditional assertion are torn down so they can't re-fire
    // after a successful login.
    removePasskeyUI();
    if (_conditionalArmed) {
      try { window.VK_WebAuthn.abortConditionalUI?.(); } catch {}
      _conditionalArmed = false;
    }
    if (!getState()?.token) return;

    if (findSettingsContainer()) {
      await injectSettingsPanel();
    }
  }

  function start() {
    setInterval(tick, 500);
    tick();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', start);
  } else {
    start();
  }

  // Public surface (for advanced use / debugging from console)
  window.VK_WebAuthnUI = {
    setHint, getHint,
    refreshDeviceList,
  };
})();
