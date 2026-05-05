# VaultKeeper

Self-hosted, end-to-end-encrypted password manager with passkey support.

**Zero-knowledge**: your master password and vault contents never leave
the device unencrypted. The server stores ciphertext only and cannot
decrypt anything, even with full database access.

**Passkey unlock**: enroll a Face ID / Touch ID / Windows Hello passkey
to sign in without typing your master password. The vault key is wrapped
under a secret derived from the passkey's PRF output, so the server
still can't decrypt anything — only your authenticated device can.

---

## Quick start

```bash
# 1. Clone or extract this directory
cd vaultkeeper

# 2. Generate three secrets — keep these safe
openssl rand -base64 48   # → JWT_SECRET
openssl rand -base64 48   # → PRELOGIN_SECRET
openssl rand -base64 24   # → PGPASSWORD (any strong password)

# 3. Edit docker-compose.yml — replace four REPLACE_ME values:
#       JWT_SECRET
#       PRELOGIN_SECRET
#       PGPASSWORD          (must match between services!)
#       WEBAUTHN_RP_ID      (your public hostname, no scheme)
#       WEBAUTHN_ORIGIN     (https:// + hostname)
nano docker-compose.yml

# 4. Build and start
docker compose up -d --build

# 5. Watch logs to confirm clean start
docker compose logs --follow vaultkeeper
# Look for: [START] VaultKeeper E2E server listening on HTTP :3333
```

The container speaks plain HTTP on port 3333. **Always put a TLS-
terminating reverse proxy in front** (Cloudflare Tunnel, Caddy, nginx,
Traefik, etc.). Browsers refuse WebAuthn / passkeys over plain HTTP
except on `localhost`.

---

## Reverse proxy examples

### Cloudflare Tunnel
Create a tunnel pointing public hostname → `http://<container-host-ip>:3333`.
Cloudflare terminates TLS and forwards plaintext to your network.

### Caddy

```caddy
vault.example.com {
    reverse_proxy localhost:3333
}
```

### nginx

```nginx
server {
    listen 443 ssl http2;
    server_name vault.example.com;
    ssl_certificate     /etc/letsencrypt/live/vault.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/vault.example.com/privkey.pem;

    location / {
        proxy_pass http://localhost:3333;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

Whatever proxy you use, the `Host:` header forwarded to VaultKeeper must
match `WEBAUTHN_RP_ID`, and the public scheme/host must match
`WEBAUTHN_ORIGIN`. Mismatches will cause passkey verification failures
with `rpid_mismatch` or `origin_mismatch` errors.

---

## Configuration reference

All configuration is via environment variables in `docker-compose.yml`.

| Variable | Required | Description |
|---|---|---|
| `JWT_SECRET` | yes | Signs session JWTs. ≥32 random bytes. |
| `PRELOGIN_SECRET` | yes | Defends against user-enumeration timing attacks. ≥32 random bytes. |
| `PGPASSWORD` | yes | Postgres password. Must match `POSTGRES_PASSWORD` on the db service. |
| `WEBAUTHN_RP_ID` | yes for passkeys | Bare hostname users access. No scheme, no port. e.g. `vault.example.com`. |
| `WEBAUTHN_ORIGIN` | yes for passkeys | Full origin URL. e.g. `https://vault.example.com`. |
| `WEBAUTHN_RP_NAME` | no | Display name in Face ID prompts. Defaults to "VaultKeeper". |
| `PORT` | no | HTTP listen port. Default `3333`. |
| `PGHOST` | no | Postgres host. Default `db`. |
| `PGPORT` | no | Postgres port. Default `5432`. |
| `PGDATABASE` | no | Database name. Default `vaultkeeper`. |
| `PGUSER` | no | Database user. Default `vault`. |
| `DROP_AND_RECREATE` | no | Set to `yes-I-am-sure` to wipe + recreate schema on next start. **Destroys all data.** Remove after first run. |

---

## First user

The first time you visit the app, click **Sign up**, choose a username and
master password (≥12 characters). The first registered user is the
account; there's no separate admin/registration UI. If you want multi-
user, every user signs up the same way through the regular UI — there's
no per-account isolation beyond their own crypto.

---

## Enabling passkeys (Face ID / Touch ID / Hello)

After signing in with your master password the first time:

1. Open **Settings**
2. Find the **Passkey** section
3. Tap **Enable Passkey**
4. Confirm the prompt from your OS (Face ID, Touch ID, Windows Hello, etc.)
5. Done. Lock the vault and you'll see "Unlock with Passkey" on the login screen.

On iOS, the passkey is also offered through the autofill bar above the
keyboard. On other platforms, you'll see your enrolled passkey listed
when navigator.credentials.get() runs.

**Requirements**:
- iOS 17+ (PRF extension support)
- Recent macOS / Windows / Android with platform authenticator
- HTTPS (passkeys don't work over plain HTTP)

---

## Architecture

VaultKeeper is a single Node.js + Express service backed by Postgres.

```
                                 ┌──────────────────┐
                                 │  Browser / PWA   │
                                 │ (E2E crypto      │
                                 │  in Web Worker)  │
                                 └────────┬─────────┘
                                          │ HTTPS
                                          ▼
                                 ┌──────────────────┐
                                 │ Reverse Proxy    │
                                 │ (TLS termination)│
                                 └────────┬─────────┘
                                          │ HTTP
                                          ▼
       ┌──────────────────┐      ┌──────────────────┐
       │ Postgres 16      │◄─────┤ vaultkeeper      │
       │ (encrypted blobs)│      │ (Node 20)        │
       └──────────────────┘      └──────────────────┘
```

**Crypto** (all in browser):

```
master password + username
         │
         ▼  argon2id (256MB, t=3, p=1)
    masterKey (32B)
         │
         ▼  HKDF
    stretchedEnc + stretchedMac
         │                │
         ▼                ▼
    AES-256-GCM         HMAC-SHA256
    wrap/unwrap         authenticate
         │                │
         └────────────────┘
                 │
                 ▼
          symKey (64B random)
                 │
                 ▼
          Per-item AES-GCM + HMAC
```

The server only ever stores:
- argon2id salt (per user)
- wrapped symKey (encrypted with stretched keys)
- per-item ciphertext + HMAC

Never plaintext. Never the master password. Never derived keys.

**Passkey unlock crypto** (when enabled):
- WebAuthn passkey + PRF extension produces a stable 32-byte secret
- HKDF that secret → DEK
- DEK encrypts symKey → encrypted blob stored on server
- On unlock: passkey's PRF output regenerates DEK → decrypts blob → symKey
- Server never sees the PRF output. Passkey can't be exfiltrated from the
  device's secure hardware. Both are required.

---

## File layout

```
vaultkeeper/
├── docker-compose.yml      ← edit this (secrets + passkey domain)
├── Dockerfile              ← container build instructions
├── package.json            ← npm dependencies
├── server.js               ← main HTTP server (~1300 lines)
├── vk-webauthn.js          ← passkey routes + verification (~640 lines)
├── public/                 ← static assets, served as-is
│   ├── index.html          ← single-page app shell
│   ├── manifest.json       ← PWA manifest
│   ├── apple-touch-icon.png
│   ├── icon-192.png
│   ├── icon-512.png
│   ├── vk-app.js           ← main app logic (~3200 lines)
│   ├── vk-crypto.js        ← E2E crypto wrapper
│   ├── vk-crypto-worker.js ← Web Worker for argon2id
│   ├── vk-import.js        ← Bitwarden / 1Password / LastPass importer
│   ├── vk-webauthn-client.js     ← passkey client
│   ├── vk-webauthn-integration.js← passkey UI hooks
│   ├── vk-offline.js             ← IndexedDB cache, mutation queue
│   ├── vk-offline-sync.js        ← reconnect drainer + conflict detection
│   ├── vk-offline-conflicts.js   ← conflict UI (badges + resolution)
│   ├── vk-sw.js                  ← service worker (offline shell)
│   └── vendor/             ← hash-wasm + lucide (see vendor/README.md)
└── tests/                  ← API + crypto test suites
    ├── api-test.js
    └── crypto-test.html
```

---

## Offline mode

VaultKeeper works fully offline once you've successfully logged in at
least once on the device.

**What works offline**:
- The whole app loads with no network — Service Worker caches the shell.
- Sign in with your master password against the cached vault metadata.
- View, search, copy any item.
- Add, edit, delete items / folders / favorites — changes queue locally.
- Generate passwords, view 2FA codes, browse vault health.

**What doesn't work offline**:
- Initial sign-up / first login on a device.
- Changing master password (must reach the server in one transaction).
- Enrolling or removing passkeys.
- Account deletion.

**Sync on reconnect**:
- Queued mutations replay automatically when network returns.
- For each one, the client fetches the server's current version first.
  If the server moved underneath the offline edit (another device
  changed the same item), the mutation is held as a **conflict**
  rather than overwriting blindly.
- Conflicts surface as a ⚠ badge on the affected item plus a top
  banner. Tap to resolve: keep yours, keep server's, or decide later.

**Cache TTL**:
- Default 7 days. Configurable in Settings → Offline cache (1–90 days).
- After expiry, the device must reconnect and log in again.
- Cache is cleared on explicit logout, or on demand from Settings.

---

## Vendor dependencies

The `public/vendor/` directory needs two files that aren't bundled:
- `hash-wasm.umd.min.js` — argon2id implementation (216,086 bytes)
- `lucide.js` — icon library

Get them by following `public/vendor/README.md`. Without these, the app
won't load.

---

## Updating

To pull in newer code without losing your data:

```bash
# Replace files in place (backup first if you've customized)
cd /your/path/to/vaultkeeper

# Drop in new versions of:
#   server.js, vk-webauthn.js, package.json, Dockerfile,
#   public/index.html, public/vk-app.js, public/vk-*.js

# Rebuild
docker compose down
docker compose build --no-cache vaultkeeper
docker compose up -d
```

Schema migrations run automatically on first startup with the new code.
Your data, passkeys, and config persist across rebuilds (Postgres data
is in a named volume; bind-mounted public/ persists too).

---

## Backup

Encrypted vault data lives in the `vaultkeeper_db` Docker volume.

```bash
# Backup
docker exec vaultkeeper-db pg_dump -U vault vaultkeeper > vaultkeeper.sql

# Restore
cat vaultkeeper.sql | docker exec -i vaultkeeper-db psql -U vault vaultkeeper
```

The dump contains only ciphertext — backups are themselves encrypted.
But still keep them somewhere safe; if you lose the dump AND the volume,
the data is gone.

You can also export individual user vaults via Settings → Export. The
"Decrypted JSON" export is plaintext (only do this on a trusted device).
The "Encrypted archive" export is ciphertext that can be re-imported.

---

## Troubleshooting

**Passkey enrollment fails with "rpid_mismatch"**
The server's `WEBAUTHN_RP_ID` doesn't match the hostname in the browser.
Check:
- The value contains no brackets `[`, parens `(`, or `http://` — just the
  bare hostname.
- It matches the URL bar exactly (case-sensitive). `vault.example.com`
  vs `Vault.example.com` will fail.
- If accessed through Cloudflare, the tunnel's public hostname matches.

**Passkey login fails with "origin_mismatch"**
Similar to above but for the full origin. Check `WEBAUTHN_ORIGIN`
matches the URL the browser shows. If you have HTTP-to-HTTPS redirects,
the origin must be the HTTPS one.

**iOS doesn't show passkey suggestion in autofill bar**
- Confirm iOS 17+
- Try cold-launching: long-press home screen icon → Delete Bookmark →
  Settings → Safari → Clear History and Website Data → reopen.
- Verify the build version: in Safari, view source and look for
  `<meta name="vk-build" content="v3.1.0">`. If it's older, you have a
  cached version.

**"Cannot find module './vk-webauthn'"**
The `Dockerfile` didn't copy `vk-webauthn.js` into the image. Make sure
you're using the v3.1.0 Dockerfile (see Quick start), then rebuild
without cache: `docker compose build --no-cache`.

**Black bar at the bottom of the screen on iOS**
Make sure the device added the app to the home screen as a PWA (not as
a Safari bookmark). Long-press → Delete Bookmark → re-add via Share →
Add to Home Screen. The icon preview must show the teal shield, not a
screenshot of the page.

---

## Security notes

- The server never sees your master password. Only argon2id-derived keys
  exist server-side, and even those exist only as wrapped ciphertext.
- Passkeys are stored in your device's secure hardware. They can't be
  extracted, copied, or used remotely.
- The encrypted blob stored on the server (for passkey unlock) cannot be
  decrypted by the server. It requires a successful passkey assertion to
  produce the DEK.
- TLS is mandatory for both crypto subtle (`crypto.subtle`) and WebAuthn.
  Browsers refuse both over plain HTTP except on `localhost`.
- The Content Security Policy is fairly tight. If you fork and modify
  the UI, you may need to adjust CSP in `server.js`.

---

## License

You're free to host this for yourself, your family, your team. No
warranty; the security guarantees are only as good as the rest of your
operational hygiene (TLS, server access, backups).
