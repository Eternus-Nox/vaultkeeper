# Vendored libraries

The client expects these files at runtime. They are NOT included in this
repo — fetch them once at deploy time. We pin specific versions and
self-host so the client only ever talks to your origin.

| File | Fetch from | Purpose |
|---|---|---|
| `hash-wasm.umd.min.js` | `https://cdn.jsdelivr.net/npm/hash-wasm@4.12.0/dist/index.umd.min.js` | argon2id + blake2b WASM |
| `lucide.js` | `https://unpkg.com/lucide@latest/dist/umd/lucide.js` | Icon library |

## One-line setup

From the project root:

```bash
mkdir -p public/vendor
curl -L -o public/vendor/hash-wasm.umd.min.js \
  https://cdn.jsdelivr.net/npm/hash-wasm@4.12.0/dist/index.umd.min.js
curl -L -o public/vendor/lucide.js \
  https://unpkg.com/lucide@latest/dist/umd/lucide.js
```

Verify the hash-wasm bundle is the right one (should be ~210 KB):

```bash
wc -c public/vendor/hash-wasm.umd.min.js
# Expected: 216086

head -c 100 public/vendor/hash-wasm.umd.min.js
# Should start with: /*! * hash-wasm (https://www.npmjs.com/package/hash-wasm) ...
```

If the file is much smaller (~11 KB) and starts with React content, you've
hit the Cloudflare cache poisoning bug we fixed during development. Purge
Cloudflare cache for `/vendor/*` and reload.

## Fonts

You'll also need:

- `public/fonts/Inter-Variable.woff2`
- `public/fonts/JetBrainsMono-Variable.woff2`

These are referenced from `index.html` `@font-face` declarations. Fetch from:

- Inter: https://github.com/rsms/inter/releases (Inter-3.x.zip → InterVariable.woff2)
- JetBrains Mono: https://github.com/JetBrains/JetBrainsMono/releases (latest → fonts/variable/JetBrainsMono[wght].ttf, convert to woff2 with fonttools or use https://www.fontsquirrel.com/tools/webfont-generator)

If you skip the fonts, the browser falls back to system sans / mono. Still
looks fine — just less polished.
