# syntax=docker/dockerfile:1.6
#
# VaultKeeper — production container.
# TLS terminated upstream (Cloudflare Tunnel, nginx, Caddy, Traefik, etc).
# To expose directly with TLS, terminate at a reverse proxy.

# ---------- deps stage: install production deps only ----------
FROM node:20-alpine AS deps
WORKDIR /app

COPY package.json package-lock.json* ./
RUN if [ -f package-lock.json ]; then \
      npm ci --omit=dev; \
    else \
      npm install --omit=dev --no-audit --no-fund; \
    fi

# ---------- runtime stage ----------
FROM node:20-alpine AS runtime
WORKDIR /app

# ca-certificates for outbound HTTPS (HIBP, 2fa.directory checks).
# wget for HEALTHCHECK.
RUN apk add --no-cache ca-certificates wget

ENV NODE_ENV=production \
    PORT=3333

COPY --from=deps /app/node_modules ./node_modules
COPY package.json ./
COPY server.js ./
COPY vk-webauthn.js ./
COPY public ./public

EXPOSE 3333

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD wget -qO- http://127.0.0.1:${PORT}/healthz >/dev/null 2>&1 || exit 1

CMD ["node", "server.js"]
