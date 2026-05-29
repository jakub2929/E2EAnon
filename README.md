# AnonChat

> Open-source, end-to-end encrypted, ephemeral group chat. No accounts, no database, no persistence. The server is a blind relay.

**Status:** ✅ Feature-complete (all phases shipped). Open-source, unaudited —
read the [threat model](docs/THREAT_MODEL.md) before relying on it.

---

## What it is

AnonChat is a web chat where you either **create a room** or **join a room** via a
single-use invite code. Messages are end-to-end encrypted in the browser; the
server only ever forwards opaque ciphertext between connected clients and can
never read message content or derive any encryption key.

- **No registration, no accounts, no database, no persistence.** Nothing is
  written to disk on the server or to `localStorage`/`sessionStorage`/IndexedDB
  in the browser.
- **Server is a blind relay.** It observes only: room ID, ephemeral connection
  presence, ciphertext blobs, and timing.
- **Rooms are ephemeral**, capped at **10 members**, and **invite-only** via
  fresh **single-use 10-character codes**.
- **Forward secrecy on membership changes:** the room key is rotated on every
  join and every leave.
- On leave / room close, all message history is wiped from memory everywhere.
- **One room per session** (soft, UX-level): a tab is in at most one room at a
  time, tracked by an ephemeral in-memory session id. Switching prompts you to
  leave first (owners are offered ownership transfer before destroying the room).
  Bypassable by another tab/browser/device — by design, see the threat model.

## Security architecture (overview)

The 10-character invite code is a **weak shared secret**. It is never used
directly as an encryption key and never traverses the server in plaintext.

1. **SPAKE2 (PAKE)** turns the weak code into a channel secure against both
   eavesdroppers and a malicious/curious server.
2. **X25519 (ECDH)** exchanges per-member public keys over that channel.
3. **XChaCha20-Poly1305** encrypts messages under a symmetric room key; the
   owner encrypts the current room key individually to each member's X25519 key.
4. **Key rotation** on every join/leave provides forward secrecy across
   membership changes.

Full details land in [`docs/PROTOCOL.md`](docs/PROTOCOL.md) and the threat model
section of this README as the relevant phases are implemented.

## Tech stack

- **Backend relay:** Go + [`github.com/coder/websocket`](https://github.com/coder/websocket).
  In-memory state only. Single static binary.
- **Frontend:** Browser client. WebCrypto (X25519/ECDH, AEAD) + a WASM/JS
  library for SPAKE2. Framework-light.
- **Deployment:** Docker + docker-compose, designed for [Coolify](https://coolify.io).

## Repository layout

```
.
├── server/        Go WebSocket relay (in-memory, single binary)
├── web/           Browser client (TypeScript, crypto in-browser)
├── docs/          PROTOCOL.md, threat model, deploy notes
├── docker-compose.yml
├── Dockerfile
├── .env.example
├── LICENSE        (MIT)
└── README.md
```

## Local development

> Requires Go ≥ 1.23 and Node ≥ 20.

**Two-terminal dev** (Vite proxies `/ws`, `/api`, `/health` → `localhost:8080`):

```bash
# Terminal 1 — relay
cd server && go run ./cmd/anonchat        # listens on :8080

# Terminal 2 — frontend dev server
cd web && npm install && npm run dev      # http://localhost:5173
```

**Single-binary mode** (serve the built frontend from Go):

```bash
cd web && npm run build                   # outputs web/dist
cd ../server && STATIC_DIR=../web/dist go run ./cmd/anonchat
# open http://localhost:8080
```

**Tests:**

```bash
cd server && go test -race ./...    # relay + proxy + opaque-relay invariant
cd web && npm test                  # message crypto (XChaCha20-Poly1305) round-trip/tamper
```

Config is via env vars — see [`.env.example`](.env.example).

## Deployment (Coolify)

Single-container: one stripped Go binary **embeds** the built frontend and
serves both the static assets and the WebSocket endpoint (final image is
distroless/static, ~15 MB). Honors the `PORT` env var, exposes `GET /health`,
works behind Coolify's Traefik reverse proxy, and uses no volumes.

```bash
docker compose up --build      # http://localhost:8080
```

Full Coolify walkthrough (env vars, health check, TLS/WS) in
[`docs/DEPLOY.md`](docs/DEPLOY.md).

## Abuse protection

- **Single-use invites** with a configurable TTL (`INVITE_CODE_TTL`); a token is
  consumed on the first redemption attempt and dropped when its room is destroyed.
- **Per-IP rate limits** on room creation (`RATE_LIMIT_CREATE_PER_MIN`) and
  invite redemption (`RATE_LIMIT_REDEEM_PER_MIN`) — the latter also bounds online
  guessing of the weak code.
- **Room size cap** (`MAX_ROOM_SIZE`, default 10), **idle-room GC**
  (`ROOM_IDLE_TIMEOUT`), and per-client send-buffer limits (slow clients are
  dropped). For public deployments, also front the service with a proxy/WAF.

## Threat model & non-goals

AnonChat protects message **content** against the **server** and the **network**:
the relay never sees the room key or the invite code and cannot derive them.

It does **not** protect against: a **malicious room member** (who legitimately
holds the key and can screenshot/leak — and can spoof another member's nick), a
**compromised endpoint**, **traffic analysis / metadata** (the server sees room
IDs, presence, timing, message sizes, and IPs), **denial of service**, or — most
importantly — a **server that serves backdoored client code** (inherent to any
browser-delivered E2E app). The SPAKE2 layer is a **custom implementation** on
audited primitives (RFC 9382, validated against the official test vectors), **not
an audited library**. The **one-room-per-session** rule is a UX convenience, not
a security boundary (trivially bypassed by another tab/browser/device).

👉 **Read the full [threat model](docs/THREAT_MODEL.md) before relying on
AnonChat.** Report issues via [`SECURITY.md`](SECURITY.md).

## Status

All planned phases are complete:

- [x] **Phase 0** — Repo scaffold
- [x] **Phase 1** — Relay skeleton (plaintext)
- [x] **Phase 2** — Dockerize + Coolify-ready
- [x] **Phase 3** — Transport encryption (XChaCha20-Poly1305)
- [x] **Phase 4** — Single-use invite codes + SPAKE2 (RFC 9382)
- [x] **Phase 5** — X25519 per-member keys + rotation (forward secrecy)
- [x] **Phase 6** — Ownership transfer + kick + hardened teardown
- [x] **Phase 7** — Threat model, docs, abuse notes

## Contributing

Issues and PRs welcome. Run `cd server && go test -race ./...` and
`cd web && npm test` before submitting; keep the security model intact (see the
threat model) and flag any tradeoff explicitly.

## License

[MIT](LICENSE).
