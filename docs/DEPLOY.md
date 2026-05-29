# Deploying AnonChat

AnonChat ships as a **single container**: one stripped Go binary that embeds the
built frontend and serves both the static assets and the WebSocket relay. There
are **no volumes and no persistent storage** — consistent with the
zero-persistence design.

- Final image: `gcr.io/distroless/static-debian12:nonroot` (~15 MB, no shell,
  non-root).
- Honors `PORT` (binds `0.0.0.0:$PORT`).
- `GET /health` → `200` for health checks.
- WebSocket upgrade works behind a reverse proxy; honors `X-Forwarded-*` when
  `TRUST_PROXY=true`.
- Container `HEALTHCHECK` uses the binary's own `-healthcheck` mode (no
  curl/wget needed in the shell-less image).

---

## Local: plain Docker

```bash
docker build -t anonchat .
docker run --rm -p 8080:8080 \
  -e ALLOWED_ORIGINS='*' -e TRUST_PROXY=false \
  anonchat
# open http://localhost:8080
```

## Local: docker compose

```bash
docker compose up --build
# open http://localhost:8080   (override with HOST_PORT=9000 docker compose up)
```

Compose env vars (all optional, with defaults) are documented in
[`.env.example`](../.env.example) and surfaced in
[`docker-compose.yml`](../docker-compose.yml). Copy `.env.example` to `.env` to
override them.

---

## Coolify

Coolify runs behind a Traefik reverse proxy that terminates TLS and forwards to
your container. AnonChat is designed to drop straight in.

### Option A — Docker Compose (recommended)

1. **New Resource → Docker Compose**, point it at this repo (it consumes the
   root [`docker-compose.yml`](../docker-compose.yml) directly).
2. Coolify builds the image from the [`Dockerfile`](../Dockerfile) and wires the
   container to its Traefik proxy automatically.
3. Set environment variables in the Coolify UI (see below).
4. Set the **health check path** to `/health` (the compose `HEALTHCHECK` also
   covers container-level health).
5. Attach your domain to the `anonchat` service's exposed port `8080`; Coolify
   provisions TLS via Let's Encrypt. WebSockets work over the same
   `https://`/`wss://` origin with no extra config — the client derives `wss://`
   from the page origin.

> On a **shared** Coolify host, remove the `ports:` mapping from the compose
> (leave only `expose: 8080`) so Traefik handles ingress without host-port
> conflicts. On a dedicated host, publishing is fine.

### Option B — Dockerfile build (simplest single container)

1. **New Resource → Dockerfile / Git**, select this repo (build context `/`,
   Dockerfile `Dockerfile`).
2. **Ports Exposes: `8080`** — the container listens on 8080 (the Dockerfile's
   `EXPOSE 8080` is auto-detected). The server defaults to `8080`; if you set
   `PORT`, also update the exposed port to match — its `-healthcheck` reads the
   same `PORT`.
3. Set the env vars below and **health check path `/health`**.
4. Attach your domain; Coolify provisions TLS. WebSockets work over `wss://` on
   the same origin automatically (no extra Traefik config needed).

> **Note (v2):** the "one room per session" limit is enforced per browser tab via
> an ephemeral client id — there is nothing to configure server-side, and it is a
> soft UX constraint (see the [threat model](THREAT_MODEL.md)).

### Environment variables to set in Coolify

| Variable            | Recommended (prod)                     | Notes                                            |
| ------------------- | -------------------------------------- | ------------------------------------------------ |
| `ALLOWED_ORIGINS`   | `https://your-domain.tld`              | **Do not** leave as `*` in production.           |
| `TRUST_PROXY`       | `true`                                 | Behind Traefik. Enables `X-Forwarded-*` parsing. |
| `MAX_ROOM_SIZE`     | `10`                                   | Spec cap.                                        |
| `ROOM_IDLE_TIMEOUT` | `30m`                                  | Idle rooms are destroyed.                        |
| `INVITE_CODE_TTL`   | `5m`                                   | Single-use invite token lifetime.                |
| `RATE_LIMIT_CREATE_PER_MIN` | `10`                           | Room creations per source IP per minute.         |
| `RATE_LIMIT_REDEEM_PER_MIN` | `20`                           | Invite redemptions per source IP per minute.     |
| `LOG_FORMAT`        | `json`                                 | Structured logs for aggregation.                 |
| `LOG_LEVEL`         | `info`                                 |                                                  |
| `PORT`              | (injected by Coolify)                  | Server honors it; defaults to `8080`.            |

> **Abuse protection.** Invites are single-use with a TTL; room creation and
> redemption are rate-limited per IP (set `TRUST_PROXY=true` so the real client
> IP is read from `X-Forwarded-For`). Rooms are capped at `MAX_ROOM_SIZE` and
> idle rooms are GC'd. For public deployments, also front the service with a
> WAF/proxy. See the [threat model](THREAT_MODEL.md) for what this does and does
> not defend against.

> **Origins:** `ALLOWED_ORIGINS` gates the WebSocket handshake (CSRF / cross-site
> WS protection). In production set it to the exact origin(s) users load the app
> from. `*` disables the check and is for local dev only.

### Verifying the deploy

```bash
curl https://your-domain.tld/health        # -> ok
# Open the site, create a room in one tab, join with the code in another.
```

### Why no volumes?

AnonChat never writes to disk: rooms, members, and (from Phase 3) ciphertext
live only in RAM and are wiped on leave/teardown/restart. Do not attach storage.
A restart intentionally destroys all rooms.
