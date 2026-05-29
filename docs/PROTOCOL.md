# AnonChat Wire Protocol

> Source of truth for the client ↔ server WebSocket protocol and the
> end-to-end crypto envelope. **Status: complete.** See also the
> [threat model](THREAT_MODEL.md).

## Transport

- One WebSocket connection per client at `GET /ws` (HTTP upgrade).
- Library: [`github.com/coder/websocket`](https://github.com/coder/websocket)
  (server). Browser uses the native `WebSocket` API.
- All Phase 1 frames are **JSON text frames**.
- Per-frame read limit: **256 KiB**.
- Origin checking: the handshake honors `ALLOWED_ORIGINS`. `*` accepts any
  origin (development only).

> **As of Phase 3:** the `body` field on `msg` and `chat` is an **opaque
> base64 ciphertext envelope** (see [Crypto layers](#crypto-layers)). The server
> relays it verbatim and cannot read it or derive the key.

## Connection lifecycle

```
client                              server
  │   ── WS upgrade /ws ──────────────▶│
  │   ── {type:"create"|"redeem"} ────▶│   (first frame = "hello", 15s deadline)
  │◀── {type:"welcome", ...} ──────────│   on success
  │◀── {type:"error", ...} ────────────│   on failure (then close)
  │                                     │
  │   ── {type:"msg", body} ──────────▶│
  │◀── {type:"chat", ...} ─────────────│   (relayed from other members)
  │◀── {type:"presence", members} ─────│   (on any membership change)
  │                                     │
  │   ── {type:"leave"} ──────────────▶│   (or transport close)
  │◀── {type:"room_closed", reason} ───│   (if the room is destroyed)
```

The **first frame must be `create` or `redeem`** within 15 seconds, else the
connection is closed. The first member of a room is its **owner**. As of Phase 4
there is **no plaintext `join`** — joining requires a single-use invite.

### Invite + handshake flow (Phase 4)

```
owner                         server                         joiner
  │── {invite} ──────────────▶│                                 │
  │◀─ {invite_created,token} ─│   (owner makes a 10-char code locally;
  │                           │    shares token+code as an invite link)
  │                           │◀──────────── {redeem,token,nick} │
  │◀─ {invite_redeemed,       │── {redeem_ok,handshake} ────────▶│
  │     handshake,token,nick} │                                  │
  │                           │                                  │
  │═══ SPAKE2 over {pake,handshake,data} relayed both ways ═════ │
  │     (server forwards opaque frames; cannot derive the key)   │
  │                           │                                  │
  │── {key_deliver,handshake, ▶ relayed ▶ ── {key_deliver,…} ───▶│
  │     data=wrapped roomKey} │                                  │
  │                           │◀──────────── {enter,handshake} ──│
  │◀─ {presence} ─────────────│── {welcome, role:member} ───────▶│
```

The joiner is **not a room member** until it sends `enter` after a successful
handshake; a wrong code fails key confirmation and the joiner never enters.

## Client → Server messages

| `type`        | Fields                  | Meaning                                              |
| ------------- | ----------------------- | --------------------------------------------------- |
| `create`      | `nick`, `session?`      | Create a new room; sender becomes owner.            |
| `redeem`      | `token`, `nick`, `session?` | Redeem a single-use invite token (starts handshake).|
| `invite`      | —                       | (Owner) request a fresh single-use invite token.    |
| `pake`        | `handshake`, `data`     | One opaque SPAKE2 frame; relayed to the other party.|
| `member_key`  | `handshake`, `data`     | X25519 pubkey sealed under Ke; relayed to the peer. |
| `key_deliver` | `handshake`, `data`     | (Owner) room key sealed to the joiner's X25519 key. |
| `enter`       | `handshake`             | (Joiner) finalize membership after the handshake.   |
| `rekey`       | `target`, `data`        | (Owner) rotated room key sealed to one member.       |
| `roster`      | `data`                  | (Owner) member→pubkey map, encrypted under room key. |
| `transfer`    | `target`                | (Owner) hand ownership to another member.            |
| `kick`        | `target`                | (Owner) remove a member from the room.               |
| `file_start`  | `transfer`, `keyId`, `data` | Begin a file transfer; `data` = encrypted metadata. |
| `file_chunk`  | `transfer`, `index`, `data` | One sealed file chunk.                          |
| `file_end`    | `transfer`              | Transfer complete.                                   |
| `file_abort`  | `transfer`              | Abandon a transfer (peers discard the partial).      |
| `msg`         | `body`                  | Send a chat message. `body` is a ciphertext envelope.|
| `leave`       | —                       | Gracefully leave the room.                           |

- `nick` is trimmed, capped at 64 runes, and defaults to `anon` if empty.
- `data` (pake/key_deliver) is opaque to the server. Unknown frames are ignored.
- `session` is the client's ephemeral per-tab id (random, in-memory only, never
  persisted). The server uses it ONLY to enforce one room per session (a RAM
  map, cleared on disconnect/teardown). Empty disables the check for that
  connection. See [One room per session](#one-room-per-session-v2).

## Server → Client messages

| `type`            | Fields                                | Meaning                                  |
| ----------------- | ------------------------------------- | ---------------------------------------- |
| `welcome`         | `room`, `memberId`, `role`, `members` | Create/enter succeeded.                  |
| `presence`        | `members`                             | Full member list after a change.         |
| `chat`            | `from`, `nick`, `body`, `ts`          | A relayed message; `body` is ciphertext. |
| `invite_created`  | `token`, `ts`                         | A single-use token (and expiry) for the owner. |
| `invite_redeemed` | `handshake`, `token`, `nick`, `memberId` | A token was redeemed; owner starts SPAKE2. |
| `redeem_ok`       | `handshake`, `memberId`               | Token accepted; joiner starts SPAKE2.    |
| `pake`            | `handshake`, `data`                   | Relayed SPAKE2 frame from the peer.      |
| `member_key`      | `handshake`, `data`                   | Relayed X25519 pubkey (sealed under Ke). |
| `key_deliver`     | `handshake`, `data`                   | Relayed room key sealed to the joiner.   |
| `rekey`           | `data`                                | Rotated room key sealed to this member.  |
| `roster`          | `data`                                | Member→pubkey map (under the room key).  |
| `file_start`/`file_chunk`/`file_end`/`file_abort` | `transfer`, `keyId`/`index`, `data`, `from`, `nick` | Relayed file-transfer frames. |
| `room_closed`     | `reason`                              | Room/this membership ended; wipe state.  |
| `error`           | `error`, `reason`                     | Recoverable/fatal error.                 |

- `role` ∈ `owner` | `member`. `members` is an array of `{ id, nick, role }`.
- `token` echoed in `invite_redeemed` is the server-generated routing handle
  (not the secret code); it lets the owner pick the matching local code.
- `memberId` (in `redeem_ok`/`invite_redeemed`) is the joiner's id, so the owner
  can address future `rekey` frames to it. Not secret.

### Reason codes

| `reason`          | Used with     | Meaning                              |
| ----------------- | ------------- | ------------------------------------ |
| `owner_left`      | `room_closed` | Owner left; room destroyed.          |
| `idle_timeout`    | `room_closed` | Room idle past `ROOM_IDLE_TIMEOUT`.  |
| `server_shutdown` | `room_closed` | Server shutting down gracefully.     |
| `room_full`       | `error`       | Redemption rejected; room at capacity.|
| `room_not_found`  | `error`       | Room no longer exists.               |
| `invalid_invite`  | `error`       | Unknown/expired/already-used token.  |
| `rate_limited`    | `error`       | Too many create/redeem attempts.     |
| `not_owner`       | `error`       | Only the owner may invite/transfer/kick. |
| `kicked`          | `room_closed` | You were removed by the owner.       |
| `already_in_room` | `error`       | This session is already in a room (one-room rule). |
| `file_rejected`   | `error`       | File transfer over the per-file / in-flight cap. |
| `bad_request`     | `error`       | Malformed/unexpected first frame.    |

## Room semantics

- Rooms are in-memory only; **nothing is persisted**.
- Capacity is `MAX_ROOM_SIZE` (default 10); redemption beyond it gets `room_full`.
- **Owner leaves *without transferring* → room destroyed.** All members receive
  `room_closed` (`owner_left`) and the server wipes the room's state.
- **Ownership transfer:** the owner may hand ownership (invite/kick/rekey rights)
  to any current member via `transfer`. After transfer the old owner is an
  ordinary member, so its later departure no longer destroys the room.
- **Kick:** the owner may remove a member via `kick`; the target gets
  `room_closed` (`kicked`) and is disconnected. The owner then rotates the room
  key (forward secrecy — the kicked member cannot read future messages).
- **Non-owner leaves → room persists**; remaining members get fresh `presence`.
- **Last member leaves → room destroyed** silently.
- **Idle rooms** (no activity for `ROOM_IDLE_TIMEOUT`) are destroyed by a
  background janitor. Destroying a room also drops its outstanding invites.

## One room per session (v2)

A session may be in **at most one room at a time**. A "session" is the client's
ephemeral, in-memory, per-page-load `session` id (see the `create`/`redeem`
fields above). The server keeps a **RAM-only** map `session → room`:

- On `create`/`redeem` the server **claims** the session id; a second room for
  the same id is rejected with `already_in_room`. For `redeem` the check runs
  **before** consuming the invite, so a blocked attempt never burns the token.
- The claim is released on graceful `leave`, on disconnect, and on room teardown
  (owner-leave/idle/kick/shutdown). Release uses **compare-and-delete** so a slow
  cleanup from an old connection can't clobber a reconnect's fresh claim.
- An empty/absent `session` disables the check for that connection.

The client surfaces this as UX: it holds one WebSocket per tab and, for an owner
switching/leaving, offers **transfer** (default) vs **destroy**.

> **This is a soft constraint, not a security guarantee.** It prevents *accidental*
> presence in multiple rooms within one tab. A user can trivially be in multiple
> rooms via separate tabs / incognito / browsers / devices (each gets a fresh
> session id), or with a modified client. Hard enforcement is impossible without
> persistent identity, which AnonChat deliberately does not have. See the
> [threat model](THREAT_MODEL.md).

## Health & static

- `GET /health` → `200 ok` (Coolify health check).
- The binary serves the frontend at `/` with SPA fallback to `index.html`.
  Release builds **embed** the assets (single binary); `STATIC_DIR` overrides
  them with files from disk (used in dev). A build with neither serves a
  placeholder page.
- `-healthcheck` CLI mode probes `/health` on `$PORT` and exits 0/1 — used by
  the container `HEALTHCHECK` so the shell-less image needs no curl/wget.

## Crypto layers

### Message AEAD (Phase 3) — implemented

Messages are sealed client-side with **XChaCha20-Poly1305** under a 256-bit
symmetric **room key**. Library: [`@noble/ciphers`](https://github.com/paulmillr/noble-ciphers)
(audited, dependency-free). WebCrypto is *not* used for the AEAD because it has
no XChaCha20-Poly1305; X25519 (Phase 5) will use WebCrypto.

**Envelope** (the value of `body`), base64-encoded (standard alphabet):

```
┌─────────┬────────────────────┬──────────────────────────────┐
│ version │ nonce (24 bytes)   │ ciphertext ‖ Poly1305 tag(16) │
│ 1 byte  │ random, per-message│ XChaCha20-Poly1305 output     │
└─────────┴────────────────────┴──────────────────────────────┘
  0x01
```

- A fresh random 24-byte nonce per message (XChaCha20's extended nonce makes
  random nonces collision-safe).
- AAD: none. Message authenticity comes from the AEAD tag under the shared room
  key; sender binding is not cryptographically enforced (a member could spoof
  another member's `nick`). This is an accepted limitation (see threat model).
- Decryption failure (wrong key, tamper, truncation) is surfaced in the UI as
  `[unable to decrypt]`; the server is never involved.

### PAKE handshake (Phase 4) — SPAKE2, RFC 9382

> ⚠️ **Custom implementation, not an audited library.** No maintained, audited
> browser SPAKE2 exists. AnonChat's SPAKE2 is a *custom* implementation
> ([`web/src/spake2.ts`](../web/src/spake2.ts)) built on the **audited**
> `@noble/curves` (P-256) and `@noble/hashes` (SHA-256/HKDF/HMAC) primitives.
> The protocol glue is isolated in that one module, annotated with the exact RFC
> 9382 sections, and **validated against the RFC's official test vectors**
> ([`web/src/spake2.test.ts`](../web/src/spake2.test.ts)). Review it
> independently before trusting it.

- **Ciphersuite:** `SPAKE2-P256-SHA256-HKDF-HMAC` (RFC 9382 §6) — chosen because
  the RFC's official test vectors are for P-256, and P-256 has cofactor 1.
- **Roles:** owner = A (point M), joiner = B (point N). Identities bind to the
  handshake id to prevent unknown-key-share / cross-handshake replay.
- **Password scalar `w`:** `w = scrypt(code) mod n` (memory-hard; RFC §3.3),
  with the handshake id as salt. The 10-char code is the only shared secret.
- **Key confirmation is mandatory** (RFC §3.3): both sides exchange and verify
  HMAC tags over the transcript before trusting the derived secret `Ke`. A wrong
  code fails confirmation and aborts.

### X25519 per-member keys + rotation (Phase 5)

Every client holds a **static X25519 keypair** (RAM only). The room key is
distributed per-member and **rotated on every membership change** for forward
secrecy.

**Public-key exchange (during the handshake).** Once SPAKE2 yields `Ke`, the
joiner and owner exchange X25519 public keys in `member_key` frames, each
**sealed under Ke**:

```
member_key.data = XChaCha20-Poly1305( HKDF(Ke, "anonchat-keyx-v1"), pubKey )
```

Sealing under `Ke` (which the relay never has) prevents a malicious server from
substituting public keys (MITM).

**Per-member room-key sealing (pairwise static ECDH).** To give a member the
room key, the owner derives a pairwise secret and seals:

```
shared  = X25519(owner_priv, member_pub)
wrapKey = HKDF-SHA256(shared, info="anonchat-rekey-v1", 32)
data    = XChaCha20-Poly1305_envelope(wrapKey, roomKey)
```

This is **authenticated** (only owner+member share `shared`) and stable across
rotations. The new joiner's first key arrives via `key_deliver`; subsequent
rotations arrive via `rekey` (routed by member id).

**Rotation (forward secrecy).** The owner generates a **fresh room key** and
re-seals it to every current member:

- **On join:** new key → delivered to the joiner, re-keyed to all existing
  members. The joiner never holds any pre-join key.
- **On leave:** new key → re-keyed to all *remaining* members. The leaver is not
  re-keyed and cannot read subsequent messages.

Clients keep a few recent keys to decrypt messages in flight during a rotation,
but always **encrypt with the newest** key. **The room key never appears in any
URL and never reaches the server.**

**Roster replication (Phase 6).** So that any member can become owner and keep
re-keying the room, the owner broadcasts the full member→X25519-pubkey map in a
`roster` frame **encrypted under the room key** (the server cannot read or
substitute it). Every client maintains this roster; members unseal `rekey`
frames using the *current* owner's pubkey from it. On `transfer`, the new owner
already holds the roster and re-keys on the next membership change; members
unseal its rekeys using its pubkey from the roster.

**Invite artifact.** The owner shares a single-use link
`https://host/#t=<token>&c=<code>`: `t` is the server-side routing token
(high-entropy, single-use, enforces expiry — the server knows it but it reveals
nothing about the code); `c` is the 10-char SPAKE2 code (the server never sees
it — it lives only in the fragment and in SPAKE2 messages it cannot invert).
For stronger security the code can be shared out-of-band on a second channel.

### Single-use, expiry, rate limiting

- A token is **consumed on the first redemption attempt** (success or not) and
  validated against `INVITE_CODE_TTL`. Expired tokens are also GC'd.
- Room creation and redemption are **rate-limited per source IP**
  (`RATE_LIMIT_CREATE_PER_MIN`, `RATE_LIMIT_REDEEM_PER_MIN`), bounding online
  guessing of the weak code.

## Encrypted file transfer

Files/images go through the **same E2E path as messages** — XChaCha20-Poly1305
under the room key — chunked over the WebSocket. The server relays only opaque
ciphertext and never sees the bytes, filename, or MIME type.

- **`file_start`** `{ transfer, keyId, data }` — `transfer` is a random
  correlation id; `keyId` is the non-secret key-epoch tag (see below); `data` is
  the **encrypted metadata** `sealBytes(roomKey, JSON{name, type, size, chunks})`.
  **Filename and MIME are inside the ciphertext** — never in cleartext fields.
- **`file_chunk`** `{ transfer, index, data }` — `data` is one independently
  sealed chunk: `sealBytes(roomKey, plaintextChunk)` (64 KiB plaintext/chunk).
  Each chunk has its own nonce + Poly1305 tag, so each is independently
  authenticated. `index` is 0-based.
- **`file_end`** `{ transfer }` — sender done; recipients assemble once all
  chunks arrive. **`file_abort`** `{ transfer }` — discard the partial.

**Key-epoch tagging (rotation-safe).** `keyId = HKDF(roomKey, "anonchat-keyid")[:8]`
(base64url) — a one-way tag both peers derive from the same key. The sender
captures the room key **once** at `file_start` and uses it for the whole file;
the recipient looks up the held key whose `keyId` matches. So a file sent just
before a rotation still decrypts afterward, as long as the recipient still holds
that key epoch (clients keep the last few keys). The tag leaks nothing about the
key.

**Server guards (RAM-only, never disk).** The relay forwards chunks one at a
time and **never buffers a file to disk** (no temp files). It enforces:
- `MAX_FILE_BYTES` — per-transfer cumulative ciphertext cap; an over-cap transfer
  is **rejected** (`error` `file_rejected` to the sender, `file_abort` to peers).
- `MAX_INFLIGHT_BYTES` — cap on total ciphertext of all concurrent transfers;
  chunks beyond it are rejected. Counters are released on `file_end`, abort, or
  sender disconnect.

The client also caps the **plaintext** size before sending and revokes all blob
object URLs on teardown / between rooms.

## Teardown / zeroing

- **Server:** destroying a room nils its members map, drops references, and
  deletes its outstanding invite tokens. Shutdown destroys all rooms.
- **Client:** on leave/close, all room keys, the X25519 secret key, and any
  handshake `Ke` are zeroed (`fill(0)`); the message + member DOM is cleared.
  Nothing is ever written to `localStorage`/`sessionStorage`/IndexedDB/cookies.

## Connection liveness

- The server pings each WebSocket every `WS_PING_INTERVAL` (default 25s; browsers
  auto-reply with pongs). This keeps idle-but-live connections alive through
  proxies/NAT (Coolify's Traefik) and detects dead ones within ~interval + 10s.
- **Silent presence is not idleness:** a room with any connected member is kept
  alive; idle GC (`ROOM_IDLE_TIMEOUT`) only reaps rooms with **zero** members.
- **Ephemerality is unchanged.** A dropped/dead connection runs the full normal
  teardown (member removed → room key rotates on leave / room destroyed if owner
  → RAM wiped). There is **no session-resume that holds a disconnected member's
  state**, so the heartbeat never defeats wipe-on-teardown. (A client cannot
  silently re-attach to a room after a drop — it returns to the lobby wiped.)
