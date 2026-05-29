# AnonChat Threat Model

This document states what AnonChat **does** and **does not** protect against. Read
it before relying on AnonChat for anything sensitive. AnonChat is an
open-source project provided as-is (MIT); it has **not** had a third-party
security audit.

## Summary

AnonChat protects the **content** of chat messages against the **server** and
the **network**. It does **not** protect against malicious participants,
compromised devices, the server serving you malicious code, or metadata /
traffic analysis.

## What AnonChat is

- An end-to-end encrypted, ephemeral group chat (≤ 10 members per room).
- The server is a **blind relay**: it forwards opaque ciphertext and handshake
  frames between connected clients. It holds room state only in RAM and persists
  nothing.
- Messages are encrypted with **XChaCha20-Poly1305** under a symmetric room key.
- A weak, single-use **10-character invite code** is turned into a strong shared
  secret via **SPAKE2** (RFC 9382, P-256), so the code is safe to share over a
  low-bandwidth channel and is never exposed to the server.
- Per-member **X25519** keys distribute the room key; it is **rotated on every
  join and leave** for forward secrecy across membership changes.

## Assets we protect

- **Message plaintext** (confidentiality + integrity) against the server and any
  network observer.
- **The room key and the invite code** against the server.

## Adversaries considered (and what holds)

### 1. Passive network eavesdropper
Sees only TLS-encrypted traffic to the server (deploy behind HTTPS/Traefik), and
even if TLS were stripped, only ciphertext + opaque PAKE/key frames. **Cannot**
read messages or derive keys.

### 2. Malicious or compromised server / relay operator
This is the primary adversary AnonChat is designed against **for message
content**. The server:
- never receives the room key (delivered only over the PAKE / X25519 channels);
- never receives the 10-char code (it lives in the URL fragment + SPAKE2
  messages it cannot invert; the server only sees a separate high-entropy
  routing token);
- cannot derive the SPAKE2 key from the PAKE messages it relays;
- cannot MITM the X25519 public-key exchange, because pubkeys are exchanged
  sealed under the SPAKE2 secret `Ke` and the roster is encrypted under the room
  key.

So a curious/malicious server **cannot read message content**. See the critical
limitation in §"Server-served code" below, however.

### 3. Online guessing of the invite code
The 10-char code is low-entropy. SPAKE2 limits an attacker to **one online guess
per handshake** (a wrong guess fails key confirmation), invite tokens are
**single-use** and **expire**, and the server **rate-limits** redemption
attempts per IP. There is no offline dictionary attack on the code from the data
the server sees.

## What AnonChat does NOT protect against (non-goals / limitations)

### A. The server serving malicious client code — the fundamental limit
AnonChat's client (the JavaScript that does all the crypto) is **delivered by
the same server** it is meant to be protected from. A malicious server can serve
**backdoored JavaScript** that leaks keys or plaintext. End-to-end encryption in
a server-delivered web app therefore protects you against a server that is
**honest at delivery time but curious/compromised later**, and against the
network — **not** against a server that is malicious *when it serves you the
app*. Mitigations a deployment/user can add: self-host the static client,
pin/verify the bundle, use Subresource Integrity, or run a packaged build.
**This is inherent to browser-delivered E2E apps and is the most important
caveat here.**

### B. Malicious room members
Any member who has been admitted can **read, screenshot, log, copy, or leak**
every message — they legitimately hold the room key. There is no DRM. Also:
- **Sender spoofing:** messages are authenticated by the shared room key, not
  per sender. A member can send a message under another member's `nick`. Nicks
  are display hints, not authenticated identities.
- **A malicious owner** is fully trusted (it generates and distributes the room
  key, can invite/kick/transfer). Choose room owners accordingly.

### C. Compromised endpoint
Malware, a malicious browser extension, a keylogger, a shoulder-surfer, or a
backdoored OS/browser defeats all client-side crypto. Key material lives in JS
memory and is best-effort zeroed, but JavaScript provides no guarantee that GC'd
copies are erased, and memory may be swapped/snapshotted.

### D. Traffic analysis & metadata
The server (and network, for connection metadata) can observe: **room IDs,
connection presence and timing, message sizes and counts, who is connected when,
and client IP addresses** (X-Forwarded-For behind the proxy). AnonChat does
**not** pad messages, cover-traffic, or anonymize IPs. For network anonymity,
put the service and clients behind Tor or a VPN — that is out of scope here.

### E. The custom SPAKE2 implementation
There is no maintained, audited browser SPAKE2 library. AnonChat's SPAKE2
([`web/src/spake2.ts`](../web/src/spake2.ts)) is a **custom implementation** on
the audited `@noble/curves` / `@noble/hashes` primitives. It implements RFC 9382
(P-256 suite) with mandatory key confirmation and passes the RFC's official test
vectors, but the protocol glue itself has **not** been independently audited.
Review it before trusting it for high-stakes use.

### F. Invite-link confidentiality
The default invite is a single link carrying both the routing token and the
code. **Anyone who obtains that link can join** (and thus read the room). Share
it privately. Splitting the code onto a second channel (e.g. read it aloud)
raises the bar against a compromised sharing channel, but the server-blindness
guarantee holds either way.

### G. Forward / post-compromise secrecy scope
Key rotation happens on **membership changes** (join/leave/kick), giving forward
secrecy across those events: a joiner can't read pre-join messages; a leaver/
kicked member can't read post-departure messages. There is **no** per-message
ratchet — a key compromised between membership changes exposes messages in that
window. Since nothing is persisted, there is no stored ciphertext to decrypt
after the fact.

### H. Denial of service
A malicious client or flood can consume server resources. Basic protections
exist (per-IP rate limits on room creation and redemption, room size cap, idle
GC, per-client send-buffer limits), but AnonChat is not hardened against a
determined DoS adversary. Put it behind a proxy/WAF for public deployments.

### I. Anonymity / deniability
"Anon" refers to **no accounts and no persistence**, not network anonymity.
The server sees your IP. AnonChat provides no cryptographic deniability or
repudiation guarantees.

### J. "One room per session" is a soft constraint, not enforcement
v2 limits a session to one room at a time. A "session" is an **ephemeral,
in-memory, per-page-load random id** (no accounts, no fingerprinting, never
persisted). This prevents *accidental* presence in multiple rooms within a tab —
it is **not** a security boundary:

- A user can be in multiple rooms at once via **separate tabs, incognito
  windows, browsers, or devices** (each generates a fresh session id), or by
  running a modified client that sends a new id per connection.
- Hard enforcement is impossible without persistent identity, which AnonChat
  deliberately refuses to add (it would erode anonymity).

**Metadata note.** The ephemeral session id is sent to the server only to drive
this RAM-only map. It lets the server link *sequential connections from the same
tab during that tab's lifetime* — but this is **no more linkable than the IP +
timing the server already observes**, the id is never persisted, and a reload
generates a new one. Net effect on anonymity: negligible.

## Trust assumptions

- The client code you run is the unmodified, intended AnonChat build (see §A).
- Your endpoint and browser are not compromised.
- TLS terminates in front of the server (HTTPS / `wss://`).
- You share invite links/codes over channels you trust appropriately.

## Reporting

Found a vulnerability? See [`SECURITY.md`](../SECURITY.md).
