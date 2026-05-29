// SPAKE2 — balanced PAKE per RFC 9382, ciphersuite P256-SHA256-HKDF-HMAC.
// https://www.rfc-editor.org/rfc/rfc9382
//
// ┌──────────────────────────────────────────────────────────────────────────┐
// │ THIS IS A CUSTOM IMPLEMENTATION of the SPAKE2 protocol, built on the       │
// │ AUDITED @noble/curves (P-256) and @noble/hashes (SHA-256/HKDF/HMAC)        │
// │ primitives. It is NOT an audited PAKE library — no maintained, audited     │
// │ browser SPAKE2 exists. The protocol glue here is intentionally isolated in │
// │ this single module, annotated with the exact RFC 9382 sections, and        │
// │ validated against the RFC's official test vectors (see spake2.test.ts) so  │
// │ it can be reviewed/audited independently. See README threat model.         │
// └──────────────────────────────────────────────────────────────────────────┘
//
// Roles (RFC 9382 §3.3): party A uses point M, party B uses point N. In
// AnonChat the room owner is A and the joiner is B. Both parties must agree on
// the identities (idA, idB) to avoid unknown-key-share attacks (§3.3).
//
// P-256 has cofactor h = 1, so the "multiply by h" step (§3.3) is a no-op and
// there is no small-subgroup concern; any on-curve point is in the prime group.

import { p256 } from "@noble/curves/nist.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { hmac } from "@noble/hashes/hmac.js";
import { scrypt } from "@noble/hashes/scrypt.js";

const Point = p256.Point;
const ORDER = Point.Fn.ORDER; // group order n
const SCALAR_BYTES = 32; // length of p (the order) in bytes, for w encoding

// Fixed generation seeds for P-256 (RFC 9382 §4), compressed SEC1 encoding.
const M = Point.fromHex("02886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f");
const N = Point.fromHex("03d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49");

export type Role = "A" | "B";

export interface Spake2State {
  role: Role;
  scalar: bigint; // own secret x (A) or y (B)
  w: bigint; // password scalar
  own: Uint8Array; // own outgoing message (pA or pB), uncompressed point
  idA: Uint8Array;
  idB: Uint8Array;
  aad: Uint8Array;
}

export interface Spake2Start {
  state: Spake2State;
  message: Uint8Array; // pA (role A) or pB (role B) — send this to the peer
}

export interface Spake2Result {
  ke: Uint8Array; // 16-byte shared secret (RFC §4). Expand via HKDF before use.
  confirm: Uint8Array; // our key-confirmation MAC to send (cA if A, cB if B)
  verifyPeer(peerConfirm: Uint8Array): boolean; // verify the peer's MAC (§3.3)

  // Intermediate values, exposed ONLY for RFC test-vector validation — the
  // application uses `ke`, `confirm`, and `verifyPeer` exclusively.
  transcript: Uint8Array; // TT
  ka: Uint8Array;
  kcA: Uint8Array;
  kcB: Uint8Array;
  cA: Uint8Array;
  cB: Uint8Array;
}

// start performs the first SPAKE2 flow (RFC §3.3): pick a secret scalar and
// compute the outgoing message pX = w*seed + scalar*P. `scalarOverride` injects
// a fixed scalar for test vectors; production always uses a random one.
export function start(
  role: Role,
  w: bigint,
  idA: Uint8Array,
  idB: Uint8Array,
  aad: Uint8Array = new Uint8Array(0),
  scalarOverride?: bigint,
): Spake2Start {
  const scalar = scalarOverride ?? randomScalar();
  const X = Point.BASE.multiply(scalar); // scalar * P
  const seed = role === "A" ? M : N; // A uses M, B uses N (§3.3)
  const pPoint = mul(seed, w).add(X); // w*M + X (A) or w*N + X (B)
  const message = pPoint.toBytes(false); // uncompressed (test vectors use 0x04)
  return { state: { role, scalar, w, own: message, idA, idB, aad }, message };
}

// finish completes SPAKE2 given the peer's message: it computes the shared
// group element K, the transcript TT, the key schedule (§4), and the key
// confirmation MACs (§3.3).
export function finish(state: Spake2State, peerMessage: Uint8Array): Spake2Result {
  // Group-membership check is mandatory (§7): fromBytes rejects off-curve /
  // malformed points. With cofactor 1 this fully validates membership.
  const peer = Point.fromBytes(peerMessage);
  peer.assertValidity();

  // K = scalar * (peerMessage - w*seed_peer). A removes w*N, B removes w*M.
  // The cofactor multiply (h=1) is omitted.
  const peerSeed = state.role === "A" ? N : M;
  const K = peer.subtract(mul(peerSeed, state.w)).multiply(state.scalar);

  // Order pA/pB by role for the transcript.
  const pA = state.role === "A" ? state.own : peerMessage;
  const pB = state.role === "A" ? peerMessage : state.own;

  // TT (RFC §3.3): len()-prefixed concat; len() is an 8-byte little-endian
  // length. w is big-endian, padded to the length of p.
  const wBytes = bigToBytesBE(state.w, SCALAR_BYTES);
  const TT = concat(
    lv(state.idA),
    lv(state.idB),
    lv(pA),
    lv(pB),
    lv(K.toBytes(false)),
    lv(wBytes),
  );

  // Key schedule (RFC §4): Ke || Ka = Hash(TT), each half = digest/2.
  const h = sha256(TT);
  const ke = h.slice(0, 16);
  const ka = h.slice(16, 32);

  // KcA || KcB = HKDF(salt=nil, ikm=Ka, info="ConfirmationKeys"||AAD, L=32).
  const kc = hkdf(sha256, ka, new Uint8Array(0), concat(utf8("ConfirmationKeys"), state.aad), 32);
  const kcA = kc.slice(0, 16);
  const kcB = kc.slice(16, 32);

  // Confirmation MACs (RFC §3.3): cA = MAC(KcA, TT), cB = MAC(KcB, TT).
  const cA = hmac(sha256, kcA, TT);
  const cB = hmac(sha256, kcB, TT);

  const confirm = state.role === "A" ? cA : cB;
  const expectedPeer = state.role === "A" ? cB : cA;

  return {
    ke,
    confirm,
    verifyPeer: (peerConfirm) => timingSafeEqual(peerConfirm, expectedPeer),
    transcript: TT,
    ka,
    kcA,
    kcB,
    cA,
    cB,
  };
}

// deriveW maps a low-entropy code to the password scalar w (RFC §3.3:
// w = MHF(pw) mod p). We use scrypt (memory-hard, RFC §3.2 recommendation) to
// slow offline brute force, then reduce mod the group order. `salt` should be a
// value both parties share (e.g. the handshake id); it is not secret.
//
// NOTE: this derivation is app-specific and NOT covered by the RFC test
// vectors (which supply w directly). Keep it identical on both peers.
export function deriveW(code: string, salt: Uint8Array): bigint {
  const pw = utf8(code.normalize("NFKC"));
  // 48 bytes (= |p| + 16) of MHF output, reduced mod n to limit modulo bias
  // (NIST SP 800-56A guidance, RFC §3.3).
  const out = scrypt(pw, salt, { N: 1 << 14, r: 8, p: 1, dkLen: SCALAR_BYTES + 16 });
  return bytesToBigBE(out) % ORDER;
}

// ── helpers ─────────────────────────────────────────────────────────────────

// mul multiplies a point by a scalar, returning the identity for scalar 0
// (noble's multiply rejects 0).
function mul(point: InstanceType<typeof Point>, k: bigint): InstanceType<typeof Point> {
  return k === 0n ? Point.ZERO : point.multiply(k);
}

function randomScalar(): bigint {
  // 48 random bytes reduced mod n (NIST SP 800-56A bias reduction, RFC §7).
  const b = new Uint8Array(SCALAR_BYTES + 16);
  crypto.getRandomValues(b);
  let s = bytesToBigBE(b) % ORDER;
  if (s === 0n) s = 1n; // negligible probability; keep scalar in [1, n)
  return s;
}

// lv prefixes a byte string with its 8-byte little-endian length (RFC §3.1).
function lv(b: Uint8Array): Uint8Array {
  const len = new Uint8Array(8);
  let n = BigInt(b.length);
  for (let i = 0; i < 8; i++) {
    len[i] = Number(n & 0xffn);
    n >>= 8n;
  }
  return concat(len, b);
}

function concat(...parts: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const p of parts) total += p.length;
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

function utf8(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

function bytesToBigBE(b: Uint8Array): bigint {
  let n = 0n;
  for (const byte of b) n = (n << 8n) | BigInt(byte);
  return n;
}

function bigToBytesBE(n: bigint, length: number): Uint8Array {
  const out = new Uint8Array(length);
  for (let i = length - 1; i >= 0; i--) {
    out[i] = Number(n & 0xffn);
    n >>= 8n;
  }
  return out;
}

function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}
