// End-to-end message crypto (Phase 3).
//
// Messages are sealed in the browser with XChaCha20-Poly1305 (AEAD) under a
// symmetric 256-bit room key. The server only ever relays the opaque envelope
// and can neither read nor derive the key.
//
// PHASE 3 PLACEHOLDER: the room key is shared out-of-band via the invite link's
// URL fragment (never sent to the server). This is replaced in Phases 4–5 by a
// SPAKE2-secured channel + per-member X25519 key distribution with rotation.

import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { x25519 } from "@noble/curves/ed25519.js";

const VERSION = 0x01; // envelope format version
const KEY_LEN = 32; // XChaCha20 key bytes
const NONCE_LEN = 24; // XChaCha20 nonce bytes
const TAG_LEN = 16; // Poly1305 tag bytes

export type RoomKey = Uint8Array; // 32 bytes, RAM only

// generateRoomKey returns a fresh random 256-bit room key.
export function generateRoomKey(): RoomKey {
  const k = new Uint8Array(KEY_LEN);
  crypto.getRandomValues(k);
  return k;
}

// wipeKey zeroes key material in place (best-effort; JS GC still applies).
export function wipeKey(key: RoomKey | null): void {
  if (key) key.fill(0);
}

// encryptMessage seals a UTF-8 string into a base64 envelope:
//   base64( version(1) || nonce(24) || ciphertext+tag )
export function encryptMessage(key: RoomKey, plaintext: string): string {
  const nonce = new Uint8Array(NONCE_LEN);
  crypto.getRandomValues(nonce);
  const pt = new TextEncoder().encode(plaintext);
  const ct = xchacha20poly1305(key, nonce).encrypt(pt);

  const out = new Uint8Array(1 + NONCE_LEN + ct.length);
  out[0] = VERSION;
  out.set(nonce, 1);
  out.set(ct, 1 + NONCE_LEN);
  return bytesToB64(out);
}

// decryptMessage opens an envelope produced by encryptMessage. Throws on a bad
// version, malformed input, or authentication failure (tampered/wrong key).
export function decryptMessage(key: RoomKey, envelope: string): string {
  const buf = b64ToBytes(envelope);
  if (buf.length < 1 + NONCE_LEN + TAG_LEN) throw new Error("ciphertext too short");
  if (buf[0] !== VERSION) throw new Error(`unsupported envelope version ${buf[0]}`);
  const nonce = buf.subarray(1, 1 + NONCE_LEN);
  const ct = buf.subarray(1 + NONCE_LEN);
  const pt = xchacha20poly1305(key, nonce).decrypt(ct); // throws on auth failure
  return new TextDecoder().decode(pt);
}

// ── X25519 per-member keys + key distribution (Phase 5) ─────────────────────
//
// Each client holds a static X25519 keypair (RAM only). Public keys are
// exchanged over the SPAKE2 channel (sealed under Ke, so the server cannot
// substitute them). The owner then distributes the room key to each member by
// sealing it under a PAIRWISE static ECDH secret (owner_priv x member_pub) —
// authenticated (only those two parties share it) and stable across rotations.

export interface KeyPair {
  pub: Uint8Array; // 32-byte X25519 public key
  priv: Uint8Array; // 32-byte X25519 secret key (RAM only)
}

export function generateKeyPair(): KeyPair {
  const priv = new Uint8Array(32);
  crypto.getRandomValues(priv);
  return { priv, pub: x25519.getPublicKey(priv) };
}

const EMPTY = new Uint8Array(0);
const KEYX_INFO = new TextEncoder().encode("anonchat-keyx-v1");
const REKEY_INFO = new TextEncoder().encode("anonchat-rekey-v1");

// sealUnderKe / openUnderKe protect a public key in transit under the SPAKE2
// secret Ke (16 bytes), expanded via HKDF. Prevents a malicious relay from
// MITM-substituting public keys during the handshake.
export function sealUnderKe(ke: Uint8Array, bytes: Uint8Array): string {
  return encryptMessage(hkdf(sha256, ke, EMPTY, KEYX_INFO, KEY_LEN), bytesToB64url(bytes));
}

export function openUnderKe(ke: Uint8Array, env: string): Uint8Array {
  return b64urlToBytes(decryptMessage(hkdf(sha256, ke, EMPTY, KEYX_INFO, KEY_LEN), env));
}

// pairKey derives the symmetric wrap key shared by owner and member from their
// static X25519 keys.
function pairKey(myPriv: Uint8Array, theirPub: Uint8Array): RoomKey {
  const shared = x25519.getSharedSecret(myPriv, theirPub);
  return hkdf(sha256, shared, EMPTY, REKEY_INFO, KEY_LEN);
}

export function sealRoomKey(myPriv: Uint8Array, theirPub: Uint8Array, roomKey: RoomKey): string {
  return encryptMessage(pairKey(myPriv, theirPub), keyToString(roomKey));
}

export function openRoomKey(myPriv: Uint8Array, theirPub: Uint8Array, env: string): RoomKey {
  return keyFromString(decryptMessage(pairKey(myPriv, theirPub), env));
}

export function bytesToB64url(b: Uint8Array): string {
  return b64ToB64url(bytesToB64(b));
}

export function b64urlToBytes(s: string): Uint8Array {
  return b64ToBytes(b64urlToB64(s));
}

// ── Key <-> URL-fragment encoding (base64url, no padding) ───────────────────

export function keyToString(key: RoomKey): string {
  return b64ToB64url(bytesToB64(key));
}

export function keyFromString(s: string): RoomKey {
  const k = b64ToBytes(b64urlToB64(s));
  if (k.length !== KEY_LEN) throw new Error("invalid room key length");
  return k;
}

// ── base64 helpers ──────────────────────────────────────────────────────────

function bytesToB64(b: Uint8Array): string {
  let s = "";
  for (let i = 0; i < b.length; i++) s += String.fromCharCode(b[i]);
  return btoa(s);
}

function b64ToBytes(s: string): Uint8Array {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function b64ToB64url(s: string): string {
  return s.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function b64urlToB64(s: string): string {
  const t = s.replace(/-/g, "+").replace(/_/g, "/");
  const pad = t.length % 4 === 0 ? "" : "=".repeat(4 - (t.length % 4));
  return t + pad;
}
