import { describe, it, expect } from "vitest";
import { HandshakeSession } from "./handshake";
import {
  generateKeyPair,
  generateRoomKey,
  openRoomKey,
  openUnderKe,
  sealRoomKey,
  sealUnderKe,
} from "./crypto";

// Wire two HandshakeSessions together through in-memory queues, simulating the
// relay, and pump until quiescent. Returns the confirmed keys (or fail flags).
function run(codeA: string, codeB: string) {
  const hsId = "handshake-id-123";
  const toB: string[] = [];
  const toA: string[] = [];
  let keA: Uint8Array | null = null;
  let keB: Uint8Array | null = null;
  let failA = false;
  let failB = false;

  const a = new HandshakeSession(
    "A",
    codeA,
    hsId,
    (d) => toB.push(d),
    (ke) => (keA = ke),
    () => (failA = true),
  );
  const b = new HandshakeSession(
    "B",
    codeB,
    hsId,
    (d) => toA.push(d),
    (ke) => (keB = ke),
    () => (failB = true),
  );
  void a;
  void b;

  for (let i = 0; i < 20 && (toA.length || toB.length); i++) {
    for (const d of toA.splice(0)) a.onData(d);
    for (const d of toB.splice(0)) b.onData(d);
  }
  return { keA, keB, failA, failB };
}

const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");

describe("handshake orchestration (owner A <-> joiner B)", () => {
  it("matching codes: both confirm and agree on ke", () => {
    const { keA, keB, failA, failB } = run("ABCDE12345", "ABCDE12345");
    expect(failA).toBe(false);
    expect(failB).toBe(false);
    expect(keA).not.toBeNull();
    expect(keB).not.toBeNull();
    expect(hex(keA!)).toBe(hex(keB!));
  });

  it("mismatched codes: both fail key confirmation, no shared key", () => {
    const { keA, keB, failA, failB } = run("ABCDE12345", "ZZZZZ99999");
    expect(keA).toBeNull();
    expect(keB).toBeNull();
    expect(failA).toBe(true);
    expect(failB).toBe(true);
  });

  it("X25519 pubkeys exchanged under Ke deliver the room key (Phase 5 flow)", () => {
    const { keA, keB } = run("SAME-CODE0", "SAME-CODE0");
    const owner = generateKeyPair();
    const joiner = generateKeyPair();

    // Exchange public keys sealed under Ke (prevents server MITM).
    const ownerPub = openUnderKe(keB!, sealUnderKe(keA!, owner.pub));
    const joinerPub = openUnderKe(keA!, sealUnderKe(keB!, joiner.pub));

    // Owner seals the room key to the joiner's pubkey; joiner opens it.
    const roomKey = generateRoomKey();
    const sealed = sealRoomKey(owner.priv, joinerPub, roomKey);
    const received = openRoomKey(joiner.priv, ownerPub, sealed);
    expect(hex(received)).toBe(hex(roomKey));
  });

  it("a third party cannot open a room key sealed to someone else", () => {
    const owner = generateKeyPair();
    const joiner = generateKeyPair();
    const attacker = generateKeyPair();
    const sealed = sealRoomKey(owner.priv, joiner.pub, generateRoomKey());
    expect(() => openRoomKey(attacker.priv, owner.pub, sealed)).toThrow();
  });
});
