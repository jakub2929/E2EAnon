// Handshake orchestration: drives one SPAKE2 exchange (spake2.ts) over the
// relay between the owner (role A) and a joiner (role B), with mutual key
// confirmation, and yields the confirmed shared secret `ke`.
//
// Wire payload (the `data` field of a `pake` frame), relayed opaquely by the
// server: JSON { t: "m" | "c", d: base64 } where "m" is the SPAKE2 message
// point and "c" is the key-confirmation MAC.

import { Role, Spake2Result, Spake2State, deriveW, finish, start } from "./spake2";

const enc = new TextEncoder();

interface Frame {
  t: "m" | "c";
  d: string;
}

export class HandshakeSession {
  private state: Spake2State;
  private result?: Spake2Result;
  private pendingPeerConfirm?: Uint8Array;
  private done = false;

  // role: "A" = owner, "B" = joiner. The salt and identities are derived from
  // the (shared) handshake id, binding the transcript to this exchange.
  constructor(
    role: Role,
    code: string,
    handshakeId: string,
    private sendPake: (data: string) => void,
    private onConfirmed: (ke: Uint8Array) => void,
    private onFail: (reason: string) => void,
  ) {
    const w = deriveW(code, enc.encode(handshakeId));
    const idA = enc.encode("anonchat-owner:" + handshakeId);
    const idB = enc.encode("anonchat-joiner:" + handshakeId);
    const s = start(role, w, idA, idB);
    this.state = s.state;
    this.sendPake(frame("m", s.message));
  }

  // onData feeds one relayed `pake` payload from the peer.
  onData(dataStr: string): void {
    if (this.done) return;
    let f: Frame;
    try {
      f = JSON.parse(dataStr) as Frame;
    } catch {
      return;
    }
    if (f.t === "m") this.handlePoint(unb64(f.d));
    else if (f.t === "c") this.handleConfirm(unb64(f.d));
  }

  private handlePoint(peerPoint: Uint8Array): void {
    if (this.result) return;
    try {
      this.result = finish(this.state, peerPoint);
    } catch {
      this.fail("handshake_failed");
      return;
    }
    this.sendPake(frame("c", this.result.confirm));
    if (this.pendingPeerConfirm) {
      const pc = this.pendingPeerConfirm;
      this.pendingPeerConfirm = undefined;
      this.verify(pc);
    }
  }

  private handleConfirm(peerConfirm: Uint8Array): void {
    if (!this.result) {
      this.pendingPeerConfirm = peerConfirm; // arrived before our point
      return;
    }
    this.verify(peerConfirm);
  }

  private verify(peerConfirm: Uint8Array): void {
    if (!this.result) return;
    if (!this.result.verifyPeer(peerConfirm)) {
      this.fail("handshake_failed");
      return;
    }
    this.done = true;
    this.onConfirmed(this.result.ke.slice());
  }

  private fail(reason: string): void {
    if (this.done) return;
    this.done = true;
    this.onFail(reason);
  }
}

function frame(t: "m" | "c", b: Uint8Array): string {
  return JSON.stringify({ t, d: b64(b) } as Frame);
}

function b64(b: Uint8Array): string {
  let s = "";
  for (const x of b) s += String.fromCharCode(x);
  return btoa(s);
}

function unb64(s: string): Uint8Array {
  const bin = atob(s);
  const o = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) o[i] = bin.charCodeAt(i);
  return o;
}
