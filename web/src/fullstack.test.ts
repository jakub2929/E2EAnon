// Full-stack integration test (Phase 6): spawns the real Go relay and drives
// multiple real clients (using the actual crypto / SPAKE2 / handshake modules)
// through the complete lifecycle: invites + SPAKE2 + X25519 pubkey exchange +
// roster replication + per-member room-key delivery + rotation on join/leave +
// ownership transfer + kick.
//
// Skips automatically when the Go toolchain is unavailable.

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { spawn, spawnSync, ChildProcess } from "node:child_process";
import { HandshakeSession } from "./handshake";
import {
  KeyPair,
  RoomKey,
  bytesToB64url,
  b64urlToBytes,
  decryptMessage,
  encryptMessage,
  generateKeyPair,
  generateRoomKey,
  openRoomKey,
  openUnderKe,
  sealRoomKey,
  sealUnderKe,
} from "./crypto";

const GO = process.env.GO_BIN || "/opt/homebrew/bin/go";
const haveGo = spawnSync(GO, ["version"], { encoding: "utf8" }).status === 0;
const PORT = 8143;
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
let proc: ChildProcess | undefined;

interface HsRec {
  hs: HandshakeSession;
  role: "owner" | "joiner";
  joinerMemberId?: string;
  ke?: Uint8Array;
  pendingKeyDeliver?: string;
}

// A faithful test client mirroring the browser client's Phase 6 protocol logic.
class Client {
  ws: WebSocket;
  kp: KeyPair = generateKeyPair();
  keys: RoomKey[] = [];
  memberId = "";
  ownerId = "";
  role: "owner" | "member" = "member";
  firstOwnerPub: Uint8Array | null = null;
  pendingInvites = new Map<string, string>();
  handshakes = new Map<string, HsRec>();
  memberPubs = new Map<string, Uint8Array>();
  knownMembers = new Set<string>();
  inbox: string[] = [];
  closedReason: string | null = null;
  lastError: string | null = null;
  isIn = false;
  entered: Promise<void>;
  private enteredResolve!: () => void;
  private inviteResolvers: ((v: { token: string; code: string }) => void)[] = [];
  private pendingJoinCode: string | null = null;

  constructor(private sessionId = "") {
    this.entered = new Promise((r) => (this.enteredResolve = r));
    this.ws = new WebSocket(`ws://127.0.0.1:${PORT}/ws`);
    this.ws.onmessage = (e: MessageEvent) => this.onMessage(JSON.parse(e.data as string));
  }
  private open() {
    return new Promise<void>((res) => {
      if (this.ws.readyState === WebSocket.OPEN) res();
      else this.ws.onopen = () => res();
    });
  }
  private send(m: unknown) {
    this.ws.send(JSON.stringify(m));
  }
  async create(nick: string) {
    await this.open();
    this.keys = [generateRoomKey()];
    this.send({ type: "create", nick, session: this.sessionId });
  }
  async join(token: string, code: string, nick: string) {
    await this.open();
    this.pendingJoinCode = code;
    this.send({ type: "redeem", token, nick, session: this.sessionId });
  }
  leave() {
    this.send({ type: "leave" });
  }
  invite(): Promise<{ token: string; code: string }> {
    return new Promise((res) => {
      this.inviteResolvers.push(res);
      this.send({ type: "invite" });
    });
  }
  msg(text: string) {
    this.send({ type: "msg", body: encryptMessage(this.keys[0], text) });
  }
  transfer(target: string) {
    this.send({ type: "transfer", target });
  }
  kick(target: string) {
    this.send({ type: "kick", target });
  }
  close() {
    this.ws.close();
  }

  private onMessage(m: any) {
    switch (m.type) {
      case "welcome":
        this.memberId = m.memberId ?? this.memberId;
        this.ownerId = ownerIdOf(m.members ?? []);
        this.role = this.ownerId === this.memberId ? "owner" : "member";
        if (this.role === "owner") this.knownMembers = new Set((m.members ?? []).map((x: any) => x.id));
        if (this.firstOwnerPub && this.ownerId) this.memberPubs.set(this.ownerId, this.firstOwnerPub);
        this.isIn = true;
        this.enteredResolve();
        break;
      case "error":
        this.lastError = m.reason ?? "error";
        break;
      case "presence":
        this.onPresence(m.members ?? []);
        break;
      case "chat": {
        const t = this.decryptAny(m.body);
        if (t !== null) this.inbox.push(t);
        break;
      }
      case "invite_created": {
        const code = randomCode();
        this.pendingInvites.set(m.token, code);
        this.inviteResolvers.shift()?.({ token: m.token, code });
        break;
      }
      case "invite_redeemed":
        this.onInviteRedeemed(m);
        break;
      case "redeem_ok":
        this.onRedeemOk(m);
        break;
      case "pake":
        this.handshakes.get(m.handshake)?.hs.onData(m.data);
        break;
      case "member_key":
        this.onMemberKey(m);
        break;
      case "key_deliver":
        this.onKeyDeliver(m);
        break;
      case "rekey":
        this.onRekey(m);
        break;
      case "roster":
        this.applyRoster(m.data);
        break;
      case "room_closed":
        this.closedReason = m.reason ?? "closed";
        break;
    }
  }

  private onInviteRedeemed(m: any) {
    const code = this.pendingInvites.get(m.token);
    if (!code) return;
    this.pendingInvites.delete(m.token);
    const hsId = m.handshake;
    const rec: HsRec = {
      role: "owner",
      joinerMemberId: m.memberId,
      hs: new HandshakeSession(
        "A",
        code,
        hsId,
        (data) => this.send({ type: "pake", handshake: hsId, data }),
        (ke) => {
          rec.ke = ke;
          this.send({ type: "member_key", handshake: hsId, data: sealUnderKe(ke, this.kp.pub) });
        },
        () => this.handshakes.delete(hsId),
      ),
    };
    this.handshakes.set(hsId, rec);
  }

  private onRedeemOk(m: any) {
    this.memberId = m.memberId ?? "";
    const hsId = m.handshake;
    const code = this.pendingJoinCode!;
    const rec: HsRec = {
      role: "joiner",
      hs: new HandshakeSession(
        "B",
        code,
        hsId,
        (data) => this.send({ type: "pake", handshake: hsId, data }),
        (ke) => {
          rec.ke = ke;
          this.send({ type: "member_key", handshake: hsId, data: sealUnderKe(ke, this.kp.pub) });
        },
        () => {},
      ),
    };
    this.handshakes.set(hsId, rec);
  }

  private onMemberKey(m: any) {
    const rec = this.handshakes.get(m.handshake);
    if (!rec || !rec.ke) return;
    const peerPub = openUnderKe(rec.ke, m.data);
    if (rec.role === "owner") {
      this.memberPubs.set(rec.joinerMemberId!, peerPub);
      this.rotateForJoin(rec.joinerMemberId!, peerPub);
      this.handshakes.delete(m.handshake);
    } else {
      this.firstOwnerPub = peerPub;
      if (rec.pendingKeyDeliver) this.finishJoin(m.handshake, rec, rec.pendingKeyDeliver);
    }
  }

  private rotateForJoin(joinerId: string, joinerPub: Uint8Array) {
    const newKey = generateRoomKey();
    this.keys.unshift(newKey);
    const hsId = [...this.handshakes.entries()].find(([, r]) => r.joinerMemberId === joinerId)?.[0];
    if (hsId)
      this.send({ type: "key_deliver", handshake: hsId, data: sealRoomKey(this.kp.priv, joinerPub, newKey) });
    for (const id of this.knownMembers) {
      if (id === this.memberId || id === joinerId) continue;
      this.rekeyMember(id, newKey);
    }
    this.knownMembers.add(joinerId);
  }

  private onKeyDeliver(m: any) {
    const rec = this.handshakes.get(m.handshake);
    if (!rec) return;
    if (!this.firstOwnerPub) {
      rec.pendingKeyDeliver = m.data;
      return;
    }
    this.finishJoin(m.handshake, rec, m.data);
  }

  private finishJoin(hsId: string, _rec: HsRec, data: string) {
    this.keys.unshift(openRoomKey(this.kp.priv, this.firstOwnerPub!, data));
    this.handshakes.delete(hsId);
    this.send({ type: "enter", handshake: hsId });
  }

  private onRekey(m: any) {
    const ownerPub = this.memberPubs.get(this.ownerId);
    if (!ownerPub) return;
    try {
      this.keys.unshift(openRoomKey(this.kp.priv, ownerPub, m.data));
    } catch {
      /* not for us */
    }
  }

  private applyRoster(data: string) {
    const json = this.decryptAny(data);
    if (!json) return;
    const obj = JSON.parse(json) as Record<string, string>;
    for (const [id, b64] of Object.entries(obj)) this.memberPubs.set(id, b64urlToBytes(b64));
  }

  private broadcastRoster() {
    if (this.role !== "owner" || !this.keys.length) return;
    const obj: Record<string, string> = { [this.memberId]: bytesToB64url(this.kp.pub) };
    for (const [id, pub] of this.memberPubs) obj[id] = bytesToB64url(pub);
    this.send({ type: "roster", data: encryptMessage(this.keys[0], JSON.stringify(obj)) });
  }

  private onPresence(members: { id: string; role: string }[]) {
    const newOwnerId = ownerIdOf(members);
    const becameOwner = newOwnerId === this.memberId && this.role !== "owner";
    this.ownerId = newOwnerId;
    this.role = newOwnerId === this.memberId ? "owner" : "member";
    if (this.role !== "owner") return;
    const current = new Set(members.map((x) => x.id));
    if (becameOwner) this.knownMembers = new Set(current);
    const removed = [...this.knownMembers].filter((id) => !current.has(id));
    if (removed.length > 0) {
      for (const id of removed) {
        this.knownMembers.delete(id);
        this.memberPubs.delete(id);
      }
      const newKey = generateRoomKey();
      this.keys.unshift(newKey);
      for (const id of current) if (id !== this.memberId) this.rekeyMember(id, newKey);
    }
    this.knownMembers = current;
    this.broadcastRoster();
  }

  private rekeyMember(memberId: string, newKey: RoomKey) {
    const pub = this.memberPubs.get(memberId);
    if (pub) this.send({ type: "rekey", target: memberId, data: sealRoomKey(this.kp.priv, pub, newKey) });
  }

  private decryptAny(body: string): string | null {
    for (const k of this.keys) {
      try {
        return decryptMessage(k, body);
      } catch {
        /* try next */
      }
    }
    return null;
  }
}

function ownerIdOf(members: { id: string; role: string }[]): string {
  return members.find((m) => m.role === "owner")?.id ?? "";
}
function randomCode(): string {
  const a = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const b = new Uint8Array(10);
  crypto.getRandomValues(b);
  return Array.from(b, (x) => a[x % a.length]).join("");
}
async function addMember(owner: Client, nick: string): Promise<Client> {
  const inv = await owner.invite();
  const c = new Client();
  await c.join(inv.token, inv.code, nick);
  await c.entered;
  await sleep(150); // let rotation + roster propagate
  return c;
}

describe.skipIf(!haveGo)("full-stack Phase 6: rotation, transfer, kick", () => {
  beforeAll(async () => {
    const build = spawnSync(GO, ["build", "-o", "/tmp/anonchat-e2e", "./cmd/anonchat"], {
      cwd: "../server",
      encoding: "utf8",
    });
    if (build.status !== 0) throw new Error("go build failed: " + build.stderr);
    proc = spawn("/tmp/anonchat-e2e", [], {
      env: { ...process.env, PORT: String(PORT), ALLOWED_ORIGINS: "*", LOG_LEVEL: "error" },
      stdio: "ignore",
    });
    for (let i = 0; i < 50; i++) {
      try {
        if ((await fetch(`http://127.0.0.1:${PORT}/health`)).ok) return;
      } catch {
        /* not up */
      }
      await sleep(100);
    }
    throw new Error("server did not become healthy");
  }, 30_000);

  afterAll(() => proc?.kill());

  it("rotates on join and on leave (forward secrecy)", async () => {
    const alice = new Client();
    await alice.create("alice");
    await alice.entered;
    const bob = await addMember(alice, "bob");
    const carol = await addMember(alice, "carol");

    alice.msg("all three");
    await sleep(200);
    expect(bob.inbox).toContain("all three");
    expect(carol.inbox).toContain("all three");

    carol.close(); // leave -> rotation
    await sleep(300);
    alice.msg("after carol left");
    await sleep(200);
    expect(bob.inbox).toContain("after carol left");

    alice.close();
    bob.close();
  }, 25_000);

  it("transfers ownership; the new owner can re-key after the old owner leaves", async () => {
    const alice = new Client();
    await alice.create("alice");
    await alice.entered;
    const bob = await addMember(alice, "bob");
    const carol = await addMember(alice, "carol");

    // Alice hands ownership to Bob.
    alice.transfer(bob.memberId);
    await sleep(250);
    expect(bob.role).toBe("owner");
    expect(alice.role).toBe("member");

    // Old owner Alice leaves -> Bob (new owner) must rotate and re-key Carol,
    // using the roster Bob holds from when it was a member.
    alice.close();
    await sleep(350);
    bob.msg("bob is owner now");
    await sleep(250);
    expect(carol.inbox).toContain("bob is owner now");

    bob.close();
    carol.close();
  }, 25_000);

  it("enforces one room per session id over the wire", async () => {
    const alice = new Client("tabA");
    await alice.create("alice");
    await alice.entered;

    // A second connection reusing the same session id is rejected.
    const dup = new Client("tabA");
    await dup.create("dup");
    await sleep(250);
    expect(dup.isIn).toBe(false);
    expect(dup.lastError).toBe("already_in_room");
    dup.close();

    // Leaving frees the session; a fresh connection with tabA can then create.
    alice.leave();
    let freed = false;
    for (let i = 0; i < 20 && !freed; i++) {
      const c = new Client("tabA");
      await c.create("again");
      await sleep(150);
      freed = c.isIn;
      c.close();
      if (!freed) await sleep(50);
    }
    expect(freed).toBe(true);
    alice.close();
  }, 15_000);

  it("kick removes a member and the kicked client is told", async () => {
    const alice = new Client();
    await alice.create("alice");
    await alice.entered;
    const bob = await addMember(alice, "bob");
    const carol = await addMember(alice, "carol");

    alice.kick(carol.memberId);
    await sleep(300);
    expect(carol.closedReason).toBe("kicked");

    // After the kick, Alice rotated; Bob still gets messages.
    alice.msg("carol gone");
    await sleep(200);
    expect(bob.inbox).toContain("carol gone");

    alice.close();
    bob.close();
  }, 25_000);
});
