// AnonChat browser client — Phase 6 (ownership transfer + hardened teardown).
//
// Builds on Phase 5 (per-member X25519 keys + forward-secret rotation). Adds:
//  - A replicated member→pubkey ROSTER, broadcast by the owner encrypted under
//    the room key, so EVERY client can become owner and re-key the room.
//  - Ownership TRANSFER (moves invite/kick/rekey rights) and KICK.
//  - Members unseal rekeys using the CURRENT owner's pubkey (from the roster),
//    so rotation keeps working across ownership changes.
//  - Explicit zeroing of all key material on teardown.
//
// No message content or key material is written to browser storage.

import { ClientMsg, MemberInfo, ServerMsg, wsURL } from "./protocol";
import {
  KeyPair,
  RoomKey,
  bytesToB64url,
  b64urlToBytes,
  decryptMessage,
  encryptMessage,
  generateKeyPair,
  generateRoomKey,
  keyId,
  openBytes,
  openRoomKey,
  openUnderKe,
  sealBytes,
  sealRoomKey,
  sealUnderKe,
  wipeKey,
} from "./crypto";
import { HandshakeSession } from "./handshake";

const MAX_KEPT_KEYS = 5;
// Plaintext bytes per encrypted file chunk (each chunk is independently sealed).
const CHUNK_SIZE = 64 * 1024;

interface FileMeta {
  name: string;
  type: string;
  size: number;
  chunks: number;
}

// In-progress inbound file transfer (reassembled in RAM, then rendered).
interface Incoming {
  key: RoomKey;
  meta: FileMeta;
  nick: string;
  parts: (Uint8Array | undefined)[];
  received: number;
}

// A live file message element with a progress bar, finalized into an
// image/download once the transfer completes (or marked failed).
interface FileMsgHandle {
  li: HTMLLIElement;
  status: HTMLElement;
  label: HTMLElement;
  fill: HTMLElement;
  meta: FileMeta;
  mine: boolean;
}

// Client-side per-file cap (Phase 1). The server enforces its own cap in Phase 2.
const MAX_FILE_BYTES = 10 * 1024 * 1024; // 10 MiB

// Ephemeral per-tab session id (v2): random, in-memory only, regenerated on
// every page load. Sent on create/redeem so the server can enforce one room per
// session. NOT persisted anywhere; not an identity.
const SESSION_ID = (() => {
  const b = new Uint8Array(16);
  crypto.getRandomValues(b);
  return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
})();

interface HsRecord {
  hs: HandshakeSession;
  role: "owner" | "joiner";
  joinerMemberId?: string;
  ke?: Uint8Array;
  pendingKeyDeliver?: string;
}

interface Session {
  ws: WebSocket;
  room: string;
  memberId: string;
  role: "owner" | "member";
  ownerId: string; // current owner's member id
  keys: RoomKey[]; // newest first
  kp: KeyPair; // our static X25519 keypair
  pendingInvites: Map<string, string>; // owner: token -> code
  handshakes: Map<string, HsRecord>;
  memberPubs: Map<string, Uint8Array>; // memberId -> static pub (all clients)
  knownMembers: Set<string>; // owner: current ids (leave detection)
  firstOwnerPub: Uint8Array | null; // joiner: owner pub from the handshake
  lastMembers: MemberInfo[]; // latest presence (for the owner-leave dialog)
  incoming: Map<string, Incoming>; // in-progress inbound file transfers
  fileMsgs: Map<string, FileMsgHandle>; // transfer id -> live message element
  objectUrls: string[]; // blob URLs for rendered files; revoked on teardown
}
let session: Session | null = null;
let pendingJoin: { token: string; code: string } | null = null;
// True when the socket is being closed deliberately (user leave / room ended),
// so onClose can distinguish a clean exit from an unexpected drop.
let intentionalClose = false;

// Locally staged attachment (Phase 1: previewed only, not sent yet). The object
// URL is revoked on remove / send / teardown so no blob bytes linger.
let staged: { file: File; url: string } | null = null;

// ── DOM helpers ─────────────────────────────────────────────────────────────
const $ = <T extends HTMLElement>(id: string): T => {
  const el = document.getElementById(id);
  if (!el) throw new Error(`missing element #${id}`);
  return el as T;
};
const lobby = $("lobby");
const room = $("room");
const lobbyError = $("lobby-error");
const lobbyStatus = $("lobby-status");
const lobbyStats = $("lobby-stats");
const roomNotice = $("room-notice");
const nickInput = $<HTMLInputElement>("nick");
const roomInput = $<HTMLInputElement>("room-input");
const roomIdEl = $("room-id");
const memberList = $("members");
const memberCount = $("member-count");
const messageList = $("messages");
const msgInput = $<HTMLInputElement>("msg-input");
const inviteBtn = $<HTMLButtonElement>("invite-btn");
const inviteBox = $("invite-box");
const inviteLink = $<HTMLInputElement>("invite-link");
const fileInput = $<HTMLInputElement>("file-input");
const attachPreview = $("attach-preview");
const modal = $("modal");
const modalTitle = $("modal-title");
const modalBody = $("modal-body");
const modalActions = $("modal-actions");

// ── Modal ───────────────────────────────────────────────────────────────────
interface ModalButton {
  label: string;
  cls?: string;
  onClick?: () => void;
}

function openModal(title: string, body: Node | string, buttons: ModalButton[]): void {
  modalTitle.textContent = title;
  modalBody.replaceChildren(typeof body === "string" ? document.createTextNode(body) : body);
  modalActions.replaceChildren();
  for (const b of buttons) {
    const btn = document.createElement("button");
    btn.textContent = b.label;
    if (b.cls) btn.className = b.cls;
    btn.addEventListener("click", () => {
      closeModal();
      b.onClick?.();
    });
    modalActions.appendChild(btn);
  }
  modal.classList.remove("hidden");
}

function closeModal(): void {
  modal.classList.add("hidden");
  modalBody.replaceChildren();
}

// ── Connection lifecycle ────────────────────────────────────────────────────

// closeCurrentSession tears down any active session and resolves once its
// WebSocket has actually closed, so the server has a chance to release the old
// room/session before we reuse the same SESSION_ID. Resolves immediately if
// there is no session; has a safety timeout so it never hangs.
function closeCurrentSession(): Promise<void> {
  const s = session;
  if (!s) return Promise.resolve();
  return new Promise<void>((resolve) => {
    let done = false;
    const finish = () => {
      if (done) return;
      done = true;
      resolve();
    };
    try {
      s.ws.addEventListener("close", finish, { once: true });
      teardown(false); // wipes state and closes the ws -> fires "close"
    } catch {
      finish();
    }
    setTimeout(finish, 2000); // safety: never block forever
  });
}

// connect opens a fresh WebSocket for `hello`. It first AWAITS the close of any
// previous session's socket (one ws per tab) — fixes the latent abandoned-socket
// case and avoids reusing SESSION_ID while the old connection is still live.
async function connect(hello: ClientMsg): Promise<void> {
  lobbyError.textContent = "";
  await closeCurrentSession();
  const ws = new WebSocket(wsURL());
  ws.addEventListener("open", () => ws.send(JSON.stringify(hello)));
  ws.addEventListener("message", (ev) => onMessage(ev.data));
  ws.addEventListener("close", () => onClose());
  ws.addEventListener("error", () => {
    if (!session?.room) lobbyError.textContent = "Connection failed.";
  });
  session = {
    ws,
    room: "",
    memberId: "",
    role: "member",
    ownerId: "",
    keys: [],
    kp: generateKeyPair(),
    pendingInvites: new Map(),
    handshakes: new Map(),
    memberPubs: new Map(),
    knownMembers: new Set(),
    firstOwnerPub: null,
    lastMembers: [],
    incoming: new Map(),
    fileMsgs: new Map(),
    objectUrls: [],
  };
}

function send(msg: ClientMsg): void {
  if (session?.ws.readyState === WebSocket.OPEN) session.ws.send(JSON.stringify(msg));
}

function onMessage(data: unknown): void {
  if (typeof data !== "string") return;
  let msg: ServerMsg;
  try {
    msg = JSON.parse(data) as ServerMsg;
  } catch {
    return;
  }
  switch (msg.type) {
    case "welcome":
      onWelcome(msg);
      break;
    case "presence":
      onPresence(msg.members ?? []);
      break;
    case "chat":
      addMessage(msg.nick ?? "?", decryptAny(msg.body ?? "") ?? "[unable to decrypt]", false);
      break;
    case "invite_created":
      onInviteCreated(msg);
      break;
    case "invite_redeemed":
      onInviteRedeemed(msg);
      break;
    case "redeem_ok":
      onRedeemOk(msg);
      break;
    case "pake":
      if (msg.handshake && msg.data !== undefined)
        session?.handshakes.get(msg.handshake)?.hs.onData(msg.data);
      break;
    case "member_key":
      onMemberKey(msg);
      break;
    case "key_deliver":
      onKeyDeliver(msg);
      break;
    case "rekey":
      onRekey(msg);
      break;
    case "roster":
      applyRoster(msg.data ?? "");
      break;
    case "file_start":
      onFileStart(msg);
      break;
    case "file_chunk":
      onFileChunk(msg);
      break;
    case "file_end":
      onFileEnd(msg);
      break;
    case "file_abort":
      if (msg.transfer) {
        session?.incoming.delete(msg.transfer);
        failFileMessage(msg.transfer, "transfer aborted");
      }
      break;
    case "room_closed":
      intentionalClose = true; // server ended the room; lobby return is expected
      teardown(true);
      lobbyError.textContent = closeReason(msg.reason);
      break;
    case "error":
      handleError(msg);
      break;
  }
}

function onWelcome(msg: ServerMsg): void {
  if (!session) return;
  session.room = msg.room ?? "";
  session.memberId = msg.memberId ?? session.memberId;
  const members = msg.members ?? [];
  session.ownerId = ownerIdOf(members);
  session.role = session.ownerId === session.memberId ? "owner" : "member";
  if (session.role === "owner") session.knownMembers = new Set(members.map((m) => m.id));
  // Joiner: seed the roster with the owner's pubkey learned during the handshake.
  if (session.firstOwnerPub && session.ownerId) session.memberPubs.set(session.ownerId, session.firstOwnerPub);
  roomIdEl.textContent = session.room;
  inviteBtn.classList.toggle("hidden", session.role !== "owner");
  lobbyStatus.textContent = "";
  renderMembers(members);
  showRoom();
}

function decryptAny(body: string): string | null {
  if (!session) return null;
  for (const k of session.keys) {
    try {
      return decryptMessage(k, body);
    } catch {
      /* try next (rotation in flight) */
    }
  }
  return null;
}

// ── Invite issuance (owner) ─────────────────────────────────────────────────

function onInviteCreated(msg: ServerMsg): void {
  if (!session || !msg.token) return;
  const code = generateCode();
  session.pendingInvites.set(msg.token, code);
  inviteLink.value = buildInviteLink(msg.token, code);
  inviteBox.classList.remove("hidden");
  inviteLink.focus();
  inviteLink.select();
}

function onInviteRedeemed(msg: ServerMsg): void {
  if (!session || !msg.handshake || !msg.token || !msg.memberId) return;
  const code = session.pendingInvites.get(msg.token);
  if (!code) return;
  session.pendingInvites.delete(msg.token);
  const hsId = msg.handshake;
  const rec: HsRecord = {
    role: "owner",
    joinerMemberId: msg.memberId,
    hs: new HandshakeSession(
      "A",
      code,
      hsId,
      (data) => send({ type: "pake", handshake: hsId, data }),
      (ke) => {
        rec.ke = ke;
        send({ type: "member_key", handshake: hsId, data: sealUnderKe(ke, session!.kp.pub) });
      },
      () => session!.handshakes.delete(hsId),
    ),
  };
  session.handshakes.set(hsId, rec);
}

// ── Join handshake (joiner) ─────────────────────────────────────────────────

function onRedeemOk(msg: ServerMsg): void {
  if (!session || !msg.handshake || !pendingJoin) return;
  session.memberId = msg.memberId ?? "";
  const hsId = msg.handshake;
  const code = pendingJoin.code;
  pendingJoin = null;
  lobbyStatus.textContent = "Establishing a secure channel…";
  const rec: HsRecord = {
    role: "joiner",
    hs: new HandshakeSession(
      "B",
      code,
      hsId,
      (data) => send({ type: "pake", handshake: hsId, data }),
      (ke) => {
        rec.ke = ke;
        send({ type: "member_key", handshake: hsId, data: sealUnderKe(ke, session!.kp.pub) });
      },
      () => {
        lobbyError.textContent = "Wrong code or handshake failed.";
        teardown();
      },
    ),
  };
  session.handshakes.set(hsId, rec);
}

function onMemberKey(msg: ServerMsg): void {
  if (!session || !msg.handshake || msg.data === undefined) return;
  const rec = session.handshakes.get(msg.handshake);
  if (!rec || !rec.ke) return;
  let peerPub: Uint8Array;
  try {
    peerPub = openUnderKe(rec.ke, msg.data);
  } catch {
    return;
  }
  if (rec.role === "owner") {
    session.memberPubs.set(rec.joinerMemberId!, peerPub);
    rotateForJoin(rec.joinerMemberId!, peerPub);
    session.handshakes.delete(msg.handshake);
  } else {
    session.firstOwnerPub = peerPub; // used to unseal the first key_deliver
    if (rec.pendingKeyDeliver) finishJoin(msg.handshake, rec, rec.pendingKeyDeliver);
  }
}

function rotateForJoin(joinerId: string, joinerPub: Uint8Array): void {
  if (!session) return;
  const newKey = generateRoomKey();
  pushKey(newKey);
  const hsId = [...session.handshakes.entries()].find(([, r]) => r.joinerMemberId === joinerId)?.[0];
  if (hsId)
    send({ type: "key_deliver", handshake: hsId, data: sealRoomKey(session.kp.priv, joinerPub, newKey) });
  for (const id of session.knownMembers) {
    if (id === session.memberId || id === joinerId) continue;
    rekeyMember(id, newKey);
  }
  session.knownMembers.add(joinerId);
}

function onKeyDeliver(msg: ServerMsg): void {
  if (!session || !msg.handshake || msg.data === undefined) return;
  const rec = session.handshakes.get(msg.handshake);
  if (!rec) return;
  if (!session.firstOwnerPub) {
    rec.pendingKeyDeliver = msg.data;
    return;
  }
  finishJoin(msg.handshake, rec, msg.data);
}

function finishJoin(hsId: string, rec: HsRecord, data: string): void {
  if (!session || !session.firstOwnerPub) return;
  let roomKey: RoomKey;
  try {
    roomKey = openRoomKey(session.kp.priv, session.firstOwnerPub, data);
  } catch {
    lobbyError.textContent = "Failed to receive the room key.";
    teardown();
    return;
  }
  pushKey(roomKey);
  if (rec.ke) wipeKey(rec.ke);
  session.handshakes.delete(hsId);
  send({ type: "enter", handshake: hsId });
}

// rekey: a rotated key sealed to us by the CURRENT owner (from the roster).
function onRekey(msg: ServerMsg): void {
  if (!session || msg.data === undefined) return;
  const ownerPub = session.memberPubs.get(session.ownerId);
  if (!ownerPub) return;
  try {
    pushKey(openRoomKey(session.kp.priv, ownerPub, msg.data));
  } catch {
    /* not for us / stale */
  }
}

// ── Roster replication ──────────────────────────────────────────────────────

// applyRoster (member): decrypt the owner's roster and merge member pubkeys.
function applyRoster(data: string): void {
  if (!session) return;
  const json = decryptAny(data);
  if (!json) return;
  try {
    const obj = JSON.parse(json) as Record<string, string>;
    for (const [id, b64] of Object.entries(obj)) session.memberPubs.set(id, b64urlToBytes(b64));
  } catch {
    /* malformed */
  }
}

// broadcastRoster (owner): publish the full member→pubkey map under the room key.
function broadcastRoster(): void {
  if (!session || session.role !== "owner" || !session.keys.length) return;
  const obj: Record<string, string> = { [session.memberId]: bytesToB64url(session.kp.pub) };
  for (const [id, pub] of session.memberPubs) obj[id] = bytesToB64url(pub);
  send({ type: "roster", data: encryptMessage(session.keys[0], JSON.stringify(obj)) });
}

// ── Presence + owner duties (rotation, roster) ──────────────────────────────

function onPresence(members: MemberInfo[]): void {
  if (!session) return;
  const newOwnerId = ownerIdOf(members);
  const becameOwner = newOwnerId === session.memberId && session.role !== "owner";
  session.ownerId = newOwnerId;
  session.role = newOwnerId === session.memberId ? "owner" : "member";
  inviteBtn.classList.toggle("hidden", session.role !== "owner");
  renderMembers(members);

  if (session.role !== "owner") return;

  const current = new Set(members.map((m) => m.id));
  if (becameOwner) session.knownMembers = new Set(current); // take over cleanly

  const removed = [...session.knownMembers].filter((id) => !current.has(id));
  if (removed.length > 0) {
    for (const id of removed) {
      session.knownMembers.delete(id);
      session.memberPubs.delete(id);
    }
    const newKey = generateRoomKey();
    pushKey(newKey);
    for (const id of current) {
      if (id !== session.memberId) rekeyMember(id, newKey);
    }
  }
  session.knownMembers = current;
  broadcastRoster();
}

function rekeyMember(memberId: string, newKey: RoomKey): void {
  if (!session) return;
  const pub = session.memberPubs.get(memberId);
  if (pub) send({ type: "rekey", target: memberId, data: sealRoomKey(session.kp.priv, pub, newKey) });
}

function pushKey(k: RoomKey): void {
  if (!session) return;
  session.keys.unshift(k);
  for (const old of session.keys.splice(MAX_KEPT_KEYS)) wipeKey(old);
}

function ownerIdOf(members: MemberInfo[]): string {
  return members.find((m) => m.role === "owner")?.id ?? "";
}

// ── Errors / close / teardown ───────────────────────────────────────────────

function handleError(msg: ServerMsg): void {
  if (msg.reason === "file_rejected") {
    if (msg.transfer) {
      session?.incoming.delete(msg.transfer);
      failFileMessage(msg.transfer, msg.error ?? "rejected");
    }
    roomNotice.textContent = `Attachment rejected: ${msg.error ?? "too large"}.`;
    return;
  }
  if (msg.reason === "already_in_room") {
    // Backstop: this tab's session is already in a room (the local flow should
    // normally prevent reaching here). Drop the dead attempt and explain.
    lobbyError.textContent = "This tab is already in a room — leave it before joining another.";
    lobbyStatus.textContent = "";
    teardown(false);
    return;
  }
  const text = msg.error ?? "Error";
  if (session && session.room) roomNotice.textContent = text;
  else {
    lobbyError.textContent = text;
    lobbyStatus.textContent = "";
    teardown(false);
  }
}

function onClose(): void {
  const wasInRoom = !!(session && session.room);
  if (wasInRoom && !intentionalClose) {
    // Unexpected drop (network blip, iOS tab suspend, proxy). We cannot resume
    // the room without a server-side resume feature, so fail cleanly to the
    // lobby with everything wiped — never a dead "stuck" room view.
    teardown(true);
    lobbyError.textContent = "Connection lost — the room has ended. Rejoin with a new invite.";
  } else if (!wasInRoom) {
    teardown(false);
  }
  intentionalClose = false;
}

function teardown(returnToLobby = true): void {
  const s = session;
  session = null;
  pendingJoin = null;
  if (s) {
    for (const k of s.keys) wipeKey(k);
    wipeKey(s.kp.priv);
    if (s.firstOwnerPub) s.firstOwnerPub.fill(0);
    for (const rec of s.handshakes.values()) wipeKey(rec.ke ?? null);
    for (const u of s.objectUrls) URL.revokeObjectURL(u); // no blob bytes linger
    s.incoming.clear();
    try {
      s.ws.close();
    } catch {
      /* already closing */
    }
  }
  messageList.replaceChildren();
  memberList.replaceChildren();
  memberCount.textContent = "0";
  roomIdEl.textContent = "";
  inviteBox.classList.add("hidden");
  inviteLink.value = "";
  inviteBtn.classList.add("hidden");
  clearStaged(); // revoke any object URL so blob bytes don't linger between rooms
  if (returnToLobby) showLobby();
}

// ── Attachment staging (Phase 1: local only) ────────────────────────────────

function onFileSelected(): void {
  const f = fileInput.files?.[0];
  fileInput.value = ""; // allow re-selecting the same file later
  if (!f) return;
  if (f.size > MAX_FILE_BYTES) {
    roomNotice.textContent = `"${f.name}" is too large (max ${formatBytes(MAX_FILE_BYTES)}).`;
    return;
  }
  clearStaged();
  staged = { file: f, url: URL.createObjectURL(f) };
  renderStaged();
}

function renderStaged(): void {
  if (!staged) return;
  attachPreview.replaceChildren();

  if (staged.file.type.startsWith("image/")) {
    const img = document.createElement("img");
    img.src = staged.url; // local object URL; decrypted-on-recipient comes later
    img.alt = "attachment preview";
    attachPreview.appendChild(img);
  }

  const meta = document.createElement("div");
  meta.className = "meta";
  const name = document.createElement("span");
  name.className = "name";
  name.textContent = staged.file.name; // textContent — no injection
  const size = document.createElement("span");
  size.className = "size";
  size.textContent = formatBytes(staged.file.size) + " · staged (not sent yet)";
  meta.append(name, size);

  const remove = document.createElement("button");
  remove.type = "button";
  remove.className = "remove";
  remove.textContent = "✕";
  remove.setAttribute("aria-label", "Remove attachment");
  remove.addEventListener("click", clearStaged);

  attachPreview.append(meta, remove);
  attachPreview.classList.remove("hidden");
}

function clearStaged(): void {
  if (staged) {
    URL.revokeObjectURL(staged.url);
    staged = null;
  }
  attachPreview.replaceChildren();
  attachPreview.classList.add("hidden");
}

function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MB`;
}

// ── Encrypted file transfer (Phase 2) ───────────────────────────────────────

function randomId(): string {
  const b = new Uint8Array(16);
  crypto.getRandomValues(b);
  return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
}

function trackUrl(url: string): string {
  session?.objectUrls.push(url);
  return url;
}

// findKeyById returns the held room key whose epoch tag matches id (the file
// can thus be decrypted even after the key rotated, while we still hold it).
function findKeyById(id: string): RoomKey | null {
  if (!session) return null;
  for (const k of session.keys) if (keyId(k) === id) return k;
  return null;
}

// sendFile encrypts a file (metadata + chunks) under the CURRENT room key,
// captured once so the whole transfer uses one epoch, and streams it chunked.
async function sendFile(file: File): Promise<void> {
  if (!session || !session.keys.length) return;
  const key = session.keys[0]; // capture epoch at send time
  const kid = keyId(key);
  const transfer = randomId();
  const buf = new Uint8Array(await file.arrayBuffer());
  const total = Math.max(1, Math.ceil(buf.length / CHUNK_SIZE));
  const meta: FileMeta = { name: file.name, type: file.type, size: buf.length, chunks: total };

  const h = startFileMessage(transfer, "you", meta, true);

  // Metadata (name/MIME/size) is ENCRYPTED in the payload — the server never
  // sees the filename or type.
  send({ type: "file_start", transfer, keyId: kid, data: encryptMessage(key, JSON.stringify(meta)) });
  for (let i = 0; i < total; i++) {
    const slice = buf.subarray(i * CHUNK_SIZE, (i + 1) * CHUNK_SIZE);
    send({ type: "file_chunk", transfer, index: i, data: sealBytes(key, slice) });
    setFileProgress(h, (i + 1) / total);
    // Yield to the event loop (macrotask) so the browser paints the bar between
    // chunks; also keeps a large upload from blocking the UI thread.
    await new Promise((r) => setTimeout(r, 0));
    if (!session) return; // left the room mid-upload
  }
  send({ type: "file_end", transfer });

  // Finalize our own copy locally.
  const url = trackUrl(URL.createObjectURL(new Blob([buf], { type: file.type })));
  finishFileMessage(transfer, url);
}

function onFileStart(msg: ServerMsg): void {
  if (!session || !msg.transfer || !msg.keyId || msg.data === undefined) return;
  const key = findKeyById(msg.keyId);
  if (!key) return; // we don't hold that key epoch — cannot decrypt; ignore
  let meta: FileMeta;
  try {
    meta = JSON.parse(decryptMessage(key, msg.data)) as FileMeta;
  } catch {
    return;
  }
  if (!meta.chunks || meta.chunks < 1 || meta.chunks > 100000) return;
  session.incoming.set(msg.transfer, {
    key,
    meta,
    nick: msg.nick ?? "?",
    parts: new Array(meta.chunks),
    received: 0,
  });
  startFileMessage(msg.transfer, msg.nick ?? "?", meta, false);
}

function onFileChunk(msg: ServerMsg): void {
  const inc = session?.incoming.get(msg.transfer ?? "");
  if (!inc || msg.data === undefined) return;
  const i = msg.index ?? -1;
  if (i < 0 || i >= inc.meta.chunks || inc.parts[i]) return;
  let chunk: Uint8Array;
  try {
    chunk = openBytes(inc.key, msg.data);
  } catch {
    return; // tampered / wrong key — drop
  }
  inc.parts[i] = chunk;
  inc.received++;
  const h = session!.fileMsgs.get(msg.transfer!);
  if (h) setFileProgress(h, inc.received / inc.meta.chunks);
  if (inc.received === inc.meta.chunks) finishIncoming(msg.transfer!);
}

function onFileEnd(msg: ServerMsg): void {
  // Completion is detected when all chunks arrive; if file_end arrives with a
  // gap, the transfer is incomplete (lost chunk) — fail it.
  if (msg.transfer && session?.incoming.has(msg.transfer)) {
    session.incoming.delete(msg.transfer);
    failFileMessage(msg.transfer, "transfer interrupted");
  }
}

function finishIncoming(transfer: string): void {
  const inc = session?.incoming.get(transfer);
  if (!inc || !session) return;
  session.incoming.delete(transfer);
  const blob = new Blob(inc.parts as unknown as BlobPart[], { type: inc.meta.type });
  const url = trackUrl(URL.createObjectURL(blob));
  finishFileMessage(transfer, url);
}

// ── File message UI (progress → image/download) ─────────────────────────────

function startFileMessage(transfer: string, nick: string, meta: FileMeta, mine: boolean): FileMsgHandle {
  const li = document.createElement("li");
  li.className = mine ? "msg-mine" : "msg-other";
  const who = document.createElement("span");
  who.className = "who";
  who.textContent = nick;

  const status = document.createElement("div");
  status.className = "file-status";
  const label = document.createElement("span");
  label.className = "file-label";
  const bar = document.createElement("div");
  bar.className = "file-bar";
  const fill = document.createElement("i");
  bar.appendChild(fill);
  status.append(label, bar);

  li.append(who, status);
  messageList.appendChild(li);
  messageList.scrollTop = messageList.scrollHeight;

  const h: FileMsgHandle = { li, status, label, fill, meta, mine };
  setFileProgress(h, 0);
  session?.fileMsgs.set(transfer, h);
  return h;
}

function setFileProgress(h: FileMsgHandle, frac: number): void {
  const pct = Math.max(0, Math.min(100, Math.round(frac * 100)));
  h.fill.style.width = pct + "%";
  h.label.textContent = `📎 ${h.meta.name} · ${formatBytes(h.meta.size)} — ${h.mine ? "uploading" : "receiving"} ${pct}%`;
}

function finishFileMessage(transfer: string, url: string): void {
  const h = session?.fileMsgs.get(transfer);
  if (!h) return;
  session!.fileMsgs.delete(transfer);
  h.status.remove();
  if ((h.meta.type || "").startsWith("image/")) {
    const img = document.createElement("img");
    img.className = "msg-image";
    img.src = url;
    img.alt = h.meta.name;
    img.addEventListener("click", () => window.open(url, "_blank", "noopener"));
    h.li.appendChild(img);
  } else {
    const a = document.createElement("a");
    a.className = "msg-file";
    a.href = url;
    a.download = h.meta.name;
    a.textContent = `📎 ${h.meta.name} (${formatBytes(h.meta.size)})`;
    h.li.appendChild(a);
  }
  messageList.scrollTop = messageList.scrollHeight;
}

function failFileMessage(transfer: string, reason: string): void {
  const h = session?.fileMsgs.get(transfer);
  if (!h) return;
  session!.fileMsgs.delete(transfer);
  h.status.remove();
  const err = document.createElement("span");
  err.className = "file-failed";
  err.textContent = `📎 ${h.meta.name} — ${reason}`;
  h.li.appendChild(err);
}

// ── Rendering ───────────────────────────────────────────────────────────────

function renderMembers(members: MemberInfo[]): void {
  if (session) session.lastMembers = members;
  memberCount.textContent = String(members.length);
  memberList.replaceChildren();
  const iAmOwner = session?.role === "owner";
  for (const m of members) {
    const li = document.createElement("li");
    const name = document.createElement("span");
    name.className = "member-name";
    name.textContent = m.nick;
    li.appendChild(name);
    if (m.role === "owner") li.appendChild(badge("owner-badge", "owner"));
    if (session && m.id === session.memberId) li.appendChild(badge("you-badge", "you"));
    // Owner controls for other members.
    if (iAmOwner && session && m.id !== session.memberId) {
      li.appendChild(actionBtn("make-owner", m.id, "Make owner", "↑"));
      li.appendChild(actionBtn("kick", m.id, "Kick", "✕"));
    }
    memberList.appendChild(li);
  }
}

function badge(cls: string, text: string): HTMLSpanElement {
  const b = document.createElement("span");
  b.className = cls;
  b.textContent = text;
  return b;
}

function actionBtn(action: string, id: string, title: string, label: string): HTMLButtonElement {
  const b = document.createElement("button");
  b.className = "member-action";
  b.dataset.action = action;
  b.dataset.id = id;
  b.title = title;
  b.textContent = label;
  return b;
}

function addMessage(nick: string, body: string, mine: boolean): void {
  const li = document.createElement("li");
  li.className = mine ? "msg-mine" : "msg-other";
  const who = document.createElement("span");
  who.className = "who";
  who.textContent = nick;
  const text = document.createElement("span");
  text.className = "text";
  text.textContent = body; // textContent — never innerHTML (no injection)
  li.append(who, text);
  messageList.appendChild(li);
  messageList.scrollTop = messageList.scrollHeight;
}

function closeReason(reason?: string): string {
  switch (reason) {
    case "owner_left":
      return "The owner left. This room has been destroyed.";
    case "kicked":
      return "You were removed from this room.";
    case "idle_timeout":
      return "Room closed due to inactivity.";
    case "server_shutdown":
      return "The server is shutting down.";
    default:
      return "This room has been closed.";
  }
}

function showRoom(): void {
  lobby.classList.add("hidden");
  room.classList.remove("hidden");
  roomNotice.textContent = "";
  msgInput.focus();
}

function showLobby(): void {
  room.classList.add("hidden");
  lobby.classList.remove("hidden");
  roomInput.value = "";
  void pollStats(); // refresh the live counts on return to the lobby
}

// ── Live lobby stats (aggregate only; polled) ───────────────────────────────

async function pollStats(): Promise<void> {
  if (lobby.classList.contains("hidden")) return; // only meaningful in the lobby
  try {
    const r = await fetch("/api/stats", { cache: "no-store" });
    if (!r.ok) throw new Error("bad status");
    const s = (await r.json()) as { online: number; rooms: number };
    const people = `${s.online} ${s.online === 1 ? "person" : "people"} online`;
    const rooms = `${s.rooms} active ${s.rooms === 1 ? "room" : "rooms"}`;
    lobbyStats.textContent = `${people} · ${rooms}`;
    lobbyStats.classList.remove("hidden");
  } catch {
    lobbyStats.classList.add("hidden"); // degrade gracefully — never block the lobby
  }
}

// ── Invite link + code ──────────────────────────────────────────────────────

function generateCode(): string {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"; // 32 chars, no 0/O/1/I
  const bytes = new Uint8Array(10);
  crypto.getRandomValues(bytes);
  let out = "";
  for (let i = 0; i < 10; i++) out += alphabet[bytes[i] % alphabet.length];
  return out;
}

function buildInviteLink(token: string, code: string): string {
  return `${location.origin + location.pathname}#t=${encodeURIComponent(token)}&c=${encodeURIComponent(code)}`;
}

function parseInvite(input: string): { token: string; code: string } | null {
  const hashIdx = input.indexOf("#");
  const hash = hashIdx >= 0 ? input.slice(hashIdx + 1) : input;
  const p = new URLSearchParams(hash);
  const token = p.get("t");
  const code = p.get("c");
  return token && code ? { token, code } : null;
}

// ── Event wiring ────────────────────────────────────────────────────────────

$("create-btn").addEventListener("click", async () => {
  await connect({ type: "create", nick: nickInput.value.trim(), session: SESSION_ID });
  if (session) session.keys = [generateRoomKey()];
});

$<HTMLFormElement>("join-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const invite = parseInvite(roomInput.value.trim());
  if (!invite) {
    lobbyError.textContent = "That invite link is invalid or missing its code.";
    return;
  }
  pendingJoin = invite;
  lobbyStatus.textContent = "Redeeming invite…";
  await connect({ type: "redeem", token: invite.token, nick: nickInput.value.trim(), session: SESSION_ID });
});

inviteBtn.addEventListener("click", () => send({ type: "invite" }));

// Attachment selection (the <label> wrapping #file-input opens the picker).
fileInput.addEventListener("change", onFileSelected);

memberList.addEventListener("click", (e) => {
  const btn = (e.target as HTMLElement).closest<HTMLButtonElement>("button.member-action");
  if (!btn || !session || session.role !== "owner") return;
  const id = btn.dataset.id!;
  if (btn.dataset.action === "make-owner") {
    if (confirm("Transfer ownership to this member? You will lose owner rights.")) {
      send({ type: "transfer", target: id });
    }
  } else if (btn.dataset.action === "kick") {
    send({ type: "kick", target: id });
  }
});

$("copy-invite-btn").addEventListener("click", async () => {
  try {
    await navigator.clipboard.writeText(inviteLink.value);
    roomNotice.textContent = "Invite link copied — share it privately; it works once.";
  } catch {
    inviteLink.select();
  }
});

$<HTMLFormElement>("msg-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  if (!session?.keys.length) return;
  const body = msgInput.value;
  if (body.trim()) {
    send({ type: "msg", body: encryptMessage(session.keys[0], body) });
    addMessage("you", body, true);
    msgInput.value = "";
  }
  if (staged) {
    const file = staged.file;
    clearStaged(); // sendFile makes its own object URL for the message
    await sendFile(file);
  }
});

$("leave-btn").addEventListener("click", onLeaveClicked);

// onLeaveClicked guards against accidental room destruction: an owner with other
// members is offered TRANSFER (default) vs. destroy; a lone owner confirms
// closing; a non-owner just leaves.
function onLeaveClicked(): void {
  if (!session) return;
  if (session.role !== "owner") {
    doLeave();
    return;
  }
  const others = session.lastMembers.filter((m) => m.id !== session!.memberId);
  if (others.length === 0) {
    openModal("Leave room?", "You're the owner and the only member. Leaving closes this room.", [
      { label: "Cancel", cls: "ghost" },
      { label: "Close room & leave", cls: "danger", onClick: doLeave },
    ]);
    return;
  }
  const sel = document.createElement("select");
  for (const m of others) {
    const o = document.createElement("option");
    o.value = m.id;
    o.textContent = m.nick;
    sel.appendChild(o);
  }
  const wrap = document.createElement("div");
  const p = document.createElement("p");
  p.textContent =
    "You're the owner. Recommended: transfer ownership before leaving so the room stays open. Destroying it removes everyone.";
  const label = document.createElement("label");
  label.textContent = "Transfer ownership to:";
  label.appendChild(sel);
  wrap.append(p, label);
  openModal("Leave room?", wrap, [
    { label: "Transfer & leave", cls: "primary", onClick: () => {
        if (sel.value) send({ type: "transfer", target: sel.value });
        doLeave();
      } },
    { label: "Destroy room & leave", cls: "danger", onClick: doLeave },
    { label: "Cancel", cls: "ghost" },
  ]);
}

function doLeave(): void {
  intentionalClose = true;
  send({ type: "leave" });
  teardown();
}

window.addEventListener("beforeunload", () => send({ type: "leave" }));

// Live lobby stats: poll now and every 12s (cheap; only updates while in lobby).
void pollStats();
setInterval(() => void pollStats(), 12_000);

// iOS Safari suspends backgrounded tabs (timers + sockets). On return, if our
// socket died, recover cleanly to the lobby instead of appearing frozen.
function recoverIfSocketDead(): void {
  if (session && session.ws.readyState >= WebSocket.CLOSING) {
    intentionalClose = false;
    onClose();
  }
}
document.addEventListener("visibilitychange", () => {
  if (document.visibilityState === "visible") recoverIfSocketDead();
});
window.addEventListener("pageshow", recoverIfSocketDead);

(function bootstrapFromHash() {
  if (!location.hash) return;
  const invite = parseInvite(location.hash);
  if (!invite) return;
  roomInput.value = buildInviteLink(invite.token, invite.code);
  history.replaceState(null, "", location.origin + location.pathname);
  lobbyStatus.textContent = "Invite detected — enter a nickname and Join.";
  nickInput.focus();
})();
