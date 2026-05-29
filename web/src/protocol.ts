// Wire protocol types, mirroring server/internal/wsproto.
//
// `body` (msg/chat) is an opaque base64 ciphertext envelope (crypto.ts).
// `data` (pake/key_deliver) is an opaque handshake payload the server relays
// blindly. The server never sees the 10-char SPAKE2 code or any key.

export type Role = "owner" | "member";

export interface MemberInfo {
  id: string;
  nick: string;
  role: Role;
}

// Client -> Server
export type ClientMsg =
  | { type: "create"; nick: string; session?: string }
  | { type: "redeem"; token: string; nick: string; session?: string }
  | { type: "msg"; body: string }
  | { type: "leave" }
  | { type: "invite" }
  | { type: "pake"; handshake: string; data: string }
  | { type: "key_deliver"; handshake: string; data: string }
  | { type: "member_key"; handshake: string; data: string }
  | { type: "enter"; handshake: string }
  | { type: "rekey"; target: string; data: string }
  | { type: "transfer"; target: string }
  | { type: "kick"; target: string }
  | { type: "roster"; data: string }
  | { type: "file_start"; transfer: string; keyId: string; data: string }
  | { type: "file_chunk"; transfer: string; index: number; data: string }
  | { type: "file_end"; transfer: string }
  | { type: "file_abort"; transfer: string };

// Server -> Client
export interface ServerMsg {
  type:
    | "welcome"
    | "presence"
    | "chat"
    | "room_closed"
    | "error"
    | "invite_created"
    | "invite_redeemed"
    | "redeem_ok"
    | "pake"
    | "key_deliver"
    | "member_key"
    | "rekey"
    | "roster"
    | "file_start"
    | "file_chunk"
    | "file_end"
    | "file_abort";
  room?: string;
  memberId?: string;
  role?: Role;
  members?: MemberInfo[];
  from?: string;
  nick?: string;
  body?: string;
  ts?: number;
  reason?: string;
  error?: string;
  token?: string;
  handshake?: string;
  data?: string;
  transfer?: string;
  keyId?: string;
  index?: number;
}

// Build the WebSocket URL for the relay on the current origin.
export function wsURL(): string {
  const proto = location.protocol === "https:" ? "wss:" : "ws:";
  return `${proto}//${location.host}/ws`;
}
