// Package wsproto defines the client <-> server WebSocket message protocol.
//
// As of Phase 3, the Body field on msg/chat carries an OPAQUE base64 ciphertext
// envelope (XChaCha20-Poly1305) produced and consumed only by clients. The
// server treats Body as an uninterpreted string and relays it verbatim; it can
// neither read message content nor derive any key. See docs/PROTOCOL.md.
package wsproto

// Client -> Server message types.
const (
	// TypeCreate is the first frame a room owner sends. Creates a new room.
	// Fields: Nick.
	TypeCreate = "create"
	// TypeMsg relays a chat message to all other members. Fields: Body.
	TypeMsg = "msg"
	// TypeLeave gracefully leaves the room. No fields.
	TypeLeave = "leave"

	// TypeInvite (owner only) requests a fresh single-use invite token.
	TypeInvite = "invite"
	// TypeRedeem joins via a single-use invite token. Fields: Token, Nick.
	// The joiner is not a member until the PAKE handshake completes.
	TypeRedeem = "redeem"
	// TypePake carries one opaque SPAKE2 handshake frame between the joiner and
	// the owner. Fields: Handshake, Data. The server relays it blindly.
	TypePake = "pake"
	// TypeKeyDeliver carries the room key wrapped under the PAKE-derived key,
	// owner -> joiner. Fields: Handshake, Data. Relayed blindly.
	TypeKeyDeliver = "key_deliver"
	// TypeMemberKey carries an X25519 public key sealed under the PAKE secret,
	// exchanged between joiner and owner during the handshake. Fields:
	// Handshake, Data. Relayed blindly.
	TypeMemberKey = "member_key"
	// TypeEnter (joiner) signals the handshake succeeded; the server promotes
	// the joiner to a full member. Fields: Handshake.
	TypeEnter = "enter"
	// TypeRekey (owner) delivers a rotated room key to one member, sealed to
	// that member's X25519 key. Fields: Target (member id), Data. The server
	// routes it to Target within the room; it never sees the key.
	TypeRekey = "rekey"
	// TypeTransfer (owner) hands ownership to another member. Fields: Target.
	TypeTransfer = "transfer"
	// TypeKick (owner) removes a member from the room. Fields: Target.
	TypeKick = "kick"
	// TypeRoster (owner) broadcasts the member->X25519-pubkey map, encrypted
	// under the room key. Fields: Data. Relayed to all other members so every
	// client can become owner and re-key on membership changes.
	TypeRoster = "roster"

	// File transfer (chunked, E2E). All payloads are opaque ciphertext; the
	// server never sees the file bytes, filename, or MIME type (metadata is
	// encrypted inside the file_start payload).
	//
	// TypeFileStart begins a transfer. Fields: Transfer (random id), KeyID
	// (non-secret key-epoch tag), Data (encrypted metadata: name/mime/size/chunks).
	TypeFileStart = "file_start"
	// TypeFileChunk carries one independently-AEAD-sealed chunk. Fields:
	// Transfer, Index, Data.
	TypeFileChunk = "file_chunk"
	// TypeFileEnd marks a transfer complete. Fields: Transfer.
	TypeFileEnd = "file_end"
	// TypeFileAbort tells peers to discard a transfer (server-initiated on cap
	// breach, or sender-initiated). Fields: Transfer.
	TypeFileAbort = "file_abort"
)

// Server -> Client message types.
const (
	// TypeWelcome confirms a successful create/join. Fields: Room, MemberID,
	// Role, Members.
	TypeWelcome = "welcome"
	// TypePresence is the full current member list, broadcast on any
	// membership change. Fields: Members.
	TypePresence = "presence"
	// TypeChat delivers a relayed chat message. Fields: From, Nick, Body, Ts.
	TypeChat = "chat"
	// TypeRoomClosed signals the room was destroyed. Fields: Reason.
	TypeRoomClosed = "room_closed"
	// TypeError reports a recoverable or fatal error. Fields: Error, Reason.
	TypeError = "error"

	// TypeInviteCreated returns a fresh invite token to the owner. Fields:
	// Token, Ts (expiry, unix ms).
	TypeInviteCreated = "invite_created"
	// TypeInviteRedeemed notifies the owner a token was redeemed and a
	// handshake should begin. Fields: Handshake, Nick (joiner's).
	TypeInviteRedeemed = "invite_redeemed"
	// TypeRedeemOk tells the joiner the token was accepted; begin the
	// handshake. Fields: Handshake.
	TypeRedeemOk = "redeem_ok"
)

// Roles.
const (
	RoleOwner  = "owner"
	RoleMember = "member"
)

// Reasons for room closure / errors.
const (
	ReasonOwnerLeft    = "owner_left"
	ReasonRoomFull     = "room_full"
	ReasonRoomMissing  = "room_not_found"
	ReasonBadRequest   = "bad_request"
	ReasonServerStop   = "server_shutdown"
	ReasonIdle         = "idle_timeout"
	ReasonBadInvite    = "invalid_invite"
	ReasonRateLimited  = "rate_limited"
	ReasonNotOwner     = "not_owner"
	ReasonKicked       = "kicked"
	ReasonInRoom       = "already_in_room"
	ReasonFileRejected = "file_rejected"
)

// ClientMsg is a message received from a client. A single envelope keeps the
// relay simple; unused fields are omitted.
type ClientMsg struct {
	Type      string `json:"type"`
	Room      string `json:"room,omitempty"`
	Nick      string `json:"nick,omitempty"`
	Body      string `json:"body,omitempty"`
	Token     string `json:"token,omitempty"`     // redeem
	Handshake string `json:"handshake,omitempty"` // pake / key_deliver / member_key / enter
	Data      string `json:"data,omitempty"`      // opaque handshake / rekey / file payload
	Target    string `json:"target,omitempty"`    // rekey: destination member id
	Transfer  string `json:"transfer,omitempty"`  // file transfer id
	KeyID     string `json:"keyId,omitempty"`     // file: key-epoch tag (non-secret)
	Index     int    `json:"index"`               // file: chunk index (0-based; never omitted)
	// Session is the client's ephemeral per-tab id (random, in-memory only),
	// sent on create/redeem. The server uses it ONLY to enforce one room per
	// session (RAM map). It is not secret and is never persisted. Empty disables
	// the check for that connection.
	Session string `json:"session,omitempty"`
}

// MemberInfo is a public, non-sensitive view of a room member.
type MemberInfo struct {
	ID   string `json:"id"`
	Nick string `json:"nick"`
	Role string `json:"role"`
}

// ServerMsg is a message sent to a client.
type ServerMsg struct {
	Type      string       `json:"type"`
	Room      string       `json:"room,omitempty"`
	MemberID  string       `json:"memberId,omitempty"`
	Role      string       `json:"role,omitempty"`
	Members   []MemberInfo `json:"members,omitempty"`
	From      string       `json:"from,omitempty"`
	Nick      string       `json:"nick,omitempty"`
	Body      string       `json:"body,omitempty"`
	Ts        int64        `json:"ts,omitempty"`
	Reason    string       `json:"reason,omitempty"`
	Error     string       `json:"error,omitempty"`
	Token     string       `json:"token,omitempty"`     // invite_created
	Handshake string       `json:"handshake,omitempty"` // handshake-related
	Data      string       `json:"data,omitempty"`      // pake / key_deliver / file payload
	Transfer  string       `json:"transfer,omitempty"`  // file transfer id
	KeyID     string       `json:"keyId,omitempty"`     // file: key-epoch tag
	Index     int          `json:"index"`               // file: chunk index (0-based; never omitted)
}
