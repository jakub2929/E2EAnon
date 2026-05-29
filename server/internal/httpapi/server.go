// Package httpapi wires the HTTP surface: the health check, the WebSocket
// relay endpoint, and (optionally) static frontend assets.
package httpapi

import (
	"context"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
	"github.com/jakub2929/E2EAnon/internal/config"
	"github.com/jakub2929/E2EAnon/internal/ratelimit"
	"github.com/jakub2929/E2EAnon/internal/relay"
	"github.com/jakub2929/E2EAnon/internal/wsproto"
)

const (
	// maxNickLen bounds a member nickname (runes).
	maxNickLen = 64
	// readLimit bounds a single inbound frame.
	readLimit = 256 << 10 // 256 KiB
	// helloTimeout bounds how long we wait for the first create/redeem frame.
	helloTimeout = 15 * time.Second
	// pongTimeout bounds how long a heartbeat ping waits for the pong before the
	// connection is considered dead.
	pongTimeout = 10 * time.Second
	// inviteTokenBytes is the entropy of an invite ROUTING token (independent of
	// the SPAKE2 code; the server never sees the code).
	inviteTokenBytes = 16 // 128-bit
)

// Server holds the HTTP handler dependencies.
type Server struct {
	cfg          config.Config
	hub          *relay.Hub
	log          *slog.Logger
	createLim    *ratelimit.Limiter
	redeemLim    *ratelimit.Limiter
	pingInterval time.Duration
}

// NewServer builds the HTTP handler. staticFS provides the frontend assets
// (embedded or from disk); nil mounts a plain-text placeholder at "/".
func NewServer(cfg config.Config, hub *relay.Hub, log *slog.Logger, staticFS fs.FS) http.Handler {
	s := &Server{
		cfg:          cfg,
		hub:          hub,
		log:          log,
		createLim:    ratelimit.New(cfg.RateLimitCreatePerMin, time.Minute),
		redeemLim:    ratelimit.New(cfg.RateLimitRedeemPerMin, time.Minute),
		pingInterval: cfg.WSPingInterval,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", s.handleHealth)
	mux.HandleFunc("/ws", s.handleWS)
	s.mountStatic(mux, staticFS)
	return mux
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

// handleWS upgrades to a WebSocket and runs one session. The handler blocks
// until the session ends, keeping the hijacked connection alive.
func (s *Server) handleWS(w http.ResponseWriter, r *http.Request) {
	opts := &websocket.AcceptOptions{}
	if s.cfg.AllowAnyOrigin() {
		opts.InsecureSkipVerify = true // dev only; gated by ALLOWED_ORIGINS=*
	} else {
		opts.OriginPatterns = s.cfg.AllowedOrigins
	}

	conn, err := websocket.Accept(w, r, opts)
	if err != nil {
		s.log.Debug("ws accept failed", "err", err)
		return
	}
	conn.SetReadLimit(readLimit)
	ip := clientIP(r, s.cfg.TrustProxy)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// Heartbeat keeps idle-but-live connections alive through proxies/NAT and
	// detects dead ones (browsers auto-reply to server pings with pongs).
	go s.heartbeat(ctx, conn, cancel)
	s.session(ctx, conn, ip)
}

// session reads the hello frame and dispatches to the owner (create) or joiner
// (redeem) flow. Handshakes involving this client are always cleaned up on exit.
func (s *Server) session(ctx context.Context, conn *websocket.Conn, ip string) {
	helloCtx, hc := context.WithTimeout(ctx, helloTimeout)
	var hello wsproto.ClientMsg
	err := wsjson.Read(helloCtx, conn, &hello)
	hc()
	if err != nil {
		_ = conn.Close(websocket.StatusPolicyViolation, "no hello")
		return
	}

	client := relay.NewClient(relay.NewMemberID(), sanitizeNick(hello.Nick), conn)
	go client.WritePump(ctx)
	sessionID := hello.Session
	// Release any session claim this connection holds on every exit path
	// (graceful leave, disconnect, handshake failure). Compare-and-delete: a
	// no-op unless this connection still owns the claim.
	defer func() {
		s.hub.EndHandshakesFor(client)
		s.hub.ClearSession(sessionID, client)
		// Release any in-flight file bytes this connection still held.
		for _, b := range client.FileTransfers {
			s.hub.AddInflight(-b)
		}
	}()

	switch hello.Type {
	case wsproto.TypeCreate:
		s.runOwner(ctx, conn, client, ip, sessionID)
	case wsproto.TypeRedeem:
		s.runJoiner(ctx, conn, client, hello, ip, sessionID)
	default:
		client.Send(wsproto.ServerMsg{Type: wsproto.TypeError, Error: "expected create or redeem", Reason: wsproto.ReasonBadRequest})
		client.CloseOut()
		<-client.Done()
	}
}

// runOwner handles a room creator: create the room, then serve as a member.
func (s *Server) runOwner(ctx context.Context, conn *websocket.Conn, client *relay.Client, ip, sessionID string) {
	if !s.createLim.Allow(ip) {
		client.Send(wsproto.ServerMsg{Type: wsproto.TypeError, Error: "too many rooms; slow down", Reason: wsproto.ReasonRateLimited})
		client.CloseOut()
		<-client.Done()
		return
	}
	// One room per session: refuse if this session is already in a room.
	if !s.hub.TryClaimSession(sessionID, client) {
		client.Send(wsproto.ServerMsg{Type: wsproto.TypeError, Error: "you are already in a room", Reason: wsproto.ReasonInRoom})
		client.CloseOut()
		<-client.Done()
		return
	}
	room := s.hub.CreateRoom()
	_, _ = room.Add(client) // first member of a fresh room cannot fail
	s.hub.SetSessionRoom(sessionID, room.ID())
	client.Send(wsproto.ServerMsg{
		Type:     wsproto.TypeWelcome,
		Room:     room.ID(),
		MemberID: client.ID(),
		Role:     wsproto.RoleOwner,
		Members:  room.SnapshotMembers(),
	})
	reason := s.memberLoop(ctx, conn, client, room)
	room.Leave(client.ID(), reason)
	// Free the session as soon as we leave the room — do not wait on the write
	// pump to drain (a non-reading client could otherwise delay this up to the
	// write timeout). The session() defer is an idempotent CAS safety net.
	s.hub.ClearSession(sessionID, client)
	<-client.Done()
}

// runJoiner handles a joiner: validate the single-use token, run the PAKE
// handshake relay, and promote to member on `enter`.
func (s *Server) runJoiner(ctx context.Context, conn *websocket.Conn, client *relay.Client, hello wsproto.ClientMsg, ip, sessionID string) {
	fail := func(msg, reason string) {
		client.Send(wsproto.ServerMsg{Type: wsproto.TypeError, Error: msg, Reason: reason})
		client.CloseOut()
		<-client.Done()
	}

	if !s.redeemLim.Allow(ip) {
		fail("too many attempts; slow down", wsproto.ReasonRateLimited)
		return
	}
	// One room per session — checked BEFORE redeeming so a blocked attempt does
	// NOT consume the single-use invite token.
	if !s.hub.TryClaimSession(sessionID, client) {
		fail("you are already in a room", wsproto.ReasonInRoom)
		return
	}
	roomID, ok := s.hub.RedeemInvite(strings.TrimSpace(hello.Token))
	if !ok {
		fail("invalid or expired invite", wsproto.ReasonBadInvite)
		return
	}
	room, ok := s.hub.GetRoom(roomID)
	if !ok {
		fail("room no longer exists", wsproto.ReasonRoomMissing)
		return
	}
	if !room.HasCapacity() {
		fail("room is full", wsproto.ReasonRoomFull)
		return
	}
	owner, ok := room.OwnerClient()
	if !ok {
		fail("room unavailable", wsproto.ReasonRoomMissing)
		return
	}

	hsID := s.hub.NewHandshake(roomID, client, owner)
	client.Send(wsproto.ServerMsg{Type: wsproto.TypeRedeemOk, Handshake: hsID, MemberID: client.ID()})
	// Echo the token (server-generated, not secret) so the owner can map this
	// handshake to the matching local SPAKE2 code, and the joiner's member id so
	// the owner can address future rekeys to it.
	owner.Send(wsproto.ServerMsg{Type: wsproto.TypeInviteRedeemed, Handshake: hsID, Nick: client.Nick(), Token: strings.TrimSpace(hello.Token), MemberID: client.ID()})

	entered, reason := s.handshakeLoop(ctx, conn, client, room, hsID)
	if !entered {
		s.hub.EndHandshake(hsID)
		client.CloseOut()
		<-client.Done()
		return
	}
	// Promoted to member inside handshakeLoop; serve as a member from here.
	s.hub.SetSessionRoom(sessionID, room.ID())
	reason = s.memberLoop(ctx, conn, client, room)
	room.Leave(client.ID(), reason)
	s.hub.ClearSession(sessionID, client) // free promptly; defer is the safety net
	<-client.Done()
}

// handshakeLoop relays the joiner's SPAKE2 frames to the owner and finalizes
// membership on `enter`. Returns entered=true once the joiner is a member.
func (s *Server) handshakeLoop(ctx context.Context, conn *websocket.Conn, client *relay.Client, room *relay.Room, hsID string) (entered bool, reason string) {
	for {
		var m wsproto.ClientMsg
		if err := wsjson.Read(ctx, conn, &m); err != nil {
			return false, ""
		}
		switch m.Type {
		case wsproto.TypePake, wsproto.TypeMemberKey:
			s.relayHandshake(client, m)
		case wsproto.TypeEnter:
			if m.Handshake != hsID {
				continue
			}
			if _, err := room.Add(client); err != nil {
				client.Send(wsproto.ServerMsg{Type: wsproto.TypeError, Error: "room is full", Reason: wsproto.ReasonRoomFull})
				return false, ""
			}
			s.hub.EndHandshake(hsID)
			client.Send(wsproto.ServerMsg{
				Type:     wsproto.TypeWelcome,
				Room:     room.ID(),
				MemberID: client.ID(),
				Role:     wsproto.RoleMember,
				Members:  room.SnapshotMembers(),
			})
			room.BroadcastPresence()
			return true, ""
		case wsproto.TypeLeave:
			return false, ""
		default:
			// Ignore anything else before entering the room.
		}
	}
}

// memberLoop serves a full room member: chat relay, leave, owner-only invites,
// and (for the owner) relaying handshake frames to joiners.
func (s *Server) memberLoop(ctx context.Context, conn *websocket.Conn, client *relay.Client, room *relay.Room) string {
	for {
		var m wsproto.ClientMsg
		if err := wsjson.Read(ctx, conn, &m); err != nil {
			return "" // disconnect
		}
		switch m.Type {
		case wsproto.TypeMsg:
			// Body is an opaque ciphertext envelope; relayed verbatim.
			room.Relay(client.ID(), m.Body, time.Now().UnixMilli())
		case wsproto.TypeInvite:
			s.handleInvite(client, room)
		case wsproto.TypePake, wsproto.TypeKeyDeliver, wsproto.TypeMemberKey:
			// Owner side of a handshake: relay to the paired joiner.
			s.relayHandshake(client, m)
		case wsproto.TypeRekey:
			s.handleRekey(client, room, m)
		case wsproto.TypeTransfer:
			s.handleTransfer(client, room, m)
		case wsproto.TypeKick:
			s.handleKick(client, room, m)
		case wsproto.TypeRoster:
			// Owner broadcasts the (room-key-encrypted) member pubkey roster.
			if s.isOwner(client, room) {
				room.BroadcastExcept(client.ID(), wsproto.ServerMsg{Type: wsproto.TypeRoster, Data: m.Data})
			}
		case wsproto.TypeFileStart, wsproto.TypeFileChunk, wsproto.TypeFileEnd, wsproto.TypeFileAbort:
			s.handleFile(client, room, m)
		case wsproto.TypeLeave:
			return ""
		default:
			// Ignore unknown frames.
		}
	}
}

// handleFile relays opaque file-transfer frames to the other members while
// enforcing the per-file and total in-flight ciphertext-byte caps. Chunks are
// relayed one at a time and NEVER buffered to disk; an over-cap transfer is
// rejected (file_abort) rather than stored.
func (s *Server) handleFile(client *relay.Client, room *relay.Room, m wsproto.ClientMsg) {
	if m.Transfer == "" {
		return
	}
	switch m.Type {
	case wsproto.TypeFileStart:
		client.FileTransfers[m.Transfer] = 0
		room.BroadcastExcept(client.ID(), wsproto.ServerMsg{
			Type: wsproto.TypeFileStart, Transfer: m.Transfer, KeyID: m.KeyID,
			Data: m.Data, From: client.ID(), Nick: client.Nick(),
		})
	case wsproto.TypeFileChunk:
		cur, ok := client.FileTransfers[m.Transfer]
		if !ok {
			return // unknown or already-aborted transfer
		}
		size := int64(len(m.Data))
		if cur+size > s.hub.MaxFileBytes() {
			s.abortFile(client, room, m.Transfer, "file too large")
			return
		}
		if s.hub.AddInflight(size) > s.hub.MaxInflightBytes() {
			s.hub.AddInflight(-size)
			s.abortFile(client, room, m.Transfer, "server busy, too many transfers")
			return
		}
		client.FileTransfers[m.Transfer] = cur + size
		room.BroadcastExcept(client.ID(), wsproto.ServerMsg{
			Type: wsproto.TypeFileChunk, Transfer: m.Transfer, Index: m.Index,
			Data: m.Data, From: client.ID(),
		})
	case wsproto.TypeFileEnd:
		s.finishFile(client, m.Transfer)
		room.BroadcastExcept(client.ID(), wsproto.ServerMsg{Type: wsproto.TypeFileEnd, Transfer: m.Transfer, From: client.ID()})
	case wsproto.TypeFileAbort:
		s.finishFile(client, m.Transfer)
		room.BroadcastExcept(client.ID(), wsproto.ServerMsg{Type: wsproto.TypeFileAbort, Transfer: m.Transfer, From: client.ID()})
	}
}

// abortFile rejects a transfer: releases its counted bytes, tells the sender,
// and tells recipients to discard the partial.
func (s *Server) abortFile(client *relay.Client, room *relay.Room, transfer, reason string) {
	s.finishFile(client, transfer)
	client.Send(wsproto.ServerMsg{Type: wsproto.TypeError, Error: reason, Reason: wsproto.ReasonFileRejected, Transfer: transfer})
	room.BroadcastExcept(client.ID(), wsproto.ServerMsg{Type: wsproto.TypeFileAbort, Transfer: transfer, From: client.ID()})
}

// finishFile releases a transfer's counted in-flight bytes.
func (s *Server) finishFile(client *relay.Client, transfer string) {
	if bytes, ok := client.FileTransfers[transfer]; ok {
		s.hub.AddInflight(-bytes)
		delete(client.FileTransfers, transfer)
	}
}

// handleInvite issues a single-use token for the room (owner only).
func (s *Server) handleInvite(client *relay.Client, room *relay.Room) {
	owner, ok := room.OwnerClient()
	if !ok || owner.ID() != client.ID() {
		client.Send(wsproto.ServerMsg{Type: wsproto.TypeError, Error: "only the owner can invite", Reason: wsproto.ReasonNotOwner})
		return
	}
	token := relay.NewToken(inviteTokenBytes)
	exp := s.hub.CreateInvite(token, room.ID())
	client.Send(wsproto.ServerMsg{Type: wsproto.TypeInviteCreated, Token: token, Ts: exp.UnixMilli()})
}

// isOwner reports whether client is the room's current owner.
func (s *Server) isOwner(client *relay.Client, room *relay.Room) bool {
	owner, ok := room.OwnerClient()
	return ok && owner.ID() == client.ID()
}

// handleTransfer hands ownership to another member (owner-only). Presence is
// re-broadcast so every client learns the new owner and updated roles.
func (s *Server) handleTransfer(client *relay.Client, room *relay.Room, m wsproto.ClientMsg) {
	if !s.isOwner(client, room) {
		client.Send(wsproto.ServerMsg{Type: wsproto.TypeError, Error: "only the owner can transfer ownership", Reason: wsproto.ReasonNotOwner})
		return
	}
	if room.SetOwner(m.Target) {
		room.BroadcastPresence()
	}
}

// handleKick forcibly removes a member (owner-only). The kicked member receives
// room_closed(kicked); remaining members get fresh presence (which prompts the
// owner to rotate the room key — forward secrecy).
func (s *Server) handleKick(client *relay.Client, room *relay.Room, m wsproto.ClientMsg) {
	if !s.isOwner(client, room) {
		client.Send(wsproto.ServerMsg{Type: wsproto.TypeError, Error: "only the owner can kick", Reason: wsproto.ReasonNotOwner})
		return
	}
	room.RemoveMember(m.Target, wsproto.ReasonKicked)
}

// handleRekey routes a rotated, sealed room key from the owner to one member.
// Owner-only; the server never sees the key (it is sealed to the member's
// X25519 key). Used for key rotation on join/leave (forward secrecy).
func (s *Server) handleRekey(from *relay.Client, room *relay.Room, m wsproto.ClientMsg) {
	owner, ok := room.OwnerClient()
	if !ok || owner.ID() != from.ID() {
		return // only the owner distributes keys
	}
	room.SendTo(m.Target, wsproto.ServerMsg{Type: wsproto.TypeRekey, Data: m.Data})
}

// relayHandshake forwards one opaque handshake frame (pake / key_deliver /
// member_key) to the other party of the handshake. The server never inspects
// Data.
func (s *Server) relayHandshake(from *relay.Client, m wsproto.ClientMsg) {
	hs, ok := s.hub.GetHandshake(m.Handshake)
	if !ok {
		return
	}
	peer := hs.Peer(from)
	if peer == nil {
		return // sender is not a party to this handshake
	}
	peer.Send(wsproto.ServerMsg{Type: m.Type, Handshake: m.Handshake, Data: m.Data})
}

// heartbeat pings the peer every pingInterval; if the pong does not arrive
// within pongTimeout the connection is treated as dead and the session is
// cancelled (which unblocks the read loop and triggers normal teardown).
// Browsers auto-reply to server pings with pongs at the protocol level, so an
// idle but live tab stays connected through Coolify/Traefik and NAT. A zero
// interval disables the heartbeat.
func (s *Server) heartbeat(ctx context.Context, conn *websocket.Conn, cancel context.CancelFunc) {
	if s.pingInterval <= 0 {
		return
	}
	t := time.NewTicker(s.pingInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			pctx, pcancel := context.WithTimeout(ctx, pongTimeout)
			err := conn.Ping(pctx)
			pcancel()
			if err != nil {
				_ = conn.Close(websocket.StatusPolicyViolation, "ping timeout")
				cancel()
				return
			}
		}
	}
}

// clientIP resolves the client's source IP. Behind a trusted reverse proxy
// (Coolify/Traefik), X-Forwarded-For / X-Real-IP are honored; otherwise the
// transport RemoteAddr is used. Used for logging and rate limiting.
func clientIP(r *http.Request, trustProxy bool) string {
	if trustProxy {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			if i := strings.IndexByte(xff, ','); i >= 0 {
				return strings.TrimSpace(xff[:i])
			}
			return strings.TrimSpace(xff)
		}
		if xrip := strings.TrimSpace(r.Header.Get("X-Real-IP")); xrip != "" {
			return xrip
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// sanitizeNick trims and bounds a nickname, defaulting to "anon".
func sanitizeNick(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "anon"
	}
	r := []rune(s)
	if len(r) > maxNickLen {
		r = r[:maxNickLen]
	}
	return string(r)
}
