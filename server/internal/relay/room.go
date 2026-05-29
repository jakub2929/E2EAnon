package relay

import (
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/jakub2929/E2EAnon/internal/wsproto"
)

// Errors returned when adding a member fails.
var (
	errRoomFull   = errors.New("room is full")
	errRoomClosed = errors.New("room is closed")
)

// Room is the in-memory state for a single ephemeral chat room. All state lives
// here and is dropped on Close; nothing is persisted.
type Room struct {
	id      string
	hub     *Hub
	log     *slog.Logger
	maxSize int

	mu           sync.Mutex
	members      map[string]*Client
	ownerID      string
	closed       bool
	lastActivity time.Time
}

func newRoom(id string, hub *Hub) *Room {
	return &Room{
		id:           id,
		hub:          hub,
		log:          hub.log,
		maxSize:      hub.cfg.MaxRoomSize,
		members:      make(map[string]*Client),
		lastActivity: hub.now(),
	}
}

// ID returns the room identifier.
func (r *Room) ID() string { return r.id }

// OwnerClient returns the current owner's connection, if the room is live.
func (r *Room) OwnerClient() (*Client, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil, false
	}
	c, ok := r.members[r.ownerID]
	return c, ok
}

// HasCapacity reports whether another member could be admitted right now.
func (r *Room) HasCapacity() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return !r.closed && len(r.members) < r.maxSize
}

// Add inserts a client into the room. The first member becomes the owner.
// Returns the assigned role. Callers must send a welcome and broadcast presence
// after a successful add.
func (r *Room) Add(c *Client) (role string, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return "", errRoomClosed
	}
	if len(r.members) >= r.maxSize {
		return "", errRoomFull
	}
	if len(r.members) == 0 {
		r.ownerID = c.id
	}
	r.members[c.id] = c
	r.touchLocked()

	if c.id == r.ownerID {
		return wsproto.RoleOwner, nil
	}
	return wsproto.RoleMember, nil
}

// SnapshotMembers returns the current member list (public info).
func (r *Room) SnapshotMembers() []wsproto.MemberInfo {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.membersInfoLocked()
}

// BroadcastPresence sends the full member list to everyone in the room.
func (r *Room) BroadcastPresence() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return
	}
	r.broadcastLocked(wsproto.ServerMsg{
		Type:    wsproto.TypePresence,
		Members: r.membersInfoLocked(),
	}, "")
}

// SetOwner transfers ownership to another current member. Returns false if the
// target is not a member or the room is closed.
func (r *Room) SetOwner(memberID string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return false
	}
	if _, ok := r.members[memberID]; !ok {
		return false
	}
	r.ownerID = memberID
	r.touchLocked()
	return true
}

// RemoveMember forcibly removes a member (kick), notifying it with the given
// reason, then broadcasts fresh presence to the rest. No-op for the owner or a
// missing member. Returns true if a member was removed.
func (r *Room) RemoveMember(memberID, reason string) bool {
	r.mu.Lock()
	c, ok := r.members[memberID]
	if !ok || r.closed || memberID == r.ownerID {
		r.mu.Unlock()
		return false
	}
	delete(r.members, memberID)
	c.trySend(wsproto.ServerMsg{Type: wsproto.TypeRoomClosed, Reason: reason})
	close(c.out) // writePump drains the notice, then closes the conn
	r.touchLocked()
	r.broadcastLocked(wsproto.ServerMsg{Type: wsproto.TypePresence, Members: r.membersInfoLocked()}, "")
	r.mu.Unlock()
	r.hub.ClearSessionByClient(c) // free the kicked member's session immediately
	return true
}

// BroadcastExcept sends a message to every member except exceptID.
func (r *Room) BroadcastExcept(exceptID string, m wsproto.ServerMsg) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return
	}
	r.broadcastLocked(m, exceptID)
}

// SendTo delivers a message to a single member by id (used for owner -> member
// rekey routing). No-op if the room is closed or the member is gone.
func (r *Room) SendTo(memberID string, m wsproto.ServerMsg) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return
	}
	if c, ok := r.members[memberID]; ok {
		c.trySend(m)
	}
}

// Relay forwards a chat message from one member to all others.
func (r *Room) Relay(fromID, body string, ts int64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return
	}
	from, ok := r.members[fromID]
	if !ok {
		return
	}
	r.touchLocked()
	r.broadcastLocked(wsproto.ServerMsg{
		Type: wsproto.TypeChat,
		From: fromID,
		Nick: from.nick,
		Body: body,
		Ts:   ts,
	}, fromID)
}

// Leave removes a member. If the owner leaves, the whole room is destroyed.
// Idempotent: leaving a room one is no longer in is a no-op.
func (r *Room) Leave(memberID, reason string) {
	r.mu.Lock()
	c, ok := r.members[memberID]
	if !ok || r.closed {
		r.mu.Unlock()
		return
	}
	if memberID == r.ownerID {
		// Owner leaving destroys the room for everyone.
		r.mu.Unlock()
		r.Close(wsproto.ReasonOwnerLeft)
		return
	}
	delete(r.members, memberID)
	close(c.out) // signals this client's writePump to drain and exit
	empty := len(r.members) == 0
	r.touchLocked()
	r.broadcastLocked(wsproto.ServerMsg{
		Type:    wsproto.TypePresence,
		Members: r.membersInfoLocked(),
	}, "")
	r.mu.Unlock()

	if empty {
		r.Close("") // teardown silently; no one left to notify
	}
}

// Close destroys the room, notifies remaining members (if reason != ""), wipes
// member references, and unregisters from the hub. Idempotent.
func (r *Room) Close(reason string) {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return
	}
	r.closed = true
	members := r.members
	r.members = nil // drop references so the GC can reclaim member state
	r.ownerID = ""
	r.mu.Unlock()

	// Unregister first so no new members can join a room being torn down, and
	// drop any outstanding invite tokens for it.
	r.hub.removeRoom(r.id)
	r.hub.dropInvitesForRoom(r.id)

	for _, c := range members {
		r.hub.ClearSessionByClient(c) // free each member's session immediately
		if reason != "" {
			// Best-effort: queue the close notice before stopping the pump.
			c.trySend(wsproto.ServerMsg{Type: wsproto.TypeRoomClosed, Reason: reason})
		}
		close(c.out) // writePump drains remaining frames, then closes the conn
	}
	r.log.Info("room closed", "room", r.id, "reason", reason, "members", len(members))
}

// isClosed reports whether the room has been torn down.
func (r *Room) isClosed() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.closed
}

// idleFor reports how long the room has been inactive.
func (r *Room) idleFor(now time.Time) time.Duration {
	r.mu.Lock()
	defer r.mu.Unlock()
	return now.Sub(r.lastActivity)
}

// --- helpers requiring the room lock to be held ---

func (r *Room) touchLocked() { r.lastActivity = r.hub.now() }

func (r *Room) membersInfoLocked() []wsproto.MemberInfo {
	out := make([]wsproto.MemberInfo, 0, len(r.members))
	for _, c := range r.members {
		role := wsproto.RoleMember
		if c.id == r.ownerID {
			role = wsproto.RoleOwner
		}
		out = append(out, wsproto.MemberInfo{ID: c.id, Nick: c.nick, Role: role})
	}
	return out
}

func (r *Room) broadcastLocked(m wsproto.ServerMsg, exceptID string) {
	for id, c := range r.members {
		if id == exceptID {
			continue
		}
		if !c.trySend(m) {
			// Slow consumer: drop and disconnect it so it cannot stall the room.
			r.log.Warn("dropping slow client", "room", r.id, "member", id)
			_ = c.conn.Close(websocket.StatusPolicyViolation, "send buffer overflow")
		}
	}
}
