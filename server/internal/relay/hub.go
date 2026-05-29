package relay

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/jakub2929/E2EAnon/internal/config"
	"github.com/jakub2929/E2EAnon/internal/wsproto"
)

// Hub owns the set of live rooms. All state is in-memory; nothing is persisted.
type Hub struct {
	cfg config.Config
	log *slog.Logger

	// nowFn is the clock, swappable in tests.
	nowFn func() time.Time

	mu         sync.RWMutex
	rooms      map[string]*Room
	invites    map[string]invite
	handshakes map[string]*Handshake
	// sessions enforces one room per ephemeral session id (v2). RAM only,
	// cleared on disconnect/teardown. Maps session id -> owning claim.
	sessions map[string]*sessionClaim
}

// sessionClaim records which connection currently holds a session id and the
// room it is in (roomID is informational; presence of the entry is what blocks
// a second room for the same session).
type sessionClaim struct {
	client *Client
	roomID string
}

// NewHub constructs an empty hub.
func NewHub(cfg config.Config, log *slog.Logger) *Hub {
	return &Hub{
		cfg:        cfg,
		log:        log,
		nowFn:      time.Now,
		rooms:      make(map[string]*Room),
		invites:    make(map[string]invite),
		handshakes: make(map[string]*Handshake),
		sessions:   make(map[string]*sessionClaim),
	}
}

// TryClaimSession reserves a session id for a connection, enforcing one room
// per session. Returns false if the session is already in (or joining) a room.
// An empty session id disables enforcement and always succeeds without tracking.
func (h *Hub) TryClaimSession(sessionID string, c *Client) bool {
	if sessionID == "" {
		return true
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if _, taken := h.sessions[sessionID]; taken {
		return false
	}
	h.sessions[sessionID] = &sessionClaim{client: c}
	return true
}

// SetSessionRoom records the room a claimed session ended up in (informational).
func (h *Hub) SetSessionRoom(sessionID, roomID string) {
	if sessionID == "" {
		return
	}
	h.mu.Lock()
	if sc, ok := h.sessions[sessionID]; ok {
		sc.roomID = roomID
	}
	h.mu.Unlock()
}

// ClearSession releases a session id, but only if c still owns the claim
// (compare-and-delete). This prevents a slow disconnect cleanup from deleting a
// mapping that a fast reconnect with the same id has since taken over.
func (h *Hub) ClearSession(sessionID string, c *Client) {
	if sessionID == "" {
		return
	}
	h.mu.Lock()
	if sc, ok := h.sessions[sessionID]; ok && sc.client == c {
		delete(h.sessions, sessionID)
	}
	h.mu.Unlock()
}

// ClearSessionByClient releases whatever session a connection holds. Called on
// room/membership teardown so a member's session frees immediately, without
// waiting for its connection goroutine to unwind (which a non-reading peer could
// delay via the close handshake). A client owns at most one session.
func (h *Hub) ClearSessionByClient(c *Client) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for id, sc := range h.sessions {
		if sc.client == c {
			delete(h.sessions, id)
			return
		}
	}
}

// SessionCount returns the number of live session claims (tests/metrics).
func (h *Hub) SessionCount() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.sessions)
}

func (h *Hub) now() time.Time { return h.nowFn() }

// CreateRoom registers and returns a fresh room with a unique ID.
func (h *Hub) CreateRoom() *Room {
	h.mu.Lock()
	defer h.mu.Unlock()
	var id string
	for {
		id = newRoomID()
		if _, exists := h.rooms[id]; !exists {
			break
		}
	}
	r := newRoom(id, h)
	h.rooms[id] = r
	h.log.Info("room created", "room", id)
	return r
}

// GetRoom returns a live room by ID.
func (h *Hub) GetRoom(id string) (*Room, bool) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	r, ok := h.rooms[id]
	return r, ok
}

// removeRoom unregisters a room. Called by Room.Close.
func (h *Hub) removeRoom(id string) {
	h.mu.Lock()
	delete(h.rooms, id)
	h.mu.Unlock()
}

// RoomCount returns the number of live rooms (for tests/metrics).
func (h *Hub) RoomCount() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.rooms)
}

// snapshotRooms returns a copy of the current rooms for safe iteration.
func (h *Hub) snapshotRooms() []*Room {
	h.mu.RLock()
	defer h.mu.RUnlock()
	out := make([]*Room, 0, len(h.rooms))
	for _, r := range h.rooms {
		out = append(out, r)
	}
	return out
}

// StartJanitor runs idle-room garbage collection until ctx is cancelled.
// Rooms idle longer than cfg.RoomIdleTimeout are destroyed. A zero timeout
// disables GC.
func (h *Hub) StartJanitor(ctx context.Context) {
	timeout := h.cfg.RoomIdleTimeout
	if timeout <= 0 {
		return
	}
	// Scan at a fraction of the timeout, bounded to a sane range.
	interval := timeout / 4
	if interval < time.Second {
		interval = time.Second
	}
	if interval > time.Minute {
		interval = time.Minute
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			now := h.now()
			for _, r := range h.snapshotRooms() {
				if r.idleFor(now) >= timeout {
					r.Close(wsproto.ReasonIdle)
				}
			}
			h.gcInvites(now)
		}
	}
}

// Shutdown destroys all rooms, notifying members of server shutdown.
func (h *Hub) Shutdown() {
	for _, r := range h.snapshotRooms() {
		r.Close(wsproto.ReasonServerStop)
	}
}
