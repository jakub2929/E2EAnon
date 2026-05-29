package relay

import "time"

// invite is a single-use invitation token bound to a room.
//
// Security note: the token is an opaque, high-entropy ROUTING handle generated
// by the owner's client (the server never learns the 10-char SPAKE2 code). It
// exists only so the server can enforce single-use + expiry and pair the joiner
// with the owner. It is independent of the code, so it leaks nothing about it.
type invite struct {
	roomID    string
	expiresAt time.Time
}

// CreateInvite registers a single-use token for a room with the configured TTL.
func (h *Hub) CreateInvite(token, roomID string) time.Time {
	exp := h.now().Add(h.cfg.InviteCodeTTL)
	h.mu.Lock()
	h.invites[token] = invite{roomID: roomID, expiresAt: exp}
	h.mu.Unlock()
	return exp
}

// RedeemInvite atomically validates and consumes a token. It returns the bound
// room ID on success. Expired or unknown tokens fail; a valid token is deleted
// so it can never be redeemed twice.
func (h *Hub) RedeemInvite(token string) (roomID string, ok bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	inv, exists := h.invites[token]
	if !exists {
		return "", false
	}
	// Consume on any redemption attempt against a known token (single-use).
	delete(h.invites, token)
	if h.now().After(inv.expiresAt) {
		return "", false
	}
	return inv.roomID, true
}

// dropInvitesForRoom removes any outstanding tokens for a destroyed room.
func (h *Hub) dropInvitesForRoom(roomID string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for tok, inv := range h.invites {
		if inv.roomID == roomID {
			delete(h.invites, tok)
		}
	}
}

// gcInvites drops expired tokens (called by the janitor).
func (h *Hub) gcInvites(now time.Time) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for tok, inv := range h.invites {
		if now.After(inv.expiresAt) {
			delete(h.invites, tok)
		}
	}
}

// Handshake pairs a redeeming joiner with the room owner for a PAKE exchange.
// The joiner is NOT a room member until it sends `enter` after the handshake.
type Handshake struct {
	id     string
	roomID string
	joiner *Client
	owner  *Client
}

// NewHandshake registers a handshake session and returns its id.
func (h *Hub) NewHandshake(roomID string, joiner, owner *Client) string {
	id := randID(8)
	h.mu.Lock()
	h.handshakes[id] = &Handshake{id: id, roomID: roomID, joiner: joiner, owner: owner}
	h.mu.Unlock()
	return id
}

// GetHandshake looks up a handshake session.
func (h *Hub) GetHandshake(id string) (*Handshake, bool) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	hs, ok := h.handshakes[id]
	return hs, ok
}

// EndHandshake removes a handshake session.
func (h *Hub) EndHandshake(id string) {
	h.mu.Lock()
	delete(h.handshakes, id)
	h.mu.Unlock()
}

// EndHandshakesFor removes all handshakes involving the given client (used when
// a client disconnects mid-handshake), notifying the peer where possible.
func (h *Hub) EndHandshakesFor(c *Client) {
	h.mu.Lock()
	var affected []*Handshake
	for id, hs := range h.handshakes {
		if hs.joiner == c || hs.owner == c {
			affected = append(affected, hs)
			delete(h.handshakes, id)
		}
	}
	h.mu.Unlock()
	// Nothing else to do here; peers observe handshake failure via timeout /
	// missing frames. (Kept as a hook for clearer signaling later.)
	_ = affected
}

// Peer returns the other party of the handshake relative to c.
func (hs *Handshake) Peer(c *Client) *Client {
	if hs.joiner == c {
		return hs.owner
	}
	if hs.owner == c {
		return hs.joiner
	}
	return nil
}
