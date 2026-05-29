package relay

import (
	"context"
	"time"

	"github.com/jakub2929/E2EAnon/internal/wsproto"
	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
)

// outboundBuffer is the number of queued server messages per client before
// writes block. A slow client that fills its buffer is disconnected rather
// than allowed to stall the room.
const outboundBuffer = 32

// writeTimeout bounds a single frame write.
const writeTimeout = 10 * time.Second

// Client represents one connected member's connection within a room.
type Client struct {
	id   string
	nick string
	conn *websocket.Conn

	// out is the per-client outbound queue, drained by WritePump. It is closed
	// exactly once: either by the owning Room (on leave/teardown) or by
	// CloseOut (for a client that never joined a room). These paths are
	// mutually exclusive.
	out chan wsproto.ServerMsg

	// done is closed when the client's write pump exits.
	done chan struct{}
}

// NewClient builds a client for an accepted connection.
func NewClient(id, nick string, conn *websocket.Conn) *Client {
	return &Client{
		id:   id,
		nick: nick,
		conn: conn,
		out:  make(chan wsproto.ServerMsg, outboundBuffer),
		done: make(chan struct{}),
	}
}

// ID returns the member ID.
func (c *Client) ID() string { return c.id }

// Nick returns the member's nickname.
func (c *Client) Nick() string { return c.nick }

// Done returns a channel closed when the write pump has exited.
func (c *Client) Done() <-chan struct{} { return c.done }

// Role returns this client's role within the given room.
func (c *Client) Role(r *Room) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if c.id == r.ownerID {
		return wsproto.RoleOwner
	}
	return wsproto.RoleMember
}

// Send queues a message to the client (non-blocking via trySend).
func (c *Client) Send(m wsproto.ServerMsg) { c.trySend(m) }

// CloseOut closes the outbound channel for a client that was never added to a
// room (e.g. failed join). Must not be used once the client is in a room.
func (c *Client) CloseOut() { close(c.out) }

// trySend enqueues a message without blocking. Returns false if the buffer is
// full (caller should treat the client as too slow and drop it).
func (c *Client) trySend(m wsproto.ServerMsg) bool {
	select {
	case c.out <- m:
		return true
	default:
		return false
	}
}

// WritePump drains the outbound queue to the websocket. It exits when out is
// closed (room teardown / member leave) or a write fails. On exit it closes the
// websocket, which unblocks the client's read loop. This makes WritePump the
// single owner of connection closure, avoiding double-close races.
func (c *Client) WritePump(ctx context.Context) {
	defer close(c.done)
	defer c.conn.Close(websocket.StatusNormalClosure, "")
	for {
		select {
		case <-ctx.Done():
			return
		case m, ok := <-c.out:
			if !ok {
				return
			}
			wctx, cancel := context.WithTimeout(ctx, writeTimeout)
			err := wsjson.Write(wctx, c.conn, m)
			cancel()
			if err != nil {
				return
			}
		}
	}
}
