package relay

import (
	"io"
	"log/slog"
	"testing"

	"github.com/jakub2929/E2EAnon/internal/config"
)

func testHub() *Hub {
	return NewHub(config.Config{MaxRoomSize: 10}, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

// TestSessionClaimCASRace exercises the compare-and-delete guard for the
// fast-disconnect-then-reconnect-with-the-same-session-id race: a stale cleanup
// from the old connection must never delete the new connection's claim.
func TestSessionClaimCASRace(t *testing.T) {
	h := testHub()
	a := NewClient("a", "", nil)
	b := NewClient("b", "", nil)
	c := NewClient("c", "", nil)

	if !h.TryClaimSession("S", a) {
		t.Fatal("A should be able to claim S")
	}
	if h.TryClaimSession("S", b) {
		t.Fatal("B must not claim S while A holds it")
	}
	// A wrong-owner clear is a no-op (B does not own S).
	h.ClearSession("S", b)
	if h.TryClaimSession("S", b) {
		t.Fatal("B still must not claim S (A holds it)")
	}

	// A releases S; now B can take it over.
	h.ClearSession("S", a)
	if !h.TryClaimSession("S", b) {
		t.Fatal("B should claim S after A released it")
	}

	// THE RACE: a late/duplicate cleanup from A must NOT delete B's claim.
	h.ClearSession("S", a)
	if h.TryClaimSession("S", c) {
		t.Fatal("A's stale ClearSession deleted B's claim — CAS guard failed")
	}

	// Empty session id is never tracked and always succeeds.
	if !h.TryClaimSession("", a) || !h.TryClaimSession("", b) {
		t.Fatal("empty session id must always succeed")
	}
	if got := h.SessionCount(); got != 1 {
		t.Fatalf("expected exactly 1 tracked session (S->B), got %d", got)
	}
}
