package httpapi_test

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jakub2929/E2EAnon/internal/config"
	"github.com/jakub2929/E2EAnon/internal/httpapi"
	"github.com/jakub2929/E2EAnon/internal/relay"
	"github.com/jakub2929/E2EAnon/internal/wsproto"
	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
)

func testConfig() config.Config {
	return config.Config{
		Port:           "0",
		MaxRoomSize:    10,
		AllowedOrigins: []string{"*"},
		InviteCodeTTL:  5 * time.Minute,
		// Rate limits left at 0 = disabled, except where a test sets them.
	}
}

func newServer(t *testing.T, cfg config.Config) string {
	t.Helper()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	hub := relay.NewHub(cfg, log)
	ts := httptest.NewServer(httpapi.NewServer(cfg, hub, log, nil))
	t.Cleanup(ts.Close)
	return "ws" + strings.TrimPrefix(ts.URL, "http") + "/ws"
}

func dial(t *testing.T, url string) *websocket.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	c, _, err := websocket.Dial(ctx, url, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = c.Close(websocket.StatusNormalClosure, "") })
	return c
}

func send(t *testing.T, c *websocket.Conn, m wsproto.ClientMsg) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := wsjson.Write(ctx, c, m); err != nil {
		t.Fatalf("write %s: %v", m.Type, err)
	}
}

func recvType(t *testing.T, c *websocket.Conn, typ string) wsproto.ServerMsg {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	for i := 0; i < 12; i++ {
		var m wsproto.ServerMsg
		if err := wsjson.Read(ctx, c, &m); err != nil {
			t.Fatalf("read (waiting for %q): %v", typ, err)
		}
		if m.Type == typ {
			return m
		}
	}
	t.Fatalf("did not receive %q", typ)
	return wsproto.ServerMsg{}
}

// createRoom dials, creates a room, and returns the owner conn + room id.
func createRoom(t *testing.T, url, nick string, session ...string) (*websocket.Conn, string) {
	t.Helper()
	owner := dial(t, url)
	send(t, owner, wsproto.ClientMsg{Type: wsproto.TypeCreate, Nick: nick, Session: opt(session)})
	w := recvType(t, owner, wsproto.TypeWelcome)
	return owner, w.Room
}

// opt returns the first variadic session id or "".
func opt(s []string) string {
	if len(s) > 0 {
		return s[0]
	}
	return ""
}

// getInvite has the owner request a single-use token.
func getInvite(t *testing.T, owner *websocket.Conn) string {
	t.Helper()
	send(t, owner, wsproto.ClientMsg{Type: wsproto.TypeInvite})
	return recvType(t, owner, wsproto.TypeInviteCreated).Token
}

// joinViaInvite performs the full server-side join dance with STUB handshake
// data (the server relays opaque frames; real SPAKE2 is covered by web tests).
// Returns the joiner conn and its welcome. The owner stream is drained of the
// join presence so it is clean afterwards.
func joinViaInvite(t *testing.T, url string, owner *websocket.Conn, nick string, session ...string) (*websocket.Conn, wsproto.ServerMsg) {
	t.Helper()
	token := getInvite(t, owner)

	joiner := dial(t, url)
	send(t, joiner, wsproto.ClientMsg{Type: wsproto.TypeRedeem, Token: token, Nick: nick, Session: opt(session)})
	ok := recvType(t, joiner, wsproto.TypeRedeemOk)
	hs := ok.Handshake
	ir := recvType(t, owner, wsproto.TypeInviteRedeemed)
	if ir.Handshake != hs {
		t.Fatalf("handshake id mismatch: %q vs %q", ir.Handshake, hs)
	}

	// Stub PAKE exchange relayed through the server.
	send(t, joiner, wsproto.ClientMsg{Type: wsproto.TypePake, Handshake: hs, Data: "joiner-msg"})
	if got := recvType(t, owner, wsproto.TypePake); got.Data != "joiner-msg" {
		t.Fatalf("owner got pake data %q", got.Data)
	}
	send(t, owner, wsproto.ClientMsg{Type: wsproto.TypePake, Handshake: hs, Data: "owner-msg"})
	if got := recvType(t, joiner, wsproto.TypePake); got.Data != "owner-msg" {
		t.Fatalf("joiner got pake data %q", got.Data)
	}
	send(t, owner, wsproto.ClientMsg{Type: wsproto.TypeKeyDeliver, Handshake: hs, Data: "wrapped-key"})
	if got := recvType(t, joiner, wsproto.TypeKeyDeliver); got.Data != "wrapped-key" {
		t.Fatalf("joiner got key_deliver data %q", got.Data)
	}

	// Finalize membership.
	send(t, joiner, wsproto.ClientMsg{Type: wsproto.TypeEnter, Handshake: hs})
	w := recvType(t, joiner, wsproto.TypeWelcome)
	recvType(t, joiner, wsproto.TypePresence) // drain joiner's own join presence
	recvType(t, owner, wsproto.TypePresence)  // drain owner's join presence
	return joiner, w
}

func TestCreateRoomReturnsOwnerWelcome(t *testing.T) {
	owner, room := createRoom(t, newServer(t, testConfig()), "alice")
	_ = owner
	if room == "" {
		t.Fatal("expected non-empty room id")
	}
}

func TestInviteJoinAndRelay(t *testing.T) {
	url := newServer(t, testConfig())
	owner, _ := createRoom(t, url, "alice")
	joiner, w := joinViaInvite(t, url, owner, "bob")
	if w.Role != wsproto.RoleMember {
		t.Fatalf("expected member role, got %q", w.Role)
	}

	// Encrypted body relayed verbatim from bob to alice.
	const cipher = "opaque+/ciphertext=="
	send(t, joiner, wsproto.ClientMsg{Type: wsproto.TypeMsg, Body: cipher})
	chat := recvType(t, owner, wsproto.TypeChat)
	if chat.Body != cipher || chat.Nick != "bob" {
		t.Fatalf("unexpected chat: %+v", chat)
	}
}

func TestRelayForwardsOpaqueBodyVerbatim(t *testing.T) {
	url := newServer(t, testConfig())
	owner, _ := createRoom(t, url, "alice")
	joiner, _ := joinViaInvite(t, url, owner, "bob")

	const cipher = "AbCdEf+/0123456789ZZZ==-_opaque-envelope"
	send(t, joiner, wsproto.ClientMsg{Type: wsproto.TypeMsg, Body: cipher})
	if chat := recvType(t, owner, wsproto.TypeChat); chat.Body != cipher {
		t.Fatalf("body altered by relay: got %q want %q", chat.Body, cipher)
	}
}

func TestInviteSingleUse(t *testing.T) {
	url := newServer(t, testConfig())
	owner, _ := createRoom(t, url, "alice")
	token := getInvite(t, owner)

	// First redemption succeeds (reaches handshake).
	j1 := dial(t, url)
	send(t, j1, wsproto.ClientMsg{Type: wsproto.TypeRedeem, Token: token, Nick: "bob"})
	recvType(t, j1, wsproto.TypeRedeemOk)

	// Second redemption of the same token must fail.
	j2 := dial(t, url)
	send(t, j2, wsproto.ClientMsg{Type: wsproto.TypeRedeem, Token: token, Nick: "eve"})
	if e := recvType(t, j2, wsproto.TypeError); e.Reason != wsproto.ReasonBadInvite {
		t.Fatalf("expected invalid_invite, got %q", e.Reason)
	}
}

func TestRedeemInvalidToken(t *testing.T) {
	url := newServer(t, testConfig())
	createRoom(t, url, "alice") // a room exists, but token is bogus
	c := dial(t, url)
	send(t, c, wsproto.ClientMsg{Type: wsproto.TypeRedeem, Token: "nope", Nick: "x"})
	if e := recvType(t, c, wsproto.TypeError); e.Reason != wsproto.ReasonBadInvite {
		t.Fatalf("expected invalid_invite, got %q", e.Reason)
	}
}

func TestInviteExpiry(t *testing.T) {
	cfg := testConfig()
	cfg.InviteCodeTTL = 20 * time.Millisecond
	url := newServer(t, cfg)
	owner, _ := createRoom(t, url, "alice")
	token := getInvite(t, owner)

	time.Sleep(40 * time.Millisecond)
	c := dial(t, url)
	send(t, c, wsproto.ClientMsg{Type: wsproto.TypeRedeem, Token: token, Nick: "late"})
	if e := recvType(t, c, wsproto.TypeError); e.Reason != wsproto.ReasonBadInvite {
		t.Fatalf("expected invalid_invite after expiry, got %q", e.Reason)
	}
}

func TestOnlyOwnerCanInvite(t *testing.T) {
	url := newServer(t, testConfig())
	owner, _ := createRoom(t, url, "alice")
	joiner, _ := joinViaInvite(t, url, owner, "bob")

	send(t, joiner, wsproto.ClientMsg{Type: wsproto.TypeInvite})
	if e := recvType(t, joiner, wsproto.TypeError); e.Reason != wsproto.ReasonNotOwner {
		t.Fatalf("expected not_owner, got %q", e.Reason)
	}
}

func TestMaxRoomSizeEnforced(t *testing.T) {
	cfg := testConfig()
	cfg.MaxRoomSize = 2
	url := newServer(t, cfg)
	owner, _ := createRoom(t, url, "a")
	joinViaInvite(t, url, owner, "b") // room now full (2)

	// A third redemption is rejected at redeem time (no capacity).
	token := getInvite(t, owner)
	j3 := dial(t, url)
	send(t, j3, wsproto.ClientMsg{Type: wsproto.TypeRedeem, Token: token, Nick: "c"})
	if e := recvType(t, j3, wsproto.TypeError); e.Reason != wsproto.ReasonRoomFull {
		t.Fatalf("expected room_full, got %q", e.Reason)
	}
}

func TestOwnerLeaveDestroysRoom(t *testing.T) {
	url := newServer(t, testConfig())
	owner, _ := createRoom(t, url, "alice")
	joiner, _ := joinViaInvite(t, url, owner, "bob")

	send(t, owner, wsproto.ClientMsg{Type: wsproto.TypeLeave})
	if closed := recvType(t, joiner, wsproto.TypeRoomClosed); closed.Reason != wsproto.ReasonOwnerLeft {
		t.Fatalf("expected owner_left, got %q", closed.Reason)
	}
}

func TestNonOwnerLeaveKeepsRoom(t *testing.T) {
	url := newServer(t, testConfig())
	owner, _ := createRoom(t, url, "alice")
	joiner, _ := joinViaInvite(t, url, owner, "bob")

	_ = joiner.Close(websocket.StatusNormalClosure, "bye")
	if pres := recvType(t, owner, wsproto.TypePresence); len(pres.Members) != 1 {
		t.Fatalf("expected 1 member after leave, got %d", len(pres.Members))
	}
}

func TestRateLimitRedeem(t *testing.T) {
	cfg := testConfig()
	cfg.RateLimitRedeemPerMin = 1
	url := newServer(t, cfg)
	owner, _ := createRoom(t, url, "alice")

	t1 := getInvite(t, owner)
	j1 := dial(t, url)
	send(t, j1, wsproto.ClientMsg{Type: wsproto.TypeRedeem, Token: t1, Nick: "bob"})
	recvType(t, j1, wsproto.TypeRedeemOk) // first allowed

	t2 := getInvite(t, owner)
	j2 := dial(t, url)
	send(t, j2, wsproto.ClientMsg{Type: wsproto.TypeRedeem, Token: t2, Nick: "eve"})
	if e := recvType(t, j2, wsproto.TypeError); e.Reason != wsproto.ReasonRateLimited {
		t.Fatalf("expected rate_limited, got %q", e.Reason)
	}
}

func TestRekeyRoutedToTargetMember(t *testing.T) {
	url := newServer(t, testConfig())
	owner, _ := createRoom(t, url, "alice")
	joiner, jw := joinViaInvite(t, url, owner, "bob")

	// Owner sends a rotated key to bob; the server routes it to bob only.
	send(t, owner, wsproto.ClientMsg{Type: wsproto.TypeRekey, Target: jw.MemberID, Data: "sealed-key"})
	if got := recvType(t, joiner, wsproto.TypeRekey); got.Data != "sealed-key" {
		t.Fatalf("bob got rekey data %q", got.Data)
	}
}

func TestRekeyFromNonOwnerDropped(t *testing.T) {
	url := newServer(t, testConfig())
	owner, _ := createRoom(t, url, "alice")
	joiner, jw := joinViaInvite(t, url, owner, "bob")

	// Bob (not owner) tries to rekey itself; the server must drop it, so bob
	// receives nothing.
	send(t, joiner, wsproto.ClientMsg{Type: wsproto.TypeRekey, Target: jw.MemberID, Data: "evil"})
	if m, ok := recvRaw(joiner, 300*time.Millisecond); ok {
		t.Fatalf("expected no frame from a non-owner rekey, got %+v", m)
	}
}

// recvRaw reads the next frame within d, returning ok=false on timeout.
func recvRaw(c *websocket.Conn, d time.Duration) (wsproto.ServerMsg, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	var m wsproto.ServerMsg
	if err := wsjson.Read(ctx, c, &m); err != nil {
		return wsproto.ServerMsg{}, false
	}
	return m, true
}

func roleOf(members []wsproto.MemberInfo, id string) string {
	for _, m := range members {
		if m.ID == id {
			return m.Role
		}
	}
	return ""
}

func TestTransferOwnership(t *testing.T) {
	url := newServer(t, testConfig())
	owner, _ := createRoom(t, url, "alice")
	joiner, jw := joinViaInvite(t, url, owner, "bob")

	send(t, owner, wsproto.ClientMsg{Type: wsproto.TypeTransfer, Target: jw.MemberID})
	pres := recvType(t, joiner, wsproto.TypePresence)
	if roleOf(pres.Members, jw.MemberID) != wsproto.RoleOwner {
		t.Fatalf("expected bob to be owner: %+v", pres.Members)
	}
	owners := 0
	for _, m := range pres.Members {
		if m.Role == wsproto.RoleOwner {
			owners++
		}
	}
	if owners != 1 {
		t.Fatalf("expected exactly one owner, got %d", owners)
	}
}

func TestTransferThenOldOwnerLeaveKeepsRoom(t *testing.T) {
	url := newServer(t, testConfig())
	owner, _ := createRoom(t, url, "alice")
	joiner, jw := joinViaInvite(t, url, owner, "bob")

	send(t, owner, wsproto.ClientMsg{Type: wsproto.TypeTransfer, Target: jw.MemberID})
	recvType(t, owner, wsproto.TypePresence)
	recvType(t, joiner, wsproto.TypePresence)

	// Old owner (alice) leaves; room must survive because bob is now owner.
	_ = owner.Close(websocket.StatusNormalClosure, "bye")
	pres := recvType(t, joiner, wsproto.TypePresence)
	if len(pres.Members) != 1 || roleOf(pres.Members, jw.MemberID) != wsproto.RoleOwner {
		t.Fatalf("room should survive with bob as owner: %+v", pres.Members)
	}
}

func TestKickMember(t *testing.T) {
	url := newServer(t, testConfig())
	owner, _ := createRoom(t, url, "alice")
	joiner, jw := joinViaInvite(t, url, owner, "bob")

	send(t, owner, wsproto.ClientMsg{Type: wsproto.TypeKick, Target: jw.MemberID})
	if closed := recvType(t, joiner, wsproto.TypeRoomClosed); closed.Reason != wsproto.ReasonKicked {
		t.Fatalf("expected kicked, got %q", closed.Reason)
	}
	if pres := recvType(t, owner, wsproto.TypePresence); len(pres.Members) != 1 {
		t.Fatalf("expected 1 member after kick, got %d", len(pres.Members))
	}
}

func TestNonOwnerCannotTransferOrKick(t *testing.T) {
	url := newServer(t, testConfig())
	owner, _ := createRoom(t, url, "alice")
	joiner, jw := joinViaInvite(t, url, owner, "bob")

	send(t, joiner, wsproto.ClientMsg{Type: wsproto.TypeTransfer, Target: jw.MemberID})
	if e := recvType(t, joiner, wsproto.TypeError); e.Reason != wsproto.ReasonNotOwner {
		t.Fatalf("expected not_owner for transfer, got %q", e.Reason)
	}
	send(t, joiner, wsproto.ClientMsg{Type: wsproto.TypeKick, Target: jw.MemberID})
	if e := recvType(t, joiner, wsproto.TypeError); e.Reason != wsproto.ReasonNotOwner {
		t.Fatalf("expected not_owner for kick, got %q", e.Reason)
	}
}

func TestRosterBroadcastOwnerOnly(t *testing.T) {
	url := newServer(t, testConfig())
	owner, _ := createRoom(t, url, "alice")
	joiner, _ := joinViaInvite(t, url, owner, "bob")

	// Owner roster reaches bob.
	send(t, owner, wsproto.ClientMsg{Type: wsproto.TypeRoster, Data: "roster-blob"})
	if got := recvType(t, joiner, wsproto.TypeRoster); got.Data != "roster-blob" {
		t.Fatalf("bob got roster %q", got.Data)
	}
	// Non-owner roster is dropped (bob -> nobody).
	send(t, joiner, wsproto.ClientMsg{Type: wsproto.TypeRoster, Data: "evil"})
	if m, ok := recvRaw(owner, 300*time.Millisecond); ok {
		t.Fatalf("owner should receive nothing from a non-owner roster, got %+v", m)
	}
}

// ── v2: one room per session ────────────────────────────────────────────────

func TestSecondRoomSameSessionRejected(t *testing.T) {
	url := newServer(t, testConfig())
	c1, _ := createRoom(t, url, "alice", "sess-1")
	_ = c1

	// Same session id tries to create a second room -> rejected.
	c2 := dial(t, url)
	send(t, c2, wsproto.ClientMsg{Type: wsproto.TypeCreate, Nick: "alice2", Session: "sess-1"})
	if e := recvType(t, c2, wsproto.TypeError); e.Reason != wsproto.ReasonInRoom {
		t.Fatalf("expected already_in_room, got %q", e.Reason)
	}

	// A different session id can create freely.
	c3, _ := createRoom(t, url, "carol", "sess-2")
	_ = c3
}

func TestDifferentSessionsAllowed(t *testing.T) {
	url := newServer(t, testConfig())
	createRoom(t, url, "a", "s1")
	createRoom(t, url, "b", "s2")
	createRoom(t, url, "c", "") // empty session = no tracking, always allowed
	createRoom(t, url, "d", "")
}

// canCreate reports whether a fresh connection with the given session id can
// create a room (true) or is rejected as already_in_room (false).
func canCreate(t *testing.T, url, session string) bool {
	t.Helper()
	c := dial(t, url)
	send(t, c, wsproto.ClientMsg{Type: wsproto.TypeCreate, Nick: "x", Session: session})
	m, ok := recvRaw(c, time.Second)
	if !ok {
		t.Fatal("no response to create")
	}
	return m.Type == wsproto.TypeWelcome
}

func TestLeaveThenJoinSameSession(t *testing.T) {
	url := newServer(t, testConfig())
	c1, _ := createRoom(t, url, "alice", "sx")

	// Graceful leave frees the session.
	send(t, c1, wsproto.ClientMsg{Type: wsproto.TypeLeave})

	// Cleanup is async (server read-loop teardown); poll briefly.
	freed := false
	for i := 0; i < 30; i++ {
		if canCreate(t, url, "sx") {
			freed = true
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !freed {
		t.Fatal("session was not freed after leave")
	}
}

func TestDisconnectFreesSession(t *testing.T) {
	url := newServer(t, testConfig())
	c1, _ := createRoom(t, url, "alice", "sd")

	// Abrupt disconnect (no graceful leave) must also free the session.
	_ = c1.Close(websocket.StatusNormalClosure, "bye")

	freed := false
	for i := 0; i < 30; i++ {
		if canCreate(t, url, "sd") {
			freed = true
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !freed {
		t.Fatal("session was not freed after disconnect")
	}
}

// TestBlockedRedeemDoesNotBurnInvite is the regression for the design promise:
// a redeem rejected by the one-room rule must NOT consume the single-use token.
func TestBlockedRedeemDoesNotBurnInvite(t *testing.T) {
	url := newServer(t, testConfig())
	owner, _ := createRoom(t, url, "alice", "sA")
	token := getInvite(t, owner)

	// A connection reusing session "sA" (already in a room) tries to redeem.
	bad := dial(t, url)
	send(t, bad, wsproto.ClientMsg{Type: wsproto.TypeRedeem, Token: token, Nick: "x", Session: "sA"})
	if e := recvType(t, bad, wsproto.TypeError); e.Reason != wsproto.ReasonInRoom {
		t.Fatalf("expected already_in_room, got %q", e.Reason)
	}

	// The token must still be valid: a fresh session redeems it successfully.
	good := dial(t, url)
	send(t, good, wsproto.ClientMsg{Type: wsproto.TypeRedeem, Token: token, Nick: "bob", Session: "sB"})
	if got := recvType(t, good, wsproto.TypeRedeemOk); got.Handshake == "" {
		t.Fatal("token was burned by the blocked redeem; fresh redeem failed")
	}
}

func TestOwnerLeaveFreesAllSessions(t *testing.T) {
	url := newServer(t, testConfig())
	owner, _ := createRoom(t, url, "alice", "sA")
	joiner, _ := joinViaInvite(t, url, owner, "bob", "sB")

	// Owner leaves -> room destroyed -> every member's session is freed.
	send(t, owner, wsproto.ClientMsg{Type: wsproto.TypeLeave})
	if c := recvType(t, joiner, wsproto.TypeRoomClosed); c.Reason != wsproto.ReasonOwnerLeft {
		t.Fatalf("expected owner_left, got %q", c.Reason)
	}

	for _, sid := range []string{"sA", "sB"} {
		freed := false
		for i := 0; i < 30; i++ {
			if canCreate(t, url, sid) {
				freed = true
				break
			}
			time.Sleep(50 * time.Millisecond)
		}
		if !freed {
			t.Fatalf("session %q not freed after owner left", sid)
		}
	}
}

func TestBadHelloRejected(t *testing.T) {
	url := newServer(t, testConfig())
	c := dial(t, url)
	send(t, c, wsproto.ClientMsg{Type: wsproto.TypeMsg, Body: "no hello"})
	if e := recvType(t, c, wsproto.TypeError); e.Reason != wsproto.ReasonBadRequest {
		t.Fatalf("expected bad_request, got %q", e.Reason)
	}
}

func TestHealthEndpoint(t *testing.T) {
	cfg := testConfig()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	hub := relay.NewHub(cfg, log)
	ts := httptest.NewServer(httpapi.NewServer(cfg, hub, log, nil))
	t.Cleanup(ts.Close)

	resp, err := http.Get(ts.URL + "/health")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}
