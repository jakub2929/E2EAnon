package relay

import (
	"crypto/rand"
	"encoding/base32"
)

// lowerBase32 is a Crockford-ish base32 alphabet without padding, lowercased,
// avoiding ambiguous characters by relying on the standard set. Room and member
// IDs are opaque handles, not secrets.
var lowerBase32 = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

// newRoomID returns a short, URL-safe, unguessable room identifier.
func newRoomID() string {
	return randID(8) // 8 bytes -> 13 base32 chars, ~64 bits
}

// NewMemberID returns a per-connection member identifier, unique within a room.
func NewMemberID() string {
	return randID(8)
}

// NewToken returns a high-entropy opaque token of nbytes of randomness, used as
// an invite routing handle. It is independent of the SPAKE2 code.
func NewToken(nbytes int) string {
	return randID(nbytes)
}

func randID(nbytes int) string {
	b := make([]byte, nbytes)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand failure is catastrophic and not expected; panic so it is
		// loud rather than producing predictable IDs.
		panic("relay: crypto/rand failed: " + err.Error())
	}
	return lowerBase32.EncodeToString(b)
}
