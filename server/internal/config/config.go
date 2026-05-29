// Package config loads AnonChat server configuration from environment
// variables. All configuration is via env vars (see .env.example); there are
// no config files and no secrets.
package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config holds the resolved runtime configuration.
type Config struct {
	// Port the HTTP/WS server binds to. Always bound on 0.0.0.0.
	Port string
	// MaxRoomSize is the hard cap on members per room (spec: 10).
	MaxRoomSize int
	// RoomIdleTimeout is how long a room may sit idle before it is destroyed
	// and its RAM wiped. Zero disables idle GC.
	RoomIdleTimeout time.Duration
	// AllowedOrigins is the set of permitted Origin header values for the WS
	// handshake. A single "*" entry allows any origin (development only).
	AllowedOrigins []string
	// TrustProxy enables honoring X-Forwarded-* headers from a reverse proxy.
	TrustProxy bool
	// StaticDir is the directory of built frontend assets to serve. Empty
	// disables static serving (API/WS only).
	StaticDir string

	// InviteCodeTTL is how long a single-use invite token remains valid.
	InviteCodeTTL time.Duration
	// RateLimitCreatePerMin caps room-creation requests per source IP per min.
	RateLimitCreatePerMin int
	// RateLimitRedeemPerMin caps invite-redemption attempts per source IP/min.
	RateLimitRedeemPerMin int

	LogLevel  string
	LogFormat string
}

// Load reads configuration from the environment, applying defaults.
func Load() (Config, error) {
	c := Config{
		Port:           getenv("PORT", "8080"),
		AllowedOrigins: splitCSV(getenv("ALLOWED_ORIGINS", "*")),
		TrustProxy:     getbool("TRUST_PROXY", false),
		StaticDir:      getenv("STATIC_DIR", ""),
		LogLevel:       getenv("LOG_LEVEL", "info"),
		LogFormat:      getenv("LOG_FORMAT", "text"),
	}

	var err error
	if c.MaxRoomSize, err = getint("MAX_ROOM_SIZE", 10); err != nil {
		return Config{}, err
	}
	if c.MaxRoomSize < 1 {
		return Config{}, fmt.Errorf("MAX_ROOM_SIZE must be >= 1, got %d", c.MaxRoomSize)
	}
	if c.RoomIdleTimeout, err = getdur("ROOM_IDLE_TIMEOUT", 30*time.Minute); err != nil {
		return Config{}, err
	}
	if c.InviteCodeTTL, err = getdur("INVITE_CODE_TTL", 5*time.Minute); err != nil {
		return Config{}, err
	}
	if c.RateLimitCreatePerMin, err = getint("RATE_LIMIT_CREATE_PER_MIN", 10); err != nil {
		return Config{}, err
	}
	if c.RateLimitRedeemPerMin, err = getint("RATE_LIMIT_REDEEM_PER_MIN", 20); err != nil {
		return Config{}, err
	}

	return c, nil
}

// AllowAnyOrigin reports whether the WS handshake should accept any origin.
func (c Config) AllowAnyOrigin() bool {
	for _, o := range c.AllowedOrigins {
		if o == "*" {
			return true
		}
	}
	return false
}

func getenv(key, def string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return def
}

func getbool(key string, def bool) bool {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return def
	}
	return b
}

func getint(key string, def int) (int, error) {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, fmt.Errorf("invalid %s: %w", key, err)
	}
	return n, nil
}

func getdur(key string, def time.Duration) (time.Duration, error) {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return def, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0, fmt.Errorf("invalid %s: %w", key, err)
	}
	return d, nil
}

func splitCSV(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
