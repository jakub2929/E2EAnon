package httpapi_test

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
	"github.com/jakub2929/E2EAnon/internal/config"
	"github.com/jakub2929/E2EAnon/internal/httpapi"
	"github.com/jakub2929/E2EAnon/internal/relay"
	"github.com/jakub2929/E2EAnon/internal/wsproto"
)

// TestWebSocketBehindReverseProxy simulates Coolify's Traefik by putting an
// httputil.ReverseProxy in front of the relay. It verifies the WS Upgrade is
// proxied correctly and that X-Forwarded-* headers are passed through (and
// tolerated) end to end.
func TestWebSocketBehindReverseProxy(t *testing.T) {
	cfg := config.Config{Port: "0", MaxRoomSize: 10, AllowedOrigins: []string{"*"}, TrustProxy: true}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	hub := relay.NewHub(cfg, log)

	backend := httptest.NewServer(httpapi.NewServer(cfg, hub, log, nil))
	t.Cleanup(backend.Close)

	backendURL, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatal(err)
	}

	// Reverse proxy that also injects forwarded headers like a real edge proxy.
	rp := httputil.NewSingleHostReverseProxy(backendURL)
	front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Header.Set("X-Forwarded-Proto", "https")
		r.Header.Set("X-Forwarded-For", "203.0.113.7")
		rp.ServeHTTP(w, r)
	}))
	t.Cleanup(front.Close)

	wsURL := "ws" + strings.TrimPrefix(front.URL, "http") + "/ws"

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	c, _, err := websocket.Dial(ctx, wsURL, nil)
	if err != nil {
		t.Fatalf("dial through proxy: %v", err)
	}
	defer c.Close(websocket.StatusNormalClosure, "")

	if err := wsjson.Write(ctx, c, wsproto.ClientMsg{Type: wsproto.TypeCreate, Nick: "proxied"}); err != nil {
		t.Fatalf("write: %v", err)
	}
	var m wsproto.ServerMsg
	if err := wsjson.Read(ctx, c, &m); err != nil {
		t.Fatalf("read: %v", err)
	}
	if m.Type != wsproto.TypeWelcome || m.Room == "" {
		t.Fatalf("expected welcome through proxy, got %+v", m)
	}
}

// TestHealthBehindReverseProxy checks the health endpoint is reachable through
// a proxy (Coolify health checks hit it via the edge).
func TestHealthBehindReverseProxy(t *testing.T) {
	cfg := config.Config{Port: "0", MaxRoomSize: 10, AllowedOrigins: []string{"*"}, TrustProxy: true}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	hub := relay.NewHub(cfg, log)
	backend := httptest.NewServer(httpapi.NewServer(cfg, hub, log, nil))
	t.Cleanup(backend.Close)

	backendURL, _ := url.Parse(backend.URL)
	front := httptest.NewServer(httputil.NewSingleHostReverseProxy(backendURL))
	t.Cleanup(front.Close)

	resp, err := http.Get(front.URL + "/health")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 through proxy, got %d", resp.StatusCode)
	}
}
