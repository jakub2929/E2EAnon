// Command anonchat is the AnonChat blind-relay server.
//
// It is a single static binary that exposes a WebSocket relay, a health check,
// and (optionally) the static frontend. All room state is held in memory; the
// server never persists anything and never sees plaintext (from Phase 3 on).
package main

import (
	"context"
	"errors"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/jakub2929/E2EAnon/internal/config"
	"github.com/jakub2929/E2EAnon/internal/httpapi"
	"github.com/jakub2929/E2EAnon/internal/relay"
	"github.com/jakub2929/E2EAnon/internal/webui"
)

func main() {
	// Self health-probe mode for container HEALTHCHECK (shell-less images).
	if len(os.Args) > 1 && (os.Args[1] == "-healthcheck" || os.Args[1] == "--healthcheck") {
		os.Exit(healthProbe())
	}
	if err := run(); err != nil {
		slog.Error("fatal", "err", err)
		os.Exit(1)
	}
}

// healthProbe performs a local GET /health and maps the result to an exit code.
func healthProbe() int {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get("http://127.0.0.1:" + port + "/health")
	if err != nil {
		return 1
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		return 0
	}
	return 1
}

// staticFS chooses the frontend asset source: disk (STATIC_DIR) overrides the
// embedded build; nil falls back to a placeholder.
func staticFS(cfg config.Config, log *slog.Logger) fs.FS {
	if cfg.StaticDir != "" {
		log.Info("serving frontend from disk", "dir", cfg.StaticDir)
		return os.DirFS(cfg.StaticDir)
	}
	f, err := webui.FS()
	if err != nil {
		log.Warn("embedded frontend unavailable", "err", err)
		return nil
	}
	return f
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	log := newLogger(cfg)

	// Root context cancelled on SIGINT/SIGTERM for graceful shutdown.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	hub := relay.NewHub(cfg, log)
	go hub.StartJanitor(ctx)

	handler := httpapi.NewServer(cfg, hub, log, staticFS(cfg, log))
	srv := &http.Server{
		Addr:              net.JoinHostPort("0.0.0.0", cfg.Port),
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		// No WriteTimeout: WebSocket connections are long-lived.
	}

	serveErr := make(chan error, 1)
	go func() {
		log.Info("listening", "addr", srv.Addr, "max_room_size", cfg.MaxRoomSize,
			"idle_timeout", cfg.RoomIdleTimeout.String(), "allow_any_origin", cfg.AllowAnyOrigin())
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serveErr <- err
		}
	}()

	select {
	case err := <-serveErr:
		return err
	case <-ctx.Done():
		log.Info("shutdown signal received")
	}

	// Graceful shutdown: destroy all rooms (notifies clients), then drain HTTP.
	hub.Shutdown()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Warn("graceful shutdown timed out", "err", err)
		return srv.Close()
	}
	log.Info("shutdown complete")
	return nil
}

func newLogger(cfg config.Config) *slog.Logger {
	var level slog.Level
	switch strings.ToLower(cfg.LogLevel) {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}
	opts := &slog.HandlerOptions{Level: level}
	var h slog.Handler
	if strings.ToLower(cfg.LogFormat) == "json" {
		h = slog.NewJSONHandler(os.Stderr, opts)
	} else {
		h = slog.NewTextHandler(os.Stderr, opts)
	}
	return slog.New(h)
}
