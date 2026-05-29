import { defineConfig } from "vite";

// AnonChat frontend build config.
// In production the Go binary serves the contents of `dist/` as static assets.
// During dev, Vite proxies WebSocket + API calls to the local Go relay.
export default defineConfig({
  server: {
    port: 5173,
    proxy: {
      "/ws": { target: "ws://localhost:8080", ws: true },
      "/api": { target: "http://localhost:8080" },
      "/health": { target: "http://localhost:8080" },
    },
  },
  build: {
    outDir: "dist",
    emptyOutDir: true,
  },
});
