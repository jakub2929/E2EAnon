# syntax=docker/dockerfile:1

# ── Stage 1: build the frontend ──────────────────────────────────────────────
FROM node:22-alpine AS web
WORKDIR /web
# Install deps against the lockfile first for better layer caching.
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ ./
RUN npm run build   # outputs /web/dist

# ── Stage 2: build the Go binary (embeds the frontend) ───────────────────────
FROM golang:1.23-alpine AS build
WORKDIR /src
# Module deps first (cached unless go.mod/go.sum change).
COPY server/go.mod server/go.sum ./
RUN go mod download
# Server source (includes the placeholder internal/webui/dist).
COPY server/ ./
# Replace the placeholder with the real built frontend so it gets embedded.
RUN rm -rf internal/webui/dist
COPY --from=web /web/dist ./internal/webui/dist
# Static, stripped, reproducible-ish binary.
ENV CGO_ENABLED=0 GOOS=linux GOFLAGS=-trimpath
RUN go build -ldflags="-s -w" -o /out/anonchat ./cmd/anonchat

# ── Stage 3: minimal runtime image ───────────────────────────────────────────
# distroless/static: no shell, nonroot user, just the binary. The container
# HEALTHCHECK uses the binary's own `-healthcheck` mode (no curl/wget needed).
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/anonchat /anonchat
ENV PORT=8080
EXPOSE 8080
USER nonroot:nonroot
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD ["/anonchat", "-healthcheck"]
ENTRYPOINT ["/anonchat"]
