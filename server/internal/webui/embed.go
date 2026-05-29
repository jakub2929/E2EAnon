// Package webui embeds the built frontend so the server ships as a single
// self-contained binary.
//
// In dev, internal/webui/dist holds only a placeholder index.html (committed so
// `go build` always works). In Docker builds, that directory is replaced with
// the real Vite output before compilation, producing a binary that serves the
// full app with no external files.
//
// Setting STATIC_DIR overrides the embedded assets with files from disk.
package webui

import (
	"embed"
	"io/fs"
)

//go:embed dist
var embedded embed.FS

// FS returns the embedded frontend filesystem rooted at the asset directory.
func FS() (fs.FS, error) {
	return fs.Sub(embedded, "dist")
}
