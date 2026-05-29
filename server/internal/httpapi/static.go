package httpapi

import (
	"io/fs"
	"net/http"
	"path"
	"strings"
)

// mountStatic serves the frontend from staticFS at "/", with SPA fallback to
// index.html for unknown paths. If staticFS is nil, a plain-text placeholder is
// mounted so "/" is not a 404 (used in tests / API-only builds).
func (s *Server) mountStatic(mux *http.ServeMux, staticFS fs.FS) {
	if staticFS == nil {
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/" {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			_, _ = w.Write([]byte("AnonChat relay is running. Frontend not bundled in this build.\n"))
		})
		return
	}

	fileServer := http.FileServerFS(staticFS)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
		if name == "" || name == "." {
			http.ServeFileFS(w, r, staticFS, "index.html")
			return
		}
		// Serve the requested file if it exists and is a regular file;
		// otherwise fall back to index.html (client-side routing).
		if st, err := fs.Stat(staticFS, name); err == nil && !st.IsDir() {
			fileServer.ServeHTTP(w, r)
			return
		}
		http.ServeFileFS(w, r, staticFS, "index.html")
	})
}
