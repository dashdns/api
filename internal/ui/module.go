// Package ui serves the static admin dashboard for the HTTP API.
//
// The assets are embedded in the binary, so a deployment stays a single file,
// and they are served from the API listener itself. Same origin as /api means
// the browser never needs a preflight and the server never needs CORS --
// which is why the dashboard is a module here rather than a separate artefact.
package ui

import (
	"embed"
	"io/fs"
	"net/http"

	"github.com/dashdns/api/internal/httpx"
)

//go:embed static
var assets embed.FS

// Module serves the dashboard under /ui/.
type Module struct {
	files http.Handler
}

// New returns a ui Module. A missing asset tree is a build-time mistake, not a
// runtime condition, so it panics rather than degrading the server.
func New() *Module {
	sub, err := fs.Sub(assets, "static")
	if err != nil {
		panic("ui: embedded assets missing: " + err.Error())
	}
	return &Module{files: http.StripPrefix("/ui/", http.FileServerFS(sub))}
}

// Name implements httpx.Module.
func (m *Module) Name() string { return "ui" }

// RegisterRoutes implements httpx.Module. ServeMux redirects /ui to /ui/ on
// its own, so the subtree pattern is the only registration needed.
func (m *Module) RegisterRoutes(r *httpx.Router) {
	r.Handle(http.MethodGet, "/ui/", m.serve)
}

func (m *Module) serve(w http.ResponseWriter, r *http.Request) {
	// The dashboard ships with the binary it talks to. Revalidating on every
	// load keeps an upgraded controller from being driven by a cached older UI
	// whose request shapes the strict JSON decoder would now reject.
	w.Header().Set("Cache-Control", "no-cache")
	m.files.ServeHTTP(w, r)
}
