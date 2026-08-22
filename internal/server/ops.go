package server

import (
	"net/http"
	"time"

	"github.com/dashdns/api/internal/httpx"
	"github.com/dashdns/api/internal/store"
)

// opsModule serves the unauthenticated operational endpoints: liveness,
// readiness and a self-describing route index.
type opsModule struct {
	store   store.Store
	router  *httpx.Router
	version string
	mode    string
	started time.Time
}

func (o *opsModule) Name() string { return "ops" }

func (o *opsModule) RegisterRoutes(r *httpx.Router) {
	r.Handle(http.MethodGet, "/healthz", o.handleHealthz)
	r.Handle(http.MethodGet, "/readyz", o.handleReadyz)
	r.Handle(http.MethodGet, "/", o.handleIndex)
}

// handleHealthz reports process liveness only; it must not touch the database,
// or a database blip would get the process restarted rather than just marked
// unready.
func (o *opsModule) handleHealthz(w http.ResponseWriter, r *http.Request) {
	httpx.JSON(w, r, http.StatusOK, map[string]any{
		"status":         "ok",
		"version":        o.version,
		"mode":           o.mode,
		"uptime_seconds": int64(time.Since(o.started).Seconds()),
	})
}

// handleReadyz reports whether the service can actually serve policies.
func (o *opsModule) handleReadyz(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := contextWithTimeout(r, 2*time.Second)
	defer cancel()

	if err := o.store.Ping(ctx); err != nil {
		httpx.JSON(w, r, http.StatusServiceUnavailable, map[string]any{
			"status": "unavailable",
			"reason": "database unreachable",
		})
		return
	}
	httpx.JSON(w, r, http.StatusOK, map[string]any{"status": "ready"})
}

// handleIndex lists the mounted routes. It is the cheapest way for an operator
// to confirm which modules a given build has mounted -- for instance whether
// the tenant routes are present in this deployment's mode.
func (o *opsModule) handleIndex(w http.ResponseWriter, r *http.Request) {
	// ServeMux routes "/" as a catch-all, so anything unmatched lands here.
	if httpx.NormalizePath(r.URL.Path) != "" {
		httpx.Errorf(w, r, http.StatusNotFound, httpx.CodeNotFound, "no route for %s %s", r.Method, r.URL.Path)
		return
	}
	httpx.JSON(w, r, http.StatusOK, map[string]any{
		"service": "policy-controller",
		"version": o.version,
		"mode":    o.mode,
		"routes":  o.router.Routes(),
	})
}
