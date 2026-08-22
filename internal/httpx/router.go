package httpx

import (
	"context"
	"net/http"
	"strings"
)

// Middleware wraps a handler.
type Middleware func(http.Handler) http.Handler

// Module is a self-contained slice of the API surface.
//
// This is the extension point for future endpoint families: a WireGuard peer
// module would be a new package exposing RegisterRoutes and mounted from
// cmd/policy-controller alongside the policy and appliance modules, with no
// change to the router, the middleware chain or the metrics wiring.
//
//	type Module struct{ ... }
//	func (m *Module) Name() string { return "vpn-peers" }
//	func (m *Module) RegisterRoutes(r *Router) {
//		r.Handle(http.MethodGet, "/api/vpn-peers", m.list, m.applianceAuth)
//		r.Handle(http.MethodPost, "/api/admin/vpn-peers", m.create, m.adminAuth)
//	}
type Module interface {
	// Name identifies the module in logs and in the route listing.
	Name() string
	// RegisterRoutes installs the module's handlers.
	RegisterRoutes(r *Router)
}

// Route is a registered endpoint, exposed for logging and for the self
// description served at GET /.
type Route struct {
	Method  string `json:"method"`
	Pattern string `json:"pattern"`
	Module  string `json:"module"`
}

// Router wraps http.ServeMux with per-route middleware and route bookkeeping.
//
// It relies on the Go 1.22+ ServeMux pattern syntax ("GET /api/admin/policies/
// {ip}"), which is why there is no third-party router here: method matching and
// path wildcards are standard-library features on the Go version dnsd already
// targets.
type Router struct {
	mux     *http.ServeMux
	global  []Middleware
	routes  []Route
	current string // module being registered, for Route.Module
}

// NewRouter returns a router whose global middleware wraps every route.
func NewRouter(global ...Middleware) *Router {
	return &Router{mux: http.NewServeMux(), global: global}
}

// Mount registers a module's routes.
func (r *Router) Mount(modules ...Module) {
	for _, m := range modules {
		r.current = m.Name()
		m.RegisterRoutes(r)
	}
	r.current = ""
}

// Handle registers handler for method+pattern, wrapping it in the global
// middleware and then the per-route middleware (outermost first).
func (r *Router) Handle(method, pattern string, handler http.HandlerFunc, mws ...Middleware) {
	var h http.Handler = handler
	for i := len(mws) - 1; i >= 0; i-- {
		h = mws[i](h)
	}
	// RouteName must be applied inside the global chain so the metrics and
	// logging middleware can read the pattern.
	h = withRouteName(pattern, h)
	for i := len(r.global) - 1; i >= 0; i-- {
		h = r.global[i](h)
	}

	r.mux.Handle(method+" "+pattern, h)
	r.routes = append(r.routes, Route{Method: method, Pattern: pattern, Module: r.current})

	// ServeMux treats GET registrations as also matching HEAD, so no extra
	// registration is needed for conditional HEAD probes against /api/policies.
}

// Routes returns every registered route, sorted by pattern then method.
func (r *Router) Routes() []Route {
	out := make([]Route, len(r.routes))
	copy(out, r.routes)
	sortRoutes(out)
	return out
}

// ServeHTTP implements http.Handler.
func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	r.mux.ServeHTTP(w, req)
}

func sortRoutes(routes []Route) {
	// Insertion sort: the route table is a few dozen entries and this keeps the
	// package free of a sort import for one call site.
	for i := 1; i < len(routes); i++ {
		for j := i; j > 0 && less(routes[j], routes[j-1]); j-- {
			routes[j], routes[j-1] = routes[j-1], routes[j]
		}
	}
}

func less(a, b Route) bool {
	if a.Pattern != b.Pattern {
		return a.Pattern < b.Pattern
	}
	return a.Method < b.Method
}

type routeNameKey struct{}

func withRouteName(pattern string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if rc := routeContextFrom(r.Context()); rc != nil {
			rc.pattern = pattern
		}
		next.ServeHTTP(w, r)
	})
}

// routeContext carries the matched route pattern back out to the outer
// middleware. ServeMux only resolves the pattern after the outer chain has
// already started, so the value is filled in from the inside.
type routeContext struct{ pattern string }

func routeContextFrom(ctx context.Context) *routeContext {
	rc, _ := ctx.Value(routeNameKey{}).(*routeContext)
	return rc
}

// withRouteContext installs the slot that withRouteName later fills in. It must
// be the outermost middleware in the global chain.
func withRouteContext(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rc := &routeContext{}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), routeNameKey{}, rc)))
	})
}

// RoutePattern returns the matched pattern, or "unmatched" if the request never
// reached a registered route. It is used as the "route" metric label, which is
// why it must be a bounded set of values and never the raw URL path.
func RoutePattern(r *http.Request) string {
	if rc := routeContextFrom(r.Context()); rc != nil && rc.pattern != "" {
		return rc.pattern
	}
	return "unmatched"
}

// NormalizePath trims a trailing slash for display purposes.
func NormalizePath(p string) string {
	if len(p) > 1 {
		return strings.TrimSuffix(p, "/")
	}
	return p
}
