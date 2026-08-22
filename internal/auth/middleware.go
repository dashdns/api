package auth

import (
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/dashdns/api/internal/httpx"
	"github.com/dashdns/api/internal/metrics"
	"github.com/dashdns/api/internal/store"
)

// TenantHeader lets a superadmin target a tenant other than its own. It is
// ignored entirely in single-tenant mode.
const TenantHeader = "X-Tenant-ID"

// RequireAppliance authenticates the appliance plane. It is the only
// middleware mounted on GET /api/policies.
func (a *Authenticator) RequireAppliance(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		principal, err := a.AuthenticateAppliance(r.Context(), r.Header.Get("Authorization"))
		if err != nil {
			a.rejectAppliance(w, r, err)
			return
		}
		next.ServeHTTP(w, r.WithContext(WithPrincipal(r.Context(), principal)))
	})
}

// RequireAdmin authenticates the management plane. Appliance tokens can never
// satisfy it: they carry a different prefix and live in a different table.
func (a *Authenticator) RequireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		principal, err := a.AuthenticateAdmin(r.Context(), r.Header.Get("Authorization"))
		if err != nil {
			a.rejectAdmin(w, r, err)
			return
		}
		next.ServeHTTP(w, r.WithContext(WithPrincipal(r.Context(), principal)))
	})
}

// RequireSuperAdmin additionally demands the superadmin role. Tenant
// management is the only thing behind it today.
func (a *Authenticator) RequireSuperAdmin(next http.Handler) http.Handler {
	return a.RequireAdmin(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !PrincipalFrom(r.Context()).IsSuperAdmin() {
			httpx.Error(w, r, http.StatusForbidden, httpx.CodeForbidden,
				"this endpoint requires the superadmin role")
			return
		}
		next.ServeHTTP(w, r)
	}))
}

func (a *Authenticator) rejectAppliance(w http.ResponseWriter, r *http.Request, err error) {
	reason := Reason(err)
	metrics.AuthFailures.WithLabelValues(metrics.PlaneAppliance, reason).Inc()

	if reason == "error" {
		httpx.Internal(w, r, err)
		return
	}
	// RFC 6750: advertise the scheme so a misconfigured dnsd logs something
	// actionable rather than a bare 401.
	w.Header().Set("WWW-Authenticate", `Bearer realm="dnsd-appliance", error="invalid_token"`)
	httpx.Errorf(w, r, http.StatusUnauthorized, httpx.CodeUnauthorized,
		"appliance authentication failed (%s); send Authorization: Bearer <appliance token>", reason)
}

func (a *Authenticator) rejectAdmin(w http.ResponseWriter, r *http.Request, err error) {
	reason := Reason(err)
	metrics.AuthFailures.WithLabelValues(metrics.PlaneAdmin, reason).Inc()

	if reason == "error" {
		httpx.Internal(w, r, err)
		return
	}
	w.Header().Set("WWW-Authenticate", `Bearer realm="dnsd-admin", error="invalid_token"`)
	httpx.Errorf(w, r, http.StatusUnauthorized, httpx.CodeUnauthorized,
		"admin authentication failed (%s); log in at POST /api/admin/auth/login", reason)
}

// ErrTenantForbidden is returned when a caller targets a tenant it may not act
// on.
var ErrTenantForbidden = errors.New("auth: tenant not permitted")

// ResolveTenant determines which tenant a request operates on.
//
//   - Single-tenant mode: always the configured default tenant. X-Tenant-ID is
//     ignored, so a self-hosted deployment cannot be talked into addressing a
//     tenant that does not exist.
//   - Multi-tenant mode: the principal's own tenant, unless a superadmin
//     overrides it with X-Tenant-ID.
func (a *Authenticator) ResolveTenant(r *http.Request) (string, error) {
	if !a.opts.MultiTenant {
		return a.opts.DefaultTenant, nil
	}

	principal := PrincipalFrom(r.Context())
	if principal == nil {
		return "", ErrInvalidCredentials
	}

	requested := strings.TrimSpace(r.Header.Get(TenantHeader))
	if requested == "" || requested == principal.TenantID {
		return principal.TenantID, nil
	}
	if principal.IsSuperAdmin() {
		return requested, nil
	}
	return "", ErrTenantForbidden
}

// TenantOrReject resolves the tenant and writes the error response itself.
// Handlers use it as: tenant, ok := a.TenantOrReject(w, r); if !ok { return }.
func (a *Authenticator) TenantOrReject(w http.ResponseWriter, r *http.Request) (string, bool) {
	tenant, err := a.ResolveTenant(r)
	switch {
	case err == nil:
		return tenant, true
	case errors.Is(err, ErrTenantForbidden):
		httpx.Errorf(w, r, http.StatusForbidden, httpx.CodeForbidden,
			"%s targets a tenant you may not act on; only superadmins can cross tenants", TenantHeader)
	default:
		httpx.Error(w, r, http.StatusUnauthorized, httpx.CodeUnauthorized, "authentication required")
	}
	return "", false
}

// EnsureTenantExists is a convenience for handlers that write into a tenant
// selected by header: in multi-tenant mode a superadmin may name a tenant that
// has not been created yet, and silently writing orphan rows would be worse
// than a clear 404.
func (a *Authenticator) EnsureTenantExists(w http.ResponseWriter, r *http.Request, tenants store.TenantRepository, tenantID string) bool {
	if _, err := tenants.GetTenant(r.Context(), tenantID); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			httpx.Errorf(w, r, http.StatusNotFound, httpx.CodeNotFound, "unknown tenant %q", tenantID)
			return false
		}
		httpx.Internal(w, r, err)
		return false
	}
	return true
}

// LogPrincipal adds the authenticated caller to the request's log attributes.
func LogPrincipal(r *http.Request) slog.Attr {
	p := PrincipalFrom(r.Context())
	if p == nil {
		return slog.String("principal", "none")
	}
	return slog.Group("principal",
		slog.String("kind", string(p.Kind)),
		slog.String("id", p.ID),
		slog.String("tenant", p.TenantID),
	)
}
