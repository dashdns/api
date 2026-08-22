// Package identity implements the management-plane login flow and, when
// tenant isolation is enabled, tenant administration.
package identity

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/dashdns/api/internal/auth"
	"github.com/dashdns/api/internal/httpx"
	"github.com/dashdns/api/internal/metrics"
	"github.com/dashdns/api/internal/store"
)

// Module serves /api/admin/auth/* and /api/admin/tenants/*.
type Module struct {
	admins  store.AdminRepository
	tenants store.TenantRepository
	authn   *auth.Authenticator
	// multiTenant mirrors config.Config.MultiTenant; the tenant routes are only
	// mounted when it is true.
	multiTenant bool
}

// Deps are the Module's collaborators.
type Deps struct {
	Admins      store.AdminRepository
	Tenants     store.TenantRepository
	Auth        *auth.Authenticator
	MultiTenant bool
}

// New returns an identity Module.
func New(d Deps) *Module {
	return &Module{admins: d.Admins, tenants: d.Tenants, authn: d.Auth, multiTenant: d.MultiTenant}
}

// Name implements httpx.Module.
func (m *Module) Name() string { return "identity" }

// RegisterRoutes implements httpx.Module.
func (m *Module) RegisterRoutes(r *httpx.Router) {
	// Login is the one admin route without admin auth; it is what mints it.
	r.Handle(http.MethodPost, "/api/admin/auth/login", m.handleLogin)
	r.Handle(http.MethodPost, "/api/admin/auth/logout", m.handleLogout, m.authn.RequireAdmin)
	r.Handle(http.MethodGet, "/api/admin/auth/whoami", m.handleWhoami, m.authn.RequireAdmin)

	if !m.multiTenant {
		// In single-tenant mode there is nothing to administer: the tenant is
		// fixed by -default-tenant and created at startup. Leaving the routes
		// unmounted turns a misdirected call into a clean 404 instead of a
		// half-working operation.
		return
	}
	super := m.authn.RequireSuperAdmin
	r.Handle(http.MethodGet, "/api/admin/tenants", m.handleListTenants, super)
	r.Handle(http.MethodPost, "/api/admin/tenants", m.handleCreateTenant, super)
	r.Handle(http.MethodGet, "/api/admin/tenants/{id}", m.handleGetTenant, super)
	r.Handle(http.MethodDelete, "/api/admin/tenants/{id}", m.handleDeleteTenant, super)
}

// --- auth -------------------------------------------------------------------

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type loginResponse struct {
	Token     string        `json:"token"`
	ExpiresAt time.Time     `json:"expires_at"`
	ExpiresIn int64         `json:"expires_in_seconds"`
	Principal principalView `json:"principal"`
}

type principalView struct {
	Kind     string `json:"kind"`
	ID       string `json:"id"`
	Username string `json:"username"`
	TenantID string `json:"tenant_id"`
	Role     string `json:"role"`
}

func (m *Module) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if !httpx.DecodeJSON(w, r, &req) {
		return
	}
	if strings.TrimSpace(req.Username) == "" || req.Password == "" {
		httpx.ValidationError(w, r, "username and password are required", map[string]string{
			"username": "required",
			"password": "required",
		})
		return
	}

	session, err := m.authn.Login(r.Context(), req.Username, req.Password)
	if err != nil {
		if errors.Is(err, auth.ErrInvalidCredentials) {
			metrics.AuthFailures.WithLabelValues(metrics.PlaneAdmin, "login").Inc()
			httpx.Error(w, r, http.StatusUnauthorized, httpx.CodeUnauthorized, "invalid username or password")
			return
		}
		httpx.Internal(w, r, err)
		return
	}

	httpx.JSON(w, r, http.StatusOK, loginResponse{
		Token:     session.Token,
		ExpiresAt: session.ExpiresAt,
		ExpiresIn: int64(time.Until(session.ExpiresAt).Seconds()),
		Principal: toPrincipalView(session.Principal),
	})
}

func (m *Module) handleLogout(w http.ResponseWriter, r *http.Request) {
	if err := m.authn.Logout(r.Context(), r.Header.Get("Authorization")); err != nil {
		httpx.Internal(w, r, err)
		return
	}
	httpx.NoContent(w)
}

func (m *Module) handleWhoami(w http.ResponseWriter, r *http.Request) {
	httpx.JSON(w, r, http.StatusOK, toPrincipalView(auth.PrincipalFrom(r.Context())))
}

func toPrincipalView(p *auth.Principal) principalView {
	if p == nil {
		return principalView{}
	}
	return principalView{
		Kind:     string(p.Kind),
		ID:       p.ID,
		Username: p.Name,
		TenantID: p.TenantID,
		Role:     p.Role,
	}
}

// --- tenants ----------------------------------------------------------------

type createTenantRequest struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

func (m *Module) handleListTenants(w http.ResponseWriter, r *http.Request) {
	tenants, err := m.tenants.ListTenants(r.Context())
	if err != nil {
		httpx.Internal(w, r, err)
		return
	}
	metrics.TenantsTotal.Set(float64(len(tenants)))
	httpx.JSON(w, r, http.StatusOK, map[string]any{"tenants": tenants, "count": len(tenants)})
}

func (m *Module) handleGetTenant(w http.ResponseWriter, r *http.Request) {
	t, err := m.tenants.GetTenant(r.Context(), r.PathValue("id"))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			httpx.Error(w, r, http.StatusNotFound, httpx.CodeNotFound, "no such tenant")
			return
		}
		httpx.Internal(w, r, err)
		return
	}
	httpx.JSON(w, r, http.StatusOK, t)
}

func (m *Module) handleCreateTenant(w http.ResponseWriter, r *http.Request) {
	var req createTenantRequest
	if !httpx.DecodeJSON(w, r, &req) {
		return
	}
	id := strings.ToLower(strings.TrimSpace(req.ID))
	if err := validateTenantID(id); err != nil {
		httpx.ValidationError(w, r, "invalid tenant id", map[string]string{"id": err.Error()})
		return
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		name = id
	}

	t, err := m.tenants.CreateTenant(r.Context(), id, name)
	if err != nil {
		if errors.Is(err, store.ErrConflict) {
			httpx.Errorf(w, r, http.StatusConflict, httpx.CodeConflict, "tenant %q already exists", id)
			return
		}
		httpx.Internal(w, r, err)
		return
	}
	w.Header().Set("Location", "/api/admin/tenants/"+t.ID)
	httpx.JSON(w, r, http.StatusCreated, t)
}

// handleDeleteTenant removes a tenant and cascades to its policies,
// appliances and admins.
func (m *Module) handleDeleteTenant(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == m.authn.Options().DefaultTenant {
		httpx.Errorf(w, r, http.StatusConflict, httpx.CodeConflict,
			"the default tenant %q cannot be deleted", id)
		return
	}
	if err := m.tenants.DeleteTenant(r.Context(), id); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			httpx.Error(w, r, http.StatusNotFound, httpx.CodeNotFound, "no such tenant")
			return
		}
		httpx.Internal(w, r, err)
		return
	}
	httpx.NoContent(w)
}

// validateTenantID keeps tenant IDs safe to embed in metric labels, log lines
// and URLs.
func validateTenantID(id string) error {
	switch {
	case id == "":
		return errors.New("must not be empty")
	case len(id) > 63:
		return errors.New("must be at most 63 characters")
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		ok := (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-'
		if !ok {
			return errors.New("must contain only lowercase letters, digits and '-'")
		}
	}
	if id[0] == '-' || id[len(id)-1] == '-' {
		return errors.New("must not start or end with '-'")
	}
	return nil
}
