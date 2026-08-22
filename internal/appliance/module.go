// Package appliance implements registration and token lifecycle for dnsd
// instances.
//
// A token is shown exactly once, at mint time. Only its SHA-256 is stored, so a
// lost token is replaced by rotation, never recovered.
package appliance

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/dashdns/api/internal/auth"
	"github.com/dashdns/api/internal/httpx"
	"github.com/dashdns/api/internal/idgen"
	"github.com/dashdns/api/internal/metrics"
	"github.com/dashdns/api/internal/store"
)

// Module serves /api/admin/appliances/*.
type Module struct {
	appliances store.ApplianceRepository
	tenants    store.TenantRepository
	authn      *auth.Authenticator
}

// Deps are the Module's collaborators.
type Deps struct {
	Appliances store.ApplianceRepository
	Tenants    store.TenantRepository
	Auth       *auth.Authenticator
}

// New returns an appliance Module.
func New(d Deps) *Module {
	return &Module{appliances: d.Appliances, tenants: d.Tenants, authn: d.Auth}
}

// Name implements httpx.Module.
func (m *Module) Name() string { return "appliances" }

// RegisterRoutes implements httpx.Module.
func (m *Module) RegisterRoutes(r *httpx.Router) {
	admin := m.authn.RequireAdmin
	r.Handle(http.MethodGet, "/api/admin/appliances", m.handleList, admin)
	r.Handle(http.MethodPost, "/api/admin/appliances", m.handleCreate, admin)
	r.Handle(http.MethodGet, "/api/admin/appliances/{id}", m.handleGet, admin)
	r.Handle(http.MethodPost, "/api/admin/appliances/{id}/rotate", m.handleRotate, admin)
	r.Handle(http.MethodPost, "/api/admin/appliances/{id}/revoke", m.handleRevoke, admin)
	r.Handle(http.MethodDelete, "/api/admin/appliances/{id}", m.handleDelete, admin)
}

// View is the admin representation of an appliance. It never carries a token.
type View struct {
	ID          string     `json:"id"`
	TenantID    string     `json:"tenant_id"`
	Name        string     `json:"name"`
	Description string     `json:"description,omitempty"`
	TokenID     string     `json:"token_id"`
	Revoked     bool       `json:"revoked"`
	CreatedAt   time.Time  `json:"created_at"`
	LastSeenAt  *time.Time `json:"last_seen_at,omitempty"`
	RevokedAt   *time.Time `json:"revoked_at,omitempty"`
}

// credentialResponse is returned by create and rotate. Token is present in
// exactly these two responses and nowhere else in the API.
type credentialResponse struct {
	Appliance View   `json:"appliance"`
	Token     string `json:"token"`
	// Hint tells the operator what to do with the value they are seeing once.
	Hint string `json:"hint"`
}

type createRequest struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

const tokenHint = "Store this token now; it cannot be retrieved again. " +
	"Pass it to dnsd with -ip-blocklist-token (or DNSD_IP_BLOCKLIST_TOKEN)."

func (m *Module) handleList(w http.ResponseWriter, r *http.Request) {
	tenant, ok := m.authn.TenantOrReject(w, r)
	if !ok {
		return
	}
	items, err := m.appliances.ListAppliances(r.Context(), tenant)
	if err != nil {
		httpx.Internal(w, r, err)
		return
	}
	views := make([]View, 0, len(items))
	for _, a := range items {
		views = append(views, toView(a))
	}
	httpx.JSON(w, r, http.StatusOK, map[string]any{"appliances": views, "count": len(views)})
}

func (m *Module) handleGet(w http.ResponseWriter, r *http.Request) {
	tenant, ok := m.authn.TenantOrReject(w, r)
	if !ok {
		return
	}
	a, err := m.appliances.GetAppliance(r.Context(), tenant, r.PathValue("id"))
	if err != nil {
		writeStoreError(w, r, err)
		return
	}
	httpx.JSON(w, r, http.StatusOK, toView(*a))
}

func (m *Module) handleCreate(w http.ResponseWriter, r *http.Request) {
	tenant, ok := m.authn.TenantOrReject(w, r)
	if !ok {
		return
	}
	if !m.authn.EnsureTenantExists(w, r, m.tenants, tenant) {
		return
	}

	var req createRequest
	if !httpx.DecodeJSON(w, r, &req) {
		return
	}
	name := strings.TrimSpace(req.Name)
	if name == "" || len(name) > 128 {
		httpx.ValidationError(w, r, "invalid appliance name",
			map[string]string{"name": "must be 1-128 characters"})
		return
	}

	token, err := auth.Mint(auth.AppliancePrefix)
	if err != nil {
		httpx.Internal(w, r, err)
		return
	}
	record := &store.Appliance{
		ID:          idgen.New(idgen.PrefixAppliance),
		TenantID:    tenant,
		Name:        name,
		Description: strings.TrimSpace(req.Description),
		TokenID:     token.ID,
		CreatedAt:   time.Now().UTC(),
	}
	if err := m.appliances.CreateAppliance(r.Context(), record, token.Hash); err != nil {
		if errors.Is(err, store.ErrConflict) {
			httpx.Errorf(w, r, http.StatusConflict, httpx.CodeConflict,
				"an appliance named %q already exists in this tenant", name)
			return
		}
		httpx.Internal(w, r, err)
		return
	}

	m.refreshCounts(r, tenant)
	w.Header().Set("Location", "/api/admin/appliances/"+record.ID)
	httpx.JSON(w, r, http.StatusCreated, credentialResponse{
		Appliance: toView(*record),
		Token:     token.Plaintext,
		Hint:      tokenHint,
	})
}

// handleRotate mints a replacement token and clears any revocation, so it is
// also how a revoked appliance is brought back into service.
func (m *Module) handleRotate(w http.ResponseWriter, r *http.Request) {
	tenant, ok := m.authn.TenantOrReject(w, r)
	if !ok {
		return
	}

	token, err := auth.Mint(auth.AppliancePrefix)
	if err != nil {
		httpx.Internal(w, r, err)
		return
	}
	updated, err := m.appliances.RotateApplianceToken(r.Context(), tenant, r.PathValue("id"), token.ID, token.Hash)
	if err != nil {
		writeStoreError(w, r, err)
		return
	}

	m.refreshCounts(r, tenant)
	httpx.JSON(w, r, http.StatusOK, credentialResponse{
		Appliance: toView(*updated),
		Token:     token.Plaintext,
		Hint:      tokenHint,
	})
}

// handleRevoke withdraws the token but keeps the record, so the audit trail and
// last_seen_at survive. It is idempotent.
func (m *Module) handleRevoke(w http.ResponseWriter, r *http.Request) {
	tenant, ok := m.authn.TenantOrReject(w, r)
	if !ok {
		return
	}
	id := r.PathValue("id")
	if err := m.appliances.RevokeAppliance(r.Context(), tenant, id); err != nil {
		writeStoreError(w, r, err)
		return
	}
	a, err := m.appliances.GetAppliance(r.Context(), tenant, id)
	if err != nil {
		writeStoreError(w, r, err)
		return
	}
	m.refreshCounts(r, tenant)
	httpx.JSON(w, r, http.StatusOK, toView(*a))
}

func (m *Module) handleDelete(w http.ResponseWriter, r *http.Request) {
	tenant, ok := m.authn.TenantOrReject(w, r)
	if !ok {
		return
	}
	if err := m.appliances.DeleteAppliance(r.Context(), tenant, r.PathValue("id")); err != nil {
		writeStoreError(w, r, err)
		return
	}
	m.refreshCounts(r, tenant)
	httpx.NoContent(w)
}

// refreshCounts keeps the appliance gauges current. Failures are not worth
// failing an otherwise successful mutation over.
func (m *Module) refreshCounts(r *http.Request, tenant string) {
	active, revoked, err := m.appliances.CountAppliances(r.Context(), tenant)
	if err != nil {
		return
	}
	metrics.Appliances.WithLabelValues(tenant, "active").Set(float64(active))
	metrics.Appliances.WithLabelValues(tenant, "revoked").Set(float64(revoked))
}

func writeStoreError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		httpx.Error(w, r, http.StatusNotFound, httpx.CodeNotFound, "no such appliance")
	case errors.Is(err, store.ErrConflict):
		httpx.Error(w, r, http.StatusConflict, httpx.CodeConflict, "appliance conflicts with an existing record")
	default:
		httpx.Internal(w, r, err)
	}
}

func toView(a store.Appliance) View {
	return View{
		ID:          a.ID,
		TenantID:    a.TenantID,
		Name:        a.Name,
		Description: a.Description,
		TokenID:     a.TokenID,
		Revoked:     a.Revoked(),
		CreatedAt:   a.CreatedAt,
		LastSeenAt:  a.LastSeenAt,
		RevokedAt:   a.RevokedAt,
	}
}
