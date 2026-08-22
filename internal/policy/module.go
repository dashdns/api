package policy

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/dashdns/api/internal/auth"
	"github.com/dashdns/api/internal/httpx"
	"github.com/dashdns/api/internal/metrics"
	"github.com/dashdns/api/internal/store"
)

// Module serves both the appliance-facing blocklist and the admin CRUD surface
// for policies. They are separate route trees with separate middleware so an
// appliance token can never reach a mutating endpoint.
type Module struct {
	policies store.PolicyRepository
	tenants  store.TenantRepository
	service  *Service
	authn    *auth.Authenticator
}

// Deps are the Module's collaborators.
type Deps struct {
	Policies store.PolicyRepository
	Tenants  store.TenantRepository
	Service  *Service
	Auth     *auth.Authenticator
}

// New returns a policy Module.
func New(d Deps) *Module {
	return &Module{policies: d.Policies, tenants: d.Tenants, service: d.Service, authn: d.Auth}
}

// Name implements httpx.Module.
func (m *Module) Name() string { return "policies" }

// RegisterRoutes implements httpx.Module.
func (m *Module) RegisterRoutes(r *httpx.Router) {
	// Appliance plane: read-only, cacheable, the contract dnsd consumes.
	r.Handle(http.MethodGet, "/api/policies", m.handleGetBlocklist, m.authn.RequireAppliance)

	// Management plane: separate prefix, separate credential kind.
	admin := m.authn.RequireAdmin
	r.Handle(http.MethodGet, "/api/admin/policies", m.handleList, admin)
	r.Handle(http.MethodPost, "/api/admin/policies", m.handleCreate, admin)
	r.Handle(http.MethodGet, "/api/admin/policies/{ip}", m.handleGet, admin)
	r.Handle(http.MethodPut, "/api/admin/policies/{ip}", m.handleReplace, admin)
	r.Handle(http.MethodPatch, "/api/admin/policies/{ip}", m.handlePatch, admin)
	r.Handle(http.MethodDelete, "/api/admin/policies/{ip}", m.handleDelete, admin)
}

// --- appliance plane --------------------------------------------------------

// handleGetBlocklist serves GET /api/policies.
//
// The body is exactly dnsdcontract.Response, byte-for-byte what dnsd's
// fetchAndUpdateIPBlocklist expects. ETag and Last-Modified are attached so a
// polling appliance that revalidates gets a 304 with no body.
func (m *Module) handleGetBlocklist(w http.ResponseWriter, r *http.Request) {
	tenant, ok := m.authn.TenantOrReject(w, r)
	if !ok {
		return
	}

	snapshot, err := m.service.Snapshot(r.Context(), tenant)
	if err != nil {
		httpx.Internal(w, r, err)
		return
	}

	validators := httpx.CacheValidators{
		ETag:         snapshot.ETag,
		LastModified: snapshot.LastModified,
	}
	if httpx.NotModified(w, r, validators) {
		metrics.PolicyFetches.WithLabelValues(tenant, metrics.OutcomeNotModified).Inc()
		return
	}

	httpx.WriteValidators(w, validators)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Policy-Revision", strconv.FormatInt(snapshot.Revision, 10))
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = w.Write(snapshot.Body)
	}
	metrics.PolicyFetches.WithLabelValues(tenant, metrics.OutcomeModified).Inc()
}

// --- management plane -------------------------------------------------------

// View is the admin representation of a policy. It is intentionally a
// different shape from the dnsd contract: the appliance payload must stay
// frozen, while this one is free to grow.
type View struct {
	ID        string    `json:"id"`
	TenantID  string    `json:"tenant_id"`
	IP        string    `json:"ip"`
	Domains   []string  `json:"domains"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type listResponse struct {
	Policies []View `json:"policies"`
	Count    int    `json:"count"`
	Revision int64  `json:"revision"`
}

type upsertRequest struct {
	IP      string   `json:"ip"`
	Domains []string `json:"domains"`
}

type patchRequest struct {
	Add    []string `json:"add"`
	Remove []string `json:"remove"`
}

func (m *Module) handleList(w http.ResponseWriter, r *http.Request) {
	tenant, ok := m.authn.TenantOrReject(w, r)
	if !ok {
		return
	}

	policies, err := m.policies.ListPolicies(r.Context(), tenant)
	if err != nil {
		httpx.Internal(w, r, err)
		return
	}
	rev, err := m.policies.Revision(r.Context(), tenant)
	if err != nil {
		httpx.Internal(w, r, err)
		return
	}

	views := make([]View, 0, len(policies))
	for _, p := range policies {
		views = append(views, toView(p))
	}
	httpx.JSON(w, r, http.StatusOK, listResponse{Policies: views, Count: len(views), Revision: rev.Value})
}

func (m *Module) handleGet(w http.ResponseWriter, r *http.Request) {
	tenant, ok := m.authn.TenantOrReject(w, r)
	if !ok {
		return
	}
	ip, ok := pathIP(w, r)
	if !ok {
		return
	}

	p, err := m.policies.GetPolicy(r.Context(), tenant, ip)
	if err != nil {
		m.writeStoreError(w, r, err, ip)
		return
	}
	httpx.JSON(w, r, http.StatusOK, toView(*p))
}

func (m *Module) handleCreate(w http.ResponseWriter, r *http.Request) {
	tenant, ok := m.authn.TenantOrReject(w, r)
	if !ok {
		return
	}
	if !m.authn.EnsureTenantExists(w, r, m.tenants, tenant) {
		return
	}

	var req upsertRequest
	if !httpx.DecodeJSON(w, r, &req) {
		return
	}

	ip, domains, ok := normalizeUpsert(w, r, req.IP, req.Domains)
	if !ok {
		return
	}
	if len(domains) == 0 {
		httpx.ValidationError(w, r, "a new policy must list at least one domain",
			map[string]string{"domains": "must not be empty"})
		return
	}

	p, err := m.policies.CreatePolicy(r.Context(), tenant, ip, domains)
	if err != nil {
		if errors.Is(err, store.ErrConflict) {
			httpx.Errorf(w, r, http.StatusConflict, httpx.CodeConflict,
				"a policy for %s already exists; use PUT or PATCH to modify it", ip)
			return
		}
		httpx.Internal(w, r, err)
		return
	}

	m.service.Invalidate(tenant)
	w.Header().Set("Location", "/api/admin/policies/"+ip)
	httpx.JSON(w, r, http.StatusCreated, toView(*p))
}

func (m *Module) handleReplace(w http.ResponseWriter, r *http.Request) {
	tenant, ok := m.authn.TenantOrReject(w, r)
	if !ok {
		return
	}
	if !m.authn.EnsureTenantExists(w, r, m.tenants, tenant) {
		return
	}
	ip, ok := pathIP(w, r)
	if !ok {
		return
	}

	var req upsertRequest
	if !httpx.DecodeJSON(w, r, &req) {
		return
	}
	// The IP in the body is optional, but if present it must agree with the
	// path so a copy-pasted payload cannot silently rewrite a different host.
	if req.IP != "" {
		bodyIP, err := NormalizeClientIP(req.IP)
		if err != nil {
			httpx.ValidationError(w, r, "invalid ip", map[string]string{"ip": err.Error()})
			return
		}
		if bodyIP != ip {
			httpx.Errorf(w, r, http.StatusBadRequest, httpx.CodeBadRequest,
				"body ip %q does not match path ip %q", bodyIP, ip)
			return
		}
	}

	domains, err := NormalizeDomains(req.Domains)
	if err != nil {
		httpx.ValidationError(w, r, "invalid domains", map[string]string{"domains": err.Error()})
		return
	}
	if len(domains) > MaxDomainsPerPolicy {
		httpx.ValidationError(w, r, "too many domains",
			map[string]string{"domains": "a policy may hold at most 4096 domains"})
		return
	}

	p, err := m.policies.ReplacePolicy(r.Context(), tenant, ip, domains)
	if err != nil {
		httpx.Internal(w, r, err)
		return
	}
	m.service.Invalidate(tenant)
	httpx.JSON(w, r, http.StatusOK, toView(*p))
}

func (m *Module) handlePatch(w http.ResponseWriter, r *http.Request) {
	tenant, ok := m.authn.TenantOrReject(w, r)
	if !ok {
		return
	}
	ip, ok := pathIP(w, r)
	if !ok {
		return
	}

	var req patchRequest
	if !httpx.DecodeJSON(w, r, &req) {
		return
	}
	if len(req.Add) == 0 && len(req.Remove) == 0 {
		httpx.ValidationError(w, r, "nothing to do",
			map[string]string{"add": "at least one of add or remove must be non-empty"})
		return
	}

	add, err := NormalizeDomains(req.Add)
	if err != nil {
		httpx.ValidationError(w, r, "invalid domains in add", map[string]string{"add": err.Error()})
		return
	}
	remove, err := NormalizeDomains(req.Remove)
	if err != nil {
		httpx.ValidationError(w, r, "invalid domains in remove", map[string]string{"remove": err.Error()})
		return
	}

	p, err := m.policies.MutatePolicyDomains(r.Context(), tenant, ip, add, remove)
	if err != nil {
		m.writeStoreError(w, r, err, ip)
		return
	}
	m.service.Invalidate(tenant)
	httpx.JSON(w, r, http.StatusOK, toView(*p))
}

func (m *Module) handleDelete(w http.ResponseWriter, r *http.Request) {
	tenant, ok := m.authn.TenantOrReject(w, r)
	if !ok {
		return
	}
	ip, ok := pathIP(w, r)
	if !ok {
		return
	}

	if err := m.policies.DeletePolicy(r.Context(), tenant, ip); err != nil {
		m.writeStoreError(w, r, err, ip)
		return
	}
	m.service.Invalidate(tenant)
	httpx.NoContent(w)
}

// --- helpers ----------------------------------------------------------------

func (m *Module) writeStoreError(w http.ResponseWriter, r *http.Request, err error, ip string) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		httpx.Errorf(w, r, http.StatusNotFound, httpx.CodeNotFound, "no policy for %s", ip)
	case errors.Is(err, store.ErrConflict):
		httpx.Errorf(w, r, http.StatusConflict, httpx.CodeConflict, "policy for %s conflicts with an existing record", ip)
	default:
		httpx.Internal(w, r, err)
	}
}

// pathIP extracts and validates the {ip} path wildcard.
func pathIP(w http.ResponseWriter, r *http.Request) (string, bool) {
	ip, err := NormalizeClientIP(r.PathValue("ip"))
	if err != nil {
		httpx.ValidationError(w, r, "invalid ip in path", map[string]string{"ip": err.Error()})
		return "", false
	}
	return ip, true
}

func normalizeUpsert(w http.ResponseWriter, r *http.Request, rawIP string, rawDomains []string) (string, []string, bool) {
	ip, err := NormalizeClientIP(rawIP)
	if err != nil {
		httpx.ValidationError(w, r, "invalid ip", map[string]string{"ip": err.Error()})
		return "", nil, false
	}
	domains, err := NormalizeDomains(rawDomains)
	if err != nil {
		httpx.ValidationError(w, r, "invalid domains", map[string]string{"domains": err.Error()})
		return "", nil, false
	}
	if len(domains) > MaxDomainsPerPolicy {
		httpx.ValidationError(w, r, "too many domains",
			map[string]string{"domains": "a policy may hold at most 4096 domains"})
		return "", nil, false
	}
	return ip, domains, true
}

func toView(p store.Policy) View {
	domains := p.Domains
	if domains == nil {
		domains = []string{}
	}
	return View{
		ID:        p.ID,
		TenantID:  p.TenantID,
		IP:        p.ClientIP,
		Domains:   domains,
		CreatedAt: p.CreatedAt,
		UpdatedAt: p.UpdatedAt,
	}
}

