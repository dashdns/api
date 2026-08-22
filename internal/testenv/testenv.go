// Package testenv builds a fully wired policy-controller against a throwaway
// SQLite database so handler tests exercise the real router, the real
// middleware chain and the real store rather than mocks.
//
// It lives in a non-test file so every _test package can share one harness;
// nothing in the production binary imports it.
package testenv

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dashdns/api/internal/auth"
	"github.com/dashdns/api/internal/config"
	"github.com/dashdns/api/internal/server"
	"github.com/dashdns/api/internal/store"
	"github.com/dashdns/api/internal/store/sqlstore"
)

// Credentials used by the harness. The password clears the 12-character
// minimum that config.Validate enforces.
const (
	AdminUsername = "test-admin"
	AdminPassword = "test-admin-password"
)

// Env is a running (but unlistened) policy-controller.
type Env struct {
	T       *testing.T
	Config  config.Config
	Store   *sqlstore.Store
	Server  *server.Server
	Handler http.Handler

	// AdminToken is a superadmin session minted through the real login
	// endpoint.
	AdminToken string
	// ApplianceToken is a read-only appliance token for DefaultTenant, minted
	// through the real registration endpoint.
	ApplianceToken string
}

// Option customises the environment before it starts.
type Option func(*config.Config)

// MultiTenant enables tenant isolation.
func MultiTenant() Option {
	return func(c *config.Config) { c.MultiTenant = true }
}

// ApplianceAuth toggles whether GET /api/policies demands a token.
func ApplianceAuth(required bool) Option {
	return func(c *config.Config) { c.RequireApplianceAuth = required }
}

// New builds an Env and registers cleanup.
func New(t *testing.T, opts ...Option) *Env {
	t.Helper()

	// Handler logs are noise in test output; keep errors only.
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))

	cfg := config.Default()
	cfg.DBDSN = "file:" + filepath.Join(t.TempDir(), "test.db") +
		"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)"
	cfg.BootstrapAdminUser = AdminUsername
	cfg.BootstrapAdminPassword = AdminPassword
	for _, opt := range opts {
		opt(&cfg)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("test config invalid: %v", err)
	}

	ctx := context.Background()
	st, err := sqlstore.Open(ctx, cfg.DBDriver, cfg.DBDSN)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	srv := server.New(cfg, st, "test")
	if err := srv.Bootstrap(ctx); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}

	env := &Env{
		T:       t,
		Config:  cfg,
		Store:   st,
		Server:  srv,
		Handler: srv.Router(),
	}
	env.AdminToken = env.login(AdminUsername, AdminPassword)
	env.ApplianceToken = env.MintApplianceToken("test-appliance")
	return env
}

// Tenant returns the environment's default tenant ID.
func (e *Env) Tenant() string { return e.Config.DefaultTenant }

// --- request helpers --------------------------------------------------------

// Request is one HTTP call against the harness.
type Request struct {
	Method  string
	Path    string
	Body    any
	Token   string
	Headers map[string]string
}

// Do executes req and returns the recorder.
func (e *Env) Do(req Request) *httptest.ResponseRecorder {
	e.T.Helper()

	var body io.Reader
	if req.Body != nil {
		switch v := req.Body.(type) {
		case string:
			body = strings.NewReader(v)
		default:
			encoded, err := json.Marshal(v)
			if err != nil {
				e.T.Fatalf("marshal request body: %v", err)
			}
			body = strings.NewReader(string(encoded))
		}
	}

	r := httptest.NewRequest(req.Method, req.Path, body)
	if req.Body != nil {
		r.Header.Set("Content-Type", "application/json")
	}
	if req.Token != "" {
		r.Header.Set("Authorization", "Bearer "+req.Token)
	}
	for k, v := range req.Headers {
		r.Header.Set(k, v)
	}

	w := httptest.NewRecorder()
	e.Handler.ServeHTTP(w, r)
	return w
}

// Admin issues an authenticated management-plane call.
func (e *Env) Admin(method, path string, body any) *httptest.ResponseRecorder {
	e.T.Helper()
	return e.Do(Request{Method: method, Path: path, Body: body, Token: e.AdminToken})
}

// Appliance issues an authenticated appliance-plane call.
func (e *Env) Appliance(method, path string, headers map[string]string) *httptest.ResponseRecorder {
	e.T.Helper()
	return e.Do(Request{Method: method, Path: path, Token: e.ApplianceToken, Headers: headers})
}

// --- fixtures ---------------------------------------------------------------

// SeedPolicy creates a policy through the admin API and fails the test if the
// call does not return 201.
func (e *Env) SeedPolicy(ip string, domains ...string) {
	e.T.Helper()
	w := e.Admin(http.MethodPost, "/api/admin/policies", map[string]any{
		"ip":      ip,
		"domains": domains,
	})
	if w.Code != http.StatusCreated {
		e.T.Fatalf("seed policy %s: status %d, body %s", ip, w.Code, w.Body.String())
	}
}

// MintApplianceToken registers an appliance and returns its plaintext token.
func (e *Env) MintApplianceToken(name string) string {
	e.T.Helper()
	w := e.Admin(http.MethodPost, "/api/admin/appliances", map[string]any{"name": name})
	if w.Code != http.StatusCreated {
		e.T.Fatalf("register appliance %s: status %d, body %s", name, w.Code, w.Body.String())
	}
	var resp struct {
		Appliance struct {
			ID string `json:"id"`
		} `json:"appliance"`
		Token string `json:"token"`
	}
	e.DecodeInto(w, &resp)
	if resp.Token == "" {
		e.T.Fatalf("register appliance %s: no token in response", name)
	}
	return resp.Token
}

// CreateTenantAdmin provisions a non-superadmin operator in tenantID and
// returns a session token for it.
func (e *Env) CreateTenantAdmin(tenantID, username string) string {
	e.T.Helper()
	if _, err := e.Store.EnsureTenant(context.Background(), tenantID, tenantID); err != nil {
		e.T.Fatalf("ensure tenant %s: %v", tenantID, err)
	}
	_, err := auth.CreateAdminUser(context.Background(), e.Store, tenantID, username, AdminPassword, store.RoleAdmin)
	if err != nil {
		e.T.Fatalf("create admin %s: %v", username, err)
	}
	return e.login(username, AdminPassword)
}

func (e *Env) login(username, password string) string {
	e.T.Helper()
	w := e.Do(Request{
		Method: http.MethodPost,
		Path:   "/api/admin/auth/login",
		Body:   map[string]string{"username": username, "password": password},
	})
	if w.Code != http.StatusOK {
		e.T.Fatalf("login as %s: status %d, body %s", username, w.Code, w.Body.String())
	}
	var resp struct {
		Token string `json:"token"`
	}
	e.DecodeInto(w, &resp)
	if resp.Token == "" {
		e.T.Fatalf("login as %s: empty token", username)
	}
	return resp.Token
}

// --- assertions -------------------------------------------------------------

// DecodeInto unmarshals a recorder body, failing the test on error.
func (e *Env) DecodeInto(w *httptest.ResponseRecorder, dst any) {
	e.T.Helper()
	if err := json.Unmarshal(w.Body.Bytes(), dst); err != nil {
		e.T.Fatalf("decode response: %v (body: %s)", err, w.Body.String())
	}
}

// RequireStatus fails the test unless the recorder carries want.
func (e *Env) RequireStatus(w *httptest.ResponseRecorder, want int) {
	e.T.Helper()
	if w.Code != want {
		e.T.Fatalf("status = %d, want %d (body: %s)", w.Code, want, strings.TrimSpace(w.Body.String()))
	}
}

// ErrorCode returns the machine-readable code from an error response.
func (e *Env) ErrorCode(w *httptest.ResponseRecorder) string {
	e.T.Helper()
	var body struct {
		Error string `json:"error"`
	}
	e.DecodeInto(w, &body)
	return body.Error
}
