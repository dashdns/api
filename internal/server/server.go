// Package server wires the modules, middleware and listeners into a runnable
// service.
//
// Adding an endpoint family means writing a package that satisfies
// httpx.Module and adding one line to buildRouter. Nothing else in this file
// needs to change -- that is the seam a future /api/vpn-peers module plugs
// into.
package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/dashdns/api/internal/appliance"
	"github.com/dashdns/api/internal/auth"
	"github.com/dashdns/api/internal/config"
	"github.com/dashdns/api/internal/httpx"
	"github.com/dashdns/api/internal/identity"
	"github.com/dashdns/api/internal/metrics"
	"github.com/dashdns/api/internal/policy"
	"github.com/dashdns/api/internal/store"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Server owns the API and metrics listeners and the background sweepers.
type Server struct {
	cfg     config.Config
	store   store.Store
	authn   *auth.Authenticator
	router  *httpx.Router
	policy  *policy.Service
	api     *http.Server
	metrics *http.Server
	version string
}

// New builds a Server. It does not listen; call Run.
func New(cfg config.Config, st store.Store, version string) *Server {
	authn := auth.NewAuthenticator(st, st, auth.Options{
		RequireApplianceAuth: cfg.RequireApplianceAuth,
		MultiTenant:          cfg.MultiTenant,
		DefaultTenant:        cfg.DefaultTenant,
		SessionTTL:           cfg.AdminSessionTTL,
	})
	policySvc := policy.NewService(st)

	s := &Server{
		cfg:     cfg,
		store:   st,
		authn:   authn,
		policy:  policySvc,
		version: version,
	}
	s.router = s.buildRouter()

	s.api = &http.Server{
		Addr:              cfg.Listen,
		Handler:           s.router,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       cfg.ReadTimeout,
		WriteTimeout:      cfg.WriteTimeout,
		IdleTimeout:       cfg.IdleTimeout,
	}

	metricsMux := http.NewServeMux()
	metricsMux.Handle("/metrics", promhttp.Handler())
	s.metrics = &http.Server{
		Addr:              cfg.MetricsListen,
		Handler:           metricsMux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       cfg.ReadTimeout,
		WriteTimeout:      cfg.WriteTimeout,
		IdleTimeout:       cfg.IdleTimeout,
	}

	return s
}

// Router exposes the handler for tests.
func (s *Server) Router() http.Handler { return s.router }

// PolicyService exposes the snapshot cache for tests.
func (s *Server) PolicyService() *policy.Service { return s.policy }

func (s *Server) buildRouter() *httpx.Router {
	r := httpx.NewRouter(httpx.DefaultMiddleware()...)

	ops := &opsModule{
		store:   s.store,
		version: s.version,
		mode:    s.Mode(),
		started: time.Now(),
	}

	r.Mount(
		policy.New(policy.Deps{
			Policies: s.store,
			Tenants:  s.store,
			Service:  s.policy,
			Auth:     s.authn,
		}),
		appliance.New(appliance.Deps{
			Appliances: s.store,
			Tenants:    s.store,
			Auth:       s.authn,
		}),
		identity.New(identity.Deps{
			Admins:      s.store,
			Tenants:     s.store,
			Auth:        s.authn,
			MultiTenant: s.cfg.MultiTenant,
		}),
		ops,
	)
	// The index handler needs the finished route table, so it is filled in
	// after every module has registered.
	ops.router = r

	return r
}

// Mode reports the isolation mode for logs, /healthz and build_info.
func (s *Server) Mode() string {
	if s.cfg.MultiTenant {
		return "multi-tenant"
	}
	return "single-tenant"
}

// Bootstrap prepares the database for serving: it guarantees the default
// tenant exists and creates the bootstrap admin on a fresh install.
func (s *Server) Bootstrap(ctx context.Context) error {
	if _, err := s.store.EnsureTenant(ctx, s.cfg.DefaultTenant, s.cfg.DefaultTenant); err != nil {
		return fmt.Errorf("server: ensure default tenant: %w", err)
	}

	count, err := s.store.CountAdminUsers(ctx)
	if err != nil {
		return fmt.Errorf("server: count admin users: %w", err)
	}
	switch {
	case count > 0:
		if s.cfg.BootstrapAdminUser != "" {
			slog.InfoContext(ctx, "bootstrap admin skipped; an admin already exists",
				"existing_admins", count)
		}
	case s.cfg.BootstrapAdminUser == "":
		// Refusing to start would be worse: the operator may be restoring a
		// database or provisioning admins out of band. Warn loudly instead.
		slog.WarnContext(ctx, "no admin users exist and -bootstrap-admin-user is unset; "+
			"the /api/admin endpoints are unreachable until an admin is created")
	default:
		// The first admin is a superadmin so that a fresh multi-tenant install
		// has someone able to create tenants.
		user, err := auth.CreateAdminUser(ctx, s.store, s.cfg.DefaultTenant,
			s.cfg.BootstrapAdminUser, s.cfg.BootstrapAdminPassword, store.RoleSuperAdmin)
		if err != nil {
			return fmt.Errorf("server: create bootstrap admin: %w", err)
		}
		slog.InfoContext(ctx, "bootstrap admin created",
			"username", user.Username, "role", user.Role, "tenant", user.TenantID)
	}

	tenants, err := s.store.ListTenants(ctx)
	if err == nil {
		metrics.TenantsTotal.Set(float64(len(tenants)))
		for _, t := range tenants {
			active, revoked, err := s.store.CountAppliances(ctx, t.ID)
			if err != nil {
				continue
			}
			metrics.Appliances.WithLabelValues(t.ID, "active").Set(float64(active))
			metrics.Appliances.WithLabelValues(t.ID, "revoked").Set(float64(revoked))
		}
	}

	metrics.BuildInfo.WithLabelValues(s.version, s.Mode(), s.cfg.DBDriver).Set(1)
	return nil
}

// Run starts both listeners and blocks until ctx is cancelled or a listener
// fails, then shuts down gracefully.
func (s *Server) Run(ctx context.Context) error {
	errCh := make(chan error, 2)

	go func() {
		slog.Info("policy API listening",
			"addr", s.cfg.Listen,
			"mode", s.Mode(),
			"appliance_auth", s.cfg.RequireApplianceAuth,
		)
		if err := s.api.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- fmt.Errorf("server: api listener: %w", err)
		}
	}()

	go func() {
		slog.Info("prometheus metrics listening", "addr", s.cfg.MetricsListen, "path", "/metrics")
		if err := s.metrics.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- fmt.Errorf("server: metrics listener: %w", err)
		}
	}()

	go s.sweepSessions(ctx)

	var runErr error
	select {
	case <-ctx.Done():
		slog.Info("shutdown signal received")
	case runErr = <-errCh:
		slog.Error("listener failed", "error", runErr)
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), s.cfg.ShutdownTimeout)
	defer cancel()

	if err := s.api.Shutdown(shutdownCtx); err != nil {
		slog.Error("api shutdown failed", "error", err)
	}
	if err := s.metrics.Shutdown(shutdownCtx); err != nil {
		slog.Error("metrics shutdown failed", "error", err)
	}
	return runErr
}

// sweepSessions prunes expired admin sessions.
func (s *Server) sweepSessions(ctx context.Context) {
	ticker := time.NewTicker(15 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			n, err := s.store.DeleteExpiredSessions(ctx, time.Now().UTC())
			if err != nil {
				slog.WarnContext(ctx, "pruning expired sessions failed", "error", err)
				continue
			}
			if n > 0 {
				slog.InfoContext(ctx, "pruned expired admin sessions", "count", n)
			}
		}
	}
}

// contextWithTimeout is a small indirection so ops handlers stay testable.
func contextWithTimeout(r *http.Request, d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(r.Context(), d)
}
