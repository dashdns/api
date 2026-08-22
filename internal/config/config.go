// Package config holds the policy-controller runtime configuration.
//
// Configuration follows dnsd's convention: plain stdlib flags, no config file,
// no third-party loader. Every flag may also be supplied through an environment
// variable (POLICY_CONTROLLER_<FLAG_IN_SCREAMING_SNAKE_CASE>) so the same
// binary is convenient both as a systemd unit in a customer VNET and as a
// container in our own SaaS deployment.
package config

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Storage drivers understood by internal/store/sqlstore.
const (
	DriverSQLite   = "sqlite"
	DriverPostgres = "postgres"
)

// Config is the fully resolved runtime configuration.
type Config struct {
	// Listen is the address of the main API server (policies + admin).
	Listen string
	// MetricsListen is the address of the Prometheus server. It is a separate
	// listener so the metrics port can stay on the management network while the
	// API port is reachable by appliances -- same split dnsd uses with :9090.
	MetricsListen string

	// DBDriver selects the storage backend: "sqlite" or "postgres".
	DBDriver string
	// DBDSN is the driver-specific data source name.
	DBDSN string

	// MultiTenant enables tenant isolation. When false the controller runs in
	// single-tenant mode: every policy, appliance and admin belongs to
	// DefaultTenant and the tenant admin endpoints are disabled.
	MultiTenant bool
	// DefaultTenant is the tenant ID used in single-tenant mode and as the home
	// tenant of the bootstrap admin.
	DefaultTenant string

	// RequireApplianceAuth gates GET /api/policies behind an appliance bearer
	// token. It defaults to true. Set it to false only for a closed-network
	// rollout where dnsd instances predate the -ip-blocklist-token flag.
	RequireApplianceAuth bool

	// BootstrapAdminUser / BootstrapAdminPassword create the first admin
	// account on an empty database. They are ignored once any admin exists.
	BootstrapAdminUser     string
	BootstrapAdminPassword string

	// AdminSessionTTL is how long an admin session token stays valid.
	AdminSessionTTL time.Duration

	// ReadTimeout / WriteTimeout / IdleTimeout / ShutdownTimeout bound the HTTP
	// servers.
	ReadTimeout     time.Duration
	WriteTimeout    time.Duration
	IdleTimeout     time.Duration
	ShutdownTimeout time.Duration
}

// Default returns the configuration used when no flags are supplied.
func Default() Config {
	return Config{
		Listen:               ":8080",
		MetricsListen:        ":9091",
		DBDriver:             DriverSQLite,
		DBDSN:                "file:policy-controller.db?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)",
		MultiTenant:          false,
		DefaultTenant:        "default",
		RequireApplianceAuth: true,
		AdminSessionTTL:      12 * time.Hour,
		ReadTimeout:          10 * time.Second,
		WriteTimeout:         30 * time.Second,
		IdleTimeout:          60 * time.Second,
		ShutdownTimeout:      10 * time.Second,
	}
}

// Parse binds every field to fs, applies environment defaults and parses args.
func Parse(fs *flag.FlagSet, args []string) (Config, error) {
	cfg := Default()

	fs.StringVar(&cfg.Listen, "listen", envString("LISTEN", cfg.Listen), "Address for the policy/admin API server")
	fs.StringVar(&cfg.MetricsListen, "metrics-listen", envString("METRICS_LISTEN", cfg.MetricsListen), "Address for the Prometheus metrics server (dnsd uses :9090; keep this one distinct)")
	fs.StringVar(&cfg.DBDriver, "db-driver", envString("DB_DRIVER", cfg.DBDriver), "Storage driver: sqlite or postgres")
	fs.StringVar(&cfg.DBDSN, "db-dsn", envString("DB_DSN", cfg.DBDSN), "Storage DSN (sqlite file path/URI or postgres connection string)")
	fs.BoolVar(&cfg.MultiTenant, "multi-tenant", envBool("MULTI_TENANT", cfg.MultiTenant), "Enable tenant isolation (SaaS mode). Off means single-tenant self-hosted mode")
	fs.StringVar(&cfg.DefaultTenant, "default-tenant", envString("DEFAULT_TENANT", cfg.DefaultTenant), "Tenant ID used in single-tenant mode")
	fs.BoolVar(&cfg.RequireApplianceAuth, "require-appliance-auth", envBool("REQUIRE_APPLIANCE_AUTH", cfg.RequireApplianceAuth), "Require a Bearer appliance token on GET /api/policies")
	fs.StringVar(&cfg.BootstrapAdminUser, "bootstrap-admin-user", envString("BOOTSTRAP_ADMIN_USER", cfg.BootstrapAdminUser), "Username of the admin account created on an empty database")
	fs.StringVar(&cfg.BootstrapAdminPassword, "bootstrap-admin-password", envString("BOOTSTRAP_ADMIN_PASSWORD", cfg.BootstrapAdminPassword), "Password for -bootstrap-admin-user (prefer the env var over the flag)")
	fs.DurationVar(&cfg.AdminSessionTTL, "admin-session-ttl", envDuration("ADMIN_SESSION_TTL", cfg.AdminSessionTTL), "Lifetime of an admin session token")
	fs.DurationVar(&cfg.ReadTimeout, "read-timeout", envDuration("READ_TIMEOUT", cfg.ReadTimeout), "HTTP read timeout")
	fs.DurationVar(&cfg.WriteTimeout, "write-timeout", envDuration("WRITE_TIMEOUT", cfg.WriteTimeout), "HTTP write timeout")
	fs.DurationVar(&cfg.IdleTimeout, "idle-timeout", envDuration("IDLE_TIMEOUT", cfg.IdleTimeout), "HTTP idle timeout")
	fs.DurationVar(&cfg.ShutdownTimeout, "shutdown-timeout", envDuration("SHUTDOWN_TIMEOUT", cfg.ShutdownTimeout), "Graceful shutdown grace period")

	if err := fs.Parse(args); err != nil {
		return Config{}, err
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// Validate reports configuration that cannot produce a working server.
func (c Config) Validate() error {
	if c.Listen == "" {
		return errors.New("config: -listen must not be empty")
	}
	if c.MetricsListen == c.Listen {
		return errors.New("config: -metrics-listen must differ from -listen")
	}
	switch c.DBDriver {
	case DriverSQLite, DriverPostgres:
	default:
		return fmt.Errorf("config: unsupported -db-driver %q (want %q or %q)", c.DBDriver, DriverSQLite, DriverPostgres)
	}
	if strings.TrimSpace(c.DBDSN) == "" {
		return errors.New("config: -db-dsn must not be empty")
	}
	if strings.TrimSpace(c.DefaultTenant) == "" {
		return errors.New("config: -default-tenant must not be empty")
	}
	if c.AdminSessionTTL <= 0 {
		return errors.New("config: -admin-session-ttl must be positive")
	}
	if (c.BootstrapAdminUser == "") != (c.BootstrapAdminPassword == "") {
		return errors.New("config: -bootstrap-admin-user and -bootstrap-admin-password must be set together")
	}
	if c.BootstrapAdminPassword != "" && len(c.BootstrapAdminPassword) < 12 {
		return errors.New("config: -bootstrap-admin-password must be at least 12 characters")
	}
	return nil
}

const envPrefix = "POLICY_CONTROLLER_"

func envString(name, fallback string) string {
	if v, ok := os.LookupEnv(envPrefix + name); ok {
		return v
	}
	return fallback
}

func envBool(name string, fallback bool) bool {
	v, ok := os.LookupEnv(envPrefix + name)
	if !ok {
		return fallback
	}
	parsed, err := strconv.ParseBool(v)
	if err != nil {
		return fallback
	}
	return parsed
}

func envDuration(name string, fallback time.Duration) time.Duration {
	v, ok := os.LookupEnv(envPrefix + name)
	if !ok {
		return fallback
	}
	parsed, err := time.ParseDuration(v)
	if err != nil {
		return fallback
	}
	return parsed
}
