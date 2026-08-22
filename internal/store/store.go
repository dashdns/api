// Package store defines the persistence contract for policy-controller.
//
// Handlers depend only on the interfaces here, never on database/sql, so the
// backend can move between SQLite and Postgres (see internal/store/sqlstore)
// or be replaced entirely by an in-memory fake in tests.
package store

import (
	"context"
	"errors"
	"time"
)

// Sentinel errors. Repositories must wrap these so handlers can map them to
// HTTP status codes with errors.Is.
var (
	ErrNotFound = errors.New("store: not found")
	ErrConflict = errors.New("store: conflict")
)

// Tenant is an isolation boundary. In single-tenant mode exactly one tenant
// exists (config.DefaultTenant) and it is created automatically at startup.
type Tenant struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Policy is the set of domains blocked for one client IP inside one tenant.
type Policy struct {
	ID        string    `json:"id"`
	TenantID  string    `json:"tenant_id"`
	ClientIP  string    `json:"ip"`
	Domains   []string  `json:"domains"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Revision is a tenant-scoped monotonic counter bumped on every policy write.
// It lets GET /api/policies decide whether its cached snapshot is still valid
// without re-reading and re-hashing the whole blocklist on each dnsd poll.
type Revision struct {
	Value     int64
	UpdatedAt time.Time
}

// Appliance is a registered dnsd instance holding one API token.
type Appliance struct {
	ID          string     `json:"id"`
	TenantID    string     `json:"tenant_id"`
	Name        string     `json:"name"`
	Description string     `json:"description,omitempty"`
	TokenID     string     `json:"token_id"`
	CreatedAt   time.Time  `json:"created_at"`
	LastSeenAt  *time.Time `json:"last_seen_at,omitempty"`
	RevokedAt   *time.Time `json:"revoked_at,omitempty"`
}

// Revoked reports whether the appliance token has been withdrawn.
func (a Appliance) Revoked() bool { return a.RevokedAt != nil }

// Admin roles. A tenant admin manages only its own tenant; a superadmin may
// act on any tenant and is the only role allowed to manage tenants themselves.
const (
	RoleAdmin      = "admin"
	RoleSuperAdmin = "superadmin"
)

// AdminUser is a human operator of the management API. Admin credentials are
// deliberately a different kind of principal from appliance tokens: appliances
// can only read /api/policies, admins can only reach /api/admin/*.
type AdminUser struct {
	ID           string    `json:"id"`
	TenantID     string    `json:"tenant_id"`
	Username     string    `json:"username"`
	Role         string    `json:"role"`
	PasswordHash []byte    `json:"-"`
	PasswordSalt []byte    `json:"-"`
	CreatedAt    time.Time `json:"created_at"`
}

// AdminSession is a bearer session minted by POST /api/admin/auth/login.
type AdminSession struct {
	TokenID     string
	TokenHash   []byte
	AdminUserID string
	CreatedAt   time.Time
	ExpiresAt   time.Time
}

// TenantRepository manages isolation boundaries.
type TenantRepository interface {
	EnsureTenant(ctx context.Context, id, name string) (*Tenant, error)
	CreateTenant(ctx context.Context, id, name string) (*Tenant, error)
	GetTenant(ctx context.Context, id string) (*Tenant, error)
	ListTenants(ctx context.Context) ([]Tenant, error)
	DeleteTenant(ctx context.Context, id string) error
}

// PolicyRepository manages per-IP domain blocklists.
//
// Domains handed to this layer are already normalised and validated by
// internal/policy; repositories persist them verbatim and return them sorted.
type PolicyRepository interface {
	ListPolicies(ctx context.Context, tenantID string) ([]Policy, error)
	GetPolicy(ctx context.Context, tenantID, clientIP string) (*Policy, error)
	// CreatePolicy fails with ErrConflict if clientIP already has a policy.
	CreatePolicy(ctx context.Context, tenantID, clientIP string, domains []string) (*Policy, error)
	// ReplacePolicy is an upsert: it creates the policy or replaces its domain
	// set wholesale.
	ReplacePolicy(ctx context.Context, tenantID, clientIP string, domains []string) (*Policy, error)
	// MutatePolicyDomains adds and removes domains on an existing policy.
	MutatePolicyDomains(ctx context.Context, tenantID, clientIP string, add, remove []string) (*Policy, error)
	DeletePolicy(ctx context.Context, tenantID, clientIP string) error
	// Revision returns the tenant's current policy revision. It is called on
	// every appliance poll, so it must stay a single cheap read.
	Revision(ctx context.Context, tenantID string) (Revision, error)
}

// ApplianceRepository manages dnsd registrations and their tokens.
//
// Only the SHA-256 of the token secret is ever stored; the plaintext is
// returned once, at mint time, and never again.
type ApplianceRepository interface {
	CreateAppliance(ctx context.Context, a *Appliance, tokenHash []byte) error
	ListAppliances(ctx context.Context, tenantID string) ([]Appliance, error)
	GetAppliance(ctx context.Context, tenantID, id string) (*Appliance, error)
	RotateApplianceToken(ctx context.Context, tenantID, id, tokenID string, tokenHash []byte) (*Appliance, error)
	RevokeAppliance(ctx context.Context, tenantID, id string) error
	DeleteAppliance(ctx context.Context, tenantID, id string) error
	// FindApplianceByTokenID resolves the public half of a bearer token. It is
	// tenant-agnostic on purpose: the token itself is what selects the tenant.
	FindApplianceByTokenID(ctx context.Context, tokenID string) (*Appliance, []byte, error)
	// TouchAppliance records liveness. Implementations should skip the write
	// when last_seen_at is already newer than notBefore to avoid one row update
	// per poll.
	TouchAppliance(ctx context.Context, id string, seenAt, notBefore time.Time) error
	CountAppliances(ctx context.Context, tenantID string) (active, revoked int, err error)
}

// AdminRepository manages management-plane identities and sessions.
type AdminRepository interface {
	CreateAdminUser(ctx context.Context, u *AdminUser) error
	GetAdminUser(ctx context.Context, id string) (*AdminUser, error)
	GetAdminUserByUsername(ctx context.Context, username string) (*AdminUser, error)
	CountAdminUsers(ctx context.Context) (int, error)
	CreateSession(ctx context.Context, s *AdminSession) error
	FindSessionByTokenID(ctx context.Context, tokenID string) (*AdminSession, error)
	DeleteSession(ctx context.Context, tokenID string) error
	DeleteExpiredSessions(ctx context.Context, now time.Time) (int64, error)
}

// Store is the full persistence surface. Modules take the narrow interfaces
// above; only wiring code depends on Store.
type Store interface {
	TenantRepository
	PolicyRepository
	ApplianceRepository
	AdminRepository

	Ping(ctx context.Context) error
	Close() error
}
