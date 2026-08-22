package auth

import (
	"context"

	"github.com/dashdns/api/internal/store"
)

// Kind distinguishes the two credential planes.
type Kind string

const (
	// KindAppliance is a dnsd instance holding a read-only appliance token.
	KindAppliance Kind = "appliance"
	// KindAdmin is a human operator holding an admin session token.
	KindAdmin Kind = "admin"
)

// Principal is the authenticated caller attached to a request context.
type Principal struct {
	Kind Kind
	// ID is the appliance ID or the admin user ID.
	ID string
	// Name is the appliance name or the admin username, for logs and metrics.
	Name string
	// TenantID is the caller's home tenant.
	TenantID string
	// Role is the admin role; empty for appliances.
	Role string
	// Anonymous marks a synthetic appliance principal issued when
	// -require-appliance-auth=false.
	Anonymous bool
}

// IsSuperAdmin reports whether the principal may act across tenants.
func (p *Principal) IsSuperAdmin() bool {
	return p != nil && p.Kind == KindAdmin && p.Role == store.RoleSuperAdmin
}

// IsAdmin reports whether the principal is a management-plane operator.
func (p *Principal) IsAdmin() bool {
	return p != nil && p.Kind == KindAdmin
}

type principalContextKey struct{}

// WithPrincipal returns a context carrying p.
func WithPrincipal(ctx context.Context, p *Principal) context.Context {
	return context.WithValue(ctx, principalContextKey{}, p)
}

// PrincipalFrom returns the principal attached to ctx, or nil.
func PrincipalFrom(ctx context.Context) *Principal {
	p, _ := ctx.Value(principalContextKey{}).(*Principal)
	return p
}
