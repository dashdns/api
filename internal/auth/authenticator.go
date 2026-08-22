package auth

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/dashdns/api/internal/idgen"
	"github.com/dashdns/api/internal/store"
)

// Authentication outcomes. Handlers map these to status codes; the reason is
// also used as the metrics label, so the set stays small and stable.
var (
	// ErrMissingCredentials means no Authorization header was presented.
	ErrMissingCredentials = errors.New("auth: missing credentials")
	// ErrInvalidCredentials covers unknown, malformed and mismatching tokens.
	// The three cases are deliberately indistinguishable to the caller.
	ErrInvalidCredentials = errors.New("auth: invalid credentials")
	// ErrRevoked means the appliance token was withdrawn by an admin.
	ErrRevoked = errors.New("auth: credential revoked")
	// ErrExpired means the admin session has aged out.
	ErrExpired = errors.New("auth: credential expired")
)

// Reason returns the short label used in logs and the auth_failures_total
// metric.
func Reason(err error) string {
	switch {
	case errors.Is(err, ErrMissingCredentials):
		return "missing"
	case errors.Is(err, ErrRevoked):
		return "revoked"
	case errors.Is(err, ErrExpired):
		return "expired"
	case errors.Is(err, ErrInvalidCredentials), errors.Is(err, ErrMalformedToken):
		return "invalid"
	default:
		return "error"
	}
}

// Options configures the Authenticator.
type Options struct {
	// RequireApplianceAuth gates GET /api/policies. When false, unauthenticated
	// callers get an anonymous principal scoped to DefaultTenant.
	RequireApplianceAuth bool
	// MultiTenant mirrors config.Config.MultiTenant.
	MultiTenant bool
	// DefaultTenant is the tenant assigned to anonymous appliances.
	DefaultTenant string
	// SessionTTL is the lifetime of a minted admin session.
	SessionTTL time.Duration
	// TouchInterval throttles appliance last_seen_at writes.
	TouchInterval time.Duration
}

// Authenticator resolves credentials against the store.
type Authenticator struct {
	appliances store.ApplianceRepository
	admins     store.AdminRepository
	opts       Options
	// dummySalt makes an unknown-username login cost the same as a known one,
	// so response timing does not enumerate accounts.
	dummySalt []byte
}

// NewAuthenticator wires an Authenticator. TouchInterval defaults to one
// minute when unset.
func NewAuthenticator(appliances store.ApplianceRepository, admins store.AdminRepository, opts Options) *Authenticator {
	if opts.TouchInterval <= 0 {
		opts.TouchInterval = time.Minute
	}
	if opts.DefaultTenant == "" {
		opts.DefaultTenant = "default"
	}
	if opts.SessionTTL <= 0 {
		opts.SessionTTL = 12 * time.Hour
	}
	salt := sha256.Sum256([]byte("policy-controller/timing-equalizer"))
	return &Authenticator{
		appliances: appliances,
		admins:     admins,
		opts:       opts,
		dummySalt:  salt[:16],
	}
}

// Options exposes the effective configuration.
func (a *Authenticator) Options() Options { return a.opts }

// AuthenticateAppliance resolves an appliance bearer token.
//
// When -require-appliance-auth is false and no credential is presented, it
// returns an anonymous principal instead of an error. A credential that *is*
// presented is always verified, so a rollout can flip the flag on only after
// every dnsd instance has been given a token.
func (a *Authenticator) AuthenticateAppliance(ctx context.Context, authorization string) (*Principal, error) {
	raw, ok := BearerToken(authorization)
	if !ok {
		if a.opts.RequireApplianceAuth {
			return nil, ErrMissingCredentials
		}
		return &Principal{
			Kind:      KindAppliance,
			ID:        "anonymous",
			Name:      "anonymous",
			TenantID:  a.opts.DefaultTenant,
			Anonymous: true,
		}, nil
	}

	tokenID, secret, err := Split(AppliancePrefix, raw)
	if err != nil {
		return nil, ErrInvalidCredentials
	}

	appliance, hash, err := a.appliances.FindApplianceByTokenID(ctx, tokenID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, ErrInvalidCredentials
		}
		return nil, fmt.Errorf("auth: lookup appliance: %w", err)
	}
	if !VerifySecret(secret, hash) {
		return nil, ErrInvalidCredentials
	}
	if appliance.Revoked() {
		return nil, ErrRevoked
	}

	now := time.Now().UTC()
	if err := a.appliances.TouchAppliance(ctx, appliance.ID, now, now.Add(-a.opts.TouchInterval)); err != nil {
		// Liveness bookkeeping is best-effort: a failed last_seen_at write must
		// never cost an appliance its policy refresh.
		slog.WarnContext(ctx, "recording appliance liveness failed",
			"appliance_id", appliance.ID, "error", err)
	}

	return &Principal{
		Kind:     KindAppliance,
		ID:       appliance.ID,
		Name:     appliance.Name,
		TenantID: appliance.TenantID,
	}, nil
}

// AuthenticateAdmin resolves an admin session bearer token.
func (a *Authenticator) AuthenticateAdmin(ctx context.Context, authorization string) (*Principal, error) {
	raw, ok := BearerToken(authorization)
	if !ok {
		return nil, ErrMissingCredentials
	}
	tokenID, secret, err := Split(SessionPrefix, raw)
	if err != nil {
		return nil, ErrInvalidCredentials
	}

	sess, err := a.admins.FindSessionByTokenID(ctx, tokenID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, ErrInvalidCredentials
		}
		return nil, fmt.Errorf("auth: lookup session: %w", err)
	}
	if !VerifySecret(secret, sess.TokenHash) {
		return nil, ErrInvalidCredentials
	}
	if time.Now().UTC().After(sess.ExpiresAt) {
		// Drop it eagerly so a replayed expired token stops hitting the table.
		_ = a.admins.DeleteSession(ctx, tokenID)
		return nil, ErrExpired
	}

	user, err := a.admins.GetAdminUser(ctx, sess.AdminUserID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, ErrInvalidCredentials
		}
		return nil, fmt.Errorf("auth: lookup admin user: %w", err)
	}

	return &Principal{
		Kind:     KindAdmin,
		ID:       user.ID,
		Name:     user.Username,
		TenantID: user.TenantID,
		Role:     user.Role,
	}, nil
}

// Session is a freshly minted admin login.
type Session struct {
	Token     string
	ExpiresAt time.Time
	Principal *Principal
}

// Login verifies a username/password pair and mints a session token.
func (a *Authenticator) Login(ctx context.Context, username, password string) (*Session, error) {
	username = strings.ToLower(strings.TrimSpace(username))

	user, err := a.admins.GetAdminUserByUsername(ctx, username)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			// Burn the same PBKDF2 work as a successful lookup would.
			VerifyPassword(password, make([]byte, pbkdf2KeyLength), a.dummySalt)
			return nil, ErrInvalidCredentials
		}
		return nil, fmt.Errorf("auth: lookup admin user: %w", err)
	}
	if !VerifyPassword(password, user.PasswordHash, user.PasswordSalt) {
		return nil, ErrInvalidCredentials
	}

	token, err := Mint(SessionPrefix)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	sess := &store.AdminSession{
		TokenID:     token.ID,
		TokenHash:   token.Hash,
		AdminUserID: user.ID,
		CreatedAt:   now,
		ExpiresAt:   now.Add(a.opts.SessionTTL),
	}
	if err := a.admins.CreateSession(ctx, sess); err != nil {
		return nil, fmt.Errorf("auth: create session: %w", err)
	}

	return &Session{
		Token:     token.Plaintext,
		ExpiresAt: sess.ExpiresAt,
		Principal: &Principal{
			Kind:     KindAdmin,
			ID:       user.ID,
			Name:     user.Username,
			TenantID: user.TenantID,
			Role:     user.Role,
		},
	}, nil
}

// Logout invalidates the session behind a bearer token. An unknown or
// malformed token is not an error: logout is idempotent.
func (a *Authenticator) Logout(ctx context.Context, authorization string) error {
	raw, ok := BearerToken(authorization)
	if !ok {
		return nil
	}
	tokenID, _, err := Split(SessionPrefix, raw)
	if err != nil {
		return nil
	}
	return a.admins.DeleteSession(ctx, tokenID)
}

// CreateAdminUser provisions an operator with a hashed password.
func CreateAdminUser(ctx context.Context, admins store.AdminRepository, tenantID, username, password, role string) (*store.AdminUser, error) {
	hash, salt, err := HashPassword(password)
	if err != nil {
		return nil, err
	}
	user := &store.AdminUser{
		ID:           idgen.New(idgen.PrefixAdminUser),
		TenantID:     tenantID,
		Username:     strings.ToLower(strings.TrimSpace(username)),
		Role:         role,
		PasswordHash: hash,
		PasswordSalt: salt,
		CreatedAt:    time.Now().UTC(),
	}
	if err := admins.CreateAdminUser(ctx, user); err != nil {
		return nil, err
	}
	return user, nil
}
