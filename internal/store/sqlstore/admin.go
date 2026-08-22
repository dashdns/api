package sqlstore

import (
	"context"
	"fmt"
	"time"

	"github.com/dashdns/api/internal/store"
)

const adminUserColumns = `id, tenant_id, username, role, password_hash, password_salt, created_at`

// CreateAdminUser inserts a management-plane operator.
func (s *Store) CreateAdminUser(ctx context.Context, u *store.AdminUser) error {
	const q = `INSERT INTO admin_users (id, tenant_id, username, role, password_hash, password_salt, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`
	_, err := s.exec(ctx, q, u.ID, u.TenantID, u.Username, u.Role, u.PasswordHash, u.PasswordSalt, toMicros(u.CreatedAt))
	if err != nil {
		return fmt.Errorf("sqlstore: create admin user %q: %w", u.Username, mapErr(err))
	}
	return nil
}

// GetAdminUser loads an operator by ID.
func (s *Store) GetAdminUser(ctx context.Context, id string) (*store.AdminUser, error) {
	q := `SELECT ` + adminUserColumns + ` FROM admin_users WHERE id = ?`
	u, err := scanAdminUser(s.queryRow(ctx, q, id))
	if err != nil {
		return nil, fmt.Errorf("sqlstore: get admin user %q: %w", id, err)
	}
	return u, nil
}

// GetAdminUserByUsername loads an operator by login name.
func (s *Store) GetAdminUserByUsername(ctx context.Context, username string) (*store.AdminUser, error) {
	q := `SELECT ` + adminUserColumns + ` FROM admin_users WHERE username = ?`
	u, err := scanAdminUser(s.queryRow(ctx, q, username))
	if err != nil {
		return nil, fmt.Errorf("sqlstore: get admin user %q: %w", username, err)
	}
	return u, nil
}

// CountAdminUsers reports how many operators exist; startup uses it to decide
// whether the bootstrap admin still needs creating.
func (s *Store) CountAdminUsers(ctx context.Context) (int, error) {
	var n int
	if err := s.queryRow(ctx, `SELECT COUNT(*) FROM admin_users`).Scan(&n); err != nil {
		return 0, fmt.Errorf("sqlstore: count admin users: %w", err)
	}
	return n, nil
}

// CreateSession stores a minted admin session.
func (s *Store) CreateSession(ctx context.Context, sess *store.AdminSession) error {
	const q = `INSERT INTO admin_sessions (token_id, token_hash, admin_user_id, created_at, expires_at)
		VALUES (?, ?, ?, ?, ?)`
	_, err := s.exec(ctx, q, sess.TokenID, sess.TokenHash, sess.AdminUserID, toMicros(sess.CreatedAt), toMicros(sess.ExpiresAt))
	if err != nil {
		return fmt.Errorf("sqlstore: create session: %w", mapErr(err))
	}
	return nil
}

// FindSessionByTokenID resolves the public half of a session token. Expiry is
// checked by the caller so an expired session can be distinguished from an
// unknown one.
func (s *Store) FindSessionByTokenID(ctx context.Context, tokenID string) (*store.AdminSession, error) {
	const q = `SELECT token_id, token_hash, admin_user_id, created_at, expires_at
		FROM admin_sessions WHERE token_id = ?`
	var (
		sess             store.AdminSession
		created, expires int64
	)
	err := s.queryRow(ctx, q, tokenID).Scan(&sess.TokenID, &sess.TokenHash, &sess.AdminUserID, &created, &expires)
	if err != nil {
		return nil, fmt.Errorf("sqlstore: find session: %w", mapErr(err))
	}
	sess.CreatedAt, sess.ExpiresAt = fromMicros(created), fromMicros(expires)
	return &sess, nil
}

// DeleteSession is the logout path. Deleting an unknown session is a no-op.
func (s *Store) DeleteSession(ctx context.Context, tokenID string) error {
	if _, err := s.exec(ctx, `DELETE FROM admin_sessions WHERE token_id = ?`, tokenID); err != nil {
		return fmt.Errorf("sqlstore: delete session: %w", err)
	}
	return nil
}

// DeleteExpiredSessions prunes the session table; a background sweeper calls it
// periodically.
func (s *Store) DeleteExpiredSessions(ctx context.Context, now time.Time) (int64, error) {
	res, err := s.exec(ctx, `DELETE FROM admin_sessions WHERE expires_at < ?`, toMicros(now))
	if err != nil {
		return 0, fmt.Errorf("sqlstore: prune sessions: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, nil // driver does not report it; not worth failing the sweep
	}
	return n, nil
}

func scanAdminUser(sc rowScanner) (*store.AdminUser, error) {
	var (
		u       store.AdminUser
		created int64
	)
	err := sc.Scan(&u.ID, &u.TenantID, &u.Username, &u.Role, &u.PasswordHash, &u.PasswordSalt, &created)
	if err != nil {
		return nil, mapErr(err)
	}
	u.CreatedAt = fromMicros(created)
	return &u, nil
}
