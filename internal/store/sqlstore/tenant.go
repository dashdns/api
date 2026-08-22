package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/dashdns/api/internal/store"
)

// EnsureTenant creates the tenant if it does not exist and returns it either
// way. Startup calls this for config.DefaultTenant so single-tenant mode never
// needs a provisioning step.
func (s *Store) EnsureTenant(ctx context.Context, id, name string) (*store.Tenant, error) {
	now := time.Now().UTC()
	const q = `INSERT INTO tenants (id, name, created_at, updated_at) VALUES (?, ?, ?, ?)
		ON CONFLICT (id) DO NOTHING`
	if _, err := s.exec(ctx, q, id, name, toMicros(now), toMicros(now)); err != nil {
		return nil, fmt.Errorf("sqlstore: ensure tenant: %w", err)
	}
	return s.GetTenant(ctx, id)
}

// CreateTenant inserts a new tenant, failing with store.ErrConflict if the ID
// is taken.
func (s *Store) CreateTenant(ctx context.Context, id, name string) (*store.Tenant, error) {
	now := time.Now().UTC()
	const q = `INSERT INTO tenants (id, name, created_at, updated_at) VALUES (?, ?, ?, ?)`
	if _, err := s.exec(ctx, q, id, name, toMicros(now), toMicros(now)); err != nil {
		return nil, fmt.Errorf("sqlstore: create tenant: %w", mapErr(err))
	}
	return &store.Tenant{ID: id, Name: name, CreatedAt: now, UpdatedAt: now}, nil
}

// GetTenant loads a single tenant.
func (s *Store) GetTenant(ctx context.Context, id string) (*store.Tenant, error) {
	const q = `SELECT id, name, created_at, updated_at FROM tenants WHERE id = ?`
	var (
		t                 store.Tenant
		created, updated  int64
	)
	err := s.queryRow(ctx, q, id).Scan(&t.ID, &t.Name, &created, &updated)
	if err != nil {
		return nil, fmt.Errorf("sqlstore: get tenant %q: %w", id, mapErr(err))
	}
	t.CreatedAt, t.UpdatedAt = fromMicros(created), fromMicros(updated)
	return &t, nil
}

// ListTenants returns every tenant ordered by ID.
func (s *Store) ListTenants(ctx context.Context) ([]store.Tenant, error) {
	const q = `SELECT id, name, created_at, updated_at FROM tenants ORDER BY id`
	rows, err := s.query(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("sqlstore: list tenants: %w", err)
	}
	defer rows.Close()

	out := []store.Tenant{}
	for rows.Next() {
		var (
			t                store.Tenant
			created, updated int64
		)
		if err := rows.Scan(&t.ID, &t.Name, &created, &updated); err != nil {
			return nil, fmt.Errorf("sqlstore: scan tenant: %w", err)
		}
		t.CreatedAt, t.UpdatedAt = fromMicros(created), fromMicros(updated)
		out = append(out, t)
	}
	return out, rows.Err()
}

// DeleteTenant removes a tenant and, by cascade, its policies, appliances and
// admins.
func (s *Store) DeleteTenant(ctx context.Context, id string) error {
	res, err := s.exec(ctx, `DELETE FROM tenants WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("sqlstore: delete tenant %q: %w", id, err)
	}
	return requireAffected(res, fmt.Sprintf("tenant %q", id))
}

// bumpRevision advances the tenant's policy revision inside tx. Every policy
// write funnels through here; GET /api/policies compares the returned value
// against its cached snapshot to decide whether a rebuild is needed.
func (s *Store) bumpRevision(ctx context.Context, tx *sql.Tx, tenantID string, at time.Time) error {
	const q = `INSERT INTO tenant_revisions (tenant_id, revision, updated_at) VALUES (?, 1, ?)
		ON CONFLICT (tenant_id) DO UPDATE SET
			revision   = tenant_revisions.revision + 1,
			updated_at = excluded.updated_at`
	if _, err := s.txExec(ctx, tx, q, tenantID, toMicros(at)); err != nil {
		return fmt.Errorf("sqlstore: bump revision for %q: %w", tenantID, err)
	}
	return nil
}

// Revision returns the tenant's current policy revision. A tenant that has
// never had a policy written reports revision 0.
func (s *Store) Revision(ctx context.Context, tenantID string) (store.Revision, error) {
	const q = `SELECT revision, updated_at FROM tenant_revisions WHERE tenant_id = ?`
	var value, updated int64
	err := s.queryRow(ctx, q, tenantID).Scan(&value, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return store.Revision{}, nil
	}
	if err != nil {
		return store.Revision{}, fmt.Errorf("sqlstore: revision for %q: %w", tenantID, err)
	}
	return store.Revision{Value: value, UpdatedAt: fromMicros(updated)}, nil
}

func requireAffected(res sql.Result, what string) error {
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("sqlstore: rows affected: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("sqlstore: %s: %w", what, store.ErrNotFound)
	}
	return nil
}
