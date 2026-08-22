package sqlstore

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/dashdns/api/internal/store"
)

const applianceColumns = `id, tenant_id, name, description, token_id, created_at, last_seen_at, revoked_at`

// CreateAppliance registers a dnsd instance. Only tokenHash is persisted; the
// caller keeps the plaintext long enough to show it once.
func (s *Store) CreateAppliance(ctx context.Context, a *store.Appliance, tokenHash []byte) error {
	const q = `INSERT INTO appliances (id, tenant_id, name, description, token_id, token_hash, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`
	_, err := s.exec(ctx, q, a.ID, a.TenantID, a.Name, a.Description, a.TokenID, tokenHash, toMicros(a.CreatedAt))
	if err != nil {
		return fmt.Errorf("sqlstore: create appliance %q: %w", a.Name, mapErr(err))
	}
	return nil
}

// ListAppliances returns the tenant's appliances ordered by name.
func (s *Store) ListAppliances(ctx context.Context, tenantID string) ([]store.Appliance, error) {
	q := `SELECT ` + applianceColumns + ` FROM appliances WHERE tenant_id = ? ORDER BY name`
	rows, err := s.query(ctx, q, tenantID)
	if err != nil {
		return nil, fmt.Errorf("sqlstore: list appliances: %w", err)
	}
	defer rows.Close()

	out := []store.Appliance{}
	for rows.Next() {
		a, err := scanAppliance(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *a)
	}
	return out, rows.Err()
}

// GetAppliance loads one appliance scoped to its tenant.
func (s *Store) GetAppliance(ctx context.Context, tenantID, id string) (*store.Appliance, error) {
	q := `SELECT ` + applianceColumns + ` FROM appliances WHERE tenant_id = ? AND id = ?`
	a, err := scanAppliance(s.queryRow(ctx, q, tenantID, id))
	if err != nil {
		return nil, fmt.Errorf("sqlstore: get appliance %q: %w", id, err)
	}
	return a, nil
}

// RotateApplianceToken swaps in a freshly minted token and clears any prior
// revocation, so rotating is also the way to re-enable a revoked appliance.
func (s *Store) RotateApplianceToken(ctx context.Context, tenantID, id, tokenID string, tokenHash []byte) (*store.Appliance, error) {
	const q = `UPDATE appliances SET token_id = ?, token_hash = ?, revoked_at = NULL
		WHERE tenant_id = ? AND id = ?`
	res, err := s.exec(ctx, q, tokenID, tokenHash, tenantID, id)
	if err != nil {
		return nil, fmt.Errorf("sqlstore: rotate appliance %q: %w", id, mapErr(err))
	}
	if err := requireAffected(res, fmt.Sprintf("appliance %q", id)); err != nil {
		return nil, err
	}
	return s.GetAppliance(ctx, tenantID, id)
}

// RevokeAppliance withdraws the appliance's token without deleting its record,
// keeping the audit trail intact. Revoking an already-revoked appliance is a
// no-op rather than an error.
func (s *Store) RevokeAppliance(ctx context.Context, tenantID, id string) error {
	const q = `UPDATE appliances SET revoked_at = ? WHERE tenant_id = ? AND id = ? AND revoked_at IS NULL`
	res, err := s.exec(ctx, q, toMicros(time.Now().UTC()), tenantID, id)
	if err != nil {
		return fmt.Errorf("sqlstore: revoke appliance %q: %w", id, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("sqlstore: rows affected: %w", err)
	}
	if n > 0 {
		return nil
	}
	// Zero rows means either "already revoked" or "does not exist"; only the
	// latter is an error.
	if _, err := s.GetAppliance(ctx, tenantID, id); err != nil {
		return err
	}
	return nil
}

// DeleteAppliance permanently removes an appliance record.
func (s *Store) DeleteAppliance(ctx context.Context, tenantID, id string) error {
	res, err := s.exec(ctx, `DELETE FROM appliances WHERE tenant_id = ? AND id = ?`, tenantID, id)
	if err != nil {
		return fmt.Errorf("sqlstore: delete appliance %q: %w", id, err)
	}
	return requireAffected(res, fmt.Sprintf("appliance %q", id))
}

// FindApplianceByTokenID resolves the public half of a bearer token to its
// appliance and stored hash. It is intentionally not tenant-scoped: the token
// is what determines the tenant.
func (s *Store) FindApplianceByTokenID(ctx context.Context, tokenID string) (*store.Appliance, []byte, error) {
	q := `SELECT ` + applianceColumns + `, token_hash FROM appliances WHERE token_id = ?`
	var (
		a                   store.Appliance
		created             int64
		lastSeen, revoked   sql.NullInt64
		hash                []byte
	)
	err := s.queryRow(ctx, q, tokenID).Scan(
		&a.ID, &a.TenantID, &a.Name, &a.Description, &a.TokenID,
		&created, &lastSeen, &revoked, &hash,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("sqlstore: find appliance by token: %w", mapErr(err))
	}
	a.CreatedAt = fromMicros(created)
	a.LastSeenAt = fromNullMicros(lastSeen)
	a.RevokedAt = fromNullMicros(revoked)
	return &a, hash, nil
}

// TouchAppliance records liveness, but only when the stored timestamp is older
// than notBefore. dnsd polls on a fixed interval per appliance and the caller
// throttles to roughly one write per minute, so this stays off the hot path.
func (s *Store) TouchAppliance(ctx context.Context, id string, seenAt, notBefore time.Time) error {
	const q = `UPDATE appliances SET last_seen_at = ?
		WHERE id = ? AND (last_seen_at IS NULL OR last_seen_at < ?)`
	if _, err := s.exec(ctx, q, toMicros(seenAt), id, toMicros(notBefore)); err != nil {
		return fmt.Errorf("sqlstore: touch appliance %q: %w", id, err)
	}
	return nil
}

// CountAppliances reports active and revoked counts for metrics.
func (s *Store) CountAppliances(ctx context.Context, tenantID string) (int, int, error) {
	const q = `SELECT
			SUM(CASE WHEN revoked_at IS NULL THEN 1 ELSE 0 END),
			SUM(CASE WHEN revoked_at IS NULL THEN 0 ELSE 1 END)
		FROM appliances WHERE tenant_id = ?`
	var active, revoked sql.NullInt64
	if err := s.queryRow(ctx, q, tenantID).Scan(&active, &revoked); err != nil {
		return 0, 0, fmt.Errorf("sqlstore: count appliances: %w", err)
	}
	return int(active.Int64), int(revoked.Int64), nil
}

// rowScanner is satisfied by both *sql.Row and *sql.Rows.
type rowScanner interface {
	Scan(dest ...any) error
}

func scanAppliance(sc rowScanner) (*store.Appliance, error) {
	var (
		a                 store.Appliance
		created           int64
		lastSeen, revoked sql.NullInt64
	)
	err := sc.Scan(&a.ID, &a.TenantID, &a.Name, &a.Description, &a.TokenID, &created, &lastSeen, &revoked)
	if err != nil {
		return nil, mapErr(err)
	}
	a.CreatedAt = fromMicros(created)
	a.LastSeenAt = fromNullMicros(lastSeen)
	a.RevokedAt = fromNullMicros(revoked)
	return &a, nil
}
