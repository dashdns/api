package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/dashdns/api/internal/idgen"
	"github.com/dashdns/api/internal/store"
)

// ListPolicies returns every policy in the tenant, ordered by client IP with
// each domain list sorted. The ordering is load-bearing: internal/policy hashes
// the serialised payload to produce the ETag, so the output must be
// deterministic for an unchanged database.
func (s *Store) ListPolicies(ctx context.Context, tenantID string) ([]store.Policy, error) {
	const q = `
		SELECT p.id, p.client_ip, p.created_at, p.updated_at, d.domain
		FROM policies p
		LEFT JOIN policy_domains d ON d.policy_id = p.id
		WHERE p.tenant_id = ?
		ORDER BY p.client_ip, d.domain`
	rows, err := s.query(ctx, q, tenantID)
	if err != nil {
		return nil, fmt.Errorf("sqlstore: list policies: %w", err)
	}
	defer rows.Close()

	out := []store.Policy{}
	byID := map[string]int{}
	for rows.Next() {
		var (
			id               string
			clientIP         string
			created, updated int64
			domain           sql.NullString
		)
		if err := rows.Scan(&id, &clientIP, &created, &updated, &domain); err != nil {
			return nil, fmt.Errorf("sqlstore: scan policy: %w", err)
		}
		idx, ok := byID[id]
		if !ok {
			out = append(out, store.Policy{
				ID:        id,
				TenantID:  tenantID,
				ClientIP:  clientIP,
				Domains:   []string{},
				CreatedAt: fromMicros(created),
				UpdatedAt: fromMicros(updated),
			})
			idx = len(out) - 1
			byID[id] = idx
		}
		if domain.Valid {
			out[idx].Domains = append(out[idx].Domains, domain.String)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("sqlstore: list policies: %w", err)
	}
	return out, nil
}

// GetPolicy loads a single policy by client IP.
func (s *Store) GetPolicy(ctx context.Context, tenantID, clientIP string) (*store.Policy, error) {
	const q = `SELECT id, created_at, updated_at FROM policies WHERE tenant_id = ? AND client_ip = ?`
	var (
		id               string
		created, updated int64
	)
	if err := s.queryRow(ctx, q, tenantID, clientIP).Scan(&id, &created, &updated); err != nil {
		return nil, fmt.Errorf("sqlstore: get policy %s: %w", clientIP, mapErr(err))
	}
	domains, err := s.loadDomains(ctx, nil, id)
	if err != nil {
		return nil, err
	}
	return &store.Policy{
		ID:        id,
		TenantID:  tenantID,
		ClientIP:  clientIP,
		Domains:   domains,
		CreatedAt: fromMicros(created),
		UpdatedAt: fromMicros(updated),
	}, nil
}

// CreatePolicy inserts a policy, returning store.ErrConflict if the client IP
// already has one in this tenant.
func (s *Store) CreatePolicy(ctx context.Context, tenantID, clientIP string, domains []string) (*store.Policy, error) {
	var result *store.Policy
	err := s.withTx(ctx, func(tx *sql.Tx) error {
		now := time.Now().UTC()
		id := idgen.New(idgen.PrefixPolicy)

		const insert = `INSERT INTO policies (id, tenant_id, client_ip, created_at, updated_at) VALUES (?, ?, ?, ?, ?)`
		if _, err := s.txExec(ctx, tx, insert, id, tenantID, clientIP, toMicros(now), toMicros(now)); err != nil {
			return fmt.Errorf("sqlstore: create policy %s: %w", clientIP, mapErr(err))
		}
		if err := s.insertDomains(ctx, tx, id, domains); err != nil {
			return err
		}
		if err := s.bumpRevision(ctx, tx, tenantID, now); err != nil {
			return err
		}
		result = &store.Policy{
			ID:        id,
			TenantID:  tenantID,
			ClientIP:  clientIP,
			Domains:   sortedCopy(domains),
			CreatedAt: now,
			UpdatedAt: now,
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// ReplacePolicy upserts: it creates the policy if absent, otherwise swaps its
// domain set wholesale. This is the PUT semantic.
func (s *Store) ReplacePolicy(ctx context.Context, tenantID, clientIP string, domains []string) (*store.Policy, error) {
	var result *store.Policy
	err := s.withTx(ctx, func(tx *sql.Tx) error {
		now := time.Now().UTC()

		id, createdAt, err := s.policyRowTx(ctx, tx, tenantID, clientIP)
		switch {
		case errors.Is(err, store.ErrNotFound):
			id, createdAt = idgen.New(idgen.PrefixPolicy), now
			const insert = `INSERT INTO policies (id, tenant_id, client_ip, created_at, updated_at) VALUES (?, ?, ?, ?, ?)`
			if _, err := s.txExec(ctx, tx, insert, id, tenantID, clientIP, toMicros(now), toMicros(now)); err != nil {
				return fmt.Errorf("sqlstore: replace policy %s: %w", clientIP, mapErr(err))
			}
		case err != nil:
			return err
		default:
			const touch = `UPDATE policies SET updated_at = ? WHERE id = ?`
			if _, err := s.txExec(ctx, tx, touch, toMicros(now), id); err != nil {
				return fmt.Errorf("sqlstore: replace policy %s: %w", clientIP, err)
			}
			if _, err := s.txExec(ctx, tx, `DELETE FROM policy_domains WHERE policy_id = ?`, id); err != nil {
				return fmt.Errorf("sqlstore: clear domains for %s: %w", clientIP, err)
			}
		}

		if err := s.insertDomains(ctx, tx, id, domains); err != nil {
			return err
		}
		if err := s.bumpRevision(ctx, tx, tenantID, now); err != nil {
			return err
		}
		result = &store.Policy{
			ID:        id,
			TenantID:  tenantID,
			ClientIP:  clientIP,
			Domains:   sortedCopy(domains),
			CreatedAt: createdAt,
			UpdatedAt: now,
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// MutatePolicyDomains applies an incremental add/remove to an existing policy.
// Removals are applied before additions so a domain present in both lists ends
// up present. The policy must already exist.
func (s *Store) MutatePolicyDomains(ctx context.Context, tenantID, clientIP string, add, remove []string) (*store.Policy, error) {
	var result *store.Policy
	err := s.withTx(ctx, func(tx *sql.Tx) error {
		now := time.Now().UTC()

		id, createdAt, err := s.policyRowTx(ctx, tx, tenantID, clientIP)
		if err != nil {
			return err
		}
		for _, domain := range remove {
			if _, err := s.txExec(ctx, tx, `DELETE FROM policy_domains WHERE policy_id = ? AND domain = ?`, id, domain); err != nil {
				return fmt.Errorf("sqlstore: remove domain %q: %w", domain, err)
			}
		}
		if err := s.insertDomains(ctx, tx, id, add); err != nil {
			return err
		}
		if _, err := s.txExec(ctx, tx, `UPDATE policies SET updated_at = ? WHERE id = ?`, toMicros(now), id); err != nil {
			return fmt.Errorf("sqlstore: touch policy %s: %w", clientIP, err)
		}
		if err := s.bumpRevision(ctx, tx, tenantID, now); err != nil {
			return err
		}

		domains, err := s.loadDomains(ctx, tx, id)
		if err != nil {
			return err
		}
		result = &store.Policy{
			ID:        id,
			TenantID:  tenantID,
			ClientIP:  clientIP,
			Domains:   domains,
			CreatedAt: createdAt,
			UpdatedAt: now,
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// DeletePolicy removes a policy and its domains.
func (s *Store) DeletePolicy(ctx context.Context, tenantID, clientIP string) error {
	return s.withTx(ctx, func(tx *sql.Tx) error {
		now := time.Now().UTC()
		res, err := s.txExec(ctx, tx, `DELETE FROM policies WHERE tenant_id = ? AND client_ip = ?`, tenantID, clientIP)
		if err != nil {
			return fmt.Errorf("sqlstore: delete policy %s: %w", clientIP, err)
		}
		if err := requireAffected(res, fmt.Sprintf("policy %s", clientIP)); err != nil {
			return err
		}
		return s.bumpRevision(ctx, tx, tenantID, now)
	})
}

// policyRowTx resolves a policy's ID and creation time inside a transaction.
func (s *Store) policyRowTx(ctx context.Context, tx *sql.Tx, tenantID, clientIP string) (string, time.Time, error) {
	const q = `SELECT id, created_at FROM policies WHERE tenant_id = ? AND client_ip = ?`
	var (
		id      string
		created int64
	)
	if err := s.txQueryRow(ctx, tx, q, tenantID, clientIP).Scan(&id, &created); err != nil {
		return "", time.Time{}, fmt.Errorf("sqlstore: policy %s: %w", clientIP, mapErr(err))
	}
	return id, fromMicros(created), nil
}

// insertDomains adds domains to a policy, ignoring duplicates.
func (s *Store) insertDomains(ctx context.Context, tx *sql.Tx, policyID string, domains []string) error {
	const q = `INSERT INTO policy_domains (policy_id, domain) VALUES (?, ?) ON CONFLICT DO NOTHING`
	for _, domain := range domains {
		if _, err := s.txExec(ctx, tx, q, policyID, domain); err != nil {
			return fmt.Errorf("sqlstore: insert domain %q: %w", domain, err)
		}
	}
	return nil
}

// loadDomains returns a policy's sorted domain list. tx may be nil to read
// outside a transaction.
func (s *Store) loadDomains(ctx context.Context, tx *sql.Tx, policyID string) ([]string, error) {
	const q = `SELECT domain FROM policy_domains WHERE policy_id = ? ORDER BY domain`

	var (
		rows *sql.Rows
		err  error
	)
	if tx != nil {
		rows, err = s.txQuery(ctx, tx, q, policyID)
	} else {
		rows, err = s.query(ctx, q, policyID)
	}
	if err != nil {
		return nil, fmt.Errorf("sqlstore: load domains: %w", err)
	}
	defer rows.Close()

	out := []string{}
	for rows.Next() {
		var domain string
		if err := rows.Scan(&domain); err != nil {
			return nil, fmt.Errorf("sqlstore: scan domain: %w", err)
		}
		out = append(out, domain)
	}
	return out, rows.Err()
}

func sortedCopy(in []string) []string {
	out := make([]string, len(in))
	copy(out, in)
	sort.Strings(out)
	return out
}
