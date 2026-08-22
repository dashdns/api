package policy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/dashdns/api/internal/metrics"
	"github.com/dashdns/api/internal/store"
	"github.com/dashdns/api/pkg/dnsdcontract"
)

// Snapshot is a rendered, cacheable /api/policies payload for one tenant.
type Snapshot struct {
	// Body is the exact JSON dnsd receives.
	Body []byte
	// ETag is the quoted strong validator derived from Body.
	ETag string
	// LastModified is the tenant's last policy write, second-resolution. Zero
	// when the tenant has never had a policy written.
	LastModified time.Time
	// Revision is the store revision this snapshot was built from.
	Revision int64
	// Entries and Domains are counts for metrics.
	Entries int
	Domains int
}

// Service renders and caches the appliance-facing blocklist.
//
// dnsd polls on a fixed interval (-ip-blocklist-interval, 5m by default) and
// every appliance in a tenant asks for the same bytes. Rebuilding and rehashing
// the payload per poll would make the controller's load scale with fleet size
// instead of with change rate, so a snapshot is kept per tenant and reused
// until the tenant's revision counter moves.
type Service struct {
	policies store.PolicyRepository

	mu    sync.RWMutex
	cache map[string]*Snapshot

	// build serialises rebuilds so a burst of polls after a write does not
	// produce one full table scan per request.
	build sync.Mutex
}

// NewService returns a Service backed by repo.
func NewService(repo store.PolicyRepository) *Service {
	return &Service{
		policies: repo,
		cache:    make(map[string]*Snapshot),
	}
}

// Snapshot returns the tenant's current payload, rebuilding it only when the
// store's revision has moved past the cached one.
func (s *Service) Snapshot(ctx context.Context, tenantID string) (*Snapshot, error) {
	rev, err := s.policies.Revision(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("policy: read revision: %w", err)
	}

	s.mu.RLock()
	cached, ok := s.cache[tenantID]
	s.mu.RUnlock()
	if ok && cached.Revision == rev.Value {
		return cached, nil
	}

	s.build.Lock()
	defer s.build.Unlock()

	// Another goroutine may have rebuilt while we waited for the lock.
	s.mu.RLock()
	cached, ok = s.cache[tenantID]
	s.mu.RUnlock()
	if ok && cached.Revision == rev.Value {
		return cached, nil
	}

	snapshot, err := s.render(ctx, tenantID, rev)
	if err != nil {
		return nil, err
	}

	s.mu.Lock()
	s.cache[tenantID] = snapshot
	s.mu.Unlock()

	metrics.PolicySnapshotBuilds.WithLabelValues(tenantID).Inc()
	metrics.PoliciesTotal.WithLabelValues(tenantID).Set(float64(snapshot.Entries))
	metrics.PolicyDomainsTotal.WithLabelValues(tenantID).Set(float64(snapshot.Domains))
	metrics.PolicyRevision.WithLabelValues(tenantID).Set(float64(snapshot.Revision))

	return snapshot, nil
}

// Invalidate drops a tenant's cached snapshot. Writes go through the store,
// which bumps the revision, so this is only an optimisation to avoid one stale
// read -- correctness does not depend on it.
func (s *Service) Invalidate(tenantID string) {
	s.mu.Lock()
	delete(s.cache, tenantID)
	s.mu.Unlock()
}

// render builds the payload from the store.
func (s *Service) render(ctx context.Context, tenantID string, rev store.Revision) (*Snapshot, error) {
	policies, err := s.policies.ListPolicies(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("policy: list policies: %w", err)
	}

	entries := make([]dnsdcontract.Entry, 0, len(policies))
	domainCount := 0
	for _, p := range policies {
		// A policy with no domains produces no BPF map entries on the appliance
		// side, so shipping it would be pure payload weight. It stays visible
		// through the admin API.
		if len(p.Domains) == 0 {
			continue
		}
		domains := make([]string, len(p.Domains))
		copy(domains, p.Domains)
		sort.Strings(domains)
		domainCount += len(domains)
		entries = append(entries, dnsdcontract.Entry{IP: p.ClientIP, Domains: domains})
	}
	// ListPolicies already orders by client_ip, but the payload hash is the
	// ETag, so the ordering is re-established here rather than trusted.
	sort.Slice(entries, func(i, j int) bool { return entries[i].IP < entries[j].IP })

	body, err := json.Marshal(dnsdcontract.NewResponse(entries))
	if err != nil {
		return nil, fmt.Errorf("policy: marshal blocklist: %w", err)
	}

	sum := sha256.Sum256(body)
	return &Snapshot{
		Body:         body,
		ETag:         `"` + hex.EncodeToString(sum[:16]) + `"`,
		LastModified: rev.UpdatedAt.Truncate(time.Second),
		Revision:     rev.Value,
		Entries:      len(entries),
		Domains:      domainCount,
	}, nil
}
