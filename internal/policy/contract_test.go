package policy_test

import (
	"encoding/json"
	"net/http"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/dashdns/api/internal/testenv"
)

// This file is the guard on the dnsd wire contract. Everything below is
// deliberately written against copies of dnsd's own code rather than against
// this repository's types: if pkg/dnsdcontract ever drifts from dnsd, these
// tests fail even though both sides still compile.

// dnsdIPBlocklistEntry and dnsdIPBlocklistResponse are copied verbatim from
// dnsd main.go (lines 116-132). Do not "clean up" or refactor them -- their
// value is being byte-identical to what the appliance actually compiles.
type dnsdIPBlocklistEntry struct {
	IP      string   `json:"ip"`
	Domains []string `json:"domains"`
}

type dnsdIPBlocklistResponse struct {
	Blocklist []dnsdIPBlocklistEntry `json:"blocklist"`
}

// hashDomain is copied verbatim from dnsd main.go. dnsd derives its BPF map key
// from this, so it is the ground truth for what a "domain" string must look
// like on the wire.
func hashDomain(domain string) uint32 {
	hash := uint32(5381)
	for _, c := range "." + strings.ToLower(domain) {
		hash = ((hash << 5) + hash) + uint32(c)
	}
	return hash
}

// TestPoliciesMatchesDNSDSchema is the primary contract test: the response must
// decode cleanly into dnsd's own struct definitions with every value intact.
func TestPoliciesMatchesDNSDSchema(t *testing.T) {
	env := testenv.New(t)
	env.SeedPolicy("192.168.1.100", "facebook.com", "instagram.com")
	env.SeedPolicy("192.168.1.101", "youtube.com")

	w := env.Appliance(http.MethodGet, "/api/policies", nil)
	env.RequireStatus(w, http.StatusOK)

	// Decoding with DisallowUnknownFields is stricter than dnsd itself, which
	// would silently ignore an added field. That strictness is the point: it
	// catches a field we added here before it ships to appliances.
	dec := json.NewDecoder(strings.NewReader(w.Body.String()))
	dec.DisallowUnknownFields()

	var got dnsdIPBlocklistResponse
	if err := dec.Decode(&got); err != nil {
		t.Fatalf("response does not decode into dnsd's IPBlocklistResponse: %v\nbody: %s", err, w.Body.String())
	}

	want := dnsdIPBlocklistResponse{
		Blocklist: []dnsdIPBlocklistEntry{
			{IP: "192.168.1.100", Domains: []string{"facebook.com", "instagram.com"}},
			{IP: "192.168.1.101", Domains: []string{"youtube.com"}},
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("decoded payload mismatch\n got: %+v\nwant: %+v", got, want)
	}
}

// TestPoliciesJSONHasExactlyTheContractFields inspects the raw JSON rather than
// the decoded struct. A missing field would be caught by the decode test above;
// an *extra* field would not, because dnsd ignores unknown keys and would keep
// working right up until someone relies on it.
func TestPoliciesJSONHasExactlyTheContractFields(t *testing.T) {
	env := testenv.New(t)
	env.SeedPolicy("10.0.0.1", "example.com")

	w := env.Appliance(http.MethodGet, "/api/policies", nil)
	env.RequireStatus(w, http.StatusOK)

	var top map[string]json.RawMessage
	env.DecodeInto(w, &top)
	if keys := sortedKeys(top); !reflect.DeepEqual(keys, []string{"blocklist"}) {
		t.Fatalf("top-level keys = %v, want [blocklist]", keys)
	}

	var entries []map[string]json.RawMessage
	if err := json.Unmarshal(top["blocklist"], &entries); err != nil {
		t.Fatalf("blocklist is not an array of objects: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("len(blocklist) = %d, want 1", len(entries))
	}
	if keys := sortedKeys(entries[0]); !reflect.DeepEqual(keys, []string{"domains", "ip"}) {
		t.Fatalf("entry keys = %v, want [domains ip]", keys)
	}

	// Types matter as much as names: dnsd would fail to unmarshal a number into
	// a string, or a string into []string.
	var ip string
	if err := json.Unmarshal(entries[0]["ip"], &ip); err != nil {
		t.Errorf("ip is not a JSON string: %v", err)
	}
	var domains []string
	if err := json.Unmarshal(entries[0]["domains"], &domains); err != nil {
		t.Errorf("domains is not a JSON array of strings: %v", err)
	}
}

// TestPoliciesEmptyIsArrayNotNull pins the empty case. dnsd tolerates null
// (ranging over a nil slice is a no-op) but an explicit [] keeps the payload
// unambiguous, and a nil slice here would be an easy regression to introduce.
func TestPoliciesEmptyIsArrayNotNull(t *testing.T) {
	env := testenv.New(t)

	w := env.Appliance(http.MethodGet, "/api/policies", nil)
	env.RequireStatus(w, http.StatusOK)

	if got := strings.TrimSpace(w.Body.String()); got != `{"blocklist":[]}` {
		t.Errorf("empty payload = %s, want {\"blocklist\":[]}", got)
	}
}

// TestPoliciesOmitsDomainlessEntries covers a policy whose domains were all
// removed. Such an entry produces no BPF map entries on the appliance, so
// shipping it is pure payload weight.
func TestPoliciesOmitsDomainlessEntries(t *testing.T) {
	env := testenv.New(t)
	env.SeedPolicy("10.0.0.1", "example.com")
	env.SeedPolicy("10.0.0.2", "other.com")

	// Empty 10.0.0.2 out via PUT.
	w := env.Admin(http.MethodPut, "/api/admin/policies/10.0.0.2", map[string]any{"domains": []string{}})
	env.RequireStatus(w, http.StatusOK)

	w = env.Appliance(http.MethodGet, "/api/policies", nil)
	env.RequireStatus(w, http.StatusOK)

	var resp dnsdIPBlocklistResponse
	env.DecodeInto(w, &resp)
	if len(resp.Blocklist) != 1 || resp.Blocklist[0].IP != "10.0.0.1" {
		t.Errorf("blocklist = %+v, want only 10.0.0.1", resp.Blocklist)
	}

	// It must still be visible to operators.
	w = env.Admin(http.MethodGet, "/api/admin/policies/10.0.0.2", nil)
	env.RequireStatus(w, http.StatusOK)
}

// TestPoliciesPayloadIsDeterministic is what makes the ETag trustworthy: the
// same state must always produce the same bytes, regardless of insertion order.
func TestPoliciesPayloadIsDeterministic(t *testing.T) {
	first := renderWith(t, [][]string{
		{"10.0.0.2", "zebra.com", "alpha.com"},
		{"10.0.0.1", "mid.com"},
	})
	second := renderWith(t, [][]string{
		{"10.0.0.1", "mid.com"},
		{"10.0.0.2", "alpha.com", "zebra.com"},
	})

	if first != second {
		t.Errorf("payload depends on insertion order:\n first: %s\nsecond: %s", first, second)
	}
	if !strings.Contains(first, `{"ip":"10.0.0.1"`) ||
		strings.Index(first, `"10.0.0.1"`) > strings.Index(first, `"10.0.0.2"`) {
		t.Errorf("entries are not sorted by IP: %s", first)
	}
	if strings.Index(first, "alpha.com") > strings.Index(first, "zebra.com") {
		t.Errorf("domains are not sorted within an entry: %s", first)
	}
}

func renderWith(t *testing.T, policies [][]string) string {
	t.Helper()
	env := testenv.New(t)
	for _, p := range policies {
		env.SeedPolicy(p[0], p[1:]...)
	}
	w := env.Appliance(http.MethodGet, "/api/policies", nil)
	env.RequireStatus(w, http.StatusOK)
	return strings.TrimSpace(w.Body.String())
}

// TestPayloadDrivesDNSDDiffLogic replays dnsd's fetchAndUpdateIPBlocklist diff
// against two consecutive snapshots and asserts the appliance would install and
// withdraw exactly the rules we intend. This is the closest thing to an
// end-to-end check without running the eBPF datapath.
func TestPayloadDrivesDNSDDiffLogic(t *testing.T) {
	env := testenv.New(t)
	env.SeedPolicy("192.168.1.100", "facebook.com", "instagram.com")

	before := fetchAsDNSD(t, env)

	// Swap instagram.com for tiktok.com and add a second client.
	w := env.Admin(http.MethodPatch, "/api/admin/policies/192.168.1.100", map[string]any{
		"add":    []string{"tiktok.com"},
		"remove": []string{"instagram.com"},
	})
	env.RequireStatus(w, http.StatusOK)
	env.SeedPolicy("192.168.1.101", "youtube.com")

	after := fetchAsDNSD(t, env)

	added, removed := dnsdDiff(before, after)

	wantAdded := []string{"192.168.1.100|tiktok.com", "192.168.1.101|youtube.com"}
	wantRemoved := []string{"192.168.1.100|instagram.com"}
	if !reflect.DeepEqual(added, wantAdded) {
		t.Errorf("dnsd would add %v, want %v", added, wantAdded)
	}
	if !reflect.DeepEqual(removed, wantRemoved) {
		t.Errorf("dnsd would remove %v, want %v", removed, wantRemoved)
	}

	// Every domain we ship must survive dnsd's hashing unchanged: hashing the
	// served string and hashing its lowercase form must agree, which is only
	// true if we already normalised it.
	for _, entry := range after {
		for _, domain := range entry.Domains {
			if hashDomain(domain) != hashDomain(strings.ToLower(domain)) {
				t.Errorf("domain %q is not lowercase; dnsd would hash it differently than intended", domain)
			}
			if strings.HasSuffix(domain, ".") {
				t.Errorf("domain %q has a trailing dot; dnsd prepends '.' and would hash %q", domain, "."+domain)
			}
		}
	}
}

func fetchAsDNSD(t *testing.T, env *testenv.Env) []dnsdIPBlocklistEntry {
	t.Helper()
	w := env.Appliance(http.MethodGet, "/api/policies", nil)
	env.RequireStatus(w, http.StatusOK)

	var resp dnsdIPBlocklistResponse
	env.DecodeInto(w, &resp)
	return resp.Blocklist
}

// dnsdDiff reproduces the set-building and diffing in dnsd's
// fetchAndUpdateIPBlocklist and reports the (IP, domain) rules it would add and
// remove, each sorted for comparison.
func dnsdDiff(current, next []dnsdIPBlocklistEntry) (added, removed []string) {
	toSet := func(entries []dnsdIPBlocklistEntry) map[string]map[string]bool {
		set := make(map[string]map[string]bool)
		for _, entry := range entries {
			if set[entry.IP] == nil {
				set[entry.IP] = make(map[string]bool)
			}
			for _, domain := range entry.Domains {
				set[entry.IP][strings.ToLower(domain)] = true
			}
		}
		return set
	}

	currentSet, newSet := toSet(current), toSet(next)

	for ip, domains := range currentSet {
		for domain := range domains {
			if newSet[ip] == nil || !newSet[ip][domain] {
				removed = append(removed, ip+"|"+domain)
			}
		}
	}
	for _, entry := range next {
		for _, domain := range entry.Domains {
			domain = strings.ToLower(domain)
			if currentSet[entry.IP] == nil || !currentSet[entry.IP][domain] {
				added = append(added, entry.IP+"|"+domain)
			}
		}
	}

	sort.Strings(added)
	sort.Strings(removed)
	return added, removed
}

func sortedKeys(m map[string]json.RawMessage) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
