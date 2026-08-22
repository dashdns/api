package policy

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
)

// Limits on a single policy. They exist to keep one bad admin call from
// producing a payload that every appliance in the fleet then has to download
// and diff every refresh interval.
const (
	MaxDomainLength      = 253
	MaxLabelLength       = 63
	MaxDomainsPerPolicy  = 4096
	MaxDomainsPerRequest = 4096
)

// NormalizeClientIP canonicalises a client IP for storage and for the dnsd
// payload.
//
// IPv4 only, on purpose: dnsd keys its ip_blocklist BPF map on a uint32 built
// from the four address octets and rejects anything without a 4-byte form
// (BlockDomainForIP in dnsd main.go). Accepting an IPv6 literal here would
// produce a policy that every appliance silently refuses to install, so it is
// rejected at the edge instead. IPv4-mapped IPv6 forms such as
// "::ffff:192.168.1.1" are rejected too -- dnsd never sees that shape, and
// accepting it would let the same host appear as two distinct policies.
func NormalizeClientIP(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", fmt.Errorf("ip must not be empty")
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return "", fmt.Errorf("%q is not a valid IP address", raw)
	}
	if addr.Zone() != "" {
		return "", fmt.Errorf("%q must not carry a zone identifier", raw)
	}
	if !addr.Is4() {
		return "", fmt.Errorf("%q is not IPv4; dnsd's per-IP blocklist is IPv4-only", raw)
	}
	return addr.String(), nil
}

// NormalizeDomain canonicalises a blocked domain.
//
// dnsd lowercases and prepends a dot before hashing ("."+domain in
// hashDomain), so the value stored here must be the bare, lowercase,
// dot-terminated-stripped hostname. Anything the appliance would hash
// differently than intended is rejected rather than silently mangled.
func NormalizeDomain(raw string) (string, error) {
	d := strings.ToLower(strings.TrimSpace(raw))
	d = strings.TrimSuffix(d, ".")

	switch {
	case d == "":
		return "", fmt.Errorf("domain must not be empty")
	case len(d) > MaxDomainLength:
		return "", fmt.Errorf("domain %q exceeds %d characters", raw, MaxDomainLength)
	case strings.Contains(d, "://"):
		return "", fmt.Errorf("domain %q must be a bare hostname, not a URL", raw)
	case strings.ContainsAny(d, "/?#@ \t"):
		return "", fmt.Errorf("domain %q must be a bare hostname with no path, port or whitespace", raw)
	case strings.Contains(d, "*"):
		return "", fmt.Errorf("domain %q must not contain wildcards; dnsd matches exact hashed names", raw)
	case strings.Contains(d, ".."):
		return "", fmt.Errorf("domain %q contains an empty label", raw)
	}

	for _, label := range strings.Split(d, ".") {
		if label == "" {
			return "", fmt.Errorf("domain %q contains an empty label", raw)
		}
		if len(label) > MaxLabelLength {
			return "", fmt.Errorf("domain %q has a label longer than %d characters", raw, MaxLabelLength)
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return "", fmt.Errorf("domain %q has a label starting or ending with '-'", raw)
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			isAllowed := (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_'
			if !isAllowed {
				if c >= 0x80 {
					return "", fmt.Errorf("domain %q is not ASCII; submit the punycode (xn--) form", raw)
				}
				return "", fmt.Errorf("domain %q contains an invalid character %q", raw, string(rune(c)))
			}
		}
	}
	return d, nil
}

// NormalizeDomains validates, lowercases, de-duplicates and sorts a domain
// list. The sort is what makes the served payload -- and therefore its ETag --
// stable across writes that only reorder the input.
func NormalizeDomains(raw []string) ([]string, error) {
	if len(raw) > MaxDomainsPerRequest {
		return nil, fmt.Errorf("at most %d domains may be submitted at once, got %d", MaxDomainsPerRequest, len(raw))
	}
	seen := make(map[string]struct{}, len(raw))
	out := make([]string, 0, len(raw))
	for _, r := range raw {
		d, err := NormalizeDomain(r)
		if err != nil {
			return nil, err
		}
		if _, dup := seen[d]; dup {
			continue
		}
		seen[d] = struct{}{}
		out = append(out, d)
	}
	sort.Strings(out)
	return out, nil
}
