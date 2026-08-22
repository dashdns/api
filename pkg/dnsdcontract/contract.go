// Package dnsdcontract holds the wire contract shared with the dnsd eBPF DNS
// proxy (github.com/dashdns/dnsd).
//
// dnsd fetches this payload with the -ip-blocklist-url flag and decodes it in
// fetchAndUpdateIPBlocklist (dnsd main.go). The struct definitions below are a
// byte-for-byte mirror of dnsd's own IPBlocklistEntry / IPBlocklistResponse:
//
//	type IPBlocklistEntry struct {
//		IP      string   `json:"ip"`
//		Domains []string `json:"domains"`
//	}
//
//	type IPBlocklistResponse struct {
//		Blocklist []IPBlocklistEntry `json:"blocklist"`
//	}
//
// This package is deliberately outside internal/ so dnsd (or any other
// appliance-side client) can import it directly instead of re-declaring the
// types. Nothing here may gain a field, lose a field, or change a json tag
// without a matching change on the dnsd side.
package dnsdcontract

// Entry is one client-IP -> blocked-domains mapping.
//
// dnsd keys its ip_blocklist BPF map on (client IPv4, djb2(domain)), so IP must
// be a plain dotted-quad IPv4 literal and Domains must be bare hostnames with
// no scheme, port, or trailing dot.
type Entry struct {
	IP      string   `json:"ip"`
	Domains []string `json:"domains"`
}

// Response is the top-level document served by GET /api/policies.
type Response struct {
	Blocklist []Entry `json:"blocklist"`
}

// NewResponse returns a Response whose Blocklist is guaranteed non-nil so that
// an empty policy set marshals to {"blocklist":[]} rather than
// {"blocklist":null}. dnsd tolerates null (ranging over a nil slice is a no-op)
// but an explicit empty array keeps the payload unambiguous for every consumer.
func NewResponse(entries []Entry) Response {
	if entries == nil {
		entries = []Entry{}
	}
	return Response{Blocklist: entries}
}
