package httpx

import (
	"net/http"
	"strings"
	"time"
)

// CacheValidators are the freshness signals for a cacheable response.
type CacheValidators struct {
	// ETag is the full header value including quotes, e.g. `"a1b2c3"`.
	ETag string
	// LastModified is second-resolution; the zero value omits the header.
	LastModified time.Time
	// CacheControl defaults to "private, no-cache" when empty: the response may
	// be stored but must be revalidated, which is exactly the behaviour a
	// polling client with a refresh interval wants.
	CacheControl string
}

// WriteValidators sets the caching headers on w.
func WriteValidators(w http.ResponseWriter, v CacheValidators) {
	h := w.Header()
	if v.ETag != "" {
		h.Set("ETag", v.ETag)
	}
	if !v.LastModified.IsZero() {
		h.Set("Last-Modified", v.LastModified.UTC().Format(http.TimeFormat))
	}
	cc := v.CacheControl
	if cc == "" {
		cc = "private, no-cache"
	}
	h.Set("Cache-Control", cc)
	h.Add("Vary", "Authorization")
}

// NotModified reports whether the request's preconditions are satisfied by v
// and, if so, writes a complete 304 response.
//
// Precedence follows RFC 9110 §13.1.3: when If-None-Match is present,
// If-Modified-Since is ignored entirely.
func NotModified(w http.ResponseWriter, r *http.Request, v CacheValidators) bool {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return false
	}

	fresh := false
	if inm := r.Header.Get("If-None-Match"); inm != "" {
		fresh = etagMatches(inm, v.ETag)
	} else if ims := r.Header.Get("If-Modified-Since"); ims != "" && !v.LastModified.IsZero() {
		if t, err := http.ParseTime(ims); err == nil {
			// Last-Modified has one-second resolution, so compare truncated.
			fresh = !v.LastModified.Truncate(time.Second).After(t.Truncate(time.Second))
		}
	}
	if !fresh {
		return false
	}

	WriteValidators(w, v)
	// A 304 must not carry a body or entity headers that describe one.
	h := w.Header()
	h.Del("Content-Type")
	h.Del("Content-Length")
	w.WriteHeader(http.StatusNotModified)
	return true
}

// etagMatches implements the weak comparison used for If-None-Match.
func etagMatches(header, etag string) bool {
	header = strings.TrimSpace(header)
	if header == "*" {
		return etag != ""
	}
	if etag == "" {
		return false
	}
	want := strings.TrimPrefix(etag, "W/")
	for _, candidate := range strings.Split(header, ",") {
		candidate = strings.TrimSpace(candidate)
		if candidate == "" {
			continue
		}
		if strings.TrimPrefix(candidate, "W/") == want {
			return true
		}
	}
	return false
}
