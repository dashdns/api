// Package idgen produces opaque, prefixed, collision-resistant identifiers.
package idgen

import (
	"crypto/rand"
	"encoding/hex"
)

// Resource prefixes. The prefix is part of the ID so a stray identifier in a
// log line or an API call is self-describing.
const (
	PrefixTenant    = "tnt"
	PrefixPolicy    = "pol"
	PrefixAppliance = "app"
	PrefixAdminUser = "usr"
)

// New returns prefix + "_" + 32 hex characters of cryptographic randomness.
// crypto/rand.Read is documented never to fail on any supported platform, so
// this cannot return an error.
func New(prefix string) string {
	var b [16]byte
	rand.Read(b[:]) //nolint:errcheck // documented to never fail
	return prefix + "_" + hex.EncodeToString(b[:])
}
