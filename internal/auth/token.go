// Package auth implements the two independent credential planes of
// policy-controller.
//
//   - Appliance tokens authenticate dnsd instances against GET /api/policies.
//     They are read-only, long-lived, minted per appliance and revocable.
//   - Admin sessions authenticate humans against /api/admin/*. They are minted
//     from a username/password login and expire.
//
// The two are deliberately unforgeable as each other: they carry distinct
// prefixes, live in distinct tables, and each middleware only ever consults its
// own plane. An appliance token presented to an admin route fails, and vice
// versa, even before any hash comparison happens.
package auth

import (
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// Token prefixes. The prefix is both a namespace and a fast reject: a token
// that does not start with the expected prefix never reaches the database.
const (
	AppliancePrefix = "dnsdap"
	SessionPrefix   = "dnsdsn"
)

// ErrMalformedToken is returned when a bearer value is not a well-formed token
// of the expected kind.
var ErrMalformedToken = errors.New("auth: malformed token")

// Token is a freshly minted credential. Plaintext is shown to the caller
// exactly once; only ID and Hash are persisted.
type Token struct {
	// Plaintext is the full "<prefix>_<id>_<secret>" value.
	Plaintext string
	// ID is the public half, used to look the credential up.
	ID string
	// Hash is SHA-256 of the secret half.
	//
	// A plain hash is correct here, unlike for passwords: the secret is 256
	// bits of CSPRNG output, so it is not brute-forceable and does not need a
	// slow KDF. That matters because this hash is verified on every dnsd poll.
	Hash []byte
}

// Mint generates a new token of the given kind.
func Mint(prefix string) (Token, error) {
	var idBytes [8]byte
	if _, err := rand.Read(idBytes[:]); err != nil {
		return Token{}, fmt.Errorf("auth: generate token id: %w", err)
	}
	var secretBytes [32]byte
	if _, err := rand.Read(secretBytes[:]); err != nil {
		return Token{}, fmt.Errorf("auth: generate token secret: %w", err)
	}

	id := hex.EncodeToString(idBytes[:])
	secret := base64.RawURLEncoding.EncodeToString(secretBytes[:])
	return Token{
		Plaintext: prefix + "_" + id + "_" + secret,
		ID:        id,
		Hash:      HashSecret(secret),
	}, nil
}

// Split parses a token of the expected kind into its public ID and secret.
func Split(prefix, raw string) (id, secret string, err error) {
	parts := strings.Split(strings.TrimSpace(raw), "_")
	if len(parts) != 3 || parts[0] != prefix || parts[1] == "" || parts[2] == "" {
		return "", "", ErrMalformedToken
	}
	return parts[1], parts[2], nil
}

// HashSecret returns the SHA-256 of a token secret.
func HashSecret(secret string) []byte {
	sum := sha256.Sum256([]byte(secret))
	return sum[:]
}

// VerifySecret compares a presented secret against a stored hash in constant
// time.
func VerifySecret(secret string, stored []byte) bool {
	return hmac.Equal(HashSecret(secret), stored)
}

// Password hashing parameters. PBKDF2-HMAC-SHA256 at OWASP's 2023 recommended
// iteration count, from the standard library (crypto/pbkdf2, Go 1.24+), so the
// binary stays dependency-free on the crypto side.
const (
	pbkdf2Iterations = 210_000
	pbkdf2KeyLength  = 32
	saltLength       = 16
)

// HashPassword derives a verifier for a human password.
func HashPassword(password string) (hash, salt []byte, err error) {
	salt = make([]byte, saltLength)
	if _, err := rand.Read(salt); err != nil {
		return nil, nil, fmt.Errorf("auth: generate salt: %w", err)
	}
	hash, err = pbkdf2.Key(sha256.New, password, salt, pbkdf2Iterations, pbkdf2KeyLength)
	if err != nil {
		return nil, nil, fmt.Errorf("auth: derive password hash: %w", err)
	}
	return hash, salt, nil
}

// VerifyPassword checks a password against a stored hash and salt in constant
// time.
func VerifyPassword(password string, hash, salt []byte) bool {
	derived, err := pbkdf2.Key(sha256.New, password, salt, pbkdf2Iterations, pbkdf2KeyLength)
	if err != nil {
		return false
	}
	return hmac.Equal(derived, hash)
}

// BearerToken extracts the credential from an "Authorization: Bearer <token>"
// header value. The scheme match is case-insensitive per RFC 7235.
func BearerToken(header string) (string, bool) {
	const scheme = "bearer "
	if len(header) <= len(scheme) || !strings.EqualFold(header[:len(scheme)], scheme) {
		return "", false
	}
	token := strings.TrimSpace(header[len(scheme):])
	if token == "" {
		return "", false
	}
	return token, true
}
