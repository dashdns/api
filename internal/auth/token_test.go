package auth

import (
	"strings"
	"testing"
)

// TestMintSplitRoundTrip is the regression guard for the base64url separator
// bug: Mint encodes the secret with base64.RawURLEncoding, whose alphabet
// includes '_'. A Split that broke the token on every underscore rejected any
// token whose secret happened to contain one -- roughly half of them, at
// random. Minting enough tokens here makes that essentially certain to be hit.
func TestMintSplitRoundTrip(t *testing.T) {
	prefixes := []string{AppliancePrefix, SessionPrefix}
	for _, prefix := range prefixes {
		t.Run(prefix, func(t *testing.T) {
			withUnderscore := 0
			for i := 0; i < 200; i++ {
				token, err := Mint(prefix)
				if err != nil {
					t.Fatalf("Mint: %v", err)
				}

				id, secret, err := Split(prefix, token.Plaintext)
				if err != nil {
					t.Fatalf("Split(%q) failed: %v", token.Plaintext, err)
				}
				if id != token.ID {
					t.Fatalf("id = %q, want %q", id, token.ID)
				}
				if !VerifySecret(secret, token.Hash) {
					t.Fatalf("secret from %q does not verify against its own hash", token.Plaintext)
				}
				if strings.Contains(secret, "_") {
					withUnderscore++
				}
			}
			// Not an assertion about crypto, just proof the loop actually
			// exercised the case the bug was hiding in.
			if withUnderscore == 0 {
				t.Errorf("no minted secret contained '_' in 200 tries; the regression case was not exercised")
			}
		})
	}
}

// TestSplitRejectsWrongPlane pins the property that keeps the two credential
// planes from impersonating each other.
func TestSplitRejectsWrongPlane(t *testing.T) {
	token, err := Mint(AppliancePrefix)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if _, _, err := Split(SessionPrefix, token.Plaintext); err == nil {
		t.Error("an appliance token parsed as an admin session token")
	}
}

func TestSplitRejectsMalformed(t *testing.T) {
	cases := map[string]string{
		"empty":            "",
		"prefix only":      AppliancePrefix,
		"no secret":        AppliancePrefix + "_abc123",
		"empty id":         AppliancePrefix + "__secret",
		"empty secret":     AppliancePrefix + "_abc123_",
		"unknown prefix":   "nope_abc123_secret",
		"prefix substring": "dnsda_abc123_secret",
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if _, _, err := Split(AppliancePrefix, raw); err == nil {
				t.Errorf("Split(%q) succeeded, want ErrMalformedToken", raw)
			}
		})
	}
}

// TestSplitKeepsUnderscoresInSecret is the explicit, deterministic statement of
// the bug, independent of Mint's randomness.
func TestSplitKeepsUnderscoresInSecret(t *testing.T) {
	raw := AppliancePrefix + "_5e8b1c4a09f3d726_aB_cD-eF_gH"

	id, secret, err := Split(AppliancePrefix, raw)
	if err != nil {
		t.Fatalf("Split: %v", err)
	}
	if id != "5e8b1c4a09f3d726" {
		t.Errorf("id = %q, want 5e8b1c4a09f3d726", id)
	}
	if secret != "aB_cD-eF_gH" {
		t.Errorf("secret = %q, want aB_cD-eF_gH", secret)
	}
}

func TestPasswordHashing(t *testing.T) {
	const password = "correct-horse-battery-staple"

	hash, salt, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if len(hash) != pbkdf2KeyLength || len(salt) != saltLength {
		t.Fatalf("hash/salt lengths = %d/%d, want %d/%d", len(hash), len(salt), pbkdf2KeyLength, saltLength)
	}
	if !VerifyPassword(password, hash, salt) {
		t.Error("correct password did not verify")
	}
	if VerifyPassword("wrong-password", hash, salt) {
		t.Error("wrong password verified")
	}

	// The salt must be per-user, or identical passwords would share a hash.
	otherHash, otherSalt, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if string(salt) == string(otherSalt) {
		t.Error("two calls produced the same salt")
	}
	if string(hash) == string(otherHash) {
		t.Error("two calls produced the same hash")
	}
}

func TestBearerToken(t *testing.T) {
	cases := []struct {
		header string
		want   string
		ok     bool
	}{
		{"Bearer abc123", "abc123", true},
		{"bearer abc123", "abc123", true},  // RFC 7235: scheme is case-insensitive
		{"BEARER abc123", "abc123", true},
		{"Bearer  abc123 ", "abc123", true}, // surrounding space is trimmed
		{"", "", false},
		{"Bearer", "", false},
		{"Bearer ", "", false}, // the empty-variable case: `-H "Authorization: Bearer $TOKEN"`
		{"Basic abc123", "", false},
		{"abc123", "", false},
	}
	for _, c := range cases {
		got, ok := BearerToken(c.header)
		if ok != c.ok || got != c.want {
			t.Errorf("BearerToken(%q) = (%q, %v), want (%q, %v)", c.header, got, ok, c.want, c.ok)
		}
	}
}
