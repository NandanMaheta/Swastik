package firebaseauth_test

// Test helper of this package: mints RS256 Firebase-style ID tokens and serves their public key as
// a JWKS from a local httptest server (no network, no real Google). It lives here, not in otptest,
// so no platform test imports a business module (depguard platform-does-not-know-otp has no
// test-file exemption). The otp tests keep their own copy in otp/otptest.

import (
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// Claims are the Firebase ID token claims a test wants to mint. Fields are written as given (an
// empty Subject mints an empty "sub"); only Issuer and Audience fall back to the test project's.
type Claims struct {
	Subject, PhoneNumber, SignInProvider string
	AuthTime, IssuedAt, Expires          time.Time
	Issuer, Audience                     string // empty = the test project's
}

// Minter mints RS256 Firebase-style ID tokens and serves their public key as a JWKS.
type Minter struct {
	ProjectID string
	JWKSURL   string
	KID       string

	key   *rsa.PrivateKey
	other *rsa.PrivateKey // never published
}

// NewMinter starts a local JWKS server (closed with t.Cleanup) publishing one key.
func NewMinter(t testing.TB, projectID string) *Minter {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("firebaseauth_test: generate key: %v", err)
	}
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("firebaseauth_test: generate key: %v", err)
	}
	m := &Minter{ProjectID: projectID, KID: "test-kid-1", key: key, other: other}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "public, max-age=3600")
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]any{{
			"kty": "RSA", "use": "sig", "alg": "RS256", "kid": m.KID,
			"n": b64(key.N.Bytes()),
			"e": b64(big.NewInt(int64(key.E)).Bytes()),
		}}})
	}))
	t.Cleanup(srv.Close)
	m.JWKSURL = srv.URL
	return m
}

// Valid returns claims of a fresh phone sign-in at now for the test project: signed in one minute
// ago, expiring in one hour.
func (m *Minter) Valid(now time.Time) Claims {
	return Claims{
		Subject: "fb-user-1", PhoneNumber: "+919812345678", SignInProvider: "phone",
		AuthTime: now.Add(-time.Minute), IssuedAt: now.Add(-time.Minute), Expires: now.Add(time.Hour),
	}
}

// MapOf returns the JWT payload of c, so a test can edit or delete a claim and use Raw.
func (m *Minter) MapOf(c Claims) map[string]any {
	iss, aud := c.Issuer, c.Audience
	if iss == "" {
		iss = "https://securetoken.google.com/" + m.ProjectID
	}
	if aud == "" {
		aud = m.ProjectID
	}
	out := map[string]any{
		"iss": iss, "aud": aud, "sub": c.Subject,
		"iat": c.IssuedAt.Unix(), "exp": c.Expires.Unix(), "auth_time": c.AuthTime.Unix(),
		"firebase": map[string]any{"sign_in_provider": c.SignInProvider, "identities": map[string]any{}},
	}
	if c.PhoneNumber != "" {
		out["phone_number"] = c.PhoneNumber
	}
	return out
}

// Token signs c with the published key (RS256, the published kid).
func (m *Minter) Token(t testing.TB, c Claims) string {
	t.Helper()
	return m.Raw(t, "RS256", nil, m.MapOf(c))
}

// ForeignToken signs c with a key that is NOT published, under the published kid.
func (m *Minter) ForeignToken(t testing.TB, c Claims) string {
	t.Helper()
	return m.sign(t, m.other, map[string]any{"alg": "RS256", "typ": "JWT", "kid": m.KID}, m.MapOf(c))
}

// Raw builds a token from an explicit algorithm, header overrides and payload. alg is "RS256"
// (published key), "HS256" (HMAC with a fixed secret) or "none" (empty signature). The header
// starts as {alg, typ JWT, kid: the published kid}; overrides replace or, with a nil value,
// delete entries.
func (m *Minter) Raw(t testing.TB, alg string, header, payload map[string]any) string {
	t.Helper()
	h := map[string]any{"alg": alg, "typ": "JWT", "kid": m.KID}
	for k, v := range header {
		if v == nil {
			delete(h, k)
			continue
		}
		h[k] = v
	}
	switch alg {
	case "RS256":
		return m.sign(t, m.key, h, payload)
	case "HS256":
		input := enc(t, h) + "." + enc(t, payload)
		mac := hmac.New(sha256.New, []byte("not-a-google-key"))
		mac.Write([]byte(input))
		return input + "." + b64(mac.Sum(nil))
	case "none":
		return enc(t, h) + "." + enc(t, payload) + "."
	default:
		t.Fatalf("firebaseauth_test: unsupported alg %q", alg)
		return ""
	}
}

func (m *Minter) sign(t testing.TB, key *rsa.PrivateKey, header, payload map[string]any) string {
	t.Helper()
	input := enc(t, header) + "." + enc(t, payload)
	sum := sha256.Sum256([]byte(input))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatalf("firebaseauth_test: sign: %v", err)
	}
	return input + "." + b64(sig)
}

func enc(t testing.TB, v any) string {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("firebaseauth_test: marshal: %v", err)
	}
	return b64(raw)
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
