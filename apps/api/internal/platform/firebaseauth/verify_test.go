// Tests for the Firebase phone sign-in ID token verifier (feature 004, S02; BR-CLI-04 mobile proof,
// D-04). Offline: tokens are minted with a local RSA key and served as a JWKS by an httptest
// server (otptest.Minter). The clock is injected, and set far from the real time so a verifier that
// reads time.Now() fails these tests.
//
// Contract (go-module-api.md section 4): RS256 only; kid must be in the key set; iss =
// https://securetoken.google.com/<project>; aud = project; exp > now; sub non-empty; iat <= now+30 s.
// Verify returns the claims (sub, phone_number, firebase.sign_in_provider, auth_time, iat); the
// caller (otp) decides what they mean. Every token failure is ErrInvalid; an empty project id is
// Disabled(), which always answers ErrDisabled. Errors never echo the token.
package firebaseauth_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/NandanMaheta/swastik/apps/api/internal/otp/otptest"
	"github.com/NandanMaheta/swastik/apps/api/internal/platform/firebaseauth"
)

const project = "swastik-test"

// now is far in the past of the real clock on purpose.
var now = time.Date(2026, time.November, 13, 5, 0, 0, 0, time.UTC)

func clock() time.Time { return now }

func newVerifier(t *testing.T, m *otptest.Minter) firebaseauth.Verifier {
	t.Helper()
	return firebaseauth.New(t.Context(), project, clock, firebaseauth.WithJWKSURL(m.JWKSURL))
}

func TestVerify_BR_CLI_04_AcceptsAFreshPhoneSignIn(t *testing.T) {
	m := otptest.NewMinter(t, project)
	c := m.Valid(now)
	c.Subject, c.PhoneNumber = "fb-uid-77", "+919812345678"
	c.AuthTime, c.IssuedAt = now.Add(-3*time.Minute).Truncate(time.Second), now.Add(-2*time.Minute).Truncate(time.Second)

	p, err := newVerifier(t, m).Verify(t.Context(), m.Token(t, c))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if p.Subject != "fb-uid-77" || p.PhoneNumber != "+919812345678" || p.SignInProvider != "phone" {
		t.Errorf("proof = %+v, want sub fb-uid-77, +919812345678, provider phone", p)
	}
	if !p.AuthTime.Equal(c.AuthTime) || !p.IssuedAt.Equal(c.IssuedAt) {
		t.Errorf("times = auth %v iat %v, want %v / %v", p.AuthTime, p.IssuedAt, c.AuthTime, c.IssuedAt)
	}
}

// The verifier reports another provider as it is; refusing it is otp's job (D-04), not the token check.
func TestVerify_BR_CLI_04_ReportsTheSignInProviderWithoutJudgingIt(t *testing.T) {
	m := otptest.NewMinter(t, project)
	c := m.Valid(now)
	c.SignInProvider = "password"
	p, err := newVerifier(t, m).Verify(t.Context(), m.Token(t, c))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if p.SignInProvider != "password" {
		t.Errorf("SignInProvider = %q, want password", p.SignInProvider)
	}
}

func TestVerify_BR_CLI_04_RejectsEveryInvalidToken(t *testing.T) {
	m := otptest.NewMinter(t, project)
	v := newVerifier(t, m)
	valid := m.Valid(now)

	mod := func(f func(*otptest.Claims)) string {
		c := valid
		f(&c)
		return m.Token(t, c)
	}
	payload := func(f func(map[string]any)) map[string]any {
		p := m.MapOf(valid)
		f(p)
		return p
	}

	tests := []struct {
		name  string
		token string
	}{
		{"issuer of another project", mod(func(c *otptest.Claims) { c.Issuer = "https://securetoken.google.com/other-project" })},
		{"issuer is not Firebase", mod(func(c *otptest.Claims) { c.Issuer = "https://accounts.google.com" })},
		{"audience of another project", mod(func(c *otptest.Claims) { c.Audience = "other-project" })},
		{"expired one second ago", mod(func(c *otptest.Claims) { c.Expires = now.Add(-time.Second) })},
		{"expires exactly now", mod(func(c *otptest.Claims) { c.Expires = now })},
		{"issued 31 s in the future", mod(func(c *otptest.Claims) { c.IssuedAt = now.Add(31 * time.Second) })},
		{"empty subject", mod(func(c *otptest.Claims) { c.Subject = "" })},
		{"missing subject", m.Raw(t, "RS256", nil, payload(func(p map[string]any) { delete(p, "sub") }))},
		{"missing audience", m.Raw(t, "RS256", nil, payload(func(p map[string]any) { delete(p, "aud") }))},
		{"missing expiry", m.Raw(t, "RS256", nil, payload(func(p map[string]any) { delete(p, "exp") }))},
		{"signed by an unpublished key under a published kid", m.ForeignToken(t, valid)},
		{"unknown kid", m.Raw(t, "RS256", map[string]any{"kid": "no-such-kid"}, m.MapOf(valid))},
		{"missing kid", m.Raw(t, "RS256", map[string]any{"kid": nil}, m.MapOf(valid))},
		{"alg HS256", m.Raw(t, "HS256", nil, m.MapOf(valid))},
		{"alg none", m.Raw(t, "none", nil, m.MapOf(valid))},
		{"empty token", ""},
		{"not a JWT", "not-a-token"},
		{"two segments", "aaa.bbb"},
		{"garbage segments", "!!!.@@@.###"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := v.Verify(t.Context(), tt.token)
			if !errors.Is(err, firebaseauth.ErrInvalid) {
				t.Fatalf("error = %v, want ErrInvalid", err)
			}
			if errors.Is(err, firebaseauth.ErrDisabled) {
				t.Errorf("a bad token must not look like a disabled verifier")
			}
			if p != (firebaseauth.Proof{}) {
				t.Errorf("proof = %+v, want the zero Proof on failure", p)
			}
			if tt.token != "" && len(tt.token) > 10 && strings.Contains(err.Error(), tt.token) {
				t.Errorf("error echoes the token")
			}
		})
	}
}

// Boundaries are inclusive/exclusive exactly as the contract says (SC-001): exp > now, iat <= now+30 s.
func TestVerify_BR_CLI_04_TimeBoundaries(t *testing.T) {
	m := otptest.NewMinter(t, project)
	v := newVerifier(t, m)
	tests := []struct {
		name    string
		edit    func(*otptest.Claims)
		wantErr bool
	}{
		{"expires in one second", func(c *otptest.Claims) { c.Expires = now.Add(time.Second) }, false},
		{"issued exactly 30 s ahead", func(c *otptest.Claims) { c.IssuedAt = now.Add(30 * time.Second) }, false},
		{"issued 31 s ahead", func(c *otptest.Claims) { c.IssuedAt = now.Add(31 * time.Second) }, true},
		{"expired exactly now", func(c *otptest.Claims) { c.Expires = now }, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := m.Valid(now)
			tt.edit(&c)
			_, err := v.Verify(t.Context(), m.Token(t, c))
			if (err != nil) != tt.wantErr {
				t.Fatalf("error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr && !errors.Is(err, firebaseauth.ErrInvalid) {
				t.Errorf("error = %v, want ErrInvalid", err)
			}
		})
	}
}

// The verifier must use the injected clock, not the real one.
func TestVerify_BR_CLI_04_UsesTheInjectedClock(t *testing.T) {
	m := otptest.NewMinter(t, project)
	c := m.Valid(now)
	tok := m.Token(t, c)
	v := newVerifier(t, m)
	if _, err := v.Verify(t.Context(), tok); err != nil {
		t.Fatalf("at the minting time: %v", err)
	}
	later := now.Add(2 * time.Hour)
	vLater := firebaseauth.New(t.Context(), project, func() time.Time { return later }, firebaseauth.WithJWKSURL(m.JWKSURL))
	if _, err := vLater.Verify(t.Context(), tok); !errors.Is(err, firebaseauth.ErrInvalid) {
		t.Fatalf("two hours later: error = %v, want ErrInvalid (token expired)", err)
	}
}

func TestVerify_BR_CLI_04_UnreachableKeySetFailsClosed(t *testing.T) {
	m := otptest.NewMinter(t, project)
	tok := m.Token(t, m.Valid(now))
	dead := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := dead.URL
	dead.Close()

	v := firebaseauth.New(t.Context(), project, clock, firebaseauth.WithJWKSURL(url))
	p, err := v.Verify(t.Context(), tok)
	if err == nil {
		t.Fatalf("Verify with an unreachable key set succeeded: %+v", p)
	}
	if errors.Is(err, firebaseauth.ErrDisabled) {
		t.Errorf("an unreachable key set is not 'not configured'")
	}
}

func TestVerify_BR_CLI_04_KeySetServerErrorFailsClosed(t *testing.T) {
	m := otptest.NewMinter(t, project)
	tok := m.Token(t, m.Valid(now))
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	t.Cleanup(bad.Close)

	v := firebaseauth.New(t.Context(), project, clock, firebaseauth.WithJWKSURL(bad.URL))
	if _, err := v.Verify(t.Context(), tok); err == nil {
		t.Fatal("Verify succeeded although the key set endpoint answers 500")
	}
}

func TestVerify_BR_CLI_04_CancelledContextFails(t *testing.T) {
	m := otptest.NewMinter(t, project)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := newVerifier(t, m).Verify(ctx, m.Token(t, m.Valid(now))); err == nil {
		t.Fatal("Verify with a cancelled context succeeded")
	}
}

func TestDisabled_BR_CLI_04_AlwaysErrDisabled(t *testing.T) {
	m := otptest.NewMinter(t, project)
	tok := m.Token(t, m.Valid(now))

	for name, v := range map[string]firebaseauth.Verifier{
		"Disabled()":             firebaseauth.Disabled(),
		"New with empty project": firebaseauth.New(t.Context(), "", clock, firebaseauth.WithJWKSURL(m.JWKSURL)),
	} {
		t.Run(name, func(t *testing.T) {
			if v == nil {
				t.Fatal("nil verifier")
			}
			for _, raw := range []string{tok, "", "garbage"} {
				p, err := v.Verify(t.Context(), raw)
				if !errors.Is(err, firebaseauth.ErrDisabled) {
					t.Errorf("Verify(%.8q) error = %v, want ErrDisabled", raw, err)
				}
				if p != (firebaseauth.Proof{}) {
					t.Errorf("proof = %+v, want zero", p)
				}
			}
		})
	}
}
