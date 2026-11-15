// Review-fix tests for access-token clock tolerance (feature 003; owner decision
// 2026-11-15_jwt_leeway): iat and nbf tolerate up to 5 seconds of clock skew into the future; exp
// has no leeway at all. Tokens are forged with the helpers of tokens_reject_test.go and verified on
// the injected clock fgNow (whole seconds, so each boundary is exact).
package auth_test

import (
	"errors"
	"testing"
	"time"

	"github.com/NandanMaheta/swastik/apps/api/internal/auth"
)

func TestTokensLeeway_IssuedAtUpToFiveSecondsAheadIsAccepted(t *testing.T) {
	for _, ahead := range []time.Duration{time.Second, 4 * time.Second, 5 * time.Second} {
		raw := fgSignEd(fgHeader(), fgSet(fgClaims(fgNow), "iat", fgNow.Add(ahead).Unix()), fgPriv())
		if _, err := fgVerifier(t, fgNow).Verify(raw); err != nil {
			t.Errorf("iat %v ahead of the clock was rejected: %v (5s leeway)", ahead, err)
		}
	}
}

func TestTokensLeeway_IssuedAtMoreThanFiveSecondsAheadIsRejected(t *testing.T) {
	for _, ahead := range []time.Duration{6 * time.Second, 10 * time.Second, time.Minute, time.Hour} {
		raw := fgSignEd(fgHeader(), fgSet(fgClaims(fgNow), "iat", fgNow.Add(ahead).Unix()), fgPriv())
		if _, err := fgVerifier(t, fgNow).Verify(raw); !errors.Is(err, auth.ErrInvalidToken) {
			t.Errorf("iat %v ahead of the clock: err = %v, want ErrInvalidToken", ahead, err)
		}
	}
}

func TestTokensLeeway_NotBeforeUpToFiveSecondsAheadIsAccepted(t *testing.T) {
	for _, ahead := range []time.Duration{time.Second, 5 * time.Second} {
		raw := fgSignEd(fgHeader(), fgSet(fgClaims(fgNow), "nbf", fgNow.Add(ahead).Unix()), fgPriv())
		if _, err := fgVerifier(t, fgNow).Verify(raw); err != nil {
			t.Errorf("nbf %v ahead of the clock was rejected: %v (5s leeway)", ahead, err)
		}
	}
}

func TestTokensLeeway_NotBeforeMoreThanFiveSecondsAheadIsRejected(t *testing.T) {
	for _, ahead := range []time.Duration{6 * time.Second, time.Minute} {
		raw := fgSignEd(fgHeader(), fgSet(fgClaims(fgNow), "nbf", fgNow.Add(ahead).Unix()), fgPriv())
		if _, err := fgVerifier(t, fgNow).Verify(raw); !errors.Is(err, auth.ErrInvalidToken) {
			t.Errorf("nbf %v ahead of the clock: err = %v, want ErrInvalidToken", ahead, err)
		}
	}
}

// exp is strict: the leeway never extends the life of a token.
func TestTokensLeeway_ExpiryHasNoLeeway(t *testing.T) {
	for _, past := range []time.Duration{0, time.Second, 2 * time.Second, 5 * time.Second} {
		raw := fgSignEd(fgHeader(), fgSet(fgClaims(fgNow), "iat", fgNow.Add(-time.Hour).Unix(), "exp", fgNow.Add(-past).Unix()), fgPriv())
		if _, err := fgVerifier(t, fgNow).Verify(raw); !errors.Is(err, auth.ErrInvalidToken) {
			t.Errorf("exp %v in the past (or now): err = %v, want ErrInvalidToken (exp is strict)", past, err)
		}
	}
	// One second of life left is still valid.
	raw := fgSignEd(fgHeader(), fgSet(fgClaims(fgNow), "iat", fgNow.Add(-time.Hour).Unix(), "exp", fgNow.Add(time.Second).Unix()), fgPriv())
	if _, err := fgVerifier(t, fgNow).Verify(raw); err != nil {
		t.Errorf("a token with one second left was rejected: %v", err)
	}
}

// A future iat inside the leeway must not rescue an expired token, and the leeway must not leak
// into the other checks.
func TestTokensLeeway_DoesNotRescueAnExpiredToken(t *testing.T) {
	raw := fgSignEd(fgHeader(), fgSet(fgClaims(fgNow), "iat", fgNow.Add(2*time.Second).Unix(), "exp", fgNow.Add(-time.Second).Unix()), fgPriv())
	if _, err := fgVerifier(t, fgNow).Verify(raw); !errors.Is(err, auth.ErrInvalidToken) {
		t.Errorf("expired token with a skewed iat: err = %v, want ErrInvalidToken", err)
	}
}

// The tolerance applies on the verifying clock at every call, including when it advances.
func TestTokensLeeway_BoundaryMovesWithTheClock(t *testing.T) {
	raw := fgSignEd(fgHeader(), fgSet(fgClaims(fgNow), "iat", fgNow.Add(8*time.Second).Unix()), fgPriv())
	if _, err := fgVerifier(t, fgNow).Verify(raw); !errors.Is(err, auth.ErrInvalidToken) {
		t.Fatalf("iat 8s ahead at t0: err = %v, want ErrInvalidToken", err)
	}
	if _, err := fgVerifier(t, fgNow.Add(3*time.Second)).Verify(raw); err != nil {
		t.Errorf("the same token 3s later (iat now 5s ahead) was rejected: %v", err)
	}
}
