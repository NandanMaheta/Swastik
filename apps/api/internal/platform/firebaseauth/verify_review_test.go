package firebaseauth_test

// Review-fix tests for feature 004 (BR-CLI-04, D-04, SC-004): an outage of Google's key set is not a
// bad token, and a hung key-set fetch cannot hang a sign-up request.
//
// Contract: a token that fails its checks is ErrInvalid; a key set that cannot be fetched (HTTP
// error, refused connection, unreadable body) is a different error, so the caller answers 503 and
// does not count a refusal against the client. A verifier built without WithHTTPClient has an HTTP
// client with a timeout.

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/NandanMaheta/swastik/apps/api/internal/platform/firebaseauth"
)

func TestVerify_BR_CLI_04_KeySetOutageIsNotAnInvalidToken(t *testing.T) {
	m := NewMinter(t, project)
	token := m.Token(t, m.Valid(now))

	broken := map[string]http.HandlerFunc{
		"HTTP 500":     func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "boom", http.StatusInternalServerError) },
		"HTTP 503":     func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "down", http.StatusServiceUnavailable) },
		"garbage body": func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("<html>not a key set")) },
	}
	for name, h := range broken {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewServer(h)
			t.Cleanup(srv.Close)
			v := firebaseauth.New(t.Context(), project, clock, firebaseauth.WithJWKSURL(srv.URL))
			_, err := v.Verify(t.Context(), token)
			if err == nil {
				t.Fatal("Verify succeeded without a key set")
			}
			if errors.Is(err, firebaseauth.ErrInvalid) || errors.Is(err, firebaseauth.ErrDisabled) {
				t.Errorf("Verify = %v: a key-set outage must be told apart from an invalid token (the caller answers 503, not 422)", err)
			}
		})
	}

	t.Run("connection refused", func(t *testing.T) {
		srv := httptest.NewServer(http.NotFoundHandler())
		url := srv.URL
		srv.Close() // nothing listens any more
		v := firebaseauth.New(t.Context(), project, clock, firebaseauth.WithJWKSURL(url))
		_, err := v.Verify(t.Context(), token)
		if err == nil || errors.Is(err, firebaseauth.ErrInvalid) || errors.Is(err, firebaseauth.ErrDisabled) {
			t.Errorf("Verify = %v, want an error that is neither ErrInvalid nor ErrDisabled", err)
		}
	})
}

// With a healthy key set, a kid that is not in it is a bad token, not an outage.
func TestVerify_BR_CLI_04_UnknownKeyIDWithAHealthyKeySetIsInvalid(t *testing.T) {
	m := NewMinter(t, project)
	tok := m.Raw(t, "RS256", map[string]any{"kid": "some-other-kid"}, m.MapOf(m.Valid(now)))
	if _, err := newVerifier(t, m).Verify(t.Context(), tok); !errors.Is(err, firebaseauth.ErrInvalid) {
		t.Errorf("Verify = %v, want ErrInvalid for a kid the key set does not hold", err)
	}
	if _, err := newVerifier(t, m).Verify(t.Context(), m.ForeignToken(t, m.Valid(now))); !errors.Is(err, firebaseauth.ErrInvalid) {
		t.Errorf("Verify (foreign signature) = %v, want ErrInvalid", err)
	}
}

// The key-set request has its own deadline: the caller's context is not the fetch's (the verifier
// is built once, with the process context), so without a client timeout a hung server hangs every
// sign-up request that needs a key.
func TestVerify_BR_CLI_04_HungKeySetFetchTimesOut(t *testing.T) {
	if testing.Short() {
		t.Skip("waits for the verifier's HTTP timeout")
	}
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	t.Cleanup(func() { close(release); srv.Close() })
	m := NewMinter(t, project)
	token := m.Token(t, m.Valid(now))
	v := firebaseauth.New(t.Context(), project, clock, firebaseauth.WithJWKSURL(srv.URL)) // no WithHTTPClient

	type result struct{ err error }
	done := make(chan result, 1)
	go func() {
		_, err := v.Verify(t.Context(), token) // no deadline of its own
		done <- result{err}
	}()
	const limit = 15 * time.Second
	select {
	case r := <-done:
		if r.err == nil {
			t.Error("Verify succeeded against a server that never answers")
		}
		if errors.Is(r.err, firebaseauth.ErrInvalid) {
			t.Errorf("Verify = %v: a hung key set is an outage, not an invalid token", r.err)
		}
	case <-time.After(limit):
		t.Fatalf("Verify still waiting after %v: the key-set HTTP client has no timeout", limit)
	}
}
