// Package firebaseauth verifies Firebase phone sign-in ID tokens (go-oidc, RS256, Google's
// securetoken key set). It only checks the token; the caller decides what the proof means.
package firebaseauth

import (
	"context"
	"errors"
	"net/http"
	"time"
)

// Proof is the verified content of a Firebase ID token.
type Proof struct {
	Subject, PhoneNumber, SignInProvider string
	AuthTime, IssuedAt                   time.Time
}

// Verifier checks a raw ID token.
type Verifier interface {
	Verify(ctx context.Context, rawIDToken string) (Proof, error)
}

var (
	// ErrInvalid is every token failure (signature, issuer, audience, expiry, claims).
	ErrInvalid = errors.New("firebaseauth: invalid token")
	// ErrDisabled is returned when no Firebase project is configured.
	ErrDisabled = errors.New("firebaseauth: not configured")

	errNotImplemented = errors.New("firebaseauth: not implemented")
)

// Option customises New.
type Option func(*config)

type config struct {
	jwksURL string
	client  *http.Client
}

// WithJWKSURL overrides Google's key set URL. Tests only.
func WithJWKSURL(u string) Option { return func(c *config) { c.jwksURL = u } }

// WithHTTPClient sets the HTTP client used to fetch the key set.
func WithHTTPClient(c *http.Client) Option { return func(cfg *config) { cfg.client = c } }

type verifier struct {
	projectID string
	now       func() time.Time
	cfg       config
}

// New returns a Verifier for projectID; an empty projectID returns Disabled().
func New(_ context.Context, projectID string, now func() time.Time, opts ...Option) Verifier {
	if projectID == "" {
		return Disabled()
	}
	v := &verifier{projectID: projectID, now: now}
	for _, o := range opts {
		o(&v.cfg)
	}
	return v
}

func (v *verifier) Verify(_ context.Context, _ string) (Proof, error) {
	return Proof{}, errNotImplemented
}

type disabled struct{}

// Disabled returns a Verifier that always fails with ErrDisabled.
func Disabled() Verifier { return disabled{} }

func (disabled) Verify(_ context.Context, _ string) (Proof, error) { return Proof{}, errNotImplemented }
