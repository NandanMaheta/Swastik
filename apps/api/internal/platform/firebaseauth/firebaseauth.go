// Package firebaseauth verifies Firebase phone sign-in ID tokens (go-oidc, RS256, Google's
// securetoken key set). It only checks the token; the caller decides what the proof means.
package firebaseauth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
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
	// ErrUnavailable is a key set that could not be fetched (HTTP error, timeout, unreadable
	// body). The token was not judged: the caller answers 503 and counts no refusal.
	ErrUnavailable = errors.New("firebaseauth: key set unavailable")
)

const (
	issuerPrefix = "https://securetoken.google.com/"
	jwksFirebase = "https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com"
	// maxFutureIAT is the clock skew tolerated for iat.
	maxFutureIAT = 30 * time.Second
	// fetchTimeout bounds one key-set request when the caller supplies no HTTP client.
	fetchTimeout = 5 * time.Second
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
	now      func() time.Time
	verifier *oidc.IDTokenVerifier
}

// New returns a Verifier for projectID; an empty projectID returns Disabled(). ctx only carries
// configuration for the key set fetches; pass the process context.
func New(ctx context.Context, projectID string, now func() time.Time, opts ...Option) Verifier {
	if projectID == "" {
		return Disabled()
	}
	cfg := config{jwksURL: jwksFirebase}
	for _, o := range opts {
		o(&cfg)
	}
	if cfg.client == nil {
		cfg.client = &http.Client{Timeout: fetchTimeout}
	}
	ctx = oidc.ClientContext(ctx, cfg.client)
	return &verifier{
		now: now,
		verifier: oidc.NewVerifier(issuerPrefix+projectID, outageKeySet{inner: oidc.NewRemoteKeySet(ctx, cfg.jwksURL)}, &oidc.Config{
			ClientID:             projectID,
			SupportedSigningAlgs: []string{oidc.RS256},
			Now:                  now,
		}),
	}
}

// outageKeySet tells a key set that cannot be fetched from a signature that does not verify.
// go-oidc flattens errors to text, so the outage is noted in a per-call recorder in the context.
type outageKeySet struct{ inner oidc.KeySet }

type outageKey struct{}

func (k outageKeySet) VerifySignature(ctx context.Context, jwt string) ([]byte, error) {
	payload, err := k.inner.VerifySignature(ctx, jwt)
	if err != nil && strings.HasPrefix(err.Error(), "fetching keys") {
		if rec, ok := ctx.Value(outageKey{}).(*bool); ok {
			*rec = true
		}
	}
	if err != nil {
		return nil, fmt.Errorf("key set: %w", err)
	}
	return payload, nil
}

func (v *verifier) Verify(ctx context.Context, rawIDToken string) (Proof, error) {
	if err := ctx.Err(); err != nil {
		return Proof{}, fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	if !hasKeyID(rawIDToken) {
		return Proof{}, fmt.Errorf("%w: missing key id", ErrInvalid)
	}
	var outage bool
	tok, err := v.verifier.Verify(context.WithValue(ctx, outageKey{}, &outage), rawIDToken)
	if err != nil {
		if outage {
			return Proof{}, ErrUnavailable
		}
		// go-oidc errors name claims and algorithms, never the token itself.
		return Proof{}, fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	var claims struct {
		PhoneNumber string `json:"phone_number"`
		AuthTime    int64  `json:"auth_time"`
		Firebase    struct {
			SignInProvider string `json:"sign_in_provider"`
		} `json:"firebase"`
	}
	if err := tok.Claims(&claims); err != nil {
		return Proof{}, fmt.Errorf("%w: claims", ErrInvalid)
	}
	if !tok.Expiry.After(v.now()) { // go-oidc accepts exp == now; the contract is exp > now
		return Proof{}, fmt.Errorf("%w: expired", ErrInvalid)
	}
	if tok.Subject == "" {
		return Proof{}, fmt.Errorf("%w: empty subject", ErrInvalid)
	}
	if tok.IssuedAt.After(v.now().Add(maxFutureIAT)) {
		return Proof{}, fmt.Errorf("%w: issued in the future", ErrInvalid)
	}
	return Proof{
		Subject:        tok.Subject,
		PhoneNumber:    claims.PhoneNumber,
		SignInProvider: claims.Firebase.SignInProvider,
		AuthTime:       time.Unix(claims.AuthTime, 0).UTC(),
		IssuedAt:       tok.IssuedAt.UTC(),
	}, nil
}

// hasKeyID reports whether the JWT header carries a non-empty kid. go-oidc would otherwise try
// every published key for a token without one.
func hasKeyID(raw string) bool {
	head, _, ok := strings.Cut(raw, ".")
	if !ok {
		return false
	}
	b, err := base64.RawURLEncoding.DecodeString(head)
	if err != nil {
		return false
	}
	var h struct {
		KID string `json:"kid"`
	}
	return json.Unmarshal(b, &h) == nil && h.KID != ""
}

type disabled struct{}

// Disabled returns a Verifier that always fails with ErrDisabled.
func Disabled() Verifier { return disabled{} }

func (disabled) Verify(_ context.Context, _ string) (Proof, error) { return Proof{}, ErrDisabled }
