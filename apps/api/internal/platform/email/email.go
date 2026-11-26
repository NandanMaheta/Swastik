// Package email sends transactional mail. Resend is the production provider; Discard serves local
// and CI runs without a key. Errors carry the status code only: never a body or a recipient.
package email

import (
	"context"
	"errors"
	"net/http"
)

// Mail is one message. IdempotencyKey is sent to the provider so a retried send is not duplicated.
type Mail struct {
	To, Subject, Text string
	IdempotencyKey    string
}

// Mailer sends one mail.
type Mailer interface {
	Send(ctx context.Context, m Mail) error
}

var (
	// ErrRejected is a 4xx other than 429: permanent for this content.
	ErrRejected = errors.New("email: rejected")
	// ErrUnavailable is a 429, 5xx, network failure or timeout: worth retrying.
	ErrUnavailable = errors.New("email: unavailable")

	errNotImplemented = errors.New("email: not implemented")
)

// ResendOption customises NewResend.
type ResendOption func(*resend)

type resend struct {
	apiKey, from, baseURL string
	client                *http.Client
}

// WithBaseURL overrides https://api.resend.com. Tests only.
func WithBaseURL(u string) ResendOption { return func(r *resend) { r.baseURL = u } }

// WithHTTPClient sets the HTTP client.
func WithHTTPClient(c *http.Client) ResendOption { return func(r *resend) { r.client = c } }

// NewResend returns a Mailer that POSTs to the Resend API with a Bearer key, the Idempotency-Key
// header and a 5 s timeout.
func NewResend(apiKey, from string, opts ...ResendOption) Mailer {
	r := &resend{apiKey: apiKey, from: from}
	for _, o := range opts {
		o(r)
	}
	return r
}

func (r *resend) Send(_ context.Context, _ Mail) error { return errNotImplemented }

type discard struct{}

// Discard returns a Mailer that sends nothing (local and CI without RESEND_API_KEY).
func Discard() Mailer { return discard{} }

func (discard) Send(_ context.Context, _ Mail) error { return errNotImplemented }
