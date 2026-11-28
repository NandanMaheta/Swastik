// Package email sends transactional mail. Resend is the production provider; Discard serves local
// and CI runs without a key. Errors carry the status code only: never a body or a recipient.
package email

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
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
)

const (
	defaultBaseURL = "https://api.resend.com"
	sendTimeout    = 5 * time.Second
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
	r := &resend{apiKey: apiKey, from: from, baseURL: defaultBaseURL}
	for _, o := range opts {
		o(r)
	}
	if r.client == nil {
		r.client = &http.Client{Timeout: sendTimeout}
	}
	return r
}

func (r *resend) Send(ctx context.Context, m Mail) error {
	body, err := json.Marshal(struct {
		From    string   `json:"from"`
		To      []string `json:"to"`
		Subject string   `json:"subject"`
		Text    string   `json:"text"`
	}{r.from, []string{m.To}, m.Subject, m.Text})
	if err != nil {
		return fmt.Errorf("%w: encode", ErrRejected)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.baseURL+"/emails", bytes.NewReader(body))
	if err != nil {
		// The URL is configuration; never include the underlying error text.
		return fmt.Errorf("%w: build request", ErrUnavailable)
	}
	req.Header.Set("Authorization", "Bearer "+r.apiKey)
	req.Header.Set("Content-Type", "application/json")
	if m.IdempotencyKey != "" {
		req.Header.Set("Idempotency-Key", m.IdempotencyKey)
	}
	resp, err := r.client.Do(req)
	if err != nil {
		// net/http errors embed the URL; no recipient or body, but keep the text out anyway.
		return fmt.Errorf("%w: transport failure", ErrUnavailable)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return nil
	case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500:
		return fmt.Errorf("%w: status %d", ErrUnavailable, resp.StatusCode)
	default:
		return fmt.Errorf("%w: status %d", ErrRejected, resp.StatusCode)
	}
}

type discard struct{}

// Discard returns a Mailer that sends nothing (local and CI without RESEND_API_KEY).
func Discard() Mailer { return discard{} }

func (discard) Send(_ context.Context, _ Mail) error { return nil }
