// Tests for the Resend mail client and Discard (feature 004, S02; BR-CLI-04 delivery of the sign-up
// code, FR-011, D-08). No network: an httptest server stands in for api.resend.com.
//
// Contract (specs/004-otp-delivery/contracts/go-module-api.md section 3): POST {base}/emails with
// a Bearer key, an Idempotency-Key header and a JSON body {from, to[], subject, text}; 429, 5xx,
// network failure and timeout are ErrUnavailable; every other non-2xx is ErrRejected; errors carry
// the status code only, never the recipient, subject, body, API key or provider response.
package email_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/NandanMaheta/swastik/apps/api/internal/platform/email"
)

const (
	apiKey    = "re_test_SECRETKEY0123456789"
	fromAddr  = "Swastik <no-reply@mail.swastikapp.co.in>"
	recipient = "ravi.shah@example.com"
	subject   = "Your Swastik code: 482913"
	bodyText  = "Your code is 482913. It expires in 10 minutes."
)

type captured struct {
	method, path, auth, idem, ctype string
	body                            []byte
}

// server records the request and answers with status and body.
func server(t *testing.T, status int, respBody string) (*httptest.Server, func() captured) {
	t.Helper()
	var mu sync.Mutex
	var got captured
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		mu.Lock()
		got = captured{r.Method, r.URL.Path, r.Header.Get("Authorization"), r.Header.Get("Idempotency-Key"), r.Header.Get("Content-Type"), raw}
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, respBody)
	}))
	t.Cleanup(srv.Close)
	return srv, func() captured { mu.Lock(); defer mu.Unlock(); return got }
}

func mail() email.Mail {
	return email.Mail{To: recipient, Subject: subject, Text: bodyText, IdempotencyKey: "otp:code:0198a1b2-0000-7000-8000-000000000001"}
}

func TestResendClient_BR_CLI_04_SendsOneAuthenticatedIdempotentRequest(t *testing.T) {
	srv, last := server(t, http.StatusOK, `{"id":"49a3999c-0ce1-4ea6-ab68-afcd6dc2e794"}`)
	m := email.NewResend(apiKey, fromAddr, email.WithBaseURL(srv.URL))

	if err := m.Send(t.Context(), mail()); err != nil {
		t.Fatalf("Send: %v", err)
	}
	r := last()
	if r.method != http.MethodPost || r.path != "/emails" {
		t.Errorf("request = %s %s, want POST /emails", r.method, r.path)
	}
	if r.auth != "Bearer "+apiKey {
		t.Errorf("Authorization = %q, want a Bearer key", r.auth)
	}
	if r.idem != mail().IdempotencyKey {
		t.Errorf("Idempotency-Key = %q, want the mail's key %q", r.idem, mail().IdempotencyKey)
	}
	if !strings.HasPrefix(r.ctype, "application/json") {
		t.Errorf("Content-Type = %q, want application/json", r.ctype)
	}
	var body struct {
		From    string   `json:"from"`
		To      []string `json:"to"`
		Subject string   `json:"subject"`
		Text    string   `json:"text"`
	}
	if err := json.Unmarshal(r.body, &body); err != nil {
		t.Fatalf("body is not JSON: %v\n%s", err, r.body)
	}
	if body.From != fromAddr || len(body.To) != 1 || body.To[0] != recipient || body.Subject != subject || body.Text != bodyText {
		t.Errorf("body = %+v, want from/to/subject/text as given", body)
	}
}

func TestResendClient_BR_CLI_04_StatusMapping(t *testing.T) {
	tests := []struct {
		status int
		want   error // nil = success
	}{
		{http.StatusOK, nil},
		{http.StatusCreated, nil},
		{http.StatusAccepted, nil},
		{http.StatusTooManyRequests, email.ErrUnavailable}, // the shared 100/day cap and the per-second limit
		{http.StatusInternalServerError, email.ErrUnavailable},
		{http.StatusBadGateway, email.ErrUnavailable},
		{http.StatusServiceUnavailable, email.ErrUnavailable},
		{http.StatusGatewayTimeout, email.ErrUnavailable},
		{http.StatusBadRequest, email.ErrRejected},
		{http.StatusUnauthorized, email.ErrRejected},
		{http.StatusForbidden, email.ErrRejected},
		{http.StatusNotFound, email.ErrRejected},
		{http.StatusConflict, email.ErrRejected},
		{http.StatusUnprocessableEntity, email.ErrRejected},
	}
	for _, tt := range tests {
		t.Run(strconv.Itoa(tt.status), func(t *testing.T) {
			srv, _ := server(t, tt.status, `{"name":"x","message":"x"}`)
			err := email.NewResend(apiKey, fromAddr, email.WithBaseURL(srv.URL)).Send(t.Context(), mail())
			switch {
			case tt.want == nil && err != nil:
				t.Fatalf("status %d: error %v, want success", tt.status, err)
			case tt.want != nil && !errors.Is(err, tt.want):
				t.Fatalf("status %d: error %v, want %v", tt.status, err, tt.want)
			}
			if tt.want == nil {
				return
			}
			other := email.ErrRejected
			if errors.Is(tt.want, email.ErrRejected) {
				other = email.ErrUnavailable
			}
			if errors.Is(err, other) {
				t.Errorf("status %d: error is also %v; the two must be exclusive", tt.status, other)
			}
			if !strings.Contains(err.Error(), strconv.Itoa(tt.status)) {
				t.Errorf("error %q does not carry the status code %d", err, tt.status)
			}
		})
	}
}

// D-08, FR-009: nothing the provider echoes, and nothing we sent, may reach an error.
func TestResendClient_BR_CLI_04_ErrorsNeverCarryRecipientBodyKeyOrProviderText(t *testing.T) {
	providerText := `{"name":"validation_error","message":"The to field ravi.shah@example.com is invalid; code 482913; key re_test_SECRETKEY0123456789"}`
	for _, status := range []int{http.StatusBadRequest, http.StatusTooManyRequests, http.StatusInternalServerError} {
		srv, _ := server(t, status, providerText)
		err := email.NewResend(apiKey, fromAddr, email.WithBaseURL(srv.URL)).Send(t.Context(), mail())
		if err == nil {
			t.Fatalf("status %d: want an error", status)
		}
		for _, secret := range []string{recipient, "ravi.shah", "482913", apiKey, "SECRETKEY", "validation_error", bodyText, subject, fromAddr} {
			if strings.Contains(err.Error(), secret) {
				t.Errorf("status %d: error %q leaks %q", status, err, secret)
			}
		}
	}
}

func TestResendClient_BR_CLI_04_NetworkFailureIsUnavailableAndLeaksNothing(t *testing.T) {
	srv, _ := server(t, http.StatusOK, `{}`)
	url := srv.URL
	srv.Close() // connection refused from now on

	err := email.NewResend(apiKey, fromAddr, email.WithBaseURL(url)).Send(t.Context(), mail())
	if !errors.Is(err, email.ErrUnavailable) {
		t.Fatalf("error = %v, want ErrUnavailable", err)
	}
	for _, secret := range []string{recipient, "482913", apiKey, bodyText} {
		if strings.Contains(err.Error(), secret) {
			t.Errorf("error %q leaks %q", err, secret)
		}
	}
}

func TestResendClient_BR_CLI_04_ClientTimeoutAndCancelledContextAreUnavailable(t *testing.T) {
	release := make(chan struct{})
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(slow.Close)
	t.Cleanup(func() { close(release) })

	t.Run("http client timeout", func(t *testing.T) {
		m := email.NewResend(apiKey, fromAddr, email.WithBaseURL(slow.URL), email.WithHTTPClient(&http.Client{Timeout: 50 * time.Millisecond}))
		if err := m.Send(t.Context(), mail()); !errors.Is(err, email.ErrUnavailable) {
			t.Fatalf("error = %v, want ErrUnavailable", err)
		}
	})
	t.Run("context deadline", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
		defer cancel()
		m := email.NewResend(apiKey, fromAddr, email.WithBaseURL(slow.URL))
		if err := m.Send(ctx, mail()); !errors.Is(err, email.ErrUnavailable) {
			t.Fatalf("error = %v, want ErrUnavailable", err)
		}
	})
	t.Run("already cancelled context", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		m := email.NewResend(apiKey, fromAddr, email.WithBaseURL(slow.URL))
		if err := m.Send(ctx, mail()); !errors.Is(err, email.ErrUnavailable) {
			t.Fatalf("error = %v, want ErrUnavailable", err)
		}
	})
}

// The default client gives up after 5 s (contract section 3).
func TestResendClient_BR_CLI_04_DefaultTimeoutIsFiveSeconds(t *testing.T) {
	if testing.Short() {
		t.Skip("waits for the real 5 s timeout")
	}
	release := make(chan struct{})
	slow := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	t.Cleanup(slow.Close)
	t.Cleanup(func() { close(release) })

	start := time.Now()
	err := email.NewResend(apiKey, fromAddr, email.WithBaseURL(slow.URL)).Send(t.Context(), mail())
	elapsed := time.Since(start)
	if !errors.Is(err, email.ErrUnavailable) {
		t.Fatalf("error = %v, want ErrUnavailable", err)
	}
	if elapsed < 4500*time.Millisecond || elapsed > 6500*time.Millisecond {
		t.Errorf("gave up after %v, want about 5 s", elapsed)
	}
}

func TestResendClient_BR_CLI_04_NoIdempotencyKeyMeansNoHeader(t *testing.T) {
	srv, last := server(t, http.StatusOK, `{}`)
	m := mail()
	m.IdempotencyKey = ""
	if err := email.NewResend(apiKey, fromAddr, email.WithBaseURL(srv.URL)).Send(t.Context(), m); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if got := last().idem; got != "" {
		t.Errorf("Idempotency-Key = %q, want none", got)
	}
}

func TestDiscard_BR_CLI_04_SendsNothingAndSucceeds(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits++ }))
	t.Cleanup(srv.Close)

	m := email.Discard()
	if m == nil {
		t.Fatal("Discard() = nil")
	}
	for range 3 {
		if err := m.Send(t.Context(), mail()); err != nil {
			t.Fatalf("Discard().Send: %v", err)
		}
	}
	if err := m.Send(t.Context(), email.Mail{}); err != nil {
		t.Errorf("Discard().Send(empty) = %v, want nil", err)
	}
	if hits != 0 {
		t.Errorf("Discard made %d network calls", hits)
	}
}
