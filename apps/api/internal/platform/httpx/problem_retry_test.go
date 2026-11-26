// Tests for httpx.ProblemRetry (feature 004, S02; BR-CLI-04 resend cooldown D-02/D-03, FR-016).
//
// Contract: ProblemRetry(status, code, detail, after) is a Problem that also sets the Retry-After
// header (whole seconds, rounded up, at least 1) and the body field retry_after_seconds with the
// same value. It implements huma.StatusError and huma.HeadersError.
package httpx_test

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/NandanMaheta/swastik/apps/api/internal/platform/httpx"
)

type retryBody struct {
	Code              string `json:"code"`
	Status            int    `json:"status"`
	Detail            string `json:"detail"`
	RetryAfterSeconds int    `json:"retry_after_seconds"`
}

func TestProblemRetry_BR_CLI_04_HeaderAndFieldCarryRoundedUpSeconds(t *testing.T) {
	tests := []struct {
		after time.Duration
		want  int
	}{
		{time.Millisecond, 1},
		{999 * time.Millisecond, 1},
		{time.Second, 1},
		{1001 * time.Millisecond, 2},
		{59*time.Second + time.Nanosecond, 60},
		{60 * time.Second, 60},
		{41500 * time.Millisecond, 42},
		{time.Hour, 3600},
		{0, 1},
		{-5 * time.Second, 1},
	}
	for _, tt := range tests {
		t.Run(tt.after.String(), func(t *testing.T) {
			api := newAPI(t, failWith(httpx.ProblemRetry(http.StatusTooManyRequests, "otp.cooldown", "Please wait.", tt.after)))
			rec := api.Get("/thing")
			if rec.Code != http.StatusTooManyRequests {
				t.Fatalf("status = %d, want 429", rec.Code)
			}
			if got := rec.Header().Get("Retry-After"); got != strconv.Itoa(tt.want) {
				t.Errorf("Retry-After = %q, want %d", got, tt.want)
			}
			b := decodeRetry(t, rec.Body.Bytes())
			if b.RetryAfterSeconds != tt.want {
				t.Errorf("retry_after_seconds = %d, want %d", b.RetryAfterSeconds, tt.want)
			}
			if b.Code != "otp.cooldown" || b.Status != 429 || b.Detail != "Please wait." {
				t.Errorf("body = %+v, want code otp.cooldown, status 429, the given detail", b)
			}
			if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/problem+json") {
				t.Errorf("Content-Type = %q, want application/problem+json", ct)
			}
		})
	}
}

func TestProblemRetry_BR_CLI_04_IsStatusAndHeadersError(t *testing.T) {
	httpx.InstallErrors()
	err := httpx.ProblemRetry(http.StatusTooManyRequests, "otp.rate_limited", "Try later.", 90*time.Second)
	var se huma.StatusError
	if !errors.As(err, &se) || se.GetStatus() != http.StatusTooManyRequests {
		t.Fatalf("ProblemRetry() = %T, want a huma.StatusError with status 429", err)
	}
	var he huma.HeadersError
	if !errors.As(err, &he) {
		t.Fatalf("ProblemRetry() = %T, does not implement huma.HeadersError", err)
	}
	if got := he.GetHeaders().Get("Retry-After"); got != "90" {
		t.Errorf("GetHeaders Retry-After = %q, want 90", got)
	}
}

func TestProblemRetry_BR_CLI_04_PlainProblemHasNoRetryAfter(t *testing.T) {
	rec := newAPI(t, failWith(httpx.Problem(http.StatusConflict, "otp.email_first", "Verify email first."))).Get("/thing")
	if got := rec.Header().Get("Retry-After"); got != "" {
		t.Errorf("Retry-After = %q on a plain Problem, want none", got)
	}
	if strings.Contains(rec.Body.String(), "retry_after_seconds") {
		t.Errorf("plain Problem body carries retry_after_seconds: %s", rec.Body.String())
	}
}

func TestProblemRetry_BR_CLI_04_SameInputIsByteIdentical(t *testing.T) {
	api := newAPI(t, failWith(httpx.ProblemRetry(http.StatusTooManyRequests, "otp.cooldown", "Please wait.", 30*time.Second)))
	a, b := api.Get("/thing"), api.Get("/thing")
	if a.Body.String() != b.Body.String() {
		t.Errorf("bodies differ:\n%s\n%s", a.Body.String(), b.Body.String())
	}
}

func decodeRetry(t *testing.T, raw []byte) retryBody {
	t.Helper()
	var b retryBody
	if err := json.Unmarshal(raw, &b); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, raw)
	}
	return b
}
