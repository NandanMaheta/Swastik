// Tests for ProblemFor, the otp error to HTTP problem mapping (feature 004, S06; BR-CLI-04,
// FR-016, D-08). Codes, statuses and Retry-After come from contracts/error-codes.md.
package otp_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/humatest"

	"github.com/NandanMaheta/swastik/apps/api/internal/otp"
	"github.com/NandanMaheta/swastik/apps/api/internal/platform/httpx"
)

type problemBody struct {
	Type              string `json:"type"`
	Status            int    `json:"status"`
	Code              string `json:"code"`
	Detail            string `json:"detail"`
	RetryAfterSeconds int    `json:"retry_after_seconds"`
}

func problemFor(t *testing.T, err error) (*httptest.ResponseRecorder, problemBody) {
	t.Helper()
	httpx.InstallErrors()
	_, api := humatest.New(t, huma.DefaultConfig("test", "1.0.0"))
	huma.Register(api, huma.Operation{OperationID: "x", Method: http.MethodGet, Path: "/x", Security: []map[string][]string{}},
		func(context.Context, *struct{}) (*struct{}, error) { return nil, otp.ProblemFor(err) })
	rec := api.Get("/x")
	var b problemBody
	if e := json.Unmarshal(rec.Body.Bytes(), &b); e != nil {
		t.Fatalf("not JSON: %v\n%s", e, rec.Body.String())
	}
	return rec, b
}

func TestProblemFor_BR_CLI_04_CodesAndStatuses(t *testing.T) {
	tests := []struct {
		err    error
		status int
		code   string
	}{
		{otp.ErrNotFound, 404, "otp.verification_invalid"},
		{otp.ErrVerificationExpired, 410, "otp.verification_expired"},
		{otp.ErrNothingToSend, 409, "otp.nothing_to_send"},
		{otp.ErrCodeWrong, 422, "otp.code_wrong"},
		{otp.ErrCodeExpired, 422, "otp.code_expired"},
		{otp.ErrCodeUsedUp, 422, "otp.code_used_up"},
		{otp.ErrEmailFirst, 409, "otp.email_first"},
		{otp.ErrProofInvalid, 422, "otp.proof_invalid"},
		{otp.ErrProofStale, 422, "otp.proof_stale"},
		{otp.ErrProofReplayed, 422, "otp.proof_replayed"},
		{otp.ErrNumberMismatch, 422, "otp.number_mismatch"},
		{otp.ErrContactUnavailable, 409, "otp.contact_unavailable"},
		{otp.ErrResetTokenInvalid, 422, "otp.reset_token_invalid"},
		{otp.ErrNotConfigured, 503, "otp.not_configured"},
	}
	for _, tt := range tests {
		t.Run(tt.code, func(t *testing.T) {
			rec, b := problemFor(t, tt.err)
			if rec.Code != tt.status || b.Status != tt.status || b.Code != tt.code {
				t.Errorf("got %d %q, want %d %q", rec.Code, b.Code, tt.status, tt.code)
			}
			if b.Type != "urn:swastik:problem:"+tt.code {
				t.Errorf("type = %q", b.Type)
			}
			if got := rec.Header().Get("Retry-After"); got != "" {
				t.Errorf("Retry-After = %q on a non-retry error", got)
			}
			if !strings.HasPrefix(rec.Header().Get("Content-Type"), "application/problem+json") {
				t.Errorf("Content-Type = %q", rec.Header().Get("Content-Type"))
			}
			if b.Detail == "" && tt.status < 500 {
				t.Error("empty detail")
			}
		})
	}
}

func TestProblemFor_BR_CLI_04_WrappedErrorsMapLikeTheSentinel(t *testing.T) {
	_, b := problemFor(t, fmt.Errorf("verify email: %w", fmt.Errorf("lock: %w", otp.ErrCodeExpired)))
	if b.Code != "otp.code_expired" || b.Status != 422 {
		t.Errorf("wrapped ErrCodeExpired = %d %q", b.Status, b.Code)
	}
	_, b = problemFor(t, fmt.Errorf("resend: %w", &otp.RetryError{Reason: otp.ReasonCooldown, RetryAfter: time.Second}))
	if b.Code != "otp.cooldown" || b.Status != 429 {
		t.Errorf("wrapped RetryError = %d %q", b.Status, b.Code)
	}
}

func TestProblemFor_BR_CLI_04_RetryErrorsCarryRetryAfterRoundedUp(t *testing.T) {
	tests := []struct {
		reason otp.RetryReason
		after  time.Duration
		code   string
		secs   int
	}{
		{otp.ReasonCooldown, time.Second, "otp.cooldown", 1},
		{otp.ReasonCooldown, 59*time.Second + time.Millisecond, "otp.cooldown", 60},
		{otp.ReasonCooldown, 60 * time.Second, "otp.cooldown", 60},
		{otp.ReasonCooldown, time.Millisecond, "otp.cooldown", 1},
		{otp.ReasonRateLimited, 10 * time.Minute, "otp.rate_limited", 600},
		{otp.ReasonRateLimited, 10*time.Minute + time.Nanosecond, "otp.rate_limited", 601},
		{otp.ReasonRateLimited, 17*time.Hour + 30*time.Minute, "otp.rate_limited", 63000},
	}
	for _, tt := range tests {
		t.Run(tt.code+"/"+tt.after.String(), func(t *testing.T) {
			rec, b := problemFor(t, &otp.RetryError{Reason: tt.reason, RetryAfter: tt.after})
			if rec.Code != http.StatusTooManyRequests || b.Code != tt.code {
				t.Fatalf("got %d %q, want 429 %q", rec.Code, b.Code, tt.code)
			}
			if got := rec.Header().Get("Retry-After"); got != strconv.Itoa(tt.secs) {
				t.Errorf("Retry-After = %q, want %d", got, tt.secs)
			}
			if b.RetryAfterSeconds != tt.secs {
				t.Errorf("retry_after_seconds = %d, want %d", b.RetryAfterSeconds, tt.secs)
			}
		})
	}
}

func TestProblemFor_BR_CLI_04_UnknownErrorsAreAGenericFiveHundredWithoutDetail(t *testing.T) {
	secret := errors.New("pq: duplicate key value violates unique constraint (ravi@example.com, 482913)")
	rec, b := problemFor(t, secret)
	if rec.Code != 500 || b.Code != "internal" {
		t.Fatalf("got %d %q, want 500 internal", rec.Code, b.Code)
	}
	for _, leak := range []string{"ravi@example.com", "482913", "duplicate key", "pq:"} {
		if strings.Contains(rec.Body.String(), leak) {
			t.Errorf("body leaks %q: %s", leak, rec.Body.String())
		}
	}
}

// D-08, FR-009: whatever the wrapped error says (contacts, codes), the response never repeats it.
func TestProblemFor_BR_CLI_04_NeverEchoesWrappedText(t *testing.T) {
	for _, base := range []error{otp.ErrCodeWrong, otp.ErrNumberMismatch, otp.ErrContactUnavailable, otp.ErrProofStale,
		&otp.RetryError{Reason: otp.ReasonCooldown, RetryAfter: time.Second}} {
		rec, _ := problemFor(t, fmt.Errorf("user ravi@example.com +919812345678 code 482913 handle ovh_abc: %w", base))
		for _, leak := range []string{"ravi@example.com", "+919812345678", "482913", "ovh_abc"} {
			if strings.Contains(rec.Body.String(), leak) {
				t.Errorf("%v: body leaks %q: %s", base, leak, rec.Body.String())
			}
			for k, v := range rec.Header() {
				if strings.Contains(strings.Join(v, ","), leak) {
					t.Errorf("%v: header %s leaks %q", base, k, leak)
				}
			}
		}
	}
}

func TestProblemFor_BR_CLI_04_PolicyNumbersAreTheSpecs(t *testing.T) {
	if otp.CodeTTL != 10*time.Minute || otp.MaxWrongAttempts != 5 || otp.ResendCooldown != 60*time.Second ||
		otp.VerificationTTL != 24*time.Hour || otp.ProofMaxAge != 5*time.Minute || otp.ResetTokenTTL != 10*time.Minute {
		t.Fatal("a policy constant drifted from D-01..D-04, FR-001, FR-008")
	}
}
