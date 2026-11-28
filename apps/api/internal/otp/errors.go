package otp

import (
	"errors"
	"net/http"
	"time"

	"github.com/NandanMaheta/swastik/apps/api/internal/platform/httpx"
)

// Sentinel errors (contracts/error-codes.md). Details never carry a contact, code, handle, token
// or proof.
var (
	ErrNotFound            = errors.New("otp: verification not found")
	ErrVerificationExpired = errors.New("otp: verification expired")
	ErrNothingToSend       = errors.New("otp: nothing to send")
	ErrCodeWrong           = errors.New("otp: code wrong")
	ErrCodeExpired         = errors.New("otp: code expired")
	ErrCodeUsedUp          = errors.New("otp: code used up")
	ErrEmailFirst          = errors.New("otp: verify email first")
	ErrProofInvalid        = errors.New("otp: proof invalid")
	ErrProofStale          = errors.New("otp: proof stale")
	ErrProofReplayed       = errors.New("otp: proof replayed")
	ErrNumberMismatch      = errors.New("otp: number mismatch")
	ErrContactUnavailable  = errors.New("otp: contact unavailable")
	ErrResetTokenInvalid   = errors.New("otp: reset token invalid")
	ErrNotConfigured       = errors.New("otp: not configured")

	// Go-only, for service callers 005 and 007 (never HTTP).
	ErrNotAllowed   = errors.New("otp: not allowed for this user")
	ErrInvalidInput = errors.New("otp: invalid input")
)

// RetryReason says why a send was refused.
type RetryReason string

// Refusal reasons (audit reasons too).
const (
	ReasonCooldown    RetryReason = "cooldown"
	ReasonRateLimited RetryReason = "rate_limited"
)

// RetryError is a refusal that clears with time (D-03): otp.cooldown or otp.rate_limited.
type RetryError struct {
	Reason     RetryReason
	RetryAfter time.Duration
}

func (e *RetryError) Error() string { return "otp: " + string(e.Reason) }

// ProblemFor maps an otp error to an HTTP problem with a stable code; RetryError becomes a 429
// with Retry-After rounded up to whole seconds. Unknown errors become a generic 500.
func ProblemFor(err error) error {
	var re *RetryError
	if errors.As(err, &re) {
		detail := "Please wait before asking for a new code."
		code := "otp.cooldown"
		if re.Reason == ReasonRateLimited {
			code, detail = "otp.rate_limited", "Too many codes were requested. Please try again later."
		}
		return httpx.ProblemRetry(http.StatusTooManyRequests, code, detail, re.RetryAfter)
	}
	for _, m := range problemTable {
		if errors.Is(err, m.err) {
			return httpx.Problem(m.status, m.code, m.detail)
		}
	}
	return httpx.Problem(http.StatusInternalServerError, "internal", "An unexpected error occurred.")
}

// problemTable is contracts/error-codes.md. Details are fixed text: never the wrapped error.
var problemTable = []struct {
	err    error
	status int
	code   string
	detail string
}{
	{ErrNotFound, http.StatusNotFound, "otp.verification_invalid", "This verification is not valid. Please start again."},
	{ErrVerificationExpired, http.StatusGone, "otp.verification_expired", "This verification has expired. Please start again."},
	{ErrNothingToSend, http.StatusConflict, "otp.nothing_to_send", "There is nothing to send for this step."},
	{ErrCodeWrong, http.StatusUnprocessableEntity, "otp.code_wrong", "That code is not correct. Please check it and try again."},
	{ErrCodeExpired, http.StatusUnprocessableEntity, "otp.code_expired", "That code has expired. Ask for a new one."},
	{ErrCodeUsedUp, http.StatusUnprocessableEntity, "otp.code_used_up", "Too many wrong tries. Ask for a new code."},
	{ErrEmailFirst, http.StatusConflict, "otp.email_first", "Please verify your email first."},
	{ErrProofInvalid, http.StatusUnprocessableEntity, "otp.proof_invalid", "We could not confirm your mobile number. Please try again."},
	{ErrProofStale, http.StatusUnprocessableEntity, "otp.proof_stale", "That confirmation is too old. Please request a new SMS code."},
	{ErrProofReplayed, http.StatusUnprocessableEntity, "otp.proof_replayed", "That confirmation was already used. Please request a new SMS code."},
	{ErrNumberMismatch, http.StatusUnprocessableEntity, "otp.number_mismatch", "The number you confirmed is different from the one on your account."},
	{ErrContactUnavailable, http.StatusConflict, "otp.contact_unavailable", "This email or mobile number cannot be used. Please choose another."},
	{ErrResetTokenInvalid, http.StatusUnprocessableEntity, "otp.reset_token_invalid", "This reset link has expired or was already used. Please start again."},
	{ErrNotConfigured, http.StatusServiceUnavailable, "otp.not_configured", "This step is not available right now. Please try again later."},
}
