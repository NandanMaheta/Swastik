package otp

import (
	"errors"
	"time"
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
func ProblemFor(_ error) error { panic(errNotImplemented) }
