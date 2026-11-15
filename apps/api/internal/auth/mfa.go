package auth

import (
	"context"
	"fmt"
)

// Compile stub (S15, test-engineer): the exported shape of the admin second-factor flow that the
// S15/S17 tests are written against. S16 replaces the method bodies; the signatures and the
// documented behaviour are what the tests pin (plan P-05, US-5).

// ErrInvalidChallenge is every failure of the interim challenge proof at the service level: unknown,
// expired, already consumed, wrong purpose, or the user is no longer an active admin. It never
// names the cause; the HTTP layer answers it as auth.unauthenticated.
var ErrInvalidChallenge = errInvalidChallenge

// MFAVerifyInput completes the second factor of a sign-in. ChallengeToken is the raw dmc_ token
// from the Authorization header. Exactly one of Code and RecoveryCode is set. IP is the resolved
// client address.
type MFAVerifyInput struct {
	ChallengeToken string
	Code           string
	RecoveryCode   string
	IP             string
}

// TOTPEnrolment is a new authenticator secret, shown once.
type TOTPEnrolment struct {
	Secret     string // base32, no padding
	OTPAuthURI string
}

// EnrolmentConfirmInput confirms enrolment with a code from the pending secret.
type EnrolmentConfirmInput struct {
	ChallengeToken string
	Code           string
	IP             string
}

// EnrolmentResult is a completed enrolment: the admin session and the 10 recovery codes, shown once.
type EnrolmentResult struct {
	Session       SessionTokens
	RecoveryCodes []string
}

// VerifyMFA completes an admin sign-in with a TOTP code or a recovery code (P-05). A wrong or
// replayed code, or a locked account, is ErrInvalidCredentials (a wrong code counts toward the
// lockout); a bad challenge is ErrInvalidChallenge. On success the challenge is consumed, the
// session is created with its first refresh token, the sign-in counter is cleared and
// auth.sign_in.succeeded (mfa_method totp or recovery_code) is audited.
func (s *Service) VerifyMFA(_ context.Context, _ MFAVerifyInput) (SessionTokens, error) {
	return SessionTokens{}, fmt.Errorf("verify mfa: %w", errNotImplemented)
}

// StartEnrolment creates (or replaces) the pending authenticator secret of the challenge's admin.
// The challenge must have purpose enrol (ErrInvalidChallenge otherwise) and is not consumed.
func (s *Service) StartEnrolment(_ context.Context, _ string) (TOTPEnrolment, error) {
	return TOTPEnrolment{}, fmt.Errorf("start enrolment: %w", errNotImplemented)
}

// ConfirmEnrolment confirms the pending secret with a valid code, stores it as the authenticator,
// issues 10 recovery codes and opens the admin session, consuming the challenge. ErrNoPendingSecret
// when there is no pending secret; ErrInvalidCredentials for a wrong code (nothing consumed).
func (s *Service) ConfirmEnrolment(_ context.Context, _ EnrolmentConfirmInput) (EnrolmentResult, error) {
	return EnrolmentResult{}, fmt.Errorf("confirm enrolment: %w", errNotImplemented)
}
