package auth

import (
	"context"
	"fmt"

	"github.com/NandanMaheta/swastik/apps/api/internal/platform/authz"
)

// Compile stub (S15, test-engineer): admin management of the second factor (FR-062, FR-063).

// Reauth is the re-authentication of a signed-in admin: the password plus exactly one of a current
// TOTP code and an unused recovery code.
type Reauth struct {
	Password     string
	Code         string
	RecoveryCode string
}

// RegenerateRecoveryCodes re-authenticates with the password and a current TOTP code, then issues a
// new set of 10 codes and revokes the previous set (auth.mfa.recovery_codes_regenerated). A wrong
// password or code, or a locked account, is ErrReauthFailed; wrong attempts count toward the
// lockout.
func (s *Service) RegenerateRecoveryCodes(_ context.Context, _ authz.Principal, _, _ string) ([]string, error) {
	return nil, fmt.Errorf("regenerate recovery codes: %w", errNotImplemented)
}

// StartAuthenticatorReplace re-authenticates (a recovery code is consumed and audited) and stores
// a new pending secret; the old one keeps working until the replacement is confirmed.
func (s *Service) StartAuthenticatorReplace(_ context.Context, _ authz.Principal, _ Reauth) (TOTPEnrolment, error) {
	return TOTPEnrolment{}, fmt.Errorf("start authenticator replace: %w", errNotImplemented)
}

// ConfirmAuthenticatorReplace swaps in the pending secret after a valid code from it, ends all
// other sessions of the admin (end_reason mfa_replaced) and audits auth.mfa.replaced.
// ErrNoPendingSecret without a pending secret; ErrReauthFailed for a wrong code.
func (s *Service) ConfirmAuthenticatorReplace(_ context.Context, _ authz.Principal, _ string) error {
	return fmt.Errorf("confirm authenticator replace: %w", errNotImplemented)
}
