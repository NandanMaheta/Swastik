package otp

import "context"

// StartReset starts a password reset for an email or mobile identifier. The answer is the same
// for known and unknown identifiers (decoys, D-06, D-07).
func (s *Service) StartReset(_ context.Context, _, _ string) (ResetStarted, error) {
	return ResetStarted{}, errNotImplemented
}

// CompleteReset sets a new password once the reset token proves the code was entered.
func (s *Service) CompleteReset(_ context.Context, _, _, _, _ string) error {
	return errNotImplemented
}
