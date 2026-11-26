package otp

import "context"

// VerifyEmail checks the 6-digit code of the verification behind handle.
func (s *Service) VerifyEmail(_ context.Context, _ Caller, _, _ string) (VerifyEmailResult, error) {
	return VerifyEmailResult{}, errNotImplemented
}
