package otp

import "context"

// VerifyMobile checks a Firebase phone sign-in ID token against the verification's mobile.
func (s *Service) VerifyMobile(_ context.Context, _ Caller, _, _ string) (View, error) {
	return View{}, errNotImplemented
}
