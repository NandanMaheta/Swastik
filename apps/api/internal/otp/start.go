package otp

import (
	"context"

	"github.com/google/uuid"

	"github.com/NandanMaheta/swastik/apps/api/internal/platform/audit"
)

// Start begins a verification for a user: signup needs a pending_verification client (else
// ErrNotAllowed) and targets the account email and mobile; it supersedes the user's open flow of
// the same purpose and queues the first email code, subject to the D-03 limits (*RetryError). A
// bad contact is ErrInvalidInput. It joins the caller's transaction.
func (s *Service) Start(_ context.Context, _ StartInput, _ audit.Actor) (Started, error) {
	return Started{}, errNotImplemented
}

// Cancel ends the live code of a verification and withdraws its email.
func (s *Service) Cancel(_ context.Context, _ uuid.UUID, _ audit.Actor) error {
	return errNotImplemented
}

// Get returns a verification with its readable targets (in-process only).
func (s *Service) Get(_ context.Context, _ uuid.UUID) (View, error) {
	return View{}, errNotImplemented
}

// Status returns the state of the verification behind handle.
func (s *Service) Status(_ context.Context, _ Caller, _ string) (View, error) {
	return View{}, errNotImplemented
}
