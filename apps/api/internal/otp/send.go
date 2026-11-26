package otp

import (
	"context"

	"github.com/google/uuid"
)

// Deliver sends the live code email of a verification right away (outbox.DeliverNow). Call it
// after the transaction commits; it is a no-op when there is no live code and must not run in a
// transaction.
func (s *Service) Deliver(_ context.Context, _ uuid.UUID) error { return errNotImplemented }

// Resend issues a new code for the verification behind handle (cooldown and limits apply).
func (s *Service) Resend(_ context.Context, _ Caller, _ string) (ResendResult, error) {
	return ResendResult{}, errNotImplemented
}
