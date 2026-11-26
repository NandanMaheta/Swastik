package otp

import (
	"context"

	"github.com/NandanMaheta/swastik/apps/api/internal/outbox"
	"github.com/NandanMaheta/swastik/apps/api/internal/platform/audit"
)

type sender struct{ s *Service }

func (sender) Send(_ context.Context, _ outbox.Envelope) error { return errNotImplemented }

// Sender returns the outbox.Sender for TopicEmailCode and TopicContactNotice (maxAttempts 3). It
// opens the sealed payload, skips expired codes and sends through Deps.Mailer.
func (s *Service) Sender() outbox.Sender { return sender{s: s} }

// NotifyOldContact queues the notice to the old email that a contact is being changed (FR-014).
// It respects quiet hours and carries no code and no new contact.
func (s *Service) NotifyOldContact(_ context.Context, _ ContactNotice, _ audit.Actor) error {
	return errNotImplemented
}
