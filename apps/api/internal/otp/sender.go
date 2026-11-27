package otp

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/NandanMaheta/swastik/apps/api/internal/auth"
	"github.com/NandanMaheta/swastik/apps/api/internal/outbox"
	"github.com/NandanMaheta/swastik/apps/api/internal/platform/audit"
	"github.com/NandanMaheta/swastik/apps/api/internal/platform/email"
)

type sender struct{ s *Service }

// Send opens the sealed message and mails it. A code that has expired is not sent and not
// counted: it returns nil, so the outbox marks the message sent and erases it. A provider error
// is counted and returned, so the relay retries until the message expires. Nothing here logs or
// returns the recipient, the code or the payload.
func (snd sender) Send(ctx context.Context, env outbox.Envelope) error {
	s := snd.s
	c, err := s.open(env)
	if err != nil {
		return err
	}
	if c.ExpiresAt != "" {
		exp, err := time.Parse(time.RFC3339Nano, c.ExpiresAt)
		if err == nil && !s.now().Before(exp) {
			return nil
		}
	}
	var mail email.Mail
	switch env.Topic {
	case TopicContactNotice:
		mail = noticeMail(c.To, c.Changed)
	default:
		mail = codeMail(c.To, c.Code, c.Purpose)
	}
	mail.IdempotencyKey = env.DedupeKey
	org := env.OrgID
	if err := s.d.Mailer.Send(ctx, mail); err != nil {
		s.countMail(ctx, org, MetricEmailFailed)
		return fmt.Errorf("otp: send %s: %w", env.Topic, err)
	}
	s.countMail(ctx, org, MetricEmailSent)
	return nil
}

// countMail is best effort: a counter that cannot be written is logged, never fatal.
func (s *Service) countMail(ctx context.Context, org uuid.UUID, m Metric) {
	err := s.d.Tx.InTx(context.WithoutCancel(ctx), func(ctx context.Context) error { return s.bump(ctx, org, m) })
	if err != nil {
		s.log.WarnContext(ctx, "otp: counting a delivery failed", "metric", string(m), "err", err)
	}
}

// Sender returns the outbox.Sender for TopicEmailCode and TopicContactNotice (maxAttempts 3). It
// opens the sealed payload, skips expired codes and sends through Deps.Mailer.
func (s *Service) Sender() outbox.Sender { return sender{s: s} }

// NotifyOldContact queues the notice to the old email that a contact is being changed (FR-014).
// It respects quiet hours and carries no code and no new contact.
func (s *Service) NotifyOldContact(ctx context.Context, n ContactNotice, by audit.Actor) error {
	to, err := auth.NormalizeEmail(n.OldEmail)
	if err != nil || n.OrgID == uuid.Nil || n.UserID == uuid.Nil || (n.Changed != "email" && n.Changed != "mobile") {
		return ErrInvalidInput
	}
	id, err := uuid.NewV7()
	if err != nil {
		return fmt.Errorf("otp: notice id: %w", err)
	}
	key := "otp:notice:" + id.String()
	box, err := s.seal(TopicContactNotice, key, mailContent{To: to, Changed: n.Changed})
	if err != nil {
		return err
	}
	expires := s.now().Add(noticeTTL)
	user := n.UserID
	return s.d.Tx.InTx(ctx, func(ctx context.Context) error {
		if _, err := s.d.Outbox.Add(ctx, outbox.Message{
			OrgID: n.OrgID, Topic: TopicContactNotice, Recipient: outbox.Recipient{Kind: "client", ID: &user},
			Subject: "otp:user:" + n.UserID.String(), DedupeKey: key, Payload: box, ExpiresAt: &expires, SensitivePayload: true,
		}); err != nil {
			return fmt.Errorf("otp: queue notice: %w", err)
		}
		return s.record(ctx, n.OrgID, by, n.UserID, "otp.notice.queued", auditAfter{Outcome: "queued", Reason: n.Changed})
	})
}
