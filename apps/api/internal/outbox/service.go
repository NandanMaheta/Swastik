package outbox

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/NandanMaheta/swastik/apps/api/internal/platform/clock"
	"github.com/NandanMaheta/swastik/apps/api/internal/platform/db"
	"github.com/NandanMaheta/swastik/apps/api/internal/platform/db/dbgen"
)

// Sentinel errors; callers match them with errors.Is.
var (
	ErrInvalid  = errors.New("outbox: invalid input")
	ErrNotFound = errors.New("outbox: not found")
	ErrConflict = errors.New("outbox: conflict")
)

// Recipient addresses a message: a client user, or admins (ID nil means every admin of the org).
type Recipient struct {
	Kind string // "client" (ID required) | "admin"
	ID   *uuid.UUID
}

// Message is what an owning feature records with Add.
type Message struct {
	OrgID                uuid.UUID
	Topic                string // "<audience>.<event>", e.g. "task.reminder"
	Recipient            Recipient
	Subject              string // business item, e.g. "task:<id>"; used to withdraw by item
	DedupeKey            string
	Payload              any  // content reference; never PAN, tokens or secrets
	ExemptFromQuietHours bool // zero value respects quiet hours (FR-031)
	ExpiresAt            *time.Time
	MaxAttempts          int // 0 = the topic default, else the global default
	// SensitivePayload marks a payload that carries a secret (an OTP code, sealed): it is erased
	// when the message reaches sent, dead, withdrawn or expired, and admin retry is refused.
	SensitivePayload bool
}

// Envelope is what a Sender receives.
type Envelope struct {
	ID        uuid.UUID
	OrgID     uuid.UUID
	Topic     string
	Recipient Recipient
	Subject   string
	DedupeKey string
	Payload   []byte
	Attempt   int
	CreatedAt time.Time
}

// Sender delivers one message. It must treat DedupeKey as an idempotency key: a crash between
// Send and the "sent" mark makes the relay send the same message again (FR-026).
type Sender interface {
	Send(ctx context.Context, e Envelope) error
}

// Options tunes the service; DefaultOptions holds the production values (data-model section 7).
type Options struct {
	Lease              time.Duration // how long a claim is valid before another relay may take over
	SendTimeout        time.Duration // bound on one Sender.Send call
	DefaultMaxAttempts int
	Instance           string // diagnostics only (locked_by)
}

// DefaultOptions returns lease 60 s, send timeout 5 s and 8 attempts.
func DefaultOptions() Options {
	host, err := os.Hostname()
	if err != nil || host == "" {
		host = "unknown"
	}
	return Options{Lease: 60 * time.Second, SendTimeout: 5 * time.Second, DefaultMaxAttempts: 8, Instance: host}
}

type registration struct {
	sender      Sender
	maxAttempts int
}

// Service records, withdraws and relays outbox messages.
type Service struct {
	txr  db.TxRunner
	now  clock.Func
	log  *slog.Logger
	opts Options

	mu      sync.RWMutex
	senders map[string]registration
}

// New builds the service. now is the only source of time.
func New(txr db.TxRunner, now clock.Func, log *slog.Logger, opts Options) *Service {
	return &Service{txr: txr, now: now, log: log, opts: opts, senders: map[string]registration{}}
}

// RegisterSender sets the sender for a topic and its default attempt limit (0 = the global
// default). It is called at wiring time; registering a topic again replaces the earlier sender.
func (s *Service) RegisterSender(topic string, snd Sender, maxAttempts int) {
	if topic == "" || snd == nil {
		panic("outbox: RegisterSender needs a topic and a sender")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.senders[topic] = registration{sender: snd, maxAttempts: maxAttempts}
}

func (s *Service) registrationFor(topic string) (registration, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.senders[topic]
	return r, ok
}

// DeliverNow sends the one pending, available, unexpired message (org, topic, key) during the
// caller's request, with the same fenced claim as the relay. It returns false when the message is
// absent, claimed elsewhere, expired or the send failed (a failure is recorded as a normal failed
// attempt). It refuses to run inside a transaction.
func (s *Service) DeliverNow(ctx context.Context, org uuid.UUID, topic, key string) (sent bool, err error) {
	if _, err := db.MustTx(ctx); err == nil {
		return false, errors.New("outbox: DeliverNow must not run inside a transaction")
	}
	q := dbgen.New(s.txr.Conn(ctx))
	now := s.now()
	msg, err := q.ClaimMessageByKey(ctx, dbgen.ClaimMessageByKeyParams{
		OrgID: org, Topic: topic, DedupeKey: key,
		Now:         db.Timestamptz(now),
		LockedUntil: db.Timestamptz(now.Add(s.opts.Lease)),
		LockedBy:    db.Text(s.opts.Instance),
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("outbox: claim %s: %w", topic, err)
	}
	var sum RelaySummary
	if err := s.deliver(ctx, q, msg, &sum); err != nil {
		return false, err
	}
	return sum.Sent == 1, nil
}

// Add records m in the caller's transaction, so it commits or vanishes with the business change.
// A message whose (org, topic, dedupe key) was already recorded, in any state, is ignored and
// Add returns (false, nil). Invalid input returns ErrInvalid before any SQL runs.
func (s *Service) Add(ctx context.Context, m Message) (bool, error) {
	tx, err := db.MustTx(ctx)
	if err != nil {
		return false, fmt.Errorf("outbox: add %s: %w", m.Topic, err)
	}
	payload, err := validate(m)
	if err != nil {
		return false, err
	}
	now := s.now()
	respects := !m.ExemptFromQuietHours
	availableAt, err := s.availableAt(ctx, m.OrgID, respects, now)
	if err != nil {
		return false, err
	}
	var recipient uuid.NullUUID
	if m.Recipient.ID != nil {
		recipient = uuid.NullUUID{UUID: *m.Recipient.ID, Valid: true}
	}
	n, err := dbgen.New(tx).InsertMessage(ctx, dbgen.InsertMessageParams{
		OrgID:              m.OrgID,
		Topic:              m.Topic,
		RecipientKind:      m.Recipient.Kind,
		RecipientID:        recipient,
		Subject:            m.Subject,
		DedupeKey:          m.DedupeKey,
		Payload:            payload,
		SensitivePayload:   m.SensitivePayload,
		RespectsQuietHours: respects,
		AvailableAt:        db.Timestamptz(availableAt),
		ExpiresAt:          db.NullTimestamptz(m.ExpiresAt),
		MaxAttempts:        int32(s.maxAttemptsFor(m)), //nolint:gosec // validated to 1..50 in validate/maxAttemptsFor
		Now:                db.Timestamptz(now),
	})
	if err != nil {
		return false, fmt.Errorf("outbox: add %s: %w", m.Topic, err)
	}
	return n == 1, nil
}

// Withdraw stops the pending message with this key (stop on completion). A message that is
// being sent, or is finished, is left alone. It returns how many messages were withdrawn.
func (s *Service) Withdraw(ctx context.Context, org uuid.UUID, topic, key string) (int, error) {
	tx, err := db.MustTx(ctx)
	if err != nil {
		return 0, fmt.Errorf("outbox: withdraw %s: %w", topic, err)
	}
	n, err := dbgen.New(tx).WithdrawByKey(ctx, dbgen.WithdrawByKeyParams{
		Now: db.Timestamptz(s.now()), OrgID: org, Topic: topic, DedupeKey: key,
	})
	if err != nil {
		return 0, fmt.Errorf("outbox: withdraw %s: %w", topic, err)
	}
	return int(n), nil
}

// WithdrawSubject stops every pending message of one business item.
func (s *Service) WithdrawSubject(ctx context.Context, org uuid.UUID, subject string) (int, error) {
	tx, err := db.MustTx(ctx)
	if err != nil {
		return 0, fmt.Errorf("outbox: withdraw subject: %w", err)
	}
	n, err := dbgen.New(tx).WithdrawBySubject(ctx, dbgen.WithdrawBySubjectParams{
		Now: db.Timestamptz(s.now()), OrgID: org, Subject: subject,
	})
	if err != nil {
		return 0, fmt.Errorf("outbox: withdraw subject: %w", err)
	}
	return int(n), nil
}
