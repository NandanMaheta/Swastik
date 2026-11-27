// Package otp proves that a client controls an email (a 6-digit code sent through the outbox) or
// a mobile (a Firebase phone sign-in ID token), for sign-up (005), contact changes (007), forgot
// password and the client app (024). Feature 004; rules BR-CLI-04 and BR-CLI-05.
//
// Every state change and its audit entry share one transaction. Refusals that must leave a trace
// (wrong code, limit refused, bad proof) commit their counters and audit rows and then return the
// error. Nothing here logs or audits a contact, code, handle, token or proof (D-08).
package otp

import (
	"context"
	"crypto/rand"
	"errors"
	"io"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/NandanMaheta/swastik/apps/api/internal/auth"
	"github.com/NandanMaheta/swastik/apps/api/internal/outbox"
	"github.com/NandanMaheta/swastik/apps/api/internal/platform/audit"
	"github.com/NandanMaheta/swastik/apps/api/internal/platform/clock"
	"github.com/NandanMaheta/swastik/apps/api/internal/platform/crypto"
	"github.com/NandanMaheta/swastik/apps/api/internal/platform/db"
	"github.com/NandanMaheta/swastik/apps/api/internal/platform/email"
	"github.com/NandanMaheta/swastik/apps/api/internal/platform/firebaseauth"
	"github.com/NandanMaheta/swastik/apps/api/internal/platform/istdate"
)

// Policy numbers (spec D-01..D-04, FR-001); tests reference these, never literals.
const (
	CodeTTL          = 10 * time.Minute
	MaxWrongAttempts = 5
	ResendCooldown   = 60 * time.Second
	VerificationTTL  = 24 * time.Hour
	ProofMaxAge      = 5 * time.Minute
	ProofClockLeeway = 30 * time.Second
	ResetTokenTTL    = 10 * time.Minute

	TopicEmailCode     = "otp.email_code"
	TopicContactNotice = "otp.contact_notice"
	HousekeepingKind   = "otp.housekeeping"

	// responseFloor is the earliest a public send operation answers (plan I-3).
	responseFloor = 1500 * time.Millisecond
	noticeTTL     = 24 * time.Hour
)

// Accounts is the subset of auth.Accounts otp needs (satisfied by *auth.Service).
type Accounts interface {
	GetUser(ctx context.Context, id uuid.UUID) (auth.UserView, error)
	FindUser(ctx context.Context, identifier string) (auth.UserView, error)
	DefaultOrg(ctx context.Context) (uuid.UUID, error)
	MarkEmailVerified(ctx context.Context, id uuid.UUID, by audit.Actor) (auth.Status, error)
	MarkMobileVerified(ctx context.Context, id uuid.UUID, by audit.Actor) (auth.Status, error)
	ResetPassword(ctx context.Context, id uuid.UUID, newPassword string, by audit.Actor) error
}

// Outbox is the subset of *outbox.Service otp needs.
type Outbox interface {
	Add(ctx context.Context, m outbox.Message) (bool, error)
	Withdraw(ctx context.Context, org uuid.UUID, topic, key string) (int, error)
	WithdrawSubject(ctx context.Context, org uuid.UUID, subject string) (int, error)
	DeliverNow(ctx context.Context, org uuid.UUID, topic, key string) (bool, error)
}

var (
	_ Accounts = (*auth.Service)(nil)
	_ Outbox   = (*outbox.Service)(nil)
)

// Deps are the collaborators of the service.
type Deps struct {
	Tx       db.TxRunner
	Now      clock.Func
	Accounts Accounts
	Outbox   Outbox
	Keyring  *crypto.Keyring       // PII ring: seals outbox payloads (FR-013)
	Digests  crypto.BlindIndexer   // OTP_HMAC_KEY: codes, limits, proof fingerprints (D-08)
	Proofs   firebaseauth.Verifier // nil or Disabled() => ErrNotConfigured on mobile proofs
	Mailer   email.Mailer          // used by the outbox Sender
	Log      *slog.Logger
	Wait     func(ctx context.Context, until time.Time) // response floor; nil = real timer
}

// Service is the OTP module.
type Service struct {
	d   Deps
	st  Store
	log *slog.Logger

	orgMu sync.Mutex
	org   uuid.UUID
}

// New builds the service. Missing collaborators are a wiring error.
func New(d Deps) (*Service, error) {
	switch {
	case d.Now == nil:
		return nil, errors.New("otp: Deps.Now is required")
	case d.Accounts == nil:
		return nil, errors.New("otp: Deps.Accounts is required")
	case d.Outbox == nil:
		return nil, errors.New("otp: Deps.Outbox is required")
	case d.Keyring == nil:
		return nil, errors.New("otp: Deps.Keyring is required")
	}
	if d.Mailer == nil {
		d.Mailer = email.Discard()
	}
	log := d.Log
	if log == nil {
		log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return &Service{d: d, st: NewPGStore(d.Tx), log: log}, nil
}

func (s *Service) now() time.Time { return s.d.Now() }

// orgID is the one organisation of the deployment, looked up once.
func (s *Service) orgID(ctx context.Context) (uuid.UUID, error) {
	s.orgMu.Lock()
	defer s.orgMu.Unlock()
	if s.org != uuid.Nil {
		return s.org, nil
	}
	id, err := s.d.Accounts.DefaultOrg(ctx)
	if err != nil {
		return uuid.Nil, err
	}
	s.org = id
	return id, nil
}

// wait holds a public send operation until the response floor.
func (s *Service) wait(ctx context.Context, until time.Time) {
	if s.d.Wait != nil {
		s.d.Wait(ctx, until)
		return
	}
	d := until.Sub(s.now())
	if d <= 0 {
		return
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
	case <-ctx.Done():
	}
}

// ---- limits ----

func (s *Service) limitKey(scope LimitScope, key string) LimitKey {
	return LimitKey{Scope: scope, Subject: s.d.Digests.Index("otp.limit", []byte(string(scope)+"|"+key))}
}

// applyLimits locks the rows and applies every scope. On any refusal it returns the one with the
// longest wait and stores nothing; otherwise it stores every new event list.
func (s *Service) applyLimits(ctx context.Context, org uuid.UUID, keys []LimitKey, now time.Time) (*RetryError, error) {
	rows, err := s.st.LockLimits(ctx, org, keys)
	if err != nil {
		return nil, err
	}
	decisions := make([]LimitDecision, len(rows))
	var refusal *RetryError
	for i, row := range rows {
		decisions[i] = ApplyLimits(LimitInput{Scope: row.Key.Scope, Events: row.Events}, now)
		if d := decisions[i]; !d.Allowed && (refusal == nil || d.RetryAfter > refusal.RetryAfter) {
			refusal = &RetryError{Reason: d.Reason, RetryAfter: d.RetryAfter}
		}
	}
	if refusal != nil {
		return refusal, nil
	}
	for i, row := range rows {
		if err := s.st.SaveLimit(ctx, org, row.Key, decisions[i].Events, now); err != nil {
			return nil, err
		}
	}
	return nil, nil
}

// ---- counters and audit ----

func (s *Service) bump(ctx context.Context, org uuid.UUID, m Metric) error {
	now := s.now()
	return s.st.IncrementCount(ctx, org, istdate.DateOf(now), m, now)
}

// auditAfter is the After of every otp audit row: ids and reason codes only (D-08).
type auditAfter struct {
	VerificationID string `json:"verification_id,omitempty"`
	Purpose        string `json:"purpose,omitempty"`
	Outcome        string `json:"outcome,omitempty"`
	Reason         string `json:"reason,omitempty"`
	IP             string `json:"ip,omitempty"`
}

// record writes one audit row about a user; a decoy (user Nil) writes nothing.
func (s *Service) record(ctx context.Context, org uuid.UUID, by audit.Actor, user uuid.UUID, action string, a auditAfter) error {
	if user == uuid.Nil {
		return nil
	}
	return audit.Write(ctx, audit.Entry{
		OrgID: org, Actor: by, Entity: auth.EntityUser, EntityID: user, Action: action, After: a, At: s.now(),
	})
}

// settle records a refusal to return once the transaction has committed. The transaction itself
// succeeds, so the counters and audit rows written before the refusal are kept.
func settle(dst *error, refusal error) error {
	*dst = refusal
	return nil
}

func clientActor(user uuid.UUID) audit.Actor { return audit.Actor{ID: user, Kind: audit.KindClient} }

func randomReader() io.Reader { return rand.Reader }

// errNotImplemented is the body of the slices that land later (removed by S17).
var errNotImplemented = errors.New("otp: not implemented")
