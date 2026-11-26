// Package otp proves that a client controls an email (a 6-digit code sent through the outbox) or
// a mobile (a Firebase phone sign-in ID token), for sign-up (005), contact changes (007), forgot
// password and the client app (024). Feature 004; rules BR-CLI-04 and BR-CLI-05.
//
// This file set is the compile skeleton (slice S01): exported names and signatures only; every
// body returns errNotImplemented or panics until its slice lands.
package otp

import (
	"context"
	"errors"
	"log/slog"
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
)

var errNotImplemented = errors.New("otp: not implemented")

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
	d Deps
}

// New builds the service.
func New(d Deps) (*Service, error) { return &Service{d: d}, errNotImplemented }
