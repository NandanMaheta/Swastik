// Package otptest holds test helpers of the otp module: a recording fake mailer, a Firebase token
// minter with a local JWKS server and an environment builder. Skeleton (S01); bodies arrive with
// the test slices.
package otptest

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/NandanMaheta/swastik/apps/api/internal/platform/email"
)

var errNotImplemented = errors.New("otptest: not implemented")

// Mailer is a fake email.Mailer that records what it was asked to send.
type Mailer struct {
	Sent    []email.Mail
	FailErr error // returned instead of recording when set
}

// Send implements email.Mailer.
func (m *Mailer) Send(_ context.Context, _ email.Mail) error { return errNotImplemented }

// Claims are the Firebase ID token claims a test wants to mint.
type Claims struct {
	Subject, PhoneNumber, SignInProvider string
	AuthTime, IssuedAt, Expires          time.Time
	Issuer, Audience                     string // empty = the test project's
}

// Minter mints RS256 Firebase-style ID tokens and serves their public key as a JWKS.
type Minter struct {
	ProjectID string
	JWKSURL   string
}

// NewMinter starts a local JWKS server (closed with t.Cleanup).
func NewMinter(_ testing.TB, projectID string) *Minter { return &Minter{ProjectID: projectID} }

// Token signs c.
func (m *Minter) Token(_ testing.TB, _ Claims) string { panic(errNotImplemented) }
