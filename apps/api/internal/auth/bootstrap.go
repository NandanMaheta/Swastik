package auth

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"

	"github.com/NandanMaheta/swastik/apps/api/internal/platform/clock"
	"github.com/NandanMaheta/swastik/apps/api/internal/platform/db"
)

// Compile stub (S15, test-engineer): the service part of `swastik admin create` (FR-080, P-13).
// It is independent of Service on purpose: the CLI has no JWT, PII or blind-index keys.

// Errors of the bootstrap (printed by the CLI as bootstrap.<code>).
var (
	ErrAdminExists  = errors.New("auth: an admin already exists in the organisation")       // bootstrap.admin_exists
	ErrOrgAmbiguous = errors.New("auth: more than one organisation, an org id is required") // bootstrap.org_ambiguous
)

// BootstrapDeps are the collaborators of the Bootstrapper.
type BootstrapDeps struct {
	Store  Store
	Tx     db.TxRunner
	Now    clock.Func
	Hasher *Hasher
}

// Bootstrapper creates the first admin of an organisation.
type Bootstrapper struct{ d BootstrapDeps }

// NewBootstrapper validates the dependencies.
func NewBootstrapper(d BootstrapDeps) (*Bootstrapper, error) {
	if d.Store == nil || d.Now == nil || d.Hasher == nil {
		return nil, errors.New("auth: BootstrapDeps needs Store, Now and Hasher")
	}
	return &Bootstrapper{d: d}, nil
}

// BootstrapInput is one bootstrap request. Email and Mobile are raw (normalised here); Password is
// raw and never logged. OrgID uuid.Nil means "the only org, or create one named OrgName
// (default Swastik) when none exists". Mobile may be empty.
type BootstrapInput struct {
	Email, Name, Mobile, Password string
	OrgName                       string
	OrgID                         uuid.UUID
}

// BootstrapResult is the created admin.
type BootstrapResult struct {
	UserID, OrgID uuid.UUID
	Email         string // normalised
}

// CreateAdmin checks the password policy and hashes it first, then in one transaction under a
// pg_advisory_xact_lock: resolves or creates the org, refuses when an admin exists
// (ErrAdminExists) or several orgs exist without an OrgID (ErrOrgAmbiguous) or the email or
// mobile is taken (ErrEmailTaken, ErrMobileTaken), inserts the active admin (email verified now,
// no authenticator) and audits auth.admin.bootstrapped with the system actor.
func (b *Bootstrapper) CreateAdmin(_ context.Context, _ BootstrapInput) (BootstrapResult, error) {
	return BootstrapResult{}, fmt.Errorf("create admin: %w", errNotImplemented)
}
