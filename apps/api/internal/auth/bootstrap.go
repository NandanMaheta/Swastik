package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/NandanMaheta/swastik/apps/api/internal/platform/audit"
	"github.com/NandanMaheta/swastik/apps/api/internal/platform/clock"
	"github.com/NandanMaheta/swastik/apps/api/internal/platform/db"
)

// The service part of `swastik admin create` (FR-080, P-13).
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

// defaultOrgName names the organisation created when none exists.
const defaultOrgName = "Swastik"

// CreateAdmin checks the password policy and hashes it first, then in one transaction under a
// pg_advisory_xact_lock: resolves or creates the org, refuses when an admin exists
// (ErrAdminExists) or several orgs exist without an OrgID (ErrOrgAmbiguous) or the email or
// mobile is taken (ErrEmailTaken, ErrMobileTaken), inserts the active admin (email verified now,
// no authenticator) and audits auth.admin.bootstrapped with the system actor.
func (b *Bootstrapper) CreateAdmin(ctx context.Context, in BootstrapInput) (BootstrapResult, error) {
	email, err := NormalizeEmail(in.Email)
	if err != nil {
		return BootstrapResult{}, err
	}
	mobile := ""
	if strings.TrimSpace(in.Mobile) != "" {
		if mobile, err = NormalizeMobile(in.Mobile); err != nil {
			return BootstrapResult{}, err
		}
	}
	name := strings.TrimSpace(in.Name)
	if name == "" {
		return BootstrapResult{}, errors.New("auth: the admin needs a name")
	}
	if err := CheckPolicy(in.Password, email, mobile); err != nil {
		return BootstrapResult{}, err
	}
	phc, err := b.d.Hasher.Hash(ctx, NormalizePassword(in.Password))
	if err != nil {
		return BootstrapResult{}, fmt.Errorf("auth: hash password: %w", err)
	}

	var res BootstrapResult
	err = b.d.Tx.InTx(ctx, func(ctx context.Context) error {
		if err := b.d.Store.LockBootstrap(ctx); err != nil {
			return err
		}
		now := b.d.Now()
		org, err := b.resolveOrg(ctx, in, now)
		if err != nil {
			return err
		}
		admins, err := b.d.Store.LockAdmins(ctx, org)
		if err != nil {
			return fmt.Errorf("auth: lock admins: %w", err)
		}
		if len(admins) > 0 {
			return ErrAdminExists
		}
		u, err := b.d.Store.CreateUser(ctx, NewUser{
			OrgID: org, Role: roleAdmin, Status: StatusActive, Name: name, Email: email, Mobile: mobile,
			EmailVerifiedAt: &now, PasswordHash: phc, Now: now,
		})
		if err != nil {
			return err
		}
		err = audit.Write(ctx, audit.Entry{
			OrgID: org, Actor: systemActor, Entity: EntityUser, EntityID: u.ID, Action: ActionAdminBootstrapped,
			After: AdminBootstrappedAfter{Email: email, OrgID: org}, At: now,
		})
		if err != nil {
			return fmt.Errorf("auth: audit bootstrap: %w", err)
		}
		res = BootstrapResult{UserID: u.ID, OrgID: org, Email: email}
		return nil
	})
	if err != nil {
		return BootstrapResult{}, err
	}
	return res, nil
}

// resolveOrg is the org rule of contracts/cli.md: an explicit OrgID must exist; otherwise the only
// org is used, none is created, and several are ErrOrgAmbiguous.
func (b *Bootstrapper) resolveOrg(ctx context.Context, in BootstrapInput, now time.Time) (uuid.UUID, error) {
	if in.OrgID != uuid.Nil {
		ok, err := b.d.Store.OrgExists(ctx, in.OrgID)
		switch {
		case err != nil:
			return uuid.Nil, err
		case !ok:
			return uuid.Nil, ErrNoOrg
		}
		return in.OrgID, nil
	}
	org, err := b.d.Store.DefaultOrg(ctx)
	switch {
	case err == nil:
		return org, nil
	case errors.Is(err, ErrMultipleOrgs):
		return uuid.Nil, ErrOrgAmbiguous
	case !errors.Is(err, ErrNoOrg):
		return uuid.Nil, err
	}
	name := strings.TrimSpace(in.OrgName)
	if name == "" {
		name = defaultOrgName
	}
	return b.d.Store.CreateOrg(ctx, name, now)
}
