package auth_test

// Feature 004 (S08): auth.Service.FindUser and DefaultOrg, the additive capabilities otp needs
// (contracts/go-module-api.md section 5; BR-CLI-04 sign-up, D-06/D-07 reset by email or mobile).
// FindUser normalises the identifier (auth.NormalizeIdentifier), returns the read-only UserView
// (no secrets) of the user with that email or mobile in any status and role, and writes nothing.
// ErrInvalidIdentifier for a malformed identifier, ErrUserNotFound for an unknown one; errors never
// echo the input. DefaultOrg is the one organisation (ErrNoOrg when none, ErrMultipleOrgs).

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/NandanMaheta/swastik/apps/api/internal/auth"
	"github.com/NandanMaheta/swastik/apps/api/internal/auth/authtest"
)

func TestFindUser_BR_CLI_04_ByEmailInAnyWrittenForm(t *testing.T) {
	e := authtest.New(t)
	s := e.Service(t)
	u := e.NewUser(t, authtest.UserSpec{Email: "ravi.shah@example.com", Mobile: "+919812345678", Status: auth.StatusPendingVerification})

	for _, in := range []string{"ravi.shah@example.com", "Ravi.Shah@Example.COM", "  ravi.shah@example.com\t"} {
		v, err := s.FindUser(t.Context(), in)
		if err != nil {
			t.Fatalf("FindUser(%q): %v", in, err)
		}
		if v.ID != u.ID || v.OrgID != e.Org || v.Email != "ravi.shah@example.com" || v.Mobile != "+919812345678" {
			t.Errorf("FindUser(%q) = %+v, want user %v", in, v, u.ID)
		}
		if v.Role != "client" || v.Status != auth.StatusPendingVerification || v.EmailVerified || v.MobileVerified {
			t.Errorf("FindUser(%q) view = role %q status %q verified %v/%v", in, v.Role, v.Status, v.EmailVerified, v.MobileVerified)
		}
	}
}

func TestFindUser_BR_CLI_04_ByMobileInAnyWrittenForm(t *testing.T) {
	e := authtest.New(t)
	s := e.Service(t)
	u := e.NewUser(t, authtest.UserSpec{Email: "a@example.com", Mobile: "+919812345678"})
	for _, in := range []string{"+919812345678", "9812345678", "98123 45678", "98123-45678", "+91 98123 45678", "919812345678", "09812345678"} {
		v, err := s.FindUser(t.Context(), in)
		if err != nil {
			t.Fatalf("FindUser(%q): %v", in, err)
		}
		if v.ID != u.ID {
			t.Errorf("FindUser(%q) = user %v, want %v", in, v.ID, u.ID)
		}
	}
}

func TestFindUser_BR_CLI_04_FindsEveryStatusAndAdminsByEmail(t *testing.T) {
	e := authtest.New(t)
	s := e.Service(t)
	for _, st := range []auth.Status{auth.StatusPendingVerification, auth.StatusPendingApproval, auth.StatusActive, auth.StatusDisabled} {
		u := e.UserWithStatus(t, st)
		v, err := s.FindUser(t.Context(), u.Email)
		if err != nil || v.ID != u.ID || v.Status != st {
			t.Errorf("status %s: FindUser = %+v, %v, want the user with that status", st, v, err)
		}
	}
	a := e.NewAdmin(t)
	v, err := s.FindUser(t.Context(), a.Email)
	if err != nil || v.ID != a.ID || v.Role != "admin" {
		t.Errorf("admin: FindUser = %+v, %v, want the admin (otp, not auth, excludes admins from resets)", v, err)
	}
}

func TestFindUser_BR_CLI_04_UnknownAndInvalidIdentifiers(t *testing.T) {
	e := authtest.New(t)
	s := e.Service(t)
	e.NewUser(t, authtest.UserSpec{Email: "known@example.com", Mobile: "+919812345678"})

	for _, in := range []string{"nobody@example.com", "+919812345679", "9000000000"} {
		if _, err := s.FindUser(t.Context(), in); !errors.Is(err, auth.ErrUserNotFound) {
			t.Errorf("FindUser(%q) error = %v, want ErrUserNotFound", in, err)
		}
	}
	for _, in := range []string{"", "   ", "abc", "12345", "a@b@c", "+1 555 0100", "98123", "a b@example.com", "ravi@"} {
		_, err := s.FindUser(t.Context(), in)
		if !errors.Is(err, auth.ErrInvalidIdentifier) {
			t.Errorf("FindUser(%q) error = %v, want ErrInvalidIdentifier", in, err)
		}
		if errors.Is(err, auth.ErrUserNotFound) {
			t.Errorf("FindUser(%q): invalid must not look like unknown", in)
		}
	}
	for _, in := range []string{"secret.person@example.com", "+919800000001"} {
		_, err := s.FindUser(t.Context(), in)
		if err == nil || strings.Contains(err.Error(), "secret.person") || strings.Contains(err.Error(), "9800000001") {
			t.Errorf("FindUser(%q) error %v echoes the identifier", in, err)
		}
	}
}

func TestFindUser_BR_CLI_04_ReadsOnlyAndLeavesNoAudit(t *testing.T) {
	e := authtest.New(t)
	s := e.Service(t)
	u := e.NewUser(t, authtest.UserSpec{})
	before := len(e.AuditRows(t))
	for range 3 {
		if _, err := s.FindUser(t.Context(), u.Email); err != nil {
			t.Fatal(err)
		}
	}
	_, _ = s.FindUser(t.Context(), "nobody@example.com")
	if after := len(e.AuditRows(t)); after != before {
		t.Errorf("audit rows %d -> %d, FindUser must not write", before, after)
	}
}

func TestFindUser_BR_CLI_04_JoinsTheCallersTransaction(t *testing.T) {
	e := authtest.New(t)
	s := e.Service(t)
	var found uuid.UUID
	err := e.Tx.InTx(t.Context(), func(ctx context.Context) error {
		// A user created in this very transaction is visible to FindUser in it.
		id, err := s.CreateClient(ctx, auth.NewClient{OrgID: e.Org, Name: "New Person", Email: "fresh@example.com", Mobile: "9812300001", Password: authtest.Password}, authtest.System())
		if err != nil {
			return err
		}
		v, err := s.FindUser(ctx, "fresh@example.com")
		if err != nil {
			return err
		}
		if v.ID != id {
			t.Errorf("FindUser in tx = %v, want %v", v.ID, id)
		}
		found = v.ID
		return nil
	})
	if err != nil || found == uuid.Nil {
		t.Fatalf("transaction: %v (found %v)", err, found)
	}
}

func TestDefaultOrg_BR_CLI_04_ReturnsTheOneOrganisation(t *testing.T) {
	e := authtest.New(t)
	got, err := e.Service(t).DefaultOrg(t.Context())
	if err != nil || got != e.Org {
		t.Fatalf("DefaultOrg = %v, %v, want %v", got, err, e.Org)
	}
}

func TestDefaultOrg_BR_CLI_04_NoneOrSeveralIsAnError(t *testing.T) {
	e := authtest.New(t)
	s := e.Service(t)
	e.Exec(t, `INSERT INTO orgs (id, name) VALUES ($1, 'Second')`, uuid.New())
	if got, err := s.DefaultOrg(t.Context()); !errors.Is(err, auth.ErrMultipleOrgs) || got != uuid.Nil {
		t.Errorf("two orgs: DefaultOrg = %v, %v, want uuid.Nil and ErrMultipleOrgs", got, err)
	}

	e2 := authtest.New(t)
	e2.Exec(t, `DELETE FROM orgs`)
	if got, err := e2.Service(t).DefaultOrg(t.Context()); !errors.Is(err, auth.ErrNoOrg) || got != uuid.Nil {
		t.Errorf("no org: DefaultOrg = %v, %v, want uuid.Nil and ErrNoOrg", got, err)
	}
}
