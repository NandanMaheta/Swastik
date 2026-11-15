package auth_test

// S15 - first-admin bootstrap, service part (spec US-9, FR-080, D-15, plan P-13). API under test
// (compile stub in bootstrap.go): auth.NewBootstrapper(BootstrapDeps{Store, Tx, Now, Hasher}) and
// (*Bootstrapper).CreateAdmin(ctx, BootstrapInput) (BootstrapResult, error). It needs no Service,
// because the CLI has no signing, PII or blind-index keys.

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/NandanMaheta/swastik/apps/api/internal/auth"
	"github.com/NandanMaheta/swastik/apps/api/internal/auth/authtest"
)

const bootPassword = "correct-horse-battery-staple-9"

func bsBootstrapper(t *testing.T, e *authtest.Env) *auth.Bootstrapper {
	t.Helper()
	b, err := auth.NewBootstrapper(auth.BootstrapDeps{Store: e.Store, Tx: e.Tx, Now: e.Clock.Now, Hasher: e.Hasher})
	if err != nil {
		t.Fatalf("NewBootstrapper: %v", err)
	}
	return b
}

func bsInput(email string) auth.BootstrapInput {
	return auth.BootstrapInput{Email: email, Name: "Asha Owner", Password: bootPassword}
}

// bsEmptyEnv is an Env whose database has no organisation at all, as on a fresh installation.
func bsEmptyEnv(t *testing.T) *authtest.Env {
	t.Helper()
	e := authtest.New(t)
	e.Exec(t, `DELETE FROM orgs`)
	e.Secrets.Add("bootstrap password", bootPassword)
	return e
}

func bsCount(t *testing.T, e *authtest.Env, table string) int {
	t.Helper()
	return svCount(t, e, `SELECT count(*) FROM `+table)
}

func TestBootstrap_CreatesTheOrgAndAnActiveAdminWithoutAuthenticator(t *testing.T) {
	e := bsEmptyEnv(t)
	b := bsBootstrapper(t, e)

	res, err := b.CreateAdmin(t.Context(), bsInput("  Owner@Example.COM "))
	if err != nil {
		t.Fatalf("CreateAdmin: %v", err)
	}
	if res.Email != "owner@example.com" || res.UserID == uuid.Nil || res.OrgID == uuid.Nil {
		t.Fatalf("result = %+v", res)
	}
	var name string
	if err := e.Pool.QueryRow(t.Context(), `SELECT name FROM orgs WHERE id = $1`, res.OrgID).Scan(&name); err != nil || name != "Swastik" || bsCount(t, e, "orgs") != 1 {
		t.Errorf("org = %q err=%v count=%d, want the single default org \"Swastik\"", name, err, bsCount(t, e, "orgs"))
	}
	u := svUserRow(t, e, res.UserID)
	if u.Role != "admin" || u.Status != auth.StatusActive || u.OrgID != res.OrgID || u.Email != "owner@example.com" || u.Name != "Asha Owner" || u.Mobile != "" {
		t.Errorf("user = %+v, want an active admin with only an email", u)
	}
	if u.EmailVerifiedAt == nil || !u.EmailVerifiedAt.Equal(e.Clock.Now()) || !u.CreatedAt.Equal(e.Clock.Now()) {
		t.Errorf("email_verified_at = %v created_at = %v, want the injected clock %v", u.EmailVerifiedAt, u.CreatedAt, e.Clock.Now())
	}
	if ok, err := e.Hasher.Verify(t.Context(), u.PasswordHash, auth.NormalizePassword(bootPassword)); err != nil || !ok || !strings.HasPrefix(u.PasswordHash, "$argon2id$") {
		t.Errorf("stored hash does not verify the password (ok=%v err=%v)", ok, err)
	}
	if got := bsCount(t, e, "admin_mfa"); got != 0 {
		t.Errorf("admin_mfa rows = %d, want 0 (TOTP is enrolled at first sign-in)", got)
	}
	row := mfOnly(t, e, auth.ActionAdminBootstrapped)
	after := mfAfter(t, row)
	if row.ActorKind != "system" || row.ActorID != uuid.Nil || row.EntityID != res.UserID || row.Entity != "user" ||
		after["email"] != "owner@example.com" || after["org_id"] != res.OrgID.String() {
		t.Errorf("audit = %+v %v", row, after)
	}
	if !strings.HasPrefix(row.CreatedAt, "2026-07-01 10:00:00") {
		t.Errorf("audit created_at = %q, want the injected clock", row.CreatedAt)
	}
	e.Secrets.ScanAuditLog(t.Context(), t, e.Pool)
}

func TestBootstrap_OrgNameAppliesOnlyWhenNoOrgExists(t *testing.T) {
	e := bsEmptyEnv(t)
	in := bsInput("owner@example.com")
	in.OrgName = "Acme Traders"
	res, err := bsBootstrapper(t, e).CreateAdmin(t.Context(), in)
	if err != nil {
		t.Fatalf("CreateAdmin: %v", err)
	}
	var name string
	if err := e.Pool.QueryRow(t.Context(), `SELECT name FROM orgs WHERE id = $1`, res.OrgID).Scan(&name); err != nil || name != "Acme Traders" {
		t.Errorf("org name = %q (%v), want Acme Traders", name, err)
	}

	e2 := authtest.New(t) // one org exists: it is used and the name is ignored
	in.OrgName = "Ignored Name"
	res2, err := bsBootstrapper(t, e2).CreateAdmin(t.Context(), in)
	if err != nil {
		t.Fatalf("CreateAdmin with one org: %v", err)
	}
	if res2.OrgID != e2.Org || bsCount(t, e2, "orgs") != 1 {
		t.Errorf("org = %v count = %d, want the existing org reused", res2.OrgID, bsCount(t, e2, "orgs"))
	}
}

func TestBootstrap_SeveralOrgsNeedAnOrgID(t *testing.T) {
	e := authtest.New(t)
	second := uuid.New()
	e.Exec(t, `INSERT INTO orgs (id, name) VALUES ($1, 'Second')`, second)
	e.NewAdmin(t) // an admin of the first org does not block the second
	b := bsBootstrapper(t, e)
	before := bsCount(t, e, "users")

	if _, err := b.CreateAdmin(t.Context(), bsInput("owner@example.com")); !errors.Is(err, auth.ErrOrgAmbiguous) {
		t.Fatalf("no OrgID: err = %v, want ErrOrgAmbiguous", err)
	}
	if got := bsCount(t, e, "users"); got != before || len(e.AuditOf(t, auth.ActionAdminBootstrapped)) != 0 {
		t.Errorf("a refused run changed state")
	}
	in := bsInput("owner@example.com")
	in.OrgID = second
	res, err := b.CreateAdmin(t.Context(), in)
	if err != nil {
		t.Fatalf("with OrgID: %v", err)
	}
	if res.OrgID != second || svUserRow(t, e, res.UserID).OrgID != second {
		t.Errorf("admin created in %v, want %v", res.OrgID, second)
	}
}

func TestBootstrap_RefusesWhenAnAdminExistsAndChangesNothing(t *testing.T) {
	for _, status := range []auth.Status{auth.StatusActive, auth.StatusDisabled} {
		t.Run(string(status), func(t *testing.T) {
			e := authtest.New(t)
			e.NewUser(t, authtest.UserSpec{Role: "admin", Status: status})
			e.Secrets.Add("bootstrap password", bootPassword)
			users := bsCount(t, e, "users")

			_, err := bsBootstrapper(t, e).CreateAdmin(t.Context(), bsInput("second@example.com"))
			if !errors.Is(err, auth.ErrAdminExists) {
				t.Fatalf("err = %v, want ErrAdminExists (US-9 s2)", err)
			}
			if got := bsCount(t, e, "users"); got != users {
				t.Errorf("users = %d, want %d", got, users)
			}
			if got := len(e.AuditRows(t)); got != 0 {
				t.Errorf("audit rows = %d, want 0", got)
			}
			if strings.Contains(err.Error(), bootPassword) {
				t.Error("the error message contains the password")
			}
		})
	}
}

func TestBootstrap_PolicyFailureNamesTheRuleAndCreatesNothing(t *testing.T) {
	long := strings.Repeat("a1b2", 65) // 260 characters
	for _, tt := range []struct{ name, password, code string }{
		{"too short", "short1", auth.PolicyTooShort},
		{"too long", long, auth.PolicyTooLong},
		{"too common", "1234567890", auth.PolicyTooCommon},
		{"equals the email", "owner@example.com", auth.PolicyMatchesIdentifier},
	} {
		t.Run(tt.name, func(t *testing.T) {
			e := bsEmptyEnv(t)
			in := bsInput("owner@example.com")
			in.Password = tt.password
			e.Secrets.Add("bootstrap password", tt.password)
			_, err := bsBootstrapper(t, e).CreateAdmin(t.Context(), in)
			var pe *auth.PolicyError
			if !errors.As(err, &pe) || pe.Code != tt.code {
				t.Fatalf("err = %v, want *PolicyError %s (US-9 s3)", err, tt.code)
			}
			if bsCount(t, e, "users") != 0 || bsCount(t, e, "orgs") != 0 || len(e.AuditRows(t)) != 0 {
				t.Errorf("a policy failure left rows behind (checked before the transaction)")
			}
			if len(tt.password) > 8 && strings.Contains(err.Error(), tt.password) {
				t.Error("the error message contains the password")
			}
		})
	}
}

func TestBootstrap_TakenOrInvalidContactDataIsRefused(t *testing.T) {
	e := authtest.New(t)
	client := e.UserWithStatus(t, auth.StatusActive)
	e.Secrets.Add("bootstrap password", bootPassword)
	b := bsBootstrapper(t, e)
	users := bsCount(t, e, "users")

	in := bsInput(strings.ToUpper(client.Email)) // an email already used by a client, compared normalised (US-9 s4)
	if _, err := b.CreateAdmin(t.Context(), in); !errors.Is(err, auth.ErrEmailTaken) {
		t.Errorf("email of a client: err = %v, want ErrEmailTaken", err)
	}
	in = bsInput("owner@example.com")
	in.Mobile = client.Mobile
	if _, err := b.CreateAdmin(t.Context(), in); !errors.Is(err, auth.ErrMobileTaken) {
		t.Errorf("mobile of a client: err = %v, want ErrMobileTaken", err)
	}
	for _, bad := range []auth.BootstrapInput{
		{Email: "not-an-email", Name: "A", Password: bootPassword},
		{Email: "owner@example.com", Name: "A", Mobile: "12345", Password: bootPassword},
	} {
		if _, err := b.CreateAdmin(t.Context(), bad); !errors.Is(err, auth.ErrInvalidIdentifier) {
			t.Errorf("%+v: err = %v, want ErrInvalidIdentifier", bad.Email, err)
		}
	}
	if got := bsCount(t, e, "users"); got != users || len(e.AuditRows(t)) != 0 {
		t.Errorf("a refused run changed state: users %d -> %d", users, got)
	}
}

func TestBootstrap_OptionalMobileIsStoredNormalised(t *testing.T) {
	e := authtest.New(t)
	in := bsInput("owner@example.com")
	in.Mobile = "98765 43210"
	res, err := bsBootstrapper(t, e).CreateAdmin(t.Context(), in)
	if err != nil {
		t.Fatalf("CreateAdmin: %v", err)
	}
	if u := svUserRow(t, e, res.UserID); u.Mobile != "+919876543210" {
		t.Errorf("mobile = %q, want +919876543210", u.Mobile)
	}
}

func TestBootstrap_TheNewAdminSignsInAndIsOfferedEnrolment(t *testing.T) {
	// US-9 s6: sign-in of a freshly bootstrapped admin leads to US-5 s8 (enrolment).
	e := authtest.New(t)
	e.Secrets.Add("bootstrap password", bootPassword)
	if _, err := bsBootstrapper(t, e).CreateAdmin(t.Context(), bsInput("owner@example.com")); err != nil {
		t.Fatal(err)
	}
	res, err := e.Service(t).SignIn(t.Context(), auth.SignInInput{
		Identifier: "owner@example.com", Password: bootPassword, ClientType: auth.ClientTypeWeb,
		Device: auth.DeviceInfo{ID: uuid.New(), Name: "Chrome", Platform: auth.PlatformWeb}, IP: testIP,
	})
	if err != nil {
		t.Fatalf("SignIn: %v", err)
	}
	if res.NextStep != auth.NextStepMFAEnrolmentNeeded || res.Session != nil || res.Challenge == nil {
		t.Errorf("sign-in = %+v, want mfa_enrolment_required with a challenge", res)
	}
}

func TestBootstrap_ConcurrentRunsOnAnEmptyDatabaseCreateExactlyOneAdminAndOneOrg(t *testing.T) {
	for _, n := range []int{2, 4, 8} {
		t.Run(fmt.Sprintf("%d runs", n), func(t *testing.T) {
			e := bsEmptyEnv(t)
			b := bsBootstrapper(t, e)
			errs := stRace(n, func(i int) error {
				_, err := b.CreateAdmin(t.Context(), bsInput(fmt.Sprintf("owner%d@example.com", i)))
				return err
			})
			wins := 0
			for i, err := range errs {
				switch {
				case err == nil:
					wins++
				case !errors.Is(err, auth.ErrAdminExists):
					t.Errorf("run %d: err = %v, want ErrAdminExists", i, err)
				}
			}
			if wins != 1 {
				t.Fatalf("successes = %d, want exactly 1 (advisory lock)", wins)
			}
			if got := bsCount(t, e, "users"); got != 1 {
				t.Errorf("users = %d, want 1", got)
			}
			if got := bsCount(t, e, "orgs"); got != 1 {
				t.Errorf("orgs = %d, want 1 (two runs on an empty database must not create two orgs)", got)
			}
			if got := len(e.AuditOf(t, auth.ActionAdminBootstrapped)); got != 1 {
				t.Errorf("bootstrapped audit rows = %d, want 1", got)
			}
		})
	}
}

func TestBootstrap_ConcurrentRunsWithTheSameEmailStayConsistent(t *testing.T) {
	e := authtest.New(t)
	b := bsBootstrapper(t, e)
	errs := stRace(4, func(int) error {
		_, err := b.CreateAdmin(t.Context(), bsInput("owner@example.com"))
		return err
	})
	wins := 0
	for _, err := range errs {
		if err == nil {
			wins++
		} else if !errors.Is(err, auth.ErrAdminExists) && !errors.Is(err, auth.ErrEmailTaken) {
			t.Errorf("unexpected error: %v", err)
		}
	}
	if wins != 1 || bsCount(t, e, "users") != 1 {
		t.Fatalf("successes = %d users = %d, want 1 and 1", wins, bsCount(t, e, "users"))
	}
}

func TestBootstrap_NeedsItsDependencies(t *testing.T) {
	e := authtest.New(t)
	for name, d := range map[string]auth.BootstrapDeps{
		"no store":  {Tx: e.Tx, Now: e.Clock.Now, Hasher: e.Hasher},
		"no clock":  {Store: e.Store, Tx: e.Tx, Hasher: e.Hasher},
		"no hasher": {Store: e.Store, Tx: e.Tx, Now: e.Clock.Now},
	} {
		if _, err := auth.NewBootstrapper(d); err == nil {
			t.Errorf("%s: NewBootstrapper accepted incomplete dependencies", name)
		}
	}
}
