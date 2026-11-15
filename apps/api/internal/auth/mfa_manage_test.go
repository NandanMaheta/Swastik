package auth_test

// S15 - management of the second factor by a signed-in admin (spec US-5 s10-11, FR-062, FR-063,
// plan P-05). API under test (compile stubs in mfa_manage.go):
//
//	(*Service).RegenerateRecoveryCodes(ctx, p authz.Principal, password, code string) ([]string, error)
//	(*Service).StartAuthenticatorReplace(ctx, p, Reauth{Password, Code | RecoveryCode}) (TOTPEnrolment, error)
//	(*Service).ConfirmAuthenticatorReplace(ctx, p, code string) error
//
// A wrong password, code or recovery code, or a locked account, is ErrReauthFailed; wrong attempts
// count toward the D-08 lockout; a TOTP code already used (same or earlier step) is wrong.

import (
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/NandanMaheta/swastik/apps/api/internal/auth"
	"github.com/NandanMaheta/swastik/apps/api/internal/auth/authtest"
)

func TestMFA_RegenerateRecoveryCodesReplacesTheWholeSet(t *testing.T) {
	e := authtest.New(t)
	s := e.Service(t)
	a := mfEnrolled(t, e)
	_, p := mfSession(t, e, a.User)

	codes, err := s.RegenerateRecoveryCodes(t.Context(), p, authtest.Password, mfCode(t, e, a.Secret, 0))
	if err != nil {
		t.Fatalf("RegenerateRecoveryCodes: %v", err)
	}
	if len(codes) != 10 {
		t.Fatalf("codes = %d, want 10", len(codes))
	}
	for _, c := range codes {
		e.Secrets.Add("recovery code", c)
		if !recoveryCodeShape.MatchString(c) || slices.Contains(a.Codes, c) {
			t.Errorf("new code %q is malformed or equals an old one", c)
		}
	}
	if n := mfUsableCodes(t, e, a.User); n != 10 {
		t.Errorf("usable codes = %d, want exactly the 10 new ones", n)
	}
	if got := svCount(t, e, `SELECT count(*) FROM mfa_recovery_codes WHERE user_id = $1 AND revoked_at IS NOT NULL`, a.ID); got != 10 {
		t.Errorf("revoked codes = %d, want the 10 old ones", got)
	}
	row := mfOnly(t, e, auth.ActionMFARecoveryRegenerated)
	if after := mfAfter(t, row); row.ActorKind != "admin" || row.ActorID != a.ID || row.EntityID != a.ID || after["count"] != float64(10) || after["batch_id"] == "" {
		t.Errorf("audit = %+v %v", row, after)
	}
	e.Secrets.ScanAuditLog(t.Context(), t, e.Pool)

	// The old set no longer signs in; a new code does.
	if _, err := s.VerifyMFA(t.Context(), auth.MFAVerifyInput{ChallengeToken: mfChallenge(t, e, s, a.User), RecoveryCode: a.Codes[0], IP: testIP}); !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Errorf("an old recovery code: err = %v, want ErrInvalidCredentials", err)
	}
	if _, err := s.VerifyMFA(t.Context(), auth.MFAVerifyInput{ChallengeToken: mfChallenge(t, e, s, a.User), RecoveryCode: codes[0], IP: testIP}); err != nil {
		t.Errorf("a new recovery code: %v", err)
	}
}

func TestMFA_RegenerateNeedsPasswordAndFreshCode(t *testing.T) {
	e := authtest.New(t)
	s := e.Service(t)
	a := mfEnrolled(t, e)
	_, p := mfSession(t, e, a.User)

	if _, err := s.RegenerateRecoveryCodes(t.Context(), p, wrongPassword, mfCode(t, e, a.Secret, 0)); !errors.Is(err, auth.ErrReauthFailed) {
		t.Errorf("wrong password: err = %v, want ErrReauthFailed", err)
	}
	if _, err := s.RegenerateRecoveryCodes(t.Context(), p, authtest.Password, mfWrong(t, e, a.Secret)); !errors.Is(err, auth.ErrReauthFailed) {
		t.Errorf("wrong code: err = %v, want ErrReauthFailed", err)
	}
	if got := mfFailures(t, e, a.User); got != 2 {
		t.Errorf("counted failures = %d, want 2 (D-08)", got)
	}
	if n := mfUsableCodes(t, e, a.User); n != 10 || svCount(t, e, `SELECT count(*) FROM mfa_recovery_codes WHERE user_id = $1`, a.ID) != 10 {
		t.Errorf("a refused regeneration changed the recovery codes")
	}
	if got := len(e.AuditOf(t, auth.ActionMFARecoveryRegenerated)); got != 0 {
		t.Errorf("regenerated audit rows = %d, want 0", got)
	}

	// A code works once: the same code (and the one of the step before) cannot re-authenticate again.
	c := mfCode(t, e, a.Secret, 0)
	if _, err := s.RegenerateRecoveryCodes(t.Context(), p, authtest.Password, c); err != nil {
		t.Fatalf("right password and code: %v", err)
	}
	for name, code := range map[string]string{"the same code": c, "the previous step": mfCode(t, e, a.Secret, -30*time.Second)} {
		if _, err := s.RegenerateRecoveryCodes(t.Context(), p, authtest.Password, code); !errors.Is(err, auth.ErrReauthFailed) {
			t.Errorf("%s: err = %v, want ErrReauthFailed (replay)", name, err)
		}
	}
}

func TestMFA_RegenerateWhileLockedChangesNothing(t *testing.T) {
	e := authtest.New(t)
	s := e.Service(t)
	a := mfEnrolled(t, e)
	_, p := mfSession(t, e, a.User)
	for range 5 {
		svWrong(t, s, a.User)
	}
	if !mfLocked(t, e, a.User) {
		t.Fatal("precondition: the account must be locked")
	}
	if _, err := s.RegenerateRecoveryCodes(t.Context(), p, authtest.Password, mfCode(t, e, a.Secret, 0)); !errors.Is(err, auth.ErrReauthFailed) {
		t.Fatalf("correct credentials while locked: err = %v, want ErrReauthFailed", err)
	}
	if m := mfMFARow(t, e, a.ID); m.LastUsedStep != 0 {
		t.Errorf("a locked re-authentication consumed a TOTP step (%d)", m.LastUsedStep)
	}
	if n := mfUsableCodes(t, e, a.User); n != 10 || len(e.AuditOf(t, auth.ActionMFARecoveryRegenerated)) != 0 {
		t.Errorf("a locked re-authentication regenerated the codes")
	}
}

func TestMFA_ReplaceAuthenticatorFlow(t *testing.T) {
	e := authtest.New(t)
	s := e.Service(t)
	a := mfEnrolled(t, e)
	current, p := mfSession(t, e, a.User)
	other1, _ := mfSession(t, e, a.User)
	other2, _ := mfSession(t, e, a.User)
	clientU := e.UserWithStatus(t, auth.StatusActive)
	clientSession := e.NewSession(t, clientU.ID, authtest.SessionSpec{})
	oldStep := mfMFARow(t, e, a.ID).LastUsedStep

	start, err := s.StartAuthenticatorReplace(t.Context(), p, auth.Reauth{Password: authtest.Password, Code: mfCode(t, e, a.Secret, 0)})
	if err != nil {
		t.Fatalf("StartAuthenticatorReplace: %v", err)
	}
	e.Secrets.AddTOTPSecret(start.Secret)
	if start.Secret == a.Secret || start.OTPAuthURI == "" {
		t.Fatalf("start = %+v, want a new secret and uri", start)
	}
	m := mfMFARow(t, e, a.ID)
	if m.PendingSecretEnc == nil || mfOpenSecret(t, e, a.ID, m.PendingSecretEnc) != start.Secret {
		t.Fatal("the pending secret is not stored")
	}
	if mfOpenSecret(t, e, a.ID, m.SecretEnc) != a.Secret || m.EnrolledAt == nil {
		t.Error("the old secret must stay the confirmed one until the replacement is confirmed")
	}
	if svLiveSessions(t, e, a.ID) != 3 {
		t.Errorf("sessions ended before the replacement was confirmed")
	}

	e.Clock.Advance(90 * time.Second) // a fresh step for the new secret
	newCode := authtest.TOTPCode(t, start.Secret, e.Clock.Now())
	if err := s.ConfirmAuthenticatorReplace(t.Context(), p, newCode); err != nil {
		t.Fatalf("ConfirmAuthenticatorReplace: %v", err)
	}
	m = mfMFARow(t, e, a.ID)
	if mfOpenSecret(t, e, a.ID, m.SecretEnc) != start.Secret || m.PendingSecretEnc != nil {
		t.Errorf("after confirm the secret is not the new one: %+v", m)
	}
	if want := auth.TOTPStepAt(e.Clock.Now()); m.LastUsedStep != want || want <= oldStep {
		t.Errorf("last_used_step = %d, want the matched step %d of the new secret", m.LastUsedStep, want)
	}
	if svSession(t, e, current).EndedAt != nil {
		t.Error("the current session must stay")
	}
	for _, id := range []uuid.UUID{other1, other2} {
		if ss := svSession(t, e, id); ss.EndedAt == nil || ss.EndReason != "mfa_replaced" {
			t.Errorf("other admin session %v: ended=%v reason=%q, want ended by mfa_replaced (FR-063)", id, ss.EndedAt, ss.EndReason)
		}
	}
	if svSession(t, e, clientSession).EndedAt != nil {
		t.Error("another user's session was ended")
	}
	row := mfOnly(t, e, auth.ActionMFAReplaced)
	after := mfAfter(t, row)
	ended, _ := after["ended_session_ids"].([]any)
	if row.ActorKind != "admin" || row.ActorID != a.ID || len(ended) != 2 {
		t.Errorf("replaced audit = %+v %v, want the two ended sessions", row, after)
	}
	if n := mfUsableCodes(t, e, a.User); n != 10 {
		t.Errorf("usable recovery codes = %d, want 10 (a replacement does not regenerate them)", n)
	}
	e.Secrets.ScanAuditLog(t.Context(), t, e.Pool)

	// The old secret's codes stop working at the next sign-in; the new secret's later code works,
	// but the code used at confirm cannot be replayed.
	e.Clock.Advance(90 * time.Second)
	if _, err := s.VerifyMFA(t.Context(), mfVerifyIn(mfChallenge(t, e, s, a.User), mfCode(t, e, a.Secret, 0))); !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Errorf("a code of the old secret: err = %v, want ErrInvalidCredentials", err)
	}
	if _, err := s.VerifyMFA(t.Context(), mfVerifyIn(mfChallenge(t, e, s, a.User), newCode)); !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Errorf("the code used to confirm, replayed: err = %v, want ErrInvalidCredentials", err)
	}
	if _, err := s.VerifyMFA(t.Context(), mfVerifyIn(mfChallenge(t, e, s, a.User), authtest.TOTPCode(t, start.Secret, e.Clock.Now()))); err != nil {
		t.Errorf("a fresh code of the new secret: %v", err)
	}
}

func TestMFA_ReplaceStartWithARecoveryCodeConsumesAndAuditsIt(t *testing.T) {
	e := authtest.New(t)
	s := e.Service(t)
	a := mfEnrolled(t, e)
	_, p := mfSession(t, e, a.User)

	if _, err := s.StartAuthenticatorReplace(t.Context(), p, auth.Reauth{Password: authtest.Password, RecoveryCode: a.Codes[1]}); err != nil {
		t.Fatalf("StartAuthenticatorReplace with a recovery code: %v", err)
	}
	if n := mfUsableCodes(t, e, a.User); n != 9 {
		t.Errorf("usable codes = %d, want 9 (consumed at start)", n)
	}
	row := mfOnly(t, e, auth.ActionMFARecoveryCodeUsed)
	if after := mfAfter(t, row); row.ActorKind != "admin" || after["context"] != "replace" || after["remaining"] != float64(9) {
		t.Errorf("recovery_code_used audit = %+v %v, want context replace", row, after)
	}
	if _, err := s.StartAuthenticatorReplace(t.Context(), p, auth.Reauth{Password: authtest.Password, RecoveryCode: a.Codes[1]}); !errors.Is(err, auth.ErrReauthFailed) {
		t.Errorf("the same recovery code again: err = %v, want ErrReauthFailed", err)
	}
}

func TestMFA_ReplaceStartRefusals(t *testing.T) {
	e := authtest.New(t)
	s := e.Service(t)
	a := mfEnrolled(t, e)
	_, p := mfSession(t, e, a.User)
	good := mfCode(t, e, a.Secret, 0)
	for name, in := range map[string]auth.Reauth{
		"wrong password":      {Password: wrongPassword, Code: good},
		"wrong code":          {Password: authtest.Password, Code: mfWrong(t, e, a.Secret)},
		"wrong recovery code": {Password: authtest.Password, RecoveryCode: "0000-0000-0000-0000"},
		"no second factor":    {Password: authtest.Password},
	} {
		if _, err := s.StartAuthenticatorReplace(t.Context(), p, in); !errors.Is(err, auth.ErrReauthFailed) {
			t.Errorf("%s: err = %v, want ErrReauthFailed", name, err)
		}
	}
	if m := mfMFARow(t, e, a.ID); m.PendingSecretEnc != nil || m.LastUsedStep != 0 {
		t.Errorf("a refused start changed the authenticator: %+v", m)
	}
	if n := mfUsableCodes(t, e, a.User); n != 10 {
		t.Errorf("usable codes = %d, want 10", n)
	}
}

func TestMFA_ReplaceConfirmRefusals(t *testing.T) {
	e := authtest.New(t)
	s := e.Service(t)
	a := mfEnrolled(t, e)
	_, p := mfSession(t, e, a.User)
	other, _ := mfSession(t, e, a.User)

	if err := s.ConfirmAuthenticatorReplace(t.Context(), p, "123456"); !errors.Is(err, auth.ErrNoPendingSecret) {
		t.Fatalf("confirm without a pending secret: err = %v, want ErrNoPendingSecret", err)
	}
	start, err := s.StartAuthenticatorReplace(t.Context(), p, auth.Reauth{Password: authtest.Password, Code: mfCode(t, e, a.Secret, 0)})
	if err != nil {
		t.Fatal(err)
	}
	e.Secrets.AddTOTPSecret(start.Secret)
	e.Clock.Advance(90 * time.Second)
	if err := s.ConfirmAuthenticatorReplace(t.Context(), p, mfWrong(t, e, start.Secret)); !errors.Is(err, auth.ErrReauthFailed) {
		t.Errorf("wrong code: err = %v, want ErrReauthFailed", err)
	}
	if err := s.ConfirmAuthenticatorReplace(t.Context(), p, mfCode(t, e, a.Secret, 0)); !errors.Is(err, auth.ErrReauthFailed) {
		t.Errorf("a code of the OLD secret: err = %v, want ErrReauthFailed", err)
	}
	if svSession(t, e, other).EndedAt != nil || len(e.AuditOf(t, auth.ActionMFAReplaced)) != 0 {
		t.Error("a refused confirm ended sessions or audited a replacement")
	}
	m := mfMFARow(t, e, a.ID)
	if m.PendingSecretEnc == nil || mfOpenSecret(t, e, a.ID, m.SecretEnc) != a.Secret {
		t.Errorf("a refused confirm changed the authenticator: %+v", m)
	}
}
