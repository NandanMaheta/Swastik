package auth_test

// Review-fix tests (feature 003 review pass).
//
// API assumptions (the implementer must match these names):
//
//	authz.Principal gains IP string      // the caller's address resolved by httpx.ClientIP; set by the handlers
//	auth.ActionMFAPendingSecretSet = "auth.mfa.pending_secret_set"
//	auth.HandlerConfig gains ProxySecrets []string // the PROXY_SHARED_SECRETS handed to httpx.ClientIP
//
// Behaviour under test:
//   - ChangePassword and ResetPassword invalidate every unconsumed MFA challenge of the user in the
//     same transaction as the password change; a refused change invalidates nothing.
//   - StartEnrolment and StartAuthenticatorReplace write auth.mfa.pending_secret_set (actor: the
//     admin; entity: the admin user) with no secret material in the payload.
//   - Re-authentication failures (wrong current password, wrong password or second factor in the
//     admin management operations) write auth.sign_in.failed with ip (Principal.IP) and
//     identifier_kind ("email" or "mobile": the kind of the account's sign-in identifier).

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/NandanMaheta/swastik/apps/api/internal/auth"
	"github.com/NandanMaheta/swastik/apps/api/internal/auth/authtest"
	"github.com/NandanMaheta/swastik/apps/api/internal/platform/audit"
)

const reviewIP = "203.0.113.77"

func rfUnconsumed(t *testing.T, e *authtest.Env, user uuid.UUID) int {
	t.Helper()
	return svCount(t, e, `SELECT count(*) FROM mfa_challenges WHERE user_id = $1 AND consumed_at IS NULL`, user)
}

// ---- 4. password change and reset invalidate outstanding MFA challenges ----

func TestReviewFix_PasswordChangeInvalidatesUnconsumedMFAChallenges(t *testing.T) {
	e := authtest.New(t)
	s := e.Service(t)
	e.Secrets.Add("new password", newPassword)
	adm := mfEnrolled(t, e)
	other := mfEnrolled(t, e)
	_, p := mfSession(t, e, adm.User)

	web := mfPassword(t, e, s, adm.User, auth.ClientTypeWeb).Challenge.Token
	mobile := mfChallenge(t, e, s, adm.User)
	untouched := mfChallenge(t, e, s, other.User)
	if n := rfUnconsumed(t, e, adm.ID); n != 2 {
		t.Fatalf("precondition: unconsumed challenges = %d, want 2", n)
	}

	if err := s.ChangePassword(t.Context(), p, adm.Password, newPassword); err != nil {
		t.Fatalf("ChangePassword: %v", err)
	}
	if n := rfUnconsumed(t, e, adm.ID); n != 0 {
		t.Errorf("unconsumed challenges after the change = %d, want 0", n)
	}
	for name, tok := range map[string]string{"web": web, "mobile": mobile} {
		_, err := s.VerifyMFA(t.Context(), mfVerifyIn(tok, mfCode(t, e, adm.Secret, 0)))
		if !errors.Is(err, auth.ErrInvalidChallenge) {
			t.Errorf("%s challenge with a valid code after the password change: err = %v, want ErrInvalidChallenge", name, err)
		}
	}
	// Another admin's challenge is not affected.
	if n := rfUnconsumed(t, e, other.ID); n != 1 {
		t.Errorf("another admin's unconsumed challenges = %d, want 1", n)
	}
	if res, err := s.VerifyMFA(t.Context(), mfVerifyIn(untouched, mfCode(t, e, other.Secret, 0))); err != nil || res.AccessToken == "" {
		t.Errorf("another admin's challenge was invalidated: %v", err)
	}
}

func TestReviewFix_RefusedPasswordChangeLeavesChallengesValid(t *testing.T) {
	e := authtest.New(t)
	s := e.Service(t)
	adm := mfEnrolled(t, e)
	_, p := mfSession(t, e, adm.User)
	tok := mfChallenge(t, e, s, adm.User)

	if err := s.ChangePassword(t.Context(), p, wrongPassword, newPassword); !errors.Is(err, auth.ErrReauthFailed) {
		t.Fatalf("wrong current password: err = %v, want ErrReauthFailed", err)
	}
	if err := s.ChangePassword(t.Context(), p, adm.Password, "short1"); err == nil {
		t.Fatal("a too-short new password was accepted")
	}
	if n := rfUnconsumed(t, e, adm.ID); n != 1 {
		t.Errorf("unconsumed challenges after refused changes = %d, want 1 (nothing changed)", n)
	}
	if res, err := s.VerifyMFA(t.Context(), mfVerifyIn(tok, mfCode(t, e, adm.Secret, 0))); err != nil || res.AccessToken == "" {
		t.Errorf("the challenge no longer works after a refused change: %v", err)
	}
}

func TestReviewFix_AdminPasswordResetInvalidatesUnconsumedMFAChallenges(t *testing.T) {
	e := authtest.New(t)
	s := e.Service(t)
	const fresh = "fresh-passphrase-after-reset-8"
	e.Secrets.Add("new password", fresh)
	adm := mfEnrolled(t, e)
	tok := mfChallenge(t, e, s, adm.User)
	tok2 := mfPassword(t, e, s, adm.User, auth.ClientTypeWeb).Challenge.Token

	if err := s.ResetPassword(t.Context(), adm.ID, fresh, authtest.System()); err != nil {
		t.Fatalf("ResetPassword: %v", err)
	}
	if n := rfUnconsumed(t, e, adm.ID); n != 0 {
		t.Errorf("unconsumed challenges after the reset = %d, want 0", n)
	}
	for _, c := range []string{tok, tok2} {
		if _, err := s.VerifyMFA(t.Context(), mfVerifyIn(c, mfCode(t, e, adm.Secret, 0))); !errors.Is(err, auth.ErrInvalidChallenge) {
			t.Errorf("challenge issued before the reset: err = %v, want ErrInvalidChallenge", err)
		}
	}
}

func TestReviewFix_RefusedPasswordResetLeavesChallengesValid(t *testing.T) {
	e := authtest.New(t)
	s := e.Service(t)
	adm := mfEnrolled(t, e)
	tok := mfChallenge(t, e, s, adm.User)

	if err := s.ResetPassword(t.Context(), adm.ID, "short1", authtest.System()); err == nil {
		t.Fatal("a too-short password was accepted by the reset")
	}
	if n := rfUnconsumed(t, e, adm.ID); n != 1 {
		t.Errorf("unconsumed challenges after a refused reset = %d, want 1", n)
	}
	if _, err := s.VerifyMFA(t.Context(), mfVerifyIn(tok, mfCode(t, e, adm.Secret, 0))); err != nil {
		t.Errorf("the challenge no longer works after a refused reset: %v", err)
	}
}

func TestReviewFix_PasswordChangeInvalidatesAnEnrolmentChallengeToo(t *testing.T) {
	e := authtest.New(t)
	s := e.Service(t)
	e.Secrets.Add("new password", newPassword)
	fresh := e.NewAdmin(t) // not enrolled: the password step yields an enrolment challenge
	tok := mfChallenge(t, e, s, fresh)
	if n := rfUnconsumed(t, e, fresh.ID); n != 1 {
		t.Fatalf("precondition: unconsumed challenges = %d, want 1", n)
	}
	if err := s.ResetPassword(t.Context(), fresh.ID, newPassword, authtest.System()); err != nil {
		t.Fatalf("ResetPassword: %v", err)
	}
	if _, err := s.StartEnrolment(t.Context(), tok); !errors.Is(err, auth.ErrInvalidChallenge) {
		t.Errorf("StartEnrolment with a pre-reset challenge: err = %v, want ErrInvalidChallenge", err)
	}
}

// ---- 6a. pending secret audit ----

func TestReviewFix_StartEnrolmentAuditsThePendingSecretWithoutSecretMaterial(t *testing.T) {
	e := authtest.New(t)
	s := e.Service(t)
	fresh := e.NewAdmin(t)
	tok := mfChallenge(t, e, s, fresh)

	before := len(e.AuditOf(t, auth.ActionMFAPendingSecretSet))
	enrolment, err := s.StartEnrolment(t.Context(), tok)
	if err != nil {
		t.Fatalf("StartEnrolment: %v", err)
	}
	e.Secrets.AddTOTPSecret(enrolment.Secret)
	rows := e.AuditOf(t, auth.ActionMFAPendingSecretSet)
	if len(rows) != before+1 {
		t.Fatalf("auth.mfa.pending_secret_set rows = %d, want %d", len(rows), before+1)
	}
	row := rows[len(rows)-1]
	if row.ActorKind != audit.KindAdmin || row.ActorID != fresh.ID || row.Entity != auth.EntityUser || row.EntityID != fresh.ID {
		t.Errorf("row = %+v, want actor admin %v on entity user %v", row, fresh.ID, fresh.ID)
	}
	rfNoSecret(t, row, enrolment)
	e.Secrets.ScanAuditLog(t.Context(), t, e.Pool)
}

func TestReviewFix_StartEnrolmentWithABadChallengeWritesNoPendingSecretRow(t *testing.T) {
	e := authtest.New(t)
	s := e.Service(t)
	if _, err := s.StartEnrolment(t.Context(), "dmc_not-a-real-challenge"); !errors.Is(err, auth.ErrInvalidChallenge) {
		t.Fatalf("err = %v, want ErrInvalidChallenge", err)
	}
	if rows := e.AuditOf(t, auth.ActionMFAPendingSecretSet); len(rows) != 0 {
		t.Errorf("auth.mfa.pending_secret_set rows = %d, want 0 for a refused start", len(rows))
	}
}

func TestReviewFix_StartAuthenticatorReplaceAuditsThePendingSecretWithoutSecretMaterial(t *testing.T) {
	e := authtest.New(t)
	s := e.Service(t)
	adm := mfEnrolled(t, e)
	_, p := mfSession(t, e, adm.User)

	start, err := s.StartAuthenticatorReplace(t.Context(), p, auth.Reauth{Password: adm.Password, Code: mfCode(t, e, adm.Secret, 0)})
	if err != nil {
		t.Fatalf("StartAuthenticatorReplace: %v", err)
	}
	e.Secrets.AddTOTPSecret(start.Secret)
	rows := e.AuditOf(t, auth.ActionMFAPendingSecretSet)
	if len(rows) != 1 {
		t.Fatalf("auth.mfa.pending_secret_set rows = %d, want 1", len(rows))
	}
	row := rows[0]
	if row.ActorKind != audit.KindAdmin || row.ActorID != adm.ID || row.Entity != auth.EntityUser || row.EntityID != adm.ID {
		t.Errorf("row = %+v, want actor admin %v on entity user %v", row, adm.ID, adm.ID)
	}
	rfNoSecret(t, row, start)
	e.Secrets.ScanAuditLog(t.Context(), t, e.Pool)
}

func TestReviewFix_RefusedAuthenticatorReplaceStartWritesNoPendingSecretRow(t *testing.T) {
	e := authtest.New(t)
	s := e.Service(t)
	adm := mfEnrolled(t, e)
	_, p := mfSession(t, e, adm.User)
	if _, err := s.StartAuthenticatorReplace(t.Context(), p, auth.Reauth{Password: adm.Password, Code: mfWrong(t, e, adm.Secret)}); !errors.Is(err, auth.ErrReauthFailed) {
		t.Fatalf("wrong code: err = %v, want ErrReauthFailed", err)
	}
	if rows := e.AuditOf(t, auth.ActionMFAPendingSecretSet); len(rows) != 0 {
		t.Errorf("auth.mfa.pending_secret_set rows = %d, want 0 for a refused start", len(rows))
	}
}

// rfNoSecret requires the payload to carry no authenticator secret, provisioning URI or key.
func rfNoSecret(t *testing.T, row authtest.AuditRow, en auth.TOTPEnrolment) {
	t.Helper()
	for _, banned := range []string{en.Secret, en.OTPAuthURI, "otpauth", "secret_enc", "pending_secret_enc"} {
		if banned != "" && strings.Contains(row.After, banned) {
			t.Errorf("audit payload contains secret material %.12q: %s", banned, row.After)
		}
	}
	if row.Before != "" && strings.Contains(row.Before, en.Secret) {
		t.Errorf("audit before-image contains the secret")
	}
}

// ---- 6b. re-authentication failures carry ip and identifier_kind ----

func rfFailedRows(t *testing.T, e *authtest.Env) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, r := range e.AuditOf(t, auth.ActionSignInFailed) {
		out = append(out, mfAfter(t, r))
	}
	return out
}

func rfWantContext(t *testing.T, got map[string]any, reason, kind string) {
	t.Helper()
	if got["reason"] != reason {
		t.Errorf("reason = %v, want %s (row %v)", got["reason"], reason, got)
	}
	if got["ip"] != reviewIP {
		t.Errorf("ip = %v, want %s (row %v)", got["ip"], reviewIP, got)
	}
	gotKind, _ := got["identifier_kind"].(string)
	switch kind {
	case "":
		if gotKind != "email" && gotKind != "mobile" {
			t.Errorf("identifier_kind = %v, want email or mobile (row %v)", got["identifier_kind"], got)
		}
	default:
		if gotKind != kind {
			t.Errorf("identifier_kind = %v, want %s (row %v)", got["identifier_kind"], kind, got)
		}
	}
}

func TestReviewFix_ReauthFailureAuditCarriesIPAndIdentifierKind_ChangePassword(t *testing.T) {
	e := authtest.New(t)
	s := e.Service(t)
	u := e.UserWithStatus(t, auth.StatusActive)
	tok := svSignIn(t, s, u, uuid.New())
	p := svPrincipal(e, u, tok.SessionID)
	p.IP = reviewIP

	if err := s.ChangePassword(t.Context(), p, wrongPassword, newPassword); !errors.Is(err, auth.ErrReauthFailed) {
		t.Fatalf("err = %v, want ErrReauthFailed", err)
	}
	rows := rfFailedRows(t, e)
	if len(rows) != 1 {
		t.Fatalf("sign_in.failed rows = %d, want 1", len(rows))
	}
	rfWantContext(t, rows[0], auth.ReasonWrongCurrentPassword, "")
}

func TestReviewFix_ReauthFailureAuditCarriesIPAndIdentifierKind_AdminOperations(t *testing.T) {
	e := authtest.New(t)
	s := e.Service(t)
	adm := mfEnrolled(t, e) // admins sign in by email
	_, p := mfSession(t, e, adm.User)
	p.IP = reviewIP

	steps := []struct {
		name, reason string
		run          func() error
	}{
		{"regenerate recovery codes, wrong password", auth.ReasonWrongPassword, func() error {
			_, err := s.RegenerateRecoveryCodes(t.Context(), p, wrongPassword, mfCode(t, e, adm.Secret, 0))
			return err
		}},
		{"regenerate recovery codes, wrong code", auth.ReasonWrongTOTP, func() error {
			_, err := s.RegenerateRecoveryCodes(t.Context(), p, adm.Password, mfWrong(t, e, adm.Secret))
			return err
		}},
		{"replace authenticator, wrong code", auth.ReasonWrongTOTP, func() error {
			_, err := s.StartAuthenticatorReplace(t.Context(), p, auth.Reauth{Password: adm.Password, Code: mfWrong(t, e, adm.Secret)})
			return err
		}},
		{"replace authenticator, wrong recovery code", auth.ReasonWrongRecoveryCode, func() error {
			_, err := s.StartAuthenticatorReplace(t.Context(), p, auth.Reauth{Password: adm.Password, RecoveryCode: vaWrongRecovery()})
			return err
		}},
	}
	for i, st := range steps {
		if err := st.run(); !errors.Is(err, auth.ErrReauthFailed) {
			t.Fatalf("%s: err = %v, want ErrReauthFailed", st.name, err)
		}
		rows := rfFailedRows(t, e)
		if len(rows) != i+1 {
			t.Fatalf("%s: sign_in.failed rows = %d, want %d", st.name, len(rows), i+1)
		}
		rfWantContext(t, rows[i], st.reason, "email")
		e.Clock.Advance(time.Minute)
	}

	// The confirm step re-authenticates with the pending authenticator's code.
	start, err := s.StartAuthenticatorReplace(t.Context(), p, auth.Reauth{Password: adm.Password, Code: mfCode(t, e, adm.Secret, 0)})
	if err != nil {
		t.Fatalf("StartAuthenticatorReplace: %v", err)
	}
	e.Secrets.AddTOTPSecret(start.Secret)
	if err := s.ConfirmAuthenticatorReplace(t.Context(), p, mfWrong(t, e, start.Secret)); !errors.Is(err, auth.ErrReauthFailed) {
		t.Fatalf("confirm with a wrong code: err = %v, want ErrReauthFailed", err)
	}
	rows := rfFailedRows(t, e)
	rfWantContext(t, rows[len(rows)-1], auth.ReasonWrongTOTP, "email")
}

func TestReviewFix_ReauthFailureAuditHasNoIPWhenThePrincipalCarriesNone(t *testing.T) {
	// A caller that is not an HTTP request (a feature module) has no address; the field is empty,
	// never a placeholder, and identifier_kind is still recorded.
	e := authtest.New(t)
	s := e.Service(t)
	u := e.UserWithStatus(t, auth.StatusActive)
	tok := svSignIn(t, s, u, uuid.New())
	p := svPrincipal(e, u, tok.SessionID)
	if err := s.ChangePassword(t.Context(), p, wrongPassword, newPassword); !errors.Is(err, auth.ErrReauthFailed) {
		t.Fatalf("err = %v, want ErrReauthFailed", err)
	}
	rows := rfFailedRows(t, e)
	if len(rows) != 1 {
		t.Fatalf("sign_in.failed rows = %d, want 1", len(rows))
	}
	if ip, _ := rows[0]["ip"].(string); ip != "" {
		t.Errorf("ip = %q, want empty when the principal has no address", ip)
	}
	if k, _ := rows[0]["identifier_kind"].(string); k != "email" && k != "mobile" {
		t.Errorf("identifier_kind = %v, want email or mobile", rows[0]["identifier_kind"])
	}
}
