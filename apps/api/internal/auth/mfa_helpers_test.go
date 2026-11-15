package auth_test

// Shared helpers of the S15 tests (admin MFA flow and management, plan P-05, US-5).

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/NandanMaheta/swastik/apps/api/internal/auth"
	"github.com/NandanMaheta/swastik/apps/api/internal/auth/authtest"
	"github.com/NandanMaheta/swastik/apps/api/internal/platform/authz"
)

// mfAdmin is an active admin with a confirmed authenticator and 10 unused recovery codes.
type mfAdmin struct {
	authtest.User
	Secret string
	Codes  []string
}

func mfEnrolled(t *testing.T, e *authtest.Env) mfAdmin {
	t.Helper()
	u := e.NewAdmin(t)
	return mfAdmin{User: u, Secret: e.EnrolAdmin(t, u.ID), Codes: e.NewRecoveryCodes(t, u.ID)}
}

// mfCode is the authenticator code of the secret at the clock's current time plus offset.
func mfCode(t *testing.T, e *authtest.Env, secret string, offset time.Duration) string {
	t.Helper()
	return authtest.TOTPCode(t, secret, e.Clock.Now().Add(offset))
}

// mfWrong is a six-digit code that is not any of the codes of steps N-2 .. N+2.
func mfWrong(t *testing.T, e *authtest.Env, secret string) string {
	t.Helper()
	valid := map[string]bool{}
	for _, off := range []time.Duration{-60 * time.Second, -30 * time.Second, 0, 30 * time.Second, 60 * time.Second} {
		valid[mfCode(t, e, secret, off)] = true
	}
	for _, c := range []string{"000000", "111111", "222222", "333333"} {
		if !valid[c] {
			return c
		}
	}
	t.Fatal("no wrong code found")
	return ""
}

// mfPassword runs the password step of an admin sign-in from a (new) installation.
func mfPassword(t *testing.T, e *authtest.Env, s *auth.Service, u authtest.User, clientType string) auth.SignInResult {
	t.Helper()
	in := svInput(u, uuid.New())
	in.ClientType = clientType
	res, err := s.SignIn(t.Context(), in)
	if err != nil {
		t.Fatalf("admin password step: %v", err)
	}
	if res.Challenge == nil || res.Session != nil {
		t.Fatalf("admin password step = %+v, want a challenge and no session", res)
	}
	e.Secrets.Add("challenge token", res.Challenge.Token)
	return res
}

// mfChallenge is the challenge token of a fresh mobile password step.
func mfChallenge(t *testing.T, e *authtest.Env, s *auth.Service, u authtest.User) string {
	t.Helper()
	return mfPassword(t, e, s, u, auth.ClientTypeMobile).Challenge.Token
}

func mfVerifyIn(token, code string) auth.MFAVerifyInput {
	return auth.MFAVerifyInput{ChallengeToken: token, Code: code, IP: testIP}
}

// mfSignIn runs password and TOTP steps and returns the session.
func mfSignIn(t *testing.T, e *authtest.Env, s *auth.Service, a mfAdmin) auth.SessionTokens {
	t.Helper()
	tok := mfChallenge(t, e, s, a.User)
	res, err := s.VerifyMFA(t.Context(), mfVerifyIn(tok, mfCode(t, e, a.Secret, 0)))
	if err != nil {
		t.Fatalf("VerifyMFA: %v", err)
	}
	e.Secrets.Add("access token", res.AccessToken)
	e.Secrets.Add("refresh token", res.RefreshToken)
	return res
}

// mfMFARow reads the admin_mfa row.
func mfMFARow(t *testing.T, e *authtest.Env, user uuid.UUID) auth.MFARow {
	t.Helper()
	m, err := e.Store.GetMFA(t.Context(), user)
	if err != nil {
		t.Fatalf("GetMFA: %v", err)
	}
	return m
}

// mfOpenSecret opens a stored authenticator envelope. The plan names two AADs (the confirmed and
// the pending one) and the Store copies the envelope on confirm, so both are accepted.
func mfOpenSecret(t *testing.T, e *authtest.Env, user uuid.UUID, envelope []byte) string {
	t.Helper()
	for _, aad := range []string{"admin_mfa.secret:", "admin_mfa.pending_secret:"} {
		if pt, err := e.Keyring.Open(envelope, []byte(aad+user.String())); err == nil {
			return string(pt)
		}
	}
	t.Fatalf("the stored authenticator envelope does not open under either documented AAD")
	return ""
}

func mfPrincipal(e *authtest.Env, a authtest.User, session uuid.UUID) authz.Principal {
	return authz.Principal{UserID: a.ID, OrgID: e.Org, SessionID: session, Role: authz.RoleAdmin}
}

// mfSession is a live admin session by fixture (admin lifetimes) and its principal.
func mfSession(t *testing.T, e *authtest.Env, a authtest.User) (uuid.UUID, authz.Principal) {
	t.Helper()
	id := e.NewSession(t, a.ID, authtest.SessionSpec{MFAMethod: "totp", Idle: 12 * time.Hour, Absolute: 7 * 24 * time.Hour})
	return id, mfPrincipal(e, a, id)
}

// mfAfter decodes the "after" JSON of an audit row.
func mfAfter(t *testing.T, r authtest.AuditRow) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(r.After), &m); err != nil {
		t.Fatalf("audit %s after %q: %v", r.Action, r.After, err)
	}
	return m
}

// mfOnly returns the single audit row of an action.
func mfOnly(t *testing.T, e *authtest.Env, action string) authtest.AuditRow {
	t.Helper()
	rows := e.AuditOf(t, action)
	if len(rows) != 1 {
		t.Fatalf("audit rows %q = %d, want exactly 1", action, len(rows))
	}
	return rows[0]
}

func mfFailures(t *testing.T, e *authtest.Env, u authtest.User) int {
	t.Helper()
	return len(svThrottle(t, e, svUserKey(u)).Failures)
}

func mfLocked(t *testing.T, e *authtest.Env, u authtest.User) bool {
	t.Helper()
	return svThrottle(t, e, svUserKey(u)).Locked(e.Clock.Now())
}

func mfUsableCodes(t *testing.T, e *authtest.Env, u authtest.User) int {
	t.Helper()
	n, err := e.Store.CountUsableRecoveryCodes(t.Context(), u.ID)
	if err != nil {
		t.Fatalf("CountUsableRecoveryCodes: %v", err)
	}
	return n
}

func mfConsumed(t *testing.T, e *authtest.Env, token string) bool {
	t.Helper()
	return svCount(t, e, `SELECT count(*) FROM mfa_challenges WHERE consumed_at IS NOT NULL`) > 0
}
