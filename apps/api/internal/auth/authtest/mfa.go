package authtest

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"

	"github.com/NandanMaheta/swastik/apps/api/internal/auth"
)

// TOTPCode is the six-digit code a standard authenticator app shows for a base32 secret at the
// given instant (SHA-1, 30-second step).
func TOTPCode(t testing.TB, secret string, at time.Time) string {
	t.Helper()
	code, err := totp.GenerateCodeCustom(secret, at, totp.ValidateOpts{Period: 30, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
	if err != nil {
		t.Fatalf("authtest: totp code: %v", err)
	}
	return code
}

// EnrolAdmin gives an admin a confirmed authenticator at the clock's current time, written by SQL
// (not through the Store): the secret is sealed with the fixture key ring and last_used_step is 0.
// It returns the base32 secret and registers it with Secrets.
func (e *Env) EnrolAdmin(t *testing.T, admin uuid.UUID) string {
	t.Helper()
	secret, _, err := auth.GenerateTOTP("fixture-admin@example.com")
	if err != nil {
		t.Fatalf("authtest: generate totp: %v", err)
	}
	env, err := e.Keyring.Seal([]byte(secret), []byte("admin_mfa.secret:"+admin.String()))
	if err != nil {
		t.Fatalf("authtest: seal totp secret: %v", err)
	}
	now := e.Clock.Now()
	e.Exec(t, `INSERT INTO admin_mfa (user_id, org_id, secret_enc, enrolled_at, last_used_step, updated_at)
		VALUES ($1, $2, $3, $4, 0, $4)`, admin, e.Org, env, now)
	e.Secrets.AddTOTPSecret(secret)
	return secret
}

// NewRecoveryCodes inserts a fresh batch of recovery codes for the user by SQL and returns the
// codes in their displayed form. They are registered with Secrets.
func (e *Env) NewRecoveryCodes(t *testing.T, user uuid.UUID) []string {
	t.Helper()
	codes, err := auth.GenerateRecoveryCodes()
	if err != nil {
		t.Fatalf("authtest: recovery codes: %v", err)
	}
	batch := uuid.New()
	for _, c := range codes {
		e.Secrets.Add("recovery code", c)
		e.Exec(t, `INSERT INTO mfa_recovery_codes (org_id, user_id, batch_id, code_hash, created_at)
			VALUES ($1, $2, $3, $4, $5)`, e.Org, user, batch, auth.RecoveryCodeDigest(c), e.Clock.Now())
	}
	return codes
}

// AccessToken signs an access token for a fixture session, valid until the session's absolute
// expiry or 15 minutes after the clock's current time, whichever is first. It registers the token
// with Secrets.
func (e *Env) AccessToken(t *testing.T, u User, session uuid.UUID) string {
	t.Helper()
	ss, err := e.Store.GetSession(t.Context(), session)
	if err != nil {
		t.Fatalf("authtest: read session: %v", err)
	}
	tok, err := auth.NewTokens(e.Signing, e.Clock.Now).Issue(
		auth.AccessSubject{UserID: u.ID, SessionID: session, OrgID: e.Org, Role: u.Role}, ss.AbsoluteExpiresAt)
	if err != nil {
		t.Fatalf("authtest: issue access token: %v", err)
	}
	e.Secrets.Add("access token", tok)
	return tok
}
