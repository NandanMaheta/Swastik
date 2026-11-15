package auth_test

// S15 - admin second factor: verify and enrolment (spec US-5, FR-060..065, plan P-05).
// Real Store, real PostgreSQL, fake clock. API under test (compile stubs in mfa.go):
//
//	(*Service).VerifyMFA(ctx, MFAVerifyInput{ChallengeToken, Code | RecoveryCode, IP}) (SessionTokens, error)
//	(*Service).StartEnrolment(ctx, challengeToken) (TOTPEnrolment, error)
//	(*Service).ConfirmEnrolment(ctx, EnrolmentConfirmInput{ChallengeToken, Code, IP}) (EnrolmentResult, error)
//
// Errors: ErrInvalidCredentials (wrong, replayed or locked), ErrInvalidChallenge (any challenge
// problem), ErrNoPendingSecret.

import (
	"errors"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/NandanMaheta/swastik/apps/api/internal/auth"
	"github.com/NandanMaheta/swastik/apps/api/internal/auth/authtest"
)

var recoveryCodeShape = regexp.MustCompile(`^[0-9A-HJKMNP-TV-Z]{4}(-[0-9A-HJKMNP-TV-Z]{4}){3}$`)

func TestMFA_PasswordStepIssuesChallengeAndNoSession(t *testing.T) {
	e := authtest.New(t)
	s := e.Service(t)
	a := mfEnrolled(t, e)

	res := mfPassword(t, e, s, a.User, auth.ClientTypeMobile)
	if res.NextStep != auth.NextStepMFARequired {
		t.Errorf("next step = %q, want mfa_required", res.NextStep)
	}
	if !strings.HasPrefix(res.Challenge.Token, "dmc_") || !res.Challenge.ExpiresAt.Equal(e.Clock.Now().Add(5*time.Minute)) {
		t.Errorf("challenge = %+v, want a dmc_ token valid for 5 minutes", res.Challenge)
	}
	if got := svAllSessions(t, e, a.ID); got != 0 {
		t.Errorf("sessions after the password step = %d, want 0 (US-5 s1)", got)
	}
}

func TestMFA_VerifyHappyPathCreatesAdminSession(t *testing.T) {
	e := authtest.New(t)
	s := e.Service(t)
	a := mfEnrolled(t, e)
	tok := mfChallenge(t, e, s, a.User)
	e.Clock.Advance(time.Minute)

	got, err := s.VerifyMFA(t.Context(), mfVerifyIn(tok, mfCode(t, e, a.Secret, 0)))
	if err != nil {
		t.Fatalf("VerifyMFA: %v", err)
	}
	if got.User.ID != a.ID || got.User.Role != "admin" || got.AccessToken == "" || got.RefreshToken == "" {
		t.Fatalf("session = %+v", got)
	}
	now := e.Clock.Now()
	if !got.IdleExpiresAt.Equal(now.Add(12*time.Hour)) || !got.SessionExpiresAt.Equal(now.Add(7*24*time.Hour)) {
		t.Errorf("admin lifetimes: idle %v absolute %v, want 12h and 7d from %v", got.IdleExpiresAt, got.SessionExpiresAt, now)
	}
	if p, err := s.BearerVerifier().Verify(t.Context(), got.AccessToken); err != nil || p.UserID != a.ID || p.SessionID != got.SessionID {
		t.Errorf("access token verifies to %+v, %v", p, err)
	}
	if ss := svSession(t, e, got.SessionID); ss.MFAMethod != "totp" || ss.ClientType != "mobile" || ss.Platform != "android" {
		t.Errorf("session row = %+v, want mfa_method totp, mobile, android (copied from the challenge)", ss)
	}
	if m := mfMFARow(t, e, a.ID); m.LastUsedStep != auth.TOTPStepAt(now) {
		t.Errorf("last_used_step = %d, want %d", m.LastUsedStep, auth.TOTPStepAt(now))
	}
	if !mfConsumed(t, e, tok) {
		t.Errorf("the challenge is not consumed")
	}
	row := mfOnly(t, e, auth.ActionSignInSucceeded)
	after := mfAfter(t, row)
	if row.ActorKind != "admin" || row.ActorID != a.ID || row.EntityID != a.ID ||
		after["session_id"] != got.SessionID.String() || after["mfa_method"] != "totp" || after["ip"] != testIP {
		t.Errorf("sign-in audit = %+v %v", row, after)
	}
	if _, err := s.Refresh(t.Context(), auth.RefreshInput{DeviceID: svSession(t, e, got.SessionID).DeviceID,
		RefreshToken: got.RefreshToken, ClientType: auth.ClientTypeMobile, IP: testIP}); err != nil {
		t.Errorf("refresh of the new admin session: %v", err)
	}
}

func TestMFA_WebChallengeCarriesTheTransportToTheSession(t *testing.T) {
	e := authtest.New(t)
	s := e.Service(t)
	a := mfEnrolled(t, e)
	res := mfPassword(t, e, s, a.User, auth.ClientTypeWeb)
	got, err := s.VerifyMFA(t.Context(), mfVerifyIn(res.Challenge.Token, mfCode(t, e, a.Secret, 0)))
	if err != nil {
		t.Fatalf("VerifyMFA: %v", err)
	}
	if ss := svSession(t, e, got.SessionID); ss.ClientType != "web" {
		t.Errorf("session client_type = %q, want web", ss.ClientType)
	}
}

func TestMFA_WrongCodeIsGenericCountsOneAttemptAndKeepsTheChallenge(t *testing.T) {
	e := authtest.New(t)
	s := e.Service(t)
	a := mfEnrolled(t, e)
	tok := mfChallenge(t, e, s, a.User)

	_, err := s.VerifyMFA(t.Context(), mfVerifyIn(tok, mfWrong(t, e, a.Secret)))
	if !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Fatalf("wrong code: err = %v, want ErrInvalidCredentials (US-5 s3)", err)
	}
	if got := svAllSessions(t, e, a.ID); got != 0 {
		t.Errorf("sessions = %d, want 0", got)
	}
	if got := mfFailures(t, e, a.User); got != 1 {
		t.Errorf("counted failures = %d, want 1 on the user subject", got)
	}
	row := mfOnly(t, e, auth.ActionSignInFailed)
	if after := mfAfter(t, row); after["reason"] != auth.ReasonWrongTOTP || row.EntityID != a.ID {
		t.Errorf("failure audit = %+v %v, want reason wrong_totp for the admin", row, after)
	}
	if _, err := s.VerifyMFA(t.Context(), mfVerifyIn(tok, mfCode(t, e, a.Secret, 0))); err != nil {
		t.Errorf("the same challenge with the right code after a wrong one: %v (it must survive failures so the lockout can count)", err)
	}
}

func TestMFA_CodeSkewBoundaries(t *testing.T) {
	// US-5 s4: step N-1 is accepted, N-2 is not; the same on the late side.
	for _, tt := range []struct {
		offset time.Duration
		ok     bool
	}{{-60 * time.Second, false}, {-30 * time.Second, true}, {0, true}, {30 * time.Second, true}, {60 * time.Second, false}} {
		t.Run(tt.offset.String(), func(t *testing.T) {
			e := authtest.New(t)
			s := e.Service(t)
			a := mfEnrolled(t, e)
			tok := mfChallenge(t, e, s, a.User)
			_, err := s.VerifyMFA(t.Context(), mfVerifyIn(tok, mfCode(t, e, a.Secret, tt.offset)))
			if tt.ok && err != nil {
				t.Fatalf("offset %v: %v, want accepted", tt.offset, err)
			}
			if !tt.ok && !errors.Is(err, auth.ErrInvalidCredentials) {
				t.Fatalf("offset %v: err = %v, want ErrInvalidCredentials", tt.offset, err)
			}
		})
	}
}

func TestMFA_ReplayOfTheSameOrAnEarlierStepIsRejected(t *testing.T) {
	// US-5 s5: C accepted for step N; C again, and the code of N-1, are rejected; N+1 is fine.
	e := authtest.New(t)
	s := e.Service(t)
	a := mfEnrolled(t, e)
	c := mfCode(t, e, a.Secret, 0)
	if _, err := s.VerifyMFA(t.Context(), mfVerifyIn(mfChallenge(t, e, s, a.User), c)); err != nil {
		t.Fatalf("first use: %v", err)
	}
	for name, code := range map[string]string{"the same code": c, "the code of step N-1": mfCode(t, e, a.Secret, -30*time.Second)} {
		if _, err := s.VerifyMFA(t.Context(), mfVerifyIn(mfChallenge(t, e, s, a.User), code)); !errors.Is(err, auth.ErrInvalidCredentials) {
			t.Errorf("%s: err = %v, want ErrInvalidCredentials (no replay)", name, err)
		}
	}
	if m := mfMFARow(t, e, a.ID); m.LastUsedStep != auth.TOTPStepAt(e.Clock.Now()) {
		t.Errorf("last_used_step moved to %d by a rejected code", m.LastUsedStep)
	}
	if _, err := s.VerifyMFA(t.Context(), mfVerifyIn(mfChallenge(t, e, s, a.User), mfCode(t, e, a.Secret, 30*time.Second))); err != nil {
		t.Errorf("the code of step N+1: %v, want accepted", err)
	}
}

func TestMFA_RecoveryCodeSignsInOnceAndIsAudited(t *testing.T) {
	e := authtest.New(t)
	s := e.Service(t)
	a := mfEnrolled(t, e)
	k := a.Codes[3]
	typed := strings.ToLower(strings.ReplaceAll(k, "-", " ")) // normalised: case, spaces and hyphens do not matter

	got, err := s.VerifyMFA(t.Context(), auth.MFAVerifyInput{ChallengeToken: mfChallenge(t, e, s, a.User), RecoveryCode: typed, IP: testIP})
	if err != nil {
		t.Fatalf("recovery code sign-in: %v", err)
	}
	if ss := svSession(t, e, got.SessionID); ss.MFAMethod != "recovery_code" {
		t.Errorf("session mfa_method = %q, want recovery_code", ss.MFAMethod)
	}
	if n := mfUsableCodes(t, e, a.User); n != 9 {
		t.Errorf("usable codes = %d, want 9 (US-5 s6)", n)
	}
	used := mfOnly(t, e, auth.ActionMFARecoveryCodeUsed)
	if ua := mfAfter(t, used); used.ActorKind != "admin" || ua["remaining"] != float64(9) || ua["context"] != "sign_in" {
		t.Errorf("recovery_code_used audit = %+v %v", used, ua)
	}
	if sa := mfAfter(t, mfOnly(t, e, auth.ActionSignInSucceeded)); sa["mfa_method"] != "recovery_code" {
		t.Errorf("sign-in audit mfa_method = %v, want recovery_code", sa["mfa_method"])
	}

	_, err = s.VerifyMFA(t.Context(), auth.MFAVerifyInput{ChallengeToken: mfChallenge(t, e, s, a.User), RecoveryCode: k, IP: testIP})
	if !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Fatalf("the same recovery code again: err = %v, want ErrInvalidCredentials", err)
	}
	if after := mfAfter(t, e.AuditOf(t, auth.ActionSignInFailed)[0]); after["reason"] != auth.ReasonWrongRecoveryCode {
		t.Errorf("failure reason = %v, want wrong_recovery_code", after["reason"])
	}
	if mfFailures(t, e, a.User) != 1 {
		t.Errorf("a reused recovery code must count as one failed attempt")
	}
}

func TestMFA_ChallengeExpiresExactlyAtFiveMinutes(t *testing.T) {
	for _, tt := range []struct {
		wait time.Duration
		ok   bool
	}{{4*time.Minute + 59*time.Second, true}, {5 * time.Minute, false}, {5*time.Minute + time.Second, false}} {
		t.Run(tt.wait.String(), func(t *testing.T) {
			e := authtest.New(t)
			s := e.Service(t)
			a := mfEnrolled(t, e)
			tok := mfChallenge(t, e, s, a.User)
			e.Clock.Advance(tt.wait)
			_, err := s.VerifyMFA(t.Context(), mfVerifyIn(tok, mfCode(t, e, a.Secret, 0)))
			if tt.ok != (err == nil) {
				t.Fatalf("after %v: err = %v, want ok=%v", tt.wait, err, tt.ok)
			}
			if !tt.ok {
				if !errors.Is(err, auth.ErrInvalidChallenge) {
					t.Errorf("err = %v, want ErrInvalidChallenge (US-5 s7)", err)
				}
				if mfFailures(t, e, a.User) != 0 || svAllSessions(t, e, a.ID) != 0 {
					t.Errorf("an expired challenge must not count an attempt or create a session")
				}
			}
		})
	}
}

func TestMFA_ChallengeIsSingleUse(t *testing.T) {
	e := authtest.New(t)
	s := e.Service(t)
	a := mfEnrolled(t, e)
	tok := mfChallenge(t, e, s, a.User)
	if _, err := s.VerifyMFA(t.Context(), mfVerifyIn(tok, mfCode(t, e, a.Secret, 0))); err != nil {
		t.Fatalf("first use: %v", err)
	}
	_, err := s.VerifyMFA(t.Context(), mfVerifyIn(tok, mfCode(t, e, a.Secret, 30*time.Second)))
	if !errors.Is(err, auth.ErrInvalidChallenge) {
		t.Fatalf("second use with a fresh valid code: err = %v, want ErrInvalidChallenge", err)
	}
	if got := svAllSessions(t, e, a.ID); got != 1 {
		t.Errorf("sessions = %d, want 1", got)
	}
}

func TestMFA_NotAChallengeIsRejected(t *testing.T) {
	e := authtest.New(t)
	s := e.Service(t)
	a := mfEnrolled(t, e)
	sess := mfSignIn(t, e, s, a)
	for name, token := range map[string]string{
		"an access token":  sess.AccessToken,
		"a refresh token":  sess.RefreshToken,
		"an empty string":  "",
		"a made-up dmc_":   "dmc_" + strings.Repeat("A", 43),
		"a very long junk": strings.Repeat("x", 5000),
	} {
		_, err := s.VerifyMFA(t.Context(), mfVerifyIn(token, mfCode(t, e, a.Secret, 60*time.Second)))
		if !errors.Is(err, auth.ErrInvalidChallenge) {
			t.Errorf("%s: err = %v, want ErrInvalidChallenge", name, err)
		}
		if _, err := s.StartEnrolment(t.Context(), token); !errors.Is(err, auth.ErrInvalidChallenge) {
			t.Errorf("%s at StartEnrolment: err = %v, want ErrInvalidChallenge", name, err)
		}
	}
}

func TestMFA_WrongPurposeIsRejected(t *testing.T) {
	e := authtest.New(t)
	s := e.Service(t)
	enrolled := mfEnrolled(t, e)
	fresh := e.NewAdmin(t)

	verifyTok := mfChallenge(t, e, s, enrolled.User)
	if _, err := s.StartEnrolment(t.Context(), verifyTok); !errors.Is(err, auth.ErrInvalidChallenge) {
		t.Errorf("a verify challenge at StartEnrolment: err = %v, want ErrInvalidChallenge", err)
	}
	if _, err := s.ConfirmEnrolment(t.Context(), auth.EnrolmentConfirmInput{ChallengeToken: verifyTok, Code: "123456", IP: testIP}); !errors.Is(err, auth.ErrInvalidChallenge) {
		t.Errorf("a verify challenge at ConfirmEnrolment: err = %v, want ErrInvalidChallenge", err)
	}
	enrolTok := mfChallenge(t, e, s, fresh)
	if _, err := s.VerifyMFA(t.Context(), mfVerifyIn(enrolTok, "123456")); !errors.Is(err, auth.ErrInvalidChallenge) {
		t.Errorf("an enrol challenge at VerifyMFA: err = %v, want ErrInvalidChallenge", err)
	}
	if got := svAllSessions(t, e, enrolled.ID) + svAllSessions(t, e, fresh.ID); got != 0 {
		t.Errorf("sessions = %d, want 0", got)
	}
}

func TestMFA_DisabledAdminCannotCompleteSignIn(t *testing.T) {
	e := authtest.New(t)
	s := e.Service(t)
	a := mfEnrolled(t, e)
	other := e.NewAdmin(t) // so the last-admin guard does not interfere
	tok := mfChallenge(t, e, s, a.User)
	if err := s.Disable(t.Context(), a.ID, authtest.Admin(other.ID)); err != nil {
		t.Fatalf("Disable: %v", err)
	}
	_, err := s.VerifyMFA(t.Context(), mfVerifyIn(tok, mfCode(t, e, a.Secret, 0)))
	if !errors.Is(err, auth.ErrInvalidChallenge) {
		t.Fatalf("err = %v, want ErrInvalidChallenge for a disabled admin", err)
	}
	if got := svAllSessions(t, e, a.ID); got != 0 {
		t.Errorf("sessions = %d, want 0", got)
	}
}

func TestMFA_FifthWrongCodeLocksAndALockedAccountRefusesTheRightCode(t *testing.T) {
	e := authtest.New(t)
	s := e.Service(t)
	a := mfEnrolled(t, e)
	tok := mfChallenge(t, e, s, a.User)
	for i := 1; i <= 5; i++ {
		if _, err := s.VerifyMFA(t.Context(), mfVerifyIn(tok, mfWrong(t, e, a.Secret))); !errors.Is(err, auth.ErrInvalidCredentials) {
			t.Fatalf("wrong code %d: %v", i, err)
		}
	}
	if !mfLocked(t, e, a.User) {
		t.Fatal("five wrong codes did not lock the account (D-08)")
	}
	if got := len(e.AuditOf(t, auth.ActionLockoutStarted)); got != 1 {
		t.Errorf("lockout.started audit rows = %d, want 1", got)
	}
	_, err := s.VerifyMFA(t.Context(), mfVerifyIn(tok, mfCode(t, e, a.Secret, 0)))
	if !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Fatalf("correct code while locked: err = %v, want ErrInvalidCredentials", err)
	}
	if got := svAllSessions(t, e, a.ID); got != 0 {
		t.Errorf("sessions = %d, want 0 while locked", got)
	}
	// The lock ends 15 minutes after the 5th failure; a new password step then a right code works.
	e.Clock.Advance(15 * time.Minute)
	if _, err := s.VerifyMFA(t.Context(), mfVerifyIn(mfChallenge(t, e, s, a.User), mfCode(t, e, a.Secret, 0))); err != nil {
		t.Errorf("after the lock ended: %v", err)
	}
}

func TestMFA_PasswordAndCodeFailuresShareOneCounterAndThePasswordStepDoesNotClearIt(t *testing.T) {
	e := authtest.New(t)
	s := e.Service(t)
	a := mfEnrolled(t, e)
	for range 2 {
		svWrong(t, s, a.User)
	}
	tok := mfChallenge(t, e, s, a.User) // a correct password must not clear the two failures
	if got := mfFailures(t, e, a.User); got != 2 {
		t.Fatalf("failures after a correct password step = %d, want still 2", got)
	}
	for i := 0; i < 3; i++ {
		_, _ = s.VerifyMFA(t.Context(), mfVerifyIn(tok, mfWrong(t, e, a.Secret)))
	}
	if !mfLocked(t, e, a.User) {
		t.Fatal("2 wrong passwords + 3 wrong codes must lock (one shared counter)")
	}
}

func TestMFA_SuccessClearsTheCounter(t *testing.T) {
	e := authtest.New(t)
	s := e.Service(t)
	a := mfEnrolled(t, e)
	tok := mfChallenge(t, e, s, a.User)
	for range 3 {
		_, _ = s.VerifyMFA(t.Context(), mfVerifyIn(tok, mfWrong(t, e, a.Secret)))
	}
	if _, err := s.VerifyMFA(t.Context(), mfVerifyIn(tok, mfCode(t, e, a.Secret, 0))); err != nil {
		t.Fatalf("right code: %v", err)
	}
	if got := mfFailures(t, e, a.User); got != 0 {
		t.Errorf("failures after the second factor succeeded = %d, want 0", got)
	}
}

func TestMFA_EveryNewAdminSignInNeedsTheSecondFactorAgain(t *testing.T) {
	// US-5 s12: signing out and in again asks for TOTP; refreshing within the lifetime does not.
	e := authtest.New(t)
	s := e.Service(t)
	a := mfEnrolled(t, e)
	sess := mfSignIn(t, e, s, a)
	dev := svSession(t, e, sess.SessionID).DeviceID
	e.Clock.Advance(time.Hour)
	if _, err := s.Refresh(t.Context(), svRefreshIn(dev, sess.RefreshToken)); err != nil {
		t.Fatalf("refresh needs no second factor: %v", err)
	}
	p := mfPrincipal(e, a.User, sess.SessionID)
	if err := s.SignOut(t.Context(), p); err != nil {
		t.Fatalf("SignOut: %v", err)
	}
	res, err := s.SignIn(t.Context(), svInput(a.User, dev))
	if err != nil {
		t.Fatalf("SignIn: %v", err)
	}
	if res.NextStep != auth.NextStepMFARequired || res.Session != nil {
		t.Errorf("sign-in after sign-out = %+v, want mfa_required and no session", res)
	}
}

// ---- enrolment ----

func TestMFA_EnrolmentFlow(t *testing.T) {
	e := authtest.New(t)
	s := e.Service(t)
	a := e.NewAdmin(t) // bootstrapped: no authenticator yet
	res := mfPassword(t, e, s, a, auth.ClientTypeMobile)
	if res.NextStep != auth.NextStepMFAEnrolmentNeeded {
		t.Fatalf("next step = %q, want mfa_enrolment_required (US-5 s8)", res.NextStep)
	}
	tok := res.Challenge.Token

	enrol, err := s.StartEnrolment(t.Context(), tok)
	if err != nil {
		t.Fatalf("StartEnrolment: %v", err)
	}
	e.Secrets.AddTOTPSecret(enrol.Secret)
	if !regexp.MustCompile(`^[A-Z2-7]{32}$`).MatchString(enrol.Secret) {
		t.Errorf("secret %q is not 32 upper-case base32 characters (20 bytes)", enrol.Secret)
	}
	if !strings.HasPrefix(enrol.OTPAuthURI, "otpauth://totp/Swastik:") || !strings.Contains(enrol.OTPAuthURI, "secret="+enrol.Secret) ||
		!strings.Contains(enrol.OTPAuthURI, "issuer=Swastik") || !strings.Contains(enrol.OTPAuthURI, a.Email) {
		t.Errorf("otpauth uri = %q", enrol.OTPAuthURI)
	}
	m := mfMFARow(t, e, a.ID)
	if m.PendingSecretEnc == nil || m.SecretEnc != nil || m.EnrolledAt != nil {
		t.Fatalf("after start: %+v, want only a pending secret", m)
	}
	if got := mfOpenSecret(t, e, a.ID, m.PendingSecretEnc); got != enrol.Secret {
		t.Errorf("the pending envelope does not hold the shown secret")
	}
	var text string
	if err := e.Pool.QueryRow(t.Context(), `SELECT a::text FROM admin_mfa a`).Scan(&text); err != nil || strings.Contains(text, enrol.Secret) {
		t.Errorf("the plaintext secret is in the table (err=%v)", err)
	}
	if got := svAllSessions(t, e, a.ID); got != 0 {
		t.Errorf("sessions before confirm = %d, want 0 (enrolment cannot be skipped)", got)
	}

	done, err := s.ConfirmEnrolment(t.Context(), auth.EnrolmentConfirmInput{ChallengeToken: tok, Code: authtest.TOTPCode(t, enrol.Secret, e.Clock.Now()), IP: testIP})
	if err != nil {
		t.Fatalf("ConfirmEnrolment: %v", err)
	}
	e.Secrets.Add("access token", done.Session.AccessToken)
	e.Secrets.Add("refresh token", done.Session.RefreshToken)
	if done.Session.User.ID != a.ID || done.Session.User.Role != "admin" || len(done.RecoveryCodes) != 10 {
		t.Fatalf("result = %+v", done)
	}
	seen := map[string]bool{}
	for _, c := range done.RecoveryCodes {
		e.Secrets.Add("recovery code", c)
		if !recoveryCodeShape.MatchString(c) || seen[c] {
			t.Errorf("recovery code %q is malformed or repeated", c)
		}
		seen[c] = true
	}
	m = mfMFARow(t, e, a.ID)
	if m.SecretEnc == nil || m.PendingSecretEnc != nil || m.EnrolledAt == nil || m.LastUsedStep != auth.TOTPStepAt(e.Clock.Now()) {
		t.Errorf("after confirm: %+v, want a confirmed secret and last_used_step = the matched step", m)
	}
	if n := mfUsableCodes(t, e, a); n != 10 {
		t.Errorf("usable recovery codes = %d, want 10", n)
	}
	if _, ok, err := e.Store.UseRecoveryCode(t.Context(), a.ID, auth.RecoveryCodeDigest(done.RecoveryCodes[0]), e.Clock.Now()); err != nil || !ok {
		t.Errorf("a shown code is not usable from its digest: ok=%v err=%v", ok, err)
	}
	if ss := svSession(t, e, done.Session.SessionID); ss.MFAMethod != "enrolment" || ss.ClientType != "mobile" {
		t.Errorf("session = %+v, want mfa_method enrolment", ss)
	}
	enrolled := mfOnly(t, e, auth.ActionMFAEnrolled)
	if ea := mfAfter(t, enrolled); enrolled.ActorKind != "admin" || enrolled.ActorID != a.ID || ea["session_id"] != done.Session.SessionID.String() {
		t.Errorf("enrolled audit = %+v %v", enrolled, ea)
	}
	if sa := mfAfter(t, mfOnly(t, e, auth.ActionSignInSucceeded)); sa["mfa_method"] != "enrolment" {
		t.Errorf("sign-in audit mfa_method = %v, want enrolment", sa["mfa_method"])
	}
	e.Secrets.ScanAuditLog(t.Context(), t, e.Pool)

	// The next sign-in asks for a code.
	if next := mfPassword(t, e, s, a, auth.ClientTypeMobile); next.NextStep != auth.NextStepMFARequired {
		t.Errorf("sign-in after enrolment next step = %q, want mfa_required", next.NextStep)
	}
}

func TestMFA_EnrolmentChallengeIsNotAnAccessCredential(t *testing.T) {
	// US-5 s9 and US-2 s9: before confirm, no admin operation works.
	e := authtest.New(t)
	s := e.Service(t)
	a := e.NewAdmin(t)
	tok := mfPassword(t, e, s, a, auth.ClientTypeMobile).Challenge.Token
	if _, err := s.StartEnrolment(t.Context(), tok); err != nil {
		t.Fatalf("StartEnrolment: %v", err)
	}
	if err := svVerify(t, s.BearerVerifier(), tok); err == nil {
		t.Error("the bearer verifier accepted an enrolment challenge")
	}
	if p, err := s.ChallengeVerifier().Verify(t.Context(), tok); err != nil || p.SessionID != uuid.Nil {
		t.Errorf("the challenge verifier = %+v, %v, want a principal with no session", p, err)
	}
}

func TestMFA_EnrolmentWrongCodeKeepsPendingAndChallenge(t *testing.T) {
	e := authtest.New(t)
	s := e.Service(t)
	a := e.NewAdmin(t)
	tok := mfPassword(t, e, s, a, auth.ClientTypeMobile).Challenge.Token
	enrol, err := s.StartEnrolment(t.Context(), tok)
	if err != nil {
		t.Fatalf("StartEnrolment: %v", err)
	}
	e.Secrets.AddTOTPSecret(enrol.Secret)
	_, err = s.ConfirmEnrolment(t.Context(), auth.EnrolmentConfirmInput{ChallengeToken: tok, Code: mfWrong(t, e, enrol.Secret), IP: testIP})
	if !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Fatalf("wrong code: err = %v, want ErrInvalidCredentials", err)
	}
	if m := mfMFARow(t, e, a.ID); m.PendingSecretEnc == nil || m.EnrolledAt != nil {
		t.Errorf("after a wrong confirm: %+v, want the pending secret kept and nothing enrolled", m)
	}
	if got := svAllSessions(t, e, a.ID); got != 0 {
		t.Errorf("sessions = %d, want 0", got)
	}
	if _, err := s.ConfirmEnrolment(t.Context(), auth.EnrolmentConfirmInput{ChallengeToken: tok, Code: authtest.TOTPCode(t, enrol.Secret, e.Clock.Now()), IP: testIP}); err != nil {
		t.Errorf("retry with the right code: %v", err)
	}
}

func TestMFA_ConfirmWithoutAPendingSecret(t *testing.T) {
	e := authtest.New(t)
	s := e.Service(t)
	a := e.NewAdmin(t)
	tok := mfPassword(t, e, s, a, auth.ClientTypeMobile).Challenge.Token
	_, err := s.ConfirmEnrolment(t.Context(), auth.EnrolmentConfirmInput{ChallengeToken: tok, Code: "123456", IP: testIP})
	if !errors.Is(err, auth.ErrNoPendingSecret) {
		t.Fatalf("err = %v, want ErrNoPendingSecret", err)
	}
}

func TestMFA_StartingEnrolmentAgainReplacesThePendingSecret(t *testing.T) {
	e := authtest.New(t)
	s := e.Service(t)
	a := e.NewAdmin(t)
	tok := mfPassword(t, e, s, a, auth.ClientTypeMobile).Challenge.Token
	first, err := s.StartEnrolment(t.Context(), tok)
	if err != nil {
		t.Fatal(err)
	}
	second, err := s.StartEnrolment(t.Context(), tok)
	if err != nil {
		t.Fatal(err)
	}
	e.Secrets.AddTOTPSecret(first.Secret)
	e.Secrets.AddTOTPSecret(second.Secret)
	if first.Secret == second.Secret {
		t.Fatal("a second start returned the same secret")
	}
	if got := mfOpenSecret(t, e, a.ID, mfMFARow(t, e, a.ID).PendingSecretEnc); got != second.Secret {
		t.Error("the pending secret is not the latest one")
	}
	_, err = s.ConfirmEnrolment(t.Context(), auth.EnrolmentConfirmInput{ChallengeToken: tok, Code: authtest.TOTPCode(t, first.Secret, e.Clock.Now()), IP: testIP})
	if !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Errorf("a code of the replaced secret: err = %v, want ErrInvalidCredentials", err)
	}
	if _, err := s.ConfirmEnrolment(t.Context(), auth.EnrolmentConfirmInput{ChallengeToken: tok, Code: authtest.TOTPCode(t, second.Secret, e.Clock.Now()), IP: testIP}); err != nil {
		t.Errorf("a code of the latest secret: %v", err)
	}
}

func TestMFA_EnrolmentChallengeIsSingleUseAndExpires(t *testing.T) {
	e := authtest.New(t)
	s := e.Service(t)
	a := e.NewAdmin(t)
	tok := mfPassword(t, e, s, a, auth.ClientTypeMobile).Challenge.Token
	enrol, err := s.StartEnrolment(t.Context(), tok)
	if err != nil {
		t.Fatal(err)
	}
	e.Secrets.AddTOTPSecret(enrol.Secret)
	if _, err := s.ConfirmEnrolment(t.Context(), auth.EnrolmentConfirmInput{ChallengeToken: tok, Code: authtest.TOTPCode(t, enrol.Secret, e.Clock.Now()), IP: testIP}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.StartEnrolment(t.Context(), tok); !errors.Is(err, auth.ErrInvalidChallenge) {
		t.Errorf("StartEnrolment with a consumed challenge: %v, want ErrInvalidChallenge", err)
	}
	b := e.NewAdmin(t)
	tok2 := mfPassword(t, e, s, b, auth.ClientTypeMobile).Challenge.Token
	e.Clock.Advance(5 * time.Minute)
	if _, err := s.StartEnrolment(t.Context(), tok2); !errors.Is(err, auth.ErrInvalidChallenge) {
		t.Errorf("StartEnrolment at exactly 5 minutes: %v, want ErrInvalidChallenge", err)
	}
}
