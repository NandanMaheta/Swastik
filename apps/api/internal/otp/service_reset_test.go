package otp_test

// S14 - forgot password: StartReset and CompleteReset (feature 004; BR-CLI-04; spec US4.1-US4.3,
// US2.3, D-03, D-06, D-07, FR-008, FR-009, FR-010; 003 D-13, D-22). Uniformity is tested by
// comparing what a stranger can observe for known, unknown and ineligible identifiers.

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/NandanMaheta/swastik/apps/api/internal/auth"
	"github.com/NandanMaheta/swastik/apps/api/internal/auth/authtest"
	"github.com/NandanMaheta/swastik/apps/api/internal/otp"
	"github.com/NandanMaheta/swastik/apps/api/internal/otp/otptest"
)

const svNewPassword = "tangerine-harbour-91-solstice"

func svStartReset(e *otptest.Env, identifier string) (otp.ResetStarted, error) {
	return e.Svc.StartReset(context.Background(), otptest.DefaultIP, identifier)
}

// svResetToken runs a full reset up to the one-time permission for an active user and returns it.
func svResetToken(t *testing.T, e *otptest.Env, u authtest.User) (otp.ResetStarted, string) {
	t.Helper()
	rs, err := svStartReset(e, u.Email)
	if err != nil {
		t.Fatalf("StartReset: %v", err)
	}
	res, err := svVerifyEmail(e, rs.Handle, e.LastCode(t))
	if err != nil {
		t.Fatalf("VerifyEmail (reset): %v", err)
	}
	if !svResetRE.MatchString(res.ResetToken) {
		t.Fatalf("reset token = %q, want prt_ and 43 URL-safe characters", res.ResetToken)
	}
	return rs, res.ResetToken
}

func svComplete(e *otptest.Env, rs otp.ResetStarted, token, pw string) error {
	return e.Svc.CompleteReset(context.Background(), otptest.DefaultIP, rs.Handle, token, pw)
}

func svSignIn(e *otptest.Env, u authtest.User, password string) error {
	_, err := e.Auth.SignIn(context.Background(), auth.SignInInput{
		Identifier: u.Email, Password: password, ClientType: auth.ClientTypeMobile, IP: "198.51.100.99",
		Device: auth.DeviceInfo{ID: uuid.New(), Name: "Pixel", Platform: auth.PlatformAndroid},
	})
	return err
}

func TestStartReset_BR_CLI_04_AnActiveClientGetsTheCodeByEmailWhicheverIdentifierTheyType(t *testing.T) {
	e := otptest.NewEnv(t)
	now := e.Clock.Now()
	for name, typed := range map[string]func(authtest.User) string{
		"mobile with +91":  func(u authtest.User) string { return u.Mobile },
		"mobile 10 digits": func(u authtest.User) string { return strings.TrimPrefix(u.Mobile, "+91") },
		"email upper case": func(u authtest.User) string { return upperOf(u.Email) },
	} {
		u := e.Active(t)
		before := len(e.Mailer.Mails())
		e.Waits.Reset()
		rs, err := svStartReset(e, typed(u))
		if err != nil {
			t.Fatalf("%s: StartReset: %v", name, err)
		}
		if !svHandleRE.MatchString(rs.Handle) || !rs.ExpiresAt.Equal(now.Add(otp.VerificationTTL)) || !rs.NextResendAt.Equal(now.Add(otp.ResendCooldown)) {
			t.Errorf("%s: reply = %+v", name, rs)
		}
		mails := e.Mailer.Mails()
		if len(mails) != before+1 || mails[before].To != u.Email {
			t.Fatalf("%s: mails = %d (want %d), last to %q: the code always goes to the account email (D-06)", name, len(mails), before+1, mails[len(mails)-1].To)
		}
		if w := e.Waits.Untils(); len(w) != 1 || !w[0].Equal(now.Add(svFloor)) {
			t.Errorf("%s: floor waits = %v, want one until start + 1.5 s", name, w)
		}
		var vid uuid.UUID
		var purpose, email string
		if err := e.Pool.QueryRow(context.Background(), `SELECT id, purpose, email FROM otp_verifications WHERE user_id = $1`, u.ID).Scan(&vid, &purpose, &email); err != nil ||
			purpose != "password_reset" || email != u.Email {
			t.Errorf("%s: verification = %s %q %q, %v", name, vid, purpose, email, err)
		}
		found := false
		for _, r := range e.OTPAudit(t) {
			if r.EntityID == u.ID && otptest.AuditAfter(t, r)["purpose"] == "password_reset" {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: no audit entry for the known user's reset (US6.1)", name)
		}
		svNoLeak(t, name+" audit", svAuditText(t, e), typed(u), u.Email, strings.TrimPrefix(u.Mobile, "+91"))
	}
}

func TestStartReset_BR_CLI_04_StrangersGetTheSameReplyAndNothingIsSentOrAudited(t *testing.T) {
	e := otptest.NewEnv(t)
	now := e.Clock.Now()
	pending := e.Pending(t)
	approval := e.UserWithStatus(t, auth.StatusPendingApproval)
	disabled := e.UserWithStatus(t, auth.StatusDisabled)
	admin := e.NewAdmin(t)
	identifiers := map[string]string{
		"unknown email": "nobody.here@example.com", "unknown mobile": "+919123456789",
		"pending_verification": pending.Email, "pending_approval": approval.Mobile, "disabled": disabled.Email, "admin": admin.Email,
	}
	for name, id := range identifiers {
		rs, err := svStartReset(e, id)
		if err != nil {
			t.Fatalf("%s: StartReset: %v, want the same 202-style reply as for a real account (D-07)", name, err)
		}
		if !svHandleRE.MatchString(rs.Handle) || !rs.ExpiresAt.Equal(now.Add(otp.VerificationTTL)) || !rs.NextResendAt.Equal(now.Add(otp.ResendCooldown)) {
			t.Errorf("%s: reply = %+v, want the same shape and times as a known account", name, rs)
		}
	}
	if n := len(e.Mailer.Mails()) + e.Mailer.Calls() + len(e.OutboxRows(t, "")); n != 0 {
		t.Errorf("mails/outbox rows = %d, want 0: no email for anyone who cannot reset (US4.2)", n)
	}
	if rows := e.OTPAudit(t); len(rows) != 0 {
		t.Errorf("audit rows = %d, want 0: nothing names an unmatched identifier (FR-010, 003 FR-091)", len(rows))
	}
	if w := e.Waits.Untils(); len(w) != len(identifiers) {
		t.Errorf("floor waits = %d, want one per call (%d): decoys wait like real sends", len(w), len(identifiers))
	} else {
		for _, until := range w {
			if !until.Equal(now.Add(svFloor)) {
				t.Errorf("a decoy waited until %v, want start + 1.5 s", until)
			}
		}
	}
	// Each reply is backed by a decoy: no user, no email, a live code with no outbox message.
	if n := e.Count(t, `SELECT count(*) FROM otp_verifications WHERE purpose = 'password_reset' AND user_id IS NULL AND email IS NULL`); n != len(identifiers) {
		t.Errorf("decoy verifications = %d, want %d", n, len(identifiers))
	}
	if n := e.Count(t, `SELECT count(*) FROM otp_email_codes c JOIN otp_verifications v ON v.id = c.verification_id
		WHERE v.user_id IS NULL AND c.ended_at IS NULL AND c.outbox_key IS NULL AND octet_length(c.code_digest) = 32`); n != len(identifiers) {
		t.Errorf("decoy live codes = %d, want %d", n, len(identifiers))
	}
	for name, u := range map[string]authtest.User{"pending": pending, "approval": approval, "disabled": disabled, "admin": admin} {
		if n := e.Count(t, `SELECT count(*) FROM otp_verifications WHERE user_id = $1`, u.ID); n != 0 {
			t.Errorf("%s: a real verification was created for an account that cannot reset", name)
		}
	}
}

// svWrongSequence enters five wrong codes and reports each outcome as a short word.
func svWrongSequence(t *testing.T, e *otptest.Env, handle, wrong string) []string {
	t.Helper()
	var out []string
	for i := 0; i < otp.MaxWrongAttempts; i++ {
		_, err := svVerifyEmail(e, handle, wrong)
		switch {
		case errors.Is(err, otp.ErrCodeWrong):
			out = append(out, "wrong")
		case errors.Is(err, otp.ErrCodeUsedUp):
			out = append(out, "used_up")
		default:
			out = append(out, fmt.Sprint(err))
		}
	}
	return out
}

func TestStartReset_BR_CLI_04_ADecoyStatusResendAndVerifyBehaveLikeARealFlow(t *testing.T) {
	e := otptest.NewEnv(t)
	u := e.Active(t)
	t0 := e.Clock.Now()
	real, err := svStartReset(e, u.Email)
	if err != nil {
		t.Fatal(err)
	}
	decoy, err := svStartReset(e, "nobody.here@example.com")
	if err != nil {
		t.Fatal(err)
	}
	for name, h := range map[string]string{"real": real.Handle, "decoy": decoy.Handle} {
		v, err := e.Svc.Status(t.Context(), otptest.Caller(), h)
		if err != nil || v.Purpose != otp.PurposePasswordReset || v.State != otp.FlowOpen {
			t.Fatalf("%s: Status = %+v, %v", name, v, err)
		}
		if (v.Email != nil && v.Email.Masked != "") || (v.Mobile != nil && v.Mobile.Masked != "") {
			t.Errorf("%s: a reset status shows a masked contact (plan I-2): %+v", name, v)
		}
	}
	for name, h := range map[string]string{"real": real.Handle, "decoy": decoy.Handle} {
		e.Clock.Set(t0.Add(59 * time.Second))
		_, err := e.Svc.Resend(t.Context(), otptest.Caller(), h)
		if re := svRetry(t, err, otp.ReasonCooldown); re.RetryAfter != time.Second {
			t.Errorf("%s: resend at 59 s RetryAfter = %v, want 1s", name, re.RetryAfter)
		}
		e.Clock.Set(t0)
	}
	mailsBefore := len(e.Mailer.Mails())
	e.Clock.Set(t0.Add(otp.ResendCooldown))
	for name, h := range map[string]string{"real": real.Handle, "decoy": decoy.Handle} {
		if _, err := e.Svc.Resend(t.Context(), otptest.Caller(), h); err != nil {
			t.Errorf("%s: resend at 60 s: %v", name, err)
		}
	}
	if got := len(e.Mailer.Mails()) - mailsBefore; got != 1 {
		t.Errorf("mails from the two resends = %d, want 1 (the decoy sends nothing)", got)
	}
	wantSeq := []string{"wrong", "wrong", "wrong", "wrong", "used_up"}
	realSeq := svWrongSequence(t, e, real.Handle, svWrongOf(e.LastCode(t)))
	decoySeq := svWrongSequence(t, e, decoy.Handle, "000000")
	if fmt.Sprint(realSeq) != fmt.Sprint(wantSeq) || fmt.Sprint(decoySeq) != fmt.Sprint(realSeq) {
		t.Errorf("wrong-entry outcomes: real %v, decoy %v, want both %v (D-07)", realSeq, decoySeq, wantSeq)
	}
}

// svResetTrace drives StartReset for one identifier at fixed offsets and reports each outcome.
func svResetTrace(t *testing.T, e *otptest.Env, identifier string, t0 time.Time) []string {
	t.Helper()
	var out []string
	for _, off := range []time.Duration{0, 0, 61 * time.Second, 122 * time.Second, 183 * time.Second, 244 * time.Second, 305 * time.Second} {
		e.Clock.Set(t0.Add(off))
		_, err := svStartReset(e, identifier)
		var re *otp.RetryError
		switch {
		case err == nil:
			out = append(out, "ok")
		case errors.As(err, &re):
			out = append(out, fmt.Sprintf("%s:%v", re.Reason, re.RetryAfter))
		default:
			out = append(out, "error:"+err.Error())
		}
	}
	return out
}

func TestStartReset_BR_CLI_04_LimitsApplyToUnknownIdentifiersExactlyAsToKnownOnes(t *testing.T) {
	e := otptest.NewEnv(t)
	u := e.Active(t)
	t0 := e.Clock.Now()
	known := svResetTrace(t, e, u.Email, t0)
	unknown := svResetTrace(t, e, "ghost.person@example.com", t0)
	want := []string{"ok", "cooldown:1m0s", "ok", "ok", "ok", "ok", "rate_limited:54m55s"}
	if fmt.Sprint(known) != fmt.Sprint(want) {
		t.Errorf("known trace = %v, want %v (60 s cooldown, 5 per hour; D-03)", known, want)
	}
	if fmt.Sprint(unknown) != fmt.Sprint(known) {
		t.Errorf("unknown trace = %v, known = %v: they must be identical (D-07)", unknown, known)
	}
}

func TestStartReset_BR_CLI_04_TwentyRequestsPerAddressPerHourWhateverTheIdentifier(t *testing.T) {
	e := otptest.NewEnv(t)
	u := e.Active(t)
	const ip = "198.51.100.30"
	for i := 0; i < 20; i++ {
		if _, err := e.Svc.StartReset(t.Context(), ip, fmt.Sprintf("stranger%d@example.com", i)); err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
	}
	_, err := e.Svc.StartReset(t.Context(), ip, u.Email) // even a real account
	if re := svRetry(t, err, otp.ReasonRateLimited); re.RetryAfter != time.Hour {
		t.Errorf("RetryAfter = %v, want 1h (US2.3)", re.RetryAfter)
	}
	if n := len(e.Mailer.Mails()); n != 0 {
		t.Errorf("mails = %d: a limited request must not send", n)
	}
	e.Clock.Advance(time.Hour)
	if _, err := e.Svc.StartReset(t.Context(), ip, u.Email); err != nil {
		t.Errorf("after the hour: %v", err)
	}
}

func TestStartReset_BR_CLI_04_OnlyAMalformedIdentifierIsRefused(t *testing.T) {
	e := otptest.NewEnv(t)
	for _, bad := range []string{"", "   ", "not an identifier", "12345", "a@b@c.com"} {
		if _, err := svStartReset(e, bad); !errors.Is(err, auth.ErrInvalidIdentifier) {
			t.Errorf("StartReset(%q) = %v, want auth.ErrInvalidIdentifier (the only distinguishable error, FR-009)", bad, err)
		}
	}
	if n := e.Count(t, `SELECT count(*) FROM otp_verifications`); n != 0 {
		t.Errorf("verifications = %d, want 0", n)
	}
}

func TestStartReset_BR_CLI_04_ANewStartSupersedesTheOldResetAndItsCode(t *testing.T) {
	e := otptest.NewEnv(t)
	u := e.Active(t)
	first, err := svStartReset(e, u.Email)
	if err != nil {
		t.Fatal(err)
	}
	oldCode := e.LastCode(t)
	e.Clock.Advance(otp.ResendCooldown + time.Second)
	second, err := svStartReset(e, u.Email)
	if err != nil || first.Handle == second.Handle {
		t.Fatalf("second StartReset: %+v, %v, want a new handle", second, err)
	}
	if got := e.Count(t, `SELECT count(*) FROM otp_verifications WHERE user_id = $1 AND cancel_reason = 'superseded'`, u.ID); got != 1 {
		t.Errorf("superseded verifications = %d, want 1", got)
	}
	if newCode := e.LastCode(t); newCode != oldCode {
		if _, err := svVerifyEmail(e, first.Handle, oldCode); err == nil {
			t.Error("the code of a superseded reset still works")
		}
	}
}

func TestCompleteReset_BR_CLI_04_SetsThePasswordEndsEverySessionAndClearsTheLock(t *testing.T) {
	e := otptest.NewEnv(t)
	u := e.Active(t)
	e.NewSession(t, u.ID, authtest.SessionSpec{})
	e.NewSession(t, u.ID, authtest.SessionSpec{})
	for i := 0; i < 5; i++ { // lock the account with wrong passwords (003 D-08)
		_ = svSignIn(e, u, "wrong-password-"+fmt.Sprint(i))
	}
	if err := svSignIn(e, u, u.Password); err == nil {
		t.Fatal("setup: the account is not locked after 5 wrong passwords")
	}

	rs, token := svResetToken(t, e, u)
	e.Clock.Advance(time.Minute)
	if err := svComplete(e, rs, token, svNewPassword); err != nil {
		t.Fatalf("CompleteReset: %v", err)
	}
	if n := e.Count(t, `SELECT count(*) FROM device_sessions WHERE user_id = $1 AND ended_at IS NULL`, u.ID); n != 0 {
		t.Errorf("live sessions after the reset = %d, want 0 (003 D-13)", n)
	}
	if err := svSignIn(e, u, svNewPassword); err != nil {
		t.Errorf("sign-in with the new password: %v, want it to work at once (the lock is cleared)", err)
	}
	if err := svSignIn(e, u, u.Password); err == nil {
		t.Error("the old password still works")
	}
	if got := svVer(t, e, mustOnlyVerification(t, e, u.ID)); got.Finished == nil {
		t.Error("the reset verification is not finished")
	}
	for _, action := range []string{"otp.reset.code_accepted", "otp.reset.completed"} {
		if rows := svAuditOf(t, e, action); len(rows) != 1 {
			t.Errorf("%s audit rows = %d, want 1", action, len(rows))
		}
	}
	if rows := e.AuditOf(t, auth.ActionPasswordReset); len(rows) != 1 {
		t.Errorf("auth.password.reset audit rows = %d, want 1", len(rows))
	}
	svNoLeak(t, "audit", svAuditText(t, e)+fmt.Sprint(e.AuditRows(t)), svNewPassword, token, u.Password)

	// US4.3: the same permission and the same code cannot be used again.
	if err := svComplete(e, rs, token, "another-password-4455-xyz"); !errors.Is(err, otp.ErrResetTokenInvalid) {
		t.Errorf("reusing the reset token: %v, want ErrResetTokenInvalid", err)
	}
	if err := svSignIn(e, u, "another-password-4455-xyz"); err == nil {
		t.Error("a second reset changed the password")
	}
}

func mustOnlyVerification(t *testing.T, e *otptest.Env, user uuid.UUID) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := e.Pool.QueryRow(context.Background(), `SELECT id FROM otp_verifications WHERE user_id = $1`, user).Scan(&id); err != nil {
		t.Fatalf("the user's verification: %v", err)
	}
	return id
}

func TestCompleteReset_BR_CLI_04_TheCodeOfAFinishedResetIsSpent(t *testing.T) {
	e := otptest.NewEnv(t)
	u := e.Active(t)
	rs, err := svStartReset(e, u.Email)
	if err != nil {
		t.Fatal(err)
	}
	code := e.LastCode(t)
	if _, err := svVerifyEmail(e, rs.Handle, code); err != nil {
		t.Fatal(err)
	}
	if _, err := svVerifyEmail(e, rs.Handle, code); !errors.Is(err, otp.ErrCodeExpired) {
		t.Errorf("entering the code twice: %v, want ErrCodeExpired (US4.3)", err)
	}
}

func TestCompleteReset_BR_CLI_04_APolicyErrorKeepsThePermission(t *testing.T) {
	e := otptest.NewEnv(t)
	u := e.Active(t)
	e.NewSession(t, u.ID, authtest.SessionSpec{})
	rs, token := svResetToken(t, e, u)

	err := svComplete(e, rs, token, "short")
	var pe *auth.PolicyError
	if !errors.As(err, &pe) || pe.Code != auth.PolicyTooShort {
		t.Fatalf("a weak password: %v, want *auth.PolicyError %s (so the handler answers auth.password_*)", err, auth.PolicyTooShort)
	}
	if n := e.Count(t, `SELECT count(*) FROM device_sessions WHERE user_id = $1 AND ended_at IS NULL`, u.ID); n != 1 {
		t.Errorf("live sessions after a failed reset = %d, want 1: nothing may change", n)
	}
	if err := svComplete(e, rs, token, svNewPassword); err != nil {
		t.Errorf("the second try with the same token: %v, want it accepted", err)
	}
}

func TestCompleteReset_BR_CLI_04_ThePermissionLivesTenMinutes(t *testing.T) {
	for _, tc := range []struct {
		name string
		at   time.Duration
		ok   bool
	}{{"9:59", otp.ResetTokenTTL - time.Second, true}, {"10:00", otp.ResetTokenTTL, false}} {
		t.Run(tc.name, func(t *testing.T) {
			e := otptest.NewEnv(t)
			u := e.Active(t)
			rs, err := svStartReset(e, u.Email)
			if err != nil {
				t.Fatal(err)
			}
			res, err := svVerifyEmail(e, rs.Handle, e.LastCode(t))
			if err != nil {
				t.Fatal(err)
			}
			if res.ResetTokenExpiresAt == nil || !res.ResetTokenExpiresAt.Equal(e.Clock.Now().Add(otp.ResetTokenTTL)) {
				t.Errorf("ResetTokenExpiresAt = %v, want now + 10 min", res.ResetTokenExpiresAt)
			}
			e.Clock.Advance(tc.at)
			err = svComplete(e, rs, res.ResetToken, svNewPassword)
			if tc.ok && err != nil {
				t.Errorf("CompleteReset: %v, want accepted", err)
			}
			if !tc.ok {
				if !errors.Is(err, otp.ErrResetTokenInvalid) {
					t.Errorf("CompleteReset: %v, want ErrResetTokenInvalid", err)
				}
				if err := svSignIn(e, u, u.Password); err != nil {
					t.Errorf("the old password after a refused reset: %v", err)
				}
			}
		})
	}
}

func TestCompleteReset_BR_CLI_04_ForgedOrForeignPermissionsAreRefused(t *testing.T) {
	e := otptest.NewEnv(t)
	a, b := e.Active(t), e.Active(t)
	rsA, tokenA := svResetToken(t, e, a)
	_, tokenB := svResetToken(t, e, b)
	pendingStep, err := svStartReset(e, e.Active(t).Email) // code never entered: no permission exists yet
	if err != nil {
		t.Fatal(err)
	}
	decoy, err := svStartReset(e, "ghost.person@example.com")
	if err != nil {
		t.Fatal(err)
	}
	forged := "prt_" + strings.Repeat("A", 43)
	cases := map[string]struct {
		rs    otp.ResetStarted
		token string
	}{
		"a made-up token":               {rsA, forged},
		"another reset's token":         {rsA, tokenB},
		"an unknown handle":             {otp.ResetStarted{Handle: "ovh_" + strings.Repeat("B", 43)}, tokenA},
		"before the code was entered":   {pendingStep, forged},
		"a decoy handle":                {decoy, forged},
		"an empty token":                {rsA, ""},
		"a token with the wrong prefix": {rsA, strings.Replace(tokenA, "prt_", "xxx_", 1)},
	}
	for name, c := range cases {
		if err := svComplete(e, c.rs, c.token, svNewPassword); !errors.Is(err, otp.ErrResetTokenInvalid) {
			t.Errorf("%s: %v, want ErrResetTokenInvalid (one answer for every bad permission)", name, err)
		}
	}
	for _, u := range []authtest.User{a, b} {
		if err := svSignIn(e, u, u.Password); err != nil {
			t.Errorf("a refused reset changed the password of %s: %v", u.ID, err)
		}
	}
}

func TestCompleteReset_BR_CLI_04_OnlyOneOfTwoSimultaneousCompletionsWins(t *testing.T) {
	e := otptest.NewEnv(t)
	u := e.Active(t)
	rs, token := svResetToken(t, e, u)
	const n = 3
	errs := make([]error, n)
	var ready, done sync.WaitGroup
	start := make(chan struct{})
	ready.Add(n)
	done.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer done.Done()
			ready.Done()
			<-start
			errs[i] = svComplete(e, rs, token, fmt.Sprintf("%s-%d", svNewPassword, i))
		}()
	}
	ready.Wait()
	close(start)
	done.Wait()
	wins := 0
	for _, err := range errs {
		if err == nil {
			wins++
		} else if !errors.Is(err, otp.ErrResetTokenInvalid) {
			t.Errorf("a losing completion returned %v, want ErrResetTokenInvalid", err)
		}
	}
	if wins != 1 {
		t.Fatalf("%d of %d simultaneous completions succeeded, want exactly 1 (single use)", wins, n)
	}
	if rows := e.AuditOf(t, auth.ActionPasswordReset); len(rows) != 1 {
		t.Errorf("auth.password.reset audit rows = %d, want 1", len(rows))
	}
}
