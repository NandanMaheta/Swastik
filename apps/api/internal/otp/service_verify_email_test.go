package otp_test

// S12 - VerifyEmail and Status (feature 004; BR-CLI-04, BR-CLI-05; spec US1.2-US1.4, US5.1-US5.3,
// D-01, D-02, D-03 (check limit), D-08, D-09, FR-002, FR-003, FR-006, FR-007, FR-010).
// Codes are read from the sealed outbox message (PendingCode) or from the mail the fake mailer got.

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/NandanMaheta/swastik/apps/api/internal/auth/authtest"
	"github.com/NandanMaheta/swastik/apps/api/internal/otp"
	"github.com/NandanMaheta/swastik/apps/api/internal/otp/otptest"
)

// svUserState is what the verification must change on the account (and nothing else).
type svUserState struct {
	Status                        string
	EmailVerified, MobileVerified bool
	Email, Mobile                 string
}

func svUser(t *testing.T, e *otptest.Env, id uuid.UUID) svUserState {
	t.Helper()
	var s svUserState
	var mobile *string
	err := e.Pool.QueryRow(context.Background(), `SELECT status, email_verified_at IS NOT NULL, mobile_verified_at IS NOT NULL, email, mobile
		FROM users WHERE id = $1`, id).Scan(&s.Status, &s.EmailVerified, &s.MobileVerified, &s.Email, &mobile)
	if err != nil {
		t.Fatalf("read user: %v", err)
	}
	if mobile != nil {
		s.Mobile = *mobile
	}
	return s
}

func svVerifyEmail(e *otptest.Env, handle, code string) (otp.VerifyEmailResult, error) {
	return e.Svc.VerifyEmail(context.Background(), otptest.Caller(), handle, code)
}

func TestVerifyEmail_BR_CLI_04_CodeIsValidUntilTheTenMinuteInstant(t *testing.T) {
	for _, tc := range []struct {
		name string
		at   time.Duration
		ok   bool
	}{{"10:09:59 is accepted", otp.CodeTTL - time.Second, true}, {"10:10:00 is expired", otp.CodeTTL, false}} {
		t.Run(tc.name, func(t *testing.T) {
			e := otptest.NewEnv(t)
			u := e.Pending(t)
			st := e.StartSignup(t, u)
			code := e.PendingCode(t, st.ID)
			e.Clock.Advance(tc.at)
			res, err := svVerifyEmail(e, st.Handle, code)
			got := svUser(t, e, u.ID)
			if tc.ok {
				if err != nil {
					t.Fatalf("VerifyEmail: %v", err)
				}
				if res.Verification.Email == nil || res.Verification.Email.State != otp.ContactVerified || res.Verification.Mobile.State != otp.ContactPending {
					t.Errorf("view = %+v, want email verified and mobile pending", res.Verification)
				}
				if res.ResetToken != "" || res.ResetTokenExpiresAt != nil {
					t.Error("a sign-up verification returned a reset token")
				}
				if !got.EmailVerified || got.MobileVerified || got.Status != "pending_verification" {
					t.Errorf("user = %+v, want email verified (FR-006) and still pending_verification", got)
				}
				if rows := svAuditOf(t, e, "otp.email.verified"); len(rows) != 1 {
					t.Errorf("otp.email.verified audit rows = %d, want 1", len(rows))
				} else {
					svNoLeak(t, "audit", rows[0].After, u.Email, code)
				}
				return
			}
			if !errors.Is(err, otp.ErrCodeExpired) {
				t.Fatalf("VerifyEmail at 10:10:00: %v, want ErrCodeExpired (D-01)", err)
			}
			if got.EmailVerified || svVer(t, e, st.ID).EmailDone != nil {
				t.Errorf("an expired code changed state: user %+v", got)
			}
			rows := svAuditOf(t, e, "otp.check.failed")
			if len(rows) != 1 || otptest.AuditAfter(t, rows[0])["reason"] != "expired" {
				t.Errorf("check.failed audit = %+v, want one with reason expired", rows)
			}
		})
	}
}

func TestVerifyEmail_BR_CLI_04_StatusShowsMaskedContactsAndTimes(t *testing.T) {
	e := otptest.NewEnv(t)
	u := e.Pending(t)
	now := e.Clock.Now()
	st := e.StartSignup(t, u)
	v, err := e.Svc.Status(t.Context(), otptest.Caller(), st.Handle)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if v.Purpose != otp.PurposeSignup || v.State != otp.FlowOpen || !v.ExpiresAt.Equal(now.Add(otp.VerificationTTL)) {
		t.Errorf("view = %+v", v)
	}
	if v.Email == nil || v.Email.State != otp.ContactPending || v.Email.Masked != otp.MaskEmail(u.Email) ||
		v.Email.NextResendAt == nil || !v.Email.NextResendAt.Equal(now.Add(otp.ResendCooldown)) ||
		v.Email.CodeExpiresAt == nil || !v.Email.CodeExpiresAt.Equal(now.Add(otp.CodeTTL)) {
		t.Errorf("email contact = %+v, want pending, masked, resend at +60 s, code expiry +10 min", v.Email)
	}
	if v.Mobile == nil || v.Mobile.State != otp.ContactPending || v.Mobile.Masked != otp.MaskMobile(u.Mobile) || v.Mobile.NextResendAt != nil {
		t.Errorf("mobile contact = %+v", v.Mobile)
	}
	if _, err := e.Svc.Status(t.Context(), otptest.Caller(), "ovh_nope"); !errors.Is(err, otp.ErrNotFound) {
		t.Errorf("Status(unknown handle) = %v, want ErrNotFound", err)
	}
}

func TestVerifyEmail_BR_CLI_04_OnlyOneOfTwoSimultaneousEntriesSucceeds(t *testing.T) {
	e := otptest.NewEnv(t)
	u := e.Pending(t)
	st := e.StartSignup(t, u)
	code := e.PendingCode(t, st.ID)

	const n = 4
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
			_, errs[i] = svVerifyEmail(e, st.Handle, code)
		}()
	}
	ready.Wait()
	close(start)
	done.Wait()

	ok := 0
	for _, err := range errs {
		switch {
		case err == nil:
			ok++
		case !errors.Is(err, otp.ErrCodeExpired):
			t.Errorf("a losing entry returned %v, want ErrCodeExpired (already used)", err)
		}
	}
	if ok != 1 {
		t.Fatalf("%d of %d simultaneous entries succeeded, want exactly 1 (US1.3)", ok, n)
	}
	if rows := svAuditOf(t, e, "otp.email.verified"); len(rows) != 1 {
		t.Errorf("verified audit rows = %d, want 1", len(rows))
	}
	if _, err := svVerifyEmail(e, st.Handle, code); !errors.Is(err, otp.ErrCodeExpired) {
		t.Errorf("a later re-entry = %v, want ErrCodeExpired", err)
	}
	if c := svCodes(t, e, st.ID)[0]; c.EndReason == nil || *c.EndReason != "used" {
		t.Errorf("code end reason = %v, want used", c.EndReason)
	}
}

func TestVerifyEmail_BR_CLI_04_FiveWrongEntriesUseUpTheCode(t *testing.T) {
	e := otptest.NewEnv(t)
	u := e.Pending(t)
	st := e.StartSignup(t, u)
	code := e.PendingCode(t, st.ID)
	wrong := svWrongOf(code)

	for i := 1; i < otp.MaxWrongAttempts; i++ {
		if _, err := svVerifyEmail(e, st.Handle, wrong); !errors.Is(err, otp.ErrCodeWrong) {
			t.Fatalf("wrong entry %d: %v, want ErrCodeWrong", i, err)
		}
		if got := svLive(t, e, st.ID).Wrong; got != i {
			t.Fatalf("wrong_attempts after entry %d = %d: failures must be committed, not rolled back", i, got)
		}
	}
	if _, err := svVerifyEmail(e, st.Handle, wrong); !errors.Is(err, otp.ErrCodeUsedUp) {
		t.Fatalf("the 5th wrong entry: %v, want ErrCodeUsedUp (D-02)", err)
	}
	_, err := svVerifyEmail(e, st.Handle, code)
	if !errors.Is(err, otp.ErrCodeUsedUp) && !errors.Is(err, otp.ErrCodeExpired) {
		t.Errorf("the correct code after 5 wrong ones: %v, want it rejected (used up or expired)", err)
	}
	if got := svUser(t, e, u.ID); got.EmailVerified {
		t.Error("the email was verified with a used-up code")
	}
	if c := svCodes(t, e, st.ID)[0]; c.EndReason == nil || *c.EndReason != "used_up" || c.Wrong != otp.MaxWrongAttempts {
		t.Errorf("code = %+v, want ended as used_up with 5 wrong attempts", c)
	}
	var reasons []any
	for _, r := range svAuditOf(t, e, "otp.check.failed")[:otp.MaxWrongAttempts] {
		reasons = append(reasons, otptest.AuditAfter(t, r)["reason"])
	}
	want := []any{"wrong_code", "wrong_code", "wrong_code", "wrong_code", "used_up"}
	for i := range want {
		if reasons[i] != want[i] {
			t.Errorf("audit reasons = %v, want %v (FR-010)", reasons, want)
			break
		}
	}

	e.Clock.Advance(otp.ResendCooldown) // asking for a new code is the way out
	if _, err := e.Svc.Resend(t.Context(), otptest.Caller(), st.Handle); err != nil {
		t.Fatalf("resend after used_up: %v", err)
	}
	if _, err := svVerifyEmail(e, st.Handle, e.LastCode(t)); err != nil {
		t.Errorf("the new code: %v, want it accepted", err)
	}
}

func TestVerifyEmail_BR_CLI_04_ASupersededCodeStopsWorking(t *testing.T) {
	e := otptest.NewEnv(t)
	u := e.Pending(t)
	st := e.StartSignup(t, u)
	oldCode := e.PendingCode(t, st.ID)
	e.Clock.Advance(otp.ResendCooldown)
	if _, err := e.Svc.Resend(t.Context(), otptest.Caller(), st.Handle); err != nil {
		t.Fatal(err)
	}
	newCode := e.LastCode(t)
	if oldCode != newCode { // a 1-in-a-million collision would make the two indistinguishable
		if _, err := svVerifyEmail(e, st.Handle, oldCode); !errors.Is(err, otp.ErrCodeWrong) && !errors.Is(err, otp.ErrCodeExpired) {
			t.Errorf("the old code after a resend: %v, want it refused (D-01)", err)
		}
	}
	if _, err := svVerifyEmail(e, st.Handle, newCode); err != nil {
		t.Errorf("the new code: %v", err)
	}
}

func TestVerifyEmail_BR_CLI_04_ACodeIsBoundToItsOwnVerification(t *testing.T) {
	e := otptest.NewEnv(t)
	a, b := e.Pending(t), e.Pending(t)
	sa, sb := e.StartSignup(t, a), e.StartSignup(t, b)
	codeA := e.PendingCode(t, sa.ID)
	if codeB := e.PendingCode(t, sb.ID); codeA == codeB {
		t.Skip("both users drew the same random code; the binding cannot be observed")
	}
	if _, err := svVerifyEmail(e, sb.Handle, codeA); !errors.Is(err, otp.ErrCodeWrong) {
		t.Errorf("A's code on B's handle: %v, want ErrCodeWrong (the digest binds the verification, D-08)", err)
	}
	if svUser(t, e, b.ID).EmailVerified {
		t.Error("B was verified with A's code")
	}
}

func TestVerifyEmail_BR_CLI_04_SixtyChecksPerAddressPerHour(t *testing.T) {
	e := otptest.NewEnv(t)
	attacker := otp.Caller{IP: "203.0.113.50"}
	for i := 0; i < 12; i++ { // 12 flows x 5 wrong entries = 60 check requests
		u := e.Pending(t)
		st := e.StartSignup(t, u)
		wrong := svWrongOf(e.PendingCode(t, st.ID))
		for k := 0; k < otp.MaxWrongAttempts; k++ {
			if _, err := e.Svc.VerifyEmail(t.Context(), attacker, st.Handle, wrong); err == nil || svIsRetry(err) {
				t.Fatalf("flow %d entry %d: %v, want a plain wrong/used-up refusal", i, k, err)
			}
		}
	}
	u := e.Pending(t)
	st := e.StartSignup(t, u)
	code := e.PendingCode(t, st.ID)
	_, err := e.Svc.VerifyEmail(t.Context(), attacker, st.Handle, code)
	if re := svRetry(t, err, otp.ReasonRateLimited); re.RetryAfter != time.Hour {
		t.Errorf("RetryAfter = %v, want 1h (the 61st check in the hour)", re.RetryAfter)
	}
	if svUser(t, e, u.ID).EmailVerified {
		t.Error("a rate-limited check verified the email")
	}
	if rows := svAuditOf(t, e, "otp.check.failed"); len(rows) == 0 || otptest.AuditAfter(t, rows[len(rows)-1])["reason"] != "rate_limited" {
		t.Error("the refused check is not audited with reason rate_limited")
	}
	if _, err := e.Svc.VerifyEmail(t.Context(), otp.Caller{IP: "203.0.113.51"}, st.Handle, code); err != nil {
		t.Errorf("another address with the right code: %v, want it accepted", err)
	}
	e.Clock.Advance(time.Hour)
	if _, err := e.Svc.VerifyEmail(t.Context(), attacker, "ovh_"+"x", "123456"); svIsRetry(err) {
		t.Errorf("after an hour the address is still limited: %v", err)
	}
}

func svIsRetry(err error) bool {
	var re *otp.RetryError
	return errors.As(err, &re)
}

func TestVerifyEmail_BR_CLI_05_AChangeIsProvedWithoutChangingTheAccount(t *testing.T) {
	e := otptest.NewEnv(t)
	u := e.Active(t)
	st := e.StartChange(t, u, otp.PurposeChangeEmail, "brand.new@example.com")
	code := e.PendingCode(t, st.ID)
	before := svUser(t, e, u.ID)

	res, err := e.Svc.VerifyEmail(t.Context(), otptest.CallerOf(u), st.Handle, code)
	if err != nil {
		t.Fatalf("VerifyEmail: %v", err)
	}
	if res.Verification.Email == nil || res.Verification.Email.State != otp.ContactProved || res.Verification.State != otp.FlowCompleted {
		t.Errorf("view = %+v, want the email proved and the flow completed", res.Verification)
	}
	if after := svUser(t, e, u.ID); after != before {
		t.Errorf("the account changed: %+v -> %+v (D-09: 007 applies the approved change)", before, after)
	}
	if n := len(e.AuditOf(t, "auth.user.email_verified")); n != 0 {
		t.Errorf("a change proof wrote %d auth.user.email_verified rows", n)
	}
	rows := svAuditOf(t, e, "otp.contact.proved")
	if len(rows) != 1 {
		t.Fatalf("otp.contact.proved audit rows = %d, want 1", len(rows))
	}
	svNoLeak(t, "audit", rows[0].After, "brand.new@example.com", code)
	if v, err := e.Svc.Get(t.Context(), st.ID); err != nil || v.TargetEmail != "brand.new@example.com" || v.State != otp.FlowCompleted {
		t.Errorf("Get = %+v, %v, want the proved address for 007", v, err)
	}
}

func TestVerifyEmail_BR_CLI_05_ANewContactOfAnotherUserIsUnavailable(t *testing.T) {
	e := otptest.NewEnv(t)
	owner := e.Active(t)
	holder := e.Active(t)
	pending := e.Pending(t)
	for name, taken := range map[string]authtest.User{"an active user's email": holder, "a pending user's email": pending} {
		st := e.StartChange(t, owner, otp.PurposeChangeEmail, "  "+upperOf(taken.Email)+" ")
		code := e.PendingCode(t, st.ID)
		_, err := e.Svc.VerifyEmail(t.Context(), otptest.CallerOf(owner), st.Handle, code)
		if !errors.Is(err, otp.ErrContactUnavailable) {
			t.Fatalf("%s: %v, want ErrContactUnavailable (US5.3)", name, err)
		}
		svNoLeak(t, "error text", err.Error(), taken.ID.String(), taken.Email)
		if svVer(t, e, st.ID).EmailDone != nil {
			t.Errorf("%s: the contact was marked proved", name)
		}
		e.Clock.Advance(otp.ResendCooldown + time.Second)
	}
	rows := svAuditOf(t, e, "otp.check.failed")
	if len(rows) != 2 || otptest.AuditAfter(t, rows[0])["reason"] != "contact_unavailable" {
		t.Errorf("check.failed audit = %d rows, want 2 with reason contact_unavailable", len(rows))
	}
}

func upperOf(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'a' && c <= 'z' {
			b[i] = c - 32
		}
	}
	return string(b)
}

func TestVerifyEmail_BR_CLI_05_AnotherClientsSessionSeesNothing(t *testing.T) {
	e := otptest.NewEnv(t)
	owner, other := e.Active(t), e.Active(t)
	st := e.StartChange(t, owner, otp.PurposeChangeEmail, "mine@example.com")
	code := e.PendingCode(t, st.ID)
	if _, err := e.Svc.VerifyEmail(t.Context(), otptest.CallerOf(other), st.Handle, code); !errors.Is(err, otp.ErrNotFound) {
		t.Errorf("another user's session with the right code: %v, want ErrNotFound", err)
	}
	if _, err := e.Svc.VerifyEmail(t.Context(), otptest.CallerOf(other), st.Handle, svWrongOf(code)); !errors.Is(err, otp.ErrNotFound) {
		t.Errorf("another user's session with a wrong code: %v, want ErrNotFound (no attempt is counted)", err)
	}
	if got := svLive(t, e, st.ID).Wrong; got != 0 {
		t.Errorf("wrong_attempts = %d, want 0: a stranger cannot burn the owner's attempts", got)
	}
	if _, err := e.Svc.Status(t.Context(), otptest.CallerOf(other), st.Handle); !errors.Is(err, otp.ErrNotFound) {
		t.Errorf("Status with another session: %v, want ErrNotFound", err)
	}
	if _, err := e.Svc.VerifyEmail(t.Context(), otptest.CallerOf(owner), st.Handle, code); err != nil {
		t.Errorf("the owner: %v", err)
	}
	p := e.Pending(t)
	signup := e.StartSignup(t, p)
	if _, err := e.Svc.VerifyEmail(t.Context(), otptest.CallerOf(p), signup.Handle, e.PendingCode(t, signup.ID)); !errors.Is(err, otp.ErrNotFound) {
		t.Errorf("a sign-up handle on the signed-in path: %v, want ErrNotFound", err)
	}
}

func TestVerifyEmail_BR_CLI_04_ExpiredAndUnknownHandles(t *testing.T) {
	e := otptest.NewEnv(t)
	u := e.Pending(t)
	st := e.StartSignup(t, u)
	code := e.PendingCode(t, st.ID)
	if _, err := svVerifyEmail(e, "ovh_unknown", code); !errors.Is(err, otp.ErrNotFound) {
		t.Errorf("unknown handle: %v, want ErrNotFound", err)
	}
	e.Clock.Advance(otp.VerificationTTL)
	if _, err := svVerifyEmail(e, st.Handle, code); !errors.Is(err, otp.ErrVerificationExpired) {
		t.Errorf("after 24 h: %v, want ErrVerificationExpired", err)
	}
	if svUser(t, e, u.ID).EmailVerified {
		t.Error("an expired verification verified the email")
	}
}
