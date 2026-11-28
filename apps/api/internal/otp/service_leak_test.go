package otp_test

// S14 - SC-003 (spec D-08, FR-009, FR-013, constitution VI): across a journey that exercises every
// operation and every kind of refusal, no contact, code, handle, reset token, Firebase token or
// typed password appears in the logs, the audit log, the stored outbox rows (the sealed message
// is the one allowed copy of a code), the otp tables or any error response. Secrets are collected
// while the journey runs, so one issued late is still searched for in what was written early.

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/NandanMaheta/swastik/apps/api/internal/auth/authtest"
	"github.com/NandanMaheta/swastik/apps/api/internal/otp"
	"github.com/NandanMaheta/swastik/apps/api/internal/otp/otptest"
	"github.com/NandanMaheta/swastik/apps/api/internal/platform/email"
)

func TestNoLeak_SC_003_NothingSecretIsLoggedAuditedStoredOrReturned(t *testing.T) {
	e := otptest.NewEnv(t)
	var problems strings.Builder
	record := func(err error) {
		if err == nil {
			return
		}
		problems.WriteString(err.Error() + "\n")
		rec, _ := problemFor(t, err)
		problems.WriteString(rec.Body.String() + fmt.Sprint(rec.Header()) + "\n")
	}
	secret := func(label, v string) { e.Secrets.Add(label, v) }
	addUser := func(label string, u authtest.User) {
		secret(label+" email", u.Email)
		secret(label+" email local part", strings.Split(u.Email, "@")[0])
		secret(label+" mobile", u.Mobile)
		secret(label+" mobile digits", strings.TrimPrefix(u.Mobile, "+91"))
	}

	// 1. Sign-up: code issued, resent, wrong entries, right entry; mobile with every kind of refusal.
	a := e.Pending(t)
	addUser("signup user", a)
	st := e.StartSignup(t, a)
	secret("signup handle", st.Handle)
	e.Deliver(t, st.ID)
	code := e.LastCode(t)
	secret("signup code 1", code)
	_, err := e.Svc.Resend(t.Context(), otptest.Caller(), st.Handle)
	record(err) // cooldown
	_, err = svVerifyEmail(e, st.Handle, svWrongOf(code))
	record(err)
	e.Clock.Advance(otp.ResendCooldown)
	_, err = e.Svc.Resend(t.Context(), otptest.Caller(), st.Handle)
	record(err)
	code2 := e.LastCode(t)
	secret("signup code 2", code2)
	_, err = svVerifyEmail(e, st.Handle, code2)
	record(err)
	now := e.Clock.Now()
	for label, tok := range map[string]string{
		"firebase: other number": e.Token(t, "+919812345679"),
		"firebase: stale":        e.Token(t, a.Mobile, func(c *otptest.Claims) { c.AuthTime, c.IssuedAt = now.Add(-10*time.Minute), now.Add(-10*time.Minute) }),
		"firebase: garbage":      "garbage.firebase.token",
		"firebase: good":         e.Token(t, a.Mobile),
	} {
		secret(label, tok)
		_, err = svVerifyMobile(e, st.Handle, tok)
		record(err)
	}

	// 2. Contact change by an active client, including the unavailable-contact refusal.
	b, taken := e.Active(t), e.Active(t)
	addUser("change user", b)
	addUser("taken user", taken)
	secret("new address", "fresh.address.77@example.com")
	chg := e.StartChange(t, b, otp.PurposeChangeEmail, "fresh.address.77@example.com")
	secret("change handle", chg.Handle)
	e.Deliver(t, chg.ID)
	chgCode := e.LastCode(t)
	secret("change code", chgCode)
	_, err = e.Svc.VerifyEmail(t.Context(), otptest.CallerOf(b), chg.Handle, svWrongOf(chgCode))
	record(err)
	_, err = e.Svc.VerifyEmail(t.Context(), otptest.CallerOf(b), chg.Handle, chgCode)
	record(err)
	clash := e.StartChange(t, b, otp.PurposeChangeEmail, taken.Email)
	e.Clock.Advance(time.Second)
	_, err = e.Svc.VerifyEmail(t.Context(), otptest.CallerOf(b), clash.Handle, e.PendingCode(t, clash.ID))
	record(err)
	err = e.Tx.InTx(context.Background(), func(ctx context.Context) error {
		return e.Svc.NotifyOldContact(ctx, otp.ContactNotice{OrgID: e.Org, UserID: b.ID, OldEmail: b.Email, Changed: "email"}, otptest.ActorOf(b))
	})
	record(err)

	// 3. Forgot password: a real account (policy error, then success), an unknown email and mobile.
	d := e.Active(t)
	addUser("reset user", d)
	secret("typed weak password", "weakpass")
	rs, err := svStartReset(e, d.Mobile)
	record(err)
	secret("reset handle", rs.Handle)
	resetCode := e.LastCode(t)
	secret("reset code", resetCode)
	res, err := svVerifyEmail(e, rs.Handle, resetCode)
	record(err)
	secret("reset token", res.ResetToken)
	secret("new password", svNewPassword)
	record(svComplete(e, rs, res.ResetToken, "weakpass"))
	record(svComplete(e, rs, res.ResetToken, svNewPassword))
	record(svComplete(e, rs, res.ResetToken, svNewPassword)) // reuse
	for _, typed := range []string{"ghost.person@example.com", "+919123456780"} {
		secret("typed unknown identifier", typed)
		secret("typed unknown identifier body", strings.TrimPrefix(strings.Split(typed, "@")[0], "+91"))
		gh, err := svStartReset(e, typed)
		record(err)
		secret("decoy handle", gh.Handle)
		for i := 0; i < otp.MaxWrongAttempts; i++ {
			_, err = svVerifyEmail(e, gh.Handle, "000000")
			record(err)
		}
		_, err = svStartReset(e, typed) // cooldown on an unknown identifier
		record(err)
		if fmt.Sprintf("%+v", gh) != "" && strings.Contains(fmt.Sprintf("%+v", gh), strings.Split(typed, "@")[0]) {
			t.Errorf("the reply for %q echoes the identifier", typed)
		}
	}

	// 4. A failing provider and the relay.
	f := e.Pending(t)
	addUser("failing user", f)
	e.Mailer.FailErr = fmt.Errorf("resend: status 503: %w", email.ErrUnavailable)
	fs := e.StartSignup(t, f)
	secret("failing handle", fs.Handle)
	secret("failing code", e.PendingCode(t, fs.ID))
	e.Deliver(t, fs.ID)
	e.Mailer.FailErr = nil
	e.Clock.Advance(2 * time.Minute)
	e.Relay(t)

	// Scan everything written.
	e.Secrets.Scan(t, "the otp service log", e.Logs.String())
	e.Secrets.Scan(t, "the problem responses", problems.String())
	e.Secrets.ScanAuditLog(t.Context(), t, e.Pool)
	for _, q := range map[string]string{
		"outbox_messages":  `SELECT m.id::text || ' ' || m.topic || ' ' || m.subject || ' ' || m.dedupe_key || ' ' || m.status || ' ' || COALESCE(m.last_error,'') || ' ' || m.payload::text FROM outbox_messages m`,
		"otp_email_codes":  `SELECT c::text FROM otp_email_codes c`,
		"otp_used_proofs":  `SELECT p::text FROM otp_used_proofs p`,
		"otp_limits":       `SELECT l::text FROM otp_limits l`,
		"otp_daily_counts": `SELECT d::text FROM otp_daily_counts d`,
	} {
		rows, err := e.Pool.Query(context.Background(), q)
		if err != nil {
			t.Fatalf("scan query: %v", err)
		}
		var all strings.Builder
		for rows.Next() {
			var s string
			if err := rows.Scan(&s); err != nil {
				t.Fatal(err)
			}
			all.WriteString(s + "\n")
		}
		rows.Close()
		if all.Len() == 0 {
			t.Errorf("table scan produced no rows: the journey did not reach it (outbox/codes must exist)")
		}
		e.Secrets.Scan(t, "table "+q[:min(40, len(q))], all.String())
	}
}
