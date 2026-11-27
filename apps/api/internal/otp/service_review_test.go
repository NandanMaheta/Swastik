package otp_test

// Review-fix tests for feature 004 at the service level (BR-CLI-04; spec D-04, D-06, FR-008,
// FR-010, FR-011, D-08, SC-004): CompleteReset re-checks eligibility in its own transaction, a
// key-set outage is not a refused proof, an expired code is never reported as sent, and the
// immediate delivery survives the caller going away.

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/NandanMaheta/swastik/apps/api/internal/auth"
	"github.com/NandanMaheta/swastik/apps/api/internal/auth/authtest"
	"github.com/NandanMaheta/swastik/apps/api/internal/otp"
	"github.com/NandanMaheta/swastik/apps/api/internal/otp/otptest"
	"github.com/NandanMaheta/swastik/apps/api/internal/outbox"
	"github.com/NandanMaheta/swastik/apps/api/internal/platform/clock"
)

// ---- 4. CompleteReset re-checks the account in the same transaction -----------------------------

func svPasswordHash(t *testing.T, e *otptest.Env, user uuid.UUID) string {
	t.Helper()
	var h string
	if err := e.Pool.QueryRow(context.Background(), `SELECT password_hash FROM users WHERE id = $1`, user).Scan(&h); err != nil {
		t.Fatalf("read password hash: %v", err)
	}
	return h
}

// svWantRefusedCompletion requires the contract's refusal, an unchanged password and an audit row
// that says the completion was refused (and none that says it completed).
func svWantRefusedCompletion(t *testing.T, e *otptest.Env, u authtest.User, err error, hashBefore string, auditBefore int) {
	t.Helper()
	if !errors.Is(err, otp.ErrResetTokenInvalid) {
		t.Errorf("CompleteReset = %v, want ErrResetTokenInvalid (otp.reset_token_invalid)", err)
	}
	if got := svPasswordHash(t, e, u.ID); got != hashBefore {
		t.Error("the password hash changed: a client who may not reset set a password")
	}
	if rows := svAuditOf(t, e, "otp.reset.completed"); len(rows) != 0 {
		t.Errorf("otp.reset.completed audit rows = %d, want none", len(rows))
	}
	added := 0
	for _, r := range e.OTPAudit(t) {
		if r.EntityID == u.ID {
			added++
		}
	}
	if added <= auditBefore {
		t.Errorf("audit rows about the user = %d (was %d): the refused completion left no trace (FR-010)", added, auditBefore)
	}
	svNoLeak(t, "audit", svAuditText(t, e), svNewPassword, u.Email, u.Mobile)
}

func svUserAuditRows(t *testing.T, e *otptest.Env, user uuid.UUID) int {
	t.Helper()
	n := 0
	for _, r := range e.OTPAudit(t) {
		if r.EntityID == user {
			n++
		}
	}
	return n
}

func TestCompleteReset_BR_CLI_04_AClientWhoIsNoLongerActiveCannotSetAPassword(t *testing.T) {
	for _, status := range []auth.Status{auth.StatusDisabled, auth.StatusPendingApproval, auth.StatusPendingVerification} {
		t.Run(string(status), func(t *testing.T) {
			e := otptest.NewEnv(t)
			u := e.Active(t)
			rs, token := svResetToken(t, e, u) // the code was verified while the account was active
			if status == auth.StatusDisabled {
				e.Exec(t, `UPDATE users SET status = 'disabled', status_before_disabled = 'active' WHERE id = $1`, u.ID)
			} else {
				e.Exec(t, `UPDATE users SET status = $2 WHERE id = $1`, u.ID, string(status))
			}
			hash, auditBefore := svPasswordHash(t, e, u.ID), svUserAuditRows(t, e, u.ID)

			err := svComplete(e, rs, token, svNewPassword)
			svWantRefusedCompletion(t, e, u, err, hash, auditBefore)
		})
	}
}

func TestCompleteReset_BR_CLI_04_AFlowPastItsVerificationExpiryCannotSetAPassword(t *testing.T) {
	e := otptest.NewEnv(t)
	u := e.Active(t)
	rs, err := svStartReset(e, u.Email)
	if err != nil {
		t.Fatalf("StartReset: %v", err)
	}
	// Late in the 24 hours: a fresh code, accepted, so the 10-minute token outlives the flow.
	e.Clock.Advance(otp.VerificationTTL - 6*time.Minute)
	if _, err := e.Svc.Resend(context.Background(), otptest.Caller(), rs.Handle); err != nil {
		t.Fatalf("Resend: %v", err)
	}
	res, err := svVerifyEmail(e, rs.Handle, e.LastCode(t))
	if err != nil {
		t.Fatalf("VerifyEmail: %v", err)
	}
	e.Clock.Advance(7 * time.Minute) // past the flow's expiry, inside the token's 10 minutes
	hash, auditBefore := svPasswordHash(t, e, u.ID), svUserAuditRows(t, e, u.ID)
	if !e.Clock.Now().Before(*res.ResetTokenExpiresAt) {
		t.Fatalf("test set-up: the token expired at %v before %v", res.ResetTokenExpiresAt, e.Clock.Now())
	}

	err = svComplete(e, rs, res.ResetToken, svNewPassword)
	svWantRefusedCompletion(t, e, u, err, hash, auditBefore)
}

// ---- 5. a key-set outage is not a refused proof -----------------------------------------------

func TestVerifyMobile_BR_CLI_04_KeySetOutageIsNeitherAnInvalidProofNorACountedRefusal(t *testing.T) {
	e := otptest.NewEnv(t)
	u, st := svSignupWithEmailDone(t, e)
	token := e.Token(t, u.Mobile)

	e.Minter.SetOutage(true)
	_, err := svVerifyMobile(e, st.Handle, token)
	if err == nil {
		t.Fatal("VerifyMobile succeeded without a key set")
	}
	for _, not := range []error{otp.ErrProofInvalid, otp.ErrProofStale, otp.ErrNumberMismatch, otp.ErrProofReplayed} {
		if errors.Is(err, not) {
			t.Errorf("VerifyMobile = %v: an outage is not %v (the client did nothing wrong)", err, not)
		}
	}
	if c := e.Counts(t); c.ProofRefused != 0 {
		t.Errorf("counts = %+v, want proof_refused 0", c)
	}
	if rows := svAuditOf(t, e, "otp.check.failed"); len(rows) != 0 {
		t.Errorf("otp.check.failed rows = %d, want none for an outage", len(rows))
	}
	e.Minter.SetOutage(false)
	if _, err := svVerifyMobile(e, st.Handle, token); err != nil {
		t.Errorf("the same proof once the key set is back: %v, want accepted", err)
	}
}

// ---- 6. expired codes are not "sent"; delivery is detached from the caller ----------------------

// The relay of an outbox whose clock is still before the code's expiry claims the message, while
// the sender (the service's clock) already sees the code expired: that must not end as "sent".
func TestSender_BR_CLI_04_ExpiredCodeIsReportedNotDeliveredNeverSent(t *testing.T) {
	e := otptest.NewEnv(t)
	u := e.Pending(t)
	e.StartSignup(t, u)
	row := e.OutboxRows(t, otp.TopicEmailCode)[0]

	behind := clock.NewFake(e.Clock.Now())
	ob := outbox.New(e.Tx, behind.Now, slog.New(slog.NewTextHandler(io.Discard, nil)), outbox.DefaultOptions())
	ob.RegisterSender(otp.TopicEmailCode, e.Svc.Sender(), 3)
	e.Clock.Advance(otp.CodeTTL) // the service sees now == expires_at; the relay's clock does not

	if _, err := ob.Relay(context.Background(), outbox.RelayBudget{MaxMessages: 5}); err != nil {
		t.Fatalf("Relay: %v", err)
	}
	after := e.OutboxRows(t, otp.TopicEmailCode)[0]
	if after.ID != row.ID || after.Status == "sent" {
		t.Errorf("outbox row = %s %q, want anything but sent: the code was never delivered (FR-011)", after.ID, after.Status)
	}
	if e.Mailer.Calls() != 0 {
		t.Errorf("mailer calls = %d, want 0 for an expired code", e.Mailer.Calls())
	}
	if c := e.Counts(t); c.EmailSent != 0 {
		t.Errorf("counts = %+v, want email_sent 0", c)
	}
}

// A client who goes away in the middle of the immediate send must not cancel it: the mailer's
// context is not the request's, and the outbox row ends up sent and erased.
func TestDeliverNow_BR_CLI_04_ClientDisconnectDoesNotCancelTheSend(t *testing.T) {
	// run does its set-up, calls arm() right before the call under test, and makes that call with ctx.
	ops := []struct {
		name string
		run  func(t *testing.T, e *otptest.Env, ctx context.Context, arm func())
	}{
		{"StartReset", func(t *testing.T, e *otptest.Env, ctx context.Context, arm func()) {
			u := e.Active(t)
			arm()
			_, _ = e.Svc.StartReset(ctx, otptest.DefaultIP, u.Email)
		}},
		{"Resend", func(t *testing.T, e *otptest.Env, ctx context.Context, arm func()) {
			rs, err := svStartReset(e, e.Active(t).Email)
			if err != nil {
				t.Fatalf("StartReset: %v", err)
			}
			e.Clock.Advance(otp.ResendCooldown + time.Second)
			arm()
			_, _ = e.Svc.Resend(ctx, otptest.Caller(), rs.Handle)
		}},
		{"Deliver", func(t *testing.T, e *otptest.Env, ctx context.Context, arm func()) {
			st := e.StartSignup(t, e.Pending(t))
			arm()
			_ = e.Svc.Deliver(ctx, st.ID)
		}},
	}
	for _, o := range ops {
		t.Run(o.name, func(t *testing.T) {
			e := otptest.NewEnv(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var armed atomic.Bool
			var sendCtxErr error
			sawSend := false
			e.Mailer.Hook = func(c context.Context) {
				if !armed.Load() {
					return
				}
				sawSend = true
				cancel() // the client disconnects while the mail is being sent
				sendCtxErr = c.Err()
			}
			o.run(t, e, ctx, func() { armed.Store(true) })

			if !sawSend {
				t.Fatal("the mailer was never called")
			}
			if sendCtxErr != nil {
				t.Errorf("the mailer's context was cancelled by the client going away: %v (a code must not be lost to a disconnect)", sendCtxErr)
			}
			rows := e.OutboxRows(t, otp.TopicEmailCode)
			last := rows[len(rows)-1]
			if last.Status != "sent" || string(last.Payload) != "{}" {
				t.Errorf("outbox row = %q payload %q, want sent and erased", last.Status, last.Payload)
			}
		})
	}
}
