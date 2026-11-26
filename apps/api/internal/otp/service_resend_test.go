package otp_test

// S10 - Resend, Deliver and DeliverNow behaviour (feature 004; BR-CLI-04; spec US2.1-2.4, US1.1,
// D-01, D-02, D-07, FR-002, FR-011, FR-012, FR-013, edge cases "Email delayed" and "Abandoned flows").

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/NandanMaheta/swastik/apps/api/internal/otp"
	"github.com/NandanMaheta/swastik/apps/api/internal/otp/otptest"
	"github.com/NandanMaheta/swastik/apps/api/internal/platform/email"
)

func TestResend_BR_CLI_04_CooldownAt59And60Seconds(t *testing.T) {
	e := otptest.NewEnv(t)
	u := e.Pending(t)
	t0 := e.Clock.Now()
	st := e.StartSignup(t, u)
	e.Deliver(t, st.ID) // the first email is sent
	first := svLive(t, e, st.ID)

	e.Clock.Set(t0.Add(59 * time.Second))
	_, err := e.Svc.Resend(t.Context(), otptest.Caller(), st.Handle)
	if re := svRetry(t, err, otp.ReasonCooldown); re.RetryAfter != time.Second {
		t.Errorf("RetryAfter = %v, want 1s: \"wait 1 s\" (US2.1)", re.RetryAfter)
	}
	if n := len(e.OutboxRows(t, otp.TopicEmailCode)); n != 1 {
		t.Fatalf("queued emails after the refusal = %d, want 1", n)
	}

	e.Clock.Set(t0.Add(60 * time.Second))
	res, err := e.Svc.Resend(t.Context(), otptest.Caller(), st.Handle)
	if err != nil {
		t.Fatalf("resend at 60 s: %v", err)
	}
	if !res.NextResendAt.Equal(t0.Add(2*otp.ResendCooldown)) || !res.CodeExpiresAt.Equal(t0.Add(otp.ResendCooldown+otp.CodeTTL)) {
		t.Errorf("ResendResult = %+v, want next resend +60 s and code expiry +10 min from the resend", res)
	}
	codes := svCodes(t, e, st.ID)
	if len(codes) != 2 || codes[0].ID != first.ID || codes[0].EndReason == nil || *codes[0].EndReason != "superseded" || codes[1].EndedAt != nil {
		t.Errorf("codes = %+v, want the old one superseded and one live (D-01)", codes)
	}
	rows := e.OutboxRows(t, otp.TopicEmailCode)
	if len(rows) != 2 || rows[0].Status != "sent" {
		t.Errorf("outbox statuses = %v, want the delivered old email left as sent", statuses(rows))
	}
	if rows[0].Status == "sent" && string(rows[0].Payload) != "{}" {
		t.Errorf("sent payload = %s, want it erased (FR-013)", rows[0].Payload)
	}
	if rows := svAuditOf(t, e, "otp.code.issued"); len(rows) != 2 {
		t.Errorf("otp.code.issued audit rows = %d, want 2 (first and resend)", len(rows))
	}
}

func TestResend_BR_CLI_04_AnUnsentOldEmailIsWithdrawn(t *testing.T) {
	e := otptest.NewEnv(t)
	u := e.Pending(t)
	st := e.StartSignup(t, u) // committed, never delivered
	e.Clock.Advance(otp.ResendCooldown)
	if _, err := e.Svc.Resend(t.Context(), otptest.Caller(), st.Handle); err != nil {
		t.Fatalf("resend: %v", err)
	}
	rows := e.OutboxRows(t, otp.TopicEmailCode)
	if len(rows) != 2 || rows[0].Status != "withdrawn" || string(rows[0].Payload) != "{}" {
		t.Fatalf("outbox = %v, want the unsent old email withdrawn and erased (US2.1)", statuses(rows))
	}
	// Only the new code was sent (in the request, inside the floor).
	mails := e.Mailer.Mails()
	if len(mails) != 1 || mails[0].To != u.Email {
		t.Fatalf("mails = %+v, want exactly one, to the account email", mails)
	}
}

func TestResend_BR_CLI_04_APublicResendDeliversInsideTheFloor(t *testing.T) {
	e := otptest.NewEnv(t)
	u := e.Pending(t)
	st := e.StartSignup(t, u)
	e.Clock.Advance(otp.ResendCooldown)
	start := e.Clock.Now()
	e.Waits.Reset()
	if _, err := e.Svc.Resend(t.Context(), otptest.Caller(), st.Handle); err != nil {
		t.Fatalf("resend: %v", err)
	}
	if n := len(e.Mailer.Mails()); n != 1 {
		t.Errorf("mails sent by the time Resend returned = %d, want 1 (SC-002: delivery in the request)", n)
	}
	waits := e.Waits.Untils()
	if len(waits) != 1 || !waits[0].Equal(start.Add(svFloor)) {
		t.Errorf("response floor waits = %v, want one wait until request start + 1.5 s (I-3)", waits)
	}
}

func TestResend_BR_CLI_04_QuietHoursDoNotDelayACode(t *testing.T) {
	e := otptest.NewEnv(t)
	u := e.Pending(t)
	e.Clock.Set(svIST(0, 23, 0)) // 23:00 IST, inside 21:30-08:00 (US2.4)
	st := e.StartSignup(t, u)
	now := e.Clock.Now()
	rows := e.OutboxRows(t, otp.TopicEmailCode)
	if len(rows) != 1 || rows[0].RespectsQ || !rows[0].AvailableAt.Equal(now) {
		t.Fatalf("outbox = %+v, want available now and exempt from quiet hours (FR-012)", rows)
	}
	e.Deliver(t, st.ID)
	if n := len(e.Mailer.Mails()); n != 1 {
		t.Errorf("mails at 23:00 IST = %d, want 1 at once, not at 08:00 (US2.4)", n)
	}
	e.Clock.Advance(otp.ResendCooldown)
	if _, err := e.Svc.Resend(t.Context(), otptest.Caller(), st.Handle); err != nil {
		t.Fatal(err)
	}
	if n := len(e.Mailer.Mails()); n != 2 {
		t.Errorf("mails after a 23:01 resend = %d, want 2", n)
	}
}

func TestResend_BR_CLI_04_RefusesWhatCannotBeSent(t *testing.T) {
	e := otptest.NewEnv(t)
	u := e.Pending(t)
	st := e.StartSignup(t, u)
	call := func(handle string) error {
		_, err := e.Svc.Resend(t.Context(), otptest.Caller(), handle)
		return err
	}
	if err := call("ovh_" + strings.Repeat("A", 43)); !errors.Is(err, otp.ErrNotFound) {
		t.Errorf("unknown handle: %v, want ErrNotFound", err)
	}
	if err := call(""); !errors.Is(err, otp.ErrNotFound) {
		t.Errorf("empty handle: %v, want ErrNotFound", err)
	}
	e.Exec(t, `UPDATE otp_verifications SET email_done_at = $2 WHERE id = $1`, st.ID, e.Clock.Now())
	e.Clock.Advance(otp.ResendCooldown)
	if err := call(st.Handle); !errors.Is(err, otp.ErrNothingToSend) {
		t.Errorf("email already verified: %v, want ErrNothingToSend", err)
	}

	a := e.Active(t)
	mob := e.StartChange(t, a, otp.PurposeChangeMobile, "+919876543210")
	if _, err := e.Svc.Resend(t.Context(), otptest.CallerOf(a), mob.Handle); !errors.Is(err, otp.ErrNothingToSend) {
		t.Errorf("mobile-only flow: %v, want ErrNothingToSend (nothing is emailed)", err)
	}
}

func TestResend_BR_CLI_04_AVerificationLivesTwentyFourHours(t *testing.T) {
	e := otptest.NewEnv(t)
	u := e.Pending(t)
	t0 := e.Clock.Now()
	st := e.StartSignup(t, u)
	e.Clock.Set(t0.Add(otp.VerificationTTL - time.Second))
	if _, err := e.Svc.Resend(t.Context(), otptest.Caller(), st.Handle); err != nil {
		t.Errorf("resend at 23:59:59: %v, want it allowed", err)
	}
	e.Clock.Set(t0.Add(otp.VerificationTTL))
	_, err := e.Svc.Resend(t.Context(), otptest.Caller(), st.Handle)
	if !errors.Is(err, otp.ErrVerificationExpired) {
		t.Errorf("resend at exactly 24 h: %v, want ErrVerificationExpired", err)
	}
	v, err := e.Svc.Status(t.Context(), otptest.Caller(), st.Handle)
	if err != nil || v.State != otp.FlowExpired {
		t.Errorf("Status at 24 h = %+v, %v, want state expired", v, err)
	}
}

func TestResend_BR_CLI_05_AnotherClientsChangeHandleIsNotFound(t *testing.T) {
	e := otptest.NewEnv(t)
	owner, other := e.Active(t), e.Active(t)
	st := e.StartChange(t, owner, otp.PurposeChangeEmail, "mine@example.com")
	e.Clock.Advance(otp.ResendCooldown)
	if _, err := e.Svc.Resend(t.Context(), otptest.CallerOf(other), st.Handle); !errors.Is(err, otp.ErrNotFound) {
		t.Errorf("another user's session: %v, want ErrNotFound (US5.2: no difference from an unknown handle)", err)
	}
	if n := len(e.OutboxRows(t, otp.TopicEmailCode)); n != 1 {
		t.Errorf("code emails = %d, want 1: the refused resend queued nothing", n)
	}
	if _, err := e.Svc.Resend(t.Context(), otptest.CallerOf(owner), st.Handle); err != nil {
		t.Errorf("the owner's resend: %v", err)
	}
	// A sign-up handle is never reachable with a signed-in session on /v1/me/*.
	p := e.Pending(t)
	signup := e.StartSignup(t, p)
	e.Clock.Advance(otp.ResendCooldown)
	if _, err := e.Svc.Resend(t.Context(), otptest.CallerOf(p), signup.Handle); !errors.Is(err, otp.ErrNotFound) {
		t.Errorf("sign-up handle with a user session: %v, want ErrNotFound", err)
	}
}

func TestDeliver_BR_CLI_04_SendsTheLiveCodeNowAndOnlyOnce(t *testing.T) {
	e := otptest.NewEnv(t)
	u := e.Pending(t)
	st := e.StartSignup(t, u)
	if n := len(e.Mailer.Mails()); n != 0 {
		t.Fatalf("Start itself sent %d mails; delivery happens in Deliver, after commit", n)
	}
	code := e.PendingCode(t, st.ID)
	e.Deliver(t, st.ID)

	mails := e.Mailer.Mails()
	if len(mails) != 1 {
		t.Fatalf("mails = %d, want 1", len(mails))
	}
	m := mails[0]
	live := svLive(t, e, st.ID)
	if m.To != u.Email || m.Subject != "Your Swastik code: "+code || m.IdempotencyKey != "otp:code:"+live.ID.String() {
		t.Errorf("mail = to %q subject %q key %q", m.To, m.Subject, m.IdempotencyKey)
	}
	for _, want := range []string{code, "10 minutes", "never share", "ignore"} {
		if !strings.Contains(strings.ToLower(m.Text), strings.ToLower(want)) {
			t.Errorf("mail text lacks %q: %q", want, m.Text)
		}
	}
	rows := e.OutboxRows(t, otp.TopicEmailCode)
	if rows[0].Status != "sent" || string(rows[0].Payload) != "{}" {
		t.Errorf("outbox after delivery = %s payload %s, want sent and erased (FR-013)", rows[0].Status, rows[0].Payload)
	}
	e.Deliver(t, st.ID)
	if n := len(e.Mailer.Mails()); n != 1 {
		t.Errorf("a second Deliver sent again: %d mails", n)
	}
	// Deliver inside a transaction is refused (DeliverNow must not run in one).
	err := e.Tx.InTx(context.Background(), func(ctx context.Context) error { return e.Svc.Deliver(ctx, st.ID) })
	if err == nil {
		t.Error("Deliver inside a transaction succeeded, want an error")
	}
}

func TestDeliver_BR_CLI_04_AFailedSendIsRetriedByTheRelayBeforeTheCodeExpires(t *testing.T) {
	e := otptest.NewEnv(t)
	u := e.Pending(t)
	st := e.StartSignup(t, u)
	e.Mailer.FailErr = fmt.Errorf("resend: status 503: %w", email.ErrUnavailable)
	if err := e.Svc.Deliver(t.Context(), st.ID); err != nil {
		t.Fatalf("Deliver with a failing provider: %v, want the failure recorded and the request unharmed", err)
	}
	rows := e.OutboxRows(t, otp.TopicEmailCode)
	if rows[0].Status != "pending" || rows[0].Attempts != 1 {
		t.Fatalf("outbox row = %s attempts %d, want pending after 1 failed attempt (tick relay retries)", rows[0].Status, rows[0].Attempts)
	}
	svNoLeak(t, "outbox last_error", rows[0].LastError, u.Email)
	if c := e.Counts(t); c.EmailFailed != 1 || c.EmailSent != 0 {
		t.Errorf("counts = %+v, want one email_failed", c)
	}

	e.Mailer.FailErr = nil
	e.Clock.Advance(2 * time.Minute) // past the first backoff (1 min +/- 20 %), before the 10-minute expiry
	if sum := e.Relay(t); sum.Sent != 1 {
		t.Fatalf("relay summary = %+v, want the code sent by the fallback relay", sum)
	}
	if n := len(e.Mailer.Mails()); n != 1 {
		t.Errorf("mails = %d, want 1", n)
	}
	if c := e.Counts(t); c.EmailSent != 1 || c.EmailFailed != 1 {
		t.Errorf("counts = %+v, want one sent and one failed", c)
	}
}

func TestDeliver_BR_CLI_04_AnExpiredCodeIsNeverSent(t *testing.T) {
	e := otptest.NewEnv(t)
	u := e.Pending(t)
	st := e.StartSignup(t, u)
	e.Clock.Advance(otp.CodeTTL) // exactly the expiry instant
	e.Deliver(t, st.ID)
	e.Relay(t)
	if n := e.Mailer.Calls(); n != 0 {
		t.Errorf("mailer calls = %d, want 0: a code past its expiry is never handed to the provider", n)
	}
	rows := e.OutboxRows(t, otp.TopicEmailCode)
	if rows[0].Status != "expired" || string(rows[0].Payload) != "{}" {
		t.Errorf("outbox row = %s payload %s, want expired and erased", rows[0].Status, rows[0].Payload)
	}
}

func TestDeliver_BR_CLI_04_NothingToDeliverForAnUnknownOrMobileOnlyFlow(t *testing.T) {
	e := otptest.NewEnv(t)
	a := e.Active(t)
	mob := e.StartChange(t, a, otp.PurposeChangeMobile, "+919876543210")
	e.Deliver(t, mob.ID)
	if n := e.Mailer.Calls(); n != 0 {
		t.Errorf("mailer calls = %d, want 0", n)
	}
	if err := e.Svc.Deliver(t.Context(), a.ID); err != nil { // not a verification id
		t.Errorf("Deliver(unknown id) = %v, want a no-op", err)
	}
}

func TestResend_BR_CLI_04_ARefusedResendKeepsTheOldCodeUsable(t *testing.T) {
	e := otptest.NewEnv(t)
	u := e.Pending(t)
	st := e.StartSignup(t, u)
	code := e.PendingCode(t, st.ID)
	e.Clock.Advance(20 * time.Second)
	if _, err := e.Svc.Resend(t.Context(), otptest.Caller(), st.Handle); err == nil {
		t.Fatal("resend inside the cooldown succeeded")
	}
	if got := e.PendingCode(t, st.ID); got != code {
		t.Error("a refused resend replaced the live code")
	}
	if _, err := e.Svc.VerifyEmail(t.Context(), otptest.Caller(), st.Handle, code); err != nil {
		t.Errorf("the original code after a refused resend: %v, want it still valid", err)
	}
	var verified bool
	if err := e.Pool.QueryRow(context.Background(), `SELECT email_verified_at IS NOT NULL FROM users WHERE id = $1`, u.ID).Scan(&verified); err != nil || !verified {
		t.Errorf("email verified = %v, %v", verified, err)
	}
}
