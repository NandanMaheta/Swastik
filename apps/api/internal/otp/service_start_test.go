package otp_test

// S10 - Start, Cancel, limits and audit (feature 004; BR-CLI-04, BR-CLI-05; spec US1.1, US2.1-2.3,
// US5.1, US6.1, D-01..D-03, D-08, FR-001, FR-002, FR-004, FR-010, FR-011, FR-012, FR-013).
// Fake clock, real auth, real outbox, real PostgreSQL.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/NandanMaheta/swastik/apps/api/internal/auth"
	"github.com/NandanMaheta/swastik/apps/api/internal/auth/authtest"
	"github.com/NandanMaheta/swastik/apps/api/internal/otp"
	"github.com/NandanMaheta/swastik/apps/api/internal/otp/otptest"
)

func TestStart_BR_CLI_04_SignupQueuesOneSealedCodeEmailToTheAccountEmail(t *testing.T) {
	e := otptest.NewEnv(t)
	u := e.Pending(t)
	now := e.Clock.Now()
	st := e.StartSignup(t, u)

	if !svHandleRE.MatchString(st.Handle) {
		t.Errorf("handle = %q, want ovh_ and 43 URL-safe characters", st.Handle)
	}
	if !st.ExpiresAt.Equal(now.Add(otp.VerificationTTL)) {
		t.Errorf("ExpiresAt = %v, want now + 24 h", st.ExpiresAt)
	}
	ver := svVer(t, e, st.ID)
	if ver.Purpose != "signup" || ver.UserID == nil || *ver.UserID != u.ID || ver.Email == nil || *ver.Email != u.Email ||
		ver.Mobile == nil || *ver.Mobile != u.Mobile {
		t.Errorf("verification = %+v, want a signup flow targeting the account email and mobile", ver)
	}

	rows := e.OutboxRows(t, otp.TopicEmailCode)
	if len(rows) != 1 {
		t.Fatalf("code emails queued = %d, want exactly 1 (US1.1)", len(rows))
	}
	r := rows[0]
	if r.Status != "pending" || !r.Sensitive || r.RespectsQ {
		t.Errorf("outbox row: status %q sensitive %v respects_quiet_hours %v, want pending, sensitive, exempt from quiet hours (FR-012, FR-013)", r.Status, r.Sensitive, r.RespectsQ)
	}
	if r.ExpiresAt == nil || !r.ExpiresAt.Equal(now.Add(otp.CodeTTL)) {
		t.Errorf("outbox expires_at = %v, want the code expiry now + 10 min (FR-011)", r.ExpiresAt)
	}
	if r.RecipientID == nil || *r.RecipientID != u.ID || r.Subject != "otp:"+st.ID.String() {
		t.Errorf("recipient %v subject %q, want the user and otp:<verification id>", r.RecipientID, r.Subject)
	}
	code := svLive(t, e, st.ID)
	if r.Key != "otp:code:"+code.ID.String() || code.OutboxKey == nil || *code.OutboxKey != r.Key {
		t.Errorf("dedupe key %q / outbox_key %v, want otp:code:<code id>", r.Key, code.OutboxKey)
	}
	if !code.ExpiresAt.Equal(now.Add(otp.CodeTTL)) || code.Wrong != 0 {
		t.Errorf("code row = %+v", code)
	}

	plain := e.OpenBox(t, r.Payload, r.Topic, r.Key)
	plainCode, _ := plain["code"].(string)
	if plain["to"] != u.Email || plain["purpose"] != "signup" || !svSixDigits.MatchString(plainCode) {
		t.Errorf("sealed payload keys: to=%v purpose=%v code ok=%v", plain["to"], plain["purpose"], svSixDigits.MatchString(plainCode))
	}
	if exp, _ := plain["expires_at"].(string); exp == "" {
		t.Error("sealed payload has no expires_at (the Sender skips expired codes with it)")
	} else if got, err := time.Parse(time.RFC3339Nano, exp); err != nil || !got.Equal(now.Add(otp.CodeTTL)) {
		t.Errorf("sealed expires_at = %q (%v), want %v", exp, err, now.Add(otp.CodeTTL))
	}
	// The stored digest is the keyed digest bound to purpose, verification and code id (D-08).
	if want := otp.CodeDigest(e.Digests, otp.PurposeSignup, st.ID, code.ID, plainCode); !bytes.Equal(code.Digest, want) {
		t.Error("the stored code_digest is not CodeDigest(purpose, verification id, code id, code)")
	}
	// The readable code and the address are nowhere in the stored (unencrypted) outbox columns.
	svNoLeak(t, "outbox payload column", string(r.Payload), plainCode, u.Email)
}

func TestStart_BR_CLI_04_OnlyAPendingVerificationClientMaySignUp(t *testing.T) {
	e := otptest.NewEnv(t)
	cases := map[string]authtest.User{
		"active":           e.UserWithStatus(t, auth.StatusActive),
		"pending_approval": e.UserWithStatus(t, auth.StatusPendingApproval),
		"disabled":         e.UserWithStatus(t, auth.StatusDisabled),
		"admin":            e.NewAdmin(t),
	}
	for name, u := range cases {
		_, err := e.TryStart(otp.StartInput{UserID: u.ID, Purpose: otp.PurposeSignup}, otptest.ActorOf(u))
		if !errors.Is(err, otp.ErrNotAllowed) {
			t.Errorf("%s: Start(signup) err = %v, want ErrNotAllowed (edge case: approvals pending)", name, err)
		}
	}
	if n := e.Count(t, `SELECT count(*) FROM otp_verifications`) + e.Count(t, `SELECT count(*) FROM outbox_messages`); n != 0 {
		t.Errorf("a refused Start left %d rows behind", n)
	}
	if rows := e.OTPAudit(t); len(rows) != 0 {
		t.Errorf("a refused Start wrote %d audit rows", len(rows))
	}
}

func TestStart_BR_CLI_05_ChangeEmailSendsTheCodeToTheNewAddressOnly(t *testing.T) {
	e := otptest.NewEnv(t)
	u := e.Active(t)
	const newAddr = "  New.Address@Example.COM "
	want, err := auth.NormalizeEmail(newAddr)
	if err != nil {
		t.Fatal(err)
	}
	st := e.StartChange(t, u, otp.PurposeChangeEmail, newAddr)
	e.Deliver(t, st.ID)

	mails := e.Mailer.Mails()
	if len(mails) != 1 || mails[0].To != want {
		t.Fatalf("mails = %+v, want one mail to the normalised new address (US5.1)", mails)
	}
	var email string
	if err := e.Pool.QueryRow(context.Background(), `SELECT email FROM users WHERE id = $1`, u.ID).Scan(&email); err != nil || email != u.Email {
		t.Errorf("account email = %q (%v), want it unchanged until 007 applies the approved change (D-09)", email, err)
	}
	v, err := e.Svc.Get(t.Context(), st.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if v.Purpose != otp.PurposeChangeEmail || v.TargetEmail != want || v.TargetMobile != "" || v.Mobile != nil {
		t.Errorf("View = %+v, want change_email with the readable new address for 007 and no mobile", v)
	}
	if v.UserID == nil || *v.UserID != u.ID || v.State != otp.FlowOpen || v.Email == nil || v.Email.State != otp.ContactPending {
		t.Errorf("View state = %+v", v)
	}
	if v.Email.Masked == want || strings.Contains(v.Email.Masked, "Address") {
		t.Errorf("masked contact = %q must hide the address", v.Email.Masked)
	}
}

func TestStart_BR_CLI_05_ChangeMobileQueuesNoEmail(t *testing.T) {
	e := otptest.NewEnv(t)
	u := e.Active(t)
	st := e.StartChange(t, u, otp.PurposeChangeMobile, "98765 43210")
	e.Deliver(t, st.ID)
	if n := len(e.OutboxRows(t, "")); n != 0 {
		t.Errorf("outbox rows = %d, want 0: a mobile change is proved by Firebase, not by an email", n)
	}
	if n := len(e.Mailer.Mails()); n != 0 {
		t.Errorf("mails = %d, want 0", n)
	}
	v, err := e.Svc.Get(t.Context(), st.ID)
	if err != nil || v.TargetMobile != "+919876543210" || v.TargetEmail != "" || v.Mobile == nil || v.Email != nil {
		t.Errorf("Get = %+v, %v, want the normalised new mobile and no email contact", v, err)
	}
}

func TestStart_BR_CLI_05_InvalidInputIsRefusedBeforeAnythingIsWritten(t *testing.T) {
	e := otptest.NewEnv(t)
	u := e.Active(t)
	for name, in := range map[string]otp.StartInput{
		"bad email":         {UserID: u.ID, Purpose: otp.PurposeChangeEmail, NewContact: "not-an-email"},
		"empty email":       {UserID: u.ID, Purpose: otp.PurposeChangeEmail},
		"bad mobile":        {UserID: u.ID, Purpose: otp.PurposeChangeMobile, NewContact: "12345"},
		"foreign mobile":    {UserID: u.ID, Purpose: otp.PurposeChangeMobile, NewContact: "+14155550100"},
		"unknown purpose":   {UserID: u.ID, Purpose: otp.Purpose("bogus"), NewContact: "a@example.com"},
		"reset not allowed": {UserID: u.ID, Purpose: otp.PurposePasswordReset},
	} {
		if _, err := e.TryStart(in, otptest.ActorOf(u)); err == nil {
			t.Errorf("%s: Start succeeded", name)
		} else if name != "reset not allowed" && !errors.Is(err, otp.ErrInvalidInput) {
			t.Errorf("%s: err = %v, want ErrInvalidInput", name, err)
		}
	}
	if n := e.Count(t, `SELECT count(*) FROM otp_verifications`); n != 0 {
		t.Errorf("verifications after refused starts = %d, want 0", n)
	}
}

func TestStart_BR_CLI_04_ANewerStartSupersedesTheOldFlowAndWithdrawsItsEmail(t *testing.T) {
	e := otptest.NewEnv(t)
	u := e.Pending(t)
	first := e.StartSignup(t, u)
	oldCode := svLive(t, e, first.ID)
	e.Clock.Advance(otp.ResendCooldown + time.Second)
	second := e.StartSignup(t, u)

	if first.ID == second.ID || first.Handle == second.Handle {
		t.Fatal("the second Start returned the first flow")
	}
	old := svVer(t, e, first.ID)
	if old.Cancelled == nil || old.CancelReason == nil || *old.CancelReason != "superseded" {
		t.Errorf("old verification = %+v, want cancelled as superseded", old)
	}
	for _, c := range svCodes(t, e, first.ID) {
		if c.ID == oldCode.ID && (c.EndedAt == nil || c.EndReason == nil || *c.EndReason != "superseded") {
			t.Errorf("old code = %+v, want ended as superseded", c)
		}
	}
	rows := e.OutboxRows(t, otp.TopicEmailCode)
	if len(rows) != 2 || rows[0].Status != "withdrawn" || rows[1].Status != "pending" {
		t.Fatalf("outbox statuses = %v, want [withdrawn pending]: the unsent old email is withdrawn (US2.1, D-01)", statuses(rows))
	}
	if rows[0].Payload == nil || string(rows[0].Payload) != "{}" {
		t.Errorf("withdrawn payload = %s, want it erased to {} (FR-013)", rows[0].Payload)
	}
	if v, err := e.Svc.Get(t.Context(), first.ID); err != nil || v.State != otp.FlowCancelled {
		t.Errorf("Get(old) = %+v, %v, want state cancelled", v, err)
	}
}

func statuses(rows []otptest.OutboxRow) []string {
	out := make([]string, len(rows))
	for i, r := range rows {
		out[i] = r.Status
	}
	return out
}

func TestStart_BR_CLI_04_TheCooldownAlsoGuardsAFreshStartForTheSameContact(t *testing.T) {
	e := otptest.NewEnv(t)
	u := e.Active(t)
	e.StartChange(t, u, otp.PurposeChangeEmail, "fresh@example.com")
	e.Clock.Advance(59 * time.Second)
	_, err := e.TryStart(otp.StartInput{UserID: u.ID, Purpose: otp.PurposeChangeEmail, NewContact: "fresh@example.com"}, otptest.ActorOf(u))
	re := svRetry(t, err, otp.ReasonCooldown)
	if re.RetryAfter != time.Second {
		t.Errorf("RetryAfter = %v, want 1s at 59 s after the previous send (D-02)", re.RetryAfter)
	}
	if n := len(e.OutboxRows(t, otp.TopicEmailCode)); n != 1 {
		t.Errorf("code emails = %d, want 1: a refused start queues nothing", n)
	}
	e.Clock.Advance(time.Second)
	e.StartChange(t, u, otp.PurposeChangeEmail, "fresh@example.com") // 60 s: allowed
}

func TestResend_BR_CLI_04_FiveSendsPerContactPerHourThenTheNextHourBoundary(t *testing.T) {
	e := otptest.NewEnv(t)
	u := e.Pending(t)
	t0 := e.Clock.Now()
	st := e.StartSignup(t, u) // send 1 at t0
	for i := 1; i <= 4; i++ { // sends 2..5 at t0+60 s .. t0+240 s
		e.Clock.Set(t0.Add(time.Duration(i) * otp.ResendCooldown))
		if _, err := e.Svc.Resend(t.Context(), otptest.Caller(), st.Handle); err != nil {
			t.Fatalf("resend %d: %v", i, err)
		}
	}
	e.Clock.Set(t0.Add(5 * otp.ResendCooldown)) // the 6th send, 300 s in
	_, err := e.Svc.Resend(t.Context(), otptest.Caller(), st.Handle)
	re := svRetry(t, err, otp.ReasonRateLimited)
	if want := time.Hour - 5*otp.ResendCooldown; re.RetryAfter != want {
		t.Errorf("RetryAfter = %v, want %v (the oldest send plus 1 h; US2.2)", re.RetryAfter, want)
	}
	if n := len(e.OutboxRows(t, otp.TopicEmailCode)); n != 5 {
		t.Errorf("code emails = %d, want 5: the refused send queued nothing", n)
	}
	if rows := svAuditOf(t, e, "otp.send.refused"); len(rows) != 1 || otptest.AuditAfter(t, rows[0])["reason"] != "rate_limited" {
		t.Errorf("otp.send.refused audit = %+v, want one with reason rate_limited", rows)
	}
	if c := e.Counts(t); c.LimitRefused != 1 {
		t.Errorf("limit_refused = %d, want 1 (FR-017)", c.LimitRefused)
	}

	e.Clock.Set(t0.Add(time.Hour - time.Second)) // the refusal added no event: still blocked at 59:59
	_, err = e.Svc.Resend(t.Context(), otptest.Caller(), st.Handle)
	if re := svRetry(t, err, otp.ReasonRateLimited); re.RetryAfter != time.Second {
		t.Errorf("RetryAfter at 59:59 = %v, want 1s", re.RetryAfter)
	}
	e.Clock.Set(t0.Add(time.Hour)) // the first send leaves the window: exclusive end
	if _, err := e.Svc.Resend(t.Context(), otptest.Caller(), st.Handle); err != nil {
		t.Errorf("resend at exactly one hour: %v, want it allowed", err)
	}
}

func TestStart_BR_CLI_04_TenSendsPerUserPerISTDayAcrossContacts(t *testing.T) {
	e := otptest.NewEnv(t)
	u := e.Active(t)
	for i := 0; i < 10; i++ {
		e.StartChange(t, u, otp.PurposeChangeEmail, fmt.Sprintf("alt%d@example.com", i))
	}
	_, err := e.TryStart(otp.StartInput{UserID: u.ID, Purpose: otp.PurposeChangeEmail, NewContact: "alt10@example.com"}, otptest.ActorOf(u))
	re := svRetry(t, err, otp.ReasonRateLimited)
	if want := svIST(1, 0, 0).Sub(e.Clock.Now()); re.RetryAfter != want {
		t.Errorf("RetryAfter = %v, want %v (until 00:00 IST)", re.RetryAfter, want)
	}
	e.Clock.Set(svIST(1, 0, 0)) // the IST day rolls over
	e.StartChange(t, u, otp.PurposeChangeEmail, "alt10@example.com")
}

func TestStart_BR_CLI_04_TwentySendsPerAddressPerHourWhateverTheUser(t *testing.T) {
	e := otptest.NewEnv(t)
	const ip = "198.51.100.7"
	for i := 0; i < 20; i++ {
		u := e.Pending(t)
		e.Start(t, otp.StartInput{UserID: u.ID, Purpose: otp.PurposeSignup, IP: ip}, otptest.ActorOf(u))
	}
	u := e.Pending(t)
	_, err := e.TryStart(otp.StartInput{UserID: u.ID, Purpose: otp.PurposeSignup, IP: ip}, otptest.ActorOf(u))
	if re := svRetry(t, err, otp.ReasonRateLimited); re.RetryAfter != time.Hour {
		t.Errorf("RetryAfter = %v, want 1h (US2.3)", re.RetryAfter)
	}
	e.Start(t, otp.StartInput{UserID: u.ID, Purpose: otp.PurposeSignup, IP: "198.51.100.8"}, otptest.ActorOf(u)) // another address is unaffected
}

func TestCancel_BR_CLI_04_EndsTheLiveCodeWithdrawsItsEmailAndAudits(t *testing.T) {
	e := otptest.NewEnv(t)
	u := e.Pending(t)
	st := e.StartSignup(t, u)
	err := e.Tx.InTx(context.Background(), func(ctx context.Context) error { return e.Svc.Cancel(ctx, st.ID, otptest.ActorOf(u)) })
	if err != nil {
		t.Fatalf("Cancel: %v", err)
	}
	ver := svVer(t, e, st.ID)
	if ver.Cancelled == nil || ver.CancelReason == nil || *ver.CancelReason != "cancelled" {
		t.Errorf("verification = %+v, want cancelled", ver)
	}
	if c := svCodes(t, e, st.ID)[0]; c.EndedAt == nil || c.EndReason == nil || *c.EndReason != "cancelled" {
		t.Errorf("code = %+v, want ended as cancelled", c)
	}
	if rows := e.OutboxRows(t, otp.TopicEmailCode); len(rows) != 1 || rows[0].Status != "withdrawn" {
		t.Errorf("outbox = %v, want the email withdrawn", statuses(rows))
	}
	e.Deliver(t, st.ID) // nothing to deliver now
	if n := len(e.Mailer.Mails()); n != 0 {
		t.Errorf("mails after cancel = %d, want 0", n)
	}
	if rows := svAuditOf(t, e, "otp.verification.cancelled"); len(rows) != 1 {
		t.Errorf("cancel audit rows = %d, want 1", len(rows))
	}
	err = e.Tx.InTx(context.Background(), func(ctx context.Context) error { return e.Svc.Cancel(ctx, uuid.New(), otptest.ActorOf(u)) })
	if !errors.Is(err, otp.ErrNotFound) {
		t.Errorf("Cancel(unknown) = %v, want ErrNotFound", err)
	}
}

func TestStart_BR_CLI_04_AuditHoldsNoContactCodeHandleOrToken(t *testing.T) {
	e := otptest.NewEnv(t)
	u := e.Pending(t)
	st := e.StartSignup(t, u)
	e.Deliver(t, st.ID)
	code := e.LastCode(t)
	e.Clock.Advance(30 * time.Second)
	_, err := e.Svc.Resend(t.Context(), otptest.Caller(), st.Handle) // cooldown refusal
	_ = svRetry(t, err, otp.ReasonCooldown)

	rows := e.OTPAudit(t)
	var actions []string
	for _, r := range rows {
		actions = append(actions, r.Action)
		if r.Entity != "user" || r.EntityID != u.ID || r.ActorKind != "client" || r.ActorID != u.ID {
			t.Errorf("audit row %s: entity %q/%v actor %s/%v, want the client acting on their own user", r.Action, r.Entity, r.EntityID, r.ActorKind, r.ActorID)
		}
		after := otptest.AuditAfter(t, r)
		for k := range after {
			switch k {
			case "verification_id", "purpose", "outcome", "reason", "ip":
			default:
				t.Errorf("audit row %s has the unexpected key %q (allowed: verification_id, purpose, outcome, reason, ip)", r.Action, k)
			}
		}
		if after["verification_id"] != st.ID.String() || after["purpose"] != "signup" {
			t.Errorf("audit row %s after = %v", r.Action, after)
		}
	}
	for _, want := range []string{"otp.verification.started", "otp.code.issued", "otp.send.refused"} {
		found := false
		for _, a := range actions {
			found = found || a == want
		}
		if !found {
			t.Errorf("audit actions = %v, missing %s", actions, want)
		}
	}
	refused := svAuditOf(t, e, "otp.send.refused")
	if len(refused) == 1 {
		if a := otptest.AuditAfter(t, refused[0]); a["reason"] != "cooldown" || a["ip"] != otptest.DefaultIP {
			t.Errorf("refusal audit after = %v, want reason cooldown and the caller address", a)
		}
	}
	svNoLeak(t, "audit", svAuditText(t, e), u.Email, u.Mobile, strings.TrimPrefix(u.Mobile, "+91"), code, st.Handle)
}
