package otp_test

// S10 - the outbox Sender, the old-contact notice and the daily counters (feature 004; BR-CLI-04,
// BR-CLI-05; FR-011, FR-013, FR-014, FR-017, D-08; contracts/go-module-api.md section 2).

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/NandanMaheta/swastik/apps/api/internal/otp"
	"github.com/NandanMaheta/swastik/apps/api/internal/otp/otptest"
	"github.com/NandanMaheta/swastik/apps/api/internal/outbox"
	"github.com/NandanMaheta/swastik/apps/api/internal/platform/email"
	"github.com/NandanMaheta/swastik/apps/api/internal/platform/istdate"
)

func TestSender_BR_CLI_04_OpensTheBoxAndSendsWithTheDedupeKeyAsIdempotencyKey(t *testing.T) {
	e := otptest.NewEnv(t)
	u := e.Pending(t)
	st := e.StartSignup(t, u)
	row := e.OutboxRows(t, otp.TopicEmailCode)[0]
	code := e.PendingCode(t, st.ID)

	if err := e.Svc.Sender().Send(t.Context(), row.Envelope(e.Org)); err != nil {
		t.Fatalf("Send: %v", err)
	}
	mails := e.Mailer.Mails()
	if len(mails) != 1 || mails[0].To != u.Email || mails[0].Subject != "Your Swastik code: "+code || mails[0].IdempotencyKey != row.Key {
		t.Fatalf("mails = %+v, want one code mail to the account with the dedupe key as Idempotency-Key", mails)
	}
	if c := e.Counts(t); c.EmailSent != 1 || c.EmailFailed != 0 {
		t.Errorf("counts = %+v, want email_sent 1 (FR-017)", c)
	}
}

func TestSender_BR_CLI_04_SkipsACodeThatHasExpired(t *testing.T) {
	e := otptest.NewEnv(t)
	u := e.Pending(t)
	e.StartSignup(t, u)
	row := e.OutboxRows(t, otp.TopicEmailCode)[0]
	e.Clock.Advance(otp.CodeTTL - time.Second)
	if err := e.Svc.Sender().Send(t.Context(), row.Envelope(e.Org)); err != nil || e.Mailer.Calls() != 1 {
		t.Fatalf("Send one second before expiry: %v calls %d, want it sent", err, e.Mailer.Calls())
	}
	e.Clock.Advance(time.Second) // now == expires_at
	// An expired code is not delivered, and the sender must say so: returning nil would make the
	// outbox mark the message "sent" (review fix; see TestSender_BR_CLI_04_ExpiredCodeIsReportedNotDeliveredNeverSent).
	if err := e.Svc.Sender().Send(t.Context(), row.Envelope(e.Org)); err == nil {
		t.Fatal("Send at expiry = nil, want an error: nil means delivered and the message would be marked sent")
	}
	if e.Mailer.Calls() != 1 {
		t.Errorf("mailer calls = %d, want no second call for an expired code", e.Mailer.Calls())
	}
	if c := e.Counts(t); c.EmailSent != 1 || c.EmailFailed != 0 {
		t.Errorf("counts = %+v, want the skipped send counted as neither sent nor failed", c)
	}
}

func TestSender_BR_CLI_04_ProviderFailuresAreCountedReturnedAndTextIsRedacted(t *testing.T) {
	e := otptest.NewEnv(t)
	u := e.Pending(t)
	st := e.StartSignup(t, u)
	row := e.OutboxRows(t, otp.TopicEmailCode)[0]
	code := e.PendingCode(t, st.ID)
	for _, cause := range []error{email.ErrUnavailable, email.ErrRejected} {
		e.Mailer.FailErr = fmt.Errorf("resend: status 429: %w", cause)
		err := e.Svc.Sender().Send(t.Context(), row.Envelope(e.Org))
		if !errors.Is(err, cause) {
			t.Errorf("Send with %v = %v, want the provider error returned so the relay retries", cause, err)
		}
		if err != nil {
			svNoLeak(t, "sender error", err.Error(), u.Email, code)
		}
	}
	if c := e.Counts(t); c.EmailFailed != 2 || c.EmailSent != 0 {
		t.Errorf("counts = %+v, want email_failed 2", c)
	}
	if got := e.Logs.String(); got != "" {
		svNoLeak(t, "logs", got, u.Email, code)
	}
}

func TestSender_BR_CLI_04_ABoxThatDoesNotOpenIsAnErrorWithoutDetail(t *testing.T) {
	e := otptest.NewEnv(t)
	u := e.Pending(t)
	st := e.StartSignup(t, u)
	row := e.OutboxRows(t, otp.TopicEmailCode)[0]
	code := e.PendingCode(t, st.ID)

	with := func(edit func(*outbox.Envelope)) outbox.Envelope {
		env := row.Envelope(e.Org)
		edit(&env)
		return env
	}
	cases := []struct {
		name string
		env  outbox.Envelope
	}{
		{"another dedupe key (aad mismatch)", with(func(v *outbox.Envelope) { v.DedupeKey = "otp:code:" + st.ID.String() })},
		{"another topic (aad mismatch)", with(func(v *outbox.Envelope) { v.Topic = otp.TopicContactNotice })},
		{"garbage box", with(func(v *outbox.Envelope) { v.Payload = []byte(`{"v":1,"box":"!!!not-base64!!!"}`) })},
		{"not JSON", with(func(v *outbox.Envelope) { v.Payload = []byte(`not json`) })},
		{"erased payload", with(func(v *outbox.Envelope) { v.Payload = []byte(`{}`) })},
	}
	for _, c := range cases {
		err := e.Svc.Sender().Send(t.Context(), c.env)
		if err == nil {
			t.Errorf("%s: Send succeeded", c.name)
			continue
		}
		svNoLeak(t, c.name+" error", err.Error(), u.Email, code, string(row.Payload))
	}
	if n := e.Mailer.Calls(); n != 0 {
		t.Errorf("mailer calls = %d, want 0: nothing is sent from a box that does not open", n)
	}
}

func TestNotice_BR_CLI_05_QueuesAnEmailWithoutCodeOrNewContact(t *testing.T) {
	e := otptest.NewEnv(t)
	u := e.Active(t)
	now := e.Clock.Now()
	for _, changed := range []string{"email", "mobile"} {
		err := e.Tx.InTx(context.Background(), func(ctx context.Context) error {
			return e.Svc.NotifyOldContact(ctx, otp.ContactNotice{OrgID: e.Org, UserID: u.ID, OldEmail: "old.address@example.com", Changed: changed}, otptest.ActorOf(u))
		})
		if err != nil {
			t.Fatalf("NotifyOldContact(%s): %v", changed, err)
		}
	}
	rows := e.OutboxRows(t, otp.TopicContactNotice)
	if len(rows) != 2 {
		t.Fatalf("notice rows = %d, want 2", len(rows))
	}
	for i, r := range rows {
		if r.Status != "pending" || !r.Sensitive || !r.RespectsQ || r.ExpiresAt == nil || !r.ExpiresAt.Equal(now.Add(24*time.Hour)) {
			t.Errorf("notice row %d = %+v, want pending, sensitive, respecting quiet hours, expiring in 24 h (FR-014)", i, r)
		}
		if !strings.HasPrefix(r.Key, "otp:notice:") {
			t.Errorf("dedupe key = %q, want otp:notice:<uuid>", r.Key)
		}
		plain := e.OpenBox(t, r.Payload, r.Topic, r.Key)
		if plain["to"] != "old.address@example.com" {
			t.Errorf("notice recipient = %v, want the old address", plain["to"])
		}
		if _, hasCode := plain["code"]; hasCode {
			t.Error("the notice payload carries a code")
		}
		if want := []string{"email", "mobile"}[i]; plain["changed"] != want {
			t.Errorf("changed = %v, want %s", plain["changed"], want)
		}
	}
	if rows := svAuditOf(t, e, "otp.notice.queued"); len(rows) != 2 {
		t.Errorf("otp.notice.queued audit rows = %d, want 2", len(rows))
	} else {
		svNoLeak(t, "notice audit", rows[0].After+rows[1].After, "old.address@example.com", "old.address")
	}

	if sum := e.Relay(t); sum.Sent != 2 {
		t.Fatalf("relay = %+v, want both notices sent", sum)
	}
	mails := e.Mailer.Mails()
	if len(mails) != 2 || mails[0].To != "old.address@example.com" || !strings.Contains(mails[0].Subject, "email address") || !strings.Contains(mails[1].Subject, "mobile number") {
		t.Fatalf("mails = %+v, want one notice per change, naming what changes", mails)
	}
	for _, m := range mails {
		if svSixDigitsAnywhere.MatchString(m.Subject + " " + m.Text) {
			t.Errorf("notice contains a 6-digit number (a code?): %q", m.Text)
		}
		if !strings.Contains(strings.ToLower(m.Text), "contact the operator") {
			t.Errorf("notice text lacks the contact-the-operator advice: %q", m.Text)
		}
	}
}

func TestNotice_BR_CLI_05_RespectsQuietHours(t *testing.T) {
	e := otptest.NewEnv(t)
	u := e.Active(t)
	e.Clock.Set(svIST(0, 23, 0))
	err := e.Tx.InTx(context.Background(), func(ctx context.Context) error {
		return e.Svc.NotifyOldContact(ctx, otp.ContactNotice{OrgID: e.Org, UserID: u.ID, OldEmail: "old@example.com", Changed: "email"}, otptest.ActorOf(u))
	})
	if err != nil {
		t.Fatal(err)
	}
	row := e.OutboxRows(t, otp.TopicContactNotice)[0]
	if want := svIST(1, 8, 0); !row.AvailableAt.Equal(want) {
		t.Errorf("available_at = %v, want %v (08:00 IST: only codes were exempted, Q1)", row.AvailableAt, want)
	}
	e.Relay(t)
	if e.Mailer.Calls() != 0 {
		t.Error("the notice was sent inside quiet hours")
	}
	e.Clock.Set(svIST(1, 8, 0))
	e.Relay(t)
	if e.Mailer.Calls() != 1 {
		t.Errorf("mailer calls at 08:00 IST = %d, want 1", e.Mailer.Calls())
	}
}

func TestDailyCounts_BR_CLI_04_CountPerISTDayWithoutIdentifiers(t *testing.T) {
	e := otptest.NewEnv(t)
	// 23:59:30 IST on 1 July: one sent mail; 00:00:30 IST on 2 July: one sent, one failed.
	e.Clock.Set(svIST(0, 23, 59).Add(30 * time.Second))
	u1 := e.Pending(t)
	e.Deliver(t, e.StartSignup(t, u1).ID)
	e.Clock.Set(svIST(1, 0, 0).Add(30 * time.Second))
	u2, u3 := e.Pending(t), e.Pending(t)
	e.Deliver(t, e.StartSignup(t, u2).ID)
	e.Mailer.FailErr = fmt.Errorf("resend: status 500: %w", email.ErrUnavailable)
	e.Deliver(t, e.StartSignup(t, u3).ID)

	day1, day2 := istdate.DateOf(svIST(0, 12, 0)), istdate.DateOf(svIST(1, 12, 0))
	c1, err := e.Svc.DailyCounts(t.Context(), e.Org, day1)
	if err != nil || c1 != (otp.DailyCounts{EmailSent: 1}) {
		t.Errorf("1 July counts = %+v, %v, want exactly 1 email_sent", c1, err)
	}
	c2, err := e.Svc.DailyCounts(t.Context(), e.Org, day2)
	if err != nil || c2 != (otp.DailyCounts{EmailSent: 1, EmailFailed: 1}) {
		t.Errorf("2 July counts = %+v, %v, want 1 sent and 1 failed", c2, err)
	}
	if c3, err := e.Svc.DailyCounts(t.Context(), e.Org, day2.AddDays(1)); err != nil || c3 != (otp.DailyCounts{}) {
		t.Errorf("3 July counts = %+v, %v, want zeros", c3, err)
	}
}

func TestDailyCounts_BR_CLI_04_AreIsolatedPerOrganisation(t *testing.T) {
	e := otptest.NewEnv(t)
	u := e.Pending(t)
	e.Deliver(t, e.StartSignup(t, u).ID)
	var other [16]byte
	other[0] = 1
	c, err := e.Svc.DailyCounts(t.Context(), other, istdate.DateOf(e.Clock.Now()))
	if err != nil || c != (otp.DailyCounts{}) {
		t.Errorf("another org's counts = %+v, %v, want zeros", c, err)
	}
}
