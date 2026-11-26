package outbox_test

// Feature 004 (S04): sensitive payloads, expiry of lease-lost sends and DeliverNow.
// Rules: BR-CLI-04 (the sign-up code must not outlive its use), FR-011/FR-013, ADR 0003 Am. 2
// (specs/004-otp-delivery/data-model.md section 6, contracts/go-module-api.md section 5).
//
// Contract used here:
//   - outbox.Message.SensitivePayload stores outbox_messages.sensitive_payload = true.
//   - A trigger erases payload to '{}' whenever a sensitive row is inserted or its status is set to
//     sent, dead, withdrawn or expired (relay, withdraw by key/subject, expiry sweep, admin cancel,
//     DeliverNow). The CHECK outbox_messages_sensitive_erased_ck holds the same rule.
//   - ExpireDueMessages also expires 'sending' rows whose lease ran out and whose expires_at has
//     passed; an expired message is never claimed again, so never sent.
//   - Admin retry of a sensitive dead message is ErrConflict (the payload is gone).
//   - DeliverNow(ctx, org, topic, key) (sent bool, err error): see the table in the tests; a sender
//     failure is data (false, nil) recorded as a normal failed attempt; it refuses to run in a tx.
//   - Non-sensitive messages behave exactly as before.

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/NandanMaheta/swastik/apps/api/internal/outbox"
)

// sensitiveMsg is an OTP-like message: sealed payload, sensitive, exempt from quiet hours.
func (e *env) sensitiveMsg(key string) outbox.Message {
	m := e.msg(testTopic, key)
	m.Subject = "otp:ver-1"
	m.Payload = map[string]any{"v": 1, "box": "c2VhbGVkLWNvZGUtMTIzNDU2"}
	m.SensitivePayload = true
	m.ExemptFromQuietHours = true
	return m
}

type sensRow struct {
	Payload   string
	Sensitive bool
	Status    string
	Attempts  int
}

func (e *env) sens(key string) sensRow {
	e.t.Helper()
	var r sensRow
	err := e.pool.QueryRow(e.t.Context(),
		`SELECT payload::text, sensitive_payload, status, attempts FROM outbox_messages WHERE org_id=$1 AND topic=$2 AND dedupe_key=$3`,
		e.org, testTopic, key).Scan(&r.Payload, &r.Sensitive, &r.Status, &r.Attempts)
	if err != nil {
		e.t.Fatalf("read sensitive row %s: %v", key, err)
	}
	return r
}

func (e *env) wantErased(key, status string) {
	e.t.Helper()
	r := e.sens(key)
	if r.Status != status || r.Payload != "{}" || !r.Sensitive {
		e.t.Errorf("%s: row = %+v, want status %s, payload {} and sensitive_payload true", key, r, status)
	}
}

func (e *env) deliverNow(key string) (bool, error) {
	e.t.Helper()
	return e.svc.DeliverNow(e.t.Context(), e.org, testTopic, key)
}

// ---- storage and the erase trigger ---------------------------------------------------------

func TestOutboxSensitive_BR_CLI_04_FlagAndPayloadStoredWhileUnsent(t *testing.T) {
	e := newEnv(t)
	e.add(e.sensitiveMsg("otp:code:1"))
	r := e.sens("otp:code:1")
	if !r.Sensitive || r.Status != "pending" || r.Payload == "{}" {
		t.Fatalf("row = %+v, want a pending sensitive row that still holds its payload", r)
	}
	if r2 := e.row(testTopic, "otp:code:1"); r2.RespectsQuietHours {
		t.Error("respects_quiet_hours = true, want false for an exempt message")
	}
}

func TestOutboxSensitive_BR_CLI_04_PayloadErasedOnEveryTerminalPath(t *testing.T) {
	t.Run("sent by the relay (the sender still saw the payload)", func(t *testing.T) {
		e := newEnv(t)
		e.add(e.sensitiveMsg("k"))
		if sum := e.relay(); sum.Sent != 1 {
			t.Fatalf("relay = %+v, want one sent", sum)
		}
		got := e.snd.Envelopes()
		if len(got) != 1 || string(got[0].Payload) == "{}" || len(got[0].Payload) < 10 {
			t.Fatalf("sender envelope payload = %q, want the sealed payload", got[0].Payload)
		}
		e.wantErased("k", "sent")
	})
	t.Run("dead after the last attempt", func(t *testing.T) {
		e := newEnv(t)
		m := e.sensitiveMsg("k")
		m.MaxAttempts = 1
		e.add(m)
		e.snd.FailAlways()
		if sum := e.relay(); sum.Dead != 1 {
			t.Fatalf("relay = %+v, want one dead", sum)
		}
		e.wantErased("k", "dead")
	})
	t.Run("withdrawn by key", func(t *testing.T) {
		e := newEnv(t)
		e.add(e.sensitiveMsg("k"))
		if err := e.inTx(func(ctx context.Context) error {
			n, err := e.svc.Withdraw(ctx, e.org, testTopic, "k")
			if err == nil && n != 1 {
				t.Errorf("Withdraw = %d, want 1", n)
			}
			return err
		}); err != nil {
			t.Fatal(err)
		}
		e.wantErased("k", "withdrawn")
	})
	t.Run("withdrawn by subject", func(t *testing.T) {
		e := newEnv(t)
		e.add(e.sensitiveMsg("k1"))
		e.add(e.sensitiveMsg("k2"))
		if err := e.inTx(func(ctx context.Context) error {
			n, err := e.svc.WithdrawSubject(ctx, e.org, "otp:ver-1")
			if err == nil && n != 2 {
				t.Errorf("WithdrawSubject = %d, want 2", n)
			}
			return err
		}); err != nil {
			t.Fatal(err)
		}
		e.wantErased("k1", "withdrawn")
		e.wantErased("k2", "withdrawn")
	})
	t.Run("expired by the sweep", func(t *testing.T) {
		e := newEnv(t)
		m := e.sensitiveMsg("k")
		m.ExpiresAt = ptr(t0.Add(10 * time.Minute))
		e.add(m)
		e.clk.Set(t0.Add(10 * time.Minute))
		if sum := e.relay(); sum.Expired != 1 || sum.Sent != 0 {
			t.Fatalf("relay = %+v, want one expired and none sent", sum)
		}
		if e.snd.Count() != 0 {
			t.Fatal("an expired code reached the sender")
		}
		e.wantErased("k", "expired")
	})
	t.Run("cancelled by an admin after dying", func(t *testing.T) {
		e := newEnv(t)
		e.add(e.sensitiveMsg("k"))
		e.exec(`UPDATE outbox_messages SET status='dead', attempts=3, finished_at=$1, last_attempt_at=$1 WHERE dedupe_key='k'`, t0)
		id := e.row(testTopic, "k").ID
		if _, err := e.cancel(e.org, id, ""); err != nil {
			t.Fatalf("CancelMessage: %v", err)
		}
		e.wantErased("k", "withdrawn")
	})
	t.Run("inserted already finished", func(t *testing.T) {
		e := newEnv(t)
		e.exec(`INSERT INTO outbox_messages (org_id, topic, recipient_kind, subject, dedupe_key, payload, sensitive_payload,
			available_at, status, finished_at, sent_at) VALUES ($1, $2, 'admin', 's', 'ins', '{"x":"secret"}', true, $3, 'sent', $3, $3)`,
			e.org, testTopic, t0)
		e.wantErased("ins", "sent")
	})
}

func TestOutboxSensitive_BR_CLI_04_NonSensitiveMessagesKeepTheirPayload(t *testing.T) {
	e := newEnv(t)
	e.add(e.msg(testTopic, "plain-sent"))
	e.add(e.msg(testTopic, "plain-withdrawn"))
	if sum := e.relay(); sum.Sent != 2 {
		t.Fatalf("relay = %+v", sum)
	}
	e.add(e.msg(testTopic, "plain-w2"))
	if err := e.inTx(func(ctx context.Context) error {
		_, err := e.svc.Withdraw(ctx, e.org, testTopic, "plain-w2")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"plain-sent", "plain-withdrawn", "plain-w2"} {
		r := e.sens(k)
		if r.Sensitive || r.Payload == "{}" {
			t.Errorf("%s: row = %+v, want sensitive false and the payload kept", k, r)
		}
	}
}

func TestOutboxSensitive_BR_CLI_04_CheckRefusesAReadablePayloadOnAFinishedRow(t *testing.T) {
	e := newEnv(t)
	e.add(e.sensitiveMsg("k"))
	if sum := e.relay(); sum.Sent != 1 {
		t.Fatalf("relay = %+v", sum)
	}
	// An update that does not touch status bypasses the trigger; the CHECK must still hold.
	_, err := e.pool.Exec(e.t.Context(), `UPDATE outbox_messages SET payload = '{"code":"123456"}' WHERE dedupe_key='k'`)
	var pg *pgconn.PgError
	if !errors.As(err, &pg) || pg.Code != "23514" || pg.ConstraintName != "outbox_messages_sensitive_erased_ck" {
		t.Fatalf("error = %v, want check violation outbox_messages_sensitive_erased_ck", err)
	}
	// Pending and sending rows may hold a payload.
	e.add(e.sensitiveMsg("k2"))
	e.exec(`UPDATE outbox_messages SET status='sending', locked_until=$1, lock_token=gen_random_uuid() WHERE dedupe_key='k2'`, t0.Add(time.Minute))
	if r := e.sens("k2"); r.Status != "sending" || r.Payload == "{}" {
		t.Errorf("sending row = %+v, want the payload kept while being sent", r)
	}
}

// ---- expiry of lease-lost sends -------------------------------------------------------------

func TestOutboxSensitive_BR_CLI_04_ExpiredStaleSendingMessageIsNeverClaimedAgain(t *testing.T) {
	for _, sensitive := range []bool{true, false} {
		name := map[bool]string{true: "sensitive", false: "plain"}[sensitive]
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			m := e.sensitiveMsg("k")
			m.SensitivePayload = sensitive
			m.ExpiresAt = ptr(t0.Add(10 * time.Minute))
			e.add(m)
			// A relay crashed mid-send: claimed, lease until t0+1 min.
			e.exec(`UPDATE outbox_messages SET status='sending', attempts=1, locked_until=$1, lock_token=gen_random_uuid(), locked_by='dead-host' WHERE dedupe_key='k'`, t0.Add(time.Minute))

			e.clk.Set(t0.Add(30 * time.Second)) // lease still valid, not expired
			if sum := e.relay(); sum.Sent != 0 || sum.Expired != 0 || e.snd.Count() != 0 {
				t.Fatalf("lease still valid: relay = %+v sent=%d, want nothing to happen", sum, e.snd.Count())
			}
			e.clk.Set(t0.Add(10 * time.Minute)) // lease lost AND expired: never sent
			sum := e.relay()
			if sum.Expired != 1 || sum.Sent != 0 || e.snd.Count() != 0 {
				t.Fatalf("lease lost and expired: relay = %+v sent=%d, want one expired and nothing sent", sum, e.snd.Count())
			}
			if r := e.sens("k"); r.Status != "expired" {
				t.Errorf("status = %s, want expired", r.Status)
			}
			if sensitive {
				e.wantErased("k", "expired")
			}
		})
	}
}

func TestOutboxSensitive_BR_CLI_04_LostLeaseOfAValidCodeIsStillRetaken(t *testing.T) {
	e := newEnv(t)
	m := e.sensitiveMsg("k")
	m.ExpiresAt = ptr(t0.Add(10 * time.Minute))
	e.add(m)
	e.exec(`UPDATE outbox_messages SET status='sending', attempts=1, locked_until=$1, lock_token=gen_random_uuid() WHERE dedupe_key='k'`, t0.Add(time.Minute))
	e.clk.Set(t0.Add(5 * time.Minute))
	if sum := e.relay(); sum.Sent != 1 {
		t.Fatalf("relay = %+v, want the unexpired message taken over and sent", sum)
	}
	e.wantErased("k", "sent")
}

// ---- admin retry ----------------------------------------------------------------------------

func TestOutboxSensitive_BR_CLI_04_AdminRetryOfASensitiveMessageIsAConflict(t *testing.T) {
	e := newEnv(t)
	e.add(e.sensitiveMsg("k"))
	e.exec(`UPDATE outbox_messages SET status='dead', attempts=3, finished_at=$1, last_attempt_at=$1 WHERE dedupe_key='k'`, t0)
	id := e.row(testTopic, "k").ID

	_, err := e.svc.RetryMessage(e.t.Context(), adminActor, e.org, id, "idem-1")
	if !errors.Is(err, outbox.ErrConflict) {
		t.Fatalf("RetryMessage error = %v, want ErrConflict (the payload is gone)", err)
	}
	e.wantErased("k", "dead")
	if rows := e.auditFor(id); len(rows) != 0 {
		t.Errorf("audit rows = %d, want none for a refused retry", len(rows))
	}
	// A non-sensitive dead message can still be retried.
	e.add(e.msg(testTopic, "plain"))
	e.exec(`UPDATE outbox_messages SET status='dead', attempts=8, finished_at=$1, last_attempt_at=$1 WHERE dedupe_key='plain'`, t0)
	if _, err := e.svc.RetryMessage(e.t.Context(), adminActor, e.org, e.row(testTopic, "plain").ID, ""); err != nil {
		t.Errorf("retry of a plain dead message: %v", err)
	}
}

// ---- DeliverNow -----------------------------------------------------------------------------

func TestDeliverNow_BR_CLI_04_SendsExactlyTheNamedMessage(t *testing.T) {
	e := newEnv(t)
	e.add(e.sensitiveMsg("target"))
	e.add(e.sensitiveMsg("bystander"))

	sent, err := e.deliverNow("target")
	if err != nil || !sent {
		t.Fatalf("DeliverNow = %v, %v, want true, nil", sent, err)
	}
	envs := e.snd.Envelopes()
	if len(envs) != 1 || envs[0].DedupeKey != "target" || envs[0].Attempt != 1 || string(envs[0].Payload) == "{}" {
		t.Fatalf("envelopes = %+v, want one for target, attempt 1, with the payload", envs)
	}
	e.wantErased("target", "sent")
	if r := e.row(testTopic, "target"); r.SentAt == nil || !r.SentAt.Equal(t0) || r.FinishedAt == nil || r.LockedUntil != nil {
		t.Errorf("target row = %+v, want sent_at/finished_at = now and no lease", r)
	}
	if r := e.sens("bystander"); r.Status != "pending" || r.Attempts != 0 || r.Payload == "{}" {
		t.Errorf("bystander = %+v, want untouched", r)
	}
	// The relay must not send it again.
	if sum := e.relay(); sum.Sent != 1 || e.snd.Deliveries("target") != 1 {
		t.Errorf("relay after DeliverNow = %+v, target deliveries = %d, want only the bystander sent", sum, e.snd.Deliveries("target"))
	}
}

func TestDeliverNow_BR_CLI_04_NothingToDoIsFalseWithoutError(t *testing.T) {
	e := newEnv(t)
	cases := []struct {
		name    string
		arrange func(key string)
	}{
		{"absent", nil},
		{"already sent", func(k string) { e.add(e.sensitiveMsg(k)); e.relay() }},
		{"withdrawn", func(k string) {
			e.add(e.sensitiveMsg(k))
			_ = e.inTx(func(ctx context.Context) error { _, err := e.svc.Withdraw(ctx, e.org, testTopic, k); return err })
		}},
		{"claimed by another relay, lease valid", func(k string) {
			e.add(e.sensitiveMsg(k))
			e.exec(`UPDATE outbox_messages SET status='sending', attempts=1, locked_until=$2, lock_token=gen_random_uuid() WHERE dedupe_key=$1`, k, t0.Add(time.Minute))
		}},
		{"expired", func(k string) {
			m := e.sensitiveMsg(k)
			m.ExpiresAt = ptr(t0.Add(time.Minute))
			e.add(m)
			e.clk.Set(t0.Add(time.Minute))
		}},
		{"not yet available (backoff)", func(k string) {
			e.add(e.sensitiveMsg(k))
			e.exec(`UPDATE outbox_messages SET available_at=$2 WHERE dedupe_key=$1`, k, t0.Add(time.Hour))
		}},
	}
	for i, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e.reset()
			key := "k" + string(rune('a'+i))
			if c.arrange != nil {
				c.arrange(key)
			}
			before := e.snd.Count()
			sent, err := e.deliverNow(key)
			if sent || err != nil {
				t.Fatalf("DeliverNow = %v, %v, want false, nil", sent, err)
			}
			if e.snd.Count() != before {
				t.Errorf("the sender was called (%d -> %d)", before, e.snd.Count())
			}
		})
	}
}

func TestDeliverNow_BR_CLI_04_QuietHoursApplyUnlessExempt(t *testing.T) {
	e := newEnv(t)
	e.clk.Set(ist(14, 23, 0)) // 23:00 IST, inside quiet hours 21:30-08:00

	exempt := e.sensitiveMsg("exempt")
	plain := e.sensitiveMsg("respects")
	plain.ExemptFromQuietHours = false
	e.add(exempt)
	e.add(plain)

	if sent, err := e.deliverNow("exempt"); err != nil || !sent {
		t.Fatalf("exempt at 23:00 IST: %v, %v, want true, nil (US2.4)", sent, err)
	}
	if sent, err := e.deliverNow("respects"); err != nil || sent {
		t.Fatalf("quiet-hours message at 23:00 IST: %v, %v, want false, nil", sent, err)
	}
	if e.snd.Deliveries("respects") != 0 {
		t.Error("a message that respects quiet hours was sent at night")
	}
}

func TestDeliverNow_BR_CLI_04_FailureIsARecordedAttemptNotAnError(t *testing.T) {
	e := newEnv(t)
	e.add(e.sensitiveMsg("k"))
	e.snd.FailNext(1)

	sent, err := e.deliverNow("k")
	if sent || err != nil {
		t.Fatalf("DeliverNow = %v, %v, want false, nil", sent, err)
	}
	r, row := e.sens("k"), e.row(testTopic, "k")
	if r.Status != "pending" || r.Attempts != 1 || r.Payload == "{}" {
		t.Fatalf("row = %+v, want pending, 1 attempt, payload kept for the retry", r)
	}
	if row.LastError == nil || *row.LastError == "" || row.LockedUntil != nil || !row.AvailableAt.After(t0) {
		t.Errorf("row = %+v, want last_error set, lease released and a later available_at", row)
	}
	// The relay retries it once the backoff has passed, and then erases the payload.
	e.clk.Set(row.AvailableAt.Add(time.Second))
	if sum := e.relay(); sum.Sent != 1 {
		t.Fatalf("relay = %+v, want the retry sent", sum)
	}
	e.wantErased("k", "sent")
	if got := e.snd.Envelopes(); len(got) != 1 || got[0].Attempt != 2 {
		t.Errorf("envelopes = %+v, want one delivery on attempt 2", got)
	}
}

func TestDeliverNow_BR_CLI_04_LastAttemptFailingMakesItDeadAndErased(t *testing.T) {
	e := newEnv(t)
	m := e.sensitiveMsg("k")
	m.MaxAttempts = 1
	e.add(m)
	e.snd.FailAlways()
	if sent, err := e.deliverNow("k"); sent || err != nil {
		t.Fatalf("DeliverNow = %v, %v, want false, nil", sent, err)
	}
	e.wantErased("k", "dead")
}

func TestDeliverNow_BR_CLI_04_MissingSenderIsAFailedAttempt(t *testing.T) {
	e := newEnv(t)
	m := e.sensitiveMsg("k")
	m.Topic = "otp.unregistered"
	e.add(m)
	sent, err := e.svc.DeliverNow(e.t.Context(), e.org, "otp.unregistered", "k")
	if sent || err != nil {
		t.Fatalf("DeliverNow = %v, %v, want false, nil", sent, err)
	}
	var attempts int
	if err := e.pool.QueryRow(e.t.Context(), `SELECT attempts FROM outbox_messages WHERE topic='otp.unregistered'`).Scan(&attempts); err != nil || attempts != 1 {
		t.Errorf("attempts = %d, %v, want 1", attempts, err)
	}
}

func TestDeliverNow_BR_CLI_04_RefusesToRunInsideATransaction(t *testing.T) {
	e := newEnv(t)
	e.add(e.sensitiveMsg("k"))
	var sent bool
	err := e.inTx(func(ctx context.Context) error {
		var err error
		sent, err = e.svc.DeliverNow(ctx, e.org, testTopic, "k")
		return err
	})
	if err == nil || sent {
		t.Fatalf("DeliverNow in a tx = %v, %v, want false and an error", sent, err)
	}
	if e.snd.Count() != 0 {
		t.Error("the sender was called inside a transaction")
	}
	if r := e.sens("k"); r.Status != "pending" || r.Attempts != 0 {
		t.Errorf("row = %+v, want untouched", r)
	}
}

func TestDeliverNow_BR_CLI_04_ConcurrentCallsSendOnce(t *testing.T) {
	e := newEnv(t)
	e.add(e.sensitiveMsg("k"))
	release := make(chan struct{})
	e.snd.OnSend(func(context.Context, outbox.Envelope) { <-release })

	var wg sync.WaitGroup
	results := make([]bool, 4)
	for i := range results {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i], _ = e.svc.DeliverNow(context.Background(), e.org, testTopic, "k")
		}()
	}
	time.Sleep(300 * time.Millisecond) // losers return false while the winner is inside Send
	close(release)
	wg.Wait()

	n := 0
	for _, ok := range results {
		if ok {
			n++
		}
	}
	if n != 1 || e.snd.Deliveries("k") != 1 {
		t.Fatalf("sent results = %v, deliveries = %d, want exactly one", results, e.snd.Deliveries("k"))
	}
	e.wantErased("k", "sent")
}

func TestDeliverNow_BR_CLI_04_PlainMessagesWorkToo(t *testing.T) {
	e := newEnv(t)
	e.add(e.msg(testTopic, "plain"))
	if sent, err := e.deliverNow("plain"); err != nil || !sent {
		t.Fatalf("DeliverNow = %v, %v, want true, nil", sent, err)
	}
	if r := e.sens("plain"); r.Status != "sent" || r.Sensitive || r.Payload == "{}" {
		t.Errorf("row = %+v, want sent with the payload kept", r)
	}
}

func TestDeliverNow_BR_CLI_04_OtherOrganisationsAreInvisible(t *testing.T) {
	e := newEnv(t)
	e.add(e.sensitiveMsg("k"))
	other := e.newOrg("Other")
	if sent, err := e.svc.DeliverNow(e.t.Context(), other, testTopic, "k"); sent || err != nil {
		t.Fatalf("DeliverNow for another org = %v, %v, want false, nil", sent, err)
	}
	if e.snd.Count() != 0 {
		t.Error("a message of another organisation was sent")
	}
}
