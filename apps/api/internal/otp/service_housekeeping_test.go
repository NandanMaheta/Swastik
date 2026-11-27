package otp_test

// S14 - housekeeping (feature 004; BR-CLI-04; FR-015, data-model section 8): the recurring
// otp.housekeeping job runs daily at 03:15 IST, purges expired verifications, used proofs, limit
// rows and daily counts in bounded batches, keeps every audit row, and writes one audit entry
// with counts. The job is driven through RegisterJobs with a fake registrar.

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"pgregory.net/rapid"

	"github.com/NandanMaheta/swastik/apps/api/internal/otp"
	"github.com/NandanMaheta/swastik/apps/api/internal/otp/otptest"
	"github.com/NandanMaheta/swastik/apps/api/internal/platform/istdate"
	"github.com/NandanMaheta/swastik/apps/api/internal/scheduler"
)

type svRegistrar struct {
	kinds    []string
	handlers map[string]scheduler.Handler
	opts     map[string]scheduler.KindOptions
}

func (r *svRegistrar) Register(kind string, h scheduler.Handler, opts scheduler.KindOptions) {
	if r.handlers == nil {
		r.handlers, r.opts = map[string]scheduler.Handler{}, map[string]scheduler.KindOptions{}
	}
	r.kinds = append(r.kinds, kind)
	r.handlers[kind], r.opts[kind] = h, opts
}

func TestHousekeeping_BR_CLI_04_NextRunIsQuarterPastThreeIST(t *testing.T) {
	if otp.HousekeepingKind != "otp.housekeeping" {
		t.Fatalf("HousekeepingKind = %q", otp.HousekeepingKind)
	}
	svMustPanicFree(t, "HousekeepingNext", func() {
		for _, tt := range []struct{ now, want string }{
			{"2026-07-01T10:00:00Z", "2026-07-01T21:45:00Z"}, // 15:30 IST: 03:15 IST on the 2nd
			{"2026-07-01T21:44:59Z", "2026-07-01T21:45:00Z"},
			{"2026-07-01T21:45:00Z", "2026-07-02T21:45:00Z"}, // strictly after now
			{"2026-07-01T00:00:00Z", "2026-07-01T21:45:00Z"},
		} {
			now, _ := time.Parse(time.RFC3339, tt.now)
			want, _ := time.Parse(time.RFC3339, tt.want)
			if got := otp.HousekeepingNext(now); !got.Equal(want) {
				t.Errorf("HousekeepingNext(%s) = %s, want %s", tt.now, got.UTC().Format(time.RFC3339), tt.want)
			}
		}
	})
}

func TestHousekeeping_BR_CLI_04_NextRunProperty(t *testing.T) {
	svMustPanicFree(t, "HousekeepingNext", func() {
		rapid.Check(t, func(t *rapid.T) {
			now := time.Unix(rapid.Int64Range(1_700_000_000, 2_200_000_000).Draw(t, "unix"), 0).UTC()
			next := otp.HousekeepingNext(now)
			if !next.After(now) || next.Sub(now) > 24*time.Hour {
				t.Fatalf("next %v not in (now, now+24h] for %v", next, now)
			}
			if ist := next.In(istdate.IST); ist.Hour() != 3 || ist.Minute() != 15 || ist.Second() != 0 {
				t.Fatalf("next = %v IST, want 03:15:00", ist)
			}
		})
	})
}

func TestHousekeeping_BR_CLI_04_RegistersOneRecurringJob(t *testing.T) {
	e := otptest.NewEnv(t)
	reg := &svRegistrar{}
	svMustPanicFree(t, "RegisterJobs", func() { otp.RegisterJobs(reg, e.Svc) })
	if len(reg.kinds) != 1 || reg.kinds[0] != "otp.housekeeping" {
		t.Fatalf("registered kinds = %v, want exactly [otp.housekeeping]", reg.kinds)
	}
	opts := reg.opts[otp.HousekeepingKind]
	if opts.Recurring == nil || reg.handlers[otp.HousekeepingKind] == nil {
		t.Fatalf("job options = %+v: the kind must be recurring with a handler", opts)
	}
	now := e.Clock.Now()
	if got, want := opts.Recurring(now), otp.HousekeepingNext(now); !got.Equal(want) {
		t.Errorf("Recurring(now) = %v, want HousekeepingNext(now) = %v", got, want)
	}
}

// svSeedVerification inserts a password-reset decoy row (no user, no contact) with explicit times.
func svSeedVerification(t *testing.T, e *otptest.Env, n int, expires time.Time) uuid.UUID {
	t.Helper()
	id := uuid.New()
	e.Exec(t, `INSERT INTO otp_verifications (id, org_id, purpose, handle_hash, created_at, expires_at, updated_at)
		VALUES ($1, $2, 'password_reset', decode(lpad(to_hex($3::int), 64, '0'), 'hex'), $4, $5, $4)`,
		id, e.Org, n, expires.Add(-otp.VerificationTTL), expires)
	return id
}

func svSeedProof(t *testing.T, e *otptest.Env, n int, ver uuid.UUID, usedAt time.Time) {
	t.Helper()
	e.Exec(t, `INSERT INTO otp_used_proofs (fingerprint, org_id, verification_id, used_at)
		VALUES (decode(lpad(to_hex($1::int), 64, '0'), 'hex'), $2, $3, $4)`, n, e.Org, ver, usedAt)
}

func TestHousekeeping_BR_CLI_04_PurgesWhatIsOldKeepsWhatIsNotAndAuditsOnce(t *testing.T) {
	e := otptest.NewEnv(t)
	now := e.Clock.Now()
	reg := &svRegistrar{}
	svMustPanicFree(t, "RegisterJobs", func() { otp.RegisterJobs(reg, e.Svc) })
	run := reg.handlers[otp.HousekeepingKind]
	if run == nil {
		t.Fatal("no housekeeping handler registered")
	}

	u := e.Pending(t)
	live := e.StartSignup(t, u) // a real, live flow with an audit trail
	auditBefore := len(e.OTPAudit(t))

	old := svSeedVerification(t, e, 1, now.Add(-48*time.Hour))  // expired 48 h ago: purged
	edge := svSeedVerification(t, e, 2, now.Add(-23*time.Hour)) // expired 23 h ago: kept (24 h grace)
	oldWithCode := svSeedVerification(t, e, 3, now.Add(-72*time.Hour))
	e.Exec(t, `INSERT INTO otp_email_codes (org_id, verification_id, code_digest, issued_at, expires_at)
		VALUES ($1, $2, decode(repeat('ab', 32), 'hex'), $3, $4)`, e.Org, oldWithCode, now.Add(-96*time.Hour), now.Add(-95*time.Hour))
	svSeedProof(t, e, 10, old, now.Add(-72*time.Hour))     // cascades with its verification
	svSeedProof(t, e, 11, live.ID, now.Add(-25*time.Hour)) // older than 24 h: purged on its own
	svSeedProof(t, e, 12, live.ID, now.Add(-time.Hour))    // kept
	e.Exec(t, `INSERT INTO otp_limits (org_id, scope, subject, events, updated_at) VALUES
		($1, 'send_ip', decode(repeat('01', 32), 'hex'), '{}', $2), ($1, 'send_ip', decode(repeat('02', 32), 'hex'), '{}', $3)`,
		e.Org, now.Add(-49*time.Hour), now.Add(-47*time.Hour))
	today := istdate.DateOf(now)
	e.Exec(t, `INSERT INTO otp_daily_counts (org_id, day, metric, count) VALUES ($1, $2, 'email_sent', 3), ($1, $3, 'email_sent', 4)`,
		e.Org, today.AddDays(-401).String(), today.AddDays(-399).String())

	err := e.Tx.InTx(context.Background(), func(ctx context.Context) error {
		return run(ctx, scheduler.Job{OrgID: e.Org, Kind: otp.HousekeepingKind, RunAt: now})
	})
	if err != nil {
		t.Fatalf("housekeeping job: %v", err)
	}

	has := func(table string, id uuid.UUID) bool {
		return e.Count(t, `SELECT count(*) FROM `+table+` WHERE id = $1`, id) == 1
	}
	if has("otp_verifications", old) || has("otp_verifications", oldWithCode) {
		t.Error("verifications expired more than 24 h ago were not purged")
	}
	if !has("otp_verifications", edge) || !has("otp_verifications", live.ID) {
		t.Error("a verification inside the 24 h grace, or a live one, was purged")
	}
	if n := e.Count(t, `SELECT count(*) FROM otp_email_codes WHERE verification_id = $1`, oldWithCode); n != 0 {
		t.Errorf("codes of a purged verification = %d, want them gone with it", n)
	}
	if n := e.Count(t, `SELECT count(*) FROM otp_used_proofs`); n != 1 {
		t.Errorf("used proofs left = %d, want 1 (the one used an hour ago)", n)
	}
	if n := e.Count(t, `SELECT count(*) FROM otp_limits WHERE scope = 'send_ip' AND subject = decode(repeat('01', 32), 'hex')`); n != 0 {
		t.Errorf("limit row updated 49 h ago left = %d, want purged", n)
	}
	if n := e.Count(t, `SELECT count(*) FROM otp_limits WHERE scope = 'send_ip' AND subject = decode(repeat('02', 32), 'hex')`); n != 1 {
		t.Errorf("limit row updated 47 h ago left = %d, want kept", n)
	}
	if n := e.Count(t, `SELECT count(*) FROM otp_limits WHERE updated_at < $1`, now.Add(-48*time.Hour)); n != 0 {
		t.Errorf("stale limit rows left = %d, want 0", n)
	}
	if n := e.Count(t, `SELECT count(*) FROM otp_daily_counts`); n != 1 {
		t.Errorf("daily counts left = %d, want 1 (399 days old)", n)
	}

	rows := svAuditOf(t, e, "otp.housekeeping.purged")
	if len(rows) != 1 || rows[0].ActorKind != "system" || rows[0].ActorID != uuid.Nil {
		t.Fatalf("purge audit rows = %+v, want exactly one by the system actor", rows)
	}
	var counts map[string]float64
	if err := json.Unmarshal([]byte(rows[0].After), &counts); err != nil || len(counts) == 0 {
		t.Fatalf("purge audit after = %q (%v), want an object of counts", rows[0].After, err)
	}
	sum := 0.0
	for _, v := range counts {
		sum += v
	}
	if sum < 5 {
		t.Errorf("purge counts %v add up to %v, want at least the 5 rows removed directly", counts, sum)
	}
	if got := len(e.OTPAudit(t)); got != auditBefore+1 {
		t.Errorf("otp audit rows = %d, want %d: audit rows are never purged (FR-015)", got, auditBefore+1)
	}
	if v, err := e.Svc.Status(t.Context(), otptest.Caller(), live.Handle); err != nil || v.State != otp.FlowOpen {
		t.Errorf("the live flow after housekeeping: %+v, %v", v, err)
	}
	if err := e.Tx.InTx(context.Background(), func(ctx context.Context) error {
		return run(ctx, scheduler.Job{OrgID: e.Org, Kind: otp.HousekeepingKind, RunAt: now})
	}); err != nil {
		t.Errorf("a second run: %v, want it to be harmless", err)
	}
}
