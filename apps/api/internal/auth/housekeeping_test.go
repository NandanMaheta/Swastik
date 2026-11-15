package auth_test

// S15 - the auth.housekeeping job body (plan P-20, data-model "Housekeeping queries"):
//
//	const HousekeepingKind = "auth.housekeeping"
//	func HousekeepingNext(now time.Time) time.Time                          // 03:30 IST, strictly after now
//	func (s *Service) Housekeep(ctx, orgID) (PurgeCounts, error)            // needs the job transaction
//
// Purge rules at now: auth_throttles with updated_at + 15m <= now and no lock past now;
// mfa_challenges with expires_at <= now; refresh_tokens of sessions whose LEAST(ended_at,
// absolute_expires_at) + 30 days <= now. At most 1000 rows per table per run. One audit row
// auth.housekeeping.purged (system actor, entity "auth", NULL entity id, counts) only when
// something was purged. Real Store, real PostgreSQL, fake clock.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"pgregory.net/rapid"

	"github.com/NandanMaheta/swastik/apps/api/internal/auth"
	"github.com/NandanMaheta/swastik/apps/api/internal/auth/authtest"
	"github.com/NandanMaheta/swastik/apps/api/internal/platform/crypto"
	"github.com/NandanMaheta/swastik/apps/api/internal/platform/db"
	"github.com/NandanMaheta/swastik/apps/api/internal/platform/istdate"
)

func TestHousekeep_KindAndNextRun(t *testing.T) {
	if auth.HousekeepingKind != "auth.housekeeping" {
		t.Fatalf("HousekeepingKind = %q", auth.HousekeepingKind)
	}
	for _, tt := range []struct{ now, want string }{
		{"2026-07-01T10:00:00Z", "2026-07-01T22:00:00Z"}, // 15:30 IST: next is 03:30 IST on the 2nd
		{"2026-07-01T21:59:59Z", "2026-07-01T22:00:00Z"},
		{"2026-07-01T22:00:00Z", "2026-07-02T22:00:00Z"}, // strictly after now
		{"2026-07-01T00:00:00Z", "2026-07-01T22:00:00Z"},
	} {
		now, _ := time.Parse(time.RFC3339, tt.now)
		want, _ := time.Parse(time.RFC3339, tt.want)
		if got := auth.HousekeepingNext(now); !got.Equal(want) {
			t.Errorf("HousekeepingNext(%s) = %s, want %s", tt.now, got.UTC().Format(time.RFC3339), tt.want)
		}
	}
}

func TestHousekeep_NextRunProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		now := time.Unix(rapid.Int64Range(1_700_000_000, 2_200_000_000).Draw(t, "unix"), 0).UTC()
		next := auth.HousekeepingNext(now)
		if !next.After(now) || next.Sub(now) > 24*time.Hour {
			t.Fatalf("next %v not in (now, now+24h] for %v", next, now)
		}
		if ist := next.In(istdate.IST); ist.Hour() != 3 || ist.Minute() != 30 || ist.Second() != 0 {
			t.Fatalf("next = %v IST, want 03:30:00", ist)
		}
	})
}

// ---- fixtures by SQL ----

func hkThrottle(t *testing.T, e *authtest.Env, org uuid.UUID, name string, updated time.Time, locked *time.Time, failures ...time.Time) {
	t.Helper()
	if failures == nil {
		failures = []time.Time{}
	}
	e.Exec(t, `INSERT INTO auth_throttles (org_id, scope, subject, failures, locked_until, updated_at) VALUES ($1,'signin',$2,$3,$4,$5)`,
		org, crypto.Digest("throttle:"+name), failures, locked, updated)
}

func hkChallenge(t *testing.T, e *authtest.Env, org, user uuid.UUID, name string, expires time.Time, consumed *time.Time) {
	t.Helper()
	e.Exec(t, `INSERT INTO mfa_challenges (org_id, user_id, token_hash, purpose, device_id, device_name, platform, client_type, created_at, expires_at, consumed_at)
		VALUES ($1,$2,$3,'verify',$4,'Pixel 9','android','mobile',$5,$6,$7)`,
		org, user, crypto.Digest("challenge:"+name), uuid.New(), expires.Add(-5*time.Minute), expires, consumed)
}

// hkFamily inserts a session with a two-token refresh family (R1 used, replaced by R2) and returns
// the session id and the raw R2.
func hkFamily(t *testing.T, e *authtest.Env, org, user uuid.UUID, ended *time.Time, absolute time.Time) (uuid.UUID, string) {
	t.Helper()
	sess := uuid.New()
	created := absolute.Add(-90 * 24 * time.Hour)
	var reason any
	if ended != nil {
		reason = "signed_out"
	}
	e.Exec(t, `INSERT INTO device_sessions (id, org_id, user_id, device_id, device_name, platform, client_type, created_at, last_active_at,
		idle_expires_at, absolute_expires_at, ended_at, end_reason) VALUES ($1,$2,$3,$4,'Pixel 9','android','mobile',$5,$5,$6,$7,$8,$9)`,
		sess, org, user, uuid.New(), created, created.Add(30*24*time.Hour), absolute, ended, reason)
	r2, d2, err := crypto.NewToken("drt_")
	if err != nil {
		t.Fatal(err)
	}
	_, d1, _ := crypto.NewToken("drt_")
	id2 := uuid.New()
	e.Exec(t, `INSERT INTO refresh_tokens (id, org_id, session_id, token_hash, issued_at) VALUES ($1,$2,$3,$4,$5)`, id2, org, sess, d2, created)
	e.Exec(t, `INSERT INTO refresh_tokens (org_id, session_id, token_hash, issued_at, used_at, replaced_by) VALUES ($1,$2,$3,$4,$4,$5)`, org, sess, d1, created, id2)
	return sess, r2
}

func hkRun(t *testing.T, e *authtest.Env, s *auth.Service, org uuid.UUID) auth.PurgeCounts {
	t.Helper()
	var c auth.PurgeCounts
	err := e.Tx.InTx(t.Context(), func(ctx context.Context) (err error) {
		c, err = s.Housekeep(ctx, org)
		return err
	})
	if err != nil {
		t.Fatalf("Housekeep: %v", err)
	}
	return c
}

func hkRows(t *testing.T, e *authtest.Env, table string) int {
	t.Helper()
	return svCount(t, e, `SELECT count(*) FROM `+table)
}

// ---- behaviour ----

func TestHousekeep_RequiresTheJobTransaction(t *testing.T) {
	e := authtest.New(t)
	s := e.Service(t)
	hkThrottle(t, e, e.Org, "old", e.Clock.Now().Add(-time.Hour), nil)
	if _, err := s.Housekeep(t.Context(), e.Org); !errors.Is(err, db.ErrNoTx) {
		t.Fatalf("Housekeep without a transaction: err = %v, want db.ErrNoTx", err)
	}
	if hkRows(t, e, "auth_throttles") != 1 {
		t.Error("rows were deleted outside a transaction")
	}
}

func TestHousekeep_StaleThrottlesOnlyAtTheBoundary(t *testing.T) {
	e := authtest.New(t)
	s := e.Service(t)
	now := e.Clock.Now()
	lockedFuture, lockedNow := now.Add(time.Second), now
	hkThrottle(t, e, e.Org, "stale-exactly-15m", now.Add(-15*time.Minute), nil, now.Add(-15*time.Minute))
	hkThrottle(t, e, e.Org, "recent-14m59s", now.Add(-15*time.Minute+time.Second), nil, now.Add(-15*time.Minute+time.Second))
	hkThrottle(t, e, e.Org, "locked-until-future", now.Add(-20*time.Minute), &lockedFuture)
	hkThrottle(t, e, e.Org, "lock-ended-exactly-now", now.Add(-20*time.Minute), &lockedNow)

	got := hkRun(t, e, s, e.Org)
	if got.Throttles != 2 || got.Challenges != 0 || got.RefreshTokens != 0 {
		t.Fatalf("counts = %+v, want 2 throttles only", got)
	}
	if n := hkRows(t, e, "auth_throttles"); n != 2 {
		t.Fatalf("throttle rows left = %d, want the recent one and the still-locked one", n)
	}
	var left int
	if err := e.Pool.QueryRow(t.Context(), `SELECT count(*) FROM auth_throttles WHERE subject = ANY($1)`,
		[][]byte{crypto.Digest("throttle:recent-14m59s"), crypto.Digest("throttle:locked-until-future")}).Scan(&left); err != nil || left != 2 {
		t.Errorf("the wrong throttles were kept (%d of the 2 expected, err %v)", left, err)
	}
}

func TestHousekeep_ExpiredChallengesOnly(t *testing.T) {
	e := authtest.New(t)
	s := e.Service(t)
	a := e.NewAdmin(t)
	now := e.Clock.Now()
	consumed := now.Add(-time.Hour)
	hkChallenge(t, e, e.Org, a.ID, "expires-now", now, nil)
	hkChallenge(t, e, e.Org, a.ID, "expired-and-consumed", now.Add(-time.Hour), &consumed)
	hkChallenge(t, e, e.Org, a.ID, "expires-in-1s", now.Add(time.Second), nil)
	hkChallenge(t, e, e.Org, a.ID, "consumed-but-unexpired", now.Add(time.Minute), &consumed)

	if got := hkRun(t, e, s, e.Org); got.Challenges != 2 || got.Throttles != 0 || got.RefreshTokens != 0 {
		t.Fatalf("counts = %+v, want 2 challenges only", got)
	}
	if n := hkRows(t, e, "mfa_challenges"); n != 2 {
		t.Errorf("challenge rows left = %d, want 2", n)
	}
}

func TestHousekeep_DeadRefreshFamiliesAreDeletedWholeAndSessionsKept(t *testing.T) {
	e := authtest.New(t)
	s := e.Service(t)
	u := e.UserWithStatus(t, auth.StatusActive)
	now := e.Clock.Now()
	day := 24 * time.Hour
	endedLong, endedShort := now.Add(-30*day), now.Add(-30*day+time.Second)
	farFuture := now.Add(50 * day)
	hkFamily(t, e, e.Org, u.ID, &endedLong, farFuture)             // ended exactly 30 days ago: purged
	hkFamily(t, e, e.Org, u.ID, &endedShort, farFuture)            // 1 second short: kept
	hkFamily(t, e, e.Org, u.ID, nil, now.Add(-30*day))             // expired exactly 30 days ago, never ended: purged
	hkFamily(t, e, e.Org, u.ID, nil, now.Add(-30*day+time.Second)) // kept
	hkFamily(t, e, e.Org, u.ID, nil, now.Add(30*day))              // live: kept
	sessions, tokens := hkRows(t, e, "device_sessions"), hkRows(t, e, "refresh_tokens")

	got := hkRun(t, e, s, e.Org)
	if got.RefreshTokens != 4 || got.Throttles != 0 || got.Challenges != 0 {
		t.Fatalf("counts = %+v, want 4 refresh tokens (two whole families)", got)
	}
	if n := hkRows(t, e, "refresh_tokens"); n != tokens-4 {
		t.Errorf("refresh tokens left = %d, want %d", n, tokens-4)
	}
	if n := hkRows(t, e, "device_sessions"); n != sessions {
		t.Errorf("device_sessions = %d, want %d (the device history is kept)", n, sessions)
	}
}

func TestHousekeep_AuditRowOnlyWhenSomethingWasPurgedAndRerunIsANoOp(t *testing.T) {
	e := authtest.New(t)
	s := e.Service(t)
	if got := hkRun(t, e, s, e.Org); got != (auth.PurgeCounts{}) {
		t.Fatalf("counts on an empty database = %+v", got)
	}
	if rows := e.AuditOf(t, auth.ActionHousekeepingPurged); len(rows) != 0 {
		t.Fatalf("audit rows with nothing purged = %d, want 0", len(rows))
	}

	a := e.NewAdmin(t)
	now := e.Clock.Now()
	hkThrottle(t, e, e.Org, "a", now.Add(-time.Hour), nil)
	hkThrottle(t, e, e.Org, "b", now.Add(-time.Hour), nil)
	hkChallenge(t, e, e.Org, a.ID, "c", now.Add(-time.Minute), nil)
	if got := hkRun(t, e, s, e.Org); got != (auth.PurgeCounts{Throttles: 2, Challenges: 1}) {
		t.Fatalf("counts = %+v, want 2 throttles and 1 challenge", got)
	}
	row := mfOnly(t, e, auth.ActionHousekeepingPurged)
	after := mfAfter(t, row)
	if row.ActorKind != "system" || row.ActorID != uuid.Nil || row.Entity != "auth" || row.EntityID != uuid.Nil ||
		after["throttles"] != float64(2) || after["challenges"] != float64(1) || after["refresh_tokens"] != float64(0) {
		t.Errorf("audit = %+v %v", row, after)
	}
	if got := hkRun(t, e, s, e.Org); got != (auth.PurgeCounts{}) {
		t.Errorf("rerun counts = %+v, want nothing (idempotent)", got)
	}
	if got := len(e.AuditOf(t, auth.ActionHousekeepingPurged)); got != 1 {
		t.Errorf("audit rows after the rerun = %d, want still 1", got)
	}
}

func TestHousekeep_OtherOrganisationsAreUntouched(t *testing.T) {
	e := authtest.New(t)
	s := e.Service(t)
	other := uuid.New()
	e.Exec(t, `INSERT INTO orgs (id, name) VALUES ($1, 'Other')`, other)
	old := e.Clock.Now().Add(-time.Hour)
	hkThrottle(t, e, e.Org, "mine", old, nil)
	hkThrottle(t, e, other, "theirs", old, nil)
	if got := hkRun(t, e, s, e.Org); got.Throttles != 1 {
		t.Fatalf("counts = %+v, want 1", got)
	}
	var n int
	if err := e.Pool.QueryRow(t.Context(), `SELECT count(*) FROM auth_throttles WHERE org_id = $1`, other).Scan(&n); err != nil || n != 1 {
		t.Errorf("the other organisation's throttle rows = %d (err %v), want 1", n, err)
	}
}

func TestHousekeep_AtMostAThousandRowsPerTablePerRun(t *testing.T) {
	e := authtest.New(t)
	s := e.Service(t)
	a := e.NewAdmin(t)
	now := e.Clock.Now()
	e.Exec(t, `INSERT INTO auth_throttles (org_id, scope, subject, failures, updated_at)
		SELECT $1, 'signin', decode(md5(i::text) || md5(i::text || 'x'), 'hex'), '{}', $2 FROM generate_series(1, 1005) i`, e.Org, now.Add(-time.Hour))
	e.Exec(t, `INSERT INTO mfa_challenges (org_id, user_id, token_hash, purpose, device_id, device_name, platform, client_type, created_at, expires_at)
		SELECT $1, $2, decode(md5(i::text) || md5(i::text || 'y'), 'hex'), 'verify', gen_random_uuid(), 'Pixel', 'android', 'mobile', $3, $3
		FROM generate_series(1, 1003) i`, e.Org, a.ID, now.Add(-time.Hour))

	first := hkRun(t, e, s, e.Org)
	if first.Throttles != 1000 || first.Challenges != 1000 {
		t.Fatalf("first run = %+v, want 1000 and 1000", first)
	}
	second := hkRun(t, e, s, e.Org)
	if second.Throttles != 5 || second.Challenges != 3 {
		t.Fatalf("second run = %+v, want the remaining 5 and 3", second)
	}
}

// hkOutcome is what the visible behaviour of lockout, refresh and challenge checks is, so a run
// with the purge and one without can be compared (behaviour-neutral, P-20).
type hkOutcome struct {
	LockStarted  bool
	Failures     int
	RefreshErr   string
	ChallengeErr string
	ThrottleRows int
}

func hkScenario(t *testing.T, purge bool) hkOutcome {
	t.Helper()
	e := authtest.New(t)
	s := e.Service(t)
	admin := mfEnrolled(t, e)
	client := e.UserWithStatus(t, auth.StatusActive)

	tok := mfChallenge(t, e, s, admin.User) // expires at T0+5m
	e.Clock.Advance(10 * time.Minute)
	now := e.Clock.Now()
	subject := svSubject(e, "signin", svUserKey(client))
	e.Exec(t, `INSERT INTO auth_throttles (org_id, scope, subject, failures, updated_at) VALUES ($1,'signin',$2,$3,$4)`,
		e.Org, subject, []time.Time{now.Add(-20 * time.Minute), now.Add(-20 * time.Minute), now.Add(-20 * time.Minute), now.Add(-20 * time.Minute)}, now.Add(-20*time.Minute))
	ended := now.Add(-40 * 24 * time.Hour)
	_, raw := hkFamily(t, e, e.Org, client.ID, &ended, now.Add(10*24*time.Hour))

	if purge {
		got := hkRun(t, e, s, e.Org)
		if got.Throttles != 1 || got.Challenges != 1 || got.RefreshTokens != 2 {
			t.Fatalf("purge counts = %+v, want 1, 1, 2", got)
		}
	}

	var out hkOutcome
	err := e.Tx.InTx(t.Context(), func(ctx context.Context) (err error) {
		out.LockStarted, _, err = s.Fail(ctx, e.Org, "signin", svUserKey(client), svPolicy)
		return err
	})
	if err != nil {
		t.Fatalf("Fail: %v", err)
	}
	out.Failures = len(svThrottle(t, e, svUserKey(client)).Failures)
	_, err = s.Refresh(t.Context(), svRefreshIn(uuid.New(), raw))
	out.RefreshErr = errString(err)
	_, err = s.VerifyMFA(t.Context(), mfVerifyIn(tok, mfCode(t, e, admin.Secret, 0)))
	out.ChallengeErr = errString(err)
	out.ThrottleRows = hkRows(t, e, "auth_throttles")
	return out
}

func errString(err error) string {
	if err == nil {
		return "<nil>"
	}
	return err.Error()
}

func TestHousekeep_IsBehaviourNeutral(t *testing.T) {
	without := hkScenario(t, false)
	with := hkScenario(t, true)
	if with != without {
		t.Fatalf("outcomes differ with the purge:\n without = %+v\n with    = %+v", without, with)
	}
	if without.LockStarted || without.Failures != 1 {
		t.Errorf("stale failures must not count toward a new lock: %+v (want 1 failure, no lock)", without)
	}
	if without.RefreshErr != auth.ErrRefreshRejected.Error() {
		t.Errorf("a dead family's token: %q, want ErrRefreshRejected", without.RefreshErr)
	}
	if without.ChallengeErr != auth.ErrInvalidChallenge.Error() {
		t.Errorf("an expired challenge: %q, want ErrInvalidChallenge", without.ChallengeErr)
	}
}
