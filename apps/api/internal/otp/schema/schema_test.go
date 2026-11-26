// Schema tests for migration 00005_otp.sql (feature 004, S04; BR-CLI-04, BR-CLI-05, D-01, D-02, D-08).
// Real PostgreSQL through dbtest.New; every constraint is exercised with plain SQL, so a missing or
// weakened CHECK, UNIQUE index, FK or cascade fails here. Column and constraint names are the ones
// in specs/004-otp-delivery/data-model.md sections 1 to 5 (CHECK violation = SQLSTATE 23514,
// UNIQUE = 23505, FK = 23503).
package schema_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/NandanMaheta/swastik/apps/api/internal/platform/dbtest"
)

var t0 = time.Date(2026, time.November, 26, 10, 0, 0, 0, time.UTC)

type world struct {
	t    *testing.T
	pool *pgxpool.Pool
	org  uuid.UUID
	user uuid.UUID // pending_verification client
	seq  int
}

func newWorld(t *testing.T) *world {
	t.Helper()
	w := &world{t: t, pool: dbtest.New(t), org: uuid.New(), user: uuid.New()}
	w.exec(`INSERT INTO orgs (id, name) VALUES ($1, 'Swastik')`, w.org)
	w.addUser(w.user)
	return w
}

func (w *world) addUser(id uuid.UUID) {
	w.t.Helper()
	w.seq++
	w.exec(`INSERT INTO users (id, org_id, role, status, name, email, mobile, password_hash, password_changed_at)
		VALUES ($1, $2, 'client', 'pending_verification', 'Ravi Shah', $3, $4, '$argon2id$v=19$stub', $5)`,
		id, w.org, fmt.Sprintf("u%d@example.com", w.seq), fmt.Sprintf("+91981234%04d", w.seq), t0)
}

func (w *world) exec(sql string, args ...any) {
	w.t.Helper()
	if _, err := w.pool.Exec(context.Background(), sql, args...); err != nil {
		w.t.Fatalf("exec %q: %v", sql, err)
	}
}

func (w *world) try(sql string, args ...any) error {
	_, err := w.pool.Exec(context.Background(), sql, args...)
	return err
}

func (w *world) count(table, where string, args ...any) int {
	w.t.Helper()
	var n int
	if err := w.pool.QueryRow(context.Background(), `SELECT count(*) FROM `+table+` WHERE `+where, args...).Scan(&n); err != nil {
		w.t.Fatalf("count %s: %v", table, err)
	}
	return n
}

func hash(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }

// wantCode asserts a PostgreSQL error code and, when constraint != "", the constraint or index name.
func wantCode(t *testing.T, err error, code, constraint string) {
	t.Helper()
	var pg *pgconn.PgError
	if !errors.As(err, &pg) {
		t.Fatalf("error = %v, want a PostgreSQL error %s %s", err, code, constraint)
	}
	if pg.Code != code || (constraint != "" && pg.ConstraintName != constraint) {
		t.Fatalf("error = %s %s (%s), want %s %s", pg.Code, pg.ConstraintName, pg.Message, code, constraint)
	}
}

// ver is the set of columns of one otp_verifications insert; nil/zero means NULL.
type ver struct {
	id                  uuid.UUID
	user                *uuid.UUID
	purpose             string
	handle              []byte
	email, mobile       *string
	emailDone, mobDone  *time.Time
	resetHash           []byte
	resetExpires        *time.Time
	finished, cancelled *time.Time
	cancelReason        *string
	createdAt, expires  time.Time
}

func s(v string) *string { return &v }

func (w *world) validVer(purpose string) ver {
	w.seq++
	v := ver{id: uuid.New(), purpose: purpose, handle: hash(byte(w.seq)), createdAt: t0, expires: t0.Add(24 * time.Hour)}
	u := w.user
	switch purpose {
	case "signup":
		v.user, v.email, v.mobile = &u, s("ravi@example.com"), s("+919812345678")
	case "change_email":
		v.user, v.email = &u, s("new@example.com")
	case "change_mobile":
		v.user, v.mobile = &u, s("+919812345679")
	case "password_reset":
		v.user, v.email = &u, s("ravi@example.com")
	}
	return v
}

func (w *world) insertVer(v ver) error {
	return w.try(`INSERT INTO otp_verifications (id, org_id, user_id, purpose, handle_hash, email, mobile, email_done_at,
		mobile_done_at, reset_token_hash, reset_token_expires_at, finished_at, cancelled_at, cancel_reason, created_at, expires_at, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$15)`,
		v.id, w.org, v.user, v.purpose, v.handle, v.email, v.mobile, v.emailDone, v.mobDone, v.resetHash, v.resetExpires,
		v.finished, v.cancelled, v.cancelReason, v.createdAt, v.expires)
}

func (w *world) mustVer(v ver) uuid.UUID {
	w.t.Helper()
	if err := w.insertVer(v); err != nil {
		w.t.Fatalf("insert verification (%s): %v", v.purpose, err)
	}
	return v.id
}

func (w *world) codeArgs(verID uuid.UUID) []any {
	return []any{uuid.New(), w.org, verID, hash(0xC0), t0, t0.Add(10 * time.Minute)}
}

const insertCode = `INSERT INTO otp_email_codes (id, org_id, verification_id, code_digest, issued_at, expires_at) VALUES ($1,$2,$3,$4,$5,$6)`

// ---- otp_verifications ---------------------------------------------------------------------

func TestSchema_BR_CLI_04_VerificationAcceptsEachPurposeShape(t *testing.T) {
	w := newWorld(t)
	for _, p := range []string{"signup", "change_email", "change_mobile", "password_reset"} {
		w.mustVer(w.validVer(p))
		// A different user for the next purpose is not needed: one open flow per user AND purpose.
	}
	// A password-reset decoy: no user, no email (D-06, D-07).
	decoy := w.validVer("password_reset")
	decoy.user, decoy.email = nil, nil
	w.mustVer(decoy)
	decoy2 := w.validVer("password_reset")
	decoy2.user, decoy2.email = nil, nil
	w.mustVer(decoy2) // many decoys may coexist
	if n := w.count("otp_verifications", "org_id = $1", w.org); n != 6 {
		t.Fatalf("rows = %d, want 6", n)
	}
}

func TestSchema_BR_CLI_04_VerificationTargetsCheck(t *testing.T) {
	w := newWorld(t)
	tests := []struct {
		name string
		edit func(*ver)
	}{
		{"signup without mobile", func(v *ver) { v.purpose = "signup"; v.mobile = nil }},
		{"signup without email", func(v *ver) { v.purpose = "signup"; v.email = nil }},
		{"signup without user", func(v *ver) { v.purpose = "signup"; v.user = nil }},
		{"change_email with a mobile", func(v *ver) { v.purpose = "change_email"; v.mobile = s("+919812345679") }},
		{"change_email without email", func(v *ver) { v.purpose = "change_email"; v.mobile = nil; v.email = nil }},
		{"change_email without user", func(v *ver) { v.purpose = "change_email"; v.mobile = nil; v.user = nil }},
		{"change_mobile with an email", func(v *ver) { v.purpose = "change_mobile"; v.email = s("x@example.com") }},
		{"change_mobile without mobile", func(v *ver) { v.purpose = "change_mobile"; v.email = nil; v.mobile = nil }},
		{"change_mobile without user", func(v *ver) { v.purpose = "change_mobile"; v.email = nil; v.user = nil }},
		{"password_reset with a mobile", func(v *ver) { v.purpose = "password_reset"; v.mobile = s("+919812345679") }},
		{"password_reset user without email", func(v *ver) { v.purpose = "password_reset"; v.mobile = nil; v.email = nil }},
		{"password_reset email without user", func(v *ver) { v.purpose = "password_reset"; v.mobile = nil; v.user = nil }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := w.validVer("signup")
			tt.edit(&v)
			wantCode(t, w.insertVer(v), "23514", "otp_verifications_targets_ck")
		})
	}
}

func TestSchema_BR_CLI_04_VerificationColumnChecks(t *testing.T) {
	w := newWorld(t)
	tests := []struct {
		name       string
		edit       func(*ver)
		constraint string // "" = any CHECK
	}{
		{"unknown purpose", func(v *ver) { v.purpose = "login" }, ""},
		{"handle hash of 31 bytes", func(v *ver) { v.handle = hash(1)[:31] }, ""},
		{"email not lower case", func(v *ver) { v.email = s("Ravi@Example.com") }, ""},
		{"email with padding", func(v *ver) { v.email = s(" ravi@example.com") }, ""},
		{"mobile without +91", func(v *ver) { v.mobile = s("9812345678") }, ""},
		{"mobile starting with 5", func(v *ver) { v.mobile = s("+915812345678") }, ""},
		{"expiry not after creation", func(v *ver) { v.expires = v.createdAt }, "otp_verifications_expiry_ck"},
		{"reset token on a signup", func(v *ver) { v.resetHash, v.resetExpires = hash(9), ptrT(t0.Add(time.Minute)) }, "otp_verifications_reset_only_ck"},
		{"email_done without email", func(v *ver) {
			v.purpose, v.email, v.mobile, v.emailDone = "change_mobile", nil, s("+919812345679"), ptrT(t0)
		}, "otp_verifications_done_ck"},
		{"mobile_done without mobile", func(v *ver) {
			v.purpose, v.mobile, v.mobDone = "change_email", nil, ptrT(t0)
			v.email = s("new@example.com")
		}, "otp_verifications_done_ck"},
		{"cancelled without reason", func(v *ver) { v.cancelled = ptrT(t0) }, "otp_verifications_cancel_ck"},
		{"reason without cancelled_at", func(v *ver) { v.cancelReason = s("cancelled") }, "otp_verifications_cancel_ck"},
		{"unknown cancel reason", func(v *ver) { v.cancelled, v.cancelReason = ptrT(t0), s("because") }, ""},
		{"cancelled and finished", func(v *ver) {
			v.cancelled, v.cancelReason, v.finished = ptrT(t0), s("cancelled"), ptrT(t0)
		}, "otp_verifications_cancel_ck"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := w.validVer("signup")
			tt.edit(&v)
			wantCode(t, w.insertVer(v), "23514", tt.constraint)
		})
	}
}

func TestSchema_BR_CLI_04_ResetTokenColumnsComeInPairsOnlyForResets(t *testing.T) {
	w := newWorld(t)
	v := w.validVer("password_reset")
	v.resetHash = hash(9) // expiry missing
	wantCode(t, w.insertVer(v), "23514", "otp_verifications_reset_only_ck")

	v = w.validVer("password_reset")
	v.resetExpires = ptrT(t0.Add(10 * time.Minute)) // hash missing
	wantCode(t, w.insertVer(v), "23514", "otp_verifications_reset_only_ck")

	v = w.validVer("password_reset")
	v.resetHash, v.resetExpires, v.emailDone = hash(9), ptrT(t0.Add(10*time.Minute)), ptrT(t0)
	w.mustVer(v)

	v = w.validVer("password_reset")
	v.user, v.email, v.resetHash = nil, nil, hash(8)
	v.resetExpires = ptrT(t0)
	v.handle = hash(0x55)
	w.mustVer(v) // a decoy may carry a grant shape too; only the pairing is constrained
}

func TestSchema_BR_CLI_04_HandleHashIsUnique(t *testing.T) {
	w := newWorld(t)
	a := w.validVer("signup")
	w.mustVer(a)
	b := w.validVer("change_email")
	b.handle = a.handle
	wantCode(t, w.insertVer(b), "23505", "")
}

func TestSchema_BR_CLI_04_OneOpenFlowPerUserAndPurpose(t *testing.T) {
	w := newWorld(t)
	first := w.validVer("signup")
	w.mustVer(first)

	second := w.validVer("signup")
	wantCode(t, w.insertVer(second), "23505", "otp_verifications_open_uq")

	// Another purpose of the same user is a different flow.
	w.mustVer(w.validVer("change_email"))
	// Another user may have a signup flow.
	other := uuid.New()
	w.addUser(other)
	o := w.validVer("signup")
	o.user = &other
	w.mustVer(o)

	// Cancelling the first frees the slot (Start supersedes in one transaction).
	w.exec(`UPDATE otp_verifications SET cancelled_at = $2, cancel_reason = 'superseded' WHERE id = $1`, first.id, t0)
	w.mustVer(second)
	// So does finishing.
	w.exec(`UPDATE otp_verifications SET finished_at = $2 WHERE id = $1`, second.id, t0)
	third := w.validVer("signup")
	w.mustVer(third)
	if n := w.count("otp_verifications", "user_id = $1 AND purpose = 'signup' AND cancelled_at IS NULL AND finished_at IS NULL", w.user); n != 1 {
		t.Errorf("open signup flows = %d, want 1", n)
	}
}

func TestSchema_BR_CLI_04_VerificationNeedsAnOrgAndAUser(t *testing.T) {
	w := newWorld(t)
	v := w.validVer("signup")
	if err := w.try(`INSERT INTO otp_verifications (org_id, user_id, purpose, handle_hash, email, mobile, expires_at)
		VALUES ($1,$2,'signup',$3,'a@example.com','+919812345678',$4)`, uuid.New(), v.user, v.handle, t0.Add(time.Hour)); err == nil {
		t.Error("a verification for an unknown org was accepted")
	} else {
		wantCode(t, err, "23503", "")
	}
	ghost := uuid.New()
	v.user = &ghost
	wantCode(t, w.insertVer(v), "23503", "")
}

func TestSchema_BR_CLI_04_IdsDefaultToUUIDv7AndTimestampsAreSet(t *testing.T) {
	w := newWorld(t)
	var id uuid.UUID
	var created, updated time.Time
	err := w.pool.QueryRow(context.Background(), `INSERT INTO otp_verifications (org_id, user_id, purpose, handle_hash, email, mobile, expires_at)
		VALUES ($1,$2,'signup',$3,'a@example.com','+919812345678', now() + interval '1 day') RETURNING id, created_at, updated_at`,
		w.org, w.user, hash(0x77)).Scan(&id, &created, &updated)
	if err != nil {
		t.Fatalf("insert with defaults: %v", err)
	}
	if id.Version() != 7 {
		t.Errorf("id version = %d, want 7", id.Version())
	}
	if created.IsZero() || updated.IsZero() {
		t.Error("created_at/updated_at have no default")
	}
}

// ---- otp_email_codes -----------------------------------------------------------------------

func TestSchema_BR_CLI_04_CodeRowChecks(t *testing.T) {
	w := newWorld(t)
	ver := w.mustVer(w.validVer("signup"))

	if err := w.try(insertCode, w.codeArgs(ver)...); err != nil {
		t.Fatalf("a valid code row: %v", err)
	}
	w.exec(`UPDATE otp_email_codes SET ended_at = $1, end_reason = 'used' WHERE verification_id = $2`, t0, ver)

	tests := []struct {
		name string
		sql  string
		args func() []any
	}{
		{"digest of 31 bytes", insertCode, func() []any { a := w.codeArgs(ver); a[3] = hash(1)[:31]; return a }},
		{"expiry equals issue time", insertCode, func() []any { a := w.codeArgs(ver); a[5] = a[4]; return a }},
		{"expiry before issue time", insertCode, func() []any { a := w.codeArgs(ver); a[5] = t0.Add(-time.Minute); return a }},
		{"wrong_attempts 6", `INSERT INTO otp_email_codes (id, org_id, verification_id, code_digest, issued_at, expires_at, wrong_attempts) VALUES ($1,$2,$3,$4,$5,$6,6)`,
			func() []any { return w.codeArgs(ver) }},
		{"wrong_attempts -1", `INSERT INTO otp_email_codes (id, org_id, verification_id, code_digest, issued_at, expires_at, wrong_attempts) VALUES ($1,$2,$3,$4,$5,$6,-1)`,
			func() []any { return w.codeArgs(ver) }},
		{"ended_at without reason", `INSERT INTO otp_email_codes (id, org_id, verification_id, code_digest, issued_at, expires_at, ended_at) VALUES ($1,$2,$3,$4,$5,$6,$5)`,
			func() []any { return w.codeArgs(ver) }},
		{"reason without ended_at", `INSERT INTO otp_email_codes (id, org_id, verification_id, code_digest, issued_at, expires_at, end_reason) VALUES ($1,$2,$3,$4,$5,$6,'used')`,
			func() []any { return w.codeArgs(ver) }},
		{"unknown end reason", `INSERT INTO otp_email_codes (id, org_id, verification_id, code_digest, issued_at, expires_at, ended_at, end_reason) VALUES ($1,$2,$3,$4,$5,$6,$5,'burnt')`,
			func() []any { return w.codeArgs(ver) }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wantCode(t, w.try(tt.sql, tt.args()...), "23514", "")
		})
	}
	// Each of the four end reasons is accepted; five wrong attempts is the maximum.
	for _, reason := range []string{"used", "superseded", "used_up", "cancelled"} {
		a := w.codeArgs(ver)
		w.exec(`INSERT INTO otp_email_codes (id, org_id, verification_id, code_digest, issued_at, expires_at, ended_at, end_reason, wrong_attempts)
			VALUES ($1,$2,$3,$4,$5,$6,$5,$7,5)`, append(a, reason)...)
	}
}

func TestSchema_BR_CLI_04_OnlyOneLiveCodePerVerification(t *testing.T) {
	w := newWorld(t)
	ver := w.mustVer(w.validVer("signup"))
	other := w.mustVer(w.validVer("change_email"))

	w.exec(insertCode, w.codeArgs(ver)...)
	wantCode(t, w.try(insertCode, w.codeArgs(ver)...), "23505", "otp_email_codes_live_uq")
	w.exec(insertCode, w.codeArgs(other)...) // another verification has its own live code

	// Ending the live code (a newer one supersedes it, D-01) frees the slot.
	w.exec(`UPDATE otp_email_codes SET ended_at = $2, end_reason = 'superseded' WHERE verification_id = $1`, ver, t0)
	w.exec(insertCode, w.codeArgs(ver)...)
	if n := w.count("otp_email_codes", "verification_id = $1", ver); n != 2 {
		t.Errorf("codes = %d, want 2 (one ended, one live)", n)
	}
}

func TestSchema_BR_CLI_04_DecoyCodeHasNoOutboxKey(t *testing.T) {
	w := newWorld(t)
	decoy := w.validVer("password_reset")
	decoy.user, decoy.email = nil, nil
	ver := w.mustVer(decoy)
	w.exec(insertCode, w.codeArgs(ver)...) // outbox_key stays NULL
	if n := w.count("otp_email_codes", "verification_id = $1 AND outbox_key IS NULL", ver); n != 1 {
		t.Fatalf("decoy codes without outbox key = %d, want 1", n)
	}
	// A real code carries its dedupe key.
	real := w.mustVer(w.validVer("signup"))
	a := w.codeArgs(real)
	w.exec(`INSERT INTO otp_email_codes (id, org_id, verification_id, code_digest, issued_at, expires_at, outbox_key) VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		append(a, "otp:code:"+a[0].(uuid.UUID).String())...)
}

func TestSchema_BR_CLI_04_CodeNeedsItsVerificationAndOrg(t *testing.T) {
	w := newWorld(t)
	wantCode(t, w.try(insertCode, w.codeArgs(uuid.New())...), "23503", "")
	ver := w.mustVer(w.validVer("signup"))
	a := w.codeArgs(ver)
	a[1] = uuid.New()
	wantCode(t, w.try(insertCode, a...), "23503", "")
}

// ---- otp_used_proofs -----------------------------------------------------------------------

func TestSchema_BR_CLI_04_ProofFingerprintIsUniqueAndThirtyTwoBytes(t *testing.T) {
	w := newWorld(t)
	ver := w.mustVer(w.validVer("signup"))
	const ins = `INSERT INTO otp_used_proofs (fingerprint, org_id, verification_id, used_at) VALUES ($1,$2,$3,$4)`

	w.exec(ins, hash(0xF1), w.org, ver, t0)
	wantCode(t, w.try(ins, hash(0xF1), w.org, ver, t0), "23505", "")
	if _, err := w.pool.Exec(context.Background(), ins+` ON CONFLICT DO NOTHING`, hash(0xF1), w.org, ver, t0); err != nil {
		t.Errorf("ON CONFLICT DO NOTHING failed: %v", err)
	}
	wantCode(t, w.try(ins, hash(0xF2)[:31], w.org, ver, t0), "23514", "")
	wantCode(t, w.try(ins, hash(0xF3), w.org, uuid.New(), t0), "23503", "")
	if n := w.count("otp_used_proofs", "true"); n != 1 {
		t.Errorf("proofs = %d, want 1", n)
	}
}

func TestSchema_BR_CLI_04_DeletingAVerificationCascadesToCodesAndProofs(t *testing.T) {
	w := newWorld(t)
	ver := w.mustVer(w.validVer("signup"))
	keep := w.mustVer(w.validVer("change_email"))
	w.exec(insertCode, w.codeArgs(ver)...)
	w.exec(insertCode, w.codeArgs(keep)...)
	w.exec(`INSERT INTO otp_used_proofs (fingerprint, org_id, verification_id, used_at) VALUES ($1,$2,$3,$4)`, hash(0xAA), w.org, ver, t0)
	w.exec(`INSERT INTO otp_used_proofs (fingerprint, org_id, verification_id, used_at) VALUES ($1,$2,$3,$4)`, hash(0xAB), w.org, keep, t0)

	w.exec(`DELETE FROM otp_verifications WHERE id = $1`, ver)
	if n := w.count("otp_email_codes", "verification_id = $1", ver); n != 0 {
		t.Errorf("codes left after cascade = %d", n)
	}
	if n := w.count("otp_used_proofs", "verification_id = $1", ver); n != 0 {
		t.Errorf("proofs left after cascade = %d", n)
	}
	if w.count("otp_email_codes", "verification_id = $1", keep) != 1 || w.count("otp_used_proofs", "verification_id = $1", keep) != 1 {
		t.Error("the cascade removed rows of another verification")
	}
}

// ---- otp_limits ----------------------------------------------------------------------------

func TestSchema_BR_CLI_04_LimitRowChecks(t *testing.T) {
	w := newWorld(t)
	const ins = `INSERT INTO otp_limits (org_id, scope, subject, events, updated_at) VALUES ($1,$2,$3,$4,$5)`
	events := func(n int) []time.Time {
		out := make([]time.Time, n)
		for i := range out {
			out[i] = t0.Add(time.Duration(i) * time.Second)
		}
		return out
	}
	for i, scope := range []string{"send_contact", "send_user", "send_ip", "check_ip"} {
		w.exec(ins, w.org, scope, hash(byte(i+1)), events(3), t0)
	}
	w.exec(ins, w.org, "send_contact", hash(0x40), events(60), t0) // the cap
	w.exec(ins, w.org, "send_contact", hash(0x41), []time.Time{}, t0)
	wantCode(t, w.try(ins, w.org, "send_contact", hash(0x42), events(61), t0), "23514", "")
	wantCode(t, w.try(ins, w.org, "send_contacts", hash(0x43), events(1), t0), "23514", "")
	wantCode(t, w.try(ins, w.org, "send_ip", hash(0x44)[:31], events(1), t0), "23514", "")
	wantCode(t, w.try(ins, w.org, "send_contact", hash(1), events(1), t0), "23505", "") // PK (org, scope, subject)
	w.exec(ins, w.org, "send_ip", hash(1), events(1), t0)                               // same subject, other scope is fine
	wantCode(t, w.try(ins, uuid.New(), "send_ip", hash(0x45), events(1), t0), "23503", "")

	// events defaults to the empty array.
	w.exec(`INSERT INTO otp_limits (org_id, scope, subject, updated_at) VALUES ($1,'check_ip',$2,$3)`, w.org, hash(0x46), t0)
	var n int
	if err := w.pool.QueryRow(context.Background(), `SELECT cardinality(events) FROM otp_limits WHERE subject = $1`, hash(0x46)).Scan(&n); err != nil || n != 0 {
		t.Errorf("default events cardinality = %d, %v, want 0", n, err)
	}
}

func TestSchema_BR_CLI_04_LimitRowsHaveNoUserForeignKey(t *testing.T) {
	// Unknown identifiers need rows too (D-07): the subject is a digest, never a users reference.
	w := newWorld(t)
	w.exec(`INSERT INTO otp_limits (org_id, scope, subject, events, updated_at) VALUES ($1,'send_user',$2,'{}',$3)`, w.org, hash(0x99), t0)
}

// ---- otp_daily_counts ----------------------------------------------------------------------

func TestSchema_BR_CLI_04_DailyCountsChecksAndKey(t *testing.T) {
	w := newWorld(t)
	const ins = `INSERT INTO otp_daily_counts (org_id, day, metric, count) VALUES ($1,$2,$3,$4)`
	day := "2026-11-26"
	for _, m := range []string{"email_sent", "email_failed", "limit_refused", "proof_accepted", "proof_refused"} {
		w.exec(ins, w.org, day, m, 1)
	}
	wantCode(t, w.try(ins, w.org, day, "email_sent", 2), "23505", "")
	w.exec(ins, w.org, "2026-11-27", "email_sent", 0)
	wantCode(t, w.try(ins, w.org, "2026-11-28", "email_sent", -1), "23514", "")
	wantCode(t, w.try(ins, w.org, "2026-11-28", "sms_sent", 1), "23514", "")
	wantCode(t, w.try(ins, uuid.New(), "2026-11-28", "email_sent", 1), "23503", "")

	// The upsert-increment used by the store.
	w.exec(ins+` ON CONFLICT (org_id, day, metric) DO UPDATE SET count = otp_daily_counts.count + 1`, w.org, day, "email_sent", 1)
	var c int
	if err := w.pool.QueryRow(context.Background(), `SELECT count FROM otp_daily_counts WHERE day = $1 AND metric = 'email_sent'`, day).Scan(&c); err != nil || c != 1+1 {
		t.Errorf("count after upsert = %d, %v, want 2", c, err)
	}
}

// ---- operational tables, not append-only ---------------------------------------------------

func TestSchema_BR_CLI_04_OperationalTablesAllowUpdateAndDelete(t *testing.T) {
	w := newWorld(t)
	ver := w.mustVer(w.validVer("signup"))
	w.exec(insertCode, w.codeArgs(ver)...)
	w.exec(`UPDATE otp_email_codes SET wrong_attempts = wrong_attempts + 1 WHERE verification_id = $1`, ver)
	w.exec(`UPDATE otp_verifications SET email_done_at = $2, updated_at = $2 WHERE id = $1`, ver, t0)
	w.exec(`DELETE FROM otp_verifications WHERE id = $1`, ver)
}

func ptrT(t time.Time) *time.Time { return &t }
