package ipomarket

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/NandanMaheta/swastik/apps/api/internal/platform/db"
	"github.com/NandanMaheta/swastik/apps/api/internal/platform/dbtest"
)

// Shared fixtures for the database tests of this package (slices S02, S06). Everything is raw SQL
// so no assertion depends on the code under test. Written to pass on PostgreSQL 17 and 18: no
// version-specific SQL, ids that tests choose are generated in Go.

func p64(v int64) *int64    { return &v }
func p32(v int32) *int32    { return &v }
func pStr(v string) *string { return &v }

type mEnv struct {
	t     *testing.T
	pool  *pgxpool.Pool
	tx    db.TxRunner
	store *store
	org   uuid.UUID
	now   time.Time
}

func newMEnv(t *testing.T) *mEnv {
	t.Helper()
	pool := dbtest.New(t)
	e := &mEnv{t: t, pool: pool, tx: db.NewTxRunner(pool), store: &store{}, now: time.Date(2026, 11, 14, 4, 30, 0, 0, time.UTC)}
	e.org = e.newOrg("Operator")
	return e
}

func (e *mEnv) newOrg(name string) uuid.UUID {
	e.t.Helper()
	var id uuid.UUID
	if err := e.pool.QueryRow(e.t.Context(), `INSERT INTO orgs (name) VALUES ($1) RETURNING id`, name).Scan(&id); err != nil {
		e.t.Fatalf("insert org: %v", err)
	}
	return id
}

// in runs fn in one transaction (the store requires it) and fails the test on a tx error.
func (e *mEnv) in(fn func(ctx context.Context)) {
	e.t.Helper()
	if err := e.tx.InTx(e.t.Context(), func(ctx context.Context) error { fn(ctx); return nil }); err != nil {
		e.t.Fatalf("tx: %v", err)
	}
}

type ipoRaw struct {
	published bool
	status    string // default UPCOMING
	lot       *int32
	issue     *int64
	capPaise  *int64
}

// newIPO inserts an ipos row. published=true gives a complete, once-published IPO.
func (e *mEnv) newIPO(org uuid.UUID, mod func(*ipoRaw)) uuid.UUID {
	e.t.Helper()
	r := ipoRaw{status: "UPCOMING", lot: p32(50), issue: p64(100_000)}
	if mod != nil {
		mod(&r)
	}
	var floor *int64
	if r.capPaise != nil {
		floor = p64(*r.capPaise - 5_000)
	}
	var flag, open, closeD *string
	var first *time.Time
	if r.published {
		flag, open, closeD = pStr("APPLY"), pStr("2026-11-11"), pStr("2026-11-13")
		first = &e.now
	}
	var id uuid.UUID
	err := e.pool.QueryRow(e.t.Context(), `INSERT INTO ipos (org_id, name, exchanges, lot_size, issue_price_paise,
		price_band_floor_paise, price_band_cap_paise, apply_flag, open_date, close_date, published, first_published_at,
		status, status_changed_at) VALUES ($1, 'Acme', ARRAY['NSE'], $2, $3, $4, $5, $6, $7::date, $8::date, $9, $10, $11, $12)
		RETURNING id`, org, r.lot, r.issue, floor, r.capPaise, flag, open, closeD, r.published, first, r.status, e.now).Scan(&id)
	if err != nil {
		e.t.Fatalf("insert ipo: %v", err)
	}
	return id
}

func (e *mEnv) publishedIPO() uuid.UUID {
	return e.newIPO(e.org, func(r *ipoRaw) { r.published = true })
}

type gmpRaw struct {
	org, ipo   uuid.UUID
	id         uuid.UUID
	gmp        int64
	note       *string
	corrects   *uuid.UUID
	source     string
	actorKind  string
	actorID    *uuid.UUID
	idemKey    *string
	reqHash    *string
	recordedAt time.Time
}

// rawGMP inserts one ipo_gmp_entries row with valid defaults, then applies mod.
func (e *mEnv) rawGMP(ipo uuid.UUID, mod func(*gmpRaw)) (uuid.UUID, error) {
	e.t.Helper()
	admin := uuid.New()
	g := gmpRaw{org: e.org, ipo: ipo, id: uuid.New(), gmp: 3000, source: "manual", actorKind: "admin", actorID: &admin, recordedAt: e.now}
	if mod != nil {
		mod(&g)
	}
	_, err := e.pool.Exec(e.t.Context(), `INSERT INTO ipo_gmp_entries (id, org_id, ipo_id, gmp_paise, note, corrects_entry_id,
		source, actor_kind, actor_id, idempotency_key, request_hash, recorded_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
		g.id, g.org, g.ipo, g.gmp, g.note, g.corrects, g.source, g.actorKind, g.actorID, g.idemKey, g.reqHash, g.recordedAt)
	return g.id, err
}

func (e *mEnv) mustGMP(ipo uuid.UUID, mod func(*gmpRaw)) uuid.UUID {
	e.t.Helper()
	id, err := e.rawGMP(ipo, mod)
	if err != nil {
		e.t.Fatalf("insert gmp entry: %v", err)
	}
	return id
}

type subRaw struct {
	org, ipo   uuid.UUID
	id         uuid.UUID
	asOf       time.Time
	total      *int32
	cats       [6]*int32 // qib, nii, bnii, snii, retail, employee
	source     string
	actorKind  string
	actorID    *uuid.UUID
	idemKey    *string
	reqHash    *string
	recordedAt time.Time
}

func (e *mEnv) rawSub(ipo uuid.UUID, mod func(*subRaw)) (uuid.UUID, error) {
	e.t.Helper()
	admin := uuid.New()
	s := subRaw{org: e.org, ipo: ipo, id: uuid.New(), asOf: e.now, total: p32(1234), source: "manual", actorKind: "admin", actorID: &admin, recordedAt: e.now}
	if mod != nil {
		mod(&s)
	}
	_, err := e.pool.Exec(e.t.Context(), `INSERT INTO ipo_subscription_snapshots (id, org_id, ipo_id, as_of, total_x100,
		qib_x100, nii_x100, bnii_x100, snii_x100, retail_x100, employee_x100,
		source, actor_kind, actor_id, idempotency_key, request_hash, recorded_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)`,
		s.id, s.org, s.ipo, s.asOf, s.total, s.cats[0], s.cats[1], s.cats[2], s.cats[3], s.cats[4], s.cats[5],
		s.source, s.actorKind, s.actorID, s.idemKey, s.reqHash, s.recordedAt)
	return s.id, err
}

func (e *mEnv) mustSub(ipo uuid.UUID, mod func(*subRaw)) uuid.UUID {
	e.t.Helper()
	id, err := e.rawSub(ipo, mod)
	if err != nil {
		e.t.Fatalf("insert subscription: %v", err)
	}
	return id
}

// wantPG fails unless err is a PostgreSQL error with the given SQLSTATE (23514 check, 23505 unique,
// 23503 foreign key, 23502 not null, P0001 raised by a trigger).
func wantPG(t *testing.T, err error, code string) {
	t.Helper()
	var pe *pgconn.PgError
	if !errors.As(err, &pe) {
		t.Fatalf("want PostgreSQL error %s, got %T %v", code, err, err)
	}
	if pe.Code != code {
		t.Fatalf("SQLSTATE = %s (%s), want %s", pe.Code, pe.Message, code)
	}
}

const hash64 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
