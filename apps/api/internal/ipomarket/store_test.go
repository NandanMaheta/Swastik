package ipomarket

import (
	"bytes"
	"context"
	"errors"
	"sort"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/NandanMaheta/swastik/apps/api/internal/platform/audit"
)

// S06: the data-model section 5 queries through the unexported store, inside a transaction carried
// by the context (db.TxRunner). Signatures under test are the compile stubs in store.go. Assumptions
// the contracts leave open:
//   - a missing row, or one of another org, gives ErrNotFound (single-row reads) or is absent
//     (maps) or empty (lists);
//   - history and trend lists carry every field of GMPEntry the store knows (author, note, source,
//     CorrectsEntryID, CorrectedByEntryID); ExpectedProfitPaise is the service's job and stays nil;
//   - listGMPHistory returns up to `limit` rows (the service asks for one more to detect a next
//     page); pageAfter{} is the first page; rows are strictly older than (At, ID) for GMP and
//     (At=as_of, RecordedAt, ID) for snapshots;
//   - listGMPTrend returns the newest 500 effective entries, ascending by (recorded_at, id);
//   - a duplicate (org, ipo, idempotency key) is a database error (the service looks up first).

func (e *mEnv) at(minutes int) time.Time { return e.now.Add(time.Duration(minutes) * time.Minute) }

func (e *mEnv) admin() audit.Actor { return audit.Actor{ID: uuid.New(), Kind: audit.KindAdmin} }

func (e *mEnv) putGMP(org, ipo uuid.UUID, in GMPInput, at time.Time) GMPEntry {
	e.t.Helper()
	if in.Source == "" {
		in.Source = "manual"
	}
	var out GMPEntry
	e.in(func(ctx context.Context) {
		got, err := e.store.insertGMP(ctx, org, ipo, newGMP{GMPInput: in, Actor: e.admin()}, at)
		if err != nil {
			e.t.Fatalf("insertGMP(%d): %v", in.GMPPaise, err)
		}
		out = got
	})
	return out
}

func (e *mEnv) putSub(org, ipo uuid.UUID, asOf time.Time, total int32, at time.Time) Snapshot {
	e.t.Helper()
	var out Snapshot
	e.in(func(ctx context.Context) {
		got, err := e.store.insertSnapshot(ctx, org, ipo, newSnapshot{
			SubscriptionInput: SubscriptionInput{AsOf: asOf, TotalX100: total, Source: "manual"}, Actor: e.admin()}, at)
		if err != nil {
			e.t.Fatalf("insertSnapshot: %v", err)
		}
		out = got
	})
	return out
}

func idLess(a, b uuid.UUID) bool { return bytes.Compare(a[:], b[:]) < 0 }

func gmpValues(es []GMPEntry) []int64 {
	out := make([]int64, 0, len(es))
	for _, x := range es {
		out = append(out, x.GMPPaise)
	}
	return out
}

func sameInts(got, want []int64) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

func TestQueries_BR_IPO_04_InsertGMPKeepsAuthorAndTime(t *testing.T) {
	e := newMEnv(t)
	ipo := e.publishedIPO()
	note := "broker A"
	author := audit.Actor{ID: uuid.New(), Kind: audit.KindAdmin}
	var got GMPEntry
	e.in(func(ctx context.Context) {
		var err error
		got, err = e.store.insertGMP(ctx, e.org, ipo, newGMP{GMPInput: GMPInput{GMPPaise: -1000, Note: &note, Source: "manual"}, Actor: author}, e.at(0))
		if err != nil {
			t.Fatalf("insertGMP: %v", err)
		}
	})
	if got.ID == uuid.Nil || got.IPOID != ipo || got.GMPPaise != -1000 || got.Source != "manual" {
		t.Errorf("entry = %+v", got)
	}
	if got.Note == nil || *got.Note != note {
		t.Errorf("note = %v, want %q", got.Note, note)
	}
	if got.Actor != author {
		t.Errorf("actor = %+v, want %+v", got.Actor, author)
	}
	if !got.RecordedAt.Equal(e.at(0)) {
		t.Errorf("recorded_at = %v, want the instant passed in (%v)", got.RecordedAt, e.at(0))
	}
	if got.CorrectsEntryID != nil || got.CorrectedByEntryID != nil {
		t.Errorf("fresh entry has correction links: %+v", got)
	}

	var sys GMPEntry
	e.in(func(ctx context.Context) {
		var err error
		sys, err = e.store.insertGMP(ctx, e.org, ipo, newGMP{GMPInput: GMPInput{GMPPaise: 5, Source: "import:nse_feed"}, Actor: audit.Actor{Kind: audit.KindSystem}}, e.at(1))
		if err != nil {
			t.Fatalf("insertGMP system: %v", err)
		}
	})
	if sys.Actor.Kind != audit.KindSystem || sys.Actor.ID != uuid.Nil || sys.Source != "import:nse_feed" {
		t.Errorf("system entry actor/source = %+v / %q", sys.Actor, sys.Source)
	}
}

func TestQueries_BR_IPO_04_CurrentGMP(t *testing.T) {
	e := newMEnv(t)
	ipo := e.publishedIPO()
	read := func(org, id uuid.UUID) (GMPEntry, error) {
		var out GMPEntry
		var err error
		e.in(func(ctx context.Context) { out, err = e.store.currentGMP(ctx, org, id) })
		return out, err
	}
	if _, err := read(e.org, ipo); !errors.Is(err, ErrNotFound) {
		t.Fatalf("no entries: err = %v, want ErrNotFound", err)
	}
	e.putGMP(e.org, ipo, GMPInput{GMPPaise: 3000}, e.at(0))
	newest := e.putGMP(e.org, ipo, GMPInput{GMPPaise: 2550}, e.at(60))
	e.putGMP(e.org, ipo, GMPInput{GMPPaise: 9999}, e.at(30)) // recorded later but stamped earlier: not the newest
	got, err := read(e.org, ipo)
	if err != nil || got.ID != newest.ID || got.GMPPaise != 2550 {
		t.Fatalf("current = %+v, %v; want the entry at +60 min (2550)", got, err)
	}
	if _, err := read(e.newOrg("Other"), ipo); !errors.Is(err, ErrNotFound) {
		t.Errorf("other org: err = %v, want ErrNotFound", err)
	}
	if _, err := read(e.org, e.publishedIPO()); !errors.Is(err, ErrNotFound) {
		t.Errorf("other IPO: err = %v, want ErrNotFound", err)
	}
}

func TestQueries_BR_IPO_04_CurrentGMPTieBreaksOnID(t *testing.T) {
	e := newMEnv(t)
	ipo := e.publishedIPO()
	a := e.putGMP(e.org, ipo, GMPInput{GMPPaise: 100}, e.at(0))
	b := e.putGMP(e.org, ipo, GMPInput{GMPPaise: 200}, e.at(0))
	want := a
	if idLess(a.ID, b.ID) {
		want = b
	}
	e.in(func(ctx context.Context) {
		got, err := e.store.currentGMP(ctx, e.org, ipo)
		if err != nil || got.ID != want.ID {
			t.Fatalf("current = %v, %v; want the greater id %s", got.ID, err, want.ID)
		}
	})
}

func TestQueries_BR_IPO_04_CorrectionsAreNotEffective(t *testing.T) {
	e := newMEnv(t)
	ipo := e.publishedIPO()
	a := e.putGMP(e.org, ipo, GMPInput{GMPPaise: 100}, e.at(0))
	b := e.putGMP(e.org, ipo, GMPInput{GMPPaise: 30_000}, e.at(10)) // typo for 3000
	e.in(func(ctx context.Context) {
		for _, c := range []struct {
			id   uuid.UUID
			want bool
		}{{a.ID, false}, {b.ID, false}} {
			got, err := e.store.isGMPCorrected(ctx, e.org, c.id)
			if err != nil || got != c.want {
				t.Fatalf("isGMPCorrected(%s) = %v, %v; want %v before any correction", c.id, got, err, c.want)
			}
		}
	})
	c := e.putGMP(e.org, ipo, GMPInput{GMPPaise: 3000, CorrectsEntryID: &b.ID}, e.at(20))
	if c.CorrectsEntryID == nil || *c.CorrectsEntryID != b.ID {
		t.Fatalf("correction entry = %+v", c)
	}
	e.in(func(ctx context.Context) {
		for _, x := range []struct {
			id   uuid.UUID
			want bool
		}{{a.ID, false}, {b.ID, true}, {c.ID, false}} {
			got, err := e.store.isGMPCorrected(ctx, e.org, x.id)
			if err != nil || got != x.want {
				t.Errorf("isGMPCorrected(%s) = %v, %v; want %v", x.id, got, err, x.want)
			}
		}
		cur, err := e.store.currentGMP(ctx, e.org, ipo)
		if err != nil || cur.ID != c.ID || cur.GMPPaise != 3000 {
			t.Errorf("current = %+v, %v; want the correction (3000)", cur, err)
		}
		trend, err := e.store.listGMPTrend(ctx, e.org, ipo)
		if err != nil || !sameInts(gmpValues(trend), []int64{100, 3000}) {
			t.Errorf("trend = %v, %v; want [100 3000] (corrected entry hidden)", gmpValues(trend), err)
		}
	})
	// Correcting the correction moves "current" again.
	d := e.putGMP(e.org, ipo, GMPInput{GMPPaise: 3100, CorrectsEntryID: &c.ID}, e.at(30))
	e.in(func(ctx context.Context) {
		cur, err := e.store.currentGMP(ctx, e.org, ipo)
		if err != nil || cur.ID != d.ID {
			t.Errorf("current = %+v, %v; want %s", cur, err, d.ID)
		}
	})
	// A second correction of the same entry is refused by the database.
	err := e.tx.InTx(t.Context(), func(ctx context.Context) error {
		_, err := e.store.insertGMP(ctx, e.org, ipo, newGMP{GMPInput: GMPInput{GMPPaise: 1, CorrectsEntryID: &b.ID, Source: "manual"}, Actor: e.admin()}, e.at(40))
		return err
	})
	if err == nil {
		t.Error("second correction of the same entry succeeded")
	}
}

func TestQueries_BR_IPO_04_GMPIdempotencyLookup(t *testing.T) {
	e := newMEnv(t)
	ipo, other := e.publishedIPO(), e.publishedIPO()
	key, hash := "idem-key-1", hash64
	var stored GMPEntry
	e.in(func(ctx context.Context) {
		var err error
		stored, err = e.store.insertGMP(ctx, e.org, ipo, newGMP{GMPInput: GMPInput{GMPPaise: 3000, Source: "manual"}, Actor: e.admin(), IdemKey: &key, RequestHash: &hash}, e.at(0))
		if err != nil {
			t.Fatalf("insertGMP: %v", err)
		}
	})
	e.in(func(ctx context.Context) {
		got, h, err := e.store.findGMPByIdemKey(ctx, e.org, ipo, key)
		if err != nil || got.ID != stored.ID || h != hash || got.GMPPaise != 3000 {
			t.Fatalf("find = %+v, %q, %v; want the stored entry and hash", got, h, err)
		}
		for name, c := range map[string]struct {
			org, ipo uuid.UUID
			key      string
		}{
			"unknown key": {e.org, ipo, "idem-key-2"}, "other IPO": {e.org, other, key}, "other org": {e.newOrg("Other"), ipo, key},
		} {
			if _, _, err := e.store.findGMPByIdemKey(ctx, c.org, c.ipo, c.key); !errors.Is(err, ErrNotFound) {
				t.Errorf("%s: err = %v, want ErrNotFound", name, err)
			}
		}
	})
	err := e.tx.InTx(t.Context(), func(ctx context.Context) error {
		_, err := e.store.insertGMP(ctx, e.org, ipo, newGMP{GMPInput: GMPInput{GMPPaise: 1, Source: "manual"}, Actor: e.admin(), IdemKey: &key, RequestHash: &hash}, e.at(1))
		return err
	})
	if err == nil {
		t.Error("a second insert with the same key succeeded")
	}
}

func TestQueries_BR_IPO_04_ListGMPHistoryKeyset(t *testing.T) {
	e := newMEnv(t)
	ipo := e.publishedIPO()
	var es []GMPEntry
	for i := 1; i <= 5; i++ {
		es = append(es, e.putGMP(e.org, ipo, GMPInput{GMPPaise: int64(i * 100)}, e.at(i)))
	}
	// A correction of #5: history keeps both, #5 is marked corrected.
	fix := e.putGMP(e.org, ipo, GMPInput{GMPPaise: 550, CorrectsEntryID: &es[4].ID}, e.at(6))

	page := func(after pageAfter, limit int) []GMPEntry {
		var out []GMPEntry
		e.in(func(ctx context.Context) {
			var err error
			out, err = e.store.listGMPHistory(ctx, e.org, ipo, after, limit)
			if err != nil {
				t.Fatalf("listGMPHistory: %v", err)
			}
		})
		return out
	}
	p1 := page(pageAfter{}, 2)
	if !sameInts(gmpValues(p1), []int64{550, 500}) {
		t.Fatalf("page 1 = %v, want [550 500] (newest first, corrected entries included)", gmpValues(p1))
	}
	if p1[1].CorrectedByEntryID == nil || *p1[1].CorrectedByEntryID != fix.ID {
		t.Errorf("entry 500 CorrectedByEntryID = %v, want %s", p1[1].CorrectedByEntryID, fix.ID)
	}
	if p1[0].CorrectsEntryID == nil || *p1[0].CorrectsEntryID != es[4].ID || p1[0].CorrectedByEntryID != nil {
		t.Errorf("correction entry links = %+v", p1[0])
	}
	if p1[0].Actor.Kind != audit.KindAdmin || p1[0].Actor.ID == uuid.Nil {
		t.Errorf("history rows must carry the author: %+v", p1[0].Actor)
	}
	p2 := page(pageAfter{At: p1[1].RecordedAt, ID: p1[1].ID}, 2)
	p3 := page(pageAfter{At: p2[1].RecordedAt, ID: p2[1].ID}, 2)
	p4 := page(pageAfter{At: p3[len(p3)-1].RecordedAt, ID: p3[len(p3)-1].ID}, 2)
	if !sameInts(gmpValues(p2), []int64{400, 300}) || !sameInts(gmpValues(p3), []int64{200, 100}) || len(p4) != 0 {
		t.Errorf("pages = %v %v %v", gmpValues(p2), gmpValues(p3), gmpValues(p4))
	}
	if all := page(pageAfter{}, 100); len(all) != 6 {
		t.Errorf("limit 100 returned %d rows, want 6", len(all))
	}
}

func TestQueries_BR_IPO_04_ListGMPHistoryTiesPageByID(t *testing.T) {
	e := newMEnv(t)
	ipo := e.publishedIPO()
	a := e.putGMP(e.org, ipo, GMPInput{GMPPaise: 1}, e.at(0))
	b := e.putGMP(e.org, ipo, GMPInput{GMPPaise: 2}, e.at(0))
	c := e.putGMP(e.org, ipo, GMPInput{GMPPaise: 3}, e.at(0))
	ids := []uuid.UUID{a.ID, b.ID, c.ID}
	sort.Slice(ids, func(i, j int) bool { return idLess(ids[j], ids[i]) }) // id descending
	var got []uuid.UUID
	after := pageAfter{}
	for range 3 {
		e.in(func(ctx context.Context) {
			rows, err := e.store.listGMPHistory(ctx, e.org, ipo, after, 1)
			if err != nil || len(rows) != 1 {
				t.Fatalf("page after %+v = %d rows, %v", after, len(rows), err)
			}
			got = append(got, rows[0].ID)
			after = pageAfter{At: rows[0].RecordedAt, ID: rows[0].ID}
		})
	}
	for i := range ids {
		if got[i] != ids[i] {
			t.Fatalf("order = %v, want %v (ties by id descending, no row skipped or repeated)", got, ids)
		}
	}
}

func TestQueries_BR_IPO_04_ListGMPTrend(t *testing.T) {
	e := newMEnv(t)
	ipo := e.publishedIPO()
	e.in(func(ctx context.Context) {
		got, err := e.store.listGMPTrend(ctx, e.org, ipo)
		if err != nil || len(got) != 0 {
			t.Fatalf("empty trend = %v, %v", got, err)
		}
	})
	e.putGMP(e.org, ipo, GMPInput{GMPPaise: 300}, e.at(3))
	e.putGMP(e.org, ipo, GMPInput{GMPPaise: 100}, e.at(1))
	e.putGMP(e.org, ipo, GMPInput{GMPPaise: 200}, e.at(2))
	e.in(func(ctx context.Context) {
		got, err := e.store.listGMPTrend(ctx, e.org, ipo)
		if err != nil || !sameInts(gmpValues(got), []int64{100, 200, 300}) {
			t.Fatalf("trend = %v, %v; want ascending [100 200 300]", gmpValues(got), err)
		}
		if g, err := e.store.listGMPTrend(ctx, e.newOrg("Other"), ipo); err != nil || len(g) != 0 {
			t.Errorf("other org trend = %v, %v; want empty", g, err)
		}
	})
}

func TestQueries_BR_IPO_04_TrendCappedAtNewest500(t *testing.T) {
	e := newMEnv(t)
	ipo := e.publishedIPO()
	admin := uuid.New()
	// 505 effective entries, gmp_paise = 1..505 one minute apart.
	if _, err := e.pool.Exec(t.Context(), `INSERT INTO ipo_gmp_entries (id, org_id, ipo_id, gmp_paise, source, actor_kind, actor_id, recorded_at)
		SELECT gen_random_uuid(), $1, $2, g, 'manual', 'admin', $3, $4::timestamptz + g * interval '1 minute'
		FROM generate_series(1, 505) g`, e.org, ipo, admin, e.now); err != nil {
		t.Fatalf("seed: %v", err)
	}
	e.in(func(ctx context.Context) {
		got, err := e.store.listGMPTrend(ctx, e.org, ipo)
		if err != nil || len(got) != 500 {
			t.Fatalf("trend len = %d, %v; want 500", len(got), err)
		}
		if got[0].GMPPaise != 6 || got[499].GMPPaise != 505 {
			t.Errorf("trend spans %d..%d, want the newest 500 (6..505) ascending", got[0].GMPPaise, got[499].GMPPaise)
		}
	})
}

func TestQueries_BR_IPO_04_CurrentGMPBatch(t *testing.T) {
	e := newMEnv(t)
	a, b, none := e.publishedIPO(), e.publishedIPO(), e.publishedIPO()
	otherOrg := e.newOrg("Other")
	foreign := e.newIPO(otherOrg, func(r *ipoRaw) { r.published = true })

	e.putGMP(e.org, a, GMPInput{GMPPaise: 100}, e.at(0))
	aNew := e.putGMP(e.org, a, GMPInput{GMPPaise: 150}, e.at(5))
	b1 := e.putGMP(e.org, b, GMPInput{GMPPaise: 900}, e.at(1))
	b2 := e.putGMP(e.org, b, GMPInput{GMPPaise: 90_000}, e.at(2)) // typo
	b3 := e.putGMP(e.org, b, GMPInput{GMPPaise: 9000, CorrectsEntryID: &b2.ID}, e.at(3))
	_ = b1
	e.putGMP(otherOrg, foreign, GMPInput{GMPPaise: 7}, e.at(0))

	e.in(func(ctx context.Context) {
		got, err := e.store.currentGMPBatch(ctx, e.org, []uuid.UUID{a, b, none, foreign, uuid.New()})
		if err != nil {
			t.Fatalf("currentGMPBatch: %v", err)
		}
		if len(got) != 2 || got[a].ID != aNew.ID || got[b].ID != b3.ID || got[b].GMPPaise != 9000 {
			t.Errorf("batch = %+v; want a -> %s (150), b -> %s (9000) and nothing for none/foreign/unknown", got, aNew.ID, b3.ID)
		}
		if g, err := e.store.currentGMPBatch(ctx, e.org, nil); err != nil || len(g) != 0 {
			t.Errorf("empty ids = %v, %v", g, err)
		}
		if g, err := e.store.currentGMPBatch(ctx, otherOrg, []uuid.UUID{a, b}); err != nil || len(g) != 0 {
			t.Errorf("other org sees %v, %v; want nothing", g, err)
		}
	})
}

func TestQueries_BR_IPO_04_GMPHistoryOrgIsolation(t *testing.T) {
	e := newMEnv(t)
	ipo := e.publishedIPO()
	e.putGMP(e.org, ipo, GMPInput{GMPPaise: 100}, e.at(0))
	other := e.newOrg("Other")
	e.in(func(ctx context.Context) {
		if rows, err := e.store.listGMPHistory(ctx, other, ipo, pageAfter{}, 10); err != nil || len(rows) != 0 {
			t.Errorf("other org history = %v, %v; want empty", rows, err)
		}
		if rows, err := e.store.listSnapshotHistory(ctx, other, ipo, pageAfter{}, 10); err != nil || len(rows) != 0 {
			t.Errorf("other org snapshots = %v, %v; want empty", rows, err)
		}
		if _, err := e.store.currentSnapshot(ctx, other, ipo); !errors.Is(err, ErrNotFound) {
			t.Errorf("other org current snapshot: %v, want ErrNotFound", err)
		}
	})
}

// ---- subscription snapshots ----

func TestQueries_BR_IPO_04_InsertSnapshotRoundTrip(t *testing.T) {
	e := newMEnv(t)
	ipo := e.publishedIPO()
	in := SubscriptionInput{AsOf: e.at(-60), TotalX100: 1234, QIBX100: p32(2010), NIIX100: p32(1500), RetailX100: p32(625), Source: "manual"}
	author := e.admin()
	var got Snapshot
	e.in(func(ctx context.Context) {
		var err error
		got, err = e.store.insertSnapshot(ctx, e.org, ipo, newSnapshot{SubscriptionInput: in, Actor: author}, e.at(0))
		if err != nil {
			t.Fatalf("insertSnapshot: %v", err)
		}
	})
	if got.ID == uuid.Nil || got.IPOID != ipo || got.TotalX100 != 1234 || !got.AsOf.Equal(in.AsOf) || !got.RecordedAt.Equal(e.at(0)) || got.Actor != author {
		t.Errorf("snapshot = %+v", got)
	}
	eq := func(a, b *int32) bool { return (a == nil) == (b == nil) && (a == nil || *a == *b) }
	if !eq(got.QIBX100, in.QIBX100) || !eq(got.NIIX100, in.NIIX100) || !eq(got.RetailX100, in.RetailX100) ||
		got.BNIIX100 != nil || got.SNIIX100 != nil || got.EmployeeX100 != nil {
		t.Errorf("categories = %+v, want qib/nii/retail only", got)
	}
	e.in(func(ctx context.Context) {
		cur, err := e.store.currentSnapshot(ctx, e.org, ipo)
		if err != nil || cur.ID != got.ID {
			t.Errorf("currentSnapshot = %+v, %v", cur, err)
		}
	})
}

func TestQueries_BR_IPO_04_CurrentSnapshotOrdering(t *testing.T) {
	e := newMEnv(t)
	ipo := e.publishedIPO()
	read := func() Snapshot {
		var out Snapshot
		e.in(func(ctx context.Context) {
			var err error
			out, err = e.store.currentSnapshot(ctx, e.org, ipo)
			if err != nil {
				t.Fatalf("currentSnapshot: %v", err)
			}
		})
		return out
	}
	e.in(func(ctx context.Context) {
		if _, err := e.store.currentSnapshot(ctx, e.org, ipo); !errors.Is(err, ErrNotFound) {
			t.Fatalf("no snapshots: err = %v, want ErrNotFound", err)
		}
	})
	s1 := e.putSub(e.org, ipo, e.at(0), 100, e.at(0))
	if got := read(); got.ID != s1.ID {
		t.Fatalf("current = %d, want the only snapshot", got.TotalX100)
	}
	// Recorded later but with an older as-of: the later as-of stays current (FR-009).
	e.putSub(e.org, ipo, e.at(-30), 999, e.at(10))
	if got := read(); got.ID != s1.ID {
		t.Fatalf("an older as-of recorded later won: total %d", got.TotalX100)
	}
	// Same as-of, recorded later: the newer recording wins (US4.3).
	s3 := e.putSub(e.org, ipo, e.at(0), 300, e.at(20))
	if got := read(); got.ID != s3.ID {
		t.Fatalf("same as-of, later recording: total %d, want 300", got.TotalX100)
	}
	// Same as-of and same recording instant: greater id wins.
	s4 := e.putSub(e.org, ipo, e.at(0), 400, e.at(20))
	want := s3
	if idLess(s3.ID, s4.ID) {
		want = s4
	}
	if got := read(); got.ID != want.ID {
		t.Fatalf("full tie: got %s, want the greater id %s", got.ID, want.ID)
	}
	// A later as-of beats everything.
	s5 := e.putSub(e.org, ipo, e.at(5), 500, e.at(1))
	if got := read(); got.ID != s5.ID {
		t.Fatalf("later as-of: total %d, want 500", got.TotalX100)
	}
}

func TestQueries_BR_IPO_04_CurrentSnapshotBatch(t *testing.T) {
	e := newMEnv(t)
	a, b, none := e.publishedIPO(), e.publishedIPO(), e.publishedIPO()
	other := e.newOrg("Other")
	foreign := e.newIPO(other, func(r *ipoRaw) { r.published = true })
	e.putSub(e.org, a, e.at(0), 100, e.at(0))
	aNew := e.putSub(e.org, a, e.at(10), 200, e.at(1))
	bNew := e.putSub(e.org, b, e.at(10), 50, e.at(2))
	e.putSub(e.org, b, e.at(0), 60, e.at(3))
	e.putSub(other, foreign, e.at(0), 1, e.at(0))
	e.in(func(ctx context.Context) {
		got, err := e.store.currentSnapshotBatch(ctx, e.org, []uuid.UUID{a, b, none, foreign, uuid.New()})
		if err != nil || len(got) != 2 || got[a].ID != aNew.ID || got[b].ID != bNew.ID {
			t.Fatalf("batch = %+v, %v; want a -> 200, b -> 50 only", got, err)
		}
		if g, err := e.store.currentSnapshotBatch(ctx, other, []uuid.UUID{a, b}); err != nil || len(g) != 0 {
			t.Errorf("other org sees %v, %v", g, err)
		}
	})
}

func TestQueries_BR_IPO_04_ListSnapshotHistoryKeyset(t *testing.T) {
	e := newMEnv(t)
	ipo := e.publishedIPO()
	e.putSub(e.org, ipo, e.at(0), 1, e.at(0))
	e.putSub(e.org, ipo, e.at(30), 2, e.at(1))
	e.putSub(e.org, ipo, e.at(30), 3, e.at(2)) // same as-of, recorded later: newer first
	e.putSub(e.org, ipo, e.at(60), 4, e.at(3))
	totals := func(ss []Snapshot) []int64 {
		var out []int64
		for _, s := range ss {
			out = append(out, int64(s.TotalX100))
		}
		return out
	}
	list := func(after pageAfter, limit int) []Snapshot {
		var out []Snapshot
		e.in(func(ctx context.Context) {
			var err error
			out, err = e.store.listSnapshotHistory(ctx, e.org, ipo, after, limit)
			if err != nil {
				t.Fatalf("listSnapshotHistory: %v", err)
			}
		})
		return out
	}
	p1 := list(pageAfter{}, 2)
	if !sameInts(totals(p1), []int64{4, 3}) {
		t.Fatalf("page 1 = %v, want [4 3] (by as-of, then recording, newest first)", totals(p1))
	}
	p2 := list(pageAfter{At: p1[1].AsOf, RecordedAt: p1[1].RecordedAt, ID: p1[1].ID}, 2)
	if !sameInts(totals(p2), []int64{2, 1}) {
		t.Fatalf("page 2 = %v, want [2 1]", totals(p2))
	}
	if p3 := list(pageAfter{At: p2[1].AsOf, RecordedAt: p2[1].RecordedAt, ID: p2[1].ID}, 2); len(p3) != 0 {
		t.Errorf("page 3 = %v, want empty", totals(p3))
	}
	if p1[0].Actor.Kind != audit.KindAdmin {
		t.Errorf("history rows must carry the author: %+v", p1[0].Actor)
	}
}

func TestQueries_BR_IPO_04_SnapshotIdempotencyLookup(t *testing.T) {
	e := newMEnv(t)
	ipo, other := e.publishedIPO(), e.publishedIPO()
	key, hash := "idem-sub-1", hash64
	var stored Snapshot
	e.in(func(ctx context.Context) {
		var err error
		stored, err = e.store.insertSnapshot(ctx, e.org, ipo, newSnapshot{
			SubscriptionInput: SubscriptionInput{AsOf: e.at(0), TotalX100: 1234, Source: "manual"}, Actor: e.admin(), IdemKey: &key, RequestHash: &hash}, e.at(0))
		if err != nil {
			t.Fatalf("insertSnapshot: %v", err)
		}
	})
	e.in(func(ctx context.Context) {
		got, h, err := e.store.findSnapshotByIdemKey(ctx, e.org, ipo, key)
		if err != nil || got.ID != stored.ID || h != hash {
			t.Fatalf("find = %+v, %q, %v", got, h, err)
		}
		if _, _, err := e.store.findSnapshotByIdemKey(ctx, e.org, other, key); !errors.Is(err, ErrNotFound) {
			t.Errorf("other IPO: %v, want ErrNotFound", err)
		}
		if _, _, err := e.store.findSnapshotByIdemKey(ctx, e.newOrg("Other"), ipo, key); !errors.Is(err, ErrNotFound) {
			t.Errorf("other org: %v, want ErrNotFound", err)
		}
		if _, _, err := e.store.findSnapshotByIdemKey(ctx, e.org, ipo, "nope-nope-1"); !errors.Is(err, ErrNotFound) {
			t.Errorf("unknown key: %v, want ErrNotFound", err)
		}
	})
}

// D-06: writes to one IPO serialise on a per-IPO advisory lock taken by lockIPO.
func TestQueries_BR_IPO_04_LockIPOSerialisesPerIPO(t *testing.T) {
	e := newMEnv(t)
	ipo, other := e.publishedIPO(), e.publishedIPO()
	holding, release := make(chan struct{}), make(chan struct{})
	holderDone := make(chan error, 1)
	go func() {
		holderDone <- e.tx.InTx(t.Context(), func(ctx context.Context) error {
			if err := e.store.lockIPO(ctx, ipo); err != nil {
				return err
			}
			close(holding)
			<-release
			return nil
		})
	}()
	select {
	case <-holding:
	case err := <-holderDone:
		t.Fatalf("lockIPO: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("holder never got the lock")
	}
	acquired := make(chan error, 1)
	go func() {
		acquired <- e.tx.InTx(t.Context(), func(ctx context.Context) error { return e.store.lockIPO(ctx, ipo) })
	}()
	otherDone := make(chan error, 1)
	go func() {
		otherDone <- e.tx.InTx(t.Context(), func(ctx context.Context) error { return e.store.lockIPO(ctx, other) })
	}()
	if err := <-otherDone; err != nil {
		t.Fatalf("lock on another IPO: %v", err)
	}
	select {
	case err := <-acquired:
		t.Fatalf("second lock on the same IPO returned while the first was held (err %v)", err)
	case <-time.After(300 * time.Millisecond):
	}
	close(release)
	if err := <-holderDone; err != nil {
		t.Fatalf("holder: %v", err)
	}
	select {
	case err := <-acquired:
		if err != nil {
			t.Fatalf("second lock: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("second lock never acquired after release")
	}
}
