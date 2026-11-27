package ipomarket

import (
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

// S02: schema tests for migration 00006 (data-model.md sections 1 and 2). They fail until the
// tables exist (S03). BR-IPO-04: GMP history is append-only with author and time.

func TestSchema_BR_IPO_04_AppendOnly(t *testing.T) {
	e := newMEnv(t)
	ipo := e.publishedIPO()
	gid := e.mustGMP(ipo, nil)
	sid := e.mustSub(ipo, nil)
	ctx := t.Context()

	cases := []struct {
		name, sql string
		id        uuid.UUID
	}{
		{"gmp update", `UPDATE ipo_gmp_entries SET gmp_paise = 1 WHERE id = $1`, gid},
		{"gmp delete", `DELETE FROM ipo_gmp_entries WHERE id = $1`, gid},
		{"subscription update", `UPDATE ipo_subscription_snapshots SET total_x100 = 1 WHERE id = $1`, sid},
		{"subscription delete", `DELETE FROM ipo_subscription_snapshots WHERE id = $1`, sid},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := e.pool.Exec(ctx, c.sql, c.id)
			if err == nil {
				t.Fatal("mutation succeeded; the table must be append-only")
			}
			if !strings.Contains(err.Error(), "append-only") {
				t.Errorf("error = %v, want the forbid_mutation 'append-only' error", err)
			}
		})
	}
	var n int
	_ = e.pool.QueryRow(ctx, `SELECT count(*) FROM ipo_gmp_entries WHERE gmp_paise = 3000`).Scan(&n)
	if n != 1 {
		t.Errorf("entry changed or vanished (count %d)", n)
	}
}

func TestSchema_BR_IPO_04_GMPBounds(t *testing.T) {
	e := newMEnv(t)
	ipo := e.publishedIPO()
	for _, v := range []int64{-1_000_000_000, -1, 0, 1, 1_000_000_000} {
		if _, err := e.rawGMP(ipo, func(g *gmpRaw) { g.gmp = v }); err != nil {
			t.Errorf("gmp %d rejected: %v", v, err)
		}
	}
	for _, v := range []int64{-1_000_000_001, 1_000_000_001} {
		_, err := e.rawGMP(ipo, func(g *gmpRaw) { g.gmp = v })
		wantPG(t, err, "23514")
	}
}

func TestSchema_BR_IPO_04_NoteLength(t *testing.T) {
	e := newMEnv(t)
	ipo := e.publishedIPO()
	for _, n := range []*string{nil, pStr("x"), pStr(strings.Repeat("n", 200))} {
		if _, err := e.rawGMP(ipo, func(g *gmpRaw) { g.note = n }); err != nil {
			t.Errorf("note %v rejected: %v", n, err)
		}
	}
	for _, n := range []string{"", "   ", strings.Repeat("n", 201)} {
		_, err := e.rawGMP(ipo, func(g *gmpRaw) { g.note = &n })
		wantPG(t, err, "23514")
	}
}

func TestSchema_BR_IPO_04_CorrectionRules(t *testing.T) {
	e := newMEnv(t)
	ipo, other := e.publishedIPO(), e.publishedIPO()
	first := e.mustGMP(ipo, nil)

	t.Run("a correction in the same IPO is accepted", func(t *testing.T) {
		if _, err := e.rawGMP(ipo, func(g *gmpRaw) { g.corrects = &first }); err != nil {
			t.Fatalf("correction rejected: %v", err)
		}
	})
	t.Run("an entry can be corrected only once", func(t *testing.T) {
		_, err := e.rawGMP(ipo, func(g *gmpRaw) { g.corrects = &first })
		wantPG(t, err, "23505")
	})
	t.Run("a correction cannot point to another IPO", func(t *testing.T) {
		victim := e.mustGMP(ipo, nil)
		_, err := e.rawGMP(other, func(g *gmpRaw) { g.corrects = &victim })
		wantPG(t, err, "23503")
	})
	t.Run("a correction of an unknown entry fails", func(t *testing.T) {
		ghost := uuid.New()
		_, err := e.rawGMP(ipo, func(g *gmpRaw) { g.corrects = &ghost })
		wantPG(t, err, "23503")
	})
	t.Run("an entry cannot correct itself", func(t *testing.T) {
		id := uuid.New()
		_, err := e.rawGMP(ipo, func(g *gmpRaw) { g.id = id; g.corrects = &id })
		if err == nil {
			t.Fatal("self-correction accepted")
		}
	})
}

func TestSchema_BR_IPO_04_ActorAndIdempotencyPairs(t *testing.T) {
	e := newMEnv(t)
	ipo := e.publishedIPO()
	admin := uuid.New()
	badKind := "client"
	bad := []struct {
		name string
		mod  func(*gmpRaw)
	}{
		{"admin without id", func(g *gmpRaw) { g.actorKind, g.actorID = "admin", nil }},
		{"system with id", func(g *gmpRaw) { g.actorKind, g.actorID = "system", &admin }},
		{"client actor", func(g *gmpRaw) { g.actorKind, g.actorID = badKind, &admin }},
		{"key without hash", func(g *gmpRaw) { g.idemKey = pStr("idem-key-1") }},
		{"hash without key", func(g *gmpRaw) { g.reqHash = pStr(hash64) }},
		{"key too short", func(g *gmpRaw) { g.idemKey, g.reqHash = pStr("short"), pStr(hash64) }},
		{"key too long", func(g *gmpRaw) { g.idemKey, g.reqHash = pStr(strings.Repeat("k", 201)), pStr(hash64) }},
		{"hash not hex", func(g *gmpRaw) { g.idemKey, g.reqHash = pStr("idem-key-1"), pStr(strings.Repeat("Z", 64)) }},
		{"hash too short", func(g *gmpRaw) { g.idemKey, g.reqHash = pStr("idem-key-1"), pStr("abcd") }},
	}
	for _, c := range bad {
		t.Run(c.name, func(t *testing.T) {
			_, err := e.rawGMP(ipo, c.mod)
			wantPG(t, err, "23514")
		})
	}
	t.Run("system actor without id and a full key pair are accepted", func(t *testing.T) {
		e.mustGMP(ipo, func(g *gmpRaw) { g.actorKind, g.actorID = "system", nil })
		e.mustGMP(ipo, func(g *gmpRaw) { g.idemKey, g.reqHash = pStr("idem-key-ok"), pStr(hash64) })
	})
}

func TestSchema_BR_IPO_04_IdempotencyKeyUniquePerIPO(t *testing.T) {
	e := newMEnv(t)
	a, b := e.publishedIPO(), e.publishedIPO()
	key := func(g *gmpRaw) { g.idemKey, g.reqHash = pStr("same-key-1"), pStr(hash64) }
	e.mustGMP(a, key)
	_, err := e.rawGMP(a, key)
	wantPG(t, err, "23505")
	if _, err := e.rawGMP(b, key); err != nil {
		t.Errorf("same key on another IPO rejected: %v", err)
	}
	// Rows without a key never collide.
	e.mustGMP(a, nil)
	e.mustGMP(a, nil)

	skey := func(s *subRaw) { s.idemKey, s.reqHash = pStr("same-key-1"), pStr(hash64) }
	e.mustSub(a, skey)
	_, err = e.rawSub(a, skey)
	wantPG(t, err, "23505")
	if _, err := e.rawSub(b, skey); err != nil {
		t.Errorf("same subscription key on another IPO rejected: %v", err)
	}
	// The GMP and subscription key spaces are separate (scoped per action).
	e.mustSub(b, func(s *subRaw) { s.idemKey, s.reqHash = pStr("gmp-and-sub"), pStr(hash64) })
	e.mustGMP(b, func(g *gmpRaw) { g.idemKey, g.reqHash = pStr("gmp-and-sub"), pStr(hash64) })
}

func TestSchema_BR_IPO_04_SourcePattern(t *testing.T) {
	e := newMEnv(t)
	ipo := e.publishedIPO()
	for _, s := range []string{"manual", "import:nse_feed", "import:a", "import:" + strings.Repeat("a", 32)} {
		if _, err := e.rawGMP(ipo, func(g *gmpRaw) { g.source = s }); err != nil {
			t.Errorf("source %q rejected: %v", s, err)
		}
		if _, err := e.rawSub(ipo, func(r *subRaw) { r.source = s }); err != nil {
			t.Errorf("subscription source %q rejected: %v", s, err)
		}
	}
	for _, s := range []string{"", "Manual", "import:", "import:Bad", "import:" + strings.Repeat("a", 33), "scrape:x"} {
		_, err := e.rawGMP(ipo, func(g *gmpRaw) { g.source = s })
		wantPG(t, err, "23514")
		_, err = e.rawSub(ipo, func(r *subRaw) { r.source = s })
		wantPG(t, err, "23514")
	}
}

func TestSchema_BR_IPO_04_SubscriptionBounds(t *testing.T) {
	e := newMEnv(t)
	ipo := e.publishedIPO()
	for _, v := range []int32{0, 1, 1234, 10_000_000} {
		if _, err := e.rawSub(ipo, func(s *subRaw) { s.total = p32(v) }); err != nil {
			t.Errorf("total %d rejected: %v", v, err)
		}
	}
	for _, v := range []int32{-1, 10_000_001} {
		_, err := e.rawSub(ipo, func(s *subRaw) { s.total = p32(v) })
		wantPG(t, err, "23514")
	}
	_, err := e.rawSub(ipo, func(s *subRaw) { s.total = nil })
	wantPG(t, err, "23502")

	names := []string{"qib", "nii", "bnii", "snii", "retail", "employee"}
	for i, n := range names {
		t.Run(n, func(t *testing.T) {
			if _, err := e.rawSub(ipo, func(s *subRaw) { s.cats[i] = p32(10_000_000) }); err != nil {
				t.Errorf("%s at max rejected: %v", n, err)
			}
			_, err := e.rawSub(ipo, func(s *subRaw) { s.cats[i] = p32(10_000_001) })
			wantPG(t, err, "23514")
			_, err = e.rawSub(ipo, func(s *subRaw) { s.cats[i] = p32(-1) })
			wantPG(t, err, "23514")
		})
	}
	// All optional categories may be absent.
	e.mustSub(ipo, func(s *subRaw) { s.asOf = e.now.Add(time.Hour) })
}

func TestSchema_BR_IPO_04_OrgAndIPOScoping(t *testing.T) {
	e := newMEnv(t)
	ipo := e.publishedIPO()
	_, err := e.rawGMP(ipo, func(g *gmpRaw) { g.org = uuid.New() })
	wantPG(t, err, "23503")
	_, err = e.rawGMP(uuid.New(), nil)
	wantPG(t, err, "23503")
	_, err = e.rawSub(ipo, func(s *subRaw) { s.org = uuid.New() })
	wantPG(t, err, "23503")
	_, err = e.rawSub(uuid.New(), nil)
	wantPG(t, err, "23503")
}

func TestSchema_BR_IPO_04_DraftDelete(t *testing.T) {
	e := newMEnv(t)
	t.Run("a never-published draft without rows can still be deleted", func(t *testing.T) {
		draft := e.newIPO(e.org, nil)
		if _, err := e.pool.Exec(t.Context(), `DELETE FROM ipos WHERE id = $1`, draft); err != nil {
			t.Fatalf("delete draft: %v", err)
		}
	})
	t.Run("an IPO that has market rows cannot be deleted (RESTRICT)", func(t *testing.T) {
		draft := e.newIPO(e.org, nil)
		e.mustGMP(draft, nil)
		_, err := e.pool.Exec(t.Context(), `DELETE FROM ipos WHERE id = $1`, draft)
		wantPG(t, err, "23503")
		draft2 := e.newIPO(e.org, nil)
		e.mustSub(draft2, nil)
		_, err = e.pool.Exec(t.Context(), `DELETE FROM ipos WHERE id = $1`, draft2)
		wantPG(t, err, "23503")
	})
}

func TestSchema_BR_IPO_04_Indexes(t *testing.T) {
	e := newMEnv(t)
	for _, c := range []struct{ table, index string }{
		{"ipo_gmp_entries", "ipo_gmp_entries_ipo_idx"},
		{"ipo_gmp_entries", "ipo_gmp_entries_idem_uq"},
		{"ipo_subscription_snapshots", "ipo_subscription_ipo_idx"},
		{"ipo_subscription_snapshots", "ipo_subscription_idem_uq"},
	} {
		var def string
		err := e.pool.QueryRow(t.Context(), `SELECT indexdef FROM pg_indexes WHERE tablename = $1 AND indexname = $2`, c.table, c.index).Scan(&def)
		if err != nil {
			t.Errorf("index %s on %s missing: %v", c.index, c.table, err)
			continue
		}
		if strings.HasSuffix(c.index, "_uq") && !strings.Contains(def, "UNIQUE") {
			t.Errorf("%s is not UNIQUE: %s", c.index, def)
		}
	}
}
