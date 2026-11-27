package ipomarket

import (
	"errors"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
)

// S08: RecordGMP (US1, FR-001, FR-003, FR-006, FR-007, FR-010, FR-011; BR-IPO-04). Published IPOs
// from the fixture have lot size 50 and issue price 100,000 paise (Rs 1,000).

func TestRecordGMP_BR_IPO_04_AuthorAndTime(t *testing.T) {
	e := newSvcEnv(t)
	ipo := e.publishedIPO()
	r, err := e.svc.RecordGMP(e.ctx(), e.adm, e.org, ipo, GMPInput{GMPPaise: 3000, Source: "manual"}, "")
	if err != nil {
		t.Fatalf("RecordGMP: %v", err)
	}
	en := r.Entry
	if en.ID == uuid.Nil || en.IPOID != ipo || en.GMPPaise != 3000 || en.Source != "manual" {
		t.Errorf("entry = %+v", en)
	}
	if en.Actor != e.adm {
		t.Errorf("author = %+v, want %+v (US1.1)", en.Actor, e.adm)
	}
	if !en.RecordedAt.Equal(e.now) {
		t.Errorf("recorded at %v, want the server clock %v", en.RecordedAt, e.now)
	}
	if en.ExpectedProfitPaise == nil || *en.ExpectedProfitPaise != 150_000 {
		t.Errorf("expected profit = %v, want 3000 x 50 = 150000 (US1.1)", en.ExpectedProfitPaise)
	}
	c := r.Current
	if c.GMPPaise != 3000 || c.LotSize == nil || *c.LotSize != 50 || !c.UpdatedAt.Equal(e.now) ||
		c.ExpectedProfitPaise == nil || *c.ExpectedProfitPaise != 150_000 {
		t.Errorf("current = %+v", c)
	}
	if r.Replayed || len(r.Warnings) != 0 {
		t.Errorf("replayed=%v warnings=%v, want a fresh record without warnings", r.Replayed, r.Warnings)
	}
	if e.gmpRows(ipo) != 1 {
		t.Errorf("rows = %d, want 1", e.gmpRows(ipo))
	}
}

func TestRecordGMP_BR_IPO_04_RepeatValueIsANewEntry(t *testing.T) {
	e := newSvcEnv(t)
	ipo := e.publishedIPO()
	a := e.gmp(ipo, 3000)
	e.setNow(e.at(5))
	b := e.gmp(ipo, 3000)
	if a.Entry.ID == b.Entry.ID || e.gmpRows(ipo) != 2 {
		t.Fatalf("a repeated value must be a new entry (US1.2): ids %v %v rows %d", a.Entry.ID, b.Entry.ID, e.gmpRows(ipo))
	}
	if !b.Current.UpdatedAt.Equal(e.at(5)) {
		t.Errorf("updated at = %v, want the time of the newer entry %v", b.Current.UpdatedAt, e.at(5))
	}
}

func TestRecordGMP_BR_IPO_04_NegativeAndZero(t *testing.T) {
	e := newSvcEnv(t)
	ipo := e.publishedIPO()
	for _, c := range []struct{ gmp, profit int64 }{{-2500, -125_000}, {0, 0}, {-1_000_000_000, -50_000_000_000}, {1_000_000_000, 50_000_000_000}} {
		r, err := e.svc.RecordGMP(e.ctx(), e.adm, e.org, ipo, GMPInput{GMPPaise: c.gmp, Source: "manual"}, "")
		if err != nil {
			t.Fatalf("gmp %d: %v (Q1: negative and zero are allowed)", c.gmp, err)
		}
		if r.Entry.ExpectedProfitPaise == nil || *r.Entry.ExpectedProfitPaise != c.profit {
			t.Errorf("gmp %d: expected profit = %v, want %d", c.gmp, r.Entry.ExpectedProfitPaise, c.profit)
		}
	}
}

func TestRecordGMP_BR_IPO_04_UnknownLotSizeGivesNullProfit(t *testing.T) {
	e := newSvcEnv(t)
	ipo := e.onceUnpublished(true)
	r, err := e.svc.RecordGMP(e.ctx(), e.adm, e.org, ipo, GMPInput{GMPPaise: 3000, Source: "manual"}, "")
	if err != nil {
		t.Fatalf("RecordGMP: %v (an IPO published once accepts entries, US1.4)", err)
	}
	if r.Entry.ExpectedProfitPaise != nil || r.Current.ExpectedProfitPaise != nil || r.Current.LotSize != nil {
		t.Errorf("profit/lot = %v/%v/%v, want all null without a lot size", r.Entry.ExpectedProfitPaise, r.Current.ExpectedProfitPaise, r.Current.LotSize)
	}
	if r.Current.GMPPaise != 3000 {
		t.Errorf("current gmp = %d", r.Current.GMPPaise)
	}
}

func TestRecordGMP_BR_IPO_04_PublishedAtLeastOnce(t *testing.T) {
	e := newSvcEnv(t)
	draft := e.newIPO(e.org, nil)
	if _, err := e.svc.RecordGMP(e.ctx(), e.adm, e.org, draft, GMPInput{GMPPaise: 1, Source: "manual"}, ""); !errors.Is(err, ErrNotPublishedYet) {
		t.Errorf("never published: err = %v, want ErrNotPublishedYet (Q3, US1.8)", err)
	}
	e.wantNoWrites(draft)

	// Published once, now unpublished: allowed (FR-001 "published at least once").
	again := e.onceUnpublished(false)
	if _, err := e.svc.RecordGMP(e.ctx(), e.adm, e.org, again, GMPInput{GMPPaise: 1, Source: "manual"}, ""); err != nil {
		t.Errorf("published once then unpublished: %v, want success", err)
	}
}

func TestRecordGMP_FR006_FrozenAndUnknown(t *testing.T) {
	e := newSvcEnv(t)
	for _, st := range []string{"LISTED", "SETTLED"} {
		ipo := e.publishedIPO()
		e.setStatus(ipo, st)
		if _, err := e.svc.RecordGMP(e.ctx(), e.adm, e.org, ipo, GMPInput{GMPPaise: 1, Source: "manual"}, ""); !errors.Is(err, ErrFrozen) {
			t.Errorf("%s: err = %v, want ErrFrozen (US1.7)", st, err)
		}
		e.wantNoWrites(ipo)
	}
	for _, st := range []string{"UPCOMING", "OPEN", "CLOSED", "ALLOTMENT_OUT"} {
		ipo := e.publishedIPO()
		e.setStatus(ipo, st)
		if _, err := e.svc.RecordGMP(e.ctx(), e.adm, e.org, ipo, GMPInput{GMPPaise: 1, Source: "manual"}, ""); err != nil {
			t.Errorf("%s: %v, want success", st, err)
		}
	}
	if _, err := e.svc.RecordGMP(e.ctx(), e.adm, e.org, uuid.New(), GMPInput{GMPPaise: 1, Source: "manual"}, ""); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown IPO: err = %v, want ErrNotFound", err)
	}
	other := e.newOrg("Other")
	foreign := e.newIPO(other, func(r *ipoRaw) { r.published = true })
	if _, err := e.svc.RecordGMP(e.ctx(), e.adm, e.org, foreign, GMPInput{GMPPaise: 1, Source: "manual"}, ""); !errors.Is(err, ErrNotFound) {
		t.Errorf("another org's IPO: err = %v, want ErrNotFound", err)
	}
	e.wantNoWrites(foreign)
}

func TestRecordGMP_FR001_InvalidInputWritesNothing(t *testing.T) {
	e := newSvcEnv(t)
	ipo := e.publishedIPO()
	blank, long := "   ", strings.Repeat("x", 201)
	for name, in := range map[string]GMPInput{
		"too large":    {GMPPaise: 1_000_000_001, Source: "manual"},
		"too small":    {GMPPaise: -1_000_000_001, Source: "manual"},
		"blank note":   {GMPPaise: 1, Note: &blank, Source: "manual"},
		"long note":    {GMPPaise: 1, Note: &long, Source: "manual"},
		"bad source":   {GMPPaise: 1, Source: "Import:X"},
		"empty source": {GMPPaise: 1},
	} {
		_, err := e.svc.RecordGMP(e.ctx(), e.adm, e.org, ipo, in, "")
		var ve *ValidationError
		if !errors.As(err, &ve) || ve.Code != "ipomarket.invalid_value" {
			t.Errorf("%s: err = %v, want *ValidationError ipomarket.invalid_value", name, err)
		}
	}
	e.wantNoWrites(ipo)
}

func TestRecordGMP_FR001_NoteIsTrimmed(t *testing.T) {
	e := newSvcEnv(t)
	ipo := e.publishedIPO()
	n := "  from broker  "
	r, err := e.svc.RecordGMP(e.ctx(), e.adm, e.org, ipo, GMPInput{GMPPaise: 10, Note: &n, Source: "manual"}, "")
	if err != nil || r.Entry.Note == nil || *r.Entry.Note != "from broker" {
		t.Fatalf("note = %v err = %v, want trimmed", r.Entry.Note, err)
	}
}

func TestRecordGMP_FR007_TypoGuardWarnsButStores(t *testing.T) {
	e := newSvcEnv(t)
	ipo := e.publishedIPO() // issue price 100000
	r, err := e.svc.RecordGMP(e.ctx(), e.adm, e.org, ipo, GMPInput{GMPPaise: -150_000, Source: "manual"}, "")
	if err != nil {
		t.Fatalf("RecordGMP: %v", err)
	}
	if len(r.Warnings) != 1 || r.Warnings[0].Code != "ipomarket.gmp_exceeds_price" ||
		r.Warnings[0].Params["gmp_paise"] != -150_000 || r.Warnings[0].Params["price_paise"] != 100_000 {
		t.Errorf("warnings = %+v, want one ipomarket.gmp_exceeds_price (gmp -150000, price 100000)", r.Warnings)
	}
	if e.gmpRows(ipo) != 1 {
		t.Errorf("a warned entry must still be stored; rows = %d", e.gmpRows(ipo))
	}
	ok, err := e.svc.RecordGMP(e.ctx(), e.adm, e.org, ipo, GMPInput{GMPPaise: 100_000, Source: "manual"}, "")
	if err != nil || len(ok.Warnings) != 0 {
		t.Errorf("gmp equal to the price: warnings = %v err = %v, want none", ok.Warnings, err)
	}
}

var sha256Hex = regexp.MustCompile(`^[0-9a-f]{64}$`)

func TestRecordGMP_FR010_IdempotentReplayAndReuse(t *testing.T) {
	e := newSvcEnv(t)
	ipo := e.publishedIPO()
	key := "gmp-key-0001"
	in := GMPInput{GMPPaise: 3000, Source: "manual"}
	first, err := e.svc.RecordGMP(e.ctx(), e.adm, e.org, ipo, in, key)
	if err != nil || first.Replayed {
		t.Fatalf("first: err=%v replayed=%v", err, first.Replayed)
	}
	var k, h *string
	if err := e.pool.QueryRow(e.ctx(), `SELECT idempotency_key, request_hash FROM ipo_gmp_entries WHERE id = $1`, first.Entry.ID).Scan(&k, &h); err != nil {
		t.Fatal(err)
	}
	if k == nil || *k != key || h == nil || !sha256Hex.MatchString(*h) {
		t.Errorf("stored key/hash = %v/%v, want the key and a SHA-256 hex (D-07)", k, h)
	}

	// A newer entry arrives; the replay still returns the original entry and the current state.
	e.setNow(e.at(10))
	newer := e.gmp(ipo, 999)
	again, err := e.svc.RecordGMP(e.ctx(), e.adm, e.org, ipo, in, key)
	if err != nil || !again.Replayed {
		t.Fatalf("replay: err=%v replayed=%v", err, again.Replayed)
	}
	if again.Entry.ID != first.Entry.ID || again.Current.GMPPaise != newer.Entry.GMPPaise {
		t.Errorf("replay entry %v current %d, want original %v and current 999", again.Entry.ID, again.Current.GMPPaise, first.Entry.ID)
	}
	if e.gmpRows(ipo) != 2 {
		t.Errorf("rows = %d, want 2 (original + newer, no replay row)", e.gmpRows(ipo))
	}

	// Same key, different request: 422 ipomarket.idempotency_key_reused.
	note := "x"
	for name, other := range map[string]GMPInput{
		"other value": {GMPPaise: 3001, Source: "manual"},
		"other note":  {GMPPaise: 3000, Note: &note, Source: "manual"},
	} {
		if _, err := e.svc.RecordGMP(e.ctx(), e.adm, e.org, ipo, other, key); !errors.Is(err, ErrKeyReused) {
			t.Errorf("%s: err = %v, want ErrKeyReused", name, err)
		}
	}
	if e.gmpRows(ipo) != 2 {
		t.Errorf("rows after reuse = %d, want 2", e.gmpRows(ipo))
	}
	e.wantAudits(ipo, 2)
}

func TestRecordGMP_FR010_KeyScope(t *testing.T) {
	e := newSvcEnv(t)
	a, b := e.publishedIPO(), e.publishedIPO()
	key := "shared-key-1"
	in := GMPInput{GMPPaise: 100, Source: "manual"}
	if r, err := e.svc.RecordGMP(e.ctx(), e.adm, e.org, a, in, key); err != nil || r.Replayed {
		t.Fatalf("a: %v %v", r.Replayed, err)
	}
	if r, err := e.svc.RecordGMP(e.ctx(), e.adm, e.org, b, in, key); err != nil || r.Replayed {
		t.Errorf("same key on another IPO must be a new entry: replayed=%v err=%v", r.Replayed, err)
	}
	// Per action: the GMP key does not replay (or collide with) a subscription.
	s, err := e.svc.RecordSubscription(e.ctx(), e.adm, e.org, a, SubscriptionInput{AsOf: e.now, TotalX100: 100, Source: "manual"}, key)
	if err != nil || s.Replayed {
		t.Errorf("same key for another action: replayed=%v err=%v, want a new snapshot", s.Replayed, err)
	}
	// No key: every request is new, nothing stored.
	e.gmp(a, 100)
	e.gmp(a, 100)
	var n int
	if err := e.pool.QueryRow(e.ctx(), `SELECT count(*) FROM ipo_gmp_entries WHERE ipo_id = $1 AND idempotency_key IS NULL AND request_hash IS NULL`, a).Scan(&n); err != nil || n != 2 {
		t.Errorf("keyless rows = %d err=%v, want 2 with null key and hash", n, err)
	}
}

func TestRecordGMP_FR010_ConcurrentSameKeyOneRow(t *testing.T) {
	e := newSvcEnv(t)
	ipo := e.publishedIPO()
	const n = 6
	res := make([]GMPResult, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res[i], errs[i] = e.svc.RecordGMP(e.ctx(), e.adm, e.org, ipo, GMPInput{GMPPaise: 4200, Source: "manual"}, "concurrent-key-1")
		}()
	}
	wg.Wait()
	fresh := 0
	for i := range n {
		if errs[i] != nil {
			t.Fatalf("call %d: %v", i, errs[i])
		}
		if !res[i].Replayed {
			fresh++
		}
		if res[i].Entry.ID != res[0].Entry.ID {
			t.Errorf("call %d returned entry %v, want the single entry %v", i, res[i].Entry.ID, res[0].Entry.ID)
		}
	}
	if fresh != 1 || e.gmpRows(ipo) != 1 {
		t.Errorf("fresh=%d rows=%d, want exactly one of each (D-06)", fresh, e.gmpRows(ipo))
	}
	e.wantAudits(ipo, 1)
}

func TestRecord_FR011_OneAuditPerWrite(t *testing.T) {
	e := newSvcEnv(t)
	ipo := e.publishedIPO()
	note := "n"
	r, err := e.svc.RecordGMP(e.ctx(), e.adm, e.org, ipo, GMPInput{GMPPaise: 3000, Note: &note, Source: "manual"}, "audit-key-001")
	if err != nil {
		t.Fatal(err)
	}
	a := e.audits(ipo)
	if len(a) != 1 || a[0].Action != "ipo.gmp_recorded" || a[0].ActorKind != "admin" || a[0].ActorID == nil || *a[0].ActorID != e.adm.ID {
		t.Fatalf("audit = %+v, want one ipo.gmp_recorded by the admin", a)
	}
	af := a[0].After
	if af["entry_id"] != r.Entry.ID.String() || af["gmp_paise"] != float64(3000) || af["source"] != "manual" ||
		af["note"] != "n" || af["idempotency_key"] != "audit-key-001" {
		t.Errorf("audit after = %v", af)
	}
	if h, _ := af["request_hash"].(string); !sha256Hex.MatchString(h) {
		t.Errorf("audit request_hash = %v", af["request_hash"])
	}

	// replay and rejections add none
	if _, err := e.svc.RecordGMP(e.ctx(), e.adm, e.org, ipo, GMPInput{GMPPaise: 3000, Note: &note, Source: "manual"}, "audit-key-001"); err != nil {
		t.Fatal(err)
	}
	_, _ = e.svc.RecordGMP(e.ctx(), e.adm, e.org, ipo, GMPInput{GMPPaise: 3001, Source: "manual"}, "audit-key-001")
	_, _ = e.svc.RecordGMP(e.ctx(), e.adm, e.org, ipo, GMPInput{GMPPaise: 2e9, Source: "manual"}, "")
	e.setStatus(ipo, "LISTED")
	_, _ = e.svc.RecordGMP(e.ctx(), e.adm, e.org, ipo, GMPInput{GMPPaise: 5, Source: "manual"}, "")
	e.wantAudits(ipo, 1)
}
