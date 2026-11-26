package ipomarket

import (
	"errors"
	"sync"
	"testing"

	"github.com/google/uuid"
)

// S10: corrections (US3, FR-004, FR-005, D-06). A correction is a new entry that points at the
// current effective entry of the same IPO; an entry is corrected at most once; the corrected entry
// stays in admin history and leaves the client trend.

func (e *svcEnv) correct(ipo, target uuid.UUID, v int64) (GMPResult, error) {
	return e.svc.RecordGMP(e.ctx(), e.adm, e.org, ipo, GMPInput{GMPPaise: v, CorrectsEntryID: &target, Source: "manual"}, "")
}

func TestRecordGMP_FR005_CorrectionOfCurrentEntry(t *testing.T) {
	e := newSvcEnv(t)
	ipo := e.publishedIPO()
	e.gmp(ipo, 3000)
	e.setNow(e.at(1))
	b := e.gmp(ipo, 3500)
	e.setNow(e.at(2))
	c, err := e.correct(ipo, b.Entry.ID, 3400)
	if err != nil {
		t.Fatalf("correct current: %v", err)
	}
	if c.Entry.CorrectsEntryID == nil || *c.Entry.CorrectsEntryID != b.Entry.ID || c.Current.GMPPaise != 3400 {
		t.Errorf("correction = %+v current %+v", c.Entry, c.Current)
	}
	g, ok, err := e.svc.CurrentGMP(e.ctx(), e.org, ipo)
	if err != nil || !ok || g.EntryID != c.Entry.ID || g.GMPPaise != 3400 {
		t.Errorf("CurrentGMP = %+v %v %v, want the correction", g, ok, err)
	}
	if e.gmpRows(ipo) != 3 {
		t.Errorf("rows = %d, want 3 (corrections append)", e.gmpRows(ipo))
	}
	// once only: B is already corrected
	if _, err := e.correct(ipo, b.Entry.ID, 3300); !errors.Is(err, ErrCorrectionNotLatest) {
		t.Errorf("second correction of the same entry: %v, want ErrCorrectionNotLatest (US3.2)", err)
	}
	// the correction itself is now current and may be corrected
	if _, err := e.correct(ipo, c.Entry.ID, 3450); err != nil {
		t.Errorf("correcting the new current entry: %v, want success", err)
	}
	if e.gmpRows(ipo) != 4 {
		t.Errorf("rows = %d, want 4", e.gmpRows(ipo))
	}
}

func TestRecordGMP_FR005_CorrectionRejections(t *testing.T) {
	e := newSvcEnv(t)
	ipo, other := e.publishedIPO(), e.publishedIPO()
	a := e.gmp(ipo, 3000)
	e.setNow(e.at(1))
	e.gmp(ipo, 3500)
	foreign := e.gmp(other, 100)
	before := e.gmpRows(ipo)

	for name, target := range map[string]uuid.UUID{
		"older, not current":   a.Entry.ID,
		"unknown id":           uuid.New(),
		"entry of another IPO": foreign.Entry.ID,
	} {
		if _, err := e.correct(ipo, target, 1); !errors.Is(err, ErrCorrectionNotLatest) {
			t.Errorf("%s: err = %v, want ErrCorrectionNotLatest", name, err)
		}
	}
	if e.gmpRows(ipo) != before || e.gmpRows(other) != 1 {
		t.Errorf("rejected corrections wrote rows: %d (want %d), other %d", e.gmpRows(ipo), before, e.gmpRows(other))
	}
	e.wantAudits(ipo, 2)
}

func TestRecordGMP_FR005_CorrectionAuditAndFrozen(t *testing.T) {
	e := newSvcEnv(t)
	ipo := e.publishedIPO()
	a := e.gmp(ipo, 3000)
	c, err := e.correct(ipo, a.Entry.ID, 3100)
	if err != nil {
		t.Fatal(err)
	}
	au := e.audits(ipo)
	if len(au) != 2 || au[1].Action != "ipo.gmp_recorded" || au[1].After["corrects_entry_id"] != a.Entry.ID.String() || au[1].After["entry_id"] != c.Entry.ID.String() {
		t.Errorf("audit = %+v, want a second ipo.gmp_recorded carrying corrects_entry_id", au)
	}
	e.setStatus(ipo, "LISTED")
	if _, err := e.correct(ipo, c.Entry.ID, 1); !errors.Is(err, ErrFrozen) {
		t.Errorf("correction on a LISTED IPO: %v, want ErrFrozen", err)
	}
}

func TestRecordGMP_FR005_CorrectionIsIdempotent(t *testing.T) {
	e := newSvcEnv(t)
	ipo := e.publishedIPO()
	a := e.gmp(ipo, 3000)
	in := GMPInput{GMPPaise: 3100, CorrectsEntryID: &a.Entry.ID, Source: "manual"}
	first, err := e.svc.RecordGMP(e.ctx(), e.adm, e.org, ipo, in, "corr-key-0001")
	if err != nil {
		t.Fatal(err)
	}
	// the target is no longer current, yet the same request with the same key replays
	again, err := e.svc.RecordGMP(e.ctx(), e.adm, e.org, ipo, in, "corr-key-0001")
	if err != nil || !again.Replayed || again.Entry.ID != first.Entry.ID {
		t.Errorf("replay = %+v err=%v, want the original correction", again.Entry.ID, err)
	}
	if e.gmpRows(ipo) != 2 {
		t.Errorf("rows = %d, want 2", e.gmpRows(ipo))
	}
}

func TestRecordGMP_FR005_CorrectedEntryHiddenFromClients(t *testing.T) {
	e := newSvcEnv(t)
	ipo := e.publishedIPO()
	e.gmp(ipo, 3000)
	e.setNow(e.at(1))
	b := e.gmp(ipo, 3500)
	e.setNow(e.at(2))
	if _, err := e.correct(ipo, b.Entry.ID, 3400); err != nil {
		t.Fatal(err)
	}
	v, err := e.svc.MarketView(e.ctx(), e.org, ipo, true)
	if err != nil {
		t.Fatalf("MarketView: %v", err)
	}
	if got := trendValues(v.Trend); !sameInts(got, []int64{3000, 3400}) {
		t.Errorf("client trend = %v, want [3000 3400] (corrected 3500 hidden, US3.3)", got)
	}
	page, err := e.svc.ListGMP(e.ctx(), e.org, ipo, "", 50)
	if err != nil {
		t.Fatalf("ListGMP: %v", err)
	}
	if got := gmpValues(page.Items); !sameInts(got, []int64{3400, 3500, 3000}) {
		t.Errorf("admin history = %v, want all three newest first", got)
	}
	for _, it := range page.Items {
		if it.GMPPaise == 3500 && (it.CorrectedByEntryID == nil) {
			t.Errorf("the corrected entry must show who corrected it")
		}
	}
}

func trendValues(ps []TrendPoint) []int64 {
	out := make([]int64, 0, len(ps))
	for _, p := range ps {
		out = append(out, p.GMPPaise)
	}
	return out
}

func TestCorrection_Concurrent_TwoCorrectionsOneWins(t *testing.T) {
	e := newSvcEnv(t)
	for round := range 5 {
		ipo := e.publishedIPO()
		a := e.gmp(ipo, 3000)
		var wg sync.WaitGroup
		errs := make([]error, 2)
		for i := range 2 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, errs[i] = e.correct(ipo, a.Entry.ID, int64(4000+i))
			}()
		}
		wg.Wait()
		wins := 0
		for _, err := range errs {
			switch {
			case err == nil:
				wins++
			case !errors.Is(err, ErrCorrectionNotLatest):
				t.Fatalf("round %d: loser got %v, want ErrCorrectionNotLatest (not a raw database error)", round, err)
			}
		}
		if wins != 1 || e.gmpRows(ipo) != 2 {
			t.Fatalf("round %d: winners=%d rows=%d, want one winner and 2 rows", round, wins, e.gmpRows(ipo))
		}
	}
}

func TestCorrection_Concurrent_CorrectionVersusNewEntry(t *testing.T) {
	e := newSvcEnv(t)
	for round := range 5 {
		ipo := e.publishedIPO()
		a := e.gmp(ipo, 3000)
		e.setNow(e.at(round + 1))
		var wg sync.WaitGroup
		var corrErr, newErr error
		wg.Add(2)
		go func() { defer wg.Done(); _, corrErr = e.correct(ipo, a.Entry.ID, 3100) }()
		go func() {
			defer wg.Done()
			_, newErr = e.svc.RecordGMP(e.ctx(), e.adm, e.org, ipo, GMPInput{GMPPaise: 3200, Source: "manual"}, "")
		}()
		wg.Wait()
		if newErr != nil {
			t.Fatalf("round %d: plain entry: %v", round, newErr)
		}
		if corrErr != nil && !errors.Is(corrErr, ErrCorrectionNotLatest) {
			t.Fatalf("round %d: correction: %v, want success or ErrCorrectionNotLatest", round, corrErr)
		}
		want := 3
		if corrErr != nil {
			want = 2 // the plain entry went first and made A non-current
		}
		if e.gmpRows(ipo) != want {
			t.Fatalf("round %d: rows = %d, want %d (corr err %v)", round, e.gmpRows(ipo), want, corrErr)
		}
	}
}
