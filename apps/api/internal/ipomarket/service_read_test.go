package ipomarket

import (
	"errors"
	"reflect"
	"testing"

	"github.com/google/uuid"
)

// S14: reads (US2, US5, FR-004, FR-009, FR-012, FR-013, FR-014, FR-016). Entries are arranged with
// raw SQL (mustGMP, mustSub) so each read is tested alone.

func TestCurrentGMP_BR_IPO_04_NoneAndOK(t *testing.T) {
	e := newSvcEnv(t)
	ipo := e.publishedIPO()
	if _, ok, err := e.svc.CurrentGMP(e.ctx(), e.org, ipo); err != nil || ok {
		t.Fatalf("no entries: ok=%v err=%v, want ok=false and no error (US5)", ok, err)
	}
	e.mustGMP(ipo, func(g *gmpRaw) { g.gmp = 100; g.recordedAt = e.at(-20) })
	newest := e.mustGMP(ipo, func(g *gmpRaw) { g.gmp = -250; g.recordedAt = e.at(-10); g.source = "import:acme_feed" })
	g, ok, err := e.svc.CurrentGMP(e.ctx(), e.org, ipo)
	if err != nil || !ok {
		t.Fatalf("CurrentGMP: ok=%v err=%v", ok, err)
	}
	if g.EntryID != newest || g.GMPPaise != -250 || !g.RecordedAt.Equal(e.at(-10)) || g.Source != "import:acme_feed" {
		t.Errorf("current = %+v, want the newest entry", g)
	}
	// Other org sees nothing; publication is not checked (callers decide).
	other := e.newOrg("Other")
	if _, ok, err := e.svc.CurrentGMP(e.ctx(), other, ipo); err != nil || ok {
		t.Errorf("other org: ok=%v err=%v, want none", ok, err)
	}
	draft := e.newIPO(e.org, nil)
	e.mustGMP(draft, func(g *gmpRaw) { g.gmp = 5 })
	if _, ok, err := e.svc.CurrentGMP(e.ctx(), e.org, draft); err != nil || !ok {
		t.Errorf("never-published IPO with an entry: ok=%v err=%v, want ok (no publication check)", ok, err)
	}
}

func TestCurrentGMP_FR004_TiesAndCorrections(t *testing.T) {
	e := newSvcEnv(t)
	ipo := e.publishedIPO()
	a := uuid.MustParse("00000000-0000-7000-8000-000000000001")
	b := uuid.MustParse("00000000-0000-7000-8000-000000000002")
	e.mustGMP(ipo, func(g *gmpRaw) { g.id = b; g.gmp = 2; g.recordedAt = e.now })
	e.mustGMP(ipo, func(g *gmpRaw) { g.id = a; g.gmp = 1; g.recordedAt = e.now })
	g, _, err := e.svc.CurrentGMP(e.ctx(), e.org, ipo)
	if err != nil || g.EntryID != b {
		t.Fatalf("equal recorded_at: current = %v err=%v, want the greater id %v (FR-004)", g.EntryID, err, b)
	}
	// A correction of the current entry replaces it; the corrected one is not effective.
	c := e.mustGMP(ipo, func(g *gmpRaw) { g.gmp = 3; g.corrects = &b; g.recordedAt = e.at(1) })
	g, _, err = e.svc.CurrentGMP(e.ctx(), e.org, ipo)
	if err != nil || g.EntryID != c || g.GMPPaise != 3 {
		t.Errorf("after a correction: current = %+v err=%v, want %v", g, err, c)
	}
}

func TestMarketView_BR_IPO_04_CurrentTrendSubscription(t *testing.T) {
	e := newSvcEnv(t)
	ipo := e.publishedIPO() // lot 50
	e.mustGMP(ipo, func(g *gmpRaw) { g.gmp = 1000; g.recordedAt = e.at(-30) })
	e.mustGMP(ipo, func(g *gmpRaw) { g.gmp = 1500; g.recordedAt = e.at(-20) })
	e.mustGMP(ipo, func(g *gmpRaw) { g.gmp = -500; g.recordedAt = e.at(-10) })
	e.mustSub(ipo, func(s *subRaw) { s.asOf = e.at(-90); s.total = p32(100) })
	e.mustSub(ipo, func(s *subRaw) { s.asOf = e.at(-45); s.total = p32(250); s.cats[0] = p32(900) })

	v, err := e.svc.MarketView(e.ctx(), e.org, ipo, true)
	if err != nil {
		t.Fatalf("MarketView: %v", err)
	}
	if v.IPOID != ipo {
		t.Errorf("ipo id = %v", v.IPOID)
	}
	c := v.CurrentGMP
	if c == nil || c.GMPPaise != -500 || c.ExpectedProfitPaise == nil || *c.ExpectedProfitPaise != -25_000 ||
		c.LotSize == nil || *c.LotSize != 50 || !c.UpdatedAt.Equal(e.at(-10)) {
		t.Errorf("current = %+v, want -500, expected profit -25000 (50 x -500), lot 50, updated at the entry time (US2.1)", c)
	}
	var want []TrendPoint
	for i, g := range []int64{1000, 1500, -500} {
		p := g * 50
		want = append(want, TrendPoint{GMPPaise: g, ExpectedProfitPaise: &p, At: e.at(-30 + 10*i)})
	}
	if len(v.Trend) != 3 {
		t.Fatalf("trend = %+v, want 3 points oldest first", v.Trend)
	}
	for i, p := range v.Trend {
		if p.GMPPaise != want[i].GMPPaise || p.ExpectedProfitPaise == nil || *p.ExpectedProfitPaise != *want[i].ExpectedProfitPaise || !p.At.Equal(want[i].At) {
			t.Errorf("trend[%d] = %+v, want %+v", i, p, want[i])
		}
	}
	s := v.Subscription
	if s == nil || s.TotalX100 != 250 || s.QIBX100 == nil || *s.QIBX100 != 900 || !s.AsOf.Equal(e.at(-45)) {
		t.Errorf("subscription = %+v, want the snapshot with the latest as-of", s)
	}
}

func TestMarketView_US2_NoDataIsNull(t *testing.T) {
	e := newSvcEnv(t)
	ipo := e.publishedIPO()
	v, err := e.svc.MarketView(e.ctx(), e.org, ipo, true)
	if err != nil {
		t.Fatalf("MarketView: %v", err)
	}
	if v.CurrentGMP != nil || v.Subscription != nil || len(v.Trend) != 0 {
		t.Errorf("view = %+v, want no GMP, empty trend, no subscription (US2.2)", v)
	}
}

func TestMarketView_US2_UnpublishedIsNotFoundForClients(t *testing.T) {
	e := newSvcEnv(t)
	draft := e.newIPO(e.org, nil)
	pulled := e.onceUnpublished(false)
	e.mustGMP(pulled, nil)
	foreign := e.newIPO(e.newOrg("Other"), func(r *ipoRaw) { r.published = true })
	for name, id := range map[string]uuid.UUID{"draft": draft, "unpublished again": pulled, "unknown": uuid.New(), "other org": foreign} {
		if _, err := e.svc.MarketView(e.ctx(), e.org, id, true); !errors.Is(err, ErrNotFound) {
			t.Errorf("%s with publishedOnly: err = %v, want ErrNotFound (US2.3)", name, err)
		}
	}
	// Admin read: drafts and pulled IPOs are visible, unknown and other orgs' still not.
	for name, id := range map[string]uuid.UUID{"draft": draft, "unpublished again": pulled} {
		if _, err := e.svc.MarketView(e.ctx(), e.org, id, false); err != nil {
			t.Errorf("%s without publishedOnly: %v, want a view", name, err)
		}
	}
	for name, id := range map[string]uuid.UUID{"unknown": uuid.New(), "other org": foreign} {
		if _, err := e.svc.MarketView(e.ctx(), e.org, id, false); !errors.Is(err, ErrNotFound) {
			t.Errorf("%s without publishedOnly: err = %v, want ErrNotFound", name, err)
		}
	}
}

func TestMarketView_BR_IPO_04_LotSizeEditChangesViews(t *testing.T) {
	e := newSvcEnv(t)
	ipo := e.publishedIPO()
	e.mustGMP(ipo, func(g *gmpRaw) { g.gmp = 200; g.recordedAt = e.at(-5) })
	if _, err := e.pool.Exec(e.ctx(), `UPDATE ipos SET lot_size = 100 WHERE id = $1`, ipo); err != nil {
		t.Fatal(err)
	}
	v, err := e.svc.MarketView(e.ctx(), e.org, ipo, true)
	if err != nil {
		t.Fatal(err)
	}
	if v.CurrentGMP.ExpectedProfitPaise == nil || *v.CurrentGMP.ExpectedProfitPaise != 20_000 || *v.CurrentGMP.LotSize != 100 ||
		*v.Trend[0].ExpectedProfitPaise != 20_000 {
		t.Errorf("view = %+v %+v, want expected profit recomputed with the new lot size (FR-003)", v.CurrentGMP, v.Trend)
	}
	// Lot size cleared (only possible while unpublished): profit unknown, GMP still shown.
	gone := e.onceUnpublished(true)
	e.mustGMP(gone, func(g *gmpRaw) { g.gmp = 200 })
	v, err = e.svc.MarketView(e.ctx(), e.org, gone, false)
	if err != nil || v.CurrentGMP == nil || v.CurrentGMP.ExpectedProfitPaise != nil || v.CurrentGMP.LotSize != nil || v.Trend[0].ExpectedProfitPaise != nil {
		t.Errorf("view without lot = %+v %+v err=%v, want null profit and lot", v.CurrentGMP, v.Trend, err)
	}
}

func TestMarketView_US2_TrendIsEffectiveAscendingAndCapped(t *testing.T) {
	e := newSvcEnv(t)
	ipo := e.publishedIPO()
	var first uuid.UUID
	for i := range 505 {
		id := e.mustGMP(ipo, func(g *gmpRaw) { g.gmp = int64(i); g.recordedAt = e.at(i - 600) })
		if i == 0 {
			first = id
		}
	}
	// correct the newest: it leaves the trend, the correction joins at the end
	cur, _, err := e.svc.CurrentGMP(e.ctx(), e.org, ipo)
	if err != nil {
		t.Fatal(err)
	}
	e.mustGMP(ipo, func(g *gmpRaw) { g.gmp = 9999; g.corrects = &cur.EntryID; g.recordedAt = e.at(10) })
	_ = first
	v, err := e.svc.MarketView(e.ctx(), e.org, ipo, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(v.Trend) != 500 {
		t.Fatalf("trend has %d points, want the newest 500", len(v.Trend))
	}
	for i := 1; i < len(v.Trend); i++ {
		if v.Trend[i].At.Before(v.Trend[i-1].At) {
			t.Fatalf("trend not ascending at %d", i)
		}
	}
	last := v.Trend[len(v.Trend)-1]
	if last.GMPPaise != 9999 || v.Trend[len(v.Trend)-2].GMPPaise != 503 {
		t.Errorf("trend tail = %d, %d; want 503 then the correction 9999 (the corrected 504 is not effective)", v.Trend[len(v.Trend)-2].GMPPaise, last.GMPPaise)
	}
	if v.Trend[0].GMPPaise != 5 { // 505 effective entries (0..503 and 9999), the newest 500 start at 5
		t.Errorf("oldest trend point = %d, want 5", v.Trend[0].GMPPaise)
	}
}

func TestSummaries_US2_BatchPublishedOnlyAndOmissions(t *testing.T) {
	e := newSvcEnv(t)
	withData := e.publishedIPO()
	e.mustGMP(withData, func(g *gmpRaw) { g.gmp = 300; g.recordedAt = e.at(-3) })
	e.mustSub(withData, func(s *subRaw) { s.asOf = e.at(-7); s.total = p32(4321) })
	empty := e.publishedIPO()
	draft := e.newIPO(e.org, nil)
	e.mustGMP(draft, func(g *gmpRaw) { g.gmp = 1 })
	pulled := e.onceUnpublished(false)
	foreign := e.newIPO(e.newOrg("Other"), func(r *ipoRaw) { r.published = true })
	ids := []uuid.UUID{withData, empty, draft, pulled, foreign, uuid.New(), withData}

	got, err := e.svc.Summaries(e.ctx(), e.org, ids, true)
	if err != nil {
		t.Fatalf("Summaries: %v", err)
	}
	byID := map[uuid.UUID]Summary{}
	for _, s := range got {
		if _, dup := byID[s.IPOID]; dup {
			t.Errorf("duplicate summary for %v (ids are de-duplicated)", s.IPOID)
		}
		byID[s.IPOID] = s
	}
	if len(got) != 2 || len(byID) != 2 {
		t.Fatalf("got %d summaries %v, want the 2 published IPOs only (US2.4)", len(got), got)
	}
	s := byID[withData]
	if s.CurrentGMP == nil || s.CurrentGMP.GMPPaise != 300 || *s.CurrentGMP.ExpectedProfitPaise != 15_000 || !s.CurrentGMP.UpdatedAt.Equal(e.at(-3)) ||
		s.SubscriptionTotalX100 == nil || *s.SubscriptionTotalX100 != 4321 || s.SubscriptionAsOf == nil || !s.SubscriptionAsOf.Equal(e.at(-7)) {
		t.Errorf("summary = %+v", s)
	}
	if n := byID[empty]; n.CurrentGMP != nil || n.SubscriptionTotalX100 != nil || n.SubscriptionAsOf != nil {
		t.Errorf("summary without data = %+v, want nulls", n)
	}

	// Admin: drafts and pulled IPOs included; unknown and foreign ids still absent.
	all, err := e.svc.Summaries(e.ctx(), e.org, ids, false)
	if err != nil {
		t.Fatal(err)
	}
	set := map[uuid.UUID]bool{}
	for _, s := range all {
		set[s.IPOID] = true
	}
	if len(all) != 4 || !set[withData] || !set[empty] || !set[draft] || !set[pulled] {
		t.Errorf("admin summaries = %d %v, want the 4 own IPOs including drafts", len(all), set)
	}
}

func TestSummaries_US2_UpTo200IDs(t *testing.T) {
	e := newSvcEnv(t)
	real := e.publishedIPO()
	ids := []uuid.UUID{real}
	for len(ids) < 200 {
		ids = append(ids, uuid.New())
	}
	got, err := e.svc.Summaries(e.ctx(), e.org, ids, true)
	if err != nil || len(got) != 1 || got[0].IPOID != real {
		t.Fatalf("200 ids: %v %v, want the one real IPO", got, err)
	}
	if got, err := e.svc.Summaries(e.ctx(), e.org, nil, true); err != nil || len(got) != 0 {
		t.Errorf("no ids: %v %v, want empty", got, err)
	}
}

func TestListGMP_FR012_PagesNewestFirstWithAdminFields(t *testing.T) {
	e := newSvcEnv(t)
	ipo := e.publishedIPO()
	var ids []uuid.UUID
	for i := range 5 {
		ids = append(ids, e.mustGMP(ipo, func(g *gmpRaw) {
			g.gmp = int64(i + 1)
			g.recordedAt = e.at(i)
			if i == 4 {
				g.corrects = &ids[3]
				g.note = pStr("fixed typo")
			}
		}))
	}
	var all []GMPEntry
	cursor := ""
	for page := 0; page < 5; page++ {
		p, err := e.svc.ListGMP(e.ctx(), e.org, ipo, cursor, 2)
		if err != nil {
			t.Fatalf("page %d: %v", page, err)
		}
		all = append(all, p.Items...)
		if p.NextCursor == "" {
			if page != 2 || len(p.Items) != 1 {
				t.Errorf("last page = %d items on page %d, want 1 item on page 2", len(p.Items), page)
			}
			break
		}
		if len(p.Items) != 2 {
			t.Fatalf("page %d has %d items, want 2", page, len(p.Items))
		}
		cursor = p.NextCursor
	}
	if !sameInts(gmpValues(all), []int64{5, 4, 3, 2, 1}) {
		t.Fatalf("history = %v, want newest first with no gaps or repeats", gmpValues(all))
	}
	top, corrected := all[0], all[1]
	if top.ID != ids[4] || top.Note == nil || *top.Note != "fixed typo" || top.CorrectsEntryID == nil || *top.CorrectsEntryID != ids[3] ||
		top.Actor.Kind != "admin" || top.Source != "manual" || top.ExpectedProfitPaise == nil || *top.ExpectedProfitPaise != 250 {
		t.Errorf("newest = %+v", top)
	}
	if corrected.CorrectedByEntryID == nil || *corrected.CorrectedByEntryID != ids[4] {
		t.Errorf("corrected entry shows corrected-by %v, want %v", corrected.CorrectedByEntryID, ids[4])
	}
	if p, err := e.svc.ListGMP(e.ctx(), e.org, e.newIPO(e.org, nil), "", 50); err != nil || len(p.Items) != 0 || p.NextCursor != "" {
		t.Errorf("IPO without entries: %+v %v, want an empty page", p, err)
	}
}

func TestListSubscriptions_FR012_PagesLatestAsOfFirst(t *testing.T) {
	e := newSvcEnv(t)
	ipo := e.publishedIPO()
	for i, asOf := range []int{-50, -10, -30, -20} {
		e.mustSub(ipo, func(s *subRaw) { s.asOf = e.at(asOf); s.total = p32(int32(i + 1)); s.recordedAt = e.at(i) })
	}
	p, err := e.svc.ListSubscriptions(e.ctx(), e.org, ipo, "", 3)
	if err != nil || len(p.Items) != 3 || p.NextCursor == "" {
		t.Fatalf("page 1: %d items cursor %q err %v", len(p.Items), p.NextCursor, err)
	}
	p2, err := e.svc.ListSubscriptions(e.ctx(), e.org, ipo, p.NextCursor, 3)
	if err != nil || len(p2.Items) != 1 || p2.NextCursor != "" {
		t.Fatalf("page 2: %d items cursor %q err %v", len(p2.Items), p2.NextCursor, err)
	}
	var got []int32
	for _, s := range append(p.Items, p2.Items...) {
		got = append(got, s.TotalX100)
	}
	if !reflect.DeepEqual(got, []int32{2, 4, 3, 1}) {
		t.Errorf("order by as-of desc = %v, want [2 4 3 1]", got)
	}
	if p.Items[0].Actor.Kind != "admin" || p.Items[0].Source != "manual" {
		t.Errorf("admin history must carry author and source: %+v", p.Items[0])
	}
}

// FR-014: the client-facing types carry no author, note, source, correction or idempotency data.
func TestSummaries_FR014_ClientTypesCarryNoAdminFields(t *testing.T) {
	banned := []string{"Note", "Actor", "Source", "CorrectsEntryID", "CorrectedByEntryID", "IdempotencyKey", "RequestHash", "ID", "EntryID"}
	for _, typ := range []reflect.Type{reflect.TypeFor[CurrentView](), reflect.TypeFor[TrendPoint](), reflect.TypeFor[Summary](), reflect.TypeFor[View]()} {
		for _, f := range banned {
			if _, ok := typ.FieldByName(f); ok {
				t.Errorf("%s has field %s, which clients must not see", typ.Name(), f)
			}
		}
	}
}
