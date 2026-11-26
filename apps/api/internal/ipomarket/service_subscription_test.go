package ipomarket

import (
	"errors"
	"sync"
	"testing"
	"time"
)

// S12: RecordSubscription (US4, FR-008, FR-009, FR-010, FR-011). Published fixture IPOs open on
// 2026-11-11, so as-of must not precede 2026-11-10T18:30:00Z (00:00 IST), nor exceed now + 5 min.
// The fixture clock is 2026-11-14T04:30:00Z.

var openMidnightIST = time.Date(2026, 11, 10, 18, 30, 0, 0, time.UTC)

func TestRecordSubscription_BR_IPO_04_StoresSnapshot(t *testing.T) {
	e := newSvcEnv(t)
	ipo := e.publishedIPO()
	in := SubscriptionInput{
		AsOf: e.at(-60), TotalX100: 1234, QIBX100: p32(5000), NIIX100: p32(0), RetailX100: p32(10_000_000), Source: "manual",
	}
	r, err := e.svc.RecordSubscription(e.ctx(), e.adm, e.org, ipo, in, "")
	if err != nil {
		t.Fatalf("RecordSubscription: %v", err)
	}
	s := r.Snapshot
	if s.IPOID != ipo || !s.AsOf.Equal(e.at(-60)) || s.TotalX100 != 1234 || s.Actor != e.adm || !s.RecordedAt.Equal(e.now) || s.Source != "manual" {
		t.Errorf("snapshot = %+v", s)
	}
	if s.QIBX100 == nil || *s.QIBX100 != 5000 || s.NIIX100 == nil || *s.NIIX100 != 0 || s.RetailX100 == nil || *s.RetailX100 != 10_000_000 {
		t.Errorf("categories = %v %v %v", s.QIBX100, s.NIIX100, s.RetailX100)
	}
	if s.BNIIX100 != nil || s.SNIIX100 != nil || s.EmployeeX100 != nil {
		t.Errorf("unset categories must stay null: %v %v %v", s.BNIIX100, s.SNIIX100, s.EmployeeX100)
	}
	if r.Current.ID != s.ID || r.Replayed {
		t.Errorf("current = %v replayed = %v, want this snapshot, fresh", r.Current.ID, r.Replayed)
	}
}

func TestRecordSubscription_FR008_AllCategories(t *testing.T) {
	e := newSvcEnv(t)
	ipo := e.publishedIPO()
	in := SubscriptionInput{AsOf: e.now, TotalX100: 1, QIBX100: p32(2), NIIX100: p32(3), BNIIX100: p32(4), SNIIX100: p32(5), RetailX100: p32(6), EmployeeX100: p32(7), Source: "manual"}
	r, err := e.svc.RecordSubscription(e.ctx(), e.adm, e.org, ipo, in, "")
	if err != nil {
		t.Fatal(err)
	}
	s := r.Snapshot
	got := []*int32{s.QIBX100, s.NIIX100, s.BNIIX100, s.SNIIX100, s.RetailX100, s.EmployeeX100}
	for i, g := range got {
		if g == nil || *g != int32(i+2) {
			t.Errorf("category %d = %v, want %d", i, g, i+2)
		}
	}
}

func TestRecordSubscription_FR009_LatestAsOfWinsThenRecordingOrder(t *testing.T) {
	e := newSvcEnv(t)
	ipo := e.publishedIPO()
	late := e.sub(ipo, e.at(-10), 300)
	e.setNow(e.at(1))
	back := e.sub(ipo, e.at(-120), 100) // back-filled older reading
	if back.Current.ID != late.Snapshot.ID || back.Current.TotalX100 != 300 {
		t.Errorf("current after a back-fill = %v (%d), want the later as-of (%d)", back.Current.ID, back.Current.TotalX100, 300)
	}
	e.setNow(e.at(2))
	tie1 := e.sub(ipo, e.at(-5), 400)
	e.setNow(e.at(3))
	tie2 := e.sub(ipo, e.at(-5), 410)
	if tie1.Current.ID != tie1.Snapshot.ID {
		t.Errorf("a newer as-of must become current")
	}
	if tie2.Current.ID != tie2.Snapshot.ID || tie2.Current.TotalX100 != 410 {
		t.Errorf("equal as-of: current = %d, want the later recording 410 (FR-009)", tie2.Current.TotalX100)
	}
}

func TestRecordSubscription_FR008_RangesAreChecked(t *testing.T) {
	e := newSvcEnv(t)
	ipo := e.publishedIPO()
	base := func() SubscriptionInput { return SubscriptionInput{AsOf: e.now, TotalX100: 100, Source: "manual"} }
	bad := map[string]func(*SubscriptionInput){
		"total negative":   func(s *SubscriptionInput) { s.TotalX100 = -1 },
		"total too large":  func(s *SubscriptionInput) { s.TotalX100 = 10_000_001 },
		"qib negative":     func(s *SubscriptionInput) { s.QIBX100 = p32(-1) },
		"employee too big": func(s *SubscriptionInput) { s.EmployeeX100 = p32(10_000_001) },
		"bad source":       func(s *SubscriptionInput) { s.Source = "x" },
	}
	for name, mod := range bad {
		in := base()
		mod(&in)
		_, err := e.svc.RecordSubscription(e.ctx(), e.adm, e.org, ipo, in, "")
		var ve *ValidationError
		if !errors.As(err, &ve) || ve.Code != "ipomarket.invalid_value" {
			t.Errorf("%s: err = %v, want *ValidationError ipomarket.invalid_value", name, err)
		}
	}
	e.wantNoWrites(ipo)
	for _, v := range []int32{0, 10_000_000} {
		in := base()
		in.TotalX100 = v
		if _, err := e.svc.RecordSubscription(e.ctx(), e.adm, e.org, ipo, in, ""); err != nil {
			t.Errorf("total %d: %v, want accepted (bounds are inclusive)", v, err)
		}
	}
}

func TestRecordSubscription_FR008_AsOfWindow(t *testing.T) {
	e := newSvcEnv(t)
	ipo := e.publishedIPO()
	for name, c := range map[string]struct {
		asOf time.Time
		ok   bool
	}{
		"now plus 5 min":             {e.now.Add(5 * time.Minute), true},
		"now plus 5 min 1 s":         {e.now.Add(5*time.Minute + time.Second), false},
		"open date 00:00 IST":        {openMidnightIST, true},
		"1 s before open date 00:00": {openMidnightIST.Add(-time.Second), false},
		"days before the open date":  {openMidnightIST.Add(-72 * time.Hour), false},
	} {
		_, err := e.svc.RecordSubscription(e.ctx(), e.adm, e.org, ipo, SubscriptionInput{AsOf: c.asOf, TotalX100: 100, Source: "manual"}, "")
		var ve *ValidationError
		switch {
		case c.ok && err != nil:
			t.Errorf("%s: %v, want accepted", name, err)
		case !c.ok && (!errors.As(err, &ve) || ve.Code != "ipomarket.invalid_value"):
			t.Errorf("%s: err = %v, want ipomarket.invalid_value (US4.4)", name, err)
		}
	}
}

func TestRecordSubscription_FR006_FrozenNotPublishedUnknown(t *testing.T) {
	e := newSvcEnv(t)
	in := SubscriptionInput{AsOf: e.now, TotalX100: 100, Source: "manual"}
	draft := e.newIPO(e.org, nil)
	if _, err := e.svc.RecordSubscription(e.ctx(), e.adm, e.org, draft, in, ""); !errors.Is(err, ErrNotPublishedYet) {
		t.Errorf("never published: %v, want ErrNotPublishedYet", err)
	}
	for _, st := range []string{"LISTED", "SETTLED"} {
		ipo := e.publishedIPO()
		e.setStatus(ipo, st)
		if _, err := e.svc.RecordSubscription(e.ctx(), e.adm, e.org, ipo, in, ""); !errors.Is(err, ErrFrozen) {
			t.Errorf("%s: %v, want ErrFrozen", st, err)
		}
		e.wantNoWrites(ipo)
	}
	if _, err := e.svc.RecordSubscription(e.ctx(), e.adm, e.org, e.publishedIPO(), in, ""); err != nil {
		t.Errorf("open IPO: %v", err)
	}
	e.wantNoWrites(draft)
}

func TestRecordSubscription_FR010_IdempotentReplayAndReuse(t *testing.T) {
	e := newSvcEnv(t)
	ipo := e.publishedIPO()
	key := "sub-key-0001"
	in := SubscriptionInput{AsOf: e.at(-30), TotalX100: 700, QIBX100: p32(10), Source: "manual"}
	first, err := e.svc.RecordSubscription(e.ctx(), e.adm, e.org, ipo, in, key)
	if err != nil || first.Replayed {
		t.Fatalf("first: %v %v", err, first.Replayed)
	}
	e.setNow(e.at(5))
	newer := e.sub(ipo, e.at(-1), 900)
	again, err := e.svc.RecordSubscription(e.ctx(), e.adm, e.org, ipo, in, key)
	if err != nil || !again.Replayed {
		t.Fatalf("replay: %v replayed=%v", err, again.Replayed)
	}
	if again.Snapshot.ID != first.Snapshot.ID || again.Current.ID != newer.Snapshot.ID {
		t.Errorf("replay snapshot %v current %v, want original %v and current %v", again.Snapshot.ID, again.Current.ID, first.Snapshot.ID, newer.Snapshot.ID)
	}
	if e.subRows(ipo) != 2 {
		t.Errorf("rows = %d, want 2", e.subRows(ipo))
	}
	other := in
	other.TotalX100 = 701
	if _, err := e.svc.RecordSubscription(e.ctx(), e.adm, e.org, ipo, other, key); !errors.Is(err, ErrKeyReused) {
		t.Errorf("same key, other body: %v, want ErrKeyReused", err)
	}
	other = in
	other.QIBX100 = nil
	if _, err := e.svc.RecordSubscription(e.ctx(), e.adm, e.org, ipo, other, key); !errors.Is(err, ErrKeyReused) {
		t.Errorf("same key, category dropped: %v, want ErrKeyReused", err)
	}
	e.wantAudits(ipo, 2)
}

func TestRecordSubscription_FR010_ConcurrentSameKeyOneRow(t *testing.T) {
	e := newSvcEnv(t)
	ipo := e.publishedIPO()
	const n = 6
	res := make([]SubscriptionResult, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res[i], errs[i] = e.svc.RecordSubscription(e.ctx(), e.adm, e.org, ipo, SubscriptionInput{AsOf: e.now, TotalX100: 55, Source: "manual"}, "sub-concurrent-1")
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
	}
	if fresh != 1 || e.subRows(ipo) != 1 {
		t.Errorf("fresh=%d rows=%d, want one each", fresh, e.subRows(ipo))
	}
	e.wantAudits(ipo, 1)
}

func TestRecordSubscription_FR011_OneAuditPerWrite(t *testing.T) {
	e := newSvcEnv(t)
	ipo := e.publishedIPO()
	in := SubscriptionInput{AsOf: e.at(-30), TotalX100: 1234, QIBX100: p32(77), Source: "manual"}
	r, err := e.svc.RecordSubscription(e.ctx(), e.adm, e.org, ipo, in, "sub-audit-001")
	if err != nil {
		t.Fatal(err)
	}
	a := e.audits(ipo)
	if len(a) != 1 || a[0].Action != "ipo.subscription_recorded" || a[0].ActorKind != "admin" || a[0].ActorID == nil || *a[0].ActorID != e.adm.ID {
		t.Fatalf("audit = %+v, want one ipo.subscription_recorded by the admin", a)
	}
	af := a[0].After
	if af["snapshot_id"] != r.Snapshot.ID.String() || af["total_x100"] != float64(1234) || af["qib_x100"] != float64(77) ||
		af["source"] != "manual" || af["idempotency_key"] != "sub-audit-001" {
		t.Errorf("audit after = %v", af)
	}
	if _, err := e.svc.RecordSubscription(e.ctx(), e.adm, e.org, ipo, in, "sub-audit-001"); err != nil {
		t.Fatal(err)
	}
	in.TotalX100 = -5
	_, _ = e.svc.RecordSubscription(e.ctx(), e.adm, e.org, ipo, in, "")
	e.wantAudits(ipo, 1)
}
