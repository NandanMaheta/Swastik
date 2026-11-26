package ipomarket

import (
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/NandanMaheta/swastik/apps/api/internal/ipos"
)

// Review-fix tests (feature 009): cross-org integrity, service-level id cap, idempotency before
// validation.

func TestSchema_BR_IPO_04_CrossOrgIPORejected(t *testing.T) {
	e := newMEnv(t)
	ipo := e.publishedIPO() // belongs to e.org
	other := e.newOrg("Other")

	_, err := e.rawGMP(ipo, func(g *gmpRaw) { g.org = other })
	wantPG(t, err, "23503")
	_, err = e.rawSub(ipo, func(s *subRaw) { s.org = other })
	wantPG(t, err, "23503")

	// Same-org rows still insert.
	e.mustGMP(ipo, nil)
	e.mustSub(ipo, nil)
}

func TestSummaries_BR_IPO_04_ServiceCapsIDs(t *testing.T) {
	e := newSvcEnv(t)
	ids := func(n int) []uuid.UUID {
		out := make([]uuid.UUID, n)
		for i := range out {
			out[i] = uuid.New()
		}
		return out
	}
	for _, published := range []bool{false, true} {
		_, err := e.svc.Summaries(e.ctx(), e.org, ids(201), published)
		var ve *ValidationError
		if !errors.As(err, &ve) || ve.Code != codeInvalidValue {
			t.Errorf("Summaries(201 ids, publishedOnly=%v): err = %v, want *ValidationError %s", published, err, codeInvalidValue)
		}
	}
	if _, err := e.svc.Summaries(e.ctx(), e.org, ids(200), false); err != nil {
		t.Errorf("Summaries(200 ids): %v, want ok", err)
	}
}

func TestGetMany_BR_IPO_04_ServiceCapsIDs(t *testing.T) {
	e := newSvcEnv(t)
	reader := ipos.NewService(ipos.Deps{Tx: e.tx, Now: e.now_, Log: e.svc.d.Log})
	ids := make([]uuid.UUID, 201)
	for i := range ids {
		ids[i] = uuid.New()
	}
	_, err := reader.GetMany(e.ctx(), e.org, ids)
	var ve *ipos.ValidationError
	if !errors.As(err, &ve) {
		t.Errorf("GetMany(201 ids): err = %v, want *ipos.ValidationError", err)
	}
	if _, err := reader.GetMany(e.ctx(), e.org, ids[:200]); err != nil {
		t.Errorf("GetMany(200 ids): %v, want ok", err)
	}
}

func TestHandler_BR_IPO_04_IPOIDsQueryHasMaxLength(t *testing.T) {
	e := newHTTPEnv(t)
	item := e.api.OpenAPI().Paths["/v1/admin/ipos/market"]
	if item == nil || item.Get == nil {
		t.Fatal("GET /v1/admin/ipos/market not registered")
	}
	var found bool
	for _, p := range item.Get.Parameters {
		if p.Name != "ipo_ids" {
			continue
		}
		found = true
		// 200 uuids (36 chars) joined by commas is 7399 characters.
		if p.Schema == nil || p.Schema.MaxLength == nil || *p.Schema.MaxLength < 7399 || *p.Schema.MaxLength > 8192 {
			t.Errorf("ipo_ids schema maxLength = %v, want between 7399 and 8192", p.Schema)
		}
	}
	if !found {
		t.Fatal("ipo_ids parameter missing")
	}
	big := make([]byte, 100_000)
	for i := range big {
		big[i] = 'a'
	}
	wantHTTP(t, e.admin("GET", "/v1/admin/ipos/market?ipo_ids="+string(big), nil), 422)
}

func TestRecordSubscription_FR010_ReplayBeforeValidation(t *testing.T) {
	e := newSvcEnv(t)
	ipo := e.publishedIPO()
	in := SubscriptionInput{AsOf: openMidnightIST, TotalX100: 250, Source: "manual"}
	first, err := e.svc.RecordSubscription(e.ctx(), e.adm, e.org, ipo, in, "replay-sub-0001")
	if err != nil || first.Replayed {
		t.Fatalf("first: err=%v replayed=%v", err, first.Replayed)
	}
	// The open date moves later: the same as_of would now be rejected as before the open date.
	if _, err := e.pool.Exec(e.ctx(), `UPDATE ipos SET open_date = '2026-11-20', close_date = '2026-11-22' WHERE id = $1`, ipo); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.RecordSubscription(e.ctx(), e.adm, e.org, ipo, in, ""); err == nil {
		t.Fatal("precondition: the same body without a key must now fail validation")
	}
	again, err := e.svc.RecordSubscription(e.ctx(), e.adm, e.org, ipo, in, "replay-sub-0001")
	if err != nil || !again.Replayed || again.Snapshot.ID != first.Snapshot.ID {
		t.Fatalf("replay: err=%v replayed=%v, want the stored snapshot", err, again.Replayed)
	}
	if e.subRows(ipo) != 1 {
		t.Errorf("rows = %d, want 1", e.subRows(ipo))
	}
}

func TestRecordGMP_FR010_ReplayBeforeStateChecks(t *testing.T) {
	e := newSvcEnv(t)
	ipo := e.publishedIPO()
	in := GMPInput{GMPPaise: 3000, Source: "manual"}
	first, err := e.svc.RecordGMP(e.ctx(), e.adm, e.org, ipo, in, "replay-gmp-0001")
	if err != nil || first.Replayed {
		t.Fatalf("first: err=%v replayed=%v", err, first.Replayed)
	}
	e.setStatus(ipo, "LISTED")
	if _, err := e.svc.RecordGMP(e.ctx(), e.adm, e.org, ipo, in, ""); !errors.Is(err, ErrFrozen) {
		t.Fatalf("precondition: keyless request on a listed IPO = %v, want ErrFrozen", err)
	}
	again, err := e.svc.RecordGMP(e.ctx(), e.adm, e.org, ipo, in, "replay-gmp-0001")
	if err != nil || !again.Replayed || again.Entry.ID != first.Entry.ID {
		t.Fatalf("replay: err=%v replayed=%v, want the stored entry", err, again.Replayed)
	}
}
