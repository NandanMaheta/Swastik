package ipomarket

import (
	"strings"
	"testing"

	"github.com/google/uuid"
)

// S16: client operations (US2, FR-013, FR-014). Any signed-in user may read; only published IPOs
// of the caller's org are visible; the body never carries author, note or idempotency data.

func marketPath(ipo uuid.UUID) string { return "/v1/ipos/" + ipo.String() + "/market" }

func TestClient_BR_IPO_04_LatestWithUpdatedAt(t *testing.T) {
	e := newHTTPEnv(t)
	ipo := e.publishedIPO()
	e.mustGMP(ipo, func(g *gmpRaw) { g.gmp = 1000; g.recordedAt = e.at(-30) })
	e.mustGMP(ipo, func(g *gmpRaw) { g.gmp = -400; g.recordedAt = e.at(-5) })
	e.mustSub(ipo, func(s *subRaw) { s.asOf = e.at(-60); s.total = p32(100) })
	e.mustSub(ipo, func(s *subRaw) { s.asOf = e.at(-20); s.total = p32(1234); s.cats[4] = p32(2500) })

	r := e.client("GET", marketPath(ipo))
	wantHTTP(t, r, 200)
	if r.M["ipo_id"] != ipo.String() {
		t.Errorf("ipo_id = %v", r.M["ipo_id"])
	}
	c := r.obj("current_gmp")
	if c["gmp_paise"] != float64(-400) || c["expected_profit_per_lot_paise"] != float64(-20_000) || c["lot_size"] != float64(50) ||
		c["updated_at"] != "2026-11-14T04:25:00Z" {
		t.Errorf("current_gmp = %v, want -400, -20000, lot 50, updated_at 04:25:00Z (US2.1)", c)
	}
	tr := r.list("trend")
	if len(tr) != 2 || tr[0].(map[string]any)["gmp_paise"] != float64(1000) || tr[1].(map[string]any)["gmp_paise"] != float64(-400) ||
		tr[0].(map[string]any)["at"] != "2026-11-14T04:00:00Z" {
		t.Errorf("trend = %v, want oldest first", tr)
	}
	s := r.obj("subscription")
	if s["total_x100"] != float64(1234) || s["retail_x100"] != float64(2500) || s["qib_x100"] != nil || s["as_of"] != "2026-11-14T04:10:00Z" {
		t.Errorf("subscription = %v, want the latest as-of", s)
	}
	// an admin is a signed-in user too
	wantHTTP(t, e.admin("GET", marketPath(ipo), nil), 200)
}

func TestClient_FR014_NoAdminFields(t *testing.T) {
	e := newHTTPEnv(t)
	ipo := e.publishedIPO()
	note := "secret-broker-note"
	a := e.mustGMP(ipo, func(g *gmpRaw) {
		g.gmp = 1000
		g.note = &note
		g.recordedAt = e.at(-30)
		g.idemKey = pStr("secret-idem-key")
		g.reqHash = pStr(hash64)
	})
	e.mustGMP(ipo, func(g *gmpRaw) { g.gmp = 1100; g.corrects = &a; g.recordedAt = e.at(-20) })
	e.mustGMP(ipo, func(g *gmpRaw) { g.gmp = 1200; g.recordedAt = e.at(-10); g.source = "import:acme_feed" })
	e.mustSub(ipo, func(s *subRaw) {
		s.asOf = e.at(-5)
		s.total = p32(100)
		s.source = "import:acme_feed"
		s.idemKey = pStr("secret-idem-key-2")
		s.reqHash = pStr(hash64)
	})

	r := e.client("GET", marketPath(ipo))
	wantHTTP(t, r, 200)
	wantKeys(t, "view", r.M, "ipo_id", "current_gmp", "trend", "subscription")
	wantKeys(t, "current_gmp", r.obj("current_gmp"), "gmp_paise", "expected_profit_per_lot_paise", "lot_size", "updated_at")
	wantKeys(t, "trend point", r.list("trend")[0].(map[string]any), "gmp_paise", "expected_profit_per_lot_paise", "at")
	wantKeys(t, "subscription", r.obj("subscription"), "as_of", "total_x100", "qib_x100", "nii_x100", "bnii_x100", "snii_x100", "retail_x100", "employee_x100")
	raw := string(r.Raw)
	for _, leak := range []string{note, "secret-idem", hash64, "acme_feed", e.adm.ID.String(), a.String(), "actor", "note", "source", "recorded_at"} {
		if strings.Contains(raw, leak) {
			t.Errorf("client body contains %q: %s", leak, raw)
		}
	}
	// corrected entry (1000) is gone from the trend
	var vals []float64
	for _, p := range r.list("trend") {
		vals = append(vals, p.(map[string]any)["gmp_paise"].(float64))
	}
	if len(vals) != 2 || vals[0] != 1100 || vals[1] != 1200 {
		t.Errorf("trend = %v, want [1100 1200]", vals)
	}

	// the batch carries no admin fields either
	b := e.client("GET", "/v1/ipos/market?ipo_ids="+ipo.String())
	wantHTTP(t, b, 200)
	wantKeys(t, "summary", b.list("items")[0].(map[string]any), "ipo_id", "current_gmp", "subscription_total_x100", "subscription_as_of")
	for _, leak := range []string{"secret", "actor", "note", "source"} {
		if strings.Contains(string(b.Raw), leak) {
			t.Errorf("batch body contains %q", leak)
		}
	}
}

func TestClient_US2_NoDataIsNull(t *testing.T) {
	e := newHTTPEnv(t)
	r := e.client("GET", marketPath(e.publishedIPO()))
	wantHTTP(t, r, 200)
	if v, present := r.M["current_gmp"]; !present || v != nil {
		t.Errorf("current_gmp = %v (present %v), want null", v, present)
	}
	if v, present := r.M["subscription"]; !present || v != nil {
		t.Errorf("subscription = %v (present %v), want null", v, present)
	}
	if tr, ok := r.M["trend"].([]any); !ok || len(tr) != 0 {
		t.Errorf("trend = %v, want an empty array", r.M["trend"])
	}
}

func TestClient_US2_UnpublishedLooksLikeUnknown(t *testing.T) {
	e := newHTTPEnv(t)
	draft := e.newIPO(e.org, nil)
	e.mustGMP(draft, nil)
	pulled := e.onceUnpublished(false)
	e.mustGMP(pulled, nil)
	foreign := e.newIPO(e.newOrg("Other"), func(r *ipoRaw) { r.published = true })
	unknown := e.client("GET", marketPath(uuid.New()))
	wantProblem(t, unknown, 404, "not_found")
	for name, id := range map[string]uuid.UUID{"draft": draft, "unpublished again": pulled, "other org": foreign} {
		r := e.client("GET", marketPath(id))
		wantProblem(t, r, 404, "not_found")
		if string(r.Raw) != string(unknown.Raw) && !sameShape(r.M, unknown.M) {
			t.Errorf("%s: body differs from the unknown-id body (US2.3):\n%s\n%s", name, r.Raw, unknown.Raw)
		}
	}
	// the admin view of the same ids is not hidden
	wantHTTP(t, e.admin("GET", gmpPath(draft), nil), 200)
}

func sameShape(a, b map[string]any) bool {
	for _, k := range []string{"status", "code", "title", "detail", "type"} {
		if a[k] != b[k] {
			return false
		}
	}
	return len(a) == len(b)
}

func TestClient_US2_BatchPublishedOnlyAndLimit(t *testing.T) {
	e := newHTTPEnv(t)
	pub, empty := e.publishedIPO(), e.publishedIPO()
	e.mustGMP(pub, func(g *gmpRaw) { g.gmp = 300; g.recordedAt = e.at(-3) })
	e.mustSub(pub, func(s *subRaw) { s.asOf = e.at(-7); s.total = p32(4321) })
	draft := e.newIPO(e.org, nil)
	pulled := e.onceUnpublished(false)
	foreign := e.newIPO(e.newOrg("Other"), func(r *ipoRaw) { r.published = true })

	r := e.client("GET", "/v1/ipos/market?ipo_ids="+idList(pub, empty, draft, pulled, foreign, uuid.New(), pub))
	wantHTTP(t, r, 200)
	items := r.list("items")
	seen := map[string]map[string]any{}
	for _, it := range items {
		m := it.(map[string]any)
		seen[m["ipo_id"].(string)] = m
	}
	if len(items) != 2 || seen[pub.String()] == nil || seen[empty.String()] == nil {
		t.Fatalf("items = %v, want only the 2 published IPOs, others omitted silently (US2.4)", items)
	}
	p := seen[pub.String()]
	if c, _ := p["current_gmp"].(map[string]any); c["gmp_paise"] != float64(300) || c["expected_profit_per_lot_paise"] != float64(15_000) || c["updated_at"] != "2026-11-14T04:27:00Z" {
		t.Errorf("current_gmp = %v", p["current_gmp"])
	}
	if p["subscription_total_x100"] != float64(4321) || p["subscription_as_of"] != "2026-11-14T04:23:00Z" {
		t.Errorf("subscription = %v / %v", p["subscription_total_x100"], p["subscription_as_of"])
	}
	if n := seen[empty.String()]; n["current_gmp"] != nil || n["subscription_total_x100"] != nil || n["subscription_as_of"] != nil {
		t.Errorf("no data = %v, want nulls", n)
	}

	// 200 ids are fine and an all-unknown batch is an empty array; 201, none or malformed are 422
	none := e.client("GET", "/v1/ipos/market?ipo_ids="+idList(manyIDs(200)...))
	wantHTTP(t, none, 200)
	if items, ok := none.M["items"].([]any); !ok || len(items) != 0 {
		t.Errorf("items = %v, want an empty array", none.M["items"])
	}
	for name, q := range map[string]string{
		"201 ids":   "?ipo_ids=" + idList(manyIDs(201)...),
		"missing":   "",
		"empty":     "?ipo_ids=",
		"not uuids": "?ipo_ids=1,2",
	} {
		if r := e.client("GET", "/v1/ipos/market"+q); r.Code != 422 {
			t.Errorf("%s: %d, want 422 (and /market must not be read as an IPO id)", name, r.Code)
		}
	}
}

func TestClient_FR015_Authentication(t *testing.T) {
	e := newHTTPEnv(t)
	ipo := e.publishedIPO()
	wantProblem(t, e.do("", "GET", marketPath(ipo), nil), 401, "auth.unauthenticated")
	wantProblem(t, e.do("", "GET", "/v1/ipos/market?ipo_ids="+ipo.String(), nil), 401, "auth.unauthenticated")
	wantHTTP(t, e.client("GET", "/v1/ipos/market?ipo_ids="+ipo.String()), 200)
}
