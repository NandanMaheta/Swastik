package ipomarket

import (
	"strings"
	"testing"

	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"
)

// S16: admin operations (contracts/http-api.md). Authorisation: admin only (FR-015).

func TestAdmin_BR_IPO_04_RecordGMP(t *testing.T) {
	e := newHTTPEnv(t)
	ipo := e.publishedIPO()
	r := e.admin("POST", gmpPath(ipo), map[string]any{"gmp_paise": 3000, "note": "  broker call "})
	wantHTTP(t, r, 201)
	en := r.obj("entry")
	if en["gmp_paise"] != float64(3000) || en["expected_profit_per_lot_paise"] != float64(150_000) || en["note"] != "broker call" ||
		en["source"] != "manual" || en["corrects_entry_id"] != nil || en["corrected_by_entry_id"] != nil {
		t.Errorf("entry = %v", en)
	}
	if a, _ := en["actor"].(map[string]any); a["kind"] != "admin" || a["id"] != e.adm.ID.String() {
		t.Errorf("actor = %v, want the signed-in admin (US1.1)", en["actor"])
	}
	if s, _ := en["recorded_at"].(string); !strings.HasPrefix(s, "2026-11-14T04:30:00") || en["id"] == "" {
		t.Errorf("id/recorded_at = %v / %v", en["id"], en["recorded_at"])
	}
	c := r.obj("current")
	if c["gmp_paise"] != float64(3000) || c["lot_size"] != float64(50) || c["expected_profit_per_lot_paise"] != float64(150_000) || c["updated_at"] == nil {
		t.Errorf("current = %v", c)
	}
	if w, ok := r.M["warnings"].([]any); !ok || len(w) != 0 {
		t.Errorf("warnings = %v, want an empty array, never null", r.M["warnings"])
	}
}

func TestAdmin_FR007_WarningInBody(t *testing.T) {
	e := newHTTPEnv(t)
	ipo := e.publishedIPO()
	r := e.admin("POST", gmpPath(ipo), map[string]any{"gmp_paise": 250_000})
	wantHTTP(t, r, 201)
	w := r.list("warnings")
	if len(w) != 1 {
		t.Fatalf("warnings = %v, want one", w)
	}
	m := w[0].(map[string]any)
	p, _ := m["params"].(map[string]any)
	if m["code"] != "ipomarket.gmp_exceeds_price" || p["gmp_paise"] != float64(250_000) || p["price_paise"] != float64(100_000) {
		t.Errorf("warning = %v", m)
	}
}

func TestAdmin_FR010_IdempotencyKey(t *testing.T) {
	e := newHTTPEnv(t)
	ipo := e.publishedIPO()
	body := map[string]any{"gmp_paise": 3000}
	first := e.admin("POST", gmpPath(ipo), body, idemHdr("http-key-0001"))
	wantHTTP(t, first, 201)
	again := e.admin("POST", gmpPath(ipo), body, idemHdr("http-key-0001"))
	wantHTTP(t, again, 200)
	if again.obj("entry")["id"] != first.obj("entry")["id"] || e.gmpRows(ipo) != 1 {
		t.Errorf("replay entry %v rows %d, want the original and one row", again.obj("entry")["id"], e.gmpRows(ipo))
	}
	wantProblem(t, e.admin("POST", gmpPath(ipo), map[string]any{"gmp_paise": 3001}, idemHdr("http-key-0001")), 422, "ipomarket.idempotency_key_reused")
	// no key: always new
	wantHTTP(t, e.admin("POST", gmpPath(ipo), body), 201)
	wantHTTP(t, e.admin("POST", gmpPath(ipo), body), 201)
	// key shape: 8-200 chars of [A-Za-z0-9._:-]
	for _, k := range []string{"short", "has space in it", strings.Repeat("k", 201)} {
		wantProblem(t, e.admin("POST", gmpPath(ipo), body, idemHdr(k)), 422, "validation_failed")
	}
	wantHTTP(t, e.admin("POST", gmpPath(ipo), body, idemHdr("Aa0._:-x")), 201)
}

func TestAdmin_FR001_RecordGMPValidation(t *testing.T) {
	e := newHTTPEnv(t)
	ipo := e.publishedIPO()
	for name, body := range map[string]map[string]any{
		"missing gmp":    {"note": "x"},
		"gmp too large":  {"gmp_paise": 1_000_000_001},
		"gmp too small":  {"gmp_paise": -1_000_000_001},
		"gmp not number": {"gmp_paise": "12"},
		"empty note":     {"gmp_paise": 1, "note": ""},
		"long note":      {"gmp_paise": 1, "note": strings.Repeat("x", 201)},
		"bad corrects":   {"gmp_paise": 1, "corrects_entry_id": "nope"},
	} {
		r := e.admin("POST", gmpPath(ipo), body)
		if r.Code != 422 || r.problemCode() != "validation_failed" {
			t.Errorf("%s: %d %q, want 422 validation_failed", name, r.Code, r.problemCode())
		}
	}
	wantProblem(t, e.admin("POST", gmpPath(ipo), map[string]any{"gmp_paise": 1, "note": "    "}), 422, "ipomarket.invalid_value")
	wantProblem(t, e.admin("POST", "/v1/admin/ipos/not-a-uuid/gmp", map[string]any{"gmp_paise": 1}), 422, "validation_failed")
	e.wantNoWrites(ipo)
	// zero and both bounds are fine
	for _, v := range []int64{0, -1_000_000_000, 1_000_000_000} {
		wantHTTP(t, e.admin("POST", gmpPath(ipo), map[string]any{"gmp_paise": v}), 201)
	}
}

func TestAdmin_FR006_ConflictsAndNotFound(t *testing.T) {
	e := newHTTPEnv(t)
	body := map[string]any{"gmp_paise": 1}
	sub := map[string]any{"as_of": "2026-11-14T04:00:00Z", "total_x100": 100}

	draft := e.newIPO(e.org, nil)
	wantProblem(t, e.admin("POST", gmpPath(draft), body), 409, "ipomarket.not_published_yet")
	wantProblem(t, e.admin("POST", subPath(draft), sub), 409, "ipomarket.not_published_yet")

	listed := e.publishedIPO()
	e.setStatus(listed, "LISTED")
	wantProblem(t, e.admin("POST", gmpPath(listed), body), 409, "ipomarket.frozen")
	wantProblem(t, e.admin("POST", subPath(listed), sub), 409, "ipomarket.frozen")

	unknown := uuid.New()
	wantProblem(t, e.admin("POST", gmpPath(unknown), body), 404, "not_found")
	wantProblem(t, e.admin("POST", subPath(unknown), sub), 404, "not_found")
	wantProblem(t, e.admin("GET", gmpPath(unknown), nil), 404, "not_found")
	wantProblem(t, e.admin("GET", subPath(unknown), nil), 404, "not_found")
	foreign := e.newIPO(e.newOrg("Other"), func(r *ipoRaw) { r.published = true })
	wantProblem(t, e.admin("POST", gmpPath(foreign), body), 404, "not_found")
	wantProblem(t, e.admin("GET", gmpPath(foreign), nil), 404, "not_found")
}

func TestAdmin_FR005_CorrectionOverHTTP(t *testing.T) {
	e := newHTTPEnv(t)
	ipo := e.publishedIPO()
	a := e.admin("POST", gmpPath(ipo), map[string]any{"gmp_paise": 3000})
	wantHTTP(t, a, 201)
	aid := a.obj("entry")["id"]
	c := e.admin("POST", gmpPath(ipo), map[string]any{"gmp_paise": 3100, "corrects_entry_id": aid})
	wantHTTP(t, c, 201)
	if c.obj("entry")["corrects_entry_id"] != aid || c.obj("current")["gmp_paise"] != float64(3100) {
		t.Errorf("correction = %v", c.M)
	}
	wantProblem(t, e.admin("POST", gmpPath(ipo), map[string]any{"gmp_paise": 1, "corrects_entry_id": aid}), 409, "ipomarket.correction_not_latest")
	wantProblem(t, e.admin("POST", gmpPath(ipo), map[string]any{"gmp_paise": 1, "corrects_entry_id": uuid.New().String()}), 409, "ipomarket.correction_not_latest")
}

func TestAdmin_FR012_ListGMP(t *testing.T) {
	e := newHTTPEnv(t)
	ipo := e.publishedIPO()
	for i := range 5 {
		e.setNow(e.at(i))
		e.gmp(ipo, int64(i+1))
	}
	r := e.admin("GET", gmpPath(ipo)+"?limit=2", nil)
	wantHTTP(t, r, 200)
	items := r.list("items")
	if len(items) != 2 || items[0].(map[string]any)["gmp_paise"] != float64(5) {
		t.Fatalf("page 1 = %v, want 5,4", items)
	}
	wantKeys(t, "admin entry", items[0].(map[string]any), "id", "gmp_paise", "expected_profit_per_lot_paise", "note", "corrects_entry_id",
		"corrected_by_entry_id", "source", "actor", "recorded_at")
	cur, _ := r.M["next_cursor"].(string)
	if cur == "" {
		t.Fatalf("next_cursor = %v, want a cursor", r.M["next_cursor"])
	}
	var got []float64
	for _, it := range items {
		got = append(got, it.(map[string]any)["gmp_paise"].(float64))
	}
	for cur != "" {
		p := e.admin("GET", gmpPath(ipo)+"?limit=2&cursor="+cur, nil)
		wantHTTP(t, p, 200)
		for _, it := range p.list("items") {
			got = append(got, it.(map[string]any)["gmp_paise"].(float64))
		}
		cur, _ = p.M["next_cursor"].(string)
		if cur == "" {
			if v, present := p.M["next_cursor"]; !present || v != nil {
				t.Errorf("last page next_cursor = %v, want null", v)
			}
		}
	}
	if len(got) != 5 || got[0] != 5 || got[4] != 1 {
		t.Errorf("history = %v, want 5..1", got)
	}
	d := e.admin("GET", gmpPath(ipo), nil) // default limit 50
	wantHTTP(t, d, 200)
	if len(d.list("items")) != 5 {
		t.Errorf("default page = %d items", len(d.list("items")))
	}
	for _, q := range []string{"?limit=0", "?limit=201", "?limit=x", "?cursor=!!!garbage"} {
		if r := e.admin("GET", gmpPath(ipo)+q, nil); r.Code != 422 {
			t.Errorf("%s: %d, want 422", q, r.Code)
		}
	}
	empty := e.admin("GET", gmpPath(e.publishedIPO()), nil)
	wantHTTP(t, empty, 200)
	if items, ok := empty.M["items"].([]any); !ok || len(items) != 0 {
		t.Errorf("items = %v, want an empty array", empty.M["items"])
	}
}

func TestAdmin_FR008_RecordSubscription(t *testing.T) {
	e := newHTTPEnv(t)
	ipo := e.publishedIPO()
	body := map[string]any{"as_of": "2026-11-14T03:30:00Z", "total_x100": 1234, "qib_x100": 5000, "retail_x100": 0}
	r := e.admin("POST", subPath(ipo), body, idemHdr("sub-http-001"))
	wantHTTP(t, r, 201)
	s := r.obj("snapshot")
	if s["total_x100"] != float64(1234) || s["qib_x100"] != float64(5000) || s["retail_x100"] != float64(0) || s["nii_x100"] != nil ||
		s["employee_x100"] != nil || s["source"] != "manual" || s["id"] == nil || s["recorded_at"] == nil {
		t.Errorf("snapshot = %v", s)
	}
	if a, _ := s["actor"].(map[string]any); a["kind"] != "admin" || a["id"] != e.adm.ID.String() {
		t.Errorf("actor = %v", s["actor"])
	}
	if r.obj("current")["total_x100"] != float64(1234) {
		t.Errorf("current = %v", r.obj("current"))
	}
	again := e.admin("POST", subPath(ipo), body, idemHdr("sub-http-001"))
	wantHTTP(t, again, 200)
	if again.obj("snapshot")["id"] != s["id"] || e.subRows(ipo) != 1 {
		t.Errorf("replay snapshot %v rows %d", again.obj("snapshot")["id"], e.subRows(ipo))
	}
	body["total_x100"] = 1235
	wantProblem(t, e.admin("POST", subPath(ipo), body, idemHdr("sub-http-001")), 422, "ipomarket.idempotency_key_reused")
}

func TestAdmin_FR008_SubscriptionValidation(t *testing.T) {
	e := newHTTPEnv(t)
	ipo := e.publishedIPO()
	ok := func() map[string]any { return map[string]any{"as_of": "2026-11-14T04:00:00Z", "total_x100": 100} }
	for name, mod := range map[string]func(map[string]any){
		"missing total":    func(m map[string]any) { delete(m, "total_x100") },
		"missing as_of":    func(m map[string]any) { delete(m, "as_of") },
		"as_of not a time": func(m map[string]any) { m["as_of"] = "yesterday" },
		"total negative":   func(m map[string]any) { m["total_x100"] = -1 },
		"total too large":  func(m map[string]any) { m["total_x100"] = 10_000_001 },
		"qib negative":     func(m map[string]any) { m["qib_x100"] = -1 },
		"employee too big": func(m map[string]any) { m["employee_x100"] = 10_000_001 },
	} {
		b := ok()
		mod(b)
		if r := e.admin("POST", subPath(ipo), b); r.Code != 422 || r.problemCode() != "validation_failed" {
			t.Errorf("%s: %d %q, want 422 validation_failed", name, r.Code, r.problemCode())
		}
	}
	future := ok()
	future["as_of"] = "2026-11-14T04:36:00Z" // now is 04:30; limit is +5 min
	wantProblem(t, e.admin("POST", subPath(ipo), future), 422, "ipomarket.invalid_value")
	early := ok()
	early["as_of"] = "2026-11-10T18:29:59Z" // open date 00:00 IST is 18:30Z the day before
	wantProblem(t, e.admin("POST", subPath(ipo), early), 422, "ipomarket.invalid_value")
	edge := ok()
	edge["as_of"] = "2026-11-14T04:35:00Z"
	wantHTTP(t, e.admin("POST", subPath(ipo), edge), 201)
}

func TestAdmin_FR012_ListSubscription(t *testing.T) {
	e := newHTTPEnv(t)
	ipo := e.publishedIPO()
	for i, m := range []int{-50, -10, -30} {
		e.mustSub(ipo, func(s *subRaw) { s.asOf = e.at(m); s.total = p32(int32(i + 1)) })
	}
	r := e.admin("GET", subPath(ipo)+"?limit=2", nil)
	wantHTTP(t, r, 200)
	items := r.list("items")
	if len(items) != 2 || items[0].(map[string]any)["total_x100"] != float64(2) || items[1].(map[string]any)["total_x100"] != float64(3) {
		t.Fatalf("items = %v, want latest as-of first (2, 3)", items)
	}
	wantKeys(t, "admin snapshot", items[0].(map[string]any), "id", "as_of", "total_x100", "qib_x100", "nii_x100", "bnii_x100", "snii_x100",
		"retail_x100", "employee_x100", "source", "actor", "recorded_at")
	if c, _ := r.M["next_cursor"].(string); c == "" {
		t.Errorf("next_cursor = %v", r.M["next_cursor"])
	}
}

func TestAdmin_FR012_Summaries(t *testing.T) {
	e := newHTTPEnv(t)
	pub, draft := e.publishedIPO(), e.newIPO(e.org, nil)
	e.mustGMP(pub, func(g *gmpRaw) { g.gmp = 300 })
	foreign := e.newIPO(e.newOrg("Other"), func(r *ipoRaw) { r.published = true })
	r := e.admin("GET", "/v1/admin/ipos/market?ipo_ids="+idList(pub, draft, uuid.New(), foreign, pub), nil)
	wantHTTP(t, r, 200)
	items := r.list("items")
	seen := map[string]map[string]any{}
	for _, it := range items {
		m := it.(map[string]any)
		wantKeys(t, "summary", m, "ipo_id", "current_gmp", "subscription_total_x100", "subscription_as_of")
		seen[m["ipo_id"].(string)] = m
	}
	if len(items) != 2 || seen[pub.String()] == nil || seen[draft.String()] == nil {
		t.Fatalf("items = %v, want the published and the draft IPO once each (drafts included, US2/FR-012)", items)
	}
	if c, _ := seen[pub.String()]["current_gmp"].(map[string]any); c["gmp_paise"] != float64(300) || c["expected_profit_per_lot_paise"] != float64(15_000) {
		t.Errorf("current_gmp = %v", c)
	}
	if seen[draft.String()]["current_gmp"] != nil {
		t.Errorf("draft current_gmp = %v, want null", seen[draft.String()]["current_gmp"])
	}
	// size and shape of ipo_ids
	for name, q := range map[string]string{
		"missing":   "",
		"empty":     "?ipo_ids=",
		"not uuids": "?ipo_ids=a,b",
		"201 ids":   "?ipo_ids=" + idList(manyIDs(201)...),
	} {
		if r := e.admin("GET", "/v1/admin/ipos/market"+q, nil); r.Code != 422 {
			t.Errorf("%s: %d, want 422 (route /market must not be read as an IPO id)", name, r.Code)
		}
	}
	wantHTTP(t, e.admin("GET", "/v1/admin/ipos/market?ipo_ids="+idList(manyIDs(200)...), nil), 200)
}

func manyIDs(n int) []uuid.UUID {
	out := make([]uuid.UUID, n)
	for i := range out {
		out[i] = uuid.New()
	}
	return out
}

func TestAdmin_FR015_ClientsAndAnonymousAreRefused(t *testing.T) {
	e := newHTTPEnv(t)
	ipo := e.publishedIPO()
	ops := []struct {
		method, path string
		body         any
	}{
		{"POST", gmpPath(ipo), map[string]any{"gmp_paise": 1}},
		{"GET", gmpPath(ipo), nil},
		{"POST", subPath(ipo), map[string]any{"as_of": "2026-11-14T04:00:00Z", "total_x100": 1}},
		{"GET", subPath(ipo), nil},
		{"GET", "/v1/admin/ipos/market?ipo_ids=" + ipo.String(), nil},
	}
	for _, op := range ops {
		wantProblem(t, e.do("client-token", op.method, op.path, op.body), 403, "auth.forbidden")
		wantProblem(t, e.do("", op.method, op.path, op.body), 401, "auth.unauthenticated")
	}
	e.wantNoWrites(ipo)
}

func TestAdmin_BR_IPO_04_OpenAPIOperations(t *testing.T) {
	e := newHTTPEnv(t)
	oa := e.api.OpenAPI()
	type op struct{ method, path, id string }
	want := []op{
		{"POST", "/v1/admin/ipos/{ipoId}/gmp", "ipomarket-record-gmp"},
		{"GET", "/v1/admin/ipos/{ipoId}/gmp", "ipomarket-list-gmp"},
		{"POST", "/v1/admin/ipos/{ipoId}/subscription", "ipomarket-record-subscription"},
		{"GET", "/v1/admin/ipos/{ipoId}/subscription", "ipomarket-list-subscription"},
		{"GET", "/v1/admin/ipos/market", "ipomarket-admin-summaries"},
		{"GET", "/v1/ipos/{ipoId}/market", "ipomarket-get"},
		{"GET", "/v1/ipos/market", "ipomarket-summaries"},
	}
	for _, w := range want {
		item := oa.Paths[w.path]
		if item == nil {
			t.Errorf("path %s is not in the OpenAPI document", w.path)
			continue
		}
		o := item.Get
		if w.method == "POST" {
			o = item.Post
		}
		if o == nil || o.OperationID != w.id {
			t.Errorf("%s %s operation = %+v, want id %s", w.method, w.path, o, w.id)
			continue
		}
		if len(o.Tags) != 1 || o.Tags[0] != "ipomarket" {
			t.Errorf("%s tags = %v, want [ipomarket]", w.id, o.Tags)
		}
		if len(o.Security) == 0 {
			t.Errorf("%s declares no security", w.id)
		}
	}
	var post *huma.Operation
	if item := oa.Paths["/v1/admin/ipos/{ipoId}/gmp"]; item != nil {
		post = item.Post
	}
	if post != nil {
		found := false
		for _, p := range post.Parameters {
			if p.In == "header" && p.Name == "Idempotency-Key" {
				found = true
				if p.Required {
					t.Errorf("Idempotency-Key must be optional")
				}
			}
		}
		if !found {
			t.Errorf("ipomarket-record-gmp lacks the Idempotency-Key header parameter")
		}
	}
}
