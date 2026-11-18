package ipos

// S15 - HTTP tests A: admin create/get/list/update, error codes, idempotent replay, route
// precedence and admin-only access (contracts/ipos.openapi.yaml, contracts/error-codes.md).
//
// The API is built like cmd/swastik does: httpx.InstallErrors, authz.Install with a fake bearer
// verifier ("admin-token", "client-token"), Register(api, svc), authz.AssertDeclared.
// Assumptions the contracts leave open:
//   - Register(api, svc) reads the organisation from the authz.Principal, not from the request.
//   - The wire `segments` values NSE_MAINBOARD / BSE_MAINBOARD map to Exchange NSE / BSE.
//   - A mutation response is {"ipo": AdminIPO, "warnings": []} with `warnings` never null.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/humatest"
	"github.com/google/uuid"

	"github.com/NandanMaheta/swastik/apps/api/internal/platform/authz"
	"github.com/NandanMaheta/swastik/apps/api/internal/platform/httpx"
)

type tokenVerifier map[string]authz.Principal

func (v tokenVerifier) Verify(_ context.Context, token string) (authz.Principal, error) {
	if p, ok := v[token]; ok {
		return p, nil
	}
	return authz.Principal{}, fmt.Errorf("unknown token")
}

type httpEnv struct {
	*svcEnv
	api humatest.TestAPI
}

func newHTTPEnv(t *testing.T) *httpEnv {
	t.Helper()
	return newHTTPEnvCfg(t, huma.DefaultConfig("test", "1.0.0"))
}

// newHTTPEnvProd builds the API like production does (httpx.NewAPIFor("production")): no $schema
// field is added to response bodies, so exact-key DTO checks need no allowance for it.
func newHTTPEnvProd(t *testing.T) *httpEnv {
	t.Helper()
	cfg := huma.DefaultConfig("test", "1.0.0")
	cfg.CreateHooks = nil // what httpx.NewAPIFor("production") does
	return newHTTPEnvCfg(t, cfg)
}

func newHTTPEnvCfg(t *testing.T, cfg huma.Config) *httpEnv {
	t.Helper()
	e := newSvcEnv(t)
	httpx.InstallErrors()
	_, api := humatest.New(t, cfg)
	authz.Install(api, map[string]authz.Verifier{
		"bearer": tokenVerifier{
			"admin-token":  {UserID: e.admin.ID, OrgID: e.org, SessionID: uuid.New(), Role: authz.RoleAdmin},
			"client-token": {UserID: uuid.New(), OrgID: e.org, SessionID: uuid.New(), Role: authz.RoleClient},
		},
		"mfaChallenge": tokenVerifier{},
	})
	guard(t, "Register", func() { Register(api, e.svc) })
	authz.AssertDeclared(api)
	return &httpEnv{svcEnv: e, api: api}
}

type resp struct {
	Code int
	Raw  []byte
	Hdr  http.Header
	M    map[string]any
}

func (e *httpEnv) do(token, method, path string, body any, headers ...string) resp {
	e.t.Helper()
	args := []any{}
	if token != "" {
		args = append(args, "Authorization: Bearer "+token)
	}
	for _, h := range headers {
		args = append(args, h)
	}
	if body != nil {
		args = append(args, body)
	}
	return toResp(e.api.Do(method, path, args...))
}

func toResp(r *httptest.ResponseRecorder) resp {
	out := resp{Code: r.Code, Raw: r.Body.Bytes(), Hdr: r.Header()}
	_ = json.Unmarshal(out.Raw, &out.M)
	return out
}

func (e *httpEnv) admin(method, path string, body any, headers ...string) resp {
	e.t.Helper()
	return e.do("admin-token", method, path, body, headers...)
}

func (e *httpEnv) client(method, path string) resp {
	e.t.Helper()
	return e.do("client-token", method, path, nil)
}

func idemHdr(key string) string { return "Idempotency-Key: " + key }

func (r resp) problemCode() string { s, _ := r.M["code"].(string); return s }

func (r resp) locations() []string {
	var out []string
	errs, _ := r.M["errors"].([]any)
	for _, x := range errs {
		if m, ok := x.(map[string]any); ok {
			s, _ := m["location"].(string)
			out = append(out, s)
		}
	}
	return out
}

func wantProblem(t *testing.T, r resp, status int, code string) {
	t.Helper()
	if r.Code != status || r.problemCode() != code {
		t.Fatalf("got %d code %q, want %d %q; body %s", r.Code, r.problemCode(), status, code, r.Raw)
	}
}

func wantHTTP(t *testing.T, r resp, status int) {
	t.Helper()
	if r.Code != status {
		t.Fatalf("got %d, want %d; body %s", r.Code, status, r.Raw)
	}
}

func (r resp) ipo() map[string]any { m, _ := r.M["ipo"].(map[string]any); return m }

func (r resp) str(k string) string { s, _ := r.ipo()[k].(string); return s }

func (r resp) version() int { v, _ := r.ipo()["version"].(float64); return int(v) }

func (r resp) warnings() []any { w, _ := r.M["warnings"].([]any); return w }

// acmeBody is the spec's Acme Ltd as a create body (minimum application value Rs 14,700).
func acmeBody() map[string]any {
	return map[string]any{
		"name": "Acme Ltd", "segments": []string{"NSE_MAINBOARD", "BSE_MAINBOARD"}, "nse_symbol": "ACME",
		"issue_size_paise": 50_000_000_000, "price_band_floor_paise": 100_000, "price_band_cap_paise": 105_000,
		"lot_size": 14,
		"dates": map[string]any{
			"open_date": "2026-11-11", "close_date": "2026-11-13", "allotment_date": "2026-11-16",
			"refund_date": "2026-11-17", "demat_credit_date": "2026-11-17", "listing_date": "2026-11-18",
		},
		"registrar": "Link Intime", "lead_managers": []string{"Axis Capital"},
	}
}

// putBody turns a create body into a full PUT body: every key present, null where unset.
func putBody(version int, over map[string]any) map[string]any {
	b := map[string]any{
		"version": version, "name": "Acme Ltd", "segments": []string{"NSE_MAINBOARD"},
		"nse_symbol": nil, "issue_size_paise": nil, "price_band_floor_paise": nil, "price_band_cap_paise": nil,
		"issue_price_paise": nil, "lot_size": nil, "registrar": nil, "lead_managers": []string{}, "offer_document_url": nil,
		"dates": map[string]any{
			"open_date": nil, "close_date": nil, "allotment_date": nil,
			"refund_date": nil, "demat_credit_date": nil, "listing_date": nil,
		},
	}
	for k, v := range over {
		b[k] = v
	}
	return b
}

func (e *httpEnv) createAcme() resp {
	e.t.Helper()
	r := e.admin("POST", "/v1/admin/ipos", acmeBody(), idemHdr(e.key()))
	wantHTTP(e.t, r, 201)
	return r
}

func TestAdmin_Create_FR001_Returns201WithAdminView(t *testing.T) {
	e := newHTTPEnv(t)
	r := e.admin("POST", "/v1/admin/ipos", acmeBody(), idemHdr("create-key-001"))
	wantHTTP(t, r, 201)
	i := r.ipo()
	if i["status"] != "UPCOMING" || i["published"] != false || i["eligible"] != false || i["apply_flag"] != nil || i["source"] != "manual" {
		t.Errorf("new draft = %v, want UPCOMING, unpublished, not eligible, no flag, source manual", i)
	}
	if i["version"] != float64(1) || i["min_application_paise"] != float64(1_470_000) {
		t.Errorf("version/min_application = %v/%v, want 1 / 1470000 (14 x 105000)", i["version"], i["min_application_paise"])
	}
	segs, _ := i["segments"].([]any)
	if len(segs) != 2 || segs[0] != "NSE_MAINBOARD" || segs[1] != "BSE_MAINBOARD" {
		t.Errorf("segments = %v, want [NSE_MAINBOARD BSE_MAINBOARD]", segs)
	}
	if _, ok := r.M["warnings"].([]any); !ok {
		t.Errorf("warnings = %v, want an empty array, not null", r.M["warnings"])
	}
	if e.iposCount() != 1 {
		t.Errorf("rows = %d, want 1", e.iposCount())
	}
}

func TestAdmin_Create_FR001_MinimalBodyAndWithoutKey(t *testing.T) {
	e := newHTTPEnv(t)
	r := e.admin("POST", "/v1/admin/ipos", map[string]any{"name": "Bare Ltd", "segments": []string{"BSE_MAINBOARD"}})
	wantHTTP(t, r, 201)
	if r.ipo()["min_application_paise"] != nil || r.ipo()["lot_size"] != nil {
		t.Errorf("unset facts must be null, got %v", r.ipo())
	}
}

func TestAdmin_Create_FR005_WarningWhenMinApplicationOutsideRange(t *testing.T) {
	e := newHTTPEnv(t)
	b := acmeBody()
	b["price_band_cap_paise"] = 200_000 // 14 x 2,000 = Rs 28,000
	r := e.admin("POST", "/v1/admin/ipos", b, idemHdr(e.key()))
	wantHTTP(t, r, 201)
	w := r.warnings()
	if len(w) != 1 {
		t.Fatalf("warnings = %v, want one", w)
	}
	m := w[0].(map[string]any)
	if m["code"] != "ipo.min_application_out_of_range" || !strings.Contains(m["detail"].(string), "₹28,000") {
		t.Errorf("warning = %v, want code ipo.min_application_out_of_range and an Indian-formatted ₹28,000 detail", m)
	}
	p := m["params"].(map[string]any)
	if p["value_paise"] != float64(2_800_000) || p["min_paise"] != float64(1_000_000) || p["max_paise"] != float64(2_000_000) {
		t.Errorf("params = %v", p)
	}
}

func TestAdmin_Create_BR_IPO_01_SegmentsRejected(t *testing.T) {
	cases := []struct {
		name string
		segs any
		code string
	}{
		{"nse emerge", []string{"NSE_EMERGE"}, "ipo.sme_not_allowed"},
		{"bse sme", []string{"BSE_SME"}, "ipo.sme_not_allowed"},
		{"mixed with mainboard", []string{"NSE_MAINBOARD", "BSE_SME"}, "ipo.sme_not_allowed"},
		{"unknown value", []string{"NYSE"}, "ipo.invalid_segment"},
		{"lowercase", []string{"nse_mainboard"}, "ipo.invalid_segment"},
	}
	e := newHTTPEnv(t)
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := e.admin("POST", "/v1/admin/ipos", map[string]any{"name": "X Ltd", "segments": c.segs}, idemHdr(e.key()))
			wantProblem(t, r, 422, c.code)
			if locs := r.locations(); len(locs) == 0 || locs[0] != "body.segments" {
				t.Errorf("errors[].location = %v, want first body.segments", locs)
			}
		})
	}
	if e.iposCount() != 0 {
		t.Errorf("rows = %d, want 0 after rejected creates", e.iposCount())
	}
}

func TestAdmin_Create_FR003_ValidationCodes(t *testing.T) {
	over := func(k string, v any) map[string]any { b := acmeBody(); b[k] = v; return b }
	cases := []struct {
		name string
		body map[string]any
		code string
		loc  string
	}{
		{"missing segments", map[string]any{"name": "X"}, "validation_failed", ""},
		{"missing name", map[string]any{"segments": []string{"NSE_MAINBOARD"}}, "validation_failed", ""},
		{"empty segments", over("segments", []string{}), "validation_failed", ""},
		{"fractional paise", over("price_band_cap_paise", 105000.5), "validation_failed", ""},
		{"lot size zero", over("lot_size", 0), "validation_failed", ""},
		{"http offer document", over("offer_document_url", "http://x.example/doc.pdf"), "validation_failed", ""},
		{"bad date", over("dates", map[string]any{"open_date": "2026-13-45", "close_date": nil, "allotment_date": nil, "refund_date": nil, "demat_credit_date": nil, "listing_date": nil}), "validation_failed", ""},
		{"blank name after trim", over("name", "   "), "ipo.invalid_value", "body.name"},
		{"only band floor", func() map[string]any { b := acmeBody(); delete(b, "price_band_cap_paise"); return b }(), "ipo.invalid_value", ""},
		{"floor above cap", over("price_band_floor_paise", 110_000), "ipo.invalid_value", ""},
		{"close before open", over("dates", map[string]any{"open_date": "2026-11-13", "close_date": "2026-11-11", "allotment_date": nil, "refund_date": nil, "demat_credit_date": nil, "listing_date": nil}), "ipo.date_order", "body.close_date"},
	}
	e := newHTTPEnv(t)
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := e.admin("POST", "/v1/admin/ipos", c.body, idemHdr(e.key()))
			wantProblem(t, r, 422, c.code)
			if c.loc != "" && !hasLoc(r.locations(), c.loc) {
				t.Errorf("errors[].location = %v, want to include %s", r.locations(), c.loc)
			}
			for _, bad := range []string{"105000.5", "   "} {
				if strings.Contains(string(r.Raw), `"value"`) && strings.Contains(string(r.Raw), bad) {
					t.Errorf("problem echoes the submitted value: %s", r.Raw)
				}
			}
		})
	}
	if e.iposCount() != 0 {
		t.Errorf("rows = %d, want 0 after rejected creates", e.iposCount())
	}
}

func hasLoc(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

func TestAdmin_Create_FR007_IdempotentReplay(t *testing.T) {
	e := newHTTPEnv(t)
	first := e.admin("POST", "/v1/admin/ipos", acmeBody(), idemHdr("same-key-0001"))
	wantHTTP(t, first, 201)
	second := e.admin("POST", "/v1/admin/ipos", acmeBody(), idemHdr("same-key-0001"))
	wantHTTP(t, second, 200)
	if first.str("id") == "" || first.str("id") != second.str("id") {
		t.Errorf("replay id = %q, want %q", second.str("id"), first.str("id"))
	}
	if e.iposCount() != 1 {
		t.Errorf("rows = %d, want 1", e.iposCount())
	}
	other := e.admin("POST", "/v1/admin/ipos", acmeBody(), idemHdr("other-key-0002"))
	wantHTTP(t, other, 201)
	if e.iposCount() != 2 {
		t.Errorf("rows = %d, want 2 with a different key", e.iposCount())
	}
}

func TestAdmin_Create_FR007_BadIdempotencyKeyRejected(t *testing.T) {
	e := newHTTPEnv(t)
	for _, k := range []string{"short", "has space in it", strings.Repeat("k", 201)} {
		r := e.admin("POST", "/v1/admin/ipos", acmeBody(), idemHdr(k))
		wantProblem(t, r, 422, "validation_failed")
	}
	if e.iposCount() != 0 {
		t.Errorf("rows = %d, want 0", e.iposCount())
	}
}

func TestAdmin_Get_FR009_AdminViewAndNotFound(t *testing.T) {
	e := newHTTPEnv(t)
	id := e.createAcme().str("id")
	r := e.admin("GET", "/v1/admin/ipos/"+id, nil)
	wantHTTP(t, r, 200)
	for _, k := range []string{"eligible", "published", "ever_published", "status_source", "status_changed_at", "source", "source_ref", "last_synced_at", "version", "created_at"} {
		if _, ok := r.M[k]; !ok {
			t.Errorf("admin IPO lacks %q: %s", k, r.Raw)
		}
	}
	if r.M["status_source"] != "schedule" {
		t.Errorf("status_source = %v, want schedule", r.M["status_source"])
	}
	wantProblem(t, e.admin("GET", "/v1/admin/ipos/"+uuid.NewString(), nil), 404, "not_found")
	wantProblem(t, e.admin("GET", "/v1/admin/ipos/not-a-uuid", nil), 422, "validation_failed")
}

func TestAdmin_Get_FR051_OtherOrgIsNotFound(t *testing.T) {
	e := newHTTPEnv(t)
	other := e.h.NewOrg("Other")
	d := minimalDraft("Foreign Ltd")
	res, err := e.svc.Create(e.ctx(), e.svcEnv.admin, other, d, e.key())
	if err != nil {
		t.Fatal(err)
	}
	wantProblem(t, e.admin("GET", "/v1/admin/ipos/"+res.IPO.ID.String(), nil), 404, "not_found")
}

func TestAdmin_List_FR009_FiltersAndOrder(t *testing.T) {
	e := newHTTPEnv(t)
	a := e.published(acme(), FlagApply)
	d2 := acme()
	d2.Name = "Beta Ltd"
	d2.Dates.Open = dt(12)
	b := e.create(d2)
	c := e.create(minimalDraft("No Dates Ltd"))

	r := e.admin("GET", "/v1/admin/ipos", nil)
	wantHTTP(t, r, 200)
	items, _ := r.M["items"].([]any)
	if len(items) != 3 {
		t.Fatalf("items = %d, want 3 (drafts included)", len(items))
	}
	wantOrder := []uuid.UUID{c.ID, b.ID, a.ID} // open_date DESC NULLS FIRST
	for i, id := range wantOrder {
		if items[i].(map[string]any)["id"] != id.String() {
			t.Errorf("item %d = %v, want %s (open_date DESC, nulls first)", i, items[i].(map[string]any)["name"], id)
		}
	}
	if r.M["next_cursor"] != nil {
		t.Errorf("next_cursor = %v, want null on the last page", r.M["next_cursor"])
	}
	count := func(q string) int {
		r := e.admin("GET", "/v1/admin/ipos?"+q, nil)
		wantHTTP(t, r, 200)
		its, _ := r.M["items"].([]any)
		return len(its)
	}
	for q, want := range map[string]int{
		"published=true": 1, "published=false": 2, "flag=APPLY": 1, "flag=NONE": 2, "flag=DO_NOT_APPLY": 0,
		"status=UPCOMING": 3, "status=OPEN": 0, "month=2026-11": 2, "month=2026-12": 0,
	} {
		if got := count(q); got != want {
			t.Errorf("?%s -> %d items, want %d", q, got, want)
		}
	}
}

func TestAdmin_List_FR009_CursorPaging(t *testing.T) {
	e := newHTTPEnv(t)
	seen := map[string]bool{}
	for i := 1; i <= 5; i++ {
		d := minimalDraft(fmt.Sprintf("Co %d", i))
		d.Dates.Open = dt(i)
		e.create(d)
	}
	cursor := ""
	pages := 0
	for {
		path := "/v1/admin/ipos?limit=2"
		if cursor != "" {
			path += "&cursor=" + cursor
		}
		r := e.admin("GET", path, nil)
		wantHTTP(t, r, 200)
		items, _ := r.M["items"].([]any)
		for _, it := range items {
			id := it.(map[string]any)["id"].(string)
			if seen[id] {
				t.Fatalf("id %s appears on two pages", id)
			}
			seen[id] = true
		}
		pages++
		next, _ := r.M["next_cursor"].(string)
		if next == "" {
			break
		}
		cursor = next
		if pages > 5 {
			t.Fatal("paging does not terminate")
		}
	}
	if len(seen) != 5 || pages != 3 {
		t.Errorf("seen %d ids over %d pages, want 5 over 3", len(seen), pages)
	}
}

func TestAdmin_List_FR009_BadQueryIs422(t *testing.T) {
	e := newHTTPEnv(t)
	for _, q := range []string{"limit=0", "limit=201", "cursor=%25%25bad", "month=2026-13", "month=nov", "status=WRONG", "flag=MAYBE", "published=perhaps"} {
		wantProblem(t, e.admin("GET", "/v1/admin/ipos?"+q, nil), 422, "validation_failed")
	}
}

func TestAdmin_Update_FR006_ReplacesFactsAndBumpsVersion(t *testing.T) {
	e := newHTTPEnv(t)
	created := e.admin("POST", "/v1/admin/ipos", map[string]any{"name": "Draft Ltd", "segments": []string{"NSE_MAINBOARD"}}, idemHdr(e.key()))
	id := created.str("id")
	body := putBody(1, map[string]any{
		"name": "Renamed Ltd", "lot_size": 14, "price_band_floor_paise": 100_000, "price_band_cap_paise": 105_000,
		"dates": map[string]any{"open_date": "2026-11-11", "close_date": "2026-11-13", "allotment_date": nil, "refund_date": nil, "demat_credit_date": nil, "listing_date": nil},
	})
	r := e.admin("PUT", "/v1/admin/ipos/"+id, body, idemHdr(e.key()))
	wantHTTP(t, r, 200)
	if r.str("name") != "Renamed Ltd" || r.version() != 2 || r.ipo()["min_application_paise"] != float64(1_470_000) {
		t.Errorf("updated = %v", r.ipo())
	}
	// null clears.
	r = e.admin("PUT", "/v1/admin/ipos/"+id, putBody(2, map[string]any{"name": "Renamed Ltd"}), idemHdr(e.key()))
	wantHTTP(t, r, 200)
	if r.ipo()["lot_size"] != nil || r.ipo()["price_band_cap_paise"] != nil {
		t.Errorf("null must clear: %v", r.ipo())
	}
}

func TestAdmin_Update_FR006_StaleVersion409(t *testing.T) {
	e := newHTTPEnv(t)
	id := e.createAcme().str("id")
	r := e.admin("PUT", "/v1/admin/ipos/"+id, putBody(7, map[string]any{"name": "Late"}), idemHdr(e.key()))
	wantProblem(t, r, 409, "ipo.stale_version")
	if got := e.admin("GET", "/v1/admin/ipos/"+id, nil).str2("name"); got != "Acme Ltd" {
		t.Errorf("name = %q after stale update, want Acme Ltd", got)
	}
}

func (r resp) str2(k string) string { s, _ := r.M[k].(string); return s }

func TestAdmin_Update_FR002_AllKeysRequired(t *testing.T) {
	e := newHTTPEnv(t)
	id := e.createAcme().str("id")
	for _, k := range []string{"version", "nse_symbol", "lot_size", "dates", "lead_managers", "offer_document_url", "registrar"} {
		b := putBody(1, nil)
		delete(b, k)
		wantProblem(t, e.admin("PUT", "/v1/admin/ipos/"+id, b, idemHdr(e.key())), 422, "validation_failed")
	}
	wantProblem(t, e.admin("PUT", "/v1/admin/ipos/"+id, putBody(0, nil), idemHdr(e.key())), 422, "validation_failed")
}

func TestAdmin_Update_BR_IPO_01_EditToSMERejected(t *testing.T) {
	e := newHTTPEnv(t)
	id := e.createAcme().str("id")
	r := e.admin("PUT", "/v1/admin/ipos/"+id, putBody(1, map[string]any{"segments": []string{"NSE_EMERGE"}}), idemHdr(e.key()))
	wantProblem(t, r, 422, "ipo.sme_not_allowed")
	if v := e.mustRow2(id); v != 1 {
		t.Errorf("version = %d, want unchanged 1", v)
	}
}

func (e *httpEnv) mustRow2(id string) int32 {
	u, _ := uuid.Parse(id)
	return e.mustRow(u).Version
}

func TestAdmin_Update_FR020_PublishedCannotLoseRequiredFacts(t *testing.T) {
	e := newHTTPEnv(t)
	ipo := e.published(acme(), FlagApply)
	r := e.admin("PUT", "/v1/admin/ipos/"+ipo.ID.String(), putBody(int(ipo.Version), map[string]any{"name": "Acme Ltd"}), idemHdr(e.key()))
	wantProblem(t, r, 422, "ipo.publish_incomplete")
	if locs := r.locations(); !hasLoc(locs, "body.lot_size") {
		t.Errorf("locations = %v, want body.lot_size among the missing items", locs)
	}
}

func TestAdmin_Update_FR007_ReplayReturns200WithoutSecondBump(t *testing.T) {
	e := newHTTPEnv(t)
	id := e.createAcme().str("id")
	body := putBody(1, map[string]any{"name": "Twice Ltd"})
	first := e.admin("PUT", "/v1/admin/ipos/"+id, body, idemHdr("update-key-01"))
	wantHTTP(t, first, 200)
	second := e.admin("PUT", "/v1/admin/ipos/"+id, body, idemHdr("update-key-01"))
	wantHTTP(t, second, 200)
	if second.version() != 2 || second.str("name") != "Twice Ltd" {
		t.Errorf("replay = %v, want version 2 and the updated name (current state)", second.ipo())
	}
}

func TestAdmin_Update_FR006_UnknownIDIs404(t *testing.T) {
	e := newHTTPEnv(t)
	wantProblem(t, e.admin("PUT", "/v1/admin/ipos/"+uuid.NewString(), putBody(1, nil), idemHdr(e.key())), 404, "not_found")
}

// ---- admin-only access (FR-050, US7.6, US7.7) ----

type adminOp struct{ method, path string }

func adminOps(id string) []adminOp {
	b := "/v1/admin/ipos"
	return []adminOp{
		{"POST", b}, {"GET", b}, {"GET", b + "/date-suggestions?close_date=2026-11-13"},
		{"GET", b + "/" + id}, {"PUT", b + "/" + id}, {"DELETE", b + "/" + id + "?version=1"},
		{"PUT", b + "/" + id + "/flag"}, {"POST", b + "/" + id + "/publish"}, {"POST", b + "/" + id + "/unpublish"},
		{"POST", b + "/" + id + "/status"},
	}
}

func TestAdminOps_FR050_ClientForbiddenAndNothingWritten(t *testing.T) {
	e := newHTTPEnv(t)
	id := e.createAcme().str("id")
	before := e.h.Count("audit_log", "entity = 'ipo'")
	for _, op := range adminOps(id) {
		var body any
		if op.method == "POST" || op.method == "PUT" {
			body = map[string]any{"version": 1}
		}
		r := e.do("client-token", op.method, op.path, body, idemHdr(e.key()))
		if r.Code != 403 || r.problemCode() != "auth.forbidden" {
			t.Errorf("client %s %s = %d %q, want 403 auth.forbidden", op.method, op.path, r.Code, r.problemCode())
		}
	}
	if e.iposCount() != 1 || e.mustRow2(id) != 1 || e.h.Count("audit_log", "entity = 'ipo'") != before {
		t.Error("a forbidden call changed state")
	}
}

func TestAdminOps_FR050_UnauthenticatedIs401(t *testing.T) {
	e := newHTTPEnv(t)
	id := e.createAcme().str("id")
	ops := adminOps(id)
	ops = append(ops, adminOp{"GET", "/v1/ipos"}, adminOp{"GET", "/v1/ipos/" + id})
	for _, tok := range []string{"", "garbage-token"} {
		for _, op := range ops {
			r := e.do(tok, op.method, op.path, nil)
			if r.Code != 401 || r.problemCode() != "auth.unauthenticated" {
				t.Errorf("token %q %s %s = %d %q, want 401 auth.unauthenticated", tok, op.method, op.path, r.Code, r.problemCode())
			}
		}
	}
}
