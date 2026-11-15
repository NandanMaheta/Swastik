package ipos

// S15 - HTTP tests A (client): ipos-list and ipos-get show published IPOs only, never admin
// fields, and treat drafts exactly like unknown ids (US7.1-7.7, FR-050, FR-051).

import (
	"bytes"
	"fmt"
	"sort"
	"testing"

	"github.com/google/uuid"
)

var clientKeys = []string{
	"apply_flag", "dates", "flag_note", "id", "issue_price_paise", "issue_size_paise", "lead_managers", "lot_size",
	"min_application_paise", "name", "nse_symbol", "offer_document_url", "price_band_cap_paise",
	"price_band_floor_paise", "registrar", "segments", "status", "updated_at",
}

func (e *httpEnv) fiveIPOs() (published []IPO, drafts []IPO) {
	e.t.Helper()
	for i := 1; i <= 5; i++ {
		d := acme()
		d.Name = fmt.Sprintf("Co %d", i)
		d.Dates.Open = dt(i)
		if i <= 3 {
			published = append(published, e.published(d, FlagApply))
		} else {
			drafts = append(drafts, e.create(d))
		}
	}
	return published, drafts
}

func TestClient_BR_IPO_02_OnlyPublished(t *testing.T) {
	e := newHTTPEnv(t)
	pub, _ := e.fiveIPOs()
	r := e.client("GET", "/v1/ipos")
	wantHTTP(t, r, 200)
	items, _ := r.M["items"].([]any)
	if len(items) != 3 {
		t.Fatalf("items = %d, want exactly the 3 published of 5 (US7.1)", len(items))
	}
	got := map[string]bool{}
	for _, it := range items {
		got[it.(map[string]any)["id"].(string)] = true
	}
	for _, p := range pub {
		if !got[p.ID.String()] {
			t.Errorf("published %s missing from the client list", p.Name)
		}
	}
	// an admin token is a signed-in user too.
	wantHTTP(t, e.admin("GET", "/v1/ipos", nil), 200)
}

func TestClient_BR_IPO_02_StatusFilter(t *testing.T) {
	e := newHTTPEnv(t)
	pub, _ := e.fiveIPOs()
	e.override(pub[0], StatusOpen, "opened")
	r := e.client("GET", "/v1/ipos?status=OPEN")
	wantHTTP(t, r, 200)
	if items, _ := r.M["items"].([]any); len(items) != 1 {
		t.Errorf("status=OPEN items = %d, want 1 (US7.2)", len(items))
	}
	wantProblem(t, e.client("GET", "/v1/ipos?status=WRONG"), 422, "validation_failed")
}

func TestClient_FR009_CursorAndLimit(t *testing.T) {
	e := newHTTPEnv(t)
	e.fiveIPOs()
	r := e.client("GET", "/v1/ipos?limit=2")
	wantHTTP(t, r, 200)
	first, _ := r.M["items"].([]any)
	next, _ := r.M["next_cursor"].(string)
	if len(first) != 2 || next == "" {
		t.Fatalf("page 1 = %d items, cursor %q, want 2 and a cursor", len(first), next)
	}
	r = e.client("GET", "/v1/ipos?limit=2&cursor="+next)
	wantHTTP(t, r, 200)
	second, _ := r.M["items"].([]any)
	if len(second) != 1 || r.M["next_cursor"] != nil {
		t.Errorf("page 2 = %d items, cursor %v, want 1 and null", len(second), r.M["next_cursor"])
	}
	if first[0].(map[string]any)["id"] == second[0].(map[string]any)["id"] || first[1].(map[string]any)["id"] == second[0].(map[string]any)["id"] {
		t.Error("page 2 repeats an item of page 1")
	}
	for _, q := range []string{"limit=0", "limit=201", "cursor=%25%25bad"} {
		wantProblem(t, e.client("GET", "/v1/ipos?"+q), 422, "validation_failed")
	}
}

func TestClient_FR051_NoAdminFields(t *testing.T) {
	e := newHTTPEnv(t)
	pub, _ := e.fiveIPOs()
	keysOf := func(m map[string]any) []string {
		var ks []string
		for k := range m {
			ks = append(ks, k)
		}
		sort.Strings(ks)
		return ks
	}
	get := e.client("GET", "/v1/ipos/"+pub[0].ID.String())
	wantHTTP(t, get, 200)
	if got := keysOf(get.M); fmt.Sprint(got) != fmt.Sprint(clientKeys) {
		t.Errorf("ipos-get keys = %v\nwant %v", got, clientKeys)
	}
	list := e.client("GET", "/v1/ipos")
	items, _ := list.M["items"].([]any)
	if got := keysOf(items[0].(map[string]any)); fmt.Sprint(got) != fmt.Sprint(clientKeys) {
		t.Errorf("ipos-list item keys = %v\nwant %v", got, clientKeys)
	}
	if get.M["apply_flag"] != "APPLY" || get.M["min_application_paise"] != float64(1_470_000) {
		t.Errorf("client view = %v, want the flag and the minimum application value", get.M)
	}
}

func TestClient_BR_IPO_02_DraftLooksUnknown(t *testing.T) {
	e := newHTTPEnv(t)
	_, drafts := e.fiveIPOs()
	draft := e.client("GET", "/v1/ipos/"+drafts[0].ID.String())
	unknown := e.client("GET", "/v1/ipos/"+uuid.NewString())
	wantProblem(t, draft, 404, "not_found")
	wantProblem(t, unknown, 404, "not_found")
	if !bytes.Equal(normalise(draft.Raw), normalise(unknown.Raw)) {
		t.Errorf("draft and unknown bodies differ (US7.3):\n%s\n%s", draft.Raw, unknown.Raw)
	}
	wantProblem(t, e.client("GET", "/v1/ipos/not-a-uuid"), 422, "validation_failed")
}

// normalise drops nothing: the contract says the bodies are byte-identical. The helper exists so
// a future per-request field (such as a trace id) is a deliberate, visible change.
func normalise(b []byte) []byte { return b }

func TestClient_BR_IPO_02_UnpublishHidesNextRead(t *testing.T) {
	e := newHTTPEnv(t)
	pub, _ := e.fiveIPOs()
	path := "/v1/ipos/" + pub[0].ID.String()
	wantHTTP(t, e.client("GET", path), 200)
	wantHTTP(t, e.admin("POST", "/v1/admin/ipos/"+pub[0].ID.String()+"/unpublish", ver(int(pub[0].Version)), idemHdr(e.key())), 200)
	wantProblem(t, e.client("GET", path), 404, "not_found")
	if items, _ := e.client("GET", "/v1/ipos").M["items"].([]any); len(items) != 2 {
		t.Errorf("list after unpublish = %d items, want 2", len(items))
	}
}

func TestClient_FR050_OtherOrgPublishedIsNotVisible(t *testing.T) {
	e := newHTTPEnv(t)
	other := e.h.NewOrg("Other")
	res, err := e.svc.Create(e.ctx(), e.svcEnv.admin, other, acme(), e.key())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.SetFlag(e.ctx(), e.svcEnv.admin, other, res.IPO.ID, res.IPO.Version, flagPtr(FlagApply), nil, e.key()); err != nil {
		t.Fatal(err)
	}
	wantProblem(t, e.client("GET", "/v1/ipos/"+res.IPO.ID.String()), 404, "not_found")
}
