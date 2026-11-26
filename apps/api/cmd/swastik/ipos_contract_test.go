package main

// S16 - the 008 OpenAPI contract (plan "API operations", contracts/ipos.openapi.yaml; FR-050, FR-051,
// FR-007, SC-007). buildAPI(deps{}) must register Register(api, nil-service) like the auth module:
// the static walk and `swastik openapi` run without a database. 003's walk covers the 401/403 runtime
// behaviour once the admin ids are in testdata/admin-operations.txt (done by the implementer).

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

type iposOp struct {
	id, method, path string
	admin            bool
}

var iposOperations = []iposOp{
	{"ipos-create", http.MethodPost, "/v1/admin/ipos", true},
	{"ipos-admin-list", http.MethodGet, "/v1/admin/ipos", true},
	{"ipos-suggest-dates", http.MethodGet, "/v1/admin/ipos/date-suggestions", true},
	{"ipos-admin-get", http.MethodGet, "/v1/admin/ipos/{ipoId}", true},
	{"ipos-update", http.MethodPut, "/v1/admin/ipos/{ipoId}", true},
	{"ipos-delete", http.MethodDelete, "/v1/admin/ipos/{ipoId}", true},
	{"ipos-set-flag", http.MethodPut, "/v1/admin/ipos/{ipoId}/flag", true},
	{"ipos-publish", http.MethodPost, "/v1/admin/ipos/{ipoId}/publish", true},
	{"ipos-unpublish", http.MethodPost, "/v1/admin/ipos/{ipoId}/unpublish", true},
	{"ipos-override-status", http.MethodPost, "/v1/admin/ipos/{ipoId}/status", true},
	{"ipos-list", http.MethodGet, "/v1/ipos", false},
	{"ipos-get", http.MethodGet, "/v1/ipos/{ipoId}", false},
}

func iposWalked(t *testing.T) map[string]walkedOp {
	t.Helper()
	got := map[string]walkedOp{}
	for _, o := range staticAPI(t) {
		if strings.HasPrefix(o.ID, "ipos-") {
			got[o.ID] = o
		}
	}
	return got
}

func TestIPOContract_TwelveOperationsWithExactMethodAndPath(t *testing.T) {
	got := iposWalked(t)
	if len(got) != len(iposOperations) {
		var ids []string
		for id := range got {
			ids = append(ids, id)
		}
		t.Errorf("registered ipos-* operations = %v, want exactly the 12 of the contract", ids)
	}
	for _, want := range iposOperations {
		o, ok := got[want.id]
		if !ok {
			t.Errorf("operation %s is not registered", want.id)
			continue
		}
		if o.Method != want.method || o.Path != want.path {
			t.Errorf("%s = %s %s, want %s %s", want.id, o.Method, o.Path, want.method, want.path)
		}
	}
}

func TestIPOContract_SecurityPerOperation(t *testing.T) {
	got := iposWalked(t)
	for _, want := range iposOperations {
		o, ok := got[want.id]
		if !ok {
			t.Errorf("operation %s is not registered", want.id)
			continue
		}
		scheme, roles := schemeOf(o)
		if scheme != "bearer" {
			t.Errorf("%s scheme = %q, want bearer", want.id, scheme)
		}
		if want.admin && !slices.Equal(roles, []string{"admin"}) {
			t.Errorf("%s roles = %v, want [admin] (FR-050)", want.id, roles)
		}
		if !want.admin && len(roles) != 0 {
			t.Errorf("%s roles = %v, want any signed-in user", want.id, roles)
		}
		if len(o.Security) != 1 {
			t.Errorf("%s declares %d security requirements, want exactly 1", want.id, len(o.Security))
		}
	}
}

func TestIPOContract_EveryMutationTakesAnIdempotencyKey(t *testing.T) {
	got := iposWalked(t)
	for _, want := range iposOperations {
		o, ok := got[want.id]
		if !ok || want.method == http.MethodGet {
			continue
		}
		found := false
		for _, p := range o.Op.Parameters {
			if p != nil && p.In == "header" && p.Name == "Idempotency-Key" {
				found = true
				if p.Required {
					t.Errorf("%s: Idempotency-Key must be optional", want.id)
				}
				if s := p.Schema; s != nil && (s.MinLength == nil || *s.MinLength != 8 || s.MaxLength == nil || *s.MaxLength != 200) {
					t.Errorf("%s: Idempotency-Key must be 8 to 200 characters", want.id)
				}
			}
		}
		if !found {
			t.Errorf("%s has no Idempotency-Key header parameter (FR-007)", want.id)
		}
	}
	for _, o := range iposWalked(t) {
		if o.Method == http.MethodGet {
			for _, p := range o.Op.Parameters {
				if p != nil && p.Name == "Idempotency-Key" {
					t.Errorf("%s: a read must not take Idempotency-Key", o.ID)
				}
			}
		}
	}
}

func TestIPOContract_DeleteTakesVersionQuery(t *testing.T) {
	o, ok := iposWalked(t)["ipos-delete"]
	if !ok {
		t.Fatal("ipos-delete is not registered")
	}
	for _, p := range o.Op.Parameters {
		if p != nil && p.In == "query" && p.Name == "version" && p.Required {
			if _, has := o.Op.Responses["204"]; !has {
				t.Error("ipos-delete must document 204")
			}
			return
		}
	}
	t.Error("ipos-delete lacks a required `version` query parameter")
}

func TestIPOContract_SuccessStatusCodes(t *testing.T) {
	got := iposWalked(t)
	want := map[string][]string{
		"ipos-create": {"201", "200"}, "ipos-update": {"200"}, "ipos-publish": {"200"}, "ipos-unpublish": {"200"},
		"ipos-set-flag": {"200"}, "ipos-override-status": {"200"}, "ipos-delete": {"204"},
		"ipos-list": {"200"}, "ipos-get": {"200"}, "ipos-admin-list": {"200"}, "ipos-admin-get": {"200"}, "ipos-suggest-dates": {"200"},
	}
	for id, codes := range want {
		o, ok := got[id]
		if !ok {
			t.Errorf("operation %s is not registered", id)
			continue
		}
		for _, c := range codes {
			if _, has := o.Op.Responses[c]; !has {
				t.Errorf("%s does not document %s", id, c)
			}
		}
	}
}

// schemas returns components.schemas of the generated document as plain JSON.
func schemas(t *testing.T) map[string]map[string]any {
	t.Helper()
	b, err := json.Marshal(buildAPI(deps{}).OpenAPI())
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Components struct {
			Schemas map[string]map[string]any `json:"schemas"`
		} `json:"components"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	return doc.Components.Schemas
}

func propsOf(t *testing.T, all map[string]map[string]any, name string) map[string]any {
	t.Helper()
	s, ok := all[name]
	if !ok {
		t.Fatalf("schema %s is missing", name)
	}
	p, _ := s["properties"].(map[string]any)
	if p == nil {
		t.Fatalf("schema %s has no properties", name)
	}
	return p
}

func TestIPOContract_ClientIPOHidesAdminFields(t *testing.T) {
	all := schemas(t)
	client := propsOf(t, all, "ClientIPO")
	for _, k := range []string{"source", "source_ref", "last_synced_at", "status_source", "status_changed_at", "version", "published", "ever_published", "eligible", "created_at"} {
		if _, has := client[k]; has {
			t.Errorf("ClientIPO exposes %q (FR-051)", k)
		}
	}
	for _, k := range []string{"id", "name", "segments", "status", "apply_flag", "flag_note", "min_application_paise", "dates", "lot_size", "updated_at"} {
		if _, has := client[k]; !has {
			t.Errorf("ClientIPO lacks %q", k)
		}
	}
}

func TestIPOContract_AdminIPOCarriesAdminFields(t *testing.T) {
	admin := propsOf(t, schemas(t), "AdminIPO")
	for _, k := range []string{"id", "name", "apply_flag", "flag_note", "eligible", "published", "ever_published", "status_source", "status_changed_at", "source", "source_ref", "last_synced_at", "version", "created_at"} {
		if _, has := admin[k]; !has {
			t.Errorf("AdminIPO lacks %q", k)
		}
	}
}

func TestIPOContract_SegmentsInputHasNoEnum(t *testing.T) {
	// R-05: an enum would turn ipo.sme_not_allowed and ipo.invalid_segment into generic
	// validation_failed responses, so the request schema takes any short string.
	draft := propsOf(t, schemas(t), "IPODraft")
	seg, _ := draft["segments"].(map[string]any)
	items, _ := seg["items"].(map[string]any)
	if seg == nil || items == nil {
		t.Fatalf("IPODraft.segments = %v, want an array with items", seg)
	}
	if _, has := items["enum"]; has {
		t.Errorf("IPODraft.segments items carry an enum: %v", items)
	}
	req, _ := schemas(t)["IPODraft"]["required"].([]any)
	if len(req) < 2 || !slices.Contains(req, any("name")) || !slices.Contains(req, any("segments")) {
		t.Errorf("IPODraft.required = %v, want name and segments", req)
	}
}

func TestIPOContract_MutationResultAndPages(t *testing.T) {
	all := schemas(t)
	for _, n := range []string{"IPOMutationResult", "AdminIPOPage", "ClientIPOPage", "DateSuggestion", "Warning"} {
		if _, ok := all[n]; !ok {
			t.Errorf("schema %s is missing", n)
		}
	}
	if p := propsOf(t, all, "IPOMutationResult"); p["ipo"] == nil || p["warnings"] == nil {
		t.Errorf("IPOMutationResult = %v, want ipo and warnings", p)
	}
	if p := propsOf(t, all, "ClientIPOPage"); p["items"] == nil || p["next_cursor"] == nil {
		t.Errorf("ClientIPOPage = %v, want items and next_cursor", p)
	}
}

func TestIPOContract_CommittedSpecIsCurrentAndCarriesTheOperations(t *testing.T) {
	committed, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "packages", "api-client", "openapi.yaml"))
	if err != nil {
		t.Fatalf("read packages/api-client/openapi.yaml: %v", err)
	}
	for _, op := range iposOperations {
		if !strings.Contains(string(committed), "operationId: "+op.id) {
			t.Errorf("packages/api-client/openapi.yaml lacks %s: run `go run ./cmd/swastik openapi > packages/api-client/openapi.yaml` and regenerate the client", op.id)
		}
	}
	spec, err := buildAPI(deps{}).OpenAPI().YAML()
	if err != nil {
		t.Fatal(err)
	}
	if string(spec) != string(committed) {
		t.Error("`swastik openapi` differs from packages/api-client/openapi.yaml; regenerate and commit both")
	}
}

func TestIPOContract_AdminOperationsAreOnTheWalkAllowlist(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("testdata", "admin-operations.txt"))
	if err != nil {
		t.Fatal(err)
	}
	listed := strings.Fields(strings.Join(slices.DeleteFunc(strings.Split(string(b), "\n"), func(l string) bool { return strings.HasPrefix(strings.TrimSpace(l), "#") }), "\n"))
	for _, op := range iposOperations {
		if op.admin && !slices.Contains(listed, op.id) {
			t.Errorf("testdata/admin-operations.txt lacks %s, so 003's walk would not probe it for 403", op.id)
		}
	}
}
