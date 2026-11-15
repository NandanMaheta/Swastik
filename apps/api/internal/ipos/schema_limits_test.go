package ipos

// Review fix: schema-level limits on array items, and a malformed month never gives 500.

import (
	"net/url"
	"strings"
	"testing"
)

func TestSchema_SegmentsItemMaxLength32(t *testing.T) {
	e := newHTTPEnv(t)
	long := strings.Repeat("X", 33)
	b := acmeBody()
	b["segments"] = []string{"NSE_MAINBOARD", long}
	r := e.admin("POST", "/v1/admin/ipos", b, idemHdr(e.key()))
	wantProblem(t, r, 422, "validation_failed")
	if !strings.Contains(strings.Join(r.locations(), ","), "segments") {
		t.Errorf("locations = %v, want one under body.segments", r.locations())
	}
	id := e.draftID()
	wantProblem(t, e.admin("PUT", "/v1/admin/ipos/"+id, putBody(1, map[string]any{"segments": []string{long}}), idemHdr(e.key())), 422, "validation_failed")
	// 32 characters pass the schema and reach service validation.
	ok32 := strings.Repeat("X", 32)
	b["segments"] = []string{ok32}
	wantProblem(t, e.admin("POST", "/v1/admin/ipos", b, idemHdr(e.key())), 422, "ipo.invalid_segment")
}

func TestSchema_SegmentDuplicatesAndUnknownStillServiceCodes(t *testing.T) {
	e := newHTTPEnv(t)
	b := acmeBody()
	b["segments"] = []string{"NSE_MAINBOARD", "NSE_MAINBOARD"}
	wantProblem(t, e.admin("POST", "/v1/admin/ipos", b, idemHdr(e.key())), 422, "ipo.invalid_segment")
}

func TestSchema_LeadManagersItemLimits(t *testing.T) {
	e := newHTTPEnv(t)
	b := acmeBody()
	b["lead_managers"] = []string{strings.Repeat("L", 201)}
	wantProblem(t, e.admin("POST", "/v1/admin/ipos", b, idemHdr(e.key())), 422, "validation_failed")
	id := e.draftID()
	wantProblem(t, e.admin("PUT", "/v1/admin/ipos/"+id, putBody(1, map[string]any{"lead_managers": []string{strings.Repeat("L", 201)}}), idemHdr(e.key())), 422, "validation_failed")
	// An empty item is rejected at the schema (minLength 1); whitespace-only reaches the service.
	b["lead_managers"] = []string{""}
	if r := e.admin("POST", "/v1/admin/ipos", b, idemHdr(e.key())); r.Code != 422 {
		t.Errorf("empty lead manager: %d %s", r.Code, r.Raw)
	}
	b["lead_managers"] = []string{"   "}
	wantProblem(t, e.admin("POST", "/v1/admin/ipos", b, idemHdr(e.key())), 422, "ipo.invalid_value")
	b["lead_managers"] = []string{strings.Repeat("L", 200)}
	wantHTTP(t, e.admin("POST", "/v1/admin/ipos", b, idemHdr(e.key())), 201)
}

func TestSchema_ItemLimitsAreInTheOpenAPIDocument(t *testing.T) {
	e := newHTTPEnv(t)
	for _, name := range []string{"IPODraft", "IPOReplace"} {
		s := e.api.OpenAPI().Components.Schemas.Map()[name]
		if s == nil {
			t.Fatalf("schema %s missing", name)
		}
		seg, lm := s.Properties["segments"], s.Properties["lead_managers"]
		if seg == nil || seg.Items == nil || seg.Items.MaxLength == nil || *seg.Items.MaxLength != 32 {
			t.Errorf("%s.segments items maxLength must be 32", name)
		}
		if lm == nil || lm.Items == nil || lm.Items.MaxLength == nil || *lm.Items.MaxLength != 200 || lm.Items.MinLength == nil || *lm.Items.MinLength != 1 {
			t.Errorf("%s.lead_managers items must have minLength 1 and maxLength 200", name)
		}
	}
}

func TestAdmin_List_MalformedMonthNeverGives500(t *testing.T) {
	e := newHTTPEnv(t)
	for _, m := range []string{"0000-01", "0000-12", "9999-12", "9999-01", "2026-00", "2026-13", "26-11", "2026-1", "nov", "2026-11-01", "%20", "２０２６-１１"} {
		r := e.admin("GET", "/v1/admin/ipos?month="+url.QueryEscape(m), nil)
		if r.Code >= 500 {
			t.Errorf("month=%q gave %d: %s", m, r.Code, r.Raw)
		}
	}
	for _, m := range []string{"2026-13", "2026-00", "nov", "2026-1"} {
		wantProblem(t, e.admin("GET", "/v1/admin/ipos?month="+m, nil), 422, "validation_failed")
	}
}
