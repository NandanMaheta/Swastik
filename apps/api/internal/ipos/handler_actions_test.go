package ipos

// S15 - HTTP tests A (actions): publish, unpublish, flag, status override, delete, date
// suggestions, listener rejection mapping (contracts/error-codes.md).

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"testing"

	"github.com/google/uuid"
)

type rejectingListener struct{ err error }

func (r rejectingListener) OnIPOEligibilityChanged(context.Context, EligibilityChanged) error {
	return r.err
}

func (e *httpEnv) draftID() string { return e.createAcme().str("id") }

func ver(v int) map[string]any { return map[string]any{"version": v} }

func TestActions_SetFlag_BR_IPO_02(t *testing.T) {
	e := newHTTPEnv(t)
	id := e.draftID()
	r := e.admin("PUT", "/v1/admin/ipos/"+id+"/flag", map[string]any{"version": 1, "apply_flag": "APPLY", "flag_note": "Strong GMP"}, idemHdr(e.key()))
	wantHTTP(t, r, 200)
	if r.str("apply_flag") != "APPLY" || r.str("flag_note") != "Strong GMP" || r.version() != 2 || r.ipo()["eligible"] != false {
		t.Errorf("flagged = %v, want APPLY, note, version 2, not eligible while unpublished", r.ipo())
	}
	r = e.admin("PUT", "/v1/admin/ipos/"+id+"/flag", map[string]any{"version": 2, "apply_flag": nil, "flag_note": nil}, idemHdr(e.key()))
	wantHTTP(t, r, 200)
	if r.ipo()["apply_flag"] != nil {
		t.Errorf("cleared flag = %v, want null", r.ipo()["apply_flag"])
	}
}

func TestActions_SetFlag_FR022_Errors(t *testing.T) {
	e := newHTTPEnv(t)
	id := e.draftID()
	flagPath := "/v1/admin/ipos/" + id + "/flag"
	wantProblem(t, e.admin("PUT", flagPath, map[string]any{"version": 1, "apply_flag": nil, "flag_note": "orphan note"}, idemHdr(e.key())), 422, "ipo.invalid_value")
	wantProblem(t, e.admin("PUT", flagPath, map[string]any{"version": 1, "apply_flag": "MAYBE", "flag_note": nil}, idemHdr(e.key())), 422, "validation_failed")
	wantProblem(t, e.admin("PUT", flagPath, map[string]any{"version": 1, "apply_flag": "APPLY"}, idemHdr(e.key())), 422, "validation_failed") // flag_note key required
	wantProblem(t, e.admin("PUT", flagPath, map[string]any{"version": 1, "apply_flag": "APPLY", "flag_note": strings.Repeat("n", 501)}, idemHdr(e.key())), 422, "validation_failed")
	wantProblem(t, e.admin("PUT", flagPath, map[string]any{"version": 9, "apply_flag": "APPLY", "flag_note": nil}, idemHdr(e.key())), 409, "ipo.stale_version")
	wantProblem(t, e.admin("PUT", "/v1/admin/ipos/"+uuid.NewString()+"/flag", map[string]any{"version": 1, "apply_flag": "APPLY", "flag_note": nil}, idemHdr(e.key())), 404, "not_found")
}

func TestActions_SetFlag_FR020_ClearOnPublishedIsIncomplete(t *testing.T) {
	e := newHTTPEnv(t)
	ipo := e.published(acme(), FlagApply)
	r := e.admin("PUT", "/v1/admin/ipos/"+ipo.ID.String()+"/flag", map[string]any{"version": ipo.Version, "apply_flag": nil, "flag_note": nil}, idemHdr(e.key()))
	wantProblem(t, r, 422, "ipo.publish_incomplete")
	if !hasLoc(r.locations(), "body.apply_flag") {
		t.Errorf("locations = %v, want body.apply_flag", r.locations())
	}
}

func TestActions_Publish_BR_IPO_02_PublishAndUnpublish(t *testing.T) {
	e := newHTTPEnv(t)
	id := e.draftID()
	wantHTTP(t, e.admin("PUT", "/v1/admin/ipos/"+id+"/flag", map[string]any{"version": 1, "apply_flag": "APPLY", "flag_note": nil}, idemHdr(e.key())), 200)

	r := e.admin("POST", "/v1/admin/ipos/"+id+"/publish", ver(2), idemHdr(e.key()))
	wantHTTP(t, r, 200)
	if r.ipo()["published"] != true || r.ipo()["eligible"] != true || r.ipo()["ever_published"] != true || r.version() != 3 {
		t.Errorf("published = %v, want published, eligible, ever_published, version 3", r.ipo())
	}
	wantProblem(t, e.admin("POST", "/v1/admin/ipos/"+id+"/publish", ver(3), idemHdr(e.key())), 409, "ipo.no_change")

	r = e.admin("POST", "/v1/admin/ipos/"+id+"/unpublish", ver(3), idemHdr(e.key()))
	wantHTTP(t, r, 200)
	if r.ipo()["published"] != false || r.ipo()["eligible"] != false || r.ipo()["ever_published"] != true {
		t.Errorf("unpublished = %v", r.ipo())
	}
	wantProblem(t, e.admin("POST", "/v1/admin/ipos/"+id+"/unpublish", ver(4), idemHdr(e.key())), 409, "ipo.no_change")
}

func TestActions_Publish_FR020_IncompleteListsEveryMissingItem(t *testing.T) {
	e := newHTTPEnv(t)
	r0 := e.admin("POST", "/v1/admin/ipos", map[string]any{"name": "Bare Ltd", "segments": []string{"NSE_MAINBOARD"}}, idemHdr(e.key()))
	r := e.admin("POST", "/v1/admin/ipos/"+r0.str("id")+"/publish", ver(1), idemHdr(e.key()))
	wantProblem(t, r, 422, "ipo.publish_incomplete")
	for _, want := range []string{"body.apply_flag", "body.open_date", "body.close_date", "body.price", "body.lot_size"} {
		if !hasLoc(r.locations(), want) {
			t.Errorf("locations = %v, want %s", r.locations(), want)
		}
	}
	if e.mustRow(uuid.MustParse(r0.str("id"))).Published {
		t.Error("an incomplete publish must not publish")
	}
}

func TestActions_Publish_FR005_WarningCarried(t *testing.T) {
	e := newHTTPEnv(t)
	b := acmeBody()
	b["price_band_cap_paise"] = 200_000
	id := e.admin("POST", "/v1/admin/ipos", b, idemHdr(e.key())).str("id")
	wantHTTP(t, e.admin("PUT", "/v1/admin/ipos/"+id+"/flag", map[string]any{"version": 1, "apply_flag": "APPLY", "flag_note": nil}, idemHdr(e.key())), 200)
	r := e.admin("POST", "/v1/admin/ipos/"+id+"/publish", ver(2), idemHdr(e.key()))
	wantHTTP(t, r, 200)
	if len(r.warnings()) != 1 {
		t.Errorf("warnings = %v, want the out-of-range warning (US3.9)", r.warnings())
	}
}

func TestActions_Publish_FR006_StaleAndBodyErrors(t *testing.T) {
	e := newHTTPEnv(t)
	id := e.draftID()
	wantProblem(t, e.admin("POST", "/v1/admin/ipos/"+id+"/publish", ver(5), idemHdr(e.key())), 409, "ipo.stale_version")
	wantProblem(t, e.admin("POST", "/v1/admin/ipos/"+id+"/publish", map[string]any{}, idemHdr(e.key())), 422, "validation_failed")
	wantProblem(t, e.admin("POST", "/v1/admin/ipos/"+id+"/publish", ver(0), idemHdr(e.key())), 422, "validation_failed")
	wantProblem(t, e.admin("POST", "/v1/admin/ipos/"+uuid.NewString()+"/publish", ver(1), idemHdr(e.key())), 404, "not_found")
	wantProblem(t, e.admin("POST", "/v1/admin/ipos/"+uuid.NewString()+"/unpublish", ver(1), idemHdr(e.key())), 404, "not_found")
}

func TestActions_Publish_FR007_ReplayReturnsCurrentState(t *testing.T) {
	e := newHTTPEnv(t)
	id := e.draftID()
	wantHTTP(t, e.admin("PUT", "/v1/admin/ipos/"+id+"/flag", map[string]any{"version": 1, "apply_flag": "APPLY", "flag_note": nil}, idemHdr(e.key())), 200)
	first := e.admin("POST", "/v1/admin/ipos/"+id+"/publish", ver(2), idemHdr("publish-key-01"))
	wantHTTP(t, first, 200)
	again := e.admin("POST", "/v1/admin/ipos/"+id+"/publish", ver(2), idemHdr("publish-key-01"))
	wantHTTP(t, again, 200)
	if again.version() != 3 || again.ipo()["published"] != true {
		t.Errorf("replay = %v, want the current state (version 3, published)", again.ipo())
	}
	if n := e.h.Count("audit_log", "entity = 'ipo' AND entity_id = $1 AND action LIKE '%publish%'", uuid.MustParse(id)); n != 1 {
		t.Errorf("publish audit rows = %d, want 1", n)
	}
}

func TestActions_Override_BR_IPO_03(t *testing.T) {
	e := newHTTPEnv(t)
	id := e.draftID()
	p := "/v1/admin/ipos/" + id + "/status"
	r := e.admin("POST", p, map[string]any{"version": 1, "status": "CLOSED", "reason": "Closed early by exchange"}, idemHdr(e.key()))
	wantHTTP(t, r, 200)
	if r.str("status") != "CLOSED" || r.str("status_source") != "admin" || r.version() != 2 {
		t.Errorf("override = %v, want CLOSED by admin, version 2", r.ipo())
	}
	wantProblem(t, e.admin("POST", p, map[string]any{"version": 2, "status": "CLOSED", "reason": "again"}, idemHdr(e.key())), 409, "ipo.no_change")
	wantProblem(t, e.admin("POST", p, map[string]any{"version": 9, "status": "OPEN", "reason": "x"}, idemHdr(e.key())), 409, "ipo.stale_version")
	// backward and SETTLED are allowed with a reason.
	wantHTTP(t, e.admin("POST", p, map[string]any{"version": 2, "status": "UPCOMING", "reason": "reopened"}, idemHdr(e.key())), 200)
	r = e.admin("POST", p, map[string]any{"version": 3, "status": "SETTLED", "reason": "settled by hand"}, idemHdr(e.key()))
	wantHTTP(t, r, 200)
}

func TestActions_Override_FR035_ReasonAndStatusValidation(t *testing.T) {
	e := newHTTPEnv(t)
	id := e.draftID()
	p := "/v1/admin/ipos/" + id + "/status"
	wantProblem(t, e.admin("POST", p, map[string]any{"version": 1, "status": "OPEN"}, idemHdr(e.key())), 422, "validation_failed")
	wantProblem(t, e.admin("POST", p, map[string]any{"version": 1, "status": "OPEN", "reason": ""}, idemHdr(e.key())), 422, "validation_failed")
	wantProblem(t, e.admin("POST", p, map[string]any{"version": 1, "status": "OPEN", "reason": "   "}, idemHdr(e.key())), 422, "ipo.invalid_value")
	wantProblem(t, e.admin("POST", p, map[string]any{"version": 1, "status": "BOGUS", "reason": "x"}, idemHdr(e.key())), 422, "validation_failed")
	wantProblem(t, e.admin("POST", p, map[string]any{"version": 1, "status": "OPEN", "reason": strings.Repeat("r", 501)}, idemHdr(e.key())), 422, "validation_failed")
	wantProblem(t, e.admin("POST", "/v1/admin/ipos/"+uuid.NewString()+"/status", map[string]any{"version": 1, "status": "OPEN", "reason": "x"}, idemHdr(e.key())), 404, "not_found")
	if e.mustRow2(id) != 1 {
		t.Error("a rejected override changed the version")
	}
}

func TestActions_Override_FR007_Replay(t *testing.T) {
	e := newHTTPEnv(t)
	id := e.draftID()
	p := "/v1/admin/ipos/" + id + "/status"
	body := map[string]any{"version": 1, "status": "OPEN", "reason": "opened early"}
	wantHTTP(t, e.admin("POST", p, body, idemHdr("override-key-1")), 200)
	r := e.admin("POST", p, body, idemHdr("override-key-1"))
	wantHTTP(t, r, 200)
	if r.str("status") != "OPEN" || r.version() != 2 {
		t.Errorf("replay = %v, want OPEN at version 2", r.ipo())
	}
}

func TestActions_Delete_FR008_DraftIs204(t *testing.T) {
	e := newHTTPEnv(t)
	id := e.draftID()
	r := e.admin("DELETE", "/v1/admin/ipos/"+id+"?version=1", nil, idemHdr("delete-key-01"))
	wantHTTP(t, r, 204)
	if _, ok := e.row(uuid.MustParse(id)); ok {
		t.Error("draft still exists after delete")
	}
	wantHTTP(t, e.admin("DELETE", "/v1/admin/ipos/"+id+"?version=1", nil, idemHdr("delete-key-01")), 204) // replay
	wantProblem(t, e.admin("GET", "/v1/admin/ipos/"+id, nil), 404, "not_found")
	wantProblem(t, e.admin("DELETE", "/v1/admin/ipos/"+id+"?version=1", nil, idemHdr(e.key())), 404, "not_found")
}

func TestActions_Delete_FR008_Errors(t *testing.T) {
	e := newHTTPEnv(t)
	id := e.draftID()
	wantProblem(t, e.admin("DELETE", "/v1/admin/ipos/"+id, nil, idemHdr(e.key())), 422, "validation_failed") // version required
	wantProblem(t, e.admin("DELETE", "/v1/admin/ipos/"+id+"?version=0", nil, idemHdr(e.key())), 422, "validation_failed")
	wantProblem(t, e.admin("DELETE", "/v1/admin/ipos/"+id+"?version=4", nil, idemHdr(e.key())), 409, "ipo.stale_version")
	ipo := e.published(acme(), FlagApply)
	unpublished := e.admin("POST", "/v1/admin/ipos/"+ipo.ID.String()+"/unpublish", ver(int(ipo.Version)), idemHdr(e.key()))
	wantHTTP(t, unpublished, 200)
	wantProblem(t, e.admin("DELETE", "/v1/admin/ipos/"+ipo.ID.String()+"?version="+strconv.Itoa(unpublished.version()), nil, idemHdr(e.key())), 409, "ipo.published_not_deletable")
	if _, ok := e.row(ipo.ID); !ok {
		t.Error("an ever-published IPO was deleted")
	}
}

func TestActions_Listener_FR024_RollsBackWholeChange(t *testing.T) {
	e := newHTTPEnv(t)
	id := e.draftID()
	wantHTTP(t, e.admin("PUT", "/v1/admin/ipos/"+id+"/flag", map[string]any{"version": 1, "apply_flag": "APPLY", "flag_note": nil}, idemHdr(e.key())), 200)
	e.svc.OnEligibilityChanged(rejectingListener{err: &RejectedError{Code: "deal.has_open_tasks", Detail: "open tasks exist"}})
	auditBefore := e.h.Count("audit_log", "entity = 'ipo'")
	r := e.admin("POST", "/v1/admin/ipos/"+id+"/publish", ver(2), idemHdr(e.key()))
	wantProblem(t, r, 409, "deal.has_open_tasks")
	row := e.mustRow(uuid.MustParse(id))
	if row.Published || row.Version != 2 || e.h.Count("audit_log", "entity = 'ipo'") != auditBefore {
		t.Errorf("rejected publish left state behind: %+v", row)
	}
}

func TestActions_Listener_US3_10_UnexpectedFailureIs500WithoutDetail(t *testing.T) {
	e := newHTTPEnv(t)
	id := e.draftID()
	wantHTTP(t, e.admin("PUT", "/v1/admin/ipos/"+id+"/flag", map[string]any{"version": 1, "apply_flag": "APPLY", "flag_note": nil}, idemHdr(e.key())), 200)
	e.svc.OnEligibilityChanged(rejectingListener{err: errors.New("secret connection string leaked")})
	r := e.admin("POST", "/v1/admin/ipos/"+id+"/publish", ver(2), idemHdr(e.key()))
	wantProblem(t, r, 500, "internal")
	if strings.Contains(string(r.Raw), "secret") {
		t.Errorf("500 body leaks the cause: %s", r.Raw)
	}
	if e.mustRow(uuid.MustParse(id)).Published {
		t.Error("a failed listener must roll the publish back")
	}
}

func TestSuggest_US8_WeekdayDates(t *testing.T) {
	e := newHTTPEnv(t)
	r := e.admin("GET", "/v1/admin/ipos/date-suggestions?close_date=2026-11-13", nil)
	wantHTTP(t, r, 200)
	want := map[string]string{
		"close_date": "2026-11-13", "allotment_date": "2026-11-16", "refund_date": "2026-11-17",
		"demat_credit_date": "2026-11-17", "listing_date": "2026-11-18",
		"notice_code": "ipo.weekdays_only", "notice": "weekdays only; check exchange holidays",
	}
	for k, v := range want {
		if r.M[k] != v {
			t.Errorf("%s = %v, want %s", k, r.M[k], v)
		}
	}
}

func TestSuggest_US8_RoutePrecedenceOverIpoID(t *testing.T) {
	e := newHTTPEnv(t)
	r := e.admin("GET", "/v1/admin/ipos/date-suggestions?close_date=2026-11-13", nil)
	if r.problemCode() == "validation_failed" || r.Code == 404 {
		t.Fatalf("the literal route lost to /{ipoId}: %d %s", r.Code, r.Raw)
	}
	wantHTTP(t, r, 200)
}

func TestSuggest_US8_Validation(t *testing.T) {
	e := newHTTPEnv(t)
	wantProblem(t, e.admin("GET", "/v1/admin/ipos/date-suggestions", nil), 422, "validation_failed")
	wantProblem(t, e.admin("GET", "/v1/admin/ipos/date-suggestions?close_date=13-11-2026", nil), 422, "validation_failed")
	wantProblem(t, e.admin("GET", "/v1/admin/ipos/date-suggestions?close_date=2026-02-30", nil), 422, "validation_failed")
}

func TestSuggest_US8_4_NoSideEffects(t *testing.T) {
	e := newHTTPEnv(t)
	e.createAcme()
	rows, jobs, audits := e.iposCount(), e.h.Count("scheduled_jobs", "true"), e.h.Count("audit_log", "true")
	wantHTTP(t, e.admin("GET", "/v1/admin/ipos/date-suggestions?close_date=2026-11-14", nil), 200) // a Saturday
	if e.iposCount() != rows || e.h.Count("scheduled_jobs", "true") != jobs || e.h.Count("audit_log", "true") != audits {
		t.Error("date suggestions wrote to the database")
	}
}
