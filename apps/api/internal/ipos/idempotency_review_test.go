package ipos

// Review fix: an Idempotency-Key replayed with a DIFFERENT request body is rejected with
// 422 ipo.idempotency_key_reused (contracts/error-codes.md); the same body still replays; keys
// are scoped per org (FR-007).

import (
	"testing"

	"github.com/google/uuid"
)

const reusedCode = "ipo.idempotency_key_reused"

func TestIdempotency_FR007_Create_KeyReusedWithDifferentBody(t *testing.T) {
	e := newHTTPEnv(t)
	k := idemHdr("create-key-001")
	first := e.admin("POST", "/v1/admin/ipos", acmeBody(), k)
	wantHTTP(t, first, 201)
	wantHTTP(t, e.admin("POST", "/v1/admin/ipos", acmeBody(), k), 200) // same body replays
	other := acmeBody()
	other["name"] = "Different Ltd"
	wantProblem(t, e.admin("POST", "/v1/admin/ipos", other, k), 422, reusedCode)
	if n := e.h.Count("ipos", "org_id = $1", e.org); n != 1 {
		t.Errorf("ipos = %d, want 1", n)
	}
}

func TestIdempotency_FR007_Update_KeyReusedWithDifferentBody(t *testing.T) {
	e := newHTTPEnv(t)
	id := e.draftID()
	k := idemHdr("update-key-001")
	wantHTTP(t, e.admin("PUT", "/v1/admin/ipos/"+id, putBody(1, map[string]any{"name": "A Ltd"}), k), 200)
	wantHTTP(t, e.admin("PUT", "/v1/admin/ipos/"+id, putBody(1, map[string]any{"name": "A Ltd"}), k), 200)
	wantProblem(t, e.admin("PUT", "/v1/admin/ipos/"+id, putBody(1, map[string]any{"name": "B Ltd"}), k), 422, reusedCode)
	if got := e.admin("GET", "/v1/admin/ipos/"+id, nil); got.M["name"] != "A Ltd" {
		t.Errorf("name = %v, want unchanged A Ltd", got.M["name"])
	}
}

func TestIdempotency_FR007_Flag_KeyReusedWithDifferentBody(t *testing.T) {
	e := newHTTPEnv(t)
	id := e.draftID()
	p := "/v1/admin/ipos/" + id + "/flag"
	k := idemHdr("flag-key-0001")
	body := map[string]any{"version": 1, "apply_flag": "APPLY", "flag_note": nil}
	wantHTTP(t, e.admin("PUT", p, body, k), 200)
	wantHTTP(t, e.admin("PUT", p, body, k), 200)
	wantProblem(t, e.admin("PUT", p, map[string]any{"version": 1, "apply_flag": "DO_NOT_APPLY", "flag_note": nil}, k), 422, reusedCode)
}

func TestIdempotency_FR007_Publish_KeyReusedWithDifferentBody(t *testing.T) {
	e := newHTTPEnv(t)
	id := e.draftID()
	wantHTTP(t, e.admin("PUT", "/v1/admin/ipos/"+id+"/flag", map[string]any{"version": 1, "apply_flag": "APPLY", "flag_note": nil}, idemHdr(e.key())), 200)
	p := "/v1/admin/ipos/" + id + "/publish"
	k := idemHdr("publish-key-r1")
	wantHTTP(t, e.admin("POST", p, ver(2), k), 200)
	wantHTTP(t, e.admin("POST", p, ver(2), k), 200)
	wantProblem(t, e.admin("POST", p, ver(3), k), 422, reusedCode)
}

func TestIdempotency_FR007_Unpublish_KeyReusedWithDifferentBody(t *testing.T) {
	e := newHTTPEnv(t)
	id := e.draftID()
	wantHTTP(t, e.admin("PUT", "/v1/admin/ipos/"+id+"/flag", map[string]any{"version": 1, "apply_flag": "APPLY", "flag_note": nil}, idemHdr(e.key())), 200)
	wantHTTP(t, e.admin("POST", "/v1/admin/ipos/"+id+"/publish", ver(2), idemHdr(e.key())), 200)
	p := "/v1/admin/ipos/" + id + "/unpublish"
	k := idemHdr("unpublish-key1")
	wantHTTP(t, e.admin("POST", p, ver(3), k), 200)
	wantHTTP(t, e.admin("POST", p, ver(3), k), 200)
	wantProblem(t, e.admin("POST", p, ver(4), k), 422, reusedCode)
}

func TestIdempotency_FR007_Override_KeyReusedWithDifferentBody(t *testing.T) {
	e := newHTTPEnv(t)
	id := e.draftID()
	p := "/v1/admin/ipos/" + id + "/status"
	k := idemHdr("override-key-r")
	wantHTTP(t, e.admin("POST", p, map[string]any{"version": 1, "status": "OPEN", "reason": "early"}, k), 200)
	wantHTTP(t, e.admin("POST", p, map[string]any{"version": 1, "status": "OPEN", "reason": "early"}, k), 200)
	wantProblem(t, e.admin("POST", p, map[string]any{"version": 1, "status": "CLOSED", "reason": "early"}, k), 422, reusedCode)
	wantProblem(t, e.admin("POST", p, map[string]any{"version": 1, "status": "OPEN", "reason": "another"}, k), 422, reusedCode)
}

func TestIdempotency_FR007_Delete_KeyReusedWithDifferentBody(t *testing.T) {
	e := newHTTPEnv(t)
	id := e.draftID()
	k := idemHdr("delete-key-r01")
	wantHTTP(t, e.admin("DELETE", "/v1/admin/ipos/"+id+"?version=1", nil, k), 204)
	wantHTTP(t, e.admin("DELETE", "/v1/admin/ipos/"+id+"?version=1", nil, k), 204)
	wantProblem(t, e.admin("DELETE", "/v1/admin/ipos/"+id+"?version=2", nil, k), 422, reusedCode)
}

func TestIdempotency_FR007_KeysAreScopedPerOrg(t *testing.T) {
	e := newSvcEnv(t)
	var other uuid.UUID
	if err := e.h.Pool.QueryRow(e.ctx(), `INSERT INTO orgs (name) VALUES ('Other') RETURNING id`).Scan(&other); err != nil {
		t.Fatal(err)
	}
	a, err := e.svc.Create(e.ctx(), e.admin, e.org, acme(), "shared-org-key")
	if err != nil || a.Replayed {
		t.Fatalf("org A: %v %+v", err, a)
	}
	d := acme()
	d.Name = "Another Ltd"
	b, err := e.svc.Create(e.ctx(), e.admin, other, d, "shared-org-key")
	if err != nil || b.Replayed || b.IPO.ID == a.IPO.ID {
		t.Fatalf("the same key in another org must create its own IPO: %v %+v", err, b)
	}
}
