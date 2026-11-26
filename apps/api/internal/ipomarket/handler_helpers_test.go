package ipomarket

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

// S16: HTTP contract tests. The API is built like cmd/swastik does: httpx.InstallErrors,
// authz.Install with a fake bearer verifier ("admin-token", "client-token", both in the fixture
// org), Register(api, svc), authz.AssertDeclared. The config drops the `$schema` response field
// (what httpx.NewAPIFor("production") does) so exact-key checks need no allowance for it.
//
// Assumptions the contracts leave open:
//   - Register reads the organisation and the author from the authz.Principal.
//   - Huma schema violations (types, ranges, lengths, header pattern, uuid, list size, bad cursor)
//     give 422 `validation_failed`.
//   - A mutation response is {entry|snapshot, current, warnings?}; `warnings` is never null.

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
	e := newSvcEnv(t)
	httpx.InstallErrors()
	cfg := huma.DefaultConfig("test", "1.0.0")
	cfg.CreateHooks = nil
	_, api := humatest.New(t, cfg)
	authz.Install(api, map[string]authz.Verifier{
		"bearer": tokenVerifier{
			"admin-token":  {UserID: e.adm.ID, OrgID: e.org, SessionID: uuid.New(), Role: authz.RoleAdmin},
			"client-token": {UserID: uuid.New(), OrgID: e.org, SessionID: uuid.New(), Role: authz.RoleClient},
		},
		"mfaChallenge": tokenVerifier{},
	})
	Register(api, e.svc)
	authz.AssertDeclared(api)
	return &httpEnv{svcEnv: e, api: api}
}

type resp struct {
	Code int
	Raw  []byte
	Hdr  http.Header
	M    map[string]any
}

func toResp(r *httptest.ResponseRecorder) resp {
	out := resp{Code: r.Code, Raw: r.Body.Bytes(), Hdr: r.Header()}
	_ = json.Unmarshal(out.Raw, &out.M)
	return out
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

func (r resp) obj(k string) map[string]any { m, _ := r.M[k].(map[string]any); return m }

func (r resp) list(k string) []any { l, _ := r.M[k].([]any); return l }

func keysOf(m map[string]any) map[string]bool {
	out := map[string]bool{}
	for k := range m {
		out[k] = true
	}
	return out
}

func wantKeys(t *testing.T, what string, m map[string]any, want ...string) {
	t.Helper()
	got := keysOf(m)
	ok := len(got) == len(want)
	for _, w := range want {
		ok = ok && got[w]
	}
	if !ok {
		t.Errorf("%s keys = %v, want exactly %v", what, got, want)
	}
}

func gmpPath(ipo uuid.UUID) string { return "/v1/admin/ipos/" + ipo.String() + "/gmp" }
func subPath(ipo uuid.UUID) string { return "/v1/admin/ipos/" + ipo.String() + "/subscription" }

func idList(ids ...uuid.UUID) string {
	s := make([]string, len(ids))
	for i, id := range ids {
		s[i] = id.String()
	}
	return strings.Join(s, ",")
}
