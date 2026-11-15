package main

// S17 - the generated OpenAPI document of feature 003 (plan "API operations", contracts/openapi-auth.yaml):
// the 16 auth operations, the two security schemes, `security: []` on the probes, the `code` property
// of ErrorModel, and nothing hidden. The `swastik openapi` command must build all of it with no
// database, keys or network.

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/NandanMaheta/swastik/apps/api/internal/platform/tickauth"
	"github.com/NandanMaheta/swastik/apps/api/internal/scheduler"
)

// openAPIJSON is the document of buildAPI as generic JSON.
func openAPIJSON(t *testing.T) map[string]any {
	t.Helper()
	b, err := json.Marshal(buildAPI(deps{Tick: (*scheduler.Service)(nil), TickAuth: tickauth.Disabled()}).OpenAPI())
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

func at(t *testing.T, m map[string]any, keys ...string) any {
	t.Helper()
	var cur any = m
	for _, k := range keys {
		next, ok := cur.(map[string]any)
		if !ok {
			t.Fatalf("path %v: %T is not an object at %q", keys, cur, k)
		}
		if cur, ok = next[k]; !ok {
			t.Fatalf("path %v: no %q in the document", keys, k)
		}
	}
	return cur
}

func TestOpenAPI_AuthOperationsAreInTheDocument(t *testing.T) {
	doc := openAPIJSON(t)
	for _, want := range authOperations {
		op, ok := at(t, doc, "paths", want.path, strings.ToLower(want.method)).(map[string]any)
		if !ok || op["operationId"] != want.id {
			t.Errorf("%s %s: operation = %v, want operationId %s", want.method, want.path, op, want.id)
		}
	}
}

func TestOpenAPI_SecuritySchemesAndPerOperationSecurity(t *testing.T) {
	doc := openAPIJSON(t)
	bearer := at(t, doc, "components", "securitySchemes", "bearer").(map[string]any)
	challenge := at(t, doc, "components", "securitySchemes", "mfaChallenge").(map[string]any)
	if bearer["type"] != "http" || bearer["scheme"] != "bearer" || bearer["bearerFormat"] != "JWT" {
		t.Errorf("bearer scheme = %v", bearer)
	}
	if challenge["type"] != "http" || challenge["scheme"] != "bearer" || challenge["bearerFormat"] != "opaque" {
		t.Errorf("mfaChallenge scheme = %v", challenge)
	}
	for _, probe := range []struct{ path, method string }{{"/healthz", "get"}, {"/readyz", "get"}, {"/v1/auth/sign-in", "post"}, {"/v1/auth/refresh", "post"}} {
		sec, ok := at(t, doc, "paths", probe.path, probe.method, "security").([]any)
		if !ok || len(sec) != 0 {
			t.Errorf("%s %s: security = %v, want an explicit empty list (public)", probe.method, probe.path, sec)
		}
	}
	admin, _ := at(t, doc, "paths", "/v1/auth/mfa/recovery-codes", "post", "security").([]any)
	if len(admin) != 1 || admin[0].(map[string]any)["bearer"].([]any)[0] != "admin" {
		t.Errorf("recovery-codes security = %v, want [{bearer: [admin]}]", admin)
	}
	any1, _ := at(t, doc, "paths", "/v1/auth/devices", "get", "security").([]any)
	if len(any1) != 1 || len(any1[0].(map[string]any)["bearer"].([]any)) != 0 {
		t.Errorf("devices security = %v, want [{bearer: []}] (any signed-in role)", any1)
	}
	ch, _ := at(t, doc, "paths", "/v1/auth/mfa/verify", "post", "security").([]any)
	if len(ch) != 1 {
		t.Fatalf("mfa verify security = %v", ch)
	}
	if _, ok := ch[0].(map[string]any)["mfaChallenge"]; !ok {
		t.Errorf("mfa verify security = %v, want mfaChallenge", ch)
	}
}

func TestOpenAPI_ErrorModelCarriesTheStableCode(t *testing.T) {
	doc := openAPIJSON(t)
	props := at(t, doc, "components", "schemas", "ErrorModel", "properties").(map[string]any)
	code, ok := props["code"].(map[string]any)
	if !ok || code["type"] != "string" {
		t.Errorf("ErrorModel.code = %v, want a string property (plan P-10)", props["code"])
	}
	if _, ok := code["enum"]; ok {
		t.Error("ErrorModel.code is an enum: adding a code would be a breaking change")
	}
}

func TestOpenAPI_RefreshCookieAndWebHeadersAreDocumented(t *testing.T) {
	doc := openAPIJSON(t)
	params, _ := at(t, doc, "paths", "/v1/auth/refresh", "post", "parameters").([]any)
	var names []string
	for _, p := range params {
		m := p.(map[string]any)
		names = append(names, m["in"].(string)+":"+m["name"].(string))
	}
	for _, want := range []string{"cookie:__Secure-swastik_rt", "header:Origin", "header:X-Swastik-CSRF"} {
		found := false
		for _, n := range names {
			found = found || strings.EqualFold(n, want)
		}
		if !found {
			t.Errorf("refresh parameters = %v, missing %s", names, want)
		}
	}
}

func TestOpenAPI_OnlyTheExpectedAuthPathsExistAndTheTickIsAbsent(t *testing.T) {
	doc := openAPIJSON(t)
	expected := map[string]bool{}
	for _, o := range authOperations {
		expected[o.path] = true
	}
	for path := range at(t, doc, "paths").(map[string]any) {
		switch {
		case strings.HasPrefix(path, "/internal"):
			t.Errorf("hidden path %s is in the document", path)
		case (strings.HasPrefix(path, "/v1/auth/") || strings.HasPrefix(path, "/v1/admin/users")) && !expected[path]:
			t.Errorf("unexpected path %s under the auth surface (FR-050..055 are Go capabilities, not operations)", path)
		}
	}
}

func TestOpenAPI_CommandBuildsTheAuthDocumentWithZeroDependencies(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://nobody:nothing@127.0.0.1:1/none?connect_timeout=1")
	t.Setenv("APP_ENV", "production") // production would refuse to start without keys: the command must not care
	t.Setenv("JWT_SIGNING_KEYS", "")
	t.Setenv("PII_ENCRYPTION_KEYS", "")
	t.Setenv("BLIND_INDEX_KEY", "")
	t.Setenv("WEB_ORIGINS", "")
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")

	out := openAPIFromCommand(t)
	for _, o := range authOperations {
		if !strings.Contains(out, "operationId: "+o.id) {
			t.Errorf("`swastik openapi` output has no operation %s", o.id)
		}
	}
	for _, want := range []string{"securitySchemes:", "mfaChallenge:", "bearerFormat: JWT", "bearerFormat: opaque"} {
		if !strings.Contains(out, want) {
			t.Errorf("`swastik openapi` output lacks %q", want)
		}
	}
	for _, banned := range []string{"/internal", "scheduler-tick"} {
		if strings.Contains(out, banned) {
			t.Errorf("`swastik openapi` output contains %q", banned)
		}
	}
}
