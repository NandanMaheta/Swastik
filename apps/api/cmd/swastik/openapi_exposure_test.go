package main

// Review fix (feature 003): the API's self-description endpoints are served only where a developer
// needs them. In staging and production /openapi.json, /openapi.yaml, /docs and /schemas/* answer 404
// (the operation list is not advertised); in local and ci they are served. `swastik openapi` keeps
// printing the full document in every environment because it reads the in-memory document, not the
// HTTP route.
//
// API assumption: deps gains a field
//
//	Env string // APP_ENV: "local", "ci", "staging" or "production"; "" behaves as "local"
//
// and buildAPI passes it to the Huma configuration (the doc, schema and OpenAPI paths are disabled
// in staging and production).

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/danielgtaylor/huma/v2/humatest"

	"github.com/NandanMaheta/swastik/apps/api/internal/platform/tickauth"
)

var selfDescriptionPaths = []string{
	"/openapi.json",
	"/openapi.yaml",
	"/openapi-3.0.json",
	"/openapi-3.0.yaml",
	"/docs",
	"/schemas/ErrorModel.json",
	"/schemas/anything.json",
}

func exposureAPI(t *testing.T, env string) humatest.TestAPI {
	t.Helper()
	return humatest.Wrap(t, buildAPI(deps{Env: env, Tick: &walkTicker{}, TickAuth: tickauth.NewDev("tick-dev-token-1234")}))
}

func TestOpenAPIExposure_NotServedInStagingAndProduction(t *testing.T) {
	for _, env := range []string{"staging", "production"} {
		api := exposureAPI(t, env)
		for _, path := range selfDescriptionPaths {
			t.Run(env+" "+path, func(t *testing.T) {
				rec := api.Get(path)
				if rec.Code != http.StatusNotFound {
					t.Errorf("GET %s in %s = %d, want 404 (body %.120q)", path, env, rec.Code, rec.Body.String())
				}
				assertNoSpecLeak(t, rec)
			})
		}
	}
}

func TestOpenAPIExposure_RealOperationsStillWorkInProduction(t *testing.T) {
	api := exposureAPI(t, "production")
	if rec := api.Get("/healthz"); rec.Code != http.StatusOK {
		t.Errorf("GET /healthz in production = %d, want 200", rec.Code)
	}
}

func TestOpenAPIExposure_ServedLocallyAndInCI(t *testing.T) {
	for _, env := range []string{"local", "ci", ""} {
		api := exposureAPI(t, env)
		for _, path := range []string{"/openapi.json", "/openapi.yaml", "/docs"} {
			t.Run(env+" "+path, func(t *testing.T) {
				rec := api.Get(path)
				if rec.Code != http.StatusOK {
					t.Fatalf("GET %s in %q = %d, want 200", path, env, rec.Code)
				}
				if path != "/docs" && !strings.Contains(rec.Body.String(), "/v1/auth/sign-in") {
					t.Errorf("GET %s does not describe the API: %.200q", path, rec.Body.String())
				}
			})
		}
	}
}

// The in-memory document is complete in every environment, so `swastik openapi` (used to generate
// the TypeScript client) never depends on the HTTP routes being served.
func TestOpenAPIExposure_DocumentStillBuildsInProduction(t *testing.T) {
	spec, err := buildAPI(deps{Env: "production", Tick: &walkTicker{}, TickAuth: tickauth.Disabled()}).OpenAPI().YAML()
	if err != nil {
		t.Fatalf("OpenAPI().YAML(): %v", err)
	}
	if !strings.Contains(string(spec), "/v1/auth/sign-in") || !strings.Contains(string(spec), "/healthz") {
		t.Errorf("the document built for production is incomplete: %.200q", spec)
	}
}

func assertNoSpecLeak(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	body := rec.Body.String()
	for _, leak := range []string{"/v1/auth/", "openapi:", `"openapi"`, "auth-sign-in"} {
		if strings.Contains(body, leak) {
			t.Errorf("a 404 body leaks the API description (%q): %.200q", leak, body)
		}
	}
}
