package main

// S17 - the security contract walk (spec US-2, FR-030..FR-035, SC-001, plan P-09): static over the
// registered operations and runtime over every non-public one. buildAPI(deps{...}) is the real
// wiring: httpx.InstallErrors, authz.Install, auth.Register, authz.AssertDeclared. With deps{}
// (no Auth, no database) it must still register every operation.
//
// Assumed deps fields (added as stubs in main.go): Auth *auth.Service, WebOrigins []string,
// TrustedProxyHops int, next to the existing Pool, Tick and TickAuth.

import (
	"bufio"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/humatest"
	"github.com/google/uuid"

	"github.com/NandanMaheta/swastik/apps/api/internal/auth"
	"github.com/NandanMaheta/swastik/apps/api/internal/auth/authtest"
	"github.com/NandanMaheta/swastik/apps/api/internal/platform/tickauth"
	"github.com/NandanMaheta/swastik/apps/api/internal/scheduler"
)

// publicOperations is the allowlist of operations that need no credential (FR-030).
var publicOperations = []string{"auth-refresh", "auth-sign-in", "health-live", "health-ready"}

// authOperations is the contract of contracts/openapi-auth.yaml: id, method, path, security scheme
// and the roles in the requirement.
type authOp struct {
	id, method, path, scheme string
	roles                    []string
}

var authOperations = []authOp{
	{"auth-sign-in", "POST", "/v1/auth/sign-in", "", nil},
	{"auth-mfa-verify", "POST", "/v1/auth/mfa/verify", "mfaChallenge", nil},
	{"auth-mfa-enrolment-start", "POST", "/v1/auth/mfa/enrolment", "mfaChallenge", nil},
	{"auth-mfa-enrolment-confirm", "POST", "/v1/auth/mfa/enrolment/confirm", "mfaChallenge", nil},
	{"auth-refresh", "POST", "/v1/auth/refresh", "", nil},
	{"auth-sign-out", "POST", "/v1/auth/sign-out", "bearer", nil},
	{"auth-sign-out-everywhere", "POST", "/v1/auth/sign-out-everywhere", "bearer", nil},
	{"auth-devices-list", "GET", "/v1/auth/devices", "bearer", nil},
	{"auth-device-revoke", "DELETE", "/v1/auth/devices/{sessionId}", "bearer", nil},
	{"auth-password-change", "POST", "/v1/auth/password/change", "bearer", nil},
	{"auth-recovery-codes-regenerate", "POST", "/v1/auth/mfa/recovery-codes", "bearer", []string{"admin"}},
	{"auth-authenticator-replace-start", "POST", "/v1/auth/mfa/authenticator", "bearer", []string{"admin"}},
	{"auth-authenticator-replace-confirm", "POST", "/v1/auth/mfa/authenticator/confirm", "bearer", []string{"admin"}},
	{"auth-admin-user-devices-list", "GET", "/v1/admin/users/{userId}/devices", "bearer", []string{"admin"}},
	{"auth-admin-user-device-revoke", "DELETE", "/v1/admin/users/{userId}/devices/{sessionId}", "bearer", []string{"admin"}},
	{"auth-admin-user-sessions-end-all", "POST", "/v1/admin/users/{userId}/sessions/end-all", "bearer", []string{"admin"}},
}

type walkedOp struct {
	ID, Method, Path string
	Security         []map[string][]string
	Op               *huma.Operation
}

// operationsOf lists every documented operation of the API.
func operationsOf(api huma.API) []walkedOp {
	var out []walkedOp
	for path, item := range api.OpenAPI().Paths {
		for method, op := range map[string]*huma.Operation{
			http.MethodGet: item.Get, http.MethodPut: item.Put, http.MethodPost: item.Post, http.MethodDelete: item.Delete,
			http.MethodPatch: item.Patch, http.MethodHead: item.Head, http.MethodOptions: item.Options, http.MethodTrace: item.Trace,
		} {
			if op != nil {
				out = append(out, walkedOp{ID: op.OperationID, Method: method, Path: path, Security: op.Security, Op: op})
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func idsOf(ops []walkedOp, keep func(walkedOp) bool) []string {
	var ids []string
	for _, o := range ops {
		if keep(o) {
			ids = append(ids, o.ID)
		}
	}
	sort.Strings(ids)
	return ids
}

// schemeOf is the single scheme of a requirement and its scopes ("" when the operation is public).
func schemeOf(o walkedOp) (string, []string) {
	for _, req := range o.Security {
		for scheme, scopes := range req {
			return scheme, scopes
		}
	}
	return "", nil
}

func staticAPI(t *testing.T) []walkedOp {
	t.Helper()
	ops := operationsOf(buildAPI(deps{}))
	if len(ops) == 0 {
		t.Fatal("buildAPI(deps{}) registered no operation")
	}
	return ops
}

// ---- static walk ----

func TestContractWalk_EveryOperationDeclaresSecurity(t *testing.T) {
	for _, o := range staticAPI(t) {
		if o.Security == nil {
			t.Errorf("%s %s (%s) declares no Security: use authz.Public(), Require(...) or ChallengeOnly() (US-2 s2)", o.Method, o.Path, o.ID)
		}
	}
}

func TestContractWalk_PublicOperationsAreExactlyTheAllowlist(t *testing.T) {
	got := idsOf(staticAPI(t), func(o walkedOp) bool { return o.Security != nil && len(o.Security) == 0 })
	if !slices.Equal(got, publicOperations) {
		t.Errorf("operations with empty Security = %v, want exactly %v (FR-030)", got, publicOperations)
	}
}

func TestContractWalk_ChallengeOperationsAreExactlyTheSecondFactorOnes(t *testing.T) {
	got := idsOf(staticAPI(t), func(o walkedOp) bool { s, _ := schemeOf(o); return s == "mfaChallenge" })
	want := []string{"auth-mfa-enrolment-confirm", "auth-mfa-enrolment-start", "auth-mfa-verify"}
	if !slices.Equal(got, want) {
		t.Errorf("mfaChallenge operations = %v, want exactly %v (US-2 s9)", got, want)
	}
}

func TestContractWalk_EveryRequirementIsOneKnownScheme(t *testing.T) {
	for _, o := range staticAPI(t) {
		if len(o.Security) == 0 {
			continue
		}
		if len(o.Security) != 1 || len(o.Security[0]) != 1 {
			t.Errorf("%s: Security = %v, want exactly one requirement naming one scheme", o.ID, o.Security)
			continue
		}
		if s, _ := schemeOf(o); s != "bearer" && s != "mfaChallenge" {
			t.Errorf("%s: scheme %q is unknown", o.ID, s)
		}
	}
}

func TestContractWalk_AdminOperationsMatchTheRegisteredList(t *testing.T) {
	f, err := os.Open("testdata/admin-operations.txt")
	if err != nil {
		t.Fatalf("testdata/admin-operations.txt: %v", err)
	}
	defer func() { _ = f.Close() }()
	var want []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if line := strings.TrimSpace(sc.Text()); line != "" && !strings.HasPrefix(line, "#") {
			want = append(want, line)
		}
	}
	sort.Strings(want)
	got := idsOf(staticAPI(t), func(o walkedOp) bool {
		s, roles := schemeOf(o)
		return s == "bearer" && slices.Contains(roles, "admin")
	})
	if !slices.Equal(got, want) {
		t.Errorf("admin-scoped operations = %v\n  testdata/admin-operations.txt = %v\n  every admin operation must be listed, and every listed one must exist (FR-032)", got, want)
	}
}

func TestContractWalk_AuthOperationInventory(t *testing.T) {
	byID := map[string]walkedOp{}
	for _, o := range staticAPI(t) {
		byID[o.ID] = o
	}
	for _, want := range authOperations {
		o, ok := byID[want.id]
		if !ok {
			t.Errorf("operation %s is not registered", want.id)
			continue
		}
		if o.Method != want.method || o.Path != want.path {
			t.Errorf("%s = %s %s, want %s %s", want.id, o.Method, o.Path, want.method, want.path)
		}
		scheme, roles := schemeOf(o)
		sameRoles := slices.Equal(roles, want.roles) || len(roles) == 0 && len(want.roles) == 0
		if scheme != want.scheme || !sameRoles {
			t.Errorf("%s: security = %s %v, want %s %v", want.id, scheme, roles, want.scheme, want.roles)
		}
	}
	var extra []string
	for _, o := range byID {
		if strings.HasPrefix(o.ID, "auth-") && !slices.ContainsFunc(authOperations, func(a authOp) bool { return a.id == o.ID }) {
			extra = append(extra, o.ID)
		}
	}
	if len(extra) > 0 {
		t.Errorf("unexpected auth operations %v: contracts/openapi-auth.yaml lists 16", extra)
	}
}

func TestContractWalk_NoOperationExposesAnAccountCapability(t *testing.T) {
	// FR-050..FR-055 are Go interfaces for 004, 005 and 007, never HTTP operations (US-10 s7).
	banned := []string{"create-client", "mark-email-verified", "mark-mobile-verified", "approve", "disable", "enable",
		"reset-password", "end-all-sessions", "replace-email", "replace-mobile", "get-user"}
	for _, o := range staticAPI(t) {
		for _, name := range banned {
			if strings.Contains(o.ID, name) {
				t.Errorf("operation %s exposes the account capability %q over HTTP", o.ID, name)
			}
		}
	}
}

func TestContractWalk_TheTickIsHiddenFromTheDocument(t *testing.T) {
	api := buildAPI(deps{Tick: &walkTicker{}, TickAuth: tickauth.NewDev("tick-dev-token-1234")})
	for path := range api.OpenAPI().Paths {
		if strings.HasPrefix(path, "/internal") {
			t.Errorf("hidden operation %s appears in the OpenAPI paths", path)
		}
	}
}

// ---- runtime walk ----

type walkTicker struct{ calls atomic.Int32 }

func (w *walkTicker) Tick(context.Context) (scheduler.TickSummary, error) {
	w.calls.Add(1)
	return scheduler.TickSummary{}, nil
}

// fingerprint is a digest of every auth table and the audit log: equal fingerprints mean nothing
// was written.
func fingerprint(t *testing.T, e *authtest.Env) string {
	t.Helper()
	var parts []string
	for _, table := range []string{"users", "device_sessions", "refresh_tokens", "admin_mfa", "mfa_recovery_codes", "mfa_challenges", "auth_throttles", "audit_log"} {
		var d string
		if err := e.Pool.QueryRow(context.Background(), `SELECT coalesce(md5(string_agg(x::text, '|' ORDER BY x::text)), '') FROM `+table+` x`).Scan(&d); err != nil {
			t.Fatalf("fingerprint %s: %v", table, err)
		}
		parts = append(parts, table+"="+d)
	}
	return strings.Join(parts, ";")
}

// tamper changes one character in the middle of the payload segment of a token.
func tamper(token string) string {
	parts := strings.Split(token, ".")
	if len(parts) == 3 {
		p := []byte(parts[1])
		i := len(p) / 2
		if p[i] == 'A' {
			p[i] = 'B'
		} else {
			p[i] = 'A'
		}
		parts[1] = string(p)
		return strings.Join(parts, ".")
	}
	b := []byte(token)
	i := len(b) - 5 // an opaque token: change a character inside the random part
	if b[i] == 'A' {
		b[i] = 'B'
	} else {
		b[i] = 'A'
	}
	return string(b)
}

type walkWorld struct {
	e      *authtest.Env
	api    humatest.TestAPI
	ticker *walkTicker
}

func newWalkWorld(t *testing.T) *walkWorld {
	t.Helper()
	e := authtest.New(t)
	ticker := &walkTicker{}
	api := buildAPI(deps{Auth: e.Service(t), WebOrigins: []string{"https://admin.example.com"}, TrustedProxyHops: 1,
		Tick: ticker, TickAuth: tickauth.NewDev("tick-dev-token-1234")})
	return &walkWorld{e: e, api: humatest.Wrap(t, api), ticker: ticker}
}

// request sends one request to an operation with random path parameters and an empty JSON body.
func (w *walkWorld) request(o walkedOp, authorization string) *httptest.ResponseRecorder {
	path := o.Path
	for strings.Contains(path, "{") {
		start, end := strings.Index(path, "{"), strings.Index(path, "}")
		path = path[:start] + uuid.NewString() + path[end+1:]
	}
	args := []any{"X-Forwarded-For: 203.0.113.9"}
	if authorization != "" {
		args = append(args, "Authorization: "+authorization)
	}
	if o.Op.RequestBody != nil {
		args = append(args, map[string]any{})
	}
	return w.api.Do(o.Method, path, args...)
}

func problemCode(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var p struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &p); err != nil {
		t.Fatalf("not a problem body (status %d): %q", rec.Code, rec.Body.String())
	}
	return p.Code
}

func TestContractWalk_RuntimeEveryProtectedOperationRejectsEveryBadCredentialWithoutWriting(t *testing.T) {
	w := newWalkWorld(t)
	e := w.e
	svc := e.Service(t)
	client := e.UserWithStatus(t, auth.StatusActive)
	admin := e.NewAdmin(t)

	clientSession := e.NewSession(t, client.ID, authtest.SessionSpec{})
	goodClient := e.AccessToken(t, client, clientSession)
	revokedSession := e.NewSession(t, client.ID, authtest.SessionSpec{})
	revoked := e.AccessToken(t, client, revokedSession)
	e.Exec(t, `UPDATE device_sessions SET ended_at = $2, end_reason = 'signed_out' WHERE id = $1`, revokedSession, e.Clock.Now())
	adminSession := e.NewSession(t, admin.ID, authtest.SessionSpec{MFAMethod: "totp", Idle: 12 * time.Hour, Absolute: 7 * 24 * time.Hour})
	expiring := e.AccessToken(t, admin, adminSession) // issued now, dead after 15 minutes

	signIn, err := svc.SignIn(context.Background(), auth.SignInInput{Identifier: client.Email, Password: client.Password,
		ClientType: auth.ClientTypeMobile, Device: auth.DeviceInfo{ID: uuid.New(), Name: "Pixel", Platform: auth.PlatformAndroid}, IP: "203.0.113.9"})
	if err != nil || signIn.Session == nil {
		t.Fatalf("SignIn: %+v %v", signIn, err)
	}
	refresh := signIn.Session.RefreshToken
	adminSignIn, err := svc.SignIn(context.Background(), auth.SignInInput{Identifier: admin.Email, Password: admin.Password,
		ClientType: auth.ClientTypeMobile, Device: auth.DeviceInfo{ID: uuid.New(), Name: "Pixel", Platform: auth.PlatformAndroid}, IP: "203.0.113.9"})
	if err != nil || adminSignIn.Challenge == nil {
		t.Fatalf("admin SignIn: %+v %v", adminSignIn, err)
	}
	challenge := adminSignIn.Challenge.Token

	var protected []walkedOp
	for _, o := range operationsOf(w.api) {
		if len(o.Security) > 0 {
			protected = append(protected, o)
		}
	}
	if len(protected) < 14 {
		t.Fatalf("the walk found %d protected operations, want at least the 14 auth ones (a walk that covers nothing proves nothing)", len(protected))
	}
	before := fingerprint(t, e)

	type variant struct {
		name, header string
		wantStatus   int
		wantCode     string
	}
	check := func(o walkedOp, v variant) {
		t.Helper()
		rec := w.request(o, v.header)
		if rec.Code != v.wantStatus {
			t.Errorf("%s with %s: status = %d, want %d; body %s", o.ID, v.name, rec.Code, v.wantStatus, rec.Body.String())
			return
		}
		if got := problemCode(t, rec); got != v.wantCode {
			t.Errorf("%s with %s: code = %q, want %q", o.ID, v.name, got, v.wantCode)
		}
		if v.wantStatus == http.StatusUnauthorized && rec.Header().Get("WWW-Authenticate") != "Bearer" {
			t.Errorf("%s with %s: WWW-Authenticate = %q, want Bearer", o.ID, v.name, rec.Header().Get("WWW-Authenticate"))
		}
	}

	unauth := func(name, header string) variant {
		return variant{name, header, http.StatusUnauthorized, "auth.unauthenticated"}
	}
	for _, o := range protected {
		scheme, roles := schemeOf(o)
		common := []variant{
			unauth("no credential", ""),
			unauth("a basic credential", "Basic dXNlcjpwYXNz"),
			unauth("a tampered challenge token", "Bearer "+tamper(challenge)),
			unauth("a refresh token", "Bearer "+refresh),
			unauth("an access token of a revoked session", "Bearer "+revoked),
			unauth("a tampered access token", "Bearer "+tamper(goodClient)),
		}
		if scheme == "bearer" {
			common = append(common, unauth("a challenge token", "Bearer "+challenge))
			if slices.Contains(roles, "admin") {
				common = append(common, variant{"a valid client access token", "Bearer " + goodClient, http.StatusForbidden, "auth.forbidden"})
			}
		} else {
			common = append(common, unauth("a valid access token", "Bearer "+goodClient))
		}
		for _, v := range common {
			check(o, v)
		}
	}

	// Fifteen minutes later every access token has expired, and so has the challenge.
	e.Clock.Advance(16 * time.Minute)
	for _, o := range protected {
		scheme, _ := schemeOf(o)
		if scheme == "bearer" {
			check(o, unauth("an expired access token", "Bearer "+expiring))
		} else {
			check(o, unauth("an expired challenge", "Bearer "+challenge))
		}
	}

	if after := fingerprint(t, e); after != before {
		t.Errorf("rejected requests changed the database:\n before %s\n after  %s", before, after)
	}
	if got := w.ticker.calls.Load(); got != 0 {
		t.Errorf("the tick ran %d times during the walk", got)
	}
}
