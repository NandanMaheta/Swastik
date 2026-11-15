package auth_test

// S17 - harness of the HTTP tests: a humatest API on the real Service, with authz.Install and
// auth.Register as cmd/swastik wires them (httpx.InstallErrors first, authz.Install before any
// registration, authz.AssertDeclared after). API assumed (compile stub in handler.go):
//
//	auth.Register(api huma.API, svc *auth.Service, cfg auth.HandlerConfig)
//
// Wire format is contracts/openapi-auth.yaml (snake_case JSON); errors are RFC 9457 problems with
// a stable "code" (contracts/error-codes.md).

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/humatest"
	"github.com/google/uuid"

	"github.com/NandanMaheta/swastik/apps/api/internal/auth"
	"github.com/NandanMaheta/swastik/apps/api/internal/auth/authtest"
	"github.com/NandanMaheta/swastik/apps/api/internal/platform/authz"
	"github.com/NandanMaheta/swastik/apps/api/internal/platform/httpx"
	"github.com/NandanMaheta/swastik/apps/api/internal/platform/ratelimit"
)

const (
	webOrigin  = "https://admin.example.com"
	cookieName = "__Secure-swastik_rt"
	cookiePath = "/v1/auth/refresh"
	clientIP   = "203.0.113.7"
)

// hEnv is one HTTP test world.
type hEnv struct {
	*authtest.Env
	Svc *auth.Service
	API humatest.TestAPI
}

// hLimit is a limiter that never interferes unless a test sets a small limit.
func hLimit(e *authtest.Env, limit int) *ratelimit.Limiter {
	return ratelimit.New(limit, time.Minute, 1000, e.Clock.Now)
}

func newHandlerEnv(t *testing.T) *hEnv { return newHandlerEnvLimit(t, 10_000) }

func newHandlerEnvLimit(t *testing.T, limit int) *hEnv {
	t.Helper()
	e := authtest.New(t)
	svc := e.Service(t)
	httpx.InstallErrors()
	_, api := humatest.New(t, huma.DefaultConfig("Swastik test", "1.0.0"))
	authz.Install(api, map[string]authz.Verifier{"bearer": svc.BearerVerifier(), "mfaChallenge": svc.ChallengeVerifier()})
	auth.Register(api, svc, auth.HandlerConfig{WebOrigins: []string{webOrigin}, TrustedProxyHops: 1, Limiter: hLimit(e, limit)})
	authz.AssertDeclared(api)
	return &hEnv{Env: e, Svc: svc, API: api}
}

// hdr are the headers every request carries: the client address behind one trusted proxy hop.
func hdr(extra ...string) []any {
	out := []any{"X-Forwarded-For: " + clientIP}
	for _, h := range extra {
		out = append(out, h)
	}
	return out
}

func bearer(token string) string { return "Authorization: Bearer " + token }

// webHeaders are the headers a browser sends from the admin panel.
func webHeaders() []string { return []string{"Origin: " + webOrigin, "X-Swastik-CSRF: 1"} }

func (h *hEnv) do(method, path string, body any, headers ...string) *httptest.ResponseRecorder {
	args := hdr(headers...)
	if body != nil {
		args = append(args, body)
	}
	return h.API.Do(method, path, args...)
}

func (h *hEnv) post(path string, body any, headers ...string) *httptest.ResponseRecorder {
	return h.do(http.MethodPost, path, body, headers...)
}

func (h *hEnv) get(path string, headers ...string) *httptest.ResponseRecorder {
	return h.do(http.MethodGet, path, nil, headers...)
}

func (h *hEnv) del(path string, headers ...string) *httptest.ResponseRecorder {
	return h.do(http.MethodDelete, path, nil, headers...)
}

// ---- request bodies ----

func hDevice(id uuid.UUID, platform string) map[string]any {
	return map[string]any{"id": id.String(), "name": "Test device", "platform": platform}
}

func hSignInBody(u authtest.User, clientType string, device uuid.UUID) map[string]any {
	platform := auth.PlatformAndroid
	if clientType == auth.ClientTypeWeb {
		platform = auth.PlatformWeb
	}
	return map[string]any{"identifier": u.Email, "password": u.Password, "client_type": clientType, "device": hDevice(device, platform)}
}

// ---- responses ----

func hBody(rec *httptest.ResponseRecorder) string { return rec.Body.String() }

func hMap(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatalf("response is not a JSON object (status %d): %q", rec.Code, hBody(rec))
	}
	return m
}

func hSub(t *testing.T, m map[string]any, key string) map[string]any {
	t.Helper()
	sub, ok := m[key].(map[string]any)
	if !ok {
		t.Fatalf("response has no object %q: %v", key, m)
	}
	return sub
}

// hSession reads a SessionTokens object.
type hSessionBody struct {
	AccessToken      string
	RefreshToken     string
	SessionID        uuid.UUID
	SessionExpiresAt time.Time
	IdleExpiresAt    time.Time
	Raw              map[string]any
}

func hSessionOf(t *testing.T, m map[string]any) hSessionBody {
	t.Helper()
	s := hSessionBody{Raw: m}
	s.AccessToken, _ = m["access_token"].(string)
	s.RefreshToken, _ = m["refresh_token"].(string)
	id, _ := m["session_id"].(string)
	s.SessionID, _ = uuid.Parse(id)
	exp, _ := m["session_expires_at"].(string)
	s.SessionExpiresAt, _ = time.Parse(time.RFC3339, exp)
	idle, _ := m["idle_expires_at"].(string)
	s.IdleExpiresAt, _ = time.Parse(time.RFC3339, idle)
	if m["token_type"] != "Bearer" || s.AccessToken == "" || s.SessionID == uuid.Nil || s.SessionExpiresAt.IsZero() {
		t.Fatalf("not a SessionTokens object: %v", m)
	}
	return s
}

// hProblem asserts an RFC 9457 problem with the given status and code, and returns its body.
func hProblem(t *testing.T, rec *httptest.ResponseRecorder, status int, code string) map[string]any {
	t.Helper()
	if rec.Code != status {
		t.Fatalf("status = %d, want %d (%s); body %s", rec.Code, status, code, hBody(rec))
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/problem+json") {
		t.Errorf("content-type = %q, want application/problem+json", ct)
	}
	m := hMap(t, rec)
	if m["code"] != code || m["type"] != "urn:swastik:problem:"+code || m["status"] != float64(status) {
		t.Errorf("problem = %v, want code %s, type urn:swastik:problem:%s, status %d", m, code, code, status)
	}
	return m
}

func hOK(t *testing.T, rec *httptest.ResponseRecorder, status int) {
	t.Helper()
	if rec.Code != status {
		t.Fatalf("status = %d, want %d; body %s", rec.Code, status, hBody(rec))
	}
}

// hRefreshCookie returns the refresh cookie set by the response, or nil.
func hRefreshCookie(rec *httptest.ResponseRecorder) *http.Cookie {
	for _, c := range rec.Result().Cookies() {
		if c.Name == cookieName {
			return c
		}
	}
	return nil
}

// hAssertSetCookie checks every attribute of the refresh cookie of a web session (P-04).
func hAssertSetCookie(t *testing.T, rec *httptest.ResponseRecorder, wantMaxAge time.Duration) *http.Cookie {
	t.Helper()
	c := hRefreshCookie(rec)
	if c == nil {
		t.Fatalf("no %s cookie in the response; headers %v", cookieName, rec.Header()["Set-Cookie"])
	}
	if !strings.HasPrefix(c.Value, "drt_") || c.Path != cookiePath || c.Domain != "" || !c.HttpOnly || !c.Secure ||
		c.SameSite != http.SameSiteStrictMode || c.MaxAge != int(wantMaxAge.Seconds()) {
		t.Errorf("cookie = %+v, want drt_ value, Path=%s, no Domain, HttpOnly, Secure, SameSite=Strict, Max-Age=%d", c, cookiePath, int(wantMaxAge.Seconds()))
	}
	return c
}

func hAssertCookieCleared(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	c := hRefreshCookie(rec)
	if c == nil || c.Value != "" || c.MaxAge >= 0 || c.Path != cookiePath || !c.HttpOnly || !c.Secure {
		t.Errorf("cookie = %+v, want the refresh cookie cleared (empty, Max-Age=0, Path=%s)", c, cookiePath)
	}
}

// hNoSideEffects asserts nothing was written: no session, no audit row, no throttle row.
func hNoSideEffects(t *testing.T, e *authtest.Env, what string) {
	t.Helper()
	for _, table := range []string{"device_sessions", "refresh_tokens", "audit_log", "auth_throttles"} {
		if n := svCount(t, e, `SELECT count(*) FROM `+table); n != 0 {
			t.Errorf("%s: %s has %d rows, want 0 (nothing may be written)", what, table, n)
		}
	}
}

// hWebSignIn signs a client in as the web transport and returns the cookie and the session.
func hWebSignIn(t *testing.T, h *hEnv, u authtest.User, device uuid.UUID) (*http.Cookie, hSessionBody) {
	t.Helper()
	rec := h.post("/v1/auth/sign-in", hSignInBody(u, auth.ClientTypeWeb, device), webHeaders()...)
	hOK(t, rec, http.StatusOK)
	sess := hSessionOf(t, hSub(t, hMap(t, rec), "session"))
	c := hRefreshCookie(rec)
	if c == nil {
		t.Fatal("web sign-in set no refresh cookie")
	}
	h.Secrets.Add("refresh cookie", c.Value)
	h.Secrets.Add("access token", sess.AccessToken)
	return c, sess
}

// hMobileSignIn signs a client in as the mobile transport.
func hMobileSignIn(t *testing.T, h *hEnv, u authtest.User, device uuid.UUID) hSessionBody {
	t.Helper()
	rec := h.post("/v1/auth/sign-in", hSignInBody(u, auth.ClientTypeMobile, device))
	hOK(t, rec, http.StatusOK)
	sess := hSessionOf(t, hSub(t, hMap(t, rec), "session"))
	h.Secrets.Add("access token", sess.AccessToken)
	h.Secrets.Add("refresh token", sess.RefreshToken)
	return sess
}

// hAdminSession is a signed-in admin (authenticator enrolled) by fixture: its principal and token.
type hAdminSession struct {
	mfAdmin
	SessionID uuid.UUID
	Token     string
}

func hAdmin(t *testing.T, h *hEnv) hAdminSession {
	t.Helper()
	a := mfEnrolled(t, h.Env)
	id, _ := mfSession(t, h.Env, a.User)
	return hAdminSession{mfAdmin: a, SessionID: id, Token: h.AccessToken(t, a.User, id)}
}
