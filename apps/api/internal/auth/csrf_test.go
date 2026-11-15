package auth_test

// S17 - CSRF defences of the admin browser cookie flow (plan P-04, error auth.csrf_rejected).
// They apply to a refresh whose credential comes from the cookie and to every operation that sets
// the cookie: web sign-in, mfa-verify and enrolment-confirm of a web challenge. Failure is 403
// auth.csrf_rejected, answered before any credential is checked, so nothing is written, no failed
// attempt is counted and no token is consumed.

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/NandanMaheta/swastik/apps/api/internal/auth"
	"github.com/NandanMaheta/swastik/apps/api/internal/auth/authtest"
)

// csrfBad are the header sets a cross-site request can produce. Each is rejected.
var csrfBad = map[string][]string{
	"no Origin":                    {"X-Swastik-CSRF: 1"},
	"Origin null":                  {"Origin: null", "X-Swastik-CSRF: 1"},
	"foreign Origin":               {"Origin: https://evil.example.net", "X-Swastik-CSRF: 1"},
	"sibling subdomain":            {"Origin: https://evil.admin.example.com", "X-Swastik-CSRF: 1"},
	"parent domain":                {"Origin: https://example.com", "X-Swastik-CSRF: 1"},
	"http instead of https":        {"Origin: http://admin.example.com", "X-Swastik-CSRF: 1"},
	"other port":                   {"Origin: https://admin.example.com:8443", "X-Swastik-CSRF: 1"},
	"trailing slash":               {"Origin: https://admin.example.com/", "X-Swastik-CSRF: 1"},
	"different case":               {"Origin: https://ADMIN.example.com", "X-Swastik-CSRF: 1"},
	"allowed origin as a prefix":   {"Origin: https://admin.example.com.evil.net", "X-Swastik-CSRF: 1"},
	"no CSRF header":               {"Origin: " + webOrigin},
	"CSRF header 0":                {"Origin: " + webOrigin, "X-Swastik-CSRF: 0"},
	"CSRF header true":             {"Origin: " + webOrigin, "X-Swastik-CSRF: true"},
	"CSRF header empty":            {"Origin: " + webOrigin, "X-Swastik-CSRF: "},
	"neither Origin nor header":    {},
	"foreign Origin and no header": {"Origin: https://evil.example.net"},
}

func csrfRejected(t *testing.T, name string, rec *httptest.ResponseRecorder) {
	t.Helper()
	if rec.Code != http.StatusForbidden {
		t.Errorf("%s: status = %d, want 403; body %s", name, rec.Code, hBody(rec))
		return
	}
	hProblem(t, rec, http.StatusForbidden, "auth.csrf_rejected")
	if rec.Header().Get("Set-Cookie") != "" {
		t.Errorf("%s: a rejected request set a cookie", name)
	}
}

func TestCSRF_WebSignInRejectsEveryCrossSiteShape(t *testing.T) {
	h := newHandlerEnv(t)
	u := h.UserWithStatus(t, auth.StatusActive)
	wrong := hSignInBody(u, auth.ClientTypeWeb, uuid.New())
	wrong["password"] = wrongPassword // CSRF is decided before the password: still 403, never 401
	for name, headers := range csrfBad {
		csrfRejected(t, name, h.post("/v1/auth/sign-in", hSignInBody(u, auth.ClientTypeWeb, uuid.New()), headers...))
		csrfRejected(t, name+" (wrong password)", h.post("/v1/auth/sign-in", wrong, headers...))
	}
	hNoSideEffects(t, h.Env, "rejected web sign-ins")
}

func TestCSRF_WebSignInWithTheAllowedOriginSucceeds(t *testing.T) {
	h := newHandlerEnv(t)
	u := h.UserWithStatus(t, auth.StatusActive)
	rec := h.post("/v1/auth/sign-in", hSignInBody(u, auth.ClientTypeWeb, uuid.New()), webHeaders()...)
	hOK(t, rec, http.StatusOK)
	hAssertSetCookie(t, rec, 90*24*time.Hour)
}

func TestCSRF_MobileSignInNeedsNoBrowserHeaders(t *testing.T) {
	h := newHandlerEnv(t)
	u := h.UserWithStatus(t, auth.StatusActive)
	hOK(t, h.post("/v1/auth/sign-in", hSignInBody(u, auth.ClientTypeMobile, uuid.New())), http.StatusOK) // no Origin, no header
}

func TestCSRF_NonJSONContentTypesNeverReachTheCredentialCheck(t *testing.T) {
	// A form post is the classic cross-site request. The answer is 403 csrf_rejected or 415, never a
	// sign-in; nothing is written either way.
	h := newHandlerEnv(t)
	u := h.UserWithStatus(t, auth.StatusActive)
	form := url.Values{"identifier": {u.Email}, "password": {u.Password}, "client_type": {"web"}}.Encode()
	for _, ct := range []string{"application/x-www-form-urlencoded", "text/plain", "multipart/form-data; boundary=x"} {
		rec := h.post("/v1/auth/sign-in", strings.NewReader(form), append(webHeaders(), "Content-Type: "+ct)...)
		if rec.Code != http.StatusForbidden && rec.Code != http.StatusUnsupportedMediaType {
			t.Errorf("content-type %s: status = %d, want 403 or 415; body %s", ct, rec.Code, hBody(rec))
		}
		if rec.Header().Get("Set-Cookie") != "" || strings.Contains(hBody(rec), "access_token") {
			t.Errorf("content-type %s: a non-JSON request signed in", ct)
		}
	}
	hNoSideEffects(t, h.Env, "non-JSON sign-ins")
}

func TestCSRF_CookieRefreshRotatesAndKeepsTheTokenOutOfTheBody(t *testing.T) {
	h := newHandlerEnv(t)
	u := h.UserWithStatus(t, auth.StatusActive)
	dev := uuid.New()
	cookie, first := hWebSignIn(t, h, u, dev)
	h.Clock.Advance(time.Hour)

	headers := append(webHeaders(), "Cookie: "+cookieName+"="+cookie.Value)
	rec := h.post("/v1/auth/refresh", map[string]any{"device_id": dev.String()}, headers...)
	hOK(t, rec, http.StatusOK)
	next := hAssertSetCookie(t, rec, 90*24*time.Hour-time.Hour) // Max-Age runs to the absolute expiry
	if next.Value == cookie.Value {
		t.Error("the cookie was not rotated")
	}
	sess := hSessionOf(t, hMap(t, rec))
	if _, present := sess.Raw["refresh_token"]; present || strings.Contains(hBody(rec), "drt_") {
		t.Errorf("the body of a cookie refresh carries a refresh token: %s", hBody(rec))
	}
	if sess.SessionID != first.SessionID || sess.AccessToken == first.AccessToken {
		t.Errorf("session = %+v, want the same session and a new access token", sess)
	}
	// The old cookie value is now a reused credential.
	hProblem(t, h.post("/v1/auth/refresh", map[string]any{"device_id": dev.String()}, headers...), http.StatusUnauthorized, "auth.refresh_rejected")
}

func TestCSRF_CookieRefreshRejectsEveryCrossSiteShapeWithoutConsumingTheToken(t *testing.T) {
	h := newHandlerEnv(t)
	u := h.UserWithStatus(t, auth.StatusActive)
	dev := uuid.New()
	cookie, _ := hWebSignIn(t, h, u, dev)
	withCookie := func(headers []string) []string {
		return append(append([]string{}, headers...), "Cookie: "+cookieName+"="+cookie.Value)
	}

	for name, headers := range csrfBad {
		csrfRejected(t, name, h.post("/v1/auth/refresh", map[string]any{"device_id": dev.String()}, withCookie(headers)...))
	}
	form := url.Values{"device_id": {dev.String()}}.Encode()
	rec := h.post("/v1/auth/refresh", strings.NewReader(form), append(withCookie(webHeaders()), "Content-Type: application/x-www-form-urlencoded")...)
	if rec.Code != http.StatusForbidden && rec.Code != http.StatusUnsupportedMediaType {
		t.Errorf("form content type: status = %d, want 403 or 415", rec.Code)
	}
	// None of that touched the session: the genuine request still works with the same cookie.
	hOK(t, h.post("/v1/auth/refresh", map[string]any{"device_id": dev.String()}, withCookie(webHeaders())...), http.StatusOK)
}

func TestCSRF_RefreshByBodyTokenIsNotACookieRequestAndNeedsNoBrowserHeaders(t *testing.T) {
	h := newHandlerEnv(t)
	u := h.UserWithStatus(t, auth.StatusActive)
	dev := uuid.New()
	sess := hMobileSignIn(t, h, u, dev)
	hOK(t, h.post("/v1/auth/refresh", map[string]any{"device_id": dev.String(), "refresh_token": sess.RefreshToken}), http.StatusOK)
}

func TestCSRF_TransportMismatchIsRefused(t *testing.T) {
	// A web session's token presented in the body, or a mobile session's token as a cookie, is one
	// generic refresh failure (P-03 transport mismatch).
	h := newHandlerEnv(t)
	u := h.UserWithStatus(t, auth.StatusActive)
	webDev, mobileDev := uuid.New(), uuid.New()
	cookie, _ := hWebSignIn(t, h, u, webDev)
	mobile := hMobileSignIn(t, h, u, mobileDev)

	hProblem(t, h.post("/v1/auth/refresh", map[string]any{"device_id": webDev.String(), "refresh_token": cookie.Value}), http.StatusUnauthorized, "auth.refresh_rejected")
	headers := append(webHeaders(), "Cookie: "+cookieName+"="+mobile.RefreshToken)
	hProblem(t, h.post("/v1/auth/refresh", map[string]any{"device_id": mobileDev.String()}, headers...), http.StatusUnauthorized, "auth.refresh_rejected")
}

// ---- the second factor of a web admin ----

func TestCSRF_MFAVerifyOfAWebChallenge(t *testing.T) {
	h := newHandlerEnv(t)
	a := mfEnrolled(t, h.Env)
	tok := mfPassword(t, h.Env, h.Svc, a.User, auth.ClientTypeWeb).Challenge.Token
	body := map[string]any{"code": mfCode(t, h.Env, a.Secret, 0)}

	for name, headers := range csrfBad {
		csrfRejected(t, name, h.post("/v1/auth/mfa/verify", body, append([]string{bearer(tok)}, headers...)...))
	}
	if got := mfFailures(t, h.Env, a.User); got != 0 || svAllSessions(t, h.Env, a.ID) != 0 {
		t.Fatalf("rejected requests counted %d failures and created %d sessions", got, svAllSessions(t, h.Env, a.ID))
	}
	// The challenge and the code were not consumed by any of that.
	rec := h.post("/v1/auth/mfa/verify", body, append([]string{bearer(tok)}, webHeaders()...)...)
	hOK(t, rec, http.StatusOK)
	hAssertSetCookie(t, rec, 7*24*time.Hour) // an admin session lives 7 days
	sess := hSessionOf(t, hMap(t, rec))
	if _, present := sess.Raw["refresh_token"]; present || strings.Contains(hBody(rec), "drt_") {
		t.Errorf("the body carries a refresh token: %s", hBody(rec))
	}
	if ss := svSession(t, h.Env, sess.SessionID); ss.ClientType != "web" {
		t.Errorf("client_type = %q, want web", ss.ClientType)
	}
}

func TestCSRF_EnrolmentConfirmOfAWebChallenge(t *testing.T) {
	h := newHandlerEnv(t)
	a := h.NewAdmin(t)
	tok := mfPassword(t, h.Env, h.Svc, a, auth.ClientTypeWeb).Challenge.Token
	rec := h.post("/v1/auth/mfa/enrolment", nil, bearer(tok))
	hOK(t, rec, http.StatusOK)
	secret, _ := hMap(t, rec)["secret"].(string)
	h.Secrets.AddTOTPSecret(secret)
	body := map[string]any{"code": authtest.TOTPCode(t, secret, h.Clock.Now())}

	for name, headers := range csrfBad {
		csrfRejected(t, name, h.post("/v1/auth/mfa/enrolment/confirm", body, append([]string{bearer(tok)}, headers...)...))
	}
	if m := mfMFARow(t, h.Env, a.ID); m.EnrolledAt != nil || m.PendingSecretEnc == nil {
		t.Fatalf("a rejected confirm changed the authenticator: %+v", m)
	}
	rec = h.post("/v1/auth/mfa/enrolment/confirm", body, append([]string{bearer(tok)}, webHeaders()...)...)
	hOK(t, rec, http.StatusOK)
	hAssertSetCookie(t, rec, 7*24*time.Hour)
	done := hMap(t, rec)
	if sess := hSub(t, done, "session"); sess["refresh_token"] != nil || strings.Contains(hBody(rec), "drt_") {
		t.Errorf("the body carries a refresh token: %s", hBody(rec))
	}
	if codes, _ := done["recovery_codes"].([]any); len(codes) != 10 {
		t.Errorf("recovery_codes = %v, want 10", codes)
	}
}

func TestCSRF_WebAdminSignInStartsWithTheSameGuard(t *testing.T) {
	// The password step of a web admin is a client_type=web sign-in: same rules, even though the
	// response carries a challenge and no cookie yet.
	h := newHandlerEnv(t)
	a := mfEnrolled(t, h.Env)
	for name, headers := range csrfBad {
		csrfRejected(t, name, h.post("/v1/auth/sign-in", hSignInBody(a.User, auth.ClientTypeWeb, uuid.New()), headers...))
	}
	hNoSideEffects(t, h.Env, "rejected web admin sign-ins")
	hOK(t, h.post("/v1/auth/sign-in", hSignInBody(a.User, auth.ClientTypeWeb, uuid.New()), webHeaders()...), http.StatusOK)
}
