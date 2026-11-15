package auth_test

// S17 - HTTP handlers of sign-in, refresh, sessions, devices and password change
// (contracts/openapi-auth.yaml, contracts/error-codes.md, plan P-04, P-08, P-10, P-17).

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

func TestHandler_SignInMobileReturnsTheSessionWithTheRefreshTokenInTheBody(t *testing.T) {
	h := newHandlerEnv(t)
	u := h.UserWithStatus(t, auth.StatusActive)

	rec := h.post("/v1/auth/sign-in", hSignInBody(u, auth.ClientTypeMobile, uuid.New()))
	hOK(t, rec, http.StatusOK)
	m := hMap(t, rec)
	if m["next_step"] != "signed_in" || m["challenge"] != nil {
		t.Fatalf("response = %v, want next_step signed_in and no challenge", m)
	}
	sess := hSessionOf(t, hSub(t, m, "session"))
	if !strings.HasPrefix(sess.RefreshToken, "drt_") {
		t.Errorf("refresh_token = %q, want a drt_ token in the body for client_type mobile", sess.RefreshToken)
	}
	user := hSub(t, sess.Raw, "user")
	if user["id"] != u.ID.String() || user["role"] != "client" || user["email"] != u.Email || user["name"] != u.Name {
		t.Errorf("user = %v", user)
	}
	if !sess.SessionExpiresAt.Equal(h.Clock.Now().Add(90*24*time.Hour)) || !sess.IdleExpiresAt.Equal(h.Clock.Now().Add(30*24*time.Hour)) {
		t.Errorf("lifetimes: absolute %v idle %v", sess.SessionExpiresAt, sess.IdleExpiresAt)
	}
	if rec.Header().Get("Set-Cookie") != "" {
		t.Errorf("a mobile sign-in set a cookie: %q", rec.Header().Get("Set-Cookie"))
	}
	if p, err := h.Svc.BearerVerifier().Verify(t.Context(), sess.AccessToken); err != nil || p.UserID != u.ID || p.SessionID != sess.SessionID {
		t.Errorf("the access token verifies to %+v, %v", p, err)
	}
	row := mfOnly(t, h.Env, auth.ActionSignInSucceeded)
	if after := mfAfter(t, row); after["ip"] != clientIP || after["client_type"] != "mobile" {
		t.Errorf("audit after = %v, want the proxy-resolved ip %s", after, clientIP)
	}
}

func TestHandler_SignInWebKeepsTheRefreshTokenOutOfTheBodyAndSetsTheCookie(t *testing.T) {
	h := newHandlerEnv(t)
	u := h.UserWithStatus(t, auth.StatusActive)

	rec := h.post("/v1/auth/sign-in", hSignInBody(u, auth.ClientTypeWeb, uuid.New()), webHeaders()...)
	hOK(t, rec, http.StatusOK)
	c := hAssertSetCookie(t, rec, 90*24*time.Hour)
	sess := hSessionOf(t, hSub(t, hMap(t, rec), "session"))
	if _, present := sess.Raw["refresh_token"]; present || strings.Contains(hBody(rec), c.Value) || strings.Contains(hBody(rec), "drt_") {
		t.Errorf("the body of a web sign-in carries a refresh token: %s", hBody(rec))
	}
	if ss := svSession(t, h.Env, sess.SessionID); ss.ClientType != "web" {
		t.Errorf("session client_type = %q, want web", ss.ClientType)
	}
}

func TestHandler_SignInFailuresShareOneGenericResponse(t *testing.T) {
	h := newHandlerEnv(t)
	active := h.UserWithStatus(t, auth.StatusActive)
	pending := h.UserWithStatus(t, auth.StatusPendingApproval)
	disabled := h.UserWithStatus(t, auth.StatusDisabled)
	admin := h.NewAdmin(t)

	wrong := hSignInBody(active, auth.ClientTypeMobile, uuid.New())
	wrong["password"] = wrongPassword
	unknown := hSignInBody(active, auth.ClientTypeMobile, uuid.New())
	unknown["identifier"] = "nobody@example.com"
	notActive := hSignInBody(pending, auth.ClientTypeMobile, uuid.New())
	off := hSignInBody(disabled, auth.ClientTypeMobile, uuid.New())
	adminByMobile := hSignInBody(admin, auth.ClientTypeMobile, uuid.New())
	adminByMobile["identifier"] = "9876543210"

	var first string
	for name, body := range map[string]map[string]any{"wrong password": wrong, "unknown identifier": unknown,
		"pending approval": notActive, "disabled": off, "admin by mobile": adminByMobile} {
		rec := h.post("/v1/auth/sign-in", body)
		hProblem(t, rec, http.StatusUnauthorized, "auth.invalid_credentials")
		if first == "" {
			first = hBody(rec)
		} else if hBody(rec) != first {
			t.Errorf("%s: body differs from the others (US-1, D-09):\n %s\n %s", name, hBody(rec), first)
		}
		if rec.Header().Get("Retry-After") != "" {
			t.Errorf("%s: Retry-After header present (no lock timing may leak)", name)
		}
		if strings.Contains(hBody(rec), wrongPassword) {
			t.Errorf("%s: the password is echoed", name)
		}
	}
	// A locked account looks the same, even for the right password.
	for range 5 {
		hProblem(t, h.post("/v1/auth/sign-in", wrong), http.StatusUnauthorized, "auth.invalid_credentials")
	}
	locked := h.post("/v1/auth/sign-in", hSignInBody(active, auth.ClientTypeMobile, uuid.New()))
	hProblem(t, locked, http.StatusUnauthorized, "auth.invalid_credentials")
	if hBody(locked) != first {
		t.Errorf("the locked-account body differs: %s", hBody(locked))
	}
}

func TestHandler_SignInIdentifierAndValidationErrors(t *testing.T) {
	h := newHandlerEnv(t)
	u := h.UserWithStatus(t, auth.StatusActive)
	good := func() map[string]any { return hSignInBody(u, auth.ClientTypeMobile, uuid.New()) }

	bad := good()
	bad["identifier"] = "12345"
	hProblem(t, h.post("/v1/auth/sign-in", bad), http.StatusUnprocessableEntity, "auth.identifier_invalid")

	secret := "never-echo-this-9c2f1"
	for name, mutate := range map[string]func(m map[string]any){
		"missing client_type":  func(m map[string]any) { delete(m, "client_type") },
		"unknown client_type":  func(m map[string]any) { m["client_type"] = "desktop" },
		"unknown platform":     func(m map[string]any) { m["device"] = hDevice(uuid.New(), "tv") },
		"device id not a uuid": func(m map[string]any) { m["device"] = map[string]any{"id": "x", "name": "n", "platform": "android"} },
		"empty identifier":     func(m map[string]any) { m["identifier"] = "" },
		"extra property":       func(m map[string]any) { m["is_admin"] = true },
		"password not a string": func(m map[string]any) {
			m["password"] = 12345
			m["note"] = secret
		},
	} {
		body := good()
		body["password"] = secret
		mutate(body)
		rec := h.post("/v1/auth/sign-in", body)
		hProblem(t, rec, http.StatusUnprocessableEntity, "validation_failed")
		if strings.Contains(hBody(rec), secret) {
			t.Errorf("%s: the response echoes submitted data: %s", name, hBody(rec))
		}
	}

	// A body that is not JSON never comes back in the response (plan P-10).
	rec := h.post("/v1/auth/sign-in", strings.NewReader(`{"password":"`+secret+`", oops`), "Content-Type: application/json")
	if rec.Code != http.StatusBadRequest && rec.Code != http.StatusUnprocessableEntity {
		t.Errorf("malformed JSON: status = %d, want 400 or 422", rec.Code)
	}
	if strings.Contains(hBody(rec), secret) {
		t.Errorf("malformed JSON: the response echoes the body: %s", hBody(rec))
	}
	hNoSideEffects(t, h.Env, "invalid input")
}

func TestHandler_SignInWithoutAnOrganisationIsNotConfigured(t *testing.T) {
	h := newHandlerEnv(t)
	h.Exec(t, `DELETE FROM orgs`)
	body := map[string]any{"identifier": "owner@example.com", "password": "river-lantern-42-monsoon", "client_type": "mobile", "device": hDevice(uuid.New(), "android")}
	hProblem(t, h.post("/v1/auth/sign-in", body), http.StatusServiceUnavailable, "auth.not_configured")
}

func TestHandler_AdminSignInReturnsAChallengeAndNoSession(t *testing.T) {
	h := newHandlerEnv(t)
	enrolled := mfEnrolled(t, h.Env)
	fresh := h.NewAdmin(t)
	for name, tt := range map[string]struct {
		user authtest.User
		next string
	}{"enrolled": {enrolled.User, "mfa_required"}, "not yet enrolled": {fresh, "mfa_enrolment_required"}} {
		rec := h.post("/v1/auth/sign-in", hSignInBody(tt.user, auth.ClientTypeMobile, uuid.New()))
		hOK(t, rec, http.StatusOK)
		m := hMap(t, rec)
		ch := hSub(t, m, "challenge")
		token, _ := ch["challenge_token"].(string)
		if m["next_step"] != tt.next || m["session"] != nil || !strings.HasPrefix(token, "dmc_") || ch["expires_at"] == nil {
			t.Errorf("%s: response = %v, want next_step %s, a dmc_ challenge and no session", name, m, tt.next)
		}
		if rec.Header().Get("Set-Cookie") != "" {
			t.Errorf("%s: a challenge response set a cookie", name)
		}
	}
	if got := svAllSessions(t, h.Env, enrolled.ID) + svAllSessions(t, h.Env, fresh.ID); got != 0 {
		t.Errorf("sessions = %d, want 0 until the second factor completes", got)
	}
}

func TestHandler_RateLimitAnswers429BeforeAnyWork(t *testing.T) {
	h := newHandlerEnvLimit(t, 3)
	u := h.UserWithStatus(t, auth.StatusActive)
	wrong := hSignInBody(u, auth.ClientTypeMobile, uuid.New())
	wrong["password"] = wrongPassword
	for range 3 {
		hProblem(t, h.post("/v1/auth/sign-in", wrong), http.StatusUnauthorized, "auth.invalid_credentials")
	}
	before := len(h.AuditRows(t))
	rec := h.post("/v1/auth/sign-in", hSignInBody(u, auth.ClientTypeMobile, uuid.New())) // the right password, but over the limit
	hProblem(t, rec, http.StatusTooManyRequests, "rate_limited")
	if got := len(h.AuditRows(t)); got != before || svAllSessions(t, h.Env, u.ID) != 0 {
		t.Errorf("a limited request did work: audit rows %d -> %d, sessions %d", before, got, svAllSessions(t, h.Env, u.ID))
	}
	// Another client address has its own window; the window ends after a minute.
	other := h.API.Post("/v1/auth/sign-in", "X-Forwarded-For: 198.51.100.9", hSignInBody(u, auth.ClientTypeMobile, uuid.New()))
	hOK(t, other, http.StatusOK)
	h.Clock.Advance(time.Minute)
	hOK(t, h.post("/v1/auth/sign-in", hSignInBody(u, auth.ClientTypeMobile, uuid.New())), http.StatusOK)
}

func TestHandler_RateLimitCoversRefreshAndTheSecondFactorButNotBearerOperations(t *testing.T) {
	t.Run("refresh", func(t *testing.T) {
		h := newHandlerEnvLimit(t, 3)
		for range 3 {
			hProblem(t, h.post("/v1/auth/refresh", map[string]any{"device_id": uuid.NewString(), "refresh_token": "drt_unknown"}), http.StatusUnauthorized, "auth.refresh_rejected")
		}
		hProblem(t, h.post("/v1/auth/refresh", map[string]any{"device_id": uuid.NewString(), "refresh_token": "drt_unknown"}), http.StatusTooManyRequests, "rate_limited")
	})
	t.Run("mfa verify", func(t *testing.T) {
		h := newHandlerEnvLimit(t, 3)
		a := mfEnrolled(t, h.Env)
		tok := mfChallenge(t, h.Env, h.Svc, a.User)
		for range 3 {
			hProblem(t, h.post("/v1/auth/mfa/verify", map[string]any{"code": mfWrong(t, h.Env, a.Secret)}, bearer(tok)), http.StatusUnauthorized, "auth.invalid_credentials")
		}
		hProblem(t, h.post("/v1/auth/mfa/verify", map[string]any{"code": mfWrong(t, h.Env, a.Secret)}, bearer(tok)), http.StatusTooManyRequests, "rate_limited")
	})
	t.Run("enrolment", func(t *testing.T) {
		h := newHandlerEnvLimit(t, 3)
		tok := mfPassword(t, h.Env, h.Svc, h.NewAdmin(t), auth.ClientTypeMobile).Challenge.Token
		for range 3 {
			hOK(t, h.post("/v1/auth/mfa/enrolment", nil, bearer(tok)), http.StatusOK)
		}
		hProblem(t, h.post("/v1/auth/mfa/enrolment", nil, bearer(tok)), http.StatusTooManyRequests, "rate_limited")
	})
	t.Run("bearer operations are not limited", func(t *testing.T) {
		h := newHandlerEnvLimit(t, 3)
		u := h.UserWithStatus(t, auth.StatusActive)
		sess := hMobileSignIn(t, h, u, uuid.New())
		for range 8 {
			hOK(t, h.get("/v1/auth/devices", bearer(sess.AccessToken)), http.StatusOK)
		}
	})
}

// ---- refresh ----

func TestHandler_RefreshMobileRotatesAndRejectsReuse(t *testing.T) {
	h := newHandlerEnv(t)
	u := h.UserWithStatus(t, auth.StatusActive)
	dev := uuid.New()
	first := hMobileSignIn(t, h, u, dev)
	h.Clock.Advance(time.Hour)

	rec := h.post("/v1/auth/refresh", map[string]any{"device_id": dev.String(), "refresh_token": first.RefreshToken})
	hOK(t, rec, http.StatusOK)
	second := hSessionOf(t, hMap(t, rec))
	if second.SessionID != first.SessionID || second.RefreshToken == "" || second.RefreshToken == first.RefreshToken || second.AccessToken == first.AccessToken {
		t.Fatalf("rotation = %+v, want the same session with a new refresh and access token", second)
	}
	if rec.Header().Get("Set-Cookie") != "" {
		t.Errorf("a body-token refresh set a cookie")
	}
	hProblem(t, h.post("/v1/auth/refresh", map[string]any{"device_id": dev.String(), "refresh_token": first.RefreshToken}),
		http.StatusUnauthorized, "auth.refresh_rejected")
	// Reuse ended the family: the successor is dead too.
	hProblem(t, h.post("/v1/auth/refresh", map[string]any{"device_id": dev.String(), "refresh_token": second.RefreshToken}),
		http.StatusUnauthorized, "auth.refresh_rejected")
}

func TestHandler_RefreshFailuresAreOneCode(t *testing.T) {
	h := newHandlerEnv(t)
	u := h.UserWithStatus(t, auth.StatusActive)
	dev := uuid.New()
	sess := hMobileSignIn(t, h, u, dev)
	for _, body := range []map[string]any{
		{"device_id": dev.String(), "refresh_token": "drt_" + strings.Repeat("A", 43)}, // unknown token
		{"device_id": dev.String()},                                         // no token at all
		{"device_id": uuid.NewString(), "refresh_token": sess.RefreshToken}, // device mismatch
	} {
		hProblem(t, h.post("/v1/auth/refresh", body), http.StatusUnauthorized, "auth.refresh_rejected")
	}
	hProblem(t, h.post("/v1/auth/refresh", map[string]any{"device_id": "nope", "refresh_token": sess.RefreshToken}), http.StatusUnprocessableEntity, "validation_failed")
	hProblem(t, h.post("/v1/auth/refresh", map[string]any{"refresh_token": sess.RefreshToken}), http.StatusUnprocessableEntity, "validation_failed")
	if svSession(t, h.Env, sess.SessionID).EndedAt == nil {
		t.Error("a device mismatch must end the session (D-11)")
	}
}

func TestHandler_RefreshOfADisabledUserIsRejected(t *testing.T) {
	h := newHandlerEnv(t)
	u := h.UserWithStatus(t, auth.StatusActive)
	dev := uuid.New()
	sess := hMobileSignIn(t, h, u, dev)
	if err := h.Svc.Disable(t.Context(), u.ID, authtest.Admin(uuid.New())); err != nil {
		t.Fatalf("Disable: %v", err)
	}
	hProblem(t, h.post("/v1/auth/refresh", map[string]any{"device_id": dev.String(), "refresh_token": sess.RefreshToken}), http.StatusUnauthorized, "auth.refresh_rejected")
}

// ---- sign-out and devices ----

func TestHandler_SignOutEndsTheSessionAndTheTokenStopsWorking(t *testing.T) {
	h := newHandlerEnv(t)
	u := h.UserWithStatus(t, auth.StatusActive)
	sess := hMobileSignIn(t, h, u, uuid.New())
	other := hMobileSignIn(t, h, u, uuid.New())

	rec := h.post("/v1/auth/sign-out", nil, bearer(sess.AccessToken))
	hOK(t, rec, http.StatusNoContent)
	if rec.Body.Len() != 0 {
		t.Errorf("a 204 has a body: %q", hBody(rec))
	}
	h.Clock.Advance(time.Second)
	bad := h.get("/v1/auth/devices", bearer(sess.AccessToken))
	hProblem(t, bad, http.StatusUnauthorized, "auth.unauthenticated")
	if bad.Header().Get("WWW-Authenticate") != "Bearer" {
		t.Errorf("WWW-Authenticate = %q, want Bearer", bad.Header().Get("WWW-Authenticate"))
	}
	hOK(t, h.get("/v1/auth/devices", bearer(other.AccessToken)), http.StatusOK)
}

func TestHandler_SignOutOfAWebSessionClearsTheCookie(t *testing.T) {
	h := newHandlerEnv(t)
	u := h.UserWithStatus(t, auth.StatusActive)
	_, sess := hWebSignIn(t, h, u, uuid.New())
	rec := h.post("/v1/auth/sign-out", nil, bearer(sess.AccessToken))
	hOK(t, rec, http.StatusNoContent)
	hAssertCookieCleared(t, rec)
}

func TestHandler_SignOutEverywhereEndsEverySessionIncludingThisOne(t *testing.T) {
	h := newHandlerEnv(t)
	u := h.UserWithStatus(t, auth.StatusActive)
	other := h.UserWithStatus(t, auth.StatusActive)
	_, web := hWebSignIn(t, h, u, uuid.New())
	phone := hMobileSignIn(t, h, u, uuid.New())
	theirs := hMobileSignIn(t, h, other, uuid.New())

	rec := h.post("/v1/auth/sign-out-everywhere", nil, bearer(web.AccessToken))
	hOK(t, rec, http.StatusNoContent)
	hAssertCookieCleared(t, rec)
	h.Clock.Advance(time.Second)
	for _, tok := range []string{web.AccessToken, phone.AccessToken} {
		hProblem(t, h.get("/v1/auth/devices", bearer(tok)), http.StatusUnauthorized, "auth.unauthenticated")
	}
	hOK(t, h.get("/v1/auth/devices", bearer(theirs.AccessToken)), http.StatusOK)
	if got := svLiveSessions(t, h.Env, u.ID); got != 0 {
		t.Errorf("live sessions = %d, want 0 (D-12)", got)
	}
}

func TestHandler_DevicesListsLiveSessionsOfTheCaller(t *testing.T) {
	h := newHandlerEnv(t)
	u := h.UserWithStatus(t, auth.StatusActive)
	other := h.UserWithStatus(t, auth.StatusActive)
	a := hMobileSignIn(t, h, u, uuid.New())
	h.Clock.Advance(time.Minute)
	b := hMobileSignIn(t, h, u, uuid.New())
	hMobileSignIn(t, h, other, uuid.New())
	ended := hMobileSignIn(t, h, u, uuid.New())
	hOK(t, h.post("/v1/auth/sign-out", nil, bearer(ended.AccessToken)), http.StatusNoContent)

	rec := h.get("/v1/auth/devices", bearer(b.AccessToken))
	hOK(t, rec, http.StatusOK)
	items, _ := hMap(t, rec)["items"].([]any)
	if len(items) != 2 {
		t.Fatalf("items = %d, want 2 live sessions of this user: %s", len(items), hBody(rec))
	}
	byID := map[string]map[string]any{}
	for _, it := range items {
		m := it.(map[string]any)
		byID[m["session_id"].(string)] = m
		for _, k := range []string{"session_id", "device_name", "platform", "signed_in_at", "last_active_at", "is_current"} {
			if _, ok := m[k]; !ok {
				t.Errorf("a device item lacks %q: %v", k, m)
			}
		}
	}
	if byID[b.SessionID.String()]["is_current"] != true || byID[a.SessionID.String()]["is_current"] != false {
		t.Errorf("is_current wrong: %v", byID)
	}
}

func TestHandler_RevokeDevice(t *testing.T) {
	h := newHandlerEnv(t)
	u := h.UserWithStatus(t, auth.StatusActive)
	other := h.UserWithStatus(t, auth.StatusActive)
	a := hMobileSignIn(t, h, u, uuid.New())
	b := hMobileSignIn(t, h, u, uuid.New())
	theirs := hMobileSignIn(t, h, other, uuid.New())

	hOK(t, h.del("/v1/auth/devices/"+a.SessionID.String(), bearer(b.AccessToken)), http.StatusNoContent)
	h.Clock.Advance(time.Second)
	hProblem(t, h.get("/v1/auth/devices", bearer(a.AccessToken)), http.StatusUnauthorized, "auth.unauthenticated")

	// Someone else's, an already ended one and a random one are indistinguishable.
	for _, id := range []uuid.UUID{theirs.SessionID, a.SessionID, uuid.New()} {
		hProblem(t, h.del("/v1/auth/devices/"+id.String(), bearer(b.AccessToken)), http.StatusNotFound, "auth.device_not_found")
	}
	if svSession(t, h.Env, theirs.SessionID).EndedAt != nil {
		t.Error("another user's session was ended")
	}
	hProblem(t, h.del("/v1/auth/devices/not-a-uuid", bearer(b.AccessToken)), http.StatusUnprocessableEntity, "validation_failed")

	// Revoking the current web session clears the cookie.
	_, web := hWebSignIn(t, h, u, uuid.New())
	rec := h.del("/v1/auth/devices/"+web.SessionID.String(), bearer(web.AccessToken))
	hOK(t, rec, http.StatusNoContent)
	hAssertCookieCleared(t, rec)
}

func TestHandler_BearerOperationsNeedAnAccessToken(t *testing.T) {
	h := newHandlerEnv(t)
	u := h.UserWithStatus(t, auth.StatusActive)
	sess := hMobileSignIn(t, h, u, uuid.New())
	for name, headers := range map[string][]string{
		"no header":           nil,
		"wrong scheme":        {"Authorization: Basic abc"},
		"a refresh token":     {bearer(sess.RefreshToken)},
		"garbage":             {bearer("not.a.jwt")},
		"an empty token":      {"Authorization: Bearer "},
		"the token of nobody": {bearer(sess.AccessToken[:len(sess.AccessToken)-2] + "xx")},
	} {
		rec := h.get("/v1/auth/devices", headers...)
		hProblem(t, rec, http.StatusUnauthorized, "auth.unauthenticated")
		if rec.Header().Get("WWW-Authenticate") != "Bearer" {
			t.Errorf("%s: WWW-Authenticate = %q", name, rec.Header().Get("WWW-Authenticate"))
		}
	}
}

// ---- password change ----

func TestHandler_ChangePasswordKeepsThisSessionAndEndsTheOthers(t *testing.T) {
	h := newHandlerEnv(t)
	u := h.UserWithStatus(t, auth.StatusActive)
	current := hMobileSignIn(t, h, u, uuid.New())
	other := hMobileSignIn(t, h, u, uuid.New())

	const next = "monsoon-lantern-77-river"
	h.Secrets.Add("new password", next)
	rec := h.post("/v1/auth/password/change", map[string]any{"current_password": u.Password, "new_password": next}, bearer(current.AccessToken))
	hOK(t, rec, http.StatusNoContent)
	h.Clock.Advance(time.Second)
	hOK(t, h.get("/v1/auth/devices", bearer(current.AccessToken)), http.StatusOK)
	hProblem(t, h.get("/v1/auth/devices", bearer(other.AccessToken)), http.StatusUnauthorized, "auth.unauthenticated")
	// The new password signs in; the old one does not.
	hOK(t, h.post("/v1/auth/sign-in", map[string]any{"identifier": u.Email, "password": next, "client_type": "mobile", "device": hDevice(uuid.New(), "android")}), http.StatusOK)
	hProblem(t, h.post("/v1/auth/sign-in", hSignInBody(u, auth.ClientTypeMobile, uuid.New())), http.StatusUnauthorized, "auth.invalid_credentials")
	h.Secrets.ScanAuditLog(t.Context(), t, h.Pool)
}

func TestHandler_ChangePasswordRefusals(t *testing.T) {
	h := newHandlerEnv(t)
	u := h.UserWithStatus(t, auth.StatusActive)
	sess := hMobileSignIn(t, h, u, uuid.New())
	call := func(current, next string) *httptest.ResponseRecorder {
		return h.post("/v1/auth/password/change", map[string]any{"current_password": current, "new_password": next}, bearer(sess.AccessToken))
	}

	hProblem(t, call(wrongPassword, "monsoon-lantern-77-river"), http.StatusForbidden, "auth.reauth_failed")
	for name, tt := range map[string]struct{ next, code string }{
		"too short":          {"short1", auth.PolicyTooShort},
		"too common":         {"1234567890", auth.PolicyTooCommon},
		"equals the email":   {u.Email, auth.PolicyMatchesIdentifier},
		"equals the current": {u.Password, auth.PolicyUnchanged},
		"too long":           {strings.Repeat("a1b2", 65), auth.PolicyTooLong},
	} {
		rec := call(u.Password, tt.next)
		hProblem(t, rec, http.StatusUnprocessableEntity, tt.code)
		if strings.Contains(hBody(rec), u.Password) || strings.Contains(hBody(rec), tt.next) && len(tt.next) > 12 {
			t.Errorf("%s: the response echoes a password", name)
		}
	}
	hProblem(t, call(u.Password, strings.Repeat("x", 2049)), http.StatusUnprocessableEntity, "validation_failed")
	hProblem(t, h.post("/v1/auth/password/change", map[string]any{"new_password": "monsoon-lantern-77-river"}, bearer(sess.AccessToken)), http.StatusUnprocessableEntity, "validation_failed")
	hProblem(t, h.post("/v1/auth/password/change", map[string]any{"current_password": u.Password, "new_password": "monsoon-lantern-77-river"}), http.StatusUnauthorized, "auth.unauthenticated")
}

func TestHandler_ChangePasswordWhileLockedIsReauthFailed(t *testing.T) {
	h := newHandlerEnv(t)
	u := h.UserWithStatus(t, auth.StatusActive)
	sess := hMobileSignIn(t, h, u, uuid.New())
	for range 5 {
		svWrong(t, h.Svc, u)
	}
	rec := h.post("/v1/auth/password/change", map[string]any{"current_password": u.Password, "new_password": "monsoon-lantern-77-river"}, bearer(sess.AccessToken))
	hProblem(t, rec, http.StatusForbidden, "auth.reauth_failed")
}

func TestHandler_ErrorsAreProblemJSONWithTheTypeURN(t *testing.T) {
	h := newHandlerEnv(t)
	rec := h.post("/v1/auth/sign-in", map[string]any{})
	m := hProblem(t, rec, http.StatusUnprocessableEntity, "validation_failed")
	if _, err := url.Parse(m["type"].(string)); err != nil || m["title"] == nil || m["detail"] == nil {
		t.Errorf("problem fields missing: %v", m)
	}
	if errs, _ := m["errors"].([]any); len(errs) == 0 {
		t.Errorf("a validation problem lists its errors: %v", m)
	} else {
		for _, e := range errs {
			if _, hasValue := e.(map[string]any)["value"]; hasValue {
				t.Errorf("errors[] carries a value: %v", e)
			}
		}
	}
}
