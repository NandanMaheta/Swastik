package auth_test

// S17 - HTTP handlers of the admin second factor (US-5, P-05, contracts/openapi-auth.yaml):
// auth-mfa-verify, auth-mfa-enrolment-start/confirm (mfaChallenge) and
// auth-recovery-codes-regenerate, auth-authenticator-replace-start/confirm (bearer, admin).

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/NandanMaheta/swastik/apps/api/internal/auth"
	"github.com/NandanMaheta/swastik/apps/api/internal/auth/authtest"
)

func TestHandler_MFAVerifyWithATotpCode(t *testing.T) {
	h := newHandlerEnv(t)
	a := mfEnrolled(t, h.Env)
	tok := mfChallenge(t, h.Env, h.Svc, a.User)

	rec := h.post("/v1/auth/mfa/verify", map[string]any{"code": mfCode(t, h.Env, a.Secret, 0)}, bearer(tok))
	hOK(t, rec, http.StatusOK)
	sess := hSessionOf(t, hMap(t, rec)) // a flat SessionTokens, not wrapped
	if user := hSub(t, sess.Raw, "user"); user["role"] != "admin" || user["id"] != a.ID.String() {
		t.Errorf("user = %v", user)
	}
	if !strings.HasPrefix(sess.RefreshToken, "drt_") {
		t.Errorf("refresh_token = %q, want it in the body for a mobile challenge", sess.RefreshToken)
	}
	if !sess.SessionExpiresAt.Equal(h.Clock.Now().Add(7 * 24 * time.Hour)) {
		t.Errorf("absolute expiry = %v, want 7 days", sess.SessionExpiresAt)
	}
	hOK(t, h.get("/v1/auth/devices", bearer(sess.AccessToken)), http.StatusOK)
}

func TestHandler_MFAVerifyWithARecoveryCode(t *testing.T) {
	h := newHandlerEnv(t)
	a := mfEnrolled(t, h.Env)
	tok := mfChallenge(t, h.Env, h.Svc, a.User)
	hOK(t, h.post("/v1/auth/mfa/verify", map[string]any{"recovery_code": a.Codes[0]}, bearer(tok)), http.StatusOK)
	tok = mfChallenge(t, h.Env, h.Svc, a.User)
	hProblem(t, h.post("/v1/auth/mfa/verify", map[string]any{"recovery_code": a.Codes[0]}, bearer(tok)), http.StatusUnauthorized, "auth.invalid_credentials")
}

func TestHandler_MFAVerifyFailures(t *testing.T) {
	h := newHandlerEnv(t)
	a := mfEnrolled(t, h.Env)
	tok := mfChallenge(t, h.Env, h.Svc, a.User)
	code := mfCode(t, h.Env, a.Secret, 0)

	hProblem(t, h.post("/v1/auth/mfa/verify", map[string]any{"code": mfWrong(t, h.Env, a.Secret)}, bearer(tok)), http.StatusUnauthorized, "auth.invalid_credentials")
	for name, body := range map[string]map[string]any{
		"both code and recovery_code": {"code": code, "recovery_code": a.Codes[0]},
		"neither":                     {},
		"code too short":              {"code": "12345"},
		"code with letters":           {"code": "12345a"},
		"code too long":               {"code": "1234567"},
		"recovery code too short":     {"recovery_code": "ABCD-EFGH"},
		"unknown property":            {"code": code, "extra": 1},
	} {
		rec := h.post("/v1/auth/mfa/verify", body, bearer(tok))
		if rec.Code != http.StatusUnprocessableEntity {
			t.Errorf("%s: status = %d, want 422", name, rec.Code)
			continue
		}
		hProblem(t, rec, http.StatusUnprocessableEntity, "validation_failed")
	}
	// The challenge survived all of that and still completes.
	hOK(t, h.post("/v1/auth/mfa/verify", map[string]any{"code": code}, bearer(tok)), http.StatusOK)
	// ...once.
	hProblem(t, h.post("/v1/auth/mfa/verify", map[string]any{"code": mfCode(t, h.Env, a.Secret, 30*time.Second)}, bearer(tok)), http.StatusUnauthorized, "auth.unauthenticated")
}

func TestHandler_MFAOperationsAcceptOnlyAChallenge(t *testing.T) {
	h := newHandlerEnv(t)
	a := mfEnrolled(t, h.Env)
	sess := mfSignIn(t, h.Env, h.Svc, a)
	signedIn := hAdmin(t, h)
	body := map[string]any{"code": mfCode(t, h.Env, a.Secret, 60*time.Second)}
	for name, headers := range map[string][]string{
		"no credential":   nil,
		"an access token": {bearer(sess.AccessToken)},
		"a refresh token": {bearer(sess.RefreshToken)},
		"a fixture admin": {bearer(signedIn.Token)},
		"junk":            {bearer("dmc_" + strings.Repeat("A", 43))},
	} {
		for _, path := range []string{"/v1/auth/mfa/verify", "/v1/auth/mfa/enrolment", "/v1/auth/mfa/enrolment/confirm"} {
			rec := h.post(path, body, headers...)
			hProblem(t, rec, http.StatusUnauthorized, "auth.unauthenticated")
			if rec.Header().Get("WWW-Authenticate") != "Bearer" {
				t.Errorf("%s at %s: WWW-Authenticate = %q", name, path, rec.Header().Get("WWW-Authenticate"))
			}
		}
	}
}

func TestHandler_ABearerOperationRefusesAChallengeToken(t *testing.T) {
	// US-2 s9: the interim proof opens nothing but the second factor.
	h := newHandlerEnv(t)
	a := mfEnrolled(t, h.Env)
	tok := mfChallenge(t, h.Env, h.Svc, a.User)
	hProblem(t, h.get("/v1/auth/devices", bearer(tok)), http.StatusUnauthorized, "auth.unauthenticated")
	hProblem(t, h.post("/v1/auth/sign-out", nil, bearer(tok)), http.StatusUnauthorized, "auth.unauthenticated")
	hProblem(t, h.post("/v1/auth/mfa/recovery-codes", map[string]any{"password": a.Password, "code": mfCode(t, h.Env, a.Secret, 0)}, bearer(tok)), http.StatusUnauthorized, "auth.unauthenticated")
}

func TestHandler_EnrolmentOverHTTP(t *testing.T) {
	h := newHandlerEnv(t)
	a := h.NewAdmin(t)
	rec := h.post("/v1/auth/sign-in", hSignInBody(a, auth.ClientTypeMobile, uuid.New()))
	hOK(t, rec, http.StatusOK)
	m := hMap(t, rec)
	if m["next_step"] != "mfa_enrolment_required" {
		t.Fatalf("next_step = %v", m["next_step"])
	}
	tok := hSub(t, m, "challenge")["challenge_token"].(string)
	h.Secrets.Add("challenge token", tok)

	hProblem(t, h.post("/v1/auth/mfa/enrolment/confirm", map[string]any{"code": "123456"}, bearer(tok)), http.StatusConflict, "auth.mfa_no_pending_secret")

	rec = h.post("/v1/auth/mfa/enrolment", nil, bearer(tok))
	hOK(t, rec, http.StatusOK)
	enrol := hMap(t, rec)
	secret, _ := enrol["secret"].(string)
	uri, _ := enrol["otpauth_uri"].(string)
	h.Secrets.AddTOTPSecret(secret)
	if secret == "" || !strings.HasPrefix(uri, "otpauth://totp/Swastik:") || !strings.Contains(uri, "secret="+secret) {
		t.Fatalf("enrolment = %v", enrol)
	}
	if svAllSessions(t, h.Env, a.ID) != 0 {
		t.Error("a session exists before enrolment is confirmed")
	}

	hProblem(t, h.post("/v1/auth/mfa/enrolment/confirm", map[string]any{"code": mfWrong(t, h.Env, secret)}, bearer(tok)), http.StatusUnauthorized, "auth.invalid_credentials")
	rec = h.post("/v1/auth/mfa/enrolment/confirm", map[string]any{"code": authtest.TOTPCode(t, secret, h.Clock.Now())}, bearer(tok))
	hOK(t, rec, http.StatusOK)
	done := hMap(t, rec)
	sess := hSessionOf(t, hSub(t, done, "session"))
	codes, _ := done["recovery_codes"].([]any)
	if len(codes) != 10 {
		t.Fatalf("recovery_codes = %v, want 10", codes)
	}
	seen := map[string]bool{}
	for _, c := range codes {
		s, _ := c.(string)
		h.Secrets.Add("recovery code", s)
		if !recoveryCodeShape.MatchString(s) || seen[s] {
			t.Errorf("recovery code %q malformed or repeated", s)
		}
		seen[s] = true
	}
	hOK(t, h.get("/v1/auth/devices", bearer(sess.AccessToken)), http.StatusOK)
	h.Secrets.Add("access token", sess.AccessToken)
	h.Secrets.ScanAuditLog(t.Context(), t, h.Pool)
	// The challenge is used up.
	hProblem(t, h.post("/v1/auth/mfa/enrolment", nil, bearer(tok)), http.StatusUnauthorized, "auth.unauthenticated")
}

// ---- management by a signed-in admin ----

func TestHandler_RegenerateRecoveryCodes(t *testing.T) {
	h := newHandlerEnv(t)
	adm := hAdmin(t, h)
	code := mfCode(t, h.Env, adm.Secret, 0)

	rec := h.post("/v1/auth/mfa/recovery-codes", map[string]any{"password": adm.Password, "code": code}, bearer(adm.Token))
	hOK(t, rec, http.StatusOK)
	codes, _ := hMap(t, rec)["recovery_codes"].([]any)
	if len(codes) != 10 {
		t.Fatalf("recovery_codes = %v, want 10", codes)
	}
	for _, c := range codes {
		h.Secrets.Add("recovery code", c.(string))
	}
	if n := mfUsableCodes(t, h.Env, adm.User); n != 10 {
		t.Errorf("usable codes = %d, want the new 10 only", n)
	}
	// A replay of the same TOTP code, a wrong password and a malformed code.
	hProblem(t, h.post("/v1/auth/mfa/recovery-codes", map[string]any{"password": adm.Password, "code": code}, bearer(adm.Token)), http.StatusForbidden, "auth.reauth_failed")
	hProblem(t, h.post("/v1/auth/mfa/recovery-codes", map[string]any{"password": wrongPassword, "code": mfCode(t, h.Env, adm.Secret, 30*time.Second)}, bearer(adm.Token)), http.StatusForbidden, "auth.reauth_failed")
	hProblem(t, h.post("/v1/auth/mfa/recovery-codes", map[string]any{"password": adm.Password, "code": "abc"}, bearer(adm.Token)), http.StatusUnprocessableEntity, "validation_failed")
	h.Secrets.ScanAuditLog(t.Context(), t, h.Pool)
}

func TestHandler_ReplaceAuthenticator(t *testing.T) {
	h := newHandlerEnv(t)
	adm := hAdmin(t, h)
	otherID, _ := mfSession(t, h.Env, adm.User)
	otherTok := h.AccessToken(t, adm.User, otherID)

	hProblem(t, h.post("/v1/auth/mfa/authenticator/confirm", map[string]any{"code": "123456"}, bearer(adm.Token)), http.StatusConflict, "auth.mfa_no_pending_secret")
	for name, body := range map[string]map[string]any{
		"both factors": {"password": adm.Password, "code": mfCode(t, h.Env, adm.Secret, 0), "recovery_code": adm.Codes[0]},
		"no factor":    {"password": adm.Password},
	} {
		if rec := h.post("/v1/auth/mfa/authenticator", body, bearer(adm.Token)); rec.Code != http.StatusUnprocessableEntity {
			t.Errorf("%s: status = %d, want 422", name, rec.Code)
		}
	}
	hProblem(t, h.post("/v1/auth/mfa/authenticator", map[string]any{"password": wrongPassword, "code": mfCode(t, h.Env, adm.Secret, 0)}, bearer(adm.Token)), http.StatusForbidden, "auth.reauth_failed")

	rec := h.post("/v1/auth/mfa/authenticator", map[string]any{"password": adm.Password, "recovery_code": adm.Codes[2]}, bearer(adm.Token))
	hOK(t, rec, http.StatusOK)
	start := hMap(t, rec)
	secret, _ := start["secret"].(string)
	h.Secrets.AddTOTPSecret(secret)
	if secret == "" || secret == adm.Secret || start["otpauth_uri"] == nil {
		t.Fatalf("start = %v", start)
	}
	h.Clock.Advance(90 * time.Second)
	hProblem(t, h.post("/v1/auth/mfa/authenticator/confirm", map[string]any{"code": mfWrong(t, h.Env, secret)}, bearer(adm.Token)), http.StatusForbidden, "auth.reauth_failed")
	hOK(t, h.post("/v1/auth/mfa/authenticator/confirm", map[string]any{"code": authtest.TOTPCode(t, secret, h.Clock.Now())}, bearer(adm.Token)), http.StatusNoContent)

	h.Clock.Advance(time.Second)
	hProblem(t, h.get("/v1/auth/devices", bearer(otherTok)), http.StatusUnauthorized, "auth.unauthenticated") // other admin sessions ended
	hOK(t, h.get("/v1/auth/devices", bearer(adm.Token)), http.StatusOK)                                       // this one stays
}

func TestHandler_ClientsCannotUseAdminSecondFactorOperations(t *testing.T) {
	h := newHandlerEnv(t)
	u := h.UserWithStatus(t, auth.StatusActive)
	sess := hMobileSignIn(t, h, u, uuid.New())
	for path, body := range map[string]map[string]any{
		"/v1/auth/mfa/recovery-codes":        {"password": u.Password, "code": "123456"},
		"/v1/auth/mfa/authenticator":         {"password": u.Password, "code": "123456"},
		"/v1/auth/mfa/authenticator/confirm": {"code": "123456"},
	} {
		hProblem(t, h.post(path, body, bearer(sess.AccessToken)), http.StatusForbidden, "auth.forbidden")
	}
	if got := svCount(t, h.Env, `SELECT count(*) FROM admin_mfa`); got != 0 {
		t.Errorf("admin_mfa rows = %d, want 0 (clients never get an authenticator, FR-065)", got)
	}
}
