package otp_test

// S16 - the HTTP surface of feature 004 (contracts/otp.openapi.yaml, contracts/error-codes.md,
// plan "API operations"): ten POST operations with the handle in the JSON body, problems with
// stable codes, Retry-After on cooldowns, a per-IP burst limiter, the /v1/me/* owner checks, the
// uniform reset replies (D-07, FR-009) and the response floor (SC-004). humatest on the real
// Service, real PostgreSQL, fake clock; otp.Register wired as cmd/swastik wires it.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/humatest"

	"github.com/NandanMaheta/swastik/apps/api/internal/auth"
	"github.com/NandanMaheta/swastik/apps/api/internal/auth/authtest"
	"github.com/NandanMaheta/swastik/apps/api/internal/otp"
	"github.com/NandanMaheta/swastik/apps/api/internal/otp/otptest"
	"github.com/NandanMaheta/swastik/apps/api/internal/platform/authz"
	"github.com/NandanMaheta/swastik/apps/api/internal/platform/httpx"
	"github.com/NandanMaheta/swastik/apps/api/internal/platform/ratelimit"
)

const hxIP = "203.0.113.7"

type hxEnv struct {
	*otptest.Env
	API humatest.TestAPI
}

func newHxEnv(t *testing.T, limit int, opts ...otptest.Option) *hxEnv {
	t.Helper()
	e := otptest.NewEnv(t, opts...)
	httpx.InstallErrors()
	_, api := humatest.New(t, huma.DefaultConfig("Swastik test", "1.0.0"))
	authz.Install(api, map[string]authz.Verifier{"bearer": e.Auth.BearerVerifier(), "mfaChallenge": e.Auth.ChallengeVerifier()})
	svMustPanicFree(t, "otp.Register", func() {
		otp.Register(api, e.Svc, otp.HandlerConfig{TrustedProxyHops: 1, Limiter: ratelimit.New(limit, time.Minute, 1000, e.Clock.Now)})
	})
	authz.AssertDeclared(api)
	return &hxEnv{Env: e, API: api}
}

func (h *hxEnv) post(path string, body any, headers ...string) *httptest.ResponseRecorder {
	args := []any{"X-Forwarded-For: " + hxIP}
	for _, hd := range headers {
		args = append(args, hd)
	}
	if body != nil {
		args = append(args, body)
	}
	return h.API.Do(http.MethodPost, path, args...)
}

func (h *hxEnv) bearerFor(t *testing.T, u authtest.User) string {
	t.Helper()
	return "Authorization: Bearer " + h.AccessToken(t, u, h.NewSession(t, u.ID, authtest.SessionSpec{}))
}

type hxProblem struct {
	Status            int    `json:"status"`
	Code              string `json:"code"`
	Detail            string `json:"detail"`
	RetryAfterSeconds int    `json:"retry_after_seconds"`
}

// hxWantProblem requires a problem response with the status and stable code and returns it.
func hxWantProblem(t *testing.T, what string, rec *httptest.ResponseRecorder, status int, code string) hxProblem {
	t.Helper()
	var p hxProblem
	if err := json.Unmarshal(rec.Body.Bytes(), &p); err != nil {
		t.Fatalf("%s: status %d, not a problem body: %q", what, rec.Code, rec.Body.String())
	}
	if rec.Code != status || p.Code != code {
		t.Errorf("%s: status %d code %q, want %d %q; body %s", what, rec.Code, p.Code, status, code, rec.Body.String())
	}
	return p
}

func hxMap(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatalf("not a JSON object (status %d): %q", rec.Code, rec.Body.String())
	}
	return m
}

func hxSub(t *testing.T, m map[string]any, key string) map[string]any {
	t.Helper()
	sub, ok := m[key].(map[string]any)
	if !ok {
		t.Fatalf("response has no object %q: %v", key, m)
	}
	return sub
}

func hxKeys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		if k != "$schema" {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

func hxTime(t *testing.T, m map[string]any, key string) time.Time {
	t.Helper()
	s, _ := m[key].(string)
	got, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		t.Fatalf("%s = %v, not an RFC 3339 time", key, m[key])
	}
	return got
}

const (
	pStatus   = "/v1/verifications/status"
	pResend   = "/v1/verifications/resend"
	pVerifyE  = "/v1/verifications/verify-email"
	pVerifyM  = "/v1/verifications/verify-mobile"
	pResetGo  = "/v1/password-reset/start"
	pResetEnd = "/v1/password-reset/complete"
)

func TestHandler_BR_CLI_04_SignupJourneyAndWireShapes(t *testing.T) {
	h := newHxEnv(t, 10_000)
	u := h.Pending(t)
	now := h.Clock.Now()
	st := h.StartSignup(t, u)

	rec := h.post(pStatus, map[string]any{"handle": st.Handle})
	if rec.Code != http.StatusOK {
		t.Fatalf("status: %d %s", rec.Code, rec.Body.String())
	}
	m := hxMap(t, rec)
	if m["purpose"] != "signup" || m["state"] != "open" || !hxTime(t, m, "expires_at").Equal(now.Add(otp.VerificationTTL)) {
		t.Errorf("status body = %v", m)
	}
	email, mobile := hxSub(t, m, "email"), hxSub(t, m, "mobile")
	if email["state"] != "pending" || email["masked"] != otp.MaskEmail(u.Email) || mobile["state"] != "pending" || mobile["masked"] != otp.MaskMobile(u.Mobile) {
		t.Errorf("contacts = %v %v", email, mobile)
	}
	if !hxTime(t, email, "next_resend_at").Equal(now.Add(otp.ResendCooldown)) || !hxTime(t, email, "code_expires_at").Equal(now.Add(otp.CodeTTL)) {
		t.Errorf("email times = %v", email)
	}
	if _, has := mobile["next_resend_at"]; has {
		t.Error("the mobile contact has a next_resend_at: only email contacts are resent")
	}
	if strings.Contains(rec.Body.String(), st.Handle) || strings.Contains(rec.Body.String(), u.Email) {
		t.Error("the status body echoes the handle or the readable email")
	}

	h.Clock.Advance(otp.ResendCooldown)
	rec = h.post(pResend, map[string]any{"handle": st.Handle})
	if rec.Code != http.StatusAccepted {
		t.Fatalf("resend: %d %s", rec.Code, rec.Body.String())
	}
	rm := hxMap(t, rec)
	if got := hxKeys(rm); strings.Join(got, ",") != "code_expires_at,next_resend_at" ||
		!hxTime(t, rm, "next_resend_at").Equal(h.Clock.Now().Add(otp.ResendCooldown)) {
		t.Errorf("resend body = %v", rm)
	}

	rec = h.post(pVerifyE, map[string]any{"handle": st.Handle, "code": h.LastCode(t)})
	if rec.Code != http.StatusOK {
		t.Fatalf("verify-email: %d %s", rec.Code, rec.Body.String())
	}
	vm := hxMap(t, rec)
	if _, has := vm["reset_token"]; has {
		t.Error("a sign-up verification returned a reset_token")
	}
	if ver := hxSub(t, vm, "verification"); hxSub(t, ver, "email")["state"] != "verified" || ver["state"] != "open" {
		t.Errorf("verification after the email step = %v", ver)
	}

	rec = h.post(pVerifyM, map[string]any{"handle": st.Handle, "firebase_id_token": h.Token(t, u.Mobile)})
	if rec.Code != http.StatusOK {
		t.Fatalf("verify-mobile: %d %s", rec.Code, rec.Body.String())
	}
	fm := hxMap(t, rec)
	if fm["state"] != "completed" || hxSub(t, fm, "mobile")["state"] != "verified" {
		t.Errorf("verify-mobile body = %v", fm)
	}
	if strings.Contains(rec.Body.String(), u.Mobile) {
		t.Error("verify-mobile echoes the number")
	}
}

func TestHandler_BR_CLI_04_ProblemsCarryStableCodesAndRetryAfter(t *testing.T) {
	h := newHxEnv(t, 10_000)
	u := h.Pending(t)
	st := h.StartSignup(t, u)
	code := h.PendingCode(t, st.ID)
	unknown := "ovh_" + strings.Repeat("Z", 43)

	hxWantProblem(t, "unknown handle", h.post(pStatus, map[string]any{"handle": unknown}), 404, "otp.verification_invalid")
	hxWantProblem(t, "mobile before email", h.post(pVerifyM, map[string]any{"handle": st.Handle, "firebase_id_token": h.Token(t, u.Mobile)}), 409, "otp.email_first")

	h.Clock.Advance(30 * time.Second)
	rec := h.post(pResend, map[string]any{"handle": st.Handle})
	p := hxWantProblem(t, "resend in the cooldown", rec, 429, "otp.cooldown")
	if rec.Header().Get("Retry-After") != "30" || p.RetryAfterSeconds != 30 {
		t.Errorf("Retry-After %q retry_after_seconds %d, want 30 and 30", rec.Header().Get("Retry-After"), p.RetryAfterSeconds)
	}

	wrong := svWrongOf(code)
	for i := 1; i < otp.MaxWrongAttempts; i++ {
		hxWantProblem(t, "wrong code", h.post(pVerifyE, map[string]any{"handle": st.Handle, "code": wrong}), 422, "otp.code_wrong")
	}
	hxWantProblem(t, "5th wrong code", h.post(pVerifyE, map[string]any{"handle": st.Handle, "code": wrong}), 422, "otp.code_used_up")

	h.Clock.Advance(otp.CodeTTL)
	h.post(pResend, map[string]any{"handle": st.Handle}) // a new code
	h.Clock.Advance(otp.CodeTTL)
	hxWantProblem(t, "expired code", h.post(pVerifyE, map[string]any{"handle": st.Handle, "code": h.LastCode(t)}), 422, "otp.code_expired")

	// The 6th send within the hour is rate limited; Retry-After is whole seconds, rounded up.
	h2 := newHxEnv(t, 10_000)
	u2 := h2.Pending(t)
	st2 := h2.StartSignup(t, u2)
	t0 := h2.Clock.Now()
	for i := 1; i <= 4; i++ {
		h2.Clock.Set(t0.Add(time.Duration(i) * otp.ResendCooldown))
		if rec := h2.post(pResend, map[string]any{"handle": st2.Handle}); rec.Code != http.StatusAccepted {
			t.Fatalf("resend %d: %d %s", i, rec.Code, rec.Body.String())
		}
	}
	h2.Clock.Set(t0.Add(5 * otp.ResendCooldown))
	rec = h2.post(pResend, map[string]any{"handle": st2.Handle})
	p = hxWantProblem(t, "6th send in an hour", rec, 429, "otp.rate_limited")
	wantSecs := int((time.Hour - 5*otp.ResendCooldown) / time.Second)
	if rec.Header().Get("Retry-After") != strconv.Itoa(wantSecs) || p.RetryAfterSeconds != wantSecs {
		t.Errorf("Retry-After %q / %d, want %d seconds", rec.Header().Get("Retry-After"), p.RetryAfterSeconds, wantSecs)
	}

	// After 24 hours the flow reads as expired and every action on it is 410.
	h2.Clock.Set(t0.Add(otp.VerificationTTL))
	if rec := h2.post(pStatus, map[string]any{"handle": st2.Handle}); rec.Code != http.StatusOK || hxMap(t, rec)["state"] != "expired" {
		t.Errorf("status after 24 h: %d %s, want 200 with state expired", rec.Code, rec.Body.String())
	}
	hxWantProblem(t, "resend after 24 h", h2.post(pResend, map[string]any{"handle": st2.Handle}), 410, "otp.verification_expired")
	hxWantProblem(t, "verify after 24 h", h2.post(pVerifyE, map[string]any{"handle": st2.Handle, "code": "123456"}), 410, "otp.verification_expired")
}

func TestHandler_BR_CLI_04_ProofRefusalsMapToTheirCodes(t *testing.T) {
	h := newHxEnv(t, 10_000)
	u := h.Pending(t)
	st := h.StartSignup(t, u)
	h.post(pVerifyE, map[string]any{"handle": st.Handle, "code": h.PendingCode(t, st.ID)})
	now := h.Clock.Now()
	stale := h.Token(t, u.Mobile, func(c *otptest.Claims) { c.AuthTime, c.IssuedAt = now.Add(-10*time.Minute), now.Add(-10*time.Minute) })
	for name, tc := range map[string]struct {
		token  string
		status int
		code   string
	}{
		"another number": {h.Token(t, "+919812345679"), 422, "otp.number_mismatch"},
		"stale":          {stale, 422, "otp.proof_stale"},
		"garbage":        {"not.a.token", 422, "otp.proof_invalid"},
	} {
		rec := h.post(pVerifyM, map[string]any{"handle": st.Handle, "firebase_id_token": tc.token})
		p := hxWantProblem(t, name, rec, tc.status, tc.code)
		for _, secret := range []string{u.Mobile, strings.TrimPrefix(u.Mobile, "+91"), "9812345679", tc.token} {
			if strings.Contains(rec.Body.String(), secret) || strings.Contains(p.Detail, secret) {
				t.Errorf("%s: the problem body echoes a number or the token", name)
			}
		}
	}
	h.Clock.Advance(otp.ResendCooldown + time.Second)
	hxWantProblem(t, "resend with the email done", h.post(pResend, map[string]any{"handle": st.Handle}), 409, "otp.nothing_to_send")
	if rec := h.post(pVerifyM, map[string]any{"handle": st.Handle, "firebase_id_token": h.Token(t, u.Mobile)}); rec.Code != http.StatusOK {
		t.Fatalf("a good proof: %d %s", rec.Code, rec.Body.String())
	}

	// A proof used once is refused on its second use.
	owner := h.Active(t)
	bearer := h.bearerFor(t, owner)
	const newMobile = "+919876543210"
	tok := h.Token(t, newMobile)
	first := h.StartChange(t, owner, otp.PurposeChangeMobile, newMobile)
	if rec := h.post("/v1/me/verifications/verify-mobile", map[string]any{"handle": first.Handle, "firebase_id_token": tok}, bearer); rec.Code != http.StatusOK {
		t.Fatalf("first use: %d %s", rec.Code, rec.Body.String())
	}
	second := h.StartChange(t, owner, otp.PurposeChangeMobile, newMobile)
	hxWantProblem(t, "the same proof again", h.post("/v1/me/verifications/verify-mobile", map[string]any{"handle": second.Handle, "firebase_id_token": tok}, bearer), 422, "otp.proof_replayed")
}

func TestHandler_BR_CLI_04_NotConfiguredIs503(t *testing.T) {
	h := newHxEnv(t, 10_000, otptest.WithoutFirebase())
	u := h.Pending(t)
	st := h.StartSignup(t, u)
	h.post(pVerifyE, map[string]any{"handle": st.Handle, "code": h.PendingCode(t, st.ID)})
	hxWantProblem(t, "no Firebase", h.post(pVerifyM, map[string]any{"handle": st.Handle, "firebase_id_token": "a.b.c"}), 503, "otp.not_configured")
}

func TestHandler_BR_CLI_04_MalformedRequestsAreValidationFailuresAndCostNoAttempt(t *testing.T) {
	h := newHxEnv(t, 10_000)
	u := h.Pending(t)
	st := h.StartSignup(t, u)
	good := "ovh_" + strings.Repeat("a", 43)
	bad := map[string]struct {
		path string
		body any
	}{
		"short handle":        {pStatus, map[string]any{"handle": "ovh_short"}},
		"wrong prefix":        {pStatus, map[string]any{"handle": "xyz_" + strings.Repeat("a", 43)}},
		"missing handle":      {pStatus, map[string]any{}},
		"extra field":         {pStatus, map[string]any{"handle": good, "also": 1}},
		"5 digit code":        {pVerifyE, map[string]any{"handle": st.Handle, "code": "12345"}},
		"letters in the code": {pVerifyE, map[string]any{"handle": st.Handle, "code": "12a456"}},
		"missing code":        {pVerifyE, map[string]any{"handle": st.Handle}},
		"empty id token":      {pVerifyM, map[string]any{"handle": st.Handle, "firebase_id_token": ""}},
		"huge id token":       {pVerifyM, map[string]any{"handle": st.Handle, "firebase_id_token": strings.Repeat("x", 4097)}},
		"empty identifier":    {pResetGo, map[string]any{"identifier": ""}},
		"huge identifier":     {pResetGo, map[string]any{"identifier": strings.Repeat("a", 255)}},
		"bad reset token":     {pResetEnd, map[string]any{"handle": good, "reset_token": "abc", "new_password": "x"}},
		"huge password":       {pResetEnd, map[string]any{"handle": good, "reset_token": "prt_" + strings.Repeat("a", 43), "new_password": strings.Repeat("p", 1025)}},
	}
	for name, c := range bad {
		rec := h.post(c.path, c.body)
		hxWantProblem(t, name, rec, 422, "validation_failed")
		if strings.Contains(rec.Body.String(), `"value"`) {
			t.Errorf("%s: the validation problem carries a value: %s", name, rec.Body.String())
		}
	}
	if got := svLive(t, h.Env, st.ID).Wrong; got != 0 {
		t.Errorf("wrong_attempts = %d after malformed requests, want 0", got)
	}
}

func TestHandler_BR_CLI_04_APerAddressBurstLimiterGuardsThePublicOperations(t *testing.T) {
	h := newHxEnv(t, 3)
	body := map[string]any{"handle": "ovh_" + strings.Repeat("Q", 43)}
	for i := 0; i < 3; i++ {
		hxWantProblem(t, "within the burst", h.post(pStatus, body), 404, "otp.verification_invalid")
	}
	hxWantProblem(t, "4th request in the minute", h.post(pStatus, body), 429, "rate_limited")
	if rec := h.API.Do(http.MethodPost, pStatus, "X-Forwarded-For: 198.51.100.77", body); rec.Code != http.StatusNotFound {
		t.Errorf("another address: %d, want it unaffected", rec.Code)
	}
	h.Clock.Advance(time.Minute)
	hxWantProblem(t, "after the window", h.post(pStatus, body), 404, "otp.verification_invalid")
}

func TestHandler_BR_CLI_05_MyOperationsNeedTheOwnersClientSession(t *testing.T) {
	h := newHxEnv(t, 10_000)
	owner, other, taken := h.Active(t), h.Active(t), h.Active(t)
	admin := h.NewAdmin(t)
	st := h.StartChange(t, owner, otp.PurposeChangeEmail, "mine@example.com")
	hb := map[string]any{"handle": st.Handle}
	paths := []string{"/v1/me/verifications/status", "/v1/me/verifications/resend", "/v1/me/verifications/verify-email", "/v1/me/verifications/verify-mobile"}
	body := func(p string) any {
		switch {
		case strings.HasSuffix(p, "verify-email"):
			return map[string]any{"handle": st.Handle, "code": "123456"}
		case strings.HasSuffix(p, "verify-mobile"):
			return map[string]any{"handle": st.Handle, "firebase_id_token": "a.b.c"}
		}
		return hb
	}
	for _, p := range paths {
		hxWantProblem(t, p+" without a session", h.post(p, body(p)), 401, "auth.unauthenticated")
		hxWantProblem(t, p+" as an admin", h.post(p, body(p), h.bearerFor(t, admin)), 403, "auth.forbidden")
	}

	// Another client's session sees exactly what an unknown handle shows.
	otherBearer := h.bearerFor(t, other)
	unk := h.post("/v1/me/verifications/status", map[string]any{"handle": "ovh_" + strings.Repeat("Z", 43)}, otherBearer)
	got := h.post("/v1/me/verifications/status", hb, otherBearer)
	hxWantProblem(t, "unknown handle", unk, 404, "otp.verification_invalid")
	hxWantProblem(t, "another user's handle", got, 404, "otp.verification_invalid")
	if unk.Body.String() != got.Body.String() {
		t.Errorf("another user's handle answers differently from an unknown one:\n %s\n %s", got.Body.String(), unk.Body.String())
	}

	ownerBearer := h.bearerFor(t, owner)
	rec := h.post("/v1/me/verifications/status", hb, ownerBearer)
	if rec.Code != http.StatusOK || hxMap(t, rec)["purpose"] != "change_email" {
		t.Fatalf("owner status: %d %s", rec.Code, rec.Body.String())
	}
	h.Clock.Advance(otp.ResendCooldown)
	if rec := h.post("/v1/me/verifications/resend", hb, ownerBearer); rec.Code != http.StatusAccepted {
		t.Fatalf("owner resend: %d %s", rec.Code, rec.Body.String())
	}
	rec = h.post("/v1/me/verifications/verify-email", map[string]any{"handle": st.Handle, "code": h.LastCode(t)}, ownerBearer)
	if rec.Code != http.StatusOK {
		t.Fatalf("owner verify-email: %d %s", rec.Code, rec.Body.String())
	}
	if ver := hxSub(t, hxMap(t, rec), "verification"); hxSub(t, ver, "email")["state"] != "proved" {
		t.Errorf("verification = %v, want the email proved", ver)
	}

	// 409 contact_unavailable on the wire; a sign-up handle is not reachable here.
	clash := h.StartChange(t, owner, otp.PurposeChangeEmail, taken.Email)
	hxWantProblem(t, "contact unavailable", h.post("/v1/me/verifications/verify-email",
		map[string]any{"handle": clash.Handle, "code": h.PendingCode(t, clash.ID)}, ownerBearer), 409, "otp.contact_unavailable")
	p := h.Pending(t)
	signup := h.StartSignup(t, p)
	hxWantProblem(t, "a sign-up handle on /v1/me", h.post("/v1/me/verifications/status", map[string]any{"handle": signup.Handle}, h.bearerFor(t, owner)), 404, "otp.verification_invalid")

	mob := h.StartChange(t, owner, otp.PurposeChangeMobile, "+919876543210")
	rec = h.post("/v1/me/verifications/verify-mobile", map[string]any{"handle": mob.Handle, "firebase_id_token": h.Token(t, "+919876543210")}, ownerBearer)
	if rec.Code != http.StatusOK || hxSub(t, hxMap(t, rec), "mobile")["state"] != "proved" {
		t.Errorf("owner verify-mobile: %d %s", rec.Code, rec.Body.String())
	}
}

var hxHandleRE = regexp.MustCompile(`^ovh_[A-Za-z0-9_-]{43}$`)

func TestHandler_BR_CLI_04_ResetRepliesAreIdenticalForKnownUnknownAndIneligibleAccounts(t *testing.T) {
	h := newHxEnv(t, 10_000)
	known := h.Active(t)
	admin := h.NewAdmin(t)
	pending := h.Pending(t)
	idents := map[string]string{
		"known email": known.Email, "unknown email": "nobody.at.all@example.com", "unknown mobile": "+919123456789",
		"pending client": pending.Email, "admin": admin.Email,
	}
	var baseline string
	var baseHeaders []string
	for _, name := range []string{"known email", "unknown email", "unknown mobile", "pending client", "admin"} {
		rec := h.post(pResetGo, map[string]any{"identifier": idents[name]})
		if rec.Code != http.StatusAccepted {
			t.Fatalf("%s: status %d %s, want 202 for everyone", name, rec.Code, rec.Body.String())
		}
		m := hxMap(t, rec)
		if !hxHandleRE.MatchString(m["handle"].(string)) || strings.Join(hxKeys(m), ",") != "expires_at,handle,next_resend_at" {
			t.Errorf("%s: body = %v", name, m)
		}
		shape := hxTime(t, m, "expires_at").String() + "|" + hxTime(t, m, "next_resend_at").String()
		var hdrs []string
		for k := range rec.Header() {
			hdrs = append(hdrs, k)
		}
		sort.Strings(hdrs)
		if baseline == "" {
			baseline, baseHeaders = shape, hdrs
		} else if shape != baseline || strings.Join(hdrs, ",") != strings.Join(baseHeaders, ",") {
			t.Errorf("%s: times %s headers %v differ from the known account's %s %v (D-07)", name, shape, hdrs, baseline, baseHeaders)
		}
		for _, typed := range []string{idents[name], strings.Split(idents[name], "@")[0], strings.TrimPrefix(idents[name], "+91")} {
			if len(typed) > 5 && strings.Contains(rec.Body.String(), typed) {
				t.Errorf("%s: the reply echoes the typed identifier", name)
			}
		}
	}
	if n := len(h.Mailer.Mails()); n != 1 {
		t.Errorf("mails = %d, want exactly 1 (the known active client)", n)
	}
	hxWantProblem(t, "a malformed identifier", h.post(pResetGo, map[string]any{"identifier": "!!"}), 422, "auth.identifier_invalid")
}

func TestHandler_BR_CLI_04_ResetJourneyOverHTTP(t *testing.T) {
	h := newHxEnv(t, 10_000)
	u := h.Active(t)
	rec := h.post(pResetGo, map[string]any{"identifier": u.Mobile})
	if rec.Code != http.StatusAccepted {
		t.Fatalf("start: %d %s", rec.Code, rec.Body.String())
	}
	handle := hxMap(t, rec)["handle"].(string)
	rec = h.post(pVerifyE, map[string]any{"handle": handle, "code": h.LastCode(t)})
	if rec.Code != http.StatusOK {
		t.Fatalf("verify-email: %d %s", rec.Code, rec.Body.String())
	}
	vm := hxMap(t, rec)
	token, _ := vm["reset_token"].(string)
	if !svResetRE.MatchString(token) || !hxTime(t, vm, "reset_token_expires_at").Equal(h.Clock.Now().Add(otp.ResetTokenTTL)) {
		t.Fatalf("verify-email body = %v, want a prt_ token valid 10 minutes", vm)
	}

	complete := func(token, pw string) *httptest.ResponseRecorder {
		return h.post(pResetEnd, map[string]any{"handle": handle, "reset_token": token, "new_password": pw})
	}
	hxWantProblem(t, "weak password", complete(token, "short"), 422, auth.PolicyTooShort)
	hxWantProblem(t, "forged token", complete("prt_"+strings.Repeat("A", 43), svNewPassword), 422, "otp.reset_token_invalid")
	rec = complete(token, svNewPassword)
	if rec.Code != http.StatusNoContent || rec.Body.Len() != 0 {
		t.Fatalf("complete: %d %q, want 204 with no body", rec.Code, rec.Body.String())
	}
	hxWantProblem(t, "reusing the token", complete(token, svNewPassword), 422, "otp.reset_token_invalid")
	if err := svSignIn(h.Env, u, svNewPassword); err != nil {
		t.Errorf("sign-in with the new password: %v", err)
	}
}

func TestHandler_BR_CLI_04_NoOperationPutsAHandleOrSecretInTheURL(t *testing.T) {
	h := newHxEnv(t, 10_000)
	n := 0
	for path, item := range h.API.OpenAPI().Paths {
		if !strings.HasPrefix(path, "/v1/verifications/") && !strings.HasPrefix(path, "/v1/password-reset/") && !strings.HasPrefix(path, "/v1/me/verifications/") {
			continue
		}
		n++
		if strings.ContainsAny(path, "{}") {
			t.Errorf("%s has a path parameter: handles and codes travel in the body only", path)
		}
		if item.Post == nil || len(item.Post.Parameters) != 0 || item.Get != nil {
			t.Errorf("%s must be a POST with no query, path or header parameters", path)
		}
	}
	if n != 10 {
		t.Errorf("otp operations registered = %d, want 10", n)
	}
}

// SC-004: the median time of a reset start for a known account and for an unknown one differ by
// less than 10 %, with the real 1.5 s floor and the machine clock.
func TestHandler_BR_CLI_04_ResetStartTimingMatchesForKnownAndUnknown(t *testing.T) {
	if testing.Short() {
		t.Skip("takes about 10 s of real time")
	}
	h := newHxEnv(t, 10_000, otptest.WithRealClock())
	const rounds = 3
	timeIt := func(identifier string) time.Duration {
		start := time.Now()
		rec := h.post(pResetGo, map[string]any{"identifier": identifier})
		d := time.Since(start)
		if rec.Code != http.StatusAccepted {
			t.Fatalf("StartReset(%q): %d %s", identifier, rec.Code, rec.Body.String())
		}
		return d
	}
	var known, unknown []time.Duration
	for i := 0; i < rounds; i++ {
		known = append(known, timeIt(h.Active(t).Email))
		unknown = append(unknown, timeIt("nobody."+strconv.Itoa(i)+"@example.com"))
	}
	median := func(ds []time.Duration) time.Duration {
		sort.Slice(ds, func(i, j int) bool { return ds[i] < ds[j] })
		return ds[len(ds)/2]
	}
	mk, mu := median(known), median(unknown)
	if mk < 1500*time.Millisecond || mu < 1500*time.Millisecond {
		t.Errorf("medians known %v unknown %v: both must wait the 1.5 s floor (I-3)", mk, mu)
	}
	diff := mk - mu
	if diff < 0 {
		diff = -diff
	}
	if float64(diff) > 0.10*float64(max(mk, mu)) {
		t.Errorf("median known %v vs unknown %v differ by more than 10 %% (SC-004)", mk, mu)
	}
}
