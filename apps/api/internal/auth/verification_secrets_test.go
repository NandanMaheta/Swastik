package auth_test

// S20 - verification of FR-091 / SC-006 / US-11 s2: no password, TOTP code, recovery code, TOTP
// secret, access, refresh or challenge credential, signing or encryption key, or unmatched
// identifier as typed appears in an audit entry, a log line, an error value or an error response.
// A journey drives the whole HTTP surface (successes and every kind of failure) against a real
// database, with a capturing logger at debug level, and scans everything afterwards, so a secret
// issued late in the journey is still searched for in what was written early.
//
// A second registry holds what must never be returned at all, not even by a success (passwords and
// key material); credentials are returned by design on the success that issues them.

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/humatest"
	"github.com/google/uuid"

	"github.com/NandanMaheta/swastik/apps/api/internal/auth"
	"github.com/NandanMaheta/swastik/apps/api/internal/auth/authtest"
	"github.com/NandanMaheta/swastik/apps/api/internal/platform/authz"
	"github.com/NandanMaheta/swastik/apps/api/internal/platform/httpx"
)

// vsBuffer is a goroutine-safe log sink.
type vsBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (v *vsBuffer) Write(p []byte) (int, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.b.Write(p)
}

func (v *vsBuffer) String() string {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.b.String()
}

// vsKeyMaterial registers the fixture keys (signing seeds, AES keys, blind-index key) in every
// encoding a careless log line could use.
func vsKeyMaterial(s *authtest.Secrets) {
	for label, b := range map[string]byte{"keyring key 1": 0x11, "keyring key 2": 0x22, "blind index key": 0x33, "signing seed k1": 0x44, "signing seed k2": 0x55} {
		raw := bytes.Repeat([]byte{b}, 32)
		s.Add(label+" (raw)", string(raw))
		s.Add(label+" (hex)", hex.EncodeToString(raw))
		s.Add(label+" (base64)", base64.StdEncoding.EncodeToString(raw))
		s.Add(label+" (base64 raw)", base64.RawStdEncoding.EncodeToString(raw))
		s.Add(label+" (base64 url)", base64.URLEncoding.EncodeToString(raw))
		s.Add(label+" (base64 url raw)", base64.RawURLEncoding.EncodeToString(raw))
	}
}

// vsCall is one recorded response.
type vsCall struct {
	name   string
	status int
	body   string
	header string
}

// vsWorld is the journey harness: handler env, log capture, recorded responses.
type vsWorld struct {
	*hEnv
	logs  *vsBuffer
	never *authtest.Secrets
	calls []vsCall
}

func newVSWorld(t *testing.T) *vsWorld {
	t.Helper()
	e := authtest.New(t)
	logs := &vsBuffer{}
	d := e.Deps()
	d.Log = slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	svc := e.ServiceWith(t, d)
	httpx.InstallErrors()
	_, api := humatest.New(t, huma.DefaultConfig("Swastik test", "1.0.0"))
	authz.Install(api, map[string]authz.Verifier{"bearer": svc.BearerVerifier(), "mfaChallenge": svc.ChallengeVerifier()})
	auth.Register(api, svc, auth.HandlerConfig{WebOrigins: []string{webOrigin}, TrustedProxyHops: 1, Limiter: hLimit(e, 10_000)})
	authz.AssertDeclared(api)
	w := &vsWorld{hEnv: &hEnv{Env: e, Svc: svc, API: api}, logs: logs, never: authtest.NewSecrets()}
	vsKeyMaterial(e.Secrets)
	vsKeyMaterial(w.never)
	return w
}

// password registers a password as a secret that no response may carry.
func (w *vsWorld) password(label, value string) {
	w.Secrets.Add(label, value)
	w.never.Add(label, value)
}

// rec records a response and harvests the credentials it issued into the registry.
func (w *vsWorld) rec(name string, r *httptest.ResponseRecorder) *httptest.ResponseRecorder {
	w.calls = append(w.calls, vsCall{name: name, status: r.Code, body: r.Body.String(), header: fmt.Sprint(r.Header())})
	if r.Code < 300 {
		var v any
		if json.Unmarshal(r.Body.Bytes(), &v) == nil {
			w.harvest(v)
		}
		for _, c := range r.Result().Cookies() {
			w.Secrets.Add("refresh cookie", c.Value)
		}
	}
	return r
}

func (w *vsWorld) harvest(v any) {
	switch x := v.(type) {
	case map[string]any:
		for k, val := range x {
			switch k {
			case "access_token", "refresh_token", "challenge_token":
				if s, ok := val.(string); ok {
					w.Secrets.Add(k, s)
				}
			case "secret":
				if s, ok := val.(string); ok {
					w.Secrets.AddTOTPSecret(s)
				}
			case "recovery_codes":
				if codes, ok := val.([]any); ok {
					for _, c := range codes {
						if s, ok := c.(string); ok {
							w.Secrets.Add("recovery code", s)
						}
					}
				}
			}
			w.harvest(val)
		}
	case []any:
		for _, val := range x {
			w.harvest(val)
		}
	}
}

func (w *vsWorld) POST(name, path string, body any, headers ...string) *httptest.ResponseRecorder {
	return w.rec(name, w.post(path, body, headers...))
}

func (w *vsWorld) GET(name, path string, headers ...string) *httptest.ResponseRecorder {
	return w.rec(name, w.get(path, headers...))
}

func (w *vsWorld) DELETE(name, path string, headers ...string) *httptest.ResponseRecorder {
	return w.rec(name, w.del(path, headers...))
}

func TestSecrets_SC006_NothingLeaksIntoLogsErrorsResponsesOrAudit(t *testing.T) {
	w := newVSWorld(t)
	ctx := t.Context()
	w.password("fixture password", authtest.Password)
	w.password("wrong password", wrongPassword)

	const ghostEmail, ghostMobile = "ghost.user.7731@nowhere.test", "9000012345"
	for _, v := range []string{ghostEmail, ghostMobile, "+91" + ghostMobile} {
		w.Secrets.Add("unmatched identifier as typed", v)
	}

	// ---- client journey ----
	u := w.UserWithStatus(t, auth.StatusActive)
	dev := uuid.New()
	rec := w.POST("mobile sign-in", "/v1/auth/sign-in", hSignInBody(u, auth.ClientTypeMobile, dev))
	hOK(t, rec, http.StatusOK)
	mobile := hSessionOf(t, hSub(t, hMap(t, rec), "session"))
	webCookie, web := hWebSignIn(t, w.hEnv, u, uuid.New())
	_ = webCookie

	for name, body := range map[string]map[string]any{
		"wrong password":         {"identifier": u.Email, "password": wrongPassword, "client_type": "mobile", "device": hDevice(uuid.New(), "android")},
		"unknown email":          {"identifier": ghostEmail, "password": wrongPassword, "client_type": "mobile", "device": hDevice(uuid.New(), "android")},
		"unknown mobile":         {"identifier": ghostMobile, "password": wrongPassword, "client_type": "mobile", "device": hDevice(uuid.New(), "android")},
		"not an identifier":      {"identifier": "12345", "password": wrongPassword, "client_type": "mobile", "device": hDevice(uuid.New(), "android")},
		"bad device":             {"identifier": u.Email, "password": wrongPassword, "client_type": "mobile", "device": map[string]any{"id": "x"}},
		"unknown client type":    {"identifier": u.Email, "password": wrongPassword, "client_type": "tv", "device": hDevice(uuid.New(), "android")},
		"not-active correct pwd": {"identifier": w.UserWithStatus(t, auth.StatusDisabled).Email, "password": authtest.Password, "client_type": "mobile", "device": hDevice(uuid.New(), "android")},
	} {
		w.POST("sign-in: "+name, "/v1/auth/sign-in", body)
	}

	locked := w.UserWithStatus(t, auth.StatusActive)
	for range 6 {
		w.POST("sign-in: lockout", "/v1/auth/sign-in", map[string]any{"identifier": locked.Email, "password": wrongPassword, "client_type": "mobile", "device": hDevice(uuid.New(), "android")})
	}
	w.POST("sign-in: correct password while locked", "/v1/auth/sign-in", hSignInBody(locked, auth.ClientTypeMobile, uuid.New()))

	w.Clock.Advance(time.Minute)
	rec = w.POST("refresh", "/v1/auth/refresh", map[string]any{"device_id": dev.String(), "refresh_token": mobile.RefreshToken})
	hOK(t, rec, http.StatusOK)
	w.POST("refresh: reuse", "/v1/auth/refresh", map[string]any{"device_id": dev.String(), "refresh_token": mobile.RefreshToken})
	w.POST("refresh: garbage", "/v1/auth/refresh", map[string]any{"device_id": dev.String(), "refresh_token": "drt_" + strings.Repeat("A", 43)})
	w.POST("refresh: web without cookie", "/v1/auth/refresh", nil, webHeaders()...)

	w.GET("devices", "/v1/auth/devices", bearer(web.AccessToken))
	w.GET("devices: garbage token", "/v1/auth/devices", bearer("not.a.jwt"))
	w.GET("devices: refresh token as bearer", "/v1/auth/devices", bearer(web.RefreshToken))
	w.DELETE("device revoke: unknown", "/v1/auth/devices/"+uuid.NewString(), bearer(web.AccessToken))

	const next = "monsoon-lantern-77-river"
	w.password("new password", next)
	w.password("short password", "short1")
	w.POST("password change: wrong current", "/v1/auth/password/change", map[string]any{"current_password": wrongPassword, "new_password": next}, bearer(web.AccessToken))
	w.POST("password change: too short", "/v1/auth/password/change", map[string]any{"current_password": u.Password, "new_password": "short1"}, bearer(web.AccessToken))
	w.POST("password change: common", "/v1/auth/password/change", map[string]any{"current_password": u.Password, "new_password": "1234567890"}, bearer(web.AccessToken))
	w.POST("password change", "/v1/auth/password/change", map[string]any{"current_password": u.Password, "new_password": next}, bearer(web.AccessToken))
	w.POST("sign-out everywhere", "/v1/auth/sign-out-everywhere", nil, bearer(web.AccessToken))

	// ---- admin journey: enrolment, second factor, management ----
	a := w.NewAdmin(t)
	rec = w.POST("admin sign-in (enrolment)", "/v1/auth/sign-in", hSignInBody(a, auth.ClientTypeMobile, uuid.New()))
	hOK(t, rec, http.StatusOK)
	enrolTok := hSub(t, hMap(t, rec), "challenge")["challenge_token"].(string)
	w.POST("enrolment: confirm before start", "/v1/auth/mfa/enrolment/confirm", map[string]any{"code": "123456"}, bearer(enrolTok))
	rec = w.POST("enrolment: start", "/v1/auth/mfa/enrolment", nil, bearer(enrolTok))
	hOK(t, rec, http.StatusOK)
	secret := hMap(t, rec)["secret"].(string)
	w.POST("enrolment: wrong code", "/v1/auth/mfa/enrolment/confirm", map[string]any{"code": mfWrong(t, w.Env, secret)}, bearer(enrolTok))
	rec = w.POST("enrolment: confirm", "/v1/auth/mfa/enrolment/confirm", map[string]any{"code": authtest.TOTPCode(t, secret, w.Clock.Now())}, bearer(enrolTok))
	hOK(t, rec, http.StatusOK)
	done := hMap(t, rec)
	_ = hSessionOf(t, hSub(t, done, "session"))
	codes, _ := done["recovery_codes"].([]any)
	if len(codes) != 10 {
		t.Fatalf("recovery codes = %d, want 10", len(codes))
	}
	recovery := codes[0].(string)

	w.Clock.Advance(time.Minute)
	chal := func() string {
		r := w.POST("admin sign-in (second factor)", "/v1/auth/sign-in", hSignInBody(a, auth.ClientTypeMobile, uuid.New()))
		hOK(t, r, http.StatusOK)
		return hSub(t, hMap(t, r), "challenge")["challenge_token"].(string)
	}
	w.POST("verify: wrong code", "/v1/auth/mfa/verify", map[string]any{"code": mfWrong(t, w.Env, secret)}, bearer(chal()))
	w.POST("verify: wrong recovery code", "/v1/auth/mfa/verify", map[string]any{"recovery_code": vaWrongRecovery()}, bearer(chal()))
	w.POST("verify: both factors", "/v1/auth/mfa/verify", map[string]any{"code": "123456", "recovery_code": recovery}, bearer(chal()))
	w.Clock.Advance(16 * time.Minute)
	hOK(t, w.POST("verify: recovery code", "/v1/auth/mfa/verify", map[string]any{"recovery_code": recovery}, bearer(chal())), http.StatusOK)
	w.POST("verify: recovery code reused", "/v1/auth/mfa/verify", map[string]any{"recovery_code": recovery}, bearer(chal()))
	w.POST("verify: consumed challenge", "/v1/auth/mfa/verify", map[string]any{"code": "123456"}, bearer(enrolTok))

	// Access tokens live 15 minutes, so each management call signs in again with a fresh code.
	login := func(sec string) string {
		w.Clock.Advance(time.Minute)
		r := w.POST("admin sign-in (second factor)", "/v1/auth/sign-in", hSignInBody(a, auth.ClientTypeMobile, uuid.New()))
		hOK(t, r, http.StatusOK)
		tok := hSub(t, hMap(t, r), "challenge")["challenge_token"].(string)
		r = w.POST("verify", "/v1/auth/mfa/verify", map[string]any{"code": authtest.TOTPCode(t, sec, w.Clock.Now())}, bearer(tok))
		hOK(t, r, http.StatusOK)
		return hSessionOf(t, hMap(t, r)).AccessToken
	}
	w.Clock.Advance(16 * time.Minute)
	tok := login(secret)
	w.Clock.Advance(time.Minute)
	w.POST("recovery codes: wrong password", "/v1/auth/mfa/recovery-codes", map[string]any{"password": wrongPassword, "code": authtest.TOTPCode(t, secret, w.Clock.Now())}, bearer(tok))
	tok = login(secret)
	w.Clock.Advance(time.Minute)
	hOK(t, w.POST("recovery codes", "/v1/auth/mfa/recovery-codes", map[string]any{"password": a.Password, "code": authtest.TOTPCode(t, secret, w.Clock.Now())}, bearer(tok)), http.StatusOK)
	w.Clock.Advance(time.Minute)
	rec = w.POST("authenticator replace: start", "/v1/auth/mfa/authenticator", map[string]any{"password": a.Password, "code": authtest.TOTPCode(t, secret, w.Clock.Now())}, bearer(tok))
	hOK(t, rec, http.StatusOK)
	newSecret := hMap(t, rec)["secret"].(string)
	w.Clock.Advance(time.Minute)
	w.POST("authenticator replace: wrong code", "/v1/auth/mfa/authenticator/confirm", map[string]any{"code": mfWrong(t, w.Env, newSecret)}, bearer(tok))
	hOK(t, w.POST("authenticator replace: confirm", "/v1/auth/mfa/authenticator/confirm", map[string]any{"code": authtest.TOTPCode(t, newSecret, w.Clock.Now())}, bearer(tok)), http.StatusNoContent)

	tok = login(newSecret)
	w.GET("admin: devices of a user", "/v1/admin/users/"+u.ID.String()+"/devices", bearer(tok))
	w.GET("admin: devices of nobody", "/v1/admin/users/"+uuid.NewString()+"/devices", bearer(tok))
	w.POST("admin: end all sessions", "/v1/admin/users/"+u.ID.String()+"/sessions/end-all", nil, bearer(tok))
	w.GET("admin operation as a client", "/v1/admin/users/"+u.ID.String()+"/devices", bearer(mobile.AccessToken))

	// ---- the scans ----
	if len(w.calls) < 40 {
		t.Fatalf("the journey recorded only %d calls", len(w.calls))
	}
	var failures int
	for _, c := range w.calls {
		w.never.Scan(t, "the response of "+c.name, c.body+c.header)
		if c.status >= 400 {
			failures++
			w.Secrets.Scan(t, "the error response of "+c.name, c.body+c.header)
		}
	}
	if failures < 25 {
		t.Fatalf("the journey produced only %d error responses; the scan would prove little", failures)
	}
	w.Secrets.Scan(t, "the application log", w.logs.String())
	w.Secrets.ScanAuditLog(ctx, t, w.Pool)

	// The unmatched identifier is never stored, even in a form the scan cannot know.
	rows, err := w.Pool.Query(ctx, `SELECT a::text FROM audit_log a WHERE entity_id IS NULL AND action = $1`, auth.ActionSignInFailed)
	if err != nil {
		t.Fatalf("query audit: %v", err)
	}
	defer rows.Close()
	unknown := 0
	for rows.Next() {
		var text string
		if err := rows.Scan(&text); err != nil {
			t.Fatal(err)
		}
		unknown++
		for _, frag := range []string{"ghost", "nowhere", ghostMobile, "@"} {
			if strings.Contains(text, frag) {
				t.Errorf("an unknown-identifier audit row contains %q: it must not store the identifier", frag)
			}
		}
	}
	if unknown < 2 {
		t.Errorf("unknown-identifier audit rows = %d, want the 2 attempts of the journey", unknown)
	}
}

// Errors returned by the Service (not only their HTTP rendering) carry no secret, with the text and
// the %+v form a logger would print.
func TestSecrets_SC006_ServiceErrorsCarryNoSecret(t *testing.T) {
	e := authtest.New(t)
	s := e.Service(t)
	ctx := t.Context()
	vsKeyMaterial(e.Secrets)
	u := e.NewUser(t, authtest.UserSpec{})
	adm := mfEnrolled(t, e)
	_, p := mfSession(t, e, adm.User)
	sess := svSignIn(t, s, u, uuid.New())
	e.Secrets.Add("access token", sess.AccessToken)
	e.Secrets.Add("refresh token", sess.RefreshToken)
	e.Secrets.Add("wrong password", wrongPassword)
	const weak = "password1234"
	e.Secrets.Add("rejected new password", weak)
	const typed = "typed.by.nobody@nowhere.test"
	e.Secrets.Add("unmatched identifier as typed", typed)
	chal := mfChallenge(t, e, s, adm.User)

	in := svInput(u, uuid.New())
	in.Password = wrongPassword
	unknown := in
	unknown.Identifier = typed
	cases := map[string]func() error{
		"sign-in wrong password": func() error { _, err := s.SignIn(ctx, in); return err },
		"sign-in unknown":        func() error { _, err := s.SignIn(ctx, unknown); return err },
		"refresh garbage":        func() error { _, err := s.Refresh(ctx, svRefreshIn(uuid.New(), sess.RefreshToken+"x")); return err },
		"refresh wrong device":   func() error { _, err := s.Refresh(ctx, svRefreshIn(uuid.New(), sess.RefreshToken)); return err },
		"verify wrong code":      func() error { _, err := s.VerifyMFA(ctx, mfVerifyIn(chal, mfWrong(t, e, adm.Secret))); return err },
		"verify bad challenge":   func() error { _, err := s.VerifyMFA(ctx, mfVerifyIn(chal+"x", "123456")); return err },
		"change: wrong current":  func() error { return s.ChangePassword(ctx, svPrincipal(e, u, sess.SessionID), wrongPassword, weak) },
		"change: weak new":       func() error { return s.ChangePassword(ctx, svPrincipal(e, u, sess.SessionID), u.Password, weak) },
		"reset: weak":            func() error { return s.ResetPassword(ctx, u.ID, weak, authtest.System()) },
		"create: weak": func() error {
			_, err := s.CreateClient(ctx, auth.NewClient{OrgID: e.Org, Name: "N", Email: "n@example.com", Mobile: "+919800000001", Password: weak}, authtest.System())
			return err
		},
		"create: duplicate": func() error {
			_, err := s.CreateClient(ctx, auth.NewClient{OrgID: e.Org, Name: "N", Email: u.Email, Mobile: "+919800000002", Password: authtest.Password}, authtest.System())
			return err
		},
		"regenerate: wrong secret": func() error { _, err := s.RegenerateRecoveryCodes(ctx, p, wrongPassword, "123456"); return err },
		"replace: wrong recovery": func() error {
			_, err := s.StartAuthenticatorReplace(ctx, p, auth.Reauth{Password: authtest.Password, RecoveryCode: vaWrongRecovery()})
			return err
		},
		"enrolment: bad challenge":  func() error { _, err := s.StartEnrolment(ctx, chal); return err },
		"bearer: garbage":           func() error { _, err := s.BearerVerifier().Verify(ctx, "not.a.jwt"); return err },
		"bearer: refresh as access": func() error { _, err := s.BearerVerifier().Verify(ctx, sess.RefreshToken); return err },
		"challenge: access token":   func() error { _, err := s.ChallengeVerifier().Verify(ctx, sess.AccessToken); return err },
	}
	failed := 0
	for name, run := range cases {
		err := run()
		if err == nil {
			continue // a success path (the challenge is still valid, say) carries no error to scan
		}
		failed++
		e.Secrets.Scan(t, "the error of "+name, err.Error())
		e.Secrets.Scan(t, "the %+v error of "+name, fmt.Sprintf("%+v", err))
	}
	if failed < 12 {
		t.Fatalf("only %d of %d cases returned an error; the scan would prove little", failed, len(cases))
	}
	e.Secrets.ScanAuditLog(ctx, t, e.Pool)
}
