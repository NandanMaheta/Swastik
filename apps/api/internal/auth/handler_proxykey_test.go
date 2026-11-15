package auth_test

// Review-fix HTTP tests (feature 003): the handlers resolve the client address through
// httpx.ClientIP with the configured proxy secrets (HandlerConfig.ProxySecrets, the
// PROXY_SHARED_SECRETS setting) next to TrustedProxyHops. The resolved address is what the audit
// log records and what the per-address rate limiter counts. Also: re-authentication failures over
// HTTP record that address (Principal.IP set by the handler).

import (
	"net/http"
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

const (
	pxSecretA   = "proxy-secret-A-0123456789abcdefABCDEF"
	pxSecretB   = "proxy-secret-B-0123456789abcdefABCDEF"
	pxRealIP    = "198.51.100.200"
	pxForgedIP  = "6.6.6.6"
	pxLastXFFIP = clientIP // 203.0.113.7: what the platform load balancer appended
)

func newProxyEnv(t *testing.T, limit int, secrets ...string) *hEnv {
	t.Helper()
	e := authtest.New(t)
	svc := e.Service(t)
	httpx.InstallErrors()
	_, api := humatest.New(t, huma.DefaultConfig("Swastik test", "1.0.0"))
	authz.Install(api, map[string]authz.Verifier{"bearer": svc.BearerVerifier(), "mfaChallenge": svc.ChallengeVerifier()})
	auth.Register(api, svc, auth.HandlerConfig{
		WebOrigins: []string{webOrigin}, TrustedProxyHops: 1, ProxySecrets: secrets, Limiter: hLimit(e, limit),
	})
	authz.AssertDeclared(api)
	return &hEnv{Env: e, Svc: svc, API: api}
}

func rfLastSignInIP(t *testing.T, h *hEnv) string {
	t.Helper()
	rows := h.AuditOf(t, auth.ActionSignInSucceeded)
	if len(rows) == 0 {
		t.Fatal("no sign-in audit row")
	}
	ip, _ := mfAfter(t, rows[len(rows)-1])["ip"].(string)
	return ip
}

func TestProxyKeyHTTP_MatchingKeyMakesTheClientIPHeaderTheAuditedAddress(t *testing.T) {
	for name, key := range map[string]string{"first secret": pxSecretA, "second secret (rotation)": pxSecretB} {
		t.Run(name, func(t *testing.T) {
			h := newProxyEnv(t, 10_000, pxSecretA, pxSecretB)
			u := h.UserWithStatus(t, auth.StatusActive)
			rec := h.API.Post("/v1/auth/sign-in",
				"X-Forwarded-For: "+pxForgedIP+", "+pxLastXFFIP,
				"X-Swastik-Proxy-Key: "+key, "X-Swastik-Client-IP: "+pxRealIP,
				hSignInBody(u, auth.ClientTypeMobile, uuid.New()))
			hOK(t, rec, http.StatusOK)
			if got := rfLastSignInIP(t, h); got != pxRealIP {
				t.Errorf("audited ip = %q, want the proxy-supplied %q", got, pxRealIP)
			}
		})
	}
}

func TestProxyKeyHTTP_ForgedHeadersFromADirectCallerAreIgnored(t *testing.T) {
	cases := map[string][]any{
		"wrong key":      {"X-Swastik-Proxy-Key: nope-nope-nope-nope-nope-nope-nope", "X-Swastik-Client-IP: " + pxForgedIP},
		"no key":         {"X-Swastik-Client-IP: " + pxForgedIP},
		"empty key":      {"X-Swastik-Proxy-Key: ", "X-Swastik-Client-IP: " + pxForgedIP},
		"malformed ip":   {"X-Swastik-Proxy-Key: " + pxSecretA, "X-Swastik-Client-IP: not-an-ip"},
		"ip with a port": {"X-Swastik-Proxy-Key: " + pxSecretA, "X-Swastik-Client-IP: 6.6.6.6:80"},
	}
	for name, headers := range cases {
		t.Run(name, func(t *testing.T) {
			h := newProxyEnv(t, 10_000, pxSecretA, pxSecretB)
			u := h.UserWithStatus(t, auth.StatusActive)
			args := append([]any{"X-Forwarded-For: " + pxForgedIP + ", " + pxLastXFFIP}, headers...)
			rec := h.API.Post("/v1/auth/sign-in", append(args, hSignInBody(u, auth.ClientTypeMobile, uuid.New()))...)
			hOK(t, rec, http.StatusOK)
			if got := rfLastSignInIP(t, h); got != pxLastXFFIP {
				t.Errorf("audited ip = %q, want the last X-Forwarded-For entry %q", got, pxLastXFFIP)
			}
		})
	}
}

func TestProxyKeyHTTP_NoSecretsConfiguredNeverTrustsTheHeaders(t *testing.T) {
	h := newProxyEnv(t, 10_000)
	u := h.UserWithStatus(t, auth.StatusActive)
	rec := h.API.Post("/v1/auth/sign-in",
		"X-Forwarded-For: "+pxForgedIP+", "+pxLastXFFIP,
		"X-Swastik-Proxy-Key: "+pxSecretA, "X-Swastik-Client-IP: "+pxForgedIP,
		hSignInBody(u, auth.ClientTypeMobile, uuid.New()))
	hOK(t, rec, http.StatusOK)
	if got := rfLastSignInIP(t, h); got != pxLastXFFIP {
		t.Errorf("audited ip = %q, want %q", got, pxLastXFFIP)
	}
}

// The limiter counts the resolved address: a forged header cannot buy a fresh window, and distinct
// trusted addresses behind the same proxy do not share one.
func TestProxyKeyHTTP_RateLimiterCountsTheResolvedAddress(t *testing.T) {
	h := newProxyEnv(t, 2, pxSecretA)
	u := h.UserWithStatus(t, auth.StatusActive)
	wrong := hSignInBody(u, auth.ClientTypeMobile, uuid.New())
	wrong["password"] = wrongPassword
	post := func(body any, headers ...any) int {
		args := append([]any{"X-Forwarded-For: " + pxLastXFFIP}, headers...)
		return h.API.Post("/v1/auth/sign-in", append(args, body)...).Code
	}

	// Direct caller rotating forged client addresses with a wrong key stays in one window.
	for i, ip := range []string{"6.6.6.1", "6.6.6.2"} {
		if code := post(wrong, "X-Swastik-Proxy-Key: guess", "X-Swastik-Client-IP: "+ip); code != http.StatusUnauthorized {
			t.Fatalf("forged request %d = %d, want 401", i+1, code)
		}
	}
	if code := post(wrong, "X-Swastik-Proxy-Key: guess", "X-Swastik-Client-IP: 6.6.6.3"); code != http.StatusTooManyRequests {
		t.Errorf("third forged request = %d, want 429 (the forged address must not give a fresh window)", code)
	}

	// Real clients arriving through the proxy each have their own window, whatever the XFF says.
	for _, ip := range []string{"198.51.100.1", "198.51.100.2"} {
		for i := range 2 {
			if code := post(wrong, "X-Swastik-Proxy-Key: "+pxSecretA, "X-Swastik-Client-IP: "+ip); code != http.StatusUnauthorized {
				t.Fatalf("client %s request %d = %d, want 401", ip, i+1, code)
			}
		}
		if code := post(wrong, "X-Swastik-Proxy-Key: "+pxSecretA, "X-Swastik-Client-IP: "+ip); code != http.StatusTooManyRequests {
			t.Errorf("client %s third request = %d, want 429", ip, code)
		}
	}
	h.Clock.Advance(time.Minute)
}

// ---- re-authentication failures over HTTP record the resolved address ----

func TestProxyKeyHTTP_ReauthFailureAuditRecordsTheResolvedAddress(t *testing.T) {
	h := newProxyEnv(t, 10_000, pxSecretA)
	u := h.UserWithStatus(t, auth.StatusActive)
	sess := hMobileSignIn(t, h, u, uuid.New())

	rec := h.API.Post("/v1/auth/password/change",
		"X-Forwarded-For: "+pxForgedIP+", "+pxLastXFFIP,
		"X-Swastik-Proxy-Key: "+pxSecretA, "X-Swastik-Client-IP: "+pxRealIP,
		bearer(sess.AccessToken),
		map[string]any{"current_password": wrongPassword, "new_password": "monsoon-lantern-77-river"})
	hProblem(t, rec, http.StatusForbidden, "auth.reauth_failed")

	rows := h.AuditOf(t, auth.ActionSignInFailed)
	if len(rows) != 1 {
		t.Fatalf("sign_in.failed rows = %d, want 1", len(rows))
	}
	after := mfAfter(t, rows[0])
	if after["ip"] != pxRealIP {
		t.Errorf("ip = %v, want the proxy-resolved %s", after["ip"], pxRealIP)
	}
	if k, _ := after["identifier_kind"].(string); k != "email" && k != "mobile" {
		t.Errorf("identifier_kind = %v, want email or mobile", after["identifier_kind"])
	}
}

func TestProxyKeyHTTP_ReauthFailureAuditWithoutAKeyRecordsTheXFFAddress(t *testing.T) {
	h := newHandlerEnv(t) // TrustedProxyHops 1, no secrets
	u := h.UserWithStatus(t, auth.StatusActive)
	sess := hMobileSignIn(t, h, u, uuid.New())
	rec := h.post("/v1/auth/password/change",
		map[string]any{"current_password": wrongPassword, "new_password": "monsoon-lantern-77-river"}, bearer(sess.AccessToken))
	hProblem(t, rec, http.StatusForbidden, "auth.reauth_failed")
	rows := h.AuditOf(t, auth.ActionSignInFailed)
	if len(rows) != 1 || mfAfter(t, rows[0])["ip"] != clientIP {
		t.Fatalf("sign_in.failed rows = %+v, want one with ip %s", rows, clientIP)
	}
}
