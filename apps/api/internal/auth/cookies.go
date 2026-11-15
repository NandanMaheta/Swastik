package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/NandanMaheta/swastik/apps/api/internal/platform/httpx"
)

// The refresh cookie and the CSRF defences of the browser flow (plan P-04).
const (
	// RefreshCookieName is the cookie that carries a web session's refresh token. The __Secure-
	// prefix makes browsers require Secure.
	RefreshCookieName = "__Secure-swastik_rt"
	// refreshCookiePath keeps the cookie off every request except the refresh operation.
	refreshCookiePath = "/v1/auth/refresh"
)

// refreshCookie is the Set-Cookie value of a web session's refresh token, living until the
// session's absolute expiry. No Domain attribute: the cookie is host-only on the API host.
func refreshCookie(value string, expiresAt, now time.Time) string {
	maxAge := int(expiresAt.Sub(now) / time.Second)
	if maxAge < 1 {
		maxAge = 1
	}
	return newRefreshCookie(value, maxAge).String()
}

// clearedRefreshCookie expires the cookie in the browser.
func clearedRefreshCookie() string { return newRefreshCookie("", -1).String() }

func newRefreshCookie(value string, maxAge int) *http.Cookie {
	return &http.Cookie{
		Name: RefreshCookieName, Value: value, Path: refreshCookiePath, MaxAge: maxAge,
		HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode,
	}
}

// checkBrowserRequest enforces the CSRF defences: the Origin must equal one allowlisted origin
// exactly (a missing or "null" Origin never does) and X-Swastik-CSRF must be "1" (a cross-site
// form cannot set it and a cross-site script triggers a CORS preflight). The JSON-only
// content type is enforced by the framework before a handler runs.
func (h *handlers) checkBrowserRequest(origin, csrf string) error {
	if _, ok := h.origins[origin]; !ok || origin == "" || csrf != "1" {
		return httpx.Problem(http.StatusForbidden, CodeCSRFRejected, "The request did not come from the admin panel.")
	}
	return nil
}

type (
	ipKey    struct{}
	tokenKey struct{}
)

// ingress is the operation middleware of the credential operations. In this order: resolve the
// client address, apply the per-IP limit when asked (429 before any work), and keep the bearer
// token (the challenge) for handlers of mfaChallenge operations.
func (h *handlers) ingress(limited bool) func(huma.Context, func(huma.Context)) {
	return func(ctx huma.Context, next func(huma.Context)) {
		ip := h.clientIP(ctx)
		if limited && !h.limiter.Allow(ip) {
			writeProblem(ctx, http.StatusTooManyRequests, "rate_limited", "Too many requests from this address.")
			return
		}
		c := huma.WithValue(ctx, ipKey{}, ip)
		if scheme, token, ok := strings.Cut(ctx.Header("Authorization"), " "); ok && strings.EqualFold(scheme, "Bearer") {
			c = huma.WithValue(c, tokenKey{}, strings.TrimSpace(token))
		}
		next(c)
	}
}

// clientIP is httpx.ClientIP over the Huma context.
func (h *handlers) clientIP(ctx huma.Context) string {
	r := &http.Request{RemoteAddr: ctx.RemoteAddr(), Header: http.Header{}}
	ctx.EachHeader(func(name, value string) {
		if strings.EqualFold(name, "X-Forwarded-For") {
			r.Header.Add("X-Forwarded-For", value)
		}
	})
	return httpx.ClientIP(r, h.cfg.TrustedProxyHops)
}

func ipOf(ctx context.Context) string {
	ip, _ := ctx.Value(ipKey{}).(string)
	return ip
}

func tokenOf(ctx context.Context) string {
	tok, _ := ctx.Value(tokenKey{}).(string)
	return tok
}

// writeProblem answers from a middleware with an RFC 9457 problem carrying its stable code.
func writeProblem(ctx huma.Context, status int, code, detail string) {
	body, err := json.Marshal(httpx.Problem(status, code, detail))
	if err != nil {
		status, body = http.StatusInternalServerError, []byte(`{"status":500,"code":"internal"}`)
	}
	ctx.SetHeader("Content-Type", "application/problem+json")
	ctx.SetStatus(status)
	_, _ = ctx.BodyWriter().Write(body)
}
