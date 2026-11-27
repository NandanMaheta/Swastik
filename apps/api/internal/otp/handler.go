package otp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/NandanMaheta/swastik/apps/api/internal/auth"
	"github.com/NandanMaheta/swastik/apps/api/internal/platform/clock"
	"github.com/NandanMaheta/swastik/apps/api/internal/platform/httpx"
	"github.com/NandanMaheta/swastik/apps/api/internal/platform/ratelimit"
)

// HandlerConfig configures the HTTP layer, as auth's does.
type HandlerConfig struct {
	// TrustedProxyHops is the httpx.ClientIP hop count (0: RemoteAddr only).
	TrustedProxyHops int
	// ProxySecrets are the accepted X-Swastik-Proxy-Key values; empty trusts no client-IP header.
	ProxySecrets []string
	// Limiter is the per-IP burst limiter; nil means 30 requests per minute per IP.
	Limiter *ratelimit.Limiter
}

// Default per-IP burst limit of the operations (plan: like auth P-17).
const (
	defaultRateLimit   = 30
	defaultRateWindow  = time.Minute
	defaultRateMaxKeys = 10_000
	tagVerification    = "Verification"
)

type handlers struct {
	svc     *Service
	cfg     HandlerConfig
	limiter *ratelimit.Limiter
}

type ipKey struct{}

// Register mounts the ten operations: /v1/verifications/*, /v1/password-reset/* (public) and
// /v1/me/verifications/* (client). With a nil svc (the `openapi` command and the static contract
// walk) the operations still register; they answer 503 otp.not_configured.
func Register(api huma.API, svc *Service, cfg HandlerConfig) {
	h := &handlers{svc: svc, cfg: cfg, limiter: cfg.Limiter}
	if h.limiter == nil {
		h.limiter = ratelimit.New(defaultRateLimit, defaultRateWindow, defaultRateMaxKeys, clock.Real)
	}
	h.registerPublic(api)
	h.registerMe(api)
}

// ingress resolves the client address and applies the per-IP burst limit (429 before any work).
func (h *handlers) ingress(ctx huma.Context, next func(huma.Context)) {
	ip := h.clientIP(ctx)
	if !h.limiter.Allow(ip) {
		writeProblem(ctx, http.StatusTooManyRequests, "rate_limited", "Too many requests from this address.")
		return
	}
	next(huma.WithValue(ctx, ipKey{}, ip))
}

// clientIP is httpx.ClientIP over the Huma context.
func (h *handlers) clientIP(ctx huma.Context) string {
	r := &http.Request{RemoteAddr: ctx.RemoteAddr(), Header: http.Header{}}
	ctx.EachHeader(func(name, value string) {
		switch {
		case strings.EqualFold(name, "X-Forwarded-For"):
			r.Header.Add("X-Forwarded-For", value)
		case strings.EqualFold(name, "X-Swastik-Proxy-Key"):
			r.Header.Add("X-Swastik-Proxy-Key", value)
		case strings.EqualFold(name, "X-Swastik-Client-IP"):
			r.Header.Add("X-Swastik-Client-IP", value)
		}
	})
	return httpx.ClientIP(r, h.cfg.TrustedProxyHops, h.cfg.ProxySecrets...)
}

func ipOf(ctx context.Context) string {
	ip, _ := ctx.Value(ipKey{}).(string)
	return ip
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

// ready is a 503 when the API was built without a Service (never in production).
func (h *handlers) ready() error {
	if h.svc == nil {
		return httpx.Problem(http.StatusServiceUnavailable, "otp.not_configured", "This step is not available right now. Please try again later.")
	}
	return nil
}

// fail maps a service error to its RFC 9457 problem: otp's own codes, then the auth ones the
// reset reuses (password policy, identifier format, busy hasher). Anything else is a bare 500.
func (h *handlers) fail(ctx context.Context, err error) error {
	var re *RetryError
	if errors.As(err, &re) {
		return ProblemFor(err)
	}
	for _, m := range problemTable {
		if errors.Is(err, m.err) {
			return ProblemFor(err)
		}
	}
	var policy *auth.PolicyError
	switch {
	case errors.As(err, &policy), errors.Is(err, auth.ErrInvalidIdentifier):
		return auth.ProblemFor(err)
	case errors.Is(err, auth.ErrBusy):
		return httpx.Problem(http.StatusServiceUnavailable, auth.CodeBusy, "The server is busy; try again shortly.")
	}
	h.svc.log.ErrorContext(ctx, "otp: unexpected error", "err", err)
	return httpx.Problem(http.StatusInternalServerError, "internal", "An unexpected error occurred.")
}

// problems documents the error responses of an operation: the given statuses with the problem
// schema, and a Retry-After header on the 429 when retry is set (contracts/otp.openapi.yaml).
func problems(api huma.API, retry bool, statuses ...int) map[string]*huma.Response {
	exampleErr := huma.NewError(0, "")
	contentType := "application/json"
	if f, ok := exampleErr.(huma.ContentTypeFilter); ok {
		contentType = f.ContentType(contentType)
	}
	errType := reflect.TypeOf(exampleErr)
	for errType.Kind() == reflect.Pointer {
		errType = errType.Elem()
	}
	schema := api.OpenAPI().Components.Schemas.Schema(errType, true, "Error")
	out := map[string]*huma.Response{}
	for _, st := range statuses {
		r := &huma.Response{
			Description: http.StatusText(st),
			Content:     map[string]*huma.MediaType{contentType: {Schema: schema}},
		}
		if st == http.StatusTooManyRequests && retry {
			one := 1.0
			r.Description = "Refused by a cooldown or limit; Retry-After and retry_after_seconds say when to try again"
			r.Headers = map[string]*huma.Param{"Retry-After": {Schema: &huma.Schema{Type: "integer", Minimum: &one}}}
		}
		out[strconv.Itoa(st)] = r
	}
	return out
}
