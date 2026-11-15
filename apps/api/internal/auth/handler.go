package auth

import (
	"github.com/danielgtaylor/huma/v2"

	"github.com/NandanMaheta/swastik/apps/api/internal/platform/ratelimit"
)

// Compile stub (S17, test-engineer): the HTTP surface of the auth module (16 operations,
// contracts/openapi-auth.yaml). S18 implements Register; the handler tests are written against
// this signature.

// HandlerConfig is what the HTTP layer needs besides the Service.
type HandlerConfig struct {
	// WebOrigins is the exact-match allowlist of browser origins (P-04); nothing else passes CSRF.
	WebOrigins []string
	// TrustedProxyHops is the httpx.ClientIP hop count (0: RemoteAddr only).
	TrustedProxyHops int
	// Limiter is the per-IP limiter of sign-in, refresh, mfa-verify and enrolment (P-17). Nil means
	// the default: 30 requests per minute per IP.
	Limiter *ratelimit.Limiter
}

// Register adds the auth operations to the API. Every operation declares its Security through
// platform/authz. With a nil svc (the `openapi` command and the static contract walk) the
// operations still register; they are never called.
func Register(_ huma.API, _ *Service, _ HandlerConfig) {}
