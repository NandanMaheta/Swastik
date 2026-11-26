package otp

import (
	"github.com/danielgtaylor/huma/v2"

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

// Register mounts the ten operations: /v1/verifications/*, /v1/password-reset/* (public) and
// /v1/me/verifications/* (client).
func Register(_ huma.API, _ *Service, _ HandlerConfig) { panic(errNotImplemented) }
