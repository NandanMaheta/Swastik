// Package httpx builds the HTTP server and the Huma API shared by every module.
package httpx

import (
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humago"
)

// Version is overwritten at build time with -ldflags.
var Version = "dev"

// NewAPI returns the router and the Huma API (OpenAPI 3.1, RFC 9457 problem details by default).
func NewAPI() (*http.ServeMux, huma.API) { return NewAPIFor("") }

// NewAPIFor is NewAPI for an APP_ENV. In staging and production the self-description routes
// (/openapi.*, /docs, /schemas/*) are not served and responses carry no $schema link, so the
// operation list is not advertised; the in-memory document (OpenAPI()) is unaffected, so
// `swastik openapi` still emits the full spec.
func NewAPIFor(env string) (*http.ServeMux, huma.API) {
	mux := http.NewServeMux()
	cfg := huma.DefaultConfig("Swastik API", Version)
	cfg.Info.Description = "Internal IPO operations platform."
	if env == "staging" || env == "production" {
		cfg.OpenAPIPath, cfg.DocsPath, cfg.SchemasPath = "", "", ""
		cfg.CreateHooks = nil
	}
	api := humago.New(mux, cfg)
	return mux, api
}

// NewServer wraps the handler with request logging and sane timeouts.
func NewServer(addr string, h http.Handler, log *slog.Logger) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           logRequests(h, log),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

// Unwrap lets http.NewResponseController reach the real writer (deadlines, flushing) through
// the logging wrapper.
func (r *statusRecorder) Unwrap() http.ResponseWriter { return r.ResponseWriter }

// ExtendWriteDeadline moves the response write deadline to d from now, for the few routes that
// legitimately outlive the global 30 s WriteTimeout (the scheduler tick). It returns an error
// wrapping http.ErrNotSupported when the underlying writer has no deadline support. It must be
// called with a context created by the humago adapter, the only adapter in use.
func ExtendWriteDeadline(ctx huma.Context, d time.Duration) error {
	_, w := humago.Unwrap(ctx)
	if err := http.NewResponseController(w).SetWriteDeadline(time.Now().Add(d)); err != nil {
		return fmt.Errorf("httpx: extend write deadline: %w", err)
	}
	return nil
}

func logRequests(next http.Handler, log *slog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		log.LogAttrs(r.Context(), slog.LevelInfo, "http",
			slog.String("method", r.Method),
			slog.String("path", r.URL.Path),
			slog.Int("status", rec.status),
			slog.Duration("took", time.Since(start)),
		)
	})
}
