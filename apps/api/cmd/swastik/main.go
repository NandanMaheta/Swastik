// Command swastik runs the Swastik API ("serve") or applies migrations ("migrate up|down|status").
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/NandanMaheta/swastik/apps/api/internal/auth"
	"github.com/NandanMaheta/swastik/apps/api/internal/health"
	"github.com/NandanMaheta/swastik/apps/api/internal/ipomarket"
	"github.com/NandanMaheta/swastik/apps/api/internal/ipos"
	"github.com/NandanMaheta/swastik/apps/api/internal/otp"
	"github.com/NandanMaheta/swastik/apps/api/internal/outbox"
	"github.com/NandanMaheta/swastik/apps/api/internal/platform/authz"
	"github.com/NandanMaheta/swastik/apps/api/internal/platform/clock"
	"github.com/NandanMaheta/swastik/apps/api/internal/platform/config"
	"github.com/NandanMaheta/swastik/apps/api/internal/platform/db"
	"github.com/NandanMaheta/swastik/apps/api/internal/platform/httpx"
	"github.com/NandanMaheta/swastik/apps/api/internal/platform/observe"
	"github.com/NandanMaheta/swastik/apps/api/internal/platform/tickauth"
	"github.com/NandanMaheta/swastik/apps/api/internal/scheduler"
	"github.com/NandanMaheta/swastik/apps/api/migrations"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if len(os.Args) > 1 && os.Args[1] == "admin" {
		// The bootstrap command has its own exit statuses and reads only DATABASE_URL.
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		code := runAdmin(ctx, os.Args[2:], adminEnv{In: os.Stdin, Out: os.Stdout, Err: os.Stderr, Now: clock.Real, Log: log})
		stop()
		os.Exit(code)
	}
	if err := run(log, os.Args[1:]); err != nil {
		log.Error("fatal", slog.Any("err", err))
		os.Exit(1)
	}
}

func run(log *slog.Logger, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: swastik serve | swastik migrate up|down|status | swastik openapi | swastik admin create")
	}
	if args[0] == "openapi" {
		// Prints the OpenAPI 3.1 spec without needing a database; used to generate the TS client.
		// The tick is registered (hidden) with a ticker that is never called, so the command
		// proves the public document stays free of it.
		spec, err := buildAPI(deps{Tick: (*scheduler.Service)(nil), TickAuth: tickauth.Disabled()}).OpenAPI().YAML()
		if err != nil {
			return err
		}
		_, err = os.Stdout.Write(spec)
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cfg, err := config.Load()
	if err != nil {
		return err
	}
	// Error reporting is off unless SENTRY_DSN is set (staging and production set it via OpenTofu).
	flush, err := observe.Init(os.Getenv("SENTRY_DSN"), cfg.SentryEnvironment, httpx.Version)
	if err != nil {
		log.Warn("error reporting disabled", slog.Any("err", err))
	}
	defer flush()
	log = slog.New(observe.NewHandler(log.Handler()))
	pool, err := db.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()

	switch args[0] {
	case "migrate":
		direction := "up"
		if len(args) > 1 {
			direction = args[1]
		}
		return db.Migrate(ctx, pool, migrations.FS, direction)
	case "serve":
		return serve(ctx, log, cfg, pool)
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

// deps are the collaborators the API's operations need. The zero value registers only the
// operations that need none.
type deps struct {
	Env      string // APP_ENV; the OpenAPI/docs routes are served only in local and ci
	Pool     health.Pinger
	Tick     scheduler.Ticker
	TickAuth tickauth.Authenticator
	// Auth is the auth module's service; nil registers the operations without one (the openapi
	// command and the static contract walk). WebOrigins and TrustedProxyHops feed the handlers.
	Auth *auth.Service
	// IPOs is the IPO catalogue service; nil registers its operations without one.
	IPOs *ipos.Service
	// OTP is the OTP delivery service (feature 004); nil registers its operations without one.
	OTP *otp.Service
	// Market is the GMP and subscription service; nil registers its operations without one.
	Market           *ipomarket.Service
	WebOrigins       []string
	TrustedProxyHops int
	ProxySecrets     []string
}

// buildAPI registers every module's operations. New modules are wired here, in this order:
// error problems, the authz middleware (before any registration: Huma captures middlewares at
// registration time), the modules, then the startup guard that fails fast on an operation with no
// declared Security.
func buildAPI(d deps) huma.API {
	httpx.InstallErrors()
	_, api := httpx.NewAPIFor(d.Env)
	authz.Install(api, verifiersOf(d.Auth))
	health.Register(api, health.NewService(d.Pool, httpx.Version, time.Now))
	if d.Tick != nil {
		scheduler.RegisterTick(api, d.Tick, d.TickAuth)
	}
	auth.Register(api, d.Auth, auth.HandlerConfig{WebOrigins: d.WebOrigins, TrustedProxyHops: d.TrustedProxyHops, ProxySecrets: d.ProxySecrets})
	ipos.Register(api, d.IPOs)
	ipomarket.Register(api, d.Market)
	authz.AssertDeclared(api)
	return api
}

// verifiersOf returns the verifier of each security scheme. Without a Service (the openapi command
// and the static walk) every credential is refused.
func verifiersOf(svc *auth.Service) map[string]authz.Verifier {
	if svc == nil {
		return map[string]authz.Verifier{"bearer": refuseAll{}, "mfaChallenge": refuseAll{}}
	}
	return map[string]authz.Verifier{"bearer": svc.BearerVerifier(), "mfaChallenge": svc.ChallengeVerifier()}
}

// refuseAll is the verifier of an API built without a Service: no token is ever valid.
type refuseAll struct{}

func (refuseAll) Verify(context.Context, string) (authz.Principal, error) {
	return authz.Principal{}, errors.New("no authentication service is configured")
}

// selectTickAuth picks the tick authenticator from the configuration. Production verifies a
// Google-signed ID token; without audience and service account the tick is closed (every call
// is rejected) and a warning says so.
func selectTickAuth(ctx context.Context, log *slog.Logger, cfg config.Config) tickauth.Authenticator {
	t := cfg.Tick
	if t.Auth == "dev" {
		if t.DevToken == "" {
			log.Warn("tick auth is dev but TICK_DEV_TOKEN is empty: the tick endpoint rejects every call")
		}
		return tickauth.NewDev(t.DevToken)
	}
	if t.Audience == "" || t.ServiceAccount == "" {
		log.Warn("TICK_AUDIENCE or TICK_SERVICE_ACCOUNT is not set: the tick endpoint rejects every call")
		return tickauth.Disabled()
	}
	return tickauth.NewOIDC(ctx, t.Audience, t.ServiceAccount, clock.Real,
		tickauth.WithHTTPClient(&http.Client{Timeout: 10 * time.Second}))
}

// newAuthService builds the auth Service from the validated configuration.
func newAuthService(cfg config.Config, txr db.TxRunner, log *slog.Logger) (*auth.Service, error) {
	keys, err := auth.NewSigningKeys(cfg.Auth.JWTActiveKID, cfg.Auth.JWTSeeds)
	if err != nil {
		return nil, fmt.Errorf("auth: signing keys: %w", err)
	}
	return auth.New(auth.Deps{
		Store: auth.NewPGStore(txr), Tx: txr, Now: clock.Real, Keys: keys,
		Hasher: auth.NewHasher(auth.HasherOptions{MaxConcurrency: cfg.Auth.Argon2MaxConcurrency}),
		Blind:  cfg.Auth.BlindIndex, Keyring: cfg.Auth.PII, Log: log,
	})
}

func serve(ctx context.Context, log *slog.Logger, cfg config.Config, pool *pgxpool.Pool) error {
	txr := db.NewTxRunner(pool)
	ob := outbox.New(txr, clock.Real, log, outbox.DefaultOptions())
	host, err := os.Hostname()
	if err != nil || host == "" {
		host = "unknown"
	}
	sched := scheduler.New(txr, ob, clock.Real, log, host, scheduler.DefaultOptions())
	sched.Register(scheduler.RetentionKind, sched.RetentionHandler(), scheduler.RetentionOptions())
	iposSvc := ipos.NewService(ipos.Deps{Tx: txr, Scheduler: sched, Now: clock.Real, Log: log})
	ipos.RegisterJobs(sched, iposSvc)
	marketSvc := ipomarket.NewService(ipomarket.Deps{Tx: txr, IPOs: iposSvc, Now: clock.Real, Log: log})

	authSvc, err := newAuthService(cfg, txr, log)
	if err != nil {
		return err
	}
	registerAuthJobs(sched, authSvc)

	api := buildAPI(deps{ //nolint:contextcheck // the tick middleware takes its context from each request
		Env: cfg.Env, Pool: pool, Tick: sched, TickAuth: selectTickAuth(ctx, log, cfg),
		Auth: authSvc, IPOs: iposSvc, Market: marketSvc, WebOrigins: cfg.Auth.WebOrigins, TrustedProxyHops: cfg.Auth.TrustedProxyHops,
		ProxySecrets: cfg.Auth.ProxySharedSecrets,
	})
	// CORS wraps the whole API: an exact-origin allowlist with credentials, never a wildcard.
	srv := httpx.NewServer(cfg.HTTPAddr, httpx.CORS(cfg.Auth.WebOrigins)(api.Adapter()), log)
	errCh := make(chan error, 1)
	go func() {
		log.Info("listening", slog.String("addr", cfg.HTTPAddr), slog.String("env", cfg.Env))
		errCh <- srv.ListenAndServe()
	}()

	select {
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		// The parent context is already cancelled, so derive a fresh, bounded one for draining.
		shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), cfg.ShutdownTimeout)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("shutdown: %w", err)
		}
		return nil
	}
}
