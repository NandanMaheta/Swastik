package main

// S17 - wiring of the auth module into the binary (plan C-7, C-8, P-10, P-20): the hidden tick
// still answers 401 without credentials once authz is installed, public probes stay public, every
// error carries a code, and auth.housekeeping is registered as a recurring job that runs at 03:30 IST.
//
// registerAuthJobs(sch *scheduler.Service, svc *auth.Service) is the adapter of plan P-20 (compile
// stub in jobs.go); S19 calls it from serve().

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/danielgtaylor/huma/v2/humatest"

	"github.com/NandanMaheta/swastik/apps/api/internal/auth"
	"github.com/NandanMaheta/swastik/apps/api/internal/auth/authtest"
	"github.com/NandanMaheta/swastik/apps/api/internal/outbox"
	"github.com/NandanMaheta/swastik/apps/api/internal/platform/crypto"
	"github.com/NandanMaheta/swastik/apps/api/internal/platform/tickauth"
	"github.com/NandanMaheta/swastik/apps/api/internal/scheduler"
)

type okPinger struct{}

func (okPinger) Ping(context.Context) error { return nil }

func TestWiring_TheTickStaysClosedToAnonymousCallersAndOpenToItsOwnCredential(t *testing.T) {
	const token = "tick-dev-token-1234"
	ticker := &walkTicker{}
	api := humatest.Wrap(t, buildAPI(deps{Tick: ticker, TickAuth: tickauth.NewDev(token)}))

	for name, headers := range map[string][]any{
		"no credential":     {},
		"a wrong token":     {"Authorization: Bearer nope"},
		"a basic header":    {"Authorization: Basic dXNlcjpwYXNz"},
		"a JWT-looking one": {"Authorization: Bearer aaa.bbb.ccc"},
	} {
		rec := api.Post("/internal/tick", headers...)
		if rec.Code != http.StatusUnauthorized && rec.Code != http.StatusForbidden {
			t.Errorf("%s: status = %d, want 401 or 403 (never 500 platform.security_undeclared); body %s", name, rec.Code, rec.Body.String())
		}
	}
	if got := ticker.calls.Load(); got != 0 {
		t.Fatalf("the tick ran %d times for callers without credentials", got)
	}
	rec := api.Post("/internal/tick", "Authorization: Bearer "+token)
	if rec.Code != http.StatusOK || ticker.calls.Load() != 1 {
		t.Fatalf("with its own credential: status = %d calls = %d, want 200 and 1; body %s", rec.Code, ticker.calls.Load(), rec.Body.String())
	}
}

func TestWiring_ProbesStayPublic(t *testing.T) {
	api := humatest.Wrap(t, buildAPI(deps{Pool: okPinger{}}))
	for _, path := range []string{"/healthz", "/readyz"} {
		if rec := api.Get(path); rec.Code != http.StatusOK {
			t.Errorf("GET %s without a credential: status = %d, want 200; body %s", path, rec.Code, rec.Body.String())
		}
	}
}

func TestWiring_ErrorsCarryAStableCode(t *testing.T) {
	api := humatest.Wrap(t, buildAPI(deps{}))
	rec := api.Post("/v1/auth/sign-in", map[string]any{"identifier": "x"})
	if rec.Code != http.StatusUnprocessableEntity || problemCode(t, rec) != "validation_failed" {
		t.Fatalf("invalid sign-in body: status = %d body %s, want 422 with code validation_failed (httpx.InstallErrors is wired)", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), `"value"`) {
		t.Errorf("a validation problem carries a value: %s", rec.Body.String())
	}
	rec = api.Get("/v1/auth/devices")
	if rec.Code != http.StatusUnauthorized || problemCode(t, rec) != "auth.unauthenticated" {
		t.Errorf("an anonymous bearer operation: status = %d body %s, want 401 auth.unauthenticated", rec.Code, rec.Body.String())
	}
}

func TestWiring_BuildAPIDoesNotNeedAnyDependency(t *testing.T) {
	// The openapi command and the static walk build the API with the zero value; every auth
	// operation must register without a Service.
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("buildAPI(deps{}) panicked: %v", r)
		}
	}()
	ids := idsOf(operationsOf(buildAPI(deps{})), func(o walkedOp) bool { return strings.HasPrefix(o.ID, "auth-") })
	if len(ids) != len(authOperations) {
		t.Errorf("auth operations registered = %d (%v), want %d", len(ids), ids, len(authOperations))
	}
}

func TestWiring_HousekeepingJobIsRecurringAndRunsDailyAt0330IST(t *testing.T) {
	e := authtest.New(t)
	svc := e.Service(t)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	sch := scheduler.New(e.Tx, outbox.New(e.Tx, e.Clock.Now, log, outbox.DefaultOptions()), e.Clock.Now, log, "wiring-test", scheduler.DefaultOptions())
	registerAuthJobs(sch, svc)

	now := e.Clock.Now() // 2026-07-01 10:00 UTC = 15:30 IST
	stale := now.Add(-2 * time.Hour)
	e.Exec(t, `INSERT INTO auth_throttles (org_id, scope, subject, failures, updated_at) VALUES ($1,'signin',$2,'{}',$3)`, e.Org, crypto.Digest("stale"), stale)
	count := func(sql string, args ...any) int {
		t.Helper()
		var n int
		if err := e.Pool.QueryRow(context.Background(), sql, args...).Scan(&n); err != nil {
			t.Fatalf("%q: %v", sql, err)
		}
		return n
	}
	tick := func() scheduler.TickSummary {
		t.Helper()
		sum, err := sch.Tick(context.Background())
		if err != nil {
			t.Fatalf("Tick: %v", err)
		}
		return sum
	}

	tick() // the first tick creates the recurring row for the organisation, due at the next 03:30 IST
	nextRun := time.Date(2026, time.July, 1, 22, 0, 0, 0, time.UTC)
	if n := count(`SELECT count(*) FROM scheduled_jobs WHERE org_id = $1 AND kind = $2 AND recurring AND status = 'pending' AND run_at = $3`,
		e.Org, auth.HousekeepingKind, nextRun); n != 1 {
		t.Fatalf("pending recurring %s rows due at %s = %d, want 1 (is the kind registered with Recurring: auth.HousekeepingNext?)", auth.HousekeepingKind, nextRun, n)
	}
	if n := count(`SELECT count(*) FROM auth_throttles`); n != 1 {
		t.Fatalf("throttle rows before the job is due = %d, want 1 (nothing runs early)", n)
	}

	e.Clock.Set(nextRun.Add(-time.Second))
	tick()
	if n := count(`SELECT count(*) FROM auth_throttles`); n != 1 {
		t.Errorf("throttle rows at 03:29:59 IST = %d, want 1", n)
	}

	e.Clock.Set(nextRun)
	if sum := tick(); sum.Jobs.Run < 1 {
		t.Fatalf("the tick at 03:30 IST ran %d jobs, want the housekeeping job", sum.Jobs.Run)
	}
	if n := count(`SELECT count(*) FROM auth_throttles`); n != 0 {
		t.Errorf("throttle rows after the job = %d, want 0 (the stale row is purged)", n)
	}
	if rows := e.AuditOf(t, auth.ActionHousekeepingPurged); len(rows) != 1 {
		t.Errorf("housekeeping audit rows = %d, want 1", len(rows))
	}
	tomorrow := nextRun.Add(24 * time.Hour)
	if n := count(`SELECT count(*) FROM scheduled_jobs WHERE org_id = $1 AND kind = $2 AND status = 'pending' AND run_at = $3`, e.Org, auth.HousekeepingKind, tomorrow); n != 1 {
		t.Errorf("pending %s rows due %s = %d, want 1 (the job reschedules itself)", auth.HousekeepingKind, tomorrow, n)
	}
}
