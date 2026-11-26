package ipomarket

// S18 - BR-IPO-04 / constitution VII: market summaries stay under p95 200 ms with 200 IPOs and 500
// entries each. Opt-in wall-clock check (noisy on shared CI): runs only with SWASTIK_PERF=1, never
// under -short.

import (
	"os"
	"sort"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestSummaries_BR_IPO_04_P95UnderBudget(t *testing.T) {
	if testing.Short() || os.Getenv("SWASTIK_PERF") == "" {
		t.Skip("opt-in wall-clock check: set SWASTIK_PERF=1 (not under -short)")
	}
	e := newSvcEnv(t)
	ids := make([]uuid.UUID, 200)
	for i := range ids {
		ids[i] = e.publishedIPO()
	}
	ctx := e.ctx()
	if _, err := e.pool.Exec(ctx, `INSERT INTO ipo_gmp_entries (org_id, ipo_id, gmp_paise, source, actor_kind, actor_id, recorded_at)
		SELECT $1, i, 1000 + g, 'manual', 'admin', $3, $4::timestamptz - make_interval(secs => g)
		FROM unnest($2::uuid[]) i, generate_series(1, 500) g`, e.org, ids, uuid.New(), e.now); err != nil {
		t.Fatal(err)
	}
	if _, err := e.pool.Exec(ctx, `INSERT INTO ipo_subscription_snapshots (org_id, ipo_id, as_of, total_x100, source, actor_kind, actor_id, recorded_at)
		SELECT $1, i, $4::timestamptz - make_interval(secs => g), g, 'manual', 'admin', $3, $4::timestamptz - make_interval(secs => g)
		FROM unnest($2::uuid[]) i, generate_series(1, 500) g`, e.org, ids, uuid.New(), e.now); err != nil {
		t.Fatal(err)
	}
	if _, err := e.pool.Exec(ctx, `ANALYZE`); err != nil {
		t.Fatal(err)
	}
	call := func() {
		got, err := e.svc.Summaries(ctx, e.org, ids, true)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != len(ids) {
			t.Fatalf("got %d summaries, want %d", len(got), len(ids))
		}
	}
	call()
	const n = 40
	d := make([]time.Duration, n)
	for i := range d {
		start := time.Now()
		call()
		d[i] = time.Since(start)
	}
	sort.Slice(d, func(i, j int) bool { return d[i] < d[j] })
	if p95 := d[n*95/100]; p95 > 200*time.Millisecond {
		t.Errorf("Summaries p95 = %v, want under 200ms (200 IPOs x 500 entries)", p95)
	}
}
