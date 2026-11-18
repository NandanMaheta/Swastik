package ipos

// S16 - SC-008: list and detail stay inside the platform budget (constitution VII, p95 under
// 200 ms) with 500 IPOs stored, and the list queries are served by the two keyset indexes.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/NandanMaheta/swastik/apps/api/internal/platform/db/dbgen"
)

func seedIPOs(t *testing.T, e *svcEnv, n int) {
	t.Helper()
	e.h.Exec(`INSERT INTO ipos (org_id, name, exchanges, open_date, close_date, lot_size, price_band_floor_paise,
			price_band_cap_paise, apply_flag, published, first_published_at, status_changed_at)
		SELECT $1, 'Perf ' || g, ARRAY['NSE'], DATE '2026-01-01' + g, DATE '2026-01-03' + g, 10, 100000, 105000,
			'APPLY', g % 2 = 0, CASE WHEN g % 2 = 0 THEN now() END, now()
		FROM generate_series(1, $2) g`, e.org, n)
	e.h.Exec(`ANALYZE ipos`)
}

// explainDB is a dbgen.DBTX that turns every Query into EXPLAIN of the same SQL and arguments and
// records the plan, so the real generated ListIPOsAdmin / ListPublishedIPOs statements are checked.
type explainDB struct {
	t    *testing.T
	tx   pgx.Tx
	plan string
}

var errExplained = errors.New("explained")

func (d *explainDB) Exec(ctx context.Context, sql string, a ...any) (pgconn.CommandTag, error) {
	return d.tx.Exec(ctx, sql, a...)
}

func (d *explainDB) QueryRow(ctx context.Context, sql string, a ...any) pgx.Row {
	return d.tx.QueryRow(ctx, sql, a...)
}

func (d *explainDB) Query(ctx context.Context, sql string, a ...any) (pgx.Rows, error) {
	rows, err := d.tx.Query(ctx, "EXPLAIN "+sql, a...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var sb strings.Builder
	for rows.Next() {
		var l string
		_ = rows.Scan(&l)
		sb.WriteString(l + "\n")
	}
	d.plan = sb.String()
	return nil, errExplained
}

// SC-008: the keyset queries, with a cursor, are served by the two list indexes without a sort.
func TestList_SC008_KeysetQueriesUseTheListIndexes(t *testing.T) {
	e := newSvcEnv(t)
	seedIPOs(t, e, 500)
	var curID uuid.UUID
	var curOpen pgtype.Date
	if err := e.h.Pool.QueryRow(e.ctx(), `SELECT id, open_date FROM ipos WHERE published ORDER BY open_date DESC, id DESC OFFSET 100 LIMIT 1`).Scan(&curID, &curOpen); err != nil {
		t.Fatal(err)
	}
	run := func(call func(q *dbgen.Queries) error) string {
		t.Helper()
		tx, err := e.h.Pool.Begin(e.ctx())
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(e.ctx()) }()
		// With 500 rows the planner may legitimately prefer a sort; force it to show whether an
		// index can serve the order.
		for _, s := range []string{"SET LOCAL enable_seqscan = off", "SET LOCAL enable_bitmapscan = off"} {
			if _, err := tx.Exec(e.ctx(), s); err != nil {
				t.Fatal(err)
			}
		}
		d := &explainDB{t: t, tx: tx}
		if err := call(dbgen.New(d)); !errors.Is(err, errExplained) {
			t.Fatalf("query did not run through EXPLAIN: %v", err)
		}
		return d.plan
	}
	admin := run(func(q *dbgen.Queries) error {
		_, err := q.ListIPOsAdmin(e.ctx(), dbgen.ListIPOsAdminParams{OrgID: e.org, CursorSet: true, CursorID: curID, CursorOpen: curOpen, RowLimit: 51})
		return err
	})
	if !strings.Contains(admin, "ipos_admin_list_idx") || strings.Contains(admin, "Sort") {
		t.Errorf("ListIPOsAdmin plan does not use ipos_admin_list_idx without a sort:\n%s", admin)
	}
	client := run(func(q *dbgen.Queries) error {
		_, err := q.ListPublishedIPOs(e.ctx(), dbgen.ListPublishedIPOsParams{OrgID: e.org, CursorSet: true, CursorID: curID, CursorOpen: curOpen, RowLimit: 51})
		return err
	})
	if !strings.Contains(client, "ipos_published_list_idx") || strings.Contains(client, "Sort") {
		t.Errorf("ListPublishedIPOs plan does not use ipos_published_list_idx without a sort:\n%s", client)
	}
}

// An opt-in wall-clock check: it is noisy on shared CI, so it runs only with SWASTIK_PERF=1 and
// never under -short.
func TestList_SC008_RequestsUnderBudgetWith500IPOs(t *testing.T) {
	if testing.Short() || os.Getenv("SWASTIK_PERF") == "" {
		t.Skip("opt-in wall-clock check: set SWASTIK_PERF=1 (not under -short)")
	}
	e := newHTTPEnv(t)
	seedIPOs(t, e.svcEnv, 500)
	var firstID uuid.UUID
	if err := e.h.Pool.QueryRow(e.ctx(), `SELECT id FROM ipos WHERE published ORDER BY id LIMIT 1`).Scan(&firstID); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func() resp{
		"admin list":  func() resp { return e.admin("GET", "/v1/admin/ipos?limit=50", nil) },
		"admin get":   func() resp { return e.admin("GET", "/v1/admin/ipos/"+firstID.String(), nil) },
		"client list": func() resp { return e.client("GET", "/v1/ipos?limit=50") },
		"client get":  func() resp { return e.client("GET", "/v1/ipos/"+firstID.String()) },
	}
	for name, call := range cases {
		t.Run(name, func(t *testing.T) {
			r := call()
			wantHTTP(t, r, 200)
			const n = 40
			d := make([]time.Duration, n)
			for i := range d {
				start := time.Now()
				wantHTTP(t, call(), 200)
				d[i] = time.Since(start)
			}
			sort.Slice(d, func(i, j int) bool { return d[i] < d[j] })
			if p95 := d[n*95/100]; p95 > 200*time.Millisecond {
				t.Errorf("%s p95 = %v, want under 200ms with 500 IPOs", name, p95)
			}
		})
	}
	r := e.client("GET", "/v1/ipos?limit=200")
	if items, _ := r.M["items"].([]any); len(items) != 200 {
		t.Errorf("limit=200 returned %d of 250 published, want 200 (%s)", len(items), fmt.Sprint(r.M["next_cursor"] != nil))
	}
}
