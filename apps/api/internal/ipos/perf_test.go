package ipos

// S16 - SC-008: list and detail stay inside the platform budget (constitution VII, p95 under
// 200 ms) with 500 IPOs stored, and the list queries are served by the two keyset indexes.

import (
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
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

func TestList_SC008_KeysetQueriesUseTheListIndexes(t *testing.T) {
	e := newSvcEnv(t)
	seedIPOs(t, e, 500)
	plan := func(q string, args ...any) string {
		t.Helper()
		tx, err := e.h.Pool.Begin(e.ctx())
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(e.ctx()) }()
		// Force the planner to show whether an index can serve the order; with 500 rows it may
		// otherwise legitimately prefer a sort.
		for _, s := range []string{"SET LOCAL enable_seqscan = off", "SET LOCAL enable_bitmapscan = off"} {
			if _, err := tx.Exec(e.ctx(), s); err != nil {
				t.Fatal(err)
			}
		}
		rows, err := tx.Query(e.ctx(), "EXPLAIN "+q, args...)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		var sb strings.Builder
		for rows.Next() {
			var l string
			_ = rows.Scan(&l)
			sb.WriteString(l + "\n")
		}
		return sb.String()
	}
	admin := plan(`SELECT * FROM ipos WHERE org_id = $1 ORDER BY open_date DESC NULLS FIRST, id DESC LIMIT 51`, e.org)
	if !strings.Contains(admin, "ipos_admin_list_idx") || strings.Contains(admin, "Sort") {
		t.Errorf("admin list plan does not use ipos_admin_list_idx without a sort:\n%s", admin)
	}
	client := plan(`SELECT * FROM ipos WHERE org_id = $1 AND published ORDER BY open_date DESC NULLS FIRST, id DESC LIMIT 51`, e.org)
	if !strings.Contains(client, "ipos_published_list_idx") || strings.Contains(client, "Sort") {
		t.Errorf("client list plan does not use ipos_published_list_idx without a sort:\n%s", client)
	}
}

func TestList_SC008_RequestsUnderBudgetWith500IPOs(t *testing.T) {
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
