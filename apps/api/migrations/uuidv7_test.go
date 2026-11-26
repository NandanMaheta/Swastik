package migrations_test

import (
	"context"
	"os"
	"testing"

	"github.com/NandanMaheta/swastik/apps/api/internal/platform/dbtest"
)

// Production is PostgreSQL 17, which has no native uuidv7(). A migration must define a SQL
// uuidv7() so every `DEFAULT uuidv7()` works. On PostgreSQL 18 that migration must be a no-op
// (the native function is kept). To run the PG18 case: set SWASTIK_TEST_PG18=1 and change
// dbtest.Image to postgres:18-alpine locally; otherwise TestUUIDv7_NoopOnPG18 is skipped.

func TestUUIDv7_ValidVersionAndVariant(t *testing.T) {
	pool := dbtest.New(t)
	var ver, variant int
	err := pool.QueryRow(context.Background(),
		`SELECT (get_byte(uuid_send(u), 6) >> 4), (get_byte(uuid_send(u), 8) >> 6) FROM (SELECT uuidv7() AS u) s`).Scan(&ver, &variant)
	if err != nil {
		t.Fatal(err)
	}
	if ver != 7 {
		t.Errorf("version nibble = %d, want 7", ver)
	}
	if variant != 2 { // binary 10 = RFC 4122
		t.Errorf("variant bits = %b, want 10", variant)
	}
}

func TestUUIDv7_TimestampPrefixIsNow(t *testing.T) {
	pool := dbtest.New(t)
	var diffMs float64
	err := pool.QueryRow(context.Background(), `
SELECT abs(extract(epoch FROM now()) * 1000 -
  ('x' || encode(substring(uuid_send(uuidv7()) FROM 1 FOR 6), 'hex'))::bit(48)::bigint)`).Scan(&diffMs)
	if err != nil {
		t.Fatal(err)
	}
	if diffMs > 2000 {
		t.Errorf("timestamp prefix off by %.0f ms, want within 2000", diffMs)
	}
}

func TestUUIDv7_ThousandSequentialValuesIncrease(t *testing.T) {
	pool := dbtest.New(t)
	ctx := context.Background()
	var prev string
	seen := map[string]bool{}
	for i := 0; i < 1000; i++ {
		var cur string
		if err := pool.QueryRow(ctx, `SELECT uuidv7()::text`).Scan(&cur); err != nil {
			t.Fatal(err)
		}
		if seen[cur] {
			t.Fatalf("duplicate uuid %s at %d", cur, i)
		}
		seen[cur] = true
		if prev != "" && cur[:13] < prev[:13] { // timestamp (48 bits) must never go backwards
			t.Fatalf("timestamp decreased at %d: %s after %s", i, cur, prev)
		}
		prev = cur
	}
}

func TestUUIDv7_UsableAsColumnDefault(t *testing.T) {
	pool := dbtest.New(t)
	ctx := context.Background()
	if _, err := pool.Exec(ctx, `CREATE TABLE uuidv7_probe (id uuid PRIMARY KEY DEFAULT uuidv7(), n int)`); err != nil {
		t.Fatal(err)
	}
	var id string
	if err := pool.QueryRow(ctx, `INSERT INTO uuidv7_probe (n) VALUES (1) RETURNING id::text`).Scan(&id); err != nil {
		t.Fatal(err)
	}
	if len(id) != 36 || id[14] != '7' {
		t.Errorf("default id %q is not a v7 uuid", id)
	}
}

func TestUUIDv7_NoopOnPG18(t *testing.T) {
	if os.Getenv("SWASTIK_TEST_PG18") == "" {
		t.Skip("set SWASTIK_TEST_PG18=1 with dbtest.Image=postgres:18-alpine to run")
	}
	pool := dbtest.New(t)
	var isNative bool
	err := pool.QueryRow(context.Background(),
		`SELECT EXISTS (SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
		   WHERE p.proname = 'uuidv7' AND n.nspname = 'pg_catalog')`).Scan(&isNative)
	if err != nil {
		t.Fatal(err)
	}
	if !isNative {
		t.Error("native pg_catalog.uuidv7 missing")
	}
	var userDefined int
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
		   WHERE p.proname = 'uuidv7' AND n.nspname <> 'pg_catalog'`).Scan(&userDefined); err != nil {
		t.Fatal(err)
	}
	if userDefined != 0 {
		t.Errorf("migration must not shadow native uuidv7() on PG18; found %d user-defined", userDefined)
	}
}
