package db_test

// 027 T005 - infra/supabase/roles.sql (FR-009, FR-010, plan D-9). Test names contain "Roles" so the
// done command `go test ./internal/platform/db/... -run Roles` selects them.
//
// Setup mirrors Supabase: the container superuser is "swastik", Supabase migrates as role "postgres".
// The test creates `postgres` (superuser), moves ownership of the migrated objects to it, creates
// `anon`/`authenticated` (Supabase ships them), then runs the script as written. Roles are cluster
// global, so these tests must not run in parallel with each other.
//
// Assumptions for the script under test: it creates roles swastik_app and swastik_backup (LOGIN, no
// password, no superuser/createdb/createrole/bypassrls), is idempotent, and contains no password.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/NandanMaheta/swastik/apps/api/internal/platform/dbtest"
)

const (
	pgInsufficientPrivilege = "42501"
	pgRaiseException        = "P0001"
)

func rolesSQLPath(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate test file")
	}
	// apps/api/internal/platform/db -> repo root
	return filepath.Join(filepath.Dir(file), "..", "..", "..", "..", "..", "infra", "supabase", "roles.sql")
}

func runScript(ctx context.Context, t *testing.T, pool *pgxpool.Pool, sql string) error {
	t.Helper()
	c, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	defer c.Release()
	_, err = c.Conn().PgConn().Exec(ctx, sql).ReadAll() // simple protocol: multi-statement script
	return err
}

// rolesEnv gives a migrated database in Supabase shape with roles.sql applied once.
func rolesEnv(t *testing.T) (context.Context, *pgxpool.Pool, string) {
	t.Helper()
	pool := dbtest.New(t)
	ctx := context.Background()
	raw, err := os.ReadFile(rolesSQLPath(t))
	if err != nil {
		t.Fatalf("read roles.sql: %v", err)
	}
	script := string(raw)

	setup := `
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'postgres') THEN CREATE ROLE postgres SUPERUSER LOGIN; END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'anon') THEN CREATE ROLE anon NOLOGIN; END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN CREATE ROLE authenticated NOLOGIN; END IF;
END $$;
DO $$ DECLARE r record; BEGIN
  FOR r IN SELECT c.relname, c.relkind FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
           WHERE n.nspname = 'public' AND c.relkind IN ('r','p') LOOP
    EXECUTE format('ALTER TABLE public.%I OWNER TO postgres', r.relname);
  END LOOP;
  FOR r IN SELECT p.oid::regprocedure AS sig FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'public' LOOP
    EXECUTE format('ALTER FUNCTION %s OWNER TO postgres', r.sig);
  END LOOP;
END $$;
GRANT ALL ON SCHEMA public TO postgres;
-- Supabase grants the Data API roles everything by default; reproduce that so the revoke is tested.
GRANT USAGE ON SCHEMA public TO anon, authenticated;
GRANT ALL ON ALL TABLES IN SCHEMA public TO anon, authenticated;
GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO anon, authenticated;
ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public GRANT ALL ON TABLES TO anon, authenticated;
`
	if err := runScript(ctx, t, pool, setup); err != nil {
		t.Fatalf("setup supabase-shaped database: %v", err)
	}
	if err := runScript(ctx, t, pool, script); err != nil {
		t.Fatalf("roles.sql failed: %v", err)
	}
	return ctx, pool, script
}

// as runs fn on one connection with SET ROLE role and always resets it.
func as(ctx context.Context, t *testing.T, pool *pgxpool.Pool, role string, fn func(exec func(sql string, args ...any) error)) {
	t.Helper()
	c, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	defer c.Release()
	if _, err := c.Exec(ctx, "SET ROLE "+role); err != nil {
		t.Fatalf("SET ROLE %s: %v (does roles.sql create it?)", role, err)
	}
	defer func() { _, _ = c.Exec(ctx, "RESET ROLE") }()
	fn(func(sql string, args ...any) error {
		_, err := c.Exec(ctx, sql, args...)
		return err
	})
}

func sqlState(err error) string {
	var pe *pgconn.PgError
	if errors.As(err, &pe) {
		return pe.Code
	}
	return ""
}

func publicTables(ctx context.Context, t *testing.T, pool *pgxpool.Pool) []string {
	t.Helper()
	rows, err := pool.Query(ctx, `SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = 'public' AND c.relkind IN ('r','p') ORDER BY 1`)
	if err != nil {
		t.Fatalf("list tables: %v", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			t.Fatal(err)
		}
		out = append(out, s)
	}
	if len(out) < 4 {
		t.Fatalf("expected the migrated tables, got %v", out)
	}
	return out
}

func hasPriv(ctx context.Context, t *testing.T, pool *pgxpool.Pool, role, table, priv string) bool {
	t.Helper()
	var ok bool
	err := pool.QueryRow(ctx, `SELECT has_table_privilege($1, format('public.%I', $2::text), $3)`, role, table, priv).Scan(&ok)
	if err != nil {
		t.Fatalf("has_table_privilege(%s,%s,%s): %v", role, table, priv, err)
	}
	return ok
}

// BR-free ops rule FR-009: the API login can read and write every table.
func TestRoles_FR009_AppHasCRUDOnEveryTable(t *testing.T) {
	ctx, pool, _ := rolesEnv(t)
	for _, table := range publicTables(ctx, t, pool) {
		for _, p := range []string{"SELECT", "INSERT", "UPDATE", "DELETE"} {
			if !hasPriv(ctx, t, pool, "swastik_app", table, p) {
				t.Errorf("swastik_app lacks %s on %s", p, table)
			}
		}
	}
}

func TestRoles_FR009_AppCanCRUDOrgsAsAppLogin(t *testing.T) {
	ctx, pool, _ := rolesEnv(t)
	as(ctx, t, pool, "swastik_app", func(exec func(string, ...any) error) {
		for _, stmt := range []string{
			`INSERT INTO orgs (name) VALUES ('Acme')`,
			`UPDATE orgs SET name = 'Acme 2' WHERE name = 'Acme'`,
			`SELECT count(*) FROM orgs`,
			`DELETE FROM orgs WHERE name = 'Acme 2'`,
		} {
			if err := exec(stmt); err != nil {
				t.Errorf("%s: %v", stmt, err)
			}
		}
		if err := exec(`INSERT INTO orgs (name) VALUES ('Keep')`); err != nil {
			t.Fatal(err)
		}
		if err := exec(`INSERT INTO audit_log (org_id, actor_kind, entity, action) SELECT id, 'system', 'org', 'create' FROM orgs LIMIT 1`); err != nil {
			t.Errorf("audit insert must work: %v", err)
		}
	})
}

func TestRoles_FR009_AppCannotCreateTruncateOrAlter(t *testing.T) {
	ctx, pool, _ := rolesEnv(t)
	as(ctx, t, pool, "swastik_app", func(exec func(string, ...any) error) {
		for _, stmt := range []string{
			`CREATE TABLE public.sneaky (id int)`,
			`TRUNCATE orgs CASCADE`,
			`TRUNCATE audit_log`,
			`ALTER TABLE orgs ADD COLUMN x int`,
			`DROP TABLE orgs`,
			`CREATE FUNCTION public.f() RETURNS int LANGUAGE sql AS 'SELECT 1'`,
			`CREATE SCHEMA sneaky`,
		} {
			err := exec(stmt)
			if err == nil {
				t.Errorf("%q succeeded; swastik_app must not do DDL or TRUNCATE", stmt)
			} else if sqlState(err) != pgInsufficientPrivilege {
				t.Errorf("%q: want 42501 insufficient_privilege, got %v", stmt, err)
			}
		}
	})
	var canCreate, canConnect bool
	if err := pool.QueryRow(ctx, `SELECT has_schema_privilege('swastik_app','public','CREATE'), has_database_privilege('swastik_app', current_database(), 'CONNECT')`).Scan(&canCreate, &canConnect); err != nil {
		t.Fatal(err)
	}
	if canCreate {
		t.Error("swastik_app must not have CREATE on schema public")
	}
	if !canConnect {
		t.Error("swastik_app must be able to CONNECT")
	}
}

func TestRoles_FR009_AuditLogMutationStillBlockedForApp(t *testing.T) {
	ctx, pool, _ := rolesEnv(t)
	as(ctx, t, pool, "swastik_app", func(exec func(string, ...any) error) {
		if err := exec(`INSERT INTO orgs (name) VALUES ('A')`); err != nil {
			t.Fatal(err)
		}
		if err := exec(`INSERT INTO audit_log (org_id, actor_kind, entity, action) SELECT id, 'system', 'org', 'create' FROM orgs LIMIT 1`); err != nil {
			t.Fatal(err)
		}
		for _, stmt := range []string{
			`UPDATE audit_log SET action = 'tampered'`,
			`DELETE FROM audit_log`,
		} {
			err := exec(stmt)
			if err == nil {
				t.Errorf("%q succeeded; audit_log must stay append-only", stmt)
			} else if sqlState(err) != pgRaiseException {
				t.Errorf("%q: want trigger exception P0001 (so the trigger, not a missing grant, blocks it), got %v", stmt, err)
			}
		}
		if err := exec(`ALTER TABLE audit_log DISABLE TRIGGER audit_log_append_only`); err == nil {
			t.Error("swastik_app must not be able to disable the audit trigger")
		}
	})
}

func TestRoles_FR009_AppOwnsNothingAndIsNotPrivileged(t *testing.T) {
	ctx, pool, _ := rolesEnv(t)
	var owned int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM pg_class c JOIN pg_roles r ON r.oid = c.relowner
		WHERE r.rolname IN ('swastik_app','swastik_backup')`).Scan(&owned); err != nil {
		t.Fatal(err)
	}
	if owned != 0 {
		t.Errorf("app/backup logins own %d relations; owners can bypass triggers via ALTER/TRUNCATE", owned)
	}
	for _, role := range []string{"swastik_app", "swastik_backup"} {
		var login, super, createdb, createrole, bypass bool
		err := pool.QueryRow(ctx, `SELECT rolcanlogin, rolsuper, rolcreatedb, rolcreaterole, rolbypassrls FROM pg_roles WHERE rolname = $1`, role).
			Scan(&login, &super, &createdb, &createrole, &bypass)
		if err != nil {
			t.Fatalf("%s must exist: %v", role, err)
		}
		if !login || super || createdb || createrole || bypass {
			t.Errorf("%s attributes: login=%v super=%v createdb=%v createrole=%v bypassrls=%v", role, login, super, createdb, createrole, bypass)
		}
	}
}

func TestRoles_FR009_SequencesAndFunctionsUsable(t *testing.T) {
	ctx, pool, _ := rolesEnv(t)
	// A sequence created by the migration owner after the script must be usable by the app (default privileges).
	if err := runScript(ctx, t, pool, `CREATE SEQUENCE public.t_seq; CREATE TABLE public.t_new (id serial PRIMARY KEY, v text);`); err != nil {
		t.Fatal(err)
	}
	as(ctx, t, pool, "swastik_app", func(exec func(string, ...any) error) {
		if err := exec(`SELECT nextval('public.t_seq')`); err != nil {
			t.Errorf("nextval on a new sequence: %v", err)
		}
		if err := exec(`INSERT INTO t_new (v) VALUES ('x')`); err != nil {
			t.Errorf("insert with serial on a new table: %v", err)
		}
	})
	var ok bool
	if err := pool.QueryRow(ctx, `SELECT has_function_privilege('swastik_app', 'public.forbid_mutation()', 'EXECUTE')`).Scan(&ok); err != nil || !ok {
		t.Errorf("swastik_app must EXECUTE public functions: ok=%v err=%v", ok, err)
	}
}

func TestRoles_FR009_FutureTablesAreCoveredByDefaultPrivileges(t *testing.T) {
	ctx, pool, _ := rolesEnv(t)
	if err := runScript(ctx, t, pool, `SET ROLE postgres; CREATE TABLE public.future_table (id int PRIMARY KEY, v text); RESET ROLE;`); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"SELECT", "INSERT", "UPDATE", "DELETE"} {
		if !hasPriv(ctx, t, pool, "swastik_app", "future_table", p) {
			t.Errorf("a table created later by the migration owner lacks %s for swastik_app", p)
		}
	}
	for _, p := range []string{"INSERT", "UPDATE", "DELETE", "TRUNCATE"} {
		if hasPriv(ctx, t, pool, "swastik_backup", "future_table", p) {
			t.Errorf("swastik_backup got %s on a future table", p)
		}
	}
	if !hasPriv(ctx, t, pool, "swastik_backup", "future_table", "SELECT") {
		t.Error("swastik_backup must read future tables")
	}
	for _, role := range []string{"anon", "authenticated"} {
		for _, p := range []string{"SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER"} {
			if hasPriv(ctx, t, pool, role, "future_table", p) {
				t.Errorf("%s got %s on a future table (Data API exposure)", role, p)
			}
		}
	}
	var n int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM pg_class c JOIN pg_namespace s ON s.oid=c.relnamespace
		WHERE s.nspname='public' AND c.relname='future_table' AND c.relowner = (SELECT oid FROM pg_roles WHERE rolname='postgres')`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("test setup: future_table must be owned by postgres (n=%d err=%v)", n, err)
	}
}

func TestRoles_FR010_BackupIsReadOnlyEverywhere(t *testing.T) {
	ctx, pool, _ := rolesEnv(t)
	for _, table := range publicTables(ctx, t, pool) {
		if !hasPriv(ctx, t, pool, "swastik_backup", table, "SELECT") {
			t.Errorf("swastik_backup cannot SELECT %s", table)
		}
		for _, p := range []string{"INSERT", "UPDATE", "DELETE", "TRUNCATE"} {
			if hasPriv(ctx, t, pool, "swastik_backup", table, p) {
				t.Errorf("swastik_backup has %s on %s", p, table)
			}
		}
	}
	as(ctx, t, pool, "swastik_backup", func(exec func(string, ...any) error) {
		if err := exec(`INSERT INTO orgs (name) VALUES ('x')`); err == nil || sqlState(err) != pgInsufficientPrivilege {
			t.Errorf("backup login insert: want 42501, got %v", err)
		}
	})
}

func TestRoles_FR010_AnonAndAuthenticatedHaveNoRights(t *testing.T) {
	ctx, pool, _ := rolesEnv(t)
	for _, role := range []string{"anon", "authenticated"} {
		for _, table := range publicTables(ctx, t, pool) {
			for _, p := range []string{"SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER"} {
				if hasPriv(ctx, t, pool, role, table, p) {
					t.Errorf("%s has %s on %s", role, p, table)
				}
			}
		}
		as(ctx, t, pool, role, func(exec func(string, ...any) error) {
			if err := exec(`SELECT * FROM orgs`); err == nil || sqlState(err) != pgInsufficientPrivilege {
				t.Errorf("%s SELECT orgs: want 42501, got %v", role, err)
			}
		})
	}
	var n int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM pg_class c JOIN pg_namespace s ON s.oid=c.relnamespace
		WHERE s.nspname='public' AND c.relkind='S'
		  AND (has_sequence_privilege('anon', c.oid,'USAGE') OR has_sequence_privilege('authenticated', c.oid,'USAGE')
		       OR has_sequence_privilege('anon', c.oid,'SELECT') OR has_sequence_privilege('authenticated', c.oid,'SELECT'))`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("%d public sequences still usable by anon/authenticated", n)
	}
}

// aclSnapshot returns a stable text of every table/sequence/schema ACL and role attributes.
func aclSnapshot(ctx context.Context, t *testing.T, pool *pgxpool.Pool) string {
	t.Helper()
	rows, err := pool.Query(ctx, `
		SELECT 'rel ' || c.relname || ' ' || coalesce(c.relacl::text,'') FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public'
		UNION ALL SELECT 'schema ' || coalesce(nspacl::text,'') FROM pg_namespace WHERE nspname='public'
		UNION ALL SELECT 'defacl ' || coalesce(defaclacl::text,'') || defaclobjtype::text FROM pg_default_acl
		UNION ALL SELECT 'role ' || rolname || rolcanlogin || rolsuper || rolcreatedb || rolcreaterole || rolbypassrls || coalesce(rolconfig::text,'') FROM pg_roles WHERE rolname LIKE 'swastik\_%'
		UNION ALL SELECT 'member ' || r.rolname || '>' || m.rolname FROM pg_auth_members a JOIN pg_roles r ON r.oid=a.member JOIN pg_roles m ON m.oid=a.roleid WHERE r.rolname LIKE 'swastik\_%'
		ORDER BY 1`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var lines []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			t.Fatal(err)
		}
		lines = append(lines, s)
	}
	sort.Strings(lines)
	return strings.Join(lines, "\n")
}

func TestRoles_FR009_ScriptIsIdempotent(t *testing.T) {
	ctx, pool, script := rolesEnv(t)
	before := aclSnapshot(ctx, t, pool)
	if !strings.Contains(before, "swastik_app") {
		t.Fatalf("snapshot shows no swastik_app grants:\n%s", before)
	}
	for i := 0; i < 2; i++ {
		if err := runScript(ctx, t, pool, script); err != nil {
			t.Fatalf("re-run %d failed: %v", i+1, err)
		}
	}
	if after := aclSnapshot(ctx, t, pool); after != before {
		t.Errorf("re-running changed privileges\n--- before\n%s\n--- after\n%s", before, after)
	}
}

func TestRoles_FR009_ScriptHasNoPasswordsOrSecrets(t *testing.T) {
	raw, err := os.ReadFile(rolesSQLPath(t))
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	if len(strings.TrimSpace(s)) < 200 {
		t.Fatalf("roles.sql is still a stub (%d bytes)", len(s))
	}
	for _, re := range []string{`(?i)password\s+'`, `(?i)password\s+\$`, `(?i)\bencrypted\b`, `postgres(ql)?://`} {
		if regexp.MustCompile(re).MatchString(s) {
			t.Errorf("roles.sql matches %q: passwords are set by the owner with \\password", re)
		}
	}
	if regexp.MustCompile(`(?im)^\s*\\`).MatchString(s) {
		t.Error("roles.sql must be plain SQL (no psql meta-commands) so it runs from any client")
	}
	if !regexp.MustCompile(`(?i)ALTER DEFAULT PRIVILEGES\s+FOR ROLE postgres`).MatchString(s) {
		t.Error("roles.sql must set ALTER DEFAULT PRIVILEGES FOR ROLE postgres (D-9)")
	}
}

// Every table must be reachable: guards against a hard-coded table list in the script.
func TestRoles_FR009_EveryTableCoveredIncludingMigrationBookkeeping(t *testing.T) {
	ctx, pool, _ := rolesEnv(t)
	tables := publicTables(ctx, t, pool)
	want := []string{"orgs", "audit_log", "scheduled_jobs"}
	for _, w := range want {
		found := false
		for _, tb := range tables {
			found = found || tb == w
		}
		if !found {
			t.Fatalf("expected migrated table %s in %v", w, tables)
		}
	}
	missing := 0
	for _, tb := range tables {
		if !hasPriv(ctx, t, pool, "swastik_app", tb, "SELECT") || !hasPriv(ctx, t, pool, "swastik_backup", tb, "SELECT") {
			missing++
			t.Errorf("table %s not covered", tb)
		}
	}
	if missing > 0 {
		t.Logf("tables: %s", fmt.Sprint(tables))
	}
}
