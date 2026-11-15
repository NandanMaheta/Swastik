package db_test

// 027 review-fix item 7 - infra/supabase/roles.sql hardening. Shares rolesEnv/hasPriv/runScript with
// roles_test.go; the selector `-run Roles` picks these up too.

import "testing"

func TestRoles_Review_AppCannotUpdateOrDeleteAuditLogOrGoose(t *testing.T) {
	ctx, pool, _ := rolesEnv(t)
	for _, table := range []string{"audit_log", "goose_db_version"} {
		for _, p := range []string{"UPDATE", "DELETE", "TRUNCATE"} {
			if hasPriv(ctx, t, pool, "swastik_app", table, p) {
				t.Errorf("swastik_app has %s on %s; it may only SELECT/INSERT", p, table)
			}
		}
		for _, p := range []string{"SELECT", "INSERT"} {
			if table == "audit_log" && !hasPriv(ctx, t, pool, "swastik_app", table, p) {
				t.Errorf("swastik_app must keep %s on %s", p, table)
			}
		}
	}
}

// Default privileges must not hand UPDATE/DELETE back on these tables when a migration recreates them
// (a recreated table gets default privileges; the script, re-run after migrations, must strip them again).
func TestRoles_Review_RecreatedAuditTablesStayLockedAfterRerun(t *testing.T) {
	ctx, pool, script := rolesEnv(t)
	recreate := `SET ROLE postgres;
		CREATE TABLE public.audit_log_review (id int PRIMARY KEY);
		DROP TABLE IF EXISTS public.goose_db_version CASCADE;
		CREATE TABLE public.goose_db_version (id int PRIMARY KEY);
		RESET ROLE;`
	if err := runScript(ctx, t, pool, recreate); err != nil {
		t.Fatal(err)
	}
	if err := runScript(ctx, t, pool, script); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"UPDATE", "DELETE"} {
		if hasPriv(ctx, t, pool, "swastik_app", "goose_db_version", p) {
			t.Errorf("recreated goose_db_version: swastik_app has %s after the script re-ran", p)
		}
	}
	var n int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM pg_default_acl d JOIN pg_roles r ON r.oid = d.defaclrole
		WHERE d.defaclobjtype = 'r' AND d.defaclacl::text ~ 'swastik_app=[^/]*[wd]'
		  AND d.defaclnamespace = 0`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("%d database-wide default ACLs grant UPDATE/DELETE to swastik_app", n)
	}
}

func TestRoles_Review_BackupHasNoExecuteOnFunctions(t *testing.T) {
	ctx, pool, _ := rolesEnv(t)
	if err := runScript(ctx, t, pool, `SET ROLE postgres; CREATE FUNCTION public.review_future_fn() RETURNS int LANGUAGE sql AS 'SELECT 1'; RESET ROLE;`); err != nil {
		t.Fatal(err)
	}
	rows, err := pool.Query(ctx, `SELECT p.oid::regprocedure::text, has_function_privilege('swastik_backup', p.oid, 'EXECUTE'),
		has_function_privilege('swastik_app', p.oid, 'EXECUTE')
		FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'public'`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	seen := 0
	for rows.Next() {
		var sig string
		var backup, app bool
		if err := rows.Scan(&sig, &backup, &app); err != nil {
			t.Fatal(err)
		}
		seen++
		if backup {
			t.Errorf("swastik_backup can EXECUTE %s (read-only login must not run functions; PUBLIC execute must be revoked)", sig)
		}
		if !app {
			t.Errorf("swastik_app lost EXECUTE on %s", sig)
		}
	}
	if seen == 0 {
		t.Fatal("expected public functions")
	}
}

// Supabase ships service_role (BYPASSRLS Data API role) with full grants; roles.sql must revoke it when it
// exists and must not fail when it does not (local databases).
func TestRoles_Review_ServiceRoleRevokedWhenPresent(t *testing.T) {
	ctx, pool, script := rolesEnv(t)
	if err := runScript(ctx, t, pool, `
		DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'service_role') THEN CREATE ROLE service_role NOLOGIN; END IF; END $$;
		GRANT USAGE ON SCHEMA public TO service_role;
		GRANT ALL ON ALL TABLES IN SCHEMA public TO service_role;
		GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO service_role;`); err != nil {
		t.Fatal(err)
	}
	if err := runScript(ctx, t, pool, script); err != nil {
		t.Fatalf("roles.sql must run with service_role present: %v", err)
	}
	for _, table := range publicTables(ctx, t, pool) {
		for _, p := range []string{"SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE"} {
			if hasPriv(ctx, t, pool, "service_role", table, p) {
				t.Errorf("service_role still has %s on %s", p, table)
			}
		}
	}
}
