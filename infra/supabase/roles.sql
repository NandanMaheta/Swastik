-- Swastik database logins (027 FR-009, FR-010, plan D-9). OWNER STEP: run once per Supabase project as
-- `postgres` (SQL editor or psql), then set passwords with `\password swastik_app` and
-- `\password swastik_backup`, and turn the Data API off in the Supabase dashboard.
-- Idempotent and plain SQL: safe to re-run after every migration batch. Contains no passwords.
--
--   postgres        owns every object, runs migrations (unchanged)
--   swastik_app     the API: SELECT/INSERT/UPDATE/DELETE only; no DDL, no TRUNCATE, owns nothing
--   swastik_backup  read-only, used by the nightly dump; no EXECUTE on functions
--   audit_log, goose_db_version: swastik_app may not UPDATE/DELETE them (append-only; re-locked on every run)
--   service_role    (Supabase Data API role) loses all rights when it exists
--   anon, authenticated (Supabase Data API roles): no rights at all

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'swastik_app') THEN
    CREATE ROLE swastik_app LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'swastik_backup') THEN
    CREATE ROLE swastik_backup LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
  END IF;
END
$$;

-- Connection and schema access; never CREATE.
DO $$
BEGIN
  EXECUTE format('GRANT CONNECT ON DATABASE %I TO swastik_app, swastik_backup', current_database());
END
$$;
REVOKE CREATE ON SCHEMA public FROM PUBLIC, swastik_app, swastik_backup, anon, authenticated;
GRANT USAGE ON SCHEMA public TO swastik_app, swastik_backup;

-- Existing objects.
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM swastik_app, swastik_backup, anon, authenticated;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM swastik_app, swastik_backup, anon, authenticated;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA public FROM anon, authenticated;
REVOKE USAGE ON SCHEMA public FROM anon, authenticated;

GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO swastik_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO swastik_app;
-- Functions are executable by PUBLIC by default; only the API login may run them.
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA public FROM PUBLIC, swastik_backup;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO swastik_app;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO swastik_backup;
GRANT SELECT ON ALL SEQUENCES IN SCHEMA public TO swastik_backup;

-- Future objects, for the migration owner (postgres) and for whoever runs this script.
ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public REVOKE ALL ON TABLES FROM anon, authenticated;
ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public REVOKE ALL ON SEQUENCES FROM anon, authenticated;
ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public REVOKE ALL ON FUNCTIONS FROM anon, authenticated;
ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO swastik_app;
ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO swastik_app;
ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public GRANT EXECUTE ON FUNCTIONS TO swastik_app;
ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public GRANT SELECT ON TABLES TO swastik_backup;
ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public GRANT SELECT ON SEQUENCES TO swastik_backup;
ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON TABLES FROM anon, authenticated;
ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON SEQUENCES FROM anon, authenticated;
ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON FUNCTIONS FROM anon, authenticated;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO swastik_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO swastik_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT EXECUTE ON FUNCTIONS TO swastik_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO swastik_backup;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON SEQUENCES TO swastik_backup;
-- Functions created later must not be executable by PUBLIC either (database-wide default for postgres).
ALTER DEFAULT PRIVILEGES FOR ROLE postgres REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
ALTER DEFAULT PRIVILEGES REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;

-- Append-only tables: the API may read and insert audit_log, and insert-only on the migration table.
-- Placed last so it also strips the default privileges a recreated table received; re-run after migrations.
DO $$
BEGIN
  IF to_regclass('public.audit_log') IS NOT NULL THEN
    REVOKE UPDATE, DELETE, TRUNCATE ON public.audit_log FROM swastik_app;
  END IF;
  IF to_regclass('public.goose_db_version') IS NOT NULL THEN
    REVOKE UPDATE, DELETE, TRUNCATE ON public.goose_db_version FROM swastik_app;
  END IF;
END
$$;

-- Supabase's service_role bypasses RLS and ships with full grants; nothing here uses it.
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'service_role') THEN
    REVOKE ALL ON ALL TABLES IN SCHEMA public FROM service_role;
    REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM service_role;
    REVOKE ALL ON ALL FUNCTIONS IN SCHEMA public FROM service_role;
    REVOKE USAGE ON SCHEMA public FROM service_role;
  END IF;
END
$$;
