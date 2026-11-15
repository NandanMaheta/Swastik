-- Swastik database logins (027 FR-009, FR-010, plan D-9). OWNER STEP: run once per Supabase project as
-- `postgres` (SQL editor or psql), then set passwords with `\password swastik_app` and
-- `\password swastik_backup`, and turn the Data API off in the Supabase dashboard.
-- Idempotent and plain SQL: safe to re-run after every migration batch. Contains no passwords.
--
--   postgres        owns every object, runs migrations (unchanged)
--   swastik_app     the API: SELECT/INSERT/UPDATE/DELETE only; no DDL, no TRUNCATE, owns nothing
--   swastik_backup  read-only, used by the nightly dump
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
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO swastik_app, swastik_backup;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO swastik_backup;
GRANT SELECT ON ALL SEQUENCES IN SCHEMA public TO swastik_backup;

-- Future objects, for the migration owner (postgres) and for whoever runs this script.
ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public REVOKE ALL ON TABLES FROM anon, authenticated;
ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public REVOKE ALL ON SEQUENCES FROM anon, authenticated;
ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public REVOKE ALL ON FUNCTIONS FROM anon, authenticated;
ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO swastik_app;
ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO swastik_app;
ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public GRANT EXECUTE ON FUNCTIONS TO swastik_app, swastik_backup;
ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public GRANT SELECT ON TABLES TO swastik_backup;
ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public GRANT SELECT ON SEQUENCES TO swastik_backup;
ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON TABLES FROM anon, authenticated;
ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON SEQUENCES FROM anon, authenticated;
ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON FUNCTIONS FROM anon, authenticated;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO swastik_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO swastik_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT EXECUTE ON FUNCTIONS TO swastik_app, swastik_backup;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO swastik_backup;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON SEQUENCES TO swastik_backup;
