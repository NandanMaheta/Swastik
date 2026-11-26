# ADR 0010: Run on PostgreSQL 17

Status: proposed (owner approval at PR) · Date: 2026-11-26

## Context

We planned for PostgreSQL 18 because it has a built-in `uuidv7()`, which our tables use for primary keys. Supabase, our host, only offers 17.x. PostgreSQL 17 has no `uuidv7()`, so the first migration failed there.

## Decision

- Production, staging, local dev, CI tests and the backup drill all use PostgreSQL 17 (`postgres:17-alpine`). Tests must match production's major version.
- We ship our own `public.uuidv7()` (RFC 9562 v7: 48-bit unix milliseconds, version 7, variant bits, random rest). It is volatile and parallel safe.
- It is created by `apps/api/internal/platform/db/bootstrap.sql`, embedded in the API and run by `db.Migrate` before goose. It only creates the function when no `uuidv7()` exists in `pg_catalog` or `public`, so it is safe to run every time.
- Migrations 00001 to 00004 stay untouched (they are on stage and the guard forbids edits). Goose versions must be above 0, so a goose migration cannot run before 00001. A bootstrap step outside goose is the clean way to keep them immutable.

## Consequences

- On PostgreSQL 18 the bootstrap does nothing and the built-in function takes over, with no migration change.
- Revisit when Supabase offers 18: change the image in `dbtest`, `compose.yaml`, `drill.sh` and `nightly.yml`, then the bootstrap can be deleted.
- Our function does not guarantee ordering inside the same millisecond; ordering across milliseconds is guaranteed. Nothing relies on finer ordering.
