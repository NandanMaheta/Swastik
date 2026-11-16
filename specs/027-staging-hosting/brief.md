# Brief: 027 Staging hosting (Release & ops, first cut)  ·  Tier B

**Goal:** Put staging live end to end (API on Cloud Run, tick every 5 min, admin and client web on Cloudflare Pages behind Access for the admin), deployed from `stage` with no manual step; production follows the same path on `v*` tags after owner approval. Plus nightly backup + restore drill, uptime/error monitoring and cost caps at ~₹0.

**Business rules:** none (ops). Golden scenarios GS-01…04 unaffected, must keep passing.

**Acceptance criteria (spec.md):**
- US-1 / FR-005, FR-006: merge to `stage` → migrate → no-traffic revision → tagged `/readyz` → traffic → public `/healthz` → Pages upload.
- US-2 / FR-007: Scheduler OIDC tick every 5 min to `run.app`; FR-008 proxy blocks `/internal/*`.
- US-3: tag deploy waits for `production` approval; rollback < 5 min (quickstart).
- US-4 / FR-012: Access on admin custom domain + `pages.dev` hosts.
- US-5 / FR-013: nightly R2 dump, restore drill with per-table counts, 30-day retention.
- FR-001–004: all infra in OpenTofu, WIF only, secrets in Secret Manager, tofu owns config.
- FR-009/010: `swastik_app` least privilege; Supabase Data API off.
- FR-014/015, SC-004: caps (max 2 instances, keep 10 images), uptime, Sentry (if approved), budget alert.

**Public surface:**
- Go: none, except `internal/platform/observe` (`Init`, slog handler) if Sentry is approved.
- HTTP: no change; no OpenAPI diff.
- DB: no migration; `infra/supabase/roles.sql` (owner-run once).
- Infra: names in `contracts/deployment.md`.

**Files to touch:** `infra/{bootstrap,tofu,cloudflare/api-proxy,supabase,backup}/`, `.github/workflows/{deploy,infra,nightly,pr}.yml`, `scripts/check-deploy-workflow.sh`, `apps/{admin,client}/public/{_headers,_redirects}`, `apps/api/internal/platform/db/roles_test.go`, `apps/api/internal/platform/observe/` (Q1), `docs/adr/0009-hosting-topology.md`.

**Depends on:** 001 (done); 002 merged before first deploy; 003 later flips `auth_keys_enabled`. See `docs/engineering/codemap.md` (health, config, tickauth).

**Risks and non-goals:** Worker proxy instead of domain mapping (verify S1); Supabase PG major vs CI 18 (S1); XFF spoof via `run.app` (003 limiter coarse); Secret Manager ~₹10/month after 003. Non-goals: APK/OTA (024), PR previews, worker deploy (026), break-glass runbook (after 003), ops digest.
