# Feature Specification: Staging hosting (first cut of Release & ops)

**Feature Branch**: `feat/027-staging-hosting` (folder `specs/027-staging-hosting/`) · **Created**: 2026-11-15 · **Tier**: B · **Status**: Draft for owner approval

**Input**: Feature 027 (M15 Ops), first cut: get staging live end to end; production uses the same path behind the owner-approved `production` environment. Defers the APK/OTA pipeline to 024.

**Business rules**: none (operations only). **Golden scenarios**: GS-01…GS-04 are not changed and must keep passing.

## Questions for the owner (max 3)

1. **Error tracking.** May we add the Sentry Go library (`github.com/getsentry/sentry-go`) to the API? It sends crashes and errors to the `swastik-api` project. If you say no, errors stay only in Google Cloud logs and slice S13 is dropped. Proposed: yes.
2. **One Google Cloud project for both environments.** We plan to keep staging and production in `swastik-4fcc9`, kept apart by separate service accounts, secrets and names (`…-staging` / `…-production`). A second project gives stronger isolation but more setup. Proposed: one project.
3. **₹10 a month for secrets.** Secret Manager is free for 6 secrets; once auth (003) is live we need 8 (4 per environment), about ₹10 a month. Proposed: accept. The alternative is weaker (keys in GitHub only).

## User Scenarios & Testing

### US-1 Merge to `stage` puts staging live (P1)
The owner merges a PR into `stage`. Without any manual step, the API, the admin panel and the client web app on staging run the new code, with database migrations applied first.
**Acceptance**: (1) After a merge, `https://api-staging.swastikapp.co.in/healthz` answers `ok` and `/readyz` reports the new version (branch + short commit). (2) `https://admin-staging.swastikapp.co.in` and `https://app-staging.swastikapp.co.in` serve the new build. (3) If the new version fails its health check, the old version keeps serving and the run fails in red. (4) A merge never needs a Google, Supabase or Cloudflare key stored in GitHub as a JSON file.

### US-2 The 5-minute tick runs on staging (P1)
Cloud Scheduler calls `POST /internal/tick` every 5 minutes with a Google-signed token.
**Acceptance**: (1) The tick succeeds every 5 minutes (Scheduler shows success). (2) A call to `/internal/tick` without the scheduler's token is refused. (3) The public API address (`api-staging…`) never forwards `/internal/*`.

### US-3 Production release with approval, and rollback (P2)
The owner pushes a `vX.Y.Z` tag on `main`. The same steps run against production only after the owner approves the `production` environment.
**Acceptance**: (1) No production step runs before approval. (2) A written rollback note lets the owner return to the previous version in under 5 minutes. (3) Staging and production deploys never run at the same time for one environment.

### US-4 The admin panel is private (P2)
**Acceptance**: (1) Opening the admin address (custom domain or `*.pages.dev`) asks for a Cloudflare Access sign-in; only listed emails get through. (2) The API itself does not depend on Access (it has its own sign-in from 003).

### US-5 Nightly backup and a restore drill (P2)
**Acceptance**: (1) Every night the production database is dumped to a private Cloudflare R2 bucket. (2) The dump is restored into a temporary database and the row count of every table matches the count taken at dump time. (3) A failed backup or drill emails the owner (GitHub's failed-run email). (4) Dumps older than 30 days are deleted automatically.

### US-6 Know when something breaks, at ₹0 (P3)
**Acceptance**: (1) An uptime check calls `/healthz` on both environments every 5 minutes and emails the owner on failure. (2) API errors appear in Sentry (if Question 1 is yes). (3) A Google Cloud budget alert fires at ₹1 of spend. (4) Every paid limit has a cap (instances, image count, secret count) written in code.

### Edge cases
- Migration succeeds but the new version fails its check: old version keeps serving; migrations must therefore stay backward compatible (expand → migrate → contract, already a SQL rule).
- Supabase pauses an idle free project: the 5-minute tick keeps staging and production active.
- The tick runs during a deploy: both versions handle it safely (002 locks jobs).
- 003 not merged yet: auth keys are not wired until a switch is turned on in the same PR that brings 003 to staging.
- Supabase's built-in public REST API could expose `public` tables: it is switched off and its roles get no table rights.
- Someone calls the `*.run.app` address directly: same API, same auth; only the tick lives there.

## Requirements

### Functional
- **FR-001** All cloud resources (Cloud Run, Scheduler, service accounts, secret access, Artifact Registry, DNS, Pages, Access, R2, the API proxy) are defined in OpenTofu under `infra/tofu`, state in a versioned GCS bucket.
- **FR-002** GitHub reaches Google Cloud only through Workload Identity Federation, limited to this repository and to a named GitHub environment (`staging`, `production`, `infra`).
- **FR-003** Runtime secrets live in Secret Manager and reach the API as environment variables; values never appear in the repo, tofu state, workflow logs or chat.
- **FR-004** Non-secret settings (APP_ENV, TICK_*, WEB_ORIGINS, active key ids) are set by OpenTofu; the deploy workflow only changes the image.
- **FR-005** Deploy order: build image → run `goose` migrations with the migration login → start the new version with no traffic → check `/readyz` on it → move all traffic → check public `/healthz` → publish admin and client web builds.
- **FR-006** `stage` deploys to staging; `v*` tags deploy to production after owner approval; one deploy per environment at a time.
- **FR-007** Cloud Scheduler calls `/internal/tick` every 5 minutes (Asia/Kolkata) with an OIDC token whose audience and service account match `TICK_AUDIENCE` / `TICK_SERVICE_ACCOUNT`; no automatic retry (the next tick catches up).
- **FR-008** The API has a stable address per environment on `swastikapp.co.in` (`api-staging`, `api`), so admin cookies from 003 work (same registrable domain); `/internal/*` is not reachable through it.
- **FR-009** The API connects as a least-privileged database login (`swastik_app`: read/write rows only; no table creation, no TRUNCATE, owns nothing); migrations use the owner login; backups use a read-only login.
- **FR-010** Supabase's public Data API is off and the `anon` / `authenticated` roles have no rights on app tables.
- **FR-011** Admin panel and client web app are served by Cloudflare Pages (one project per app per environment) with security headers and SPA routing.
- **FR-012** Cloudflare Access protects the admin custom domain and its `pages.dev` addresses with an email allow-list and one-time PIN sign-in.
- **FR-013** Nightly backup and restore drill as in US-5, using a separate `backups` GitHub environment so it runs without a nightly approval.
- **FR-014** Cost caps: Cloud Run scales to zero, at most 2 instances; image registry keeps the 10 newest images; no always-on resources; the worker image is not deployed until 026 needs it.
- **FR-015** Uptime checks, Sentry errors (if approved) and the budget alert as in US-6.
- **FR-016** An owner runbook covers first-time setup, rollback, restoring a backup, and key rotation pointers (003).

### Key entities
Environments (`staging`, `production`); for each: an API service, a tick job, a proxy, two Pages projects, an Access app, secrets, and service accounts (runtime, tick caller, deployer). Shared: registry, state bucket, backup bucket, identity pool.

## Success Criteria
- **SC-001** From merge to staging serving the new version in ≤ 15 minutes, no manual step.
- **SC-002** 7 days in a row of staging ticks with no missed 5-minute slot that is not explained by a deploy.
- **SC-003** First restore drill passes; then every nightly drill passes or the owner gets an email the same night.
- **SC-004** Google Cloud bill for the month ≤ ₹10 (₹0 before 003); Supabase, Cloudflare, Sentry and the uptime service on free plans.
- **SC-005** No secret value in the repo, state, logs or chat (gitleaks clean; review checks state contents).
- **SC-006** API p95 for `/healthz` through the proxy < 200 ms from Mumbai (warm).

## Owner checklist (one time; details and exact names in [quickstart.md](./quickstart.md) and [contracts/deployment.md](./contracts/deployment.md))
1. In Google Cloud Shell, run `infra/bootstrap/bootstrap.sh` (creates the state bucket, the identity pool and the `tofu` service account). Create a budget with an alert at ₹1.
2. Run `infra/bootstrap/secrets.sh staging` (asks for the Supabase connection string; generates the auth keys itself, you never see them). Same for production later.
3. In Supabase (each project): switch off the Data API; run `infra/supabase/roles.sql` in Cloud Shell `psql` and set the two passwords with `\password`.
4. In Cloudflare: add a payment method so R2 can be enabled (stays free); create the two API tokens and the R2 key listed in the contract.
5. In GitHub: create environments `infra` (you as reviewer) and `backups`; limit `staging` to `stage` and `production` to `main` + `v*` tags; add the variables and secrets listed in the contract.
6. Run the **Infra** workflow for `shared`, then `staging`, and approve each; merge to `stage`; check the three staging addresses.
7. Create two uptime monitors (UptimeRobot free) for `/healthz`.

## Assumptions
- Cloud Run custom domains are not available in asia-south1 and a Google load balancer costs ~₹1,500/month, so a small Cloudflare Worker forwards `api-staging…` to the Cloud Run address (verified in slice S1).
- Supabase free projects are reached through the IPv4 session pooler (port 5432), as ADR 0003 Amendment 1 assumes.
- 002 is merged before the first staging deploy; 003 adds auth keys later behind the switch in FR-004.

## Out of scope (this cut)
APK and OTA pipeline (024); PR preview deploys; deploying the Python worker (026); admin break-glass recovery runbook (written when 003 merges, D-22 of 003); weekly ops digest; a tick-staleness alert (002's admin status covers it after 022).
