# Implementation Plan: Staging hosting (027, first cut)

**Branch**: `feat/027-staging-hosting` | **Date**: 2026-11-15 | **Spec**: [spec.md](./spec.md) | **Tier**: B
**Artifacts**: [contracts/deployment.md](./contracts/deployment.md) (every resource, variable and secret name) · [quickstart.md](./quickstart.md) (owner setup, rollback, restore) · ADR [0008](../../docs/adr/0009-hosting-topology.md) (proposed)

## Summary

OpenTofu describes everything in Google Cloud and Cloudflare; GitHub Actions only builds, migrates, ships an image and uploads static sites. One GCP project (`swastik-4fcc9`, asia-south1) holds both environments, separated by name suffix and per-environment service accounts that can only touch their own service and secrets. The API runs on Cloud Run (scale to zero); a ~30-line Cloudflare Worker gives it a stable `api[-staging].swastikapp.co.in` address (needed for 003's admin cookie). Cloud Scheduler calls the tick directly on the `run.app` address with an OIDC token. Supabase is used as plain Postgres through the session pooler with a least-privileged app login. Admin and client web builds go to Cloudflare Pages; Access guards the admin. A nightly job dumps production to R2 and proves the dump restores.

## Technical Context

- **Languages**: HCL (OpenTofu ≥ 1.10, exact version pinned in `.opentofu-version`), Bash, YAML (GitHub Actions), JavaScript (Worker, ES module), SQL (roles script), Go 1.27 (Sentry hook only, if approved).
- **Providers** (pinned in `.terraform.lock.hcl`): `hashicorp/google` 7.x, `cloudflare/cloudflare` 5.x.
- **Storage**: no schema change, no goose migration. One-time `infra/supabase/roles.sql` run by the owner.
- **Testing**: `tofu test` with `mock_provider` (plan-level, no cloud access), `node --test` (Worker), Go testcontainers (roles script), shell check scripts for workflows, `shellcheck` for bootstrap scripts.
- **Target**: Cloud Run (gen2, request-based billing), Supabase Free (Mumbai), Cloudflare Free.
- **Constraints**: ₹0 target (≈₹10/month once 003 adds 6 more secret versions, spec Q3); no JSON keys; agents never apply to cloud (owner approves the `infra` environment).
- **Scale**: 1 operator, ~100 clients; API max 2 instances × `MaxConns` 5 = 10 pooler connections (Supabase Free session pool fits).

## Constitution Check

| Principle | How this plan complies | Result |
|---|---|---|
| I Business rules | No business behaviour; GS-01…04 untouched and stay in CI. | PASS |
| II Money / immutable history | App login has no TRUNCATE and owns no table, so it cannot bypass `forbid_mutation()` triggers. | PASS |
| III Test-first | Every slice has tests written first by `test-engineer` (tofu tests, Worker tests, roles test, workflow checks). | PASS |
| IV Boundaries | No business module changes. Optional Sentry code sits in `internal/platform/observe` (no business imports; depguard). | PASS |
| V Contract-first | No OpenAPI change; `TestOpenAPI_NoInternalOperations` (002) still holds. | PASS |
| VI Security | WIF + per-environment SAs, Secret Manager, Access on admin, Data API off, least-privileged DB logins, `/internal/*` blocked at the proxy, no secrets in state. | PASS |
| VII Simple | New tools listed below with reasons; no always-on infrastructure. | PASS |

## Key decisions

- **D-1 One project, two environments.** Names end in `-staging` / `-production`. IAM is granted on individual resources (service, secret, repo), never project-wide, so the staging deployer cannot change production. (Owner Q2.)
- **D-2 Who changes what.** OpenTofu owns service config (env vars, secret refs, scaling, SA). `deploy.yml` changes only the image and traffic (`lifecycle.ignore_changes` on image, traffic, client fields). New config for later features = an infra PR + owner-approved apply. This replaces the `--set-env-vars/--set-secrets` lines in today's `deploy.yml` and the ones 003 plans to add.
- **D-3 Who applies tofu.** Workflow `infra.yml`: on PR → `fmt -check`, `validate`, `tofu test` (no credentials); on manual dispatch (input `staging|production|shared`) → `plan` then `apply` in GitHub environment `infra` (owner is required reviewer, branches `stage`/`main`). Only that environment can impersonate the `tofu` SA. The very first resources (state bucket, identity pool, `tofu` SA) come from `infra/bootstrap/bootstrap.sh`, run once by the owner in Cloud Shell.
- **D-4 Secrets created outside tofu.** `infra/bootstrap/secrets.sh <env>` creates Secret Manager secrets and their first version: it reads the database URL from a hidden prompt and generates the auth keys itself (`openssl rand`), piping them straight to `gcloud`. Tofu only references secrets by name (data sources) and grants `secretAccessor` to that environment's runtime SA. State never holds a value. Auth-key wiring is behind `var.auth_keys_enabled` (default false) and is turned on in the PR that brings 003 to staging.
- **D-5 Migrations from CI.** After the image is pushed, the job runs `docker run --rm -e DATABASE_URL=$MIGRATE_DATABASE_URL <image> migrate up` (goose, owner login, GitHub environment secret). Migrations must be expand-only relative to the running version (`.claude/rules/sql.md`); reviewers check it.
- **D-6 Safe traffic switch.** `gcloud run deploy --image … --no-traffic --tag c-<sha7>` → `curl` the tagged URL `/readyz` (expects the new version string) → `update-traffic --to-latest` → `curl $API_BASE_URL/healthz`. If the tagged check fails, traffic never moves. Build arg `VERSION=<ref>-<sha7>`. Concurrency group per environment, no cancel.
- **D-7 Stable API address via Worker.** Cloud Run domain mappings are not offered in asia-south1 and a load balancer breaks ₹0. Worker `swastik-api-proxy-<env>` on route `api[-staging].swastikapp.co.in/*` forwards to the `run.app` URL, returns 404 for `/internal/*`, replaces `X-Forwarded-For` with `CF-Connecting-IP`, passes cookies through. Free plan: 100k requests/day. S1 verifies the mapping claim; if mappings exist by then, we still keep the Worker (same setup for both environments, DNS/TLS stay in Cloudflare). `TRUSTED_PROXY_HOPS` is measured on staging and set in tfvars (003 R-7).
- **D-8 Tick.** Scheduler job `swastik-tick-<env>`, `*/5 * * * *`, Asia/Kolkata, POST to `<run.app>/internal/tick`, OIDC SA `tick-<env>@`, audience `https://api[-staging].swastikapp.co.in/internal/tick`, attempt deadline 60 s, `retry_count = 0`. The same two values go to the service as `TICK_AUDIENCE` / `TICK_SERVICE_ACCOUNT`. The service stays publicly invokable (ADR 0003 Am. 1).
- **D-9 Database logins.** Supabase `postgres` = migrations only. `swastik_app`: CONNECT, schema USAGE, SELECT/INSERT/UPDATE/DELETE on tables, USAGE/SELECT on sequences, EXECUTE on functions, plus `ALTER DEFAULT PRIVILEGES FOR ROLE postgres` so future tables are covered; no CREATE, no TRUNCATE. `swastik_backup`: SELECT only. `anon`, `authenticated` lose all rights on `public` now and by default; Data API switched off in the dashboard. Connection: session pooler, user `swastik_app.<project-ref>`, `sslmode=require`.
- **D-10 Pages.** Four direct-upload projects: `swastik-admin-<env>`, `swastik-app-<env>`, custom domains `admin[-staging]`, `app[-staging]`. Builds get `VITE_API_BASE_URL` / `EXPO_PUBLIC_API_BASE_URL` from `vars.API_BASE_URL`. `public/_headers`: CSP (`connect-src` = API origin), HSTS, `X-Frame-Options: DENY`, `Referrer-Policy`, `Permissions-Policy`; SPA fallback via `_redirects`.
- **D-11 Access.** One self-hosted Access app per environment covering the admin custom domain, `swastik-admin-<env>.pages.dev` and `*.swastik-admin-<env>.pages.dev`; allow policy = `var.access_emails`; identity = one-time PIN; session 24 h. The API host is never behind Access (003 P-04).
- **D-12 Backups.** `nightly.yml` job moves to environment `backups` (no reviewer). It runs `pg_dump` from a `postgres:<server-major>` container (Supabase major checked in S1; avoids client/server mismatch), stores per-table counts next to the dump, uploads to R2 `swastik-backups` (private, lifecycle delete after 30 days, tofu), restores into a same-major container and compares every table count. Script `infra/backup/drill.sh`, testable locally against compose Postgres.
- **D-13 Monitoring.** Sentry (if approved): `observe.Init(dsn, env, version)` + slog handler sending ERROR records and recovered panics; empty DSN = off; DSN comes from tofu var. Uptime: UptimeRobot free, owner-created (no IaC, no secret). Budget: owner-created ₹1 alert (CI holds no billing rights). Cloud Monitoring alert policies are not used (possible per-condition charges).
- **D-14 Worker image not deployed.** `deploy.yml` stops building/deploying `apps/worker` until 026; saves registry space.

## Data model, API, scheduler, outbox

- **Tables/migrations**: none. Roles and grants live in `infra/supabase/roles.sql` (idempotent `DO` blocks; no passwords in the file).
- **API operations**: none added or changed; no OpenAPI diff. The Worker blocks `/internal/*` on the public hostname.
- **Scheduler jobs / outbox events**: none new. Cloud Scheduler wiring for 002's existing tick only.

## Module placement

```text
infra/bootstrap/{bootstrap.sh,secrets.sh}        one-time owner scripts (gcloud), --dry-run mode
infra/tofu/modules/env/                           Cloud Run service, SAs, WIF bindings, secret IAM, Scheduler,
                                                  DNS, Worker + route, Pages projects + domains, Access app
infra/tofu/shared/                                APIs, Artifact Registry (+cleanup keep 10), R2 bucket + lifecycle
infra/tofu/envs/{staging,production}/             root modules: backend "gcs" prefix, *.tfvars (non-secret)
infra/tofu/tests/*.tftest.hcl                     mock-provider plan tests
infra/cloudflare/api-proxy/{worker.js,worker.test.js}
infra/supabase/roles.sql                          + apps/api/internal/platform/db/roles_test.go (testcontainers)
infra/backup/drill.sh
apps/admin/public/{_headers,_redirects}, apps/client/public/{_headers,_redirects}
apps/api/internal/platform/observe/               only if Sentry is approved
.github/workflows/{deploy.yml,infra.yml,nightly.yml,pr.yml}, scripts/check-deploy-workflow.sh
docs/adr/0009-hosting-topology.md, docs/engineering/runbook.md (from quickstart once live)
```

No business module is touched; depguard rules unchanged except allowing `sentry-go` only in `platform/observe`.

## Test strategy

| Layer | What | Where | Covers |
|---|---|---|---|
| Static | `tofu fmt -check -recursive`, `tofu validate` per root, `shellcheck`, YAML parse, gitleaks | `pr.yml` (path filter `infra/**`, `.github/**`) | FR-001, SC-005 |
| Unit (plan) | Cloud Run `min=0`, `max≤2`, 512Mi, request billing, runtime SA per env, env vars set, image ignored; secrets only via `secret_key_ref`; Scheduler cron/timezone/OIDC/audience/no retry; WIF condition pins repo + environment; IAM only resource-level; AR cleanup keep 10; R2 lifecycle 30 d; Access covers custom + pages.dev hosts; staging names never used in production root | `infra/tofu/tests/` | FR-001–004, 007, 008, 011, 012, 014 |
| Unit | Worker: forwards method/path/query/body/cookies, rewrites host, 404 on `/internal/*`, overwrites XFF, passes status/headers | `node --test infra/cloudflare/api-proxy` | FR-008 |
| Unit | Bootstrap/secrets `--dry-run` prints the expected gcloud commands, never a value | `infra/bootstrap/test.sh` | FR-002, FR-003 |
| Integration | After all migrations + `roles.sql`: `swastik_app` can CRUD every table, cannot CREATE/TRUNCATE/ALTER, `audit_log` UPDATE still blocked; `anon` has no rights; script re-runs cleanly; every table is covered | `platform/db/roles_test.go` | FR-009, FR-010 |
| Integration | Drill script: dump → restore → counts match; altered count fails | `infra/backup/drill.sh --local` in `pr.yml` | FR-013 |
| Contract | Deploy workflow: `--no-traffic`, tagged `/readyz` before traffic, concurrency per env, no `--set-env-vars`/`--set-secrets`, no worker deploy, env selection by ref | `scripts/check-deploy-workflow.sh` | FR-005, FR-006, D-14 |
| Unit (Go) | `observe`: empty DSN no-op; ERROR forwarded, INFO not; no secret fields in events (fake transport) | `platform/observe/*_test.go` | FR-015 |
| E2E | Post-deploy smoke (tagged `/readyz`, public `/healthz`, admin/app 200 + Access redirect) | `deploy.yml` | US-1, US-4 |
| Golden | GS-01…04 unchanged in CI | existing | — |
| UAT | Owner checklist on staging (`uat-checklist` skill) | PR | US-1…6 |

## Performance, security, cost

- **Performance**: Worker adds ~5–15 ms (Mumbai edge → asia-south1). Cold start ~0.3 s Go; acceptable (constitution p95 is for warm requests). No startup CPU boost (₹0).
- **Security**: no JSON keys; WIF `attribute_condition` = `assertion.repository_id == '<id>' && assertion.environment in [...]` per SA; tofu SA only from `infra`. Secret values only in Secret Manager / GitHub environment secrets. Direct `run.app` calls can forge `X-Forwarded-For` → 003's per-IP limiter is coarse only; noted as risk R-3. Backups hold readable emails/mobiles (ADR 0007; PAN encrypted): bucket private, token scoped to the bucket, 30-day retention.
- **Cost**: Cloud Run free tier, Scheduler 2 of 3 free jobs, AR ≤ ~200 MB (free 0.5 GB), Secret Manager 2 versions now / 8 after 003 (6 free), Workers/Pages/Access/R2 free, GCS state bucket a few KB.

## New dependencies and tools

| Item | Kind | Reason |
|---|---|---|
| OpenTofu ≥ 1.10 + google 7.x, cloudflare 5.x providers | CI/owner tool | Infra as code (blueprint choice); `tofu test` mocks give tests without cloud access |
| `opentofu/setup-opentofu`, `cloudflare/wrangler-action` (Pages upload) | CI actions | Pinned by SHA |
| `github.com/getsentry/sentry-go` | **Runtime, needs approval (Q1)** | Error tracking for `swastik-api` |
| UptimeRobot (free account) | Service | ₹0 uptime emails; no code |
| `shellcheck` (preinstalled on runners), `node --test` (built in) | CI | No new packages |

## Slices (skeleton first; planner refines into tasks)

S1 skeleton + checks (empty roots/modules, pinned providers, `.opentofu-version`, Worker stub, empty roles.sql, check script stubs; verify domain mapping, Supabase major, provider resource names) · S2 bootstrap + secrets scripts · S3 shared root (APIs, AR, R2) · S4 env module: SAs, WIF bindings, secret IAM · S5 env module: Cloud Run service · S6 env module: Scheduler tick · S7 Worker code · S8 env module: DNS, Worker route, Pages projects/domains · S9 env module: Access app · S10 roles.sql + roles test · S11 deploy.yml rewrite + check script · S12 Pages `_headers`/`_redirects` + web build/upload steps · S13 Sentry `observe` (if approved) · S14 infra.yml + pr.yml jobs · S15 nightly backup/drill · S16 docs: quickstart → runbook, handover, modules status, ADR 0009 final.

## Coordination and risks

- **C-1 002**: must be merged before the first deploy (tick endpoint). **C-2 003**: its `deploy.yml` secret lines are superseded by D-2/D-4; secret names gain the env suffix (`jwt-signing-keys-staging`…); `WEB_ORIGINS` = admin + app origins; break-glass runbook follows 003's merge.
- **R-1** Provider 5.x Cloudflare resource names change often → S1 pins and checks. **R-2** Supabase on PG 17 while CI tests on 18 → S1 records the major; if 17, CI adds a PG 17 job (follow-up issue). **R-3** XFF spoofing via `run.app` (see Security). **R-4** Workers free limit 100k/day → far above ~100 users; Worker errors show in uptime checks.

## Complexity tracking

Worker proxy is extra moving parts versus a direct `run.app` URL; justified by 003's same-site cookie need (D-21) and ₹0.

## S1 findings (T001)

- Providers locked: google 7.46.2, cloudflare 5.29.0 (OpenTofu 1.13.9, `.opentofu-version`). Resource names confirmed in schema: `google_cloud_run_v2_service`, `google_cloud_scheduler_job`, `google_artifact_registry_repository`, `google_iam_workload_identity_pool(_provider)`, `cloudflare_workers_script`, `cloudflare_workers_route`, `cloudflare_pages_project`, `cloudflare_pages_domain`, `cloudflare_zero_trust_access_application`, `cloudflare_zero_trust_access_policy`, `cloudflare_r2_bucket`, `cloudflare_r2_bucket_lifecycle`, `cloudflare_dns_record`.
- Cloud Run domain mapping in asia-south1: not verifiable offline (no cloud access); D-7 assumption (Worker proxy kept either way) stands.
- Supabase Postgres major: not verifiable without credentials; owner to confirm (17 vs CI 18) before T019 picks the dump image.
