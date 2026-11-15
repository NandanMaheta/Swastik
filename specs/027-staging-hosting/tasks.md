# Tasks: Staging hosting (027, Tier B)

Sources: [plan.md](./plan.md) slices, [contracts/deployment.md](./contracts/deployment.md), [spec.md](./spec.md). Business rules: none (ops); GS-01..04 must keep passing. 20 slices, each <= ~400 lines, one owner, one done command. Order: skeleton -> tests (T002-T005, red) -> implementation -> wiring -> gate. Implementers never edit the test files.

Tooling note: every done command runs from the repo root (use `(cd dir && ...)` for subdirectories, never a bare `cd`). `tofu` 1.13.9, `shellcheck`, `node --test` and `actionlint` (`/root/go/bin/actionlint`) are available in the sandbox; `tofu test` uses `mock_provider`, and `-filter` takes the path as seen from the `-chdir` directory. Nothing here touches cloud resources or needs secrets (`init -backend=false`, mock providers).

**OWNER STEP** marks work whose real-world effect is performed by the owner after merge (agents only write and test the code): bootstrap script run, secrets creation, `infra` environment approval for tofu apply, roles.sql run, first nightly. Agents never apply, run bootstrap, or create secrets.

## Slices

### T001 (S1) Compile skeleton: empty tofu roots/modules, pinned providers, .opentofu-version, Worker stub, empty roles.sql, observe stubs (errNotImplemented), check-script stubs; record domain-mapping, Supabase PG major and provider resource-name findings
- Owner: `backend-dev` · Expect: `green` · Depends: none
- Rules/FR: FR-001
- Files: infra/tofu/{shared,modules/env,envs/staging,envs/production}/, .opentofu-version, infra/cloudflare/api-proxy/worker.js, infra/supabase/roles.sql, apps/api/internal/platform/observe/observe.go, scripts/check-deploy-workflow.sh, infra/backup/drill.sh, infra/bootstrap/{bootstrap,secrets}.sh stubs
- Done: `tofu fmt -check -recursive infra/tofu && for e in staging production; do tofu -chdir=infra/tofu/envs/$e init -backend=false -input=false && tofu -chdir=infra/tofu/envs/$e validate; done && (cd apps/api && go build ./... && go vet ./internal/platform/observe/...)`

### T002 [P] (S2t) Tests first: Worker node tests (forwarding, host rewrite, 404 on /internal/*, XFF overwrite, cookies) and bootstrap/secrets --dry-run test (expected gcloud commands, no value printed)
- Owner: `test-engineer` · Expect: `red` · Depends: T001
- Rules/FR: FR-002, FR-003, FR-008
- Files: infra/cloudflare/api-proxy/worker.test.js, infra/bootstrap/test.sh
- Done: `node --test infra/cloudflare/api-proxy/worker.test.js && bash infra/bootstrap/test.sh`

### T003 [P] (S3t) Tests first (tofu A): shared root (AR keep 10, R2 30-day lifecycle, APIs), SAs/WIF condition/resource-level IAM, Cloud Run (min 0, max<=2, 512Mi, request billing, secret_key_ref only, image ignored), Scheduler (cron, Asia/Kolkata, OIDC audience, retry 0)
- Owner: `test-engineer` · Expect: `red` · Depends: T001
- Rules/FR: FR-001, FR-002, FR-003, FR-004, FR-007, FR-014
- Files: infra/tofu/tests/shared/*.tftest.hcl, infra/tofu/tests/env/{iam,cloudrun,scheduler}.tftest.hcl
- Done: `tofu -chdir=infra/tofu/shared init -backend=false -input=false && tofu -chdir=infra/tofu/shared test -test-directory=../tests/shared && tofu -chdir=infra/tofu/modules/env init -backend=false -input=false && tofu -chdir=infra/tofu/modules/env test -test-directory=../../tests/env -filter=../../tests/env/iam.tftest.hcl -filter=../../tests/env/cloudrun.tftest.hcl -filter=../../tests/env/scheduler.tftest.hcl && bash infra/tofu/tests/lifecycle_test.sh`

### T004 [P] (S8t) Tests first (tofu B): DNS records, Worker route per env, four Pages projects + domains, Access app covering custom + pages.dev hosts, staging names absent from production root
- Owner: `test-engineer` · Expect: `red` · Depends: T001
- Rules/FR: FR-001, FR-008, FR-011, FR-012
- Files: infra/tofu/tests/env/{dns,pages,access}.tftest.hcl, infra/tofu/tests/roots.tftest.hcl
- Done: `tofu -chdir=infra/tofu/modules/env init -backend=false -input=false && tofu -chdir=infra/tofu/modules/env test -test-directory=../../tests/env -filter=../../tests/env/dns.tftest.hcl -filter=../../tests/env/pages.tftest.hcl -filter=../../tests/env/access.tftest.hcl && tofu -chdir=infra/tofu/envs/staging init -backend=false -input=false >/dev/null && tofu -chdir=infra/tofu/envs/staging test -test-directory=../../tests/roots -filter=../../tests/roots/staging.tftest.hcl && tofu -chdir=infra/tofu/envs/production init -backend=false -input=false >/dev/null && tofu -chdir=infra/tofu/envs/production test -test-directory=../../tests/roots -filter=../../tests/roots/production.tftest.hcl`

### T005 [P] (S10t) Tests first: roles_test.go (swastik_app CRUD, no CREATE/TRUNCATE, audit_log mutation blocked, anon none, idempotent, every table covered), observe tests (empty DSN no-op, ERROR forwarded, INFO not, no secret fields), check-deploy-workflow.sh assertions, drill.sh --local test
- Owner: `test-engineer` · Expect: `red` · Depends: T001
- Rules/FR: FR-005, FR-006, FR-009, FR-010, FR-013, FR-015
- Files: apps/api/internal/platform/db/roles_test.go, apps/api/internal/platform/observe/*_test.go, scripts/check-deploy-workflow.sh, infra/backup/drill_test.sh
- Done: `(cd apps/api && go test -race ./internal/platform/db/... ./internal/platform/observe/...) && bash scripts/check-deploy-workflow.sh && bash infra/backup/drill_test.sh`

### T006 (S2) Bootstrap and secrets scripts (--dry-run mode): state bucket, WIF pool/provider, tofu SA; secrets created from hidden prompt / openssl rand
- Owner: `backend-dev` · Expect: `green` · Depends: T002
- Rules/FR: FR-002, FR-003
- Files: infra/bootstrap/bootstrap.sh, infra/bootstrap/secrets.sh
- Done: `shellcheck infra/bootstrap/*.sh && bash infra/bootstrap/test.sh`
- OWNER STEP (after merge, not by agents): owner runs `bootstrap.sh` in Cloud Shell, then `secrets.sh <env>` per environment.

### T007 [P] (S3) Shared root: APIs, Artifact Registry (keep 10), R2 bucket + 30-day lifecycle
- Owner: `backend-dev` · Expect: `green` · Depends: T003
- Rules/FR: FR-001, FR-014
- Files: infra/tofu/shared/*.tf
- Done: `tofu fmt -check -recursive infra/tofu && tofu -chdir=infra/tofu/shared init -backend=false -input=false && tofu -chdir=infra/tofu/shared test -test-directory=../tests/shared`
- OWNER STEP (after merge, not by agents): owner approves the `infra` environment to apply `shared`.

### T008 (S4) Env module: deployer/runtime/tick SAs, WIF bindings pinned to repo + environment, secret-level IAM
- Owner: `backend-dev` · Expect: `green` · Depends: T003, T007
- Rules/FR: FR-002, FR-003
- Files: infra/tofu/modules/env/{iam,secrets}.tf
- Done: `tofu fmt -check -recursive infra/tofu && tofu -chdir=infra/tofu/modules/env init -backend=false -input=false && tofu -chdir=infra/tofu/modules/env test -test-directory=../../tests/env -filter=../../tests/env/iam.tftest.hcl`

### T009 (S5) Env module: Cloud Run service (config owned by tofu, image/traffic ignored), env vars and secret refs, auth_keys_enabled switch
- Owner: `backend-dev` · Expect: `green` · Depends: T008
- Rules/FR: FR-003, FR-004, FR-014
- Files: infra/tofu/modules/env/cloudrun.tf, infra/tofu/envs/*/{main.tf,terraform.tfvars}
- Done: `tofu fmt -check -recursive infra/tofu && tofu -chdir=infra/tofu/modules/env init -backend=false -input=false && tofu -chdir=infra/tofu/modules/env test -test-directory=../../tests/env -filter=../../tests/env/cloudrun.tftest.hcl && bash infra/tofu/tests/lifecycle_test.sh && for e in staging production; do tofu -chdir=infra/tofu/envs/$e init -backend=false -input=false && tofu -chdir=infra/tofu/envs/$e validate; done`

### T010 (S6) Env module: Cloud Scheduler tick job, OIDC audience matching TICK_AUDIENCE
- Owner: `backend-dev` · Expect: `green` · Depends: T009
- Rules/FR: FR-007
- Files: infra/tofu/modules/env/scheduler.tf
- Done: `tofu fmt -check -recursive infra/tofu && tofu -chdir=infra/tofu/modules/env init -backend=false -input=false && tofu -chdir=infra/tofu/modules/env test -test-directory=../../tests/env -filter=../../tests/env/scheduler.tftest.hcl`

### T011 [P] (S7) Cloudflare Worker proxy code
- Owner: `backend-dev` · Expect: `green` · Depends: T002
- Rules/FR: FR-008
- Files: infra/cloudflare/api-proxy/worker.js
- Done: `node --test infra/cloudflare/api-proxy/worker.test.js`

### T012 (S8) Env module: DNS records, Worker script + route, Pages projects and domains
- Owner: `backend-dev` · Expect: `green` · Depends: T004, T009, T011
- Rules/FR: FR-008, FR-011
- Files: infra/tofu/modules/env/{dns,worker,pages}.tf
- Done: `tofu fmt -check -recursive infra/tofu && tofu -chdir=infra/tofu/modules/env init -backend=false -input=false && tofu -chdir=infra/tofu/modules/env test -test-directory=../../tests/env -filter=../../tests/env/dns.tftest.hcl -filter=../../tests/env/pages.tftest.hcl`

### T013 (S9) Env module: Cloudflare Access app, allow policy, one-time PIN
- Owner: `backend-dev` · Expect: `green` · Depends: T012
- Rules/FR: FR-012
- Files: infra/tofu/modules/env/access.tf
- Done: `tofu fmt -check -recursive infra/tofu && tofu -chdir=infra/tofu/modules/env init -backend=false -input=false && tofu -chdir=infra/tofu/modules/env test -test-directory=../../tests/env -filter=../../tests/env/access.tftest.hcl && for e in staging production; do tofu -chdir=infra/tofu/envs/$e init -backend=false -input=false && tofu -chdir=infra/tofu/envs/$e validate; done && tofu -chdir=infra/tofu/envs/staging init -backend=false -input=false >/dev/null && tofu -chdir=infra/tofu/envs/staging test -test-directory=../../tests/roots -filter=../../tests/roots/staging.tftest.hcl && tofu -chdir=infra/tofu/envs/production init -backend=false -input=false >/dev/null && tofu -chdir=infra/tofu/envs/production test -test-directory=../../tests/roots -filter=../../tests/roots/production.tftest.hcl`
- OWNER STEP (after merge, not by agents): owner approves `infra` apply for staging (then production) and fills GitHub environment variables/secrets.

### T014 [P] (S10) roles.sql: swastik_app, swastik_backup, anon/authenticated revoke, default privileges (idempotent, no passwords)
- Owner: `backend-dev` · Expect: `green` · Depends: T005
- Rules/FR: FR-009, FR-010
- Files: infra/supabase/roles.sql
- Done: `(cd apps/api && go test -race ./internal/platform/db/... -run Roles)`
- OWNER STEP (after merge, not by agents): owner runs `roles.sql` on each Supabase project, sets passwords with `\password`, turns the Data API off.

### T015 (S11) deploy.yml rewrite: build, migrate, --no-traffic tagged revision, tagged /readyz, traffic switch, public /healthz, concurrency per env, no worker deploy, no --set-env-vars
- Owner: `backend-dev` · Expect: `green` · Depends: T005
- Rules/FR: FR-004, FR-005, FR-006
- Files: `.github/workflows/deploy.yml`
- Done: `/root/go/bin/actionlint .github/workflows/*.yml && bash scripts/check-deploy-workflow.sh`

### T016 (S12) Pages _headers/_redirects for admin and client; web build with API base URL and Pages upload steps
- Owner: `backend-dev` · Expect: `green` · Depends: T015
- Rules/FR: FR-011
- Files: apps/admin/public/{_headers,_redirects}, apps/client/public/{_headers,_redirects}, `.github/workflows/deploy.yml`
- Done: `/root/go/bin/actionlint .github/workflows/*.yml && bash scripts/check-deploy-workflow.sh --pages`

### T017 [P] (S13) Sentry observe package (observe.Init, slog handler; empty DSN off); sentry-go only in platform/observe, depguard allowance, wired in cmd
- Owner: `backend-dev` · Expect: `green` · Depends: T005
- Rules/FR: FR-015
- Files: apps/api/internal/platform/observe/, apps/api/go.mod, apps/api/cmd/..., .golangci.yml
- Done: `(cd apps/api && go test -race ./internal/platform/observe/... ./internal/health/... && go mod tidy -diff)`

### T018 (S14) infra.yml (PR checks, dispatch plan/apply in infra environment) and pr.yml infra/shell/yaml/gitleaks jobs
- Owner: `backend-dev` · Expect: `green` · Depends: T015
- Rules/FR: FR-001, SC-005
- Files: `.github/workflows/{infra,pr}.yml`
- Done: `/root/go/bin/actionlint .github/workflows/*.yml && bash scripts/check-deploy-workflow.sh --infra`
- OWNER STEP (after merge, not by agents): owner creates the `infra` and `backups` GitHub environments and required reviewers.

### T019 (S15) nightly.yml backup + restore drill (backups environment) and infra/backup/drill.sh
- Owner: `backend-dev` · Expect: `green` · Depends: T005
- Rules/FR: FR-013
- Files: `.github/workflows/nightly.yml`, infra/backup/drill.sh
- Done: `shellcheck infra/backup/drill.sh && bash infra/backup/drill_test.sh && /root/go/bin/actionlint .github/workflows/nightly.yml && bash scripts/check-deploy-workflow.sh --nightly`
- OWNER STEP (after merge, not by agents): owner adds backup/R2 secrets to the `backups` environment; first nightly drill is watched.

### T020 (S16) Gate and docs: quickstart to runbook, ADR 0009 final, handover, modules.md status, go mod tidy clean, full suite + lint, GS-01..04, BR traceability
- Owner: `backend-dev` · Expect: `green` · Depends: T006, T007, T008, T009, T010, T011, T012, T013, T014, T015, T016, T017, T018, T019
- Rules/FR: all FR; GS-01..04
- Files: docs/engineering/runbook.md, docs/adr/0009-hosting-topology.md, docs/engineering/handover.md, docs/product/modules.md
- Done: `(cd apps/api && go mod tidy -diff && go test -race ./...) && make lint-go && bash scripts/check-br-traceability.sh && tofu fmt -check -recursive infra/tofu && /root/go/bin/actionlint && bash scripts/check-deploy-workflow.sh --pages --infra --nightly`

## Dependencies and parallelism

T001 first. T002-T005 [P] after T001 (one test-engineer pass). Implementation slices follow their test slice; [P] marks slices that can run in parallel with their siblings (T007, T011, T014, T017). T020 last.

## Traceability

FR-001..004: T003/T007-T009; FR-005/006: T005/T015; FR-007: T010; FR-008: T002/T011/T012; FR-009/010: T005/T014; FR-011/012: T004/T012/T013/T016; FR-013: T005/T019; FR-014: T007/T009; FR-015: T005/T017; FR-016: T020; SC-005: T018.
