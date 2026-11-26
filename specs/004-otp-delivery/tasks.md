# Slices: 004 OTP delivery (Tier A, pipeline v2)

**Feature**: 004-otp-delivery | **Branch**: `feat/004-otp-delivery` | **Brief**: `brief.md` | **Plan**: `plan.md` | **Rules**: BR-CLI-04, BR-CLI-05 (GS-01…04 must keep passing; none driven by 004)

## Format

`- [ ] S## [P] owner: title`, then dependencies, rules, owner gates, size, expected result and done command. 19 slices (limit 8–20). Mirrored in `state.json` `tasks`.

- **red** = the done command must FAIL for the right reason (assertion or not-implemented panic, never a compile error); **green** = must pass. Test slices commit `test(otp): …`; their pair commits `feat(otp): …`. Implementers never edit test-engineer files (`protected_tests`, filled by the conductor after each test pass).
- Done commands run from the worktree root `/home/user/divya-004`. Integration tests need Docker and skip under `-short`.
- **Batching**: test pass 1 = S02, S04, S06, S08, S10, S12, S14, S16, S18 (all depend only on S01, plus S05 for DB-backed tests). Code pass 1 = S03, S05, S07, S09; code pass 2 = S11, S13, S15, S17, S19.
- **Owner gates** (state.json `owner_gates`): G-MIG and G-OUTBOX and G-PG17 on S05; G-AUTH on S09; G-SECRETS on S19. The PR also needs owner approval (Tier A) and the security reviewer. No new dependency.
- **Coverage**: 100% branch coverage and mutation score ≥ 85% on `internal/otp` (Tier A auth), checked at review.

## Traceability

| Spec item | Slices |
|---|---|
| US1 / D-01, D-02, FR-002, FR-003, FR-006 | S06–S07, S10–S13 |
| US2 / D-03, FR-004, FR-012 (Q1) | S06–S07, S10–S11, S16–S17 |
| US3 / D-04, D-05, FR-005 | S02–S03, S12–S13 |
| US4 / D-06, D-07, FR-008, FR-009 | S14–S17 |
| US5 / D-09, FR-007, FR-014 | S10–S13 |
| US6 / D-08, FR-010, SC-003 | S10, S14 |
| FR-011, FR-013 (Q2) outbox | S04–S05, S10–S11 |
| FR-015 housekeeping, FR-017 counts | S10–S11, S14–S15 |
| FR-016 error codes | S06–S07, S16–S17 |
| Secrets / 027 infra, Q3 runbook | S18–S19 |

## Slices

- [x] S01 **backend-dev**: Compile skeleton: internal/otp (all files of plan 'Module placement', exported names from contracts/go-module-api.md, bodies panic(errNotImplemented)), otp/otptest, otp/schema doc, platform/email, platform/firebaseauth; additive stubs outbox.Message.SensitivePayload + DeliverNow, auth.FindUser/DefaultOrg (+Accounts), httpx.ProblemRetry + ErrorModel.RetryAfterSeconds, config.OTPConfig. No wiring yet.
  - Depends on: none | Rules: none (mechanism) | Gates: none | ~420 lines | expect green
  - Done command: `cd apps/api && go build ./... && go vet ./internal/otp/... ./internal/platform/email/... ./internal/platform/firebaseauth/...`
- [ ] S02 [P] **test-engineer**: Platform tests: email Resend client (httptest: Bearer, Idempotency-Key, from, 429/5xx=>ErrUnavailable, 4xx=>ErrRejected, timeout, no recipient/body in errors), firebaseauth (minted RS256 tokens + local JWKS: iss/aud/alg/kid/exp/future iat/empty sub, claims parsed, Disabled), httpx.ProblemRetry (header + field), config OTP all-or-nothing, JWKS URL refused in staging/production, LogValue hides secrets.
  - Depends on: S01 | Rules: BR-CLI-04 | Gates: none | ~520 lines | expect red
  - Done command: `cd apps/api && go test -race ./internal/platform/email/... ./internal/platform/firebaseauth/... ./internal/platform/httpx/... ./internal/platform/config/...`
- [x] S03 **backend-dev**: Implement platform/email (Resend over net/http, Discard), platform/firebaseauth (go-oidc verifier like tickauth), httpx.ProblemRetry, config/otp.go.
  - Depends on: S02 | Rules: BR-CLI-04 | Gates: none | ~380 lines | expect green
  - Done command: `cd apps/api && go test -race ./internal/platform/email/... ./internal/platform/firebaseauth/... ./internal/platform/httpx/... ./internal/platform/config/...`
- [ ] S04 [P] **test-engineer**: Schema + outbox tests: otp/schema (every CHECK, one live code, one open flow per user+purpose, decoy shape, cascade) and outbox (erase trigger on sent/dead/withdrawn/expired/admin-cancel/withdraw-subject; CHECK; expired stale 'sending' never re-claimed; admin retry of sensitive => ErrConflict; DeliverNow: sends one, skips claimed/absent/expired/in-tx, failure recorded as attempt; non-sensitive unchanged).
  - Depends on: S01 | Rules: BR-CLI-04, BR-CLI-05 | Gates: none | ~560 lines | expect red
  - Done command: `cd apps/api && go test -race ./internal/otp/schema/... ./internal/outbox/...`
- [x] S05 **backend-dev**: OWNER GATES G-MIG, G-OUTBOX, G-PG17: migrations/00005_otp.sql (data-model 1-6, expand-only, down drops), queries/outbox.sql + outbox_admin.sql edits, ClaimMessageByKey, sqlc generate/vet, outbox SensitivePayload + DeliverNow.
  - Depends on: S04 | Rules: BR-CLI-04, BR-CLI-05 | Gates: G-MIG, G-OUTBOX, G-PG17 | ~400 lines | expect green
  - Done command: `cd apps/api && sqlc generate && sqlc vet && go test -race ./internal/otp/schema/... ./internal/outbox/...`
- [ ] S06 [P] **test-engineer**: Pure otp tests: GenerateCode (6 digits, rapid uniformity buckets, reader errors), code digest binding, ApplyLimits unit table at boundaries (59/60 s, 1 h rolling, 00:00 IST) + rapid properties (never > N per window, exact retry_after, refusal adds no event), MaskEmail/MaskMobile, templates (no code in notice, expiry text), ProblemFor table (codes, statuses, Retry-After seconds rounded up).
  - Depends on: S01 | Rules: BR-CLI-04 | Gates: none | ~520 lines | expect red
  - Done command: `cd apps/api && go test -race -run 'TestGenerateCode|TestCodeDigest|TestApplyLimits|TestMask|TestTemplate|TestProblemFor' ./internal/otp/`
- [x] S07 **backend-dev**: Implement code.go, limits.go, model.go masks, templates.go, errors.go.
  - Depends on: S06 | Rules: BR-CLI-04 | Gates: none | ~330 lines | expect green
  - Done command: `cd apps/api && go test -race -run 'TestGenerateCode|TestCodeDigest|TestApplyLimits|TestMask|TestTemplate|TestProblemFor' ./internal/otp/`
- [ ] S08 [P] **test-engineer**: auth additions tests (FindUser by email/mobile/normalised, unknown, invalid; DefaultOrg) and otp Store tests through Store (insert/lock verification by handle hash, supersede, live code lock, wrong-attempt increment, proof insert conflict, limits lock order, counts upsert, purge batches, org isolation).
  - Depends on: S01, S05 | Rules: BR-CLI-04, BR-CLI-05 | Gates: none | ~520 lines | expect red
  - Done command: `cd apps/api && go test -race -run 'TestFindUser|TestDefaultOrg' ./internal/auth/ && go test -race -run 'TestStore_' ./internal/otp/`
- [ ] S09 **backend-dev**: OWNER GATE G-AUTH: auth.FindUser/DefaultOrg; queries/otp.sql (all filter org_id) + sqlc; otp/store.go (only pgx file).
  - Depends on: S08 | Rules: BR-CLI-04, BR-CLI-05 | Gates: G-AUTH | ~420 lines | expect green
  - Done command: `cd apps/api && sqlc generate && sqlc vet && go test -race -run 'TestFindUser|TestDefaultOrg' ./internal/auth/ && go test -race -run 'TestStore_' ./internal/otp/`
- [ ] S10 [P] **test-engineer**: Service tests A (fake clock, fake mailer, real outbox): Start signup/change (US1.1, US5.1, not-allowed statuses, supersede withdraws old email, invalid contact), Resend (US2.1-2.3, per-user 10/day, unknown handle), quiet hours 23:00 IST exempt (US2.4), Deliver/DeliverNow path, sealed sensitive payload, Sender (opens box, skips expired, counts sent/failed, idempotency key), Cancel, NotifyOldContact (respects quiet hours, no code), DailyCounts, audit rows without contacts (US6).
  - Depends on: S01, S05 | Rules: BR-CLI-04, BR-CLI-05 | Gates: none | ~600 lines | expect red
  - Done command: `cd apps/api && go test -race -run 'TestStart_|TestResend_|TestDeliver_|TestSender_|TestCancel_|TestNotice_|TestDailyCounts_' ./internal/otp/`
- [ ] S11 **backend-dev**: Implement service.go, start.go, send.go, sender.go, counts.go.
  - Depends on: S07, S09, S10 | Rules: BR-CLI-04, BR-CLI-05 | Gates: none | ~420 lines | expect green
  - Done command: `cd apps/api && go test -race -run 'TestStart_|TestResend_|TestDeliver_|TestSender_|TestCancel_|TestNotice_|TestDailyCounts_' ./internal/otp/`
- [ ] S12 [P] **test-engineer**: Service tests B: VerifyEmail (US1.2 10:09:59/10:10:00, US1.3 concurrent double entry, US1.4 5th => used_up, superseded code, check_ip 60/h, change proves without account change + contact_unavailable US5.3), VerifyMobile (US3.1-3.5: email first, mismatch without echo, 5 min boundary, other project/provider, replay, Android/iPhone tokens alike; US5.2 other user's session 404), US1.5 pending_approval after both.
  - Depends on: S01, S05 | Rules: BR-CLI-04, BR-CLI-05 | Gates: none | ~620 lines | expect red
  - Done command: `cd apps/api && go test -race -run 'TestVerifyEmail_|TestVerifyMobile_' ./internal/otp/`
- [ ] S13 **backend-dev**: Implement verify_email.go, verify_mobile.go.
  - Depends on: S11, S12 | Rules: BR-CLI-04, BR-CLI-05 | Gates: none | ~380 lines | expect green
  - Done command: `cd apps/api && go test -race -run 'TestVerifyEmail_|TestVerifyMobile_' ./internal/otp/`
- [ ] S14 [P] **test-engineer**: Reset + housekeeping + leak tests: StartReset (US4.1 email/mobile identifier, US4.2 unknown/pending/disabled/admin => decoy, identical results, no audit, no email), CompleteReset (policy error keeps token, ends sessions, clears lock, reuse refused US4.3, expired token), housekeeping purge + audit + HousekeepingNext; SC-003 leak scan over logs/audit/outbox/problems.
  - Depends on: S01, S05 | Rules: BR-CLI-04 | Gates: none | ~560 lines | expect red
  - Done command: `cd apps/api && go test -race -run 'TestStartReset_|TestCompleteReset_|TestHousekeeping|TestNoLeak_' ./internal/otp/`
- [ ] S15 **backend-dev**: Implement reset.go, housekeeping.go, RegisterJobs.
  - Depends on: S13, S14 | Rules: BR-CLI-04 | Gates: none | ~330 lines | expect green
  - Done command: `cd apps/api && go test -race -run 'TestStartReset_|TestCompleteReset_|TestHousekeeping|TestNoLeak_' ./internal/otp/`
- [ ] S16 [P] **test-engineer**: HTTP + contract tests: humatest handlers (shapes, statuses, Retry-After, handle never in URL, /v1/me/* auth + other-user 404, burst limiter, known vs unknown reset identical, timing median diff < 10% SC-004 with real floor), cmd/swastik/otp_contract_test.go (10 ops, security, public allowlist, schemas vs contracts/otp.openapi.yaml, wiring: senders for both topics, job registered), packages/domain otp-error-codes.test.ts, lint-boundary deliberate violations for otp/firebaseauth/email.
  - Depends on: S01 | Rules: BR-CLI-04, BR-CLI-05 | Gates: none | ~600 lines | expect red
  - Done command: `cd apps/api && go test -race -run 'TestHandler_|TestOTPContract|TestWiring' ./internal/otp/ ./cmd/swastik/ && cd ../.. && pnpm --filter @swastik/domain test && bash scripts/check-lint-boundaries.sh`
- [ ] S17 **backend-dev**: Implement handler*.go + api_types.go, cmd/swastik wiring (OTP config, senders, jobs), .golangci.yml depguard rules, packages/domain otp-error-codes.ts + index export, regenerate api-client.
  - Depends on: S15, S16 | Rules: BR-CLI-04, BR-CLI-05 | Gates: none | ~420 lines | expect green
  - Done command: `cd apps/api && go test -race ./internal/otp/... ./cmd/swastik/... && make -C ../.. lint-go && cd ../.. && pnpm --filter @swastik/api-client generate && pnpm turbo run typecheck test --filter @swastik/domain --filter @swastik/api-client && bash scripts/check-lint-boundaries.sh`
- [ ] S18 [P] **test-engineer**: Infra tests: infra/bootstrap/test.sh cases for --with-otp (hidden prompt for Resend key, generated 32-byte HMAC key, dry run prints names only) and --rotate-otp-hmac; tofu tftest: otp_enabled adds RESEND_API_KEY/OTP_HMAC_KEY secret refs, OTP_EMAIL_FROM/FIREBASE_PROJECT_ID plain env, IAM accessor, nothing when disabled.
  - Depends on: S01 | Rules: none (mechanism) | Gates: none | ~300 lines | expect red
  - Done command: `bash infra/bootstrap/test.sh && cd infra/tofu/modules/env && tofu init -backend=false -input=false >/dev/null && tofu test`
- [ ] S19 **ops**: OWNER GATE G-SECRETS: infra/bootstrap/secrets.sh --with-otp/--rotate-otp-hmac, tofu variables/secrets/cloudrun + envs tfvars (otp_enabled false until the owner creates the secrets), runbook (Firebase console state, Resend cap, rotation, Q3 real-device SMS test), handover + modules.md status.
  - Depends on: S18 | Rules: none (mechanism) | Gates: G-SECRETS | ~260 lines | expect green
  - Done command: `bash infra/bootstrap/test.sh && cd infra/tofu/modules/env && tofu init -backend=false -input=false >/dev/null && tofu test`
