# Implementation Plan: 004 OTP delivery (email code, Firebase mobile proof, limits)

**Branch**: `feat/004-otp-delivery` | **Date**: 2026-11-26 | **Spec**: [spec.md](./spec.md) (owner-approved 2026-11-26, Q1–Q3 as recommended) | **Tier**: A
**Artifacts**: [research.md](./research.md), [data-model.md](./data-model.md), [contracts/otp.openapi.yaml](./contracts/otp.openapi.yaml), [contracts/go-module-api.md](./contracts/go-module-api.md), [contracts/error-codes.md](./contracts/error-codes.md), [quickstart.md](./quickstart.md); ADR [0003 Am. 2](../../docs/adr/0003-tick-scheduler.md), ADR [0004 Am. 2](../../docs/adr/0004-auth.md) (proposed with this plan).
**Rules**: BR-CLI-04, BR-CLI-05. **Golden scenarios**: none driven; GS-01…04 must keep passing.

## Summary

New module `internal/otp` owns four tables (migration `00006_otp.sql`) and offers (a) an in-process capability for 005/007 (`Start`, `Deliver`, `Get`, `Cancel`, `NotifyOldContact`, `DailyCounts`) and (b) ten HTTP operations for 024 (handle-keyed public sign-up/reset operations; `/v1/me/*` change operations for the signed-in owner). Email codes: 6 uniform digits, stored as an HMAC digest, written with an encrypted outbox message in one transaction, delivered at once in the request through a new `outbox.DeliverNow` and the Resend sender, with the tick relay as fallback. Mobile: the app sends a Firebase phone sign-in ID token; `internal/platform/firebaseauth` verifies it with go-oidc; otp checks provider, freshness, number and single use. Durable limits live in `otp_limits`. Sign-up success calls `auth.MarkEmailVerified/MarkMobileVerified` in the same transaction; reset ends in `auth.ResetPassword`. Every event is audited without contacts, codes or proofs.

## Technical Context

**Language**: Go 1.27; TS only for `packages/domain` codes and the regenerated `@swastik/api-client`.
**Dependencies**: Huma v2, pgx v5, sqlc, goose, `github.com/coreos/go-oidc/v3` (approved in 002), `github.com/google/uuid`, `pgregory.net/rapid` (test). **No new Go module**; Resend over stdlib `net/http`.
**Storage**: PostgreSQL 17 (Supabase) / 18 in `dbtest`; `uuidv7()` from `fix/postgres-17-compat` (gate G-PG17). Tables: data-model §1–5; outbox change §6.
**Testing**: `go test -race`; rapid properties; `dbtest.New(t)` integration; `humatest` handlers with `authz.Install`; `cmd/swastik` contract tests + oasdiff; httptest fakes for Resend and Firebase JWKS (local RSA key); vitest for domain.
**Target**: Cloud Run `asia-south1`, `cpu_idle=true`, 5-minute tick (ADR 0003).
**Performance**: status/verify p95 < 200 ms; send operations p95 ≈ response floor (1.5 s) + nothing else (below).
**Scale**: ~100 clients, < 30 emails/day (Resend free cap 100/day shared), a few SMS/day.
No `NEEDS CLARIFICATION` remains.

## Interpretations (no new behaviour)

- **I-1** A `signup` verification carries both contacts (email code, then mobile proof); FR-001's "sign-up email / sign-up mobile" are its two steps (spec Key Entities, US3.1). Purposes stored: `signup`, `change_email`, `change_mobile`, `password_reset`.
- **I-2** Uniform reset replies (D-06/D-07) use a stored **decoy** verification for unknown identifiers and non-`active`-client accounts, so status/resend/verify behave identically later (data-model §7); reset status therefore never shows a masked contact.
- **I-3** Public send operations (`resend`, `password-reset/start`) answer no earlier than a fixed **1.5 s floor** after the request started; known accounts deliver the email inside the floor (SC-002 + SC-004). The floor is a config constant, injectable `Wait` in tests.
- **I-4** `Start` supersedes the user's open flow of the same purpose (005 "cancel and start new" stays valid). Contact-unavailable is checked at proof time (US5.3), not at start.
- **I-5** Dead code messages are erased too (stricter than "sent/withdrawn/expired"). The old-contact notice respects quiet hours (only codes were exempted by Q1).

## Constitution Check (pre- and post-design: PASS)

| Principle | Compliance |
|---|---|
| I Rules | Every test name carries BR-CLI-04/05; D-01…D-09 traced in tasks; no new business behaviour (I-1…I-5 interpret only). |
| II Money/history | No money. Audit append-only via `audit.Write` in the same tx for every user-facing event (FR-010). Decoy and limit rows for unmatched identifiers are operational state with no audit entry, as 003's throttle rows (003 FR-091). |
| III Test-first | `test-engineer` passes before code; fake clock everywhere; boundaries ±1 s (SC-001). |
| IV Boundaries | otp → auth (interface), outbox, scheduler (registrar), platform. Platform stays a leaf; depguard rules below. No cross-table reads. |
| V Contract-first | OpenAPI generated; additive only; RFC 9457 codes. **Deviation** (same as 003 Deviation 1 / P-16): credential-like operations take no `Idempotency-Key` and are marked `Metadata["idempotency"]="exempt"` (Complexity Tracking). |
| VI Security | Codes HMAC-only; outbox copy AES-GCM sealed and erased; tokens/handles SHA-256; no contacts/codes/proofs in logs/audit/errors (SC-003 scan); secrets via Secret Manager. |
| VII Simple | Stdlib Resend client; go-oidc reused; one module. |

## Module placement and dependencies

- `apps/api/internal/otp`: `model.go`, `errors.go`, `code.go`, `limits.go`, `service.go`, `start.go`, `send.go`, `verify_email.go`, `verify_mobile.go`, `reset.go`, `sender.go`, `templates.go`, `counts.go`, `housekeeping.go`, `store.go` (only file with pgx/dbgen), `api_types.go`, `handler.go`, `handler_public.go`, `handler_me.go`; `otptest/` (fake mailer, Firebase token minter + JWKS server, env builder).
- New platform leaves: `internal/platform/email` (Resend client, `Discard`), `internal/platform/firebaseauth`.
- Additive edits: `outbox` (sensitive payload, `DeliverNow`, expiry), `auth` (`FindUser`, `DefaultOrg`), `platform/httpx` (`ProblemRetry`), `platform/config` (`OTPConfig`), `cmd/swastik` (wiring, `registerOTPJobs`, sender registration for both topics with maxAttempts 3).
- **depguard** (`apps/api/.golangci.yml`): `otp-boundaries` strict allow-list (`$gostd`, huma, uuid, pgx, otp, auth, outbox, scheduler, platform); `otp-pgx-only-in-store`; rename `oidc-only-in-tickauth` → `oidc-only-in-verifiers` allowing `platform/firebaseauth`; add `internal/otp` to `platform-is-a-leaf` and `scheduler-does-not-know-owners`; `auth` must not import `otp` (new deny). `scripts/check-lint-boundaries.sh` gains deliberate violations for these.

## Data model (details: data-model.md)

`otp_verifications` (flow, handle hash, targets, per-contact done times, reset grant, 24 h expiry, one open flow per user+purpose), `otp_email_codes` (digest, 10 min, 5 wrong tries, one live code), `otp_used_proofs` (fingerprint PK), `otp_limits` (rolling/IST-day event arrays per scope+HMAC subject), `otp_daily_counts`. All carry `org_id` + FKs + CHECKs; UUIDv7 PKs. Outbox: `sensitive_payload` column, erase trigger, CHECK, query edits (§6). Expand-only; the previous app version keeps working.

## API operations (contracts/otp.openapi.yaml)

| Method + path | Security | Success | Main errors |
|---|---|---|---|
| POST `/v1/verifications/status` | public | 200 `VerificationStatus` | 404 |
| POST `/v1/verifications/resend` | public | 202 `ResendResult` | 404, 409, 410, 429 (Retry-After) |
| POST `/v1/verifications/verify-email` | public | 200 `VerifyEmailResult` (+`reset_token` for reset) | 404, 410, 422, 429 |
| POST `/v1/verifications/verify-mobile` | public | 200 `VerificationStatus` | 404, 409 email_first, 410, 422, 429, 503 |
| POST `/v1/password-reset/start` | public | 202 `ResetStarted` always | 422 identifier format, 429 |
| POST `/v1/password-reset/complete` | public | 204 | 422 token/policy, 429, 503 busy |
| POST `/v1/me/verifications/{status,resend,verify-email,verify-mobile}` | client bearer | as above | + 409 contact_unavailable; 404 for another user's handle |

Public operations: handle in the JSON body (never in URLs), per-IP in-memory burst limiter (30/min, like auth P-17) plus durable D-03 limits; added to the contract-test public allowlist. Idempotency: none (see Complexity Tracking); retries are safe because codes are single-use and resends are cooldown-guarded; a lost `verify-email` reply for a reset means asking for a new code.

## Key flows

- **Send (Start/Resend/StartReset)**: one tx: lock limit rows (contact, user, ip order) → `ApplyLimits` → on refusal: audit `otp.send.refused`, count `limit_refused`, commit, `RetryError`; else end the live code (`superseded`) + `Withdraw` its message, insert code (digest), `outbox.Add` (sealed, sensitive, quiet-exempt, expires with code), append limit events, audit `otp.code.issued`. After commit: `DeliverNow`; public ops then wait for the floor.
- **Verify email**: `check_ip` limit → lock verification + live code → expired/used-up/wrong (increment; 5th ⇒ `used_up`) → success: end code `used`, set `email_done_at`; signup ⇒ `auth.MarkEmailVerified` (same tx, FR-006); change ⇒ contact-unavailable check via `FindUser` then `proved`; reset ⇒ mint `prt_` token (hash stored, 10 min). Failures commit their counter + audit.
- **Verify mobile**: `check_ip` → `firebaseauth.Verify` (outside tx) → tx: lock verification; signup needs `email_done_at` (D-05) → provider/freshness/number → insert fingerprint (conflict ⇒ replayed) → `MarkMobileVerified` / proved. Signup with both done ⇒ `finished_at`; 003 moves the user to `pending_approval`.
- **Complete reset**: pre-check token + `auth.CheckPolicy` outside tx → tx: lock verification, re-check token unused/unexpired, `auth.ResetPassword` (joins tx; hashing inside this one rare tx, ~100 ms, accepted for atomicity) → mark completed, audit.

## Scheduler jobs and outbox events

- Job `otp.housekeeping` (recurring, 03:15 IST, data-model §8).
- Outbox topics: `otp.email_code` (client recipient, sensitive, quiet-hours exempt, expires with the code, maxAttempts 3) and `otp.contact_notice` (sensitive, respects quiet hours, expires 24 h). Both sent by `otp.Service.Sender()` via `email.Mailer`.

## Configuration, secrets and infra (owner gate G-SECRETS)

- **Secrets (names only)**: `RESEND_API_KEY`, `OTP_HMAC_KEY` (32 random bytes, bare base64). Reused: `PII_ENCRYPTION_KEYS`/`PII_ACTIVE_KEY_ID`. **Plain settings**: `OTP_EMAIL_FROM` (`no-reply@mail.swastikapp.co.in`), `FIREBASE_PROJECT_ID` (`swastik-4fcc9`); `FIREBASE_JWKS_URL` local/ci only.
- **Secret Manager ids**: `resend-api-key-<env>`, `otp-hmac-key-<env>`.
- **027 tofu** (`infra/tofu/modules/env`): variable `otp_enabled` (bool, default false); `secrets.tf` secret ids + accessor IAM for both; `cloudrun.tf` `secret_env` adds `RESEND_API_KEY`, `OTP_HMAC_KEY` and `plain_env` adds `OTP_EMAIL_FROM`, `FIREBASE_PROJECT_ID` when enabled; `envs/*` tfvars; `tests/env/cloudrun.tftest.hcl` assertions.
- **`infra/bootstrap/secrets.sh`**: `--with-otp` creates `otp-hmac-key-<env>` (openssl, never printed) and `resend-api-key-<env>` (hidden prompt; owner pastes the Resend key); `--rotate-otp-hmac` adds a version (safe: live codes and limit counters reset). `infra/bootstrap/test.sh` covers both flags and the dry run.
- Runbook (`docs/engineering/runbook.md`): Firebase console state (SMS region policy IN only, reCAPTCHA on, App Check deferred, test numbers), Resend domain + daily cap, secret rotation, the staging real-device SMS test (Q3) before 024.

## Test strategy (rule IDs in test names)

| Layer | Where | Covers |
|---|---|---|
| Unit | `otp/code_test`, `limits_test`, `mask_test`, `errors_test`, `templates_test`, `email/resend_test` (httptest: headers, 429/5xx ⇒ unavailable, 4xx ⇒ rejected, no body/recipient in errors), `firebaseauth/verify_test` (minted RS256 tokens: wrong iss/aud/alg/kid, expired, future iat) | D-01…D-04, D-08 |
| Property (rapid) | `limits_prop_test` (never more than N accepted per window; retry_after exact; IST-day reset), `code_prop_test` (6 digits, uniform bucket check, digest binds verification/purpose/code id) | BR-CLI-04 D-02/D-03 |
| Integration (DB) | `00006` schema tests (CHECKs, unique live code/open flow, outbox erase trigger and CHECK on every terminal path), outbox `DeliverNow`/expiry tests, otp store tests | FR-011, FR-013, FR-015 |
| Integration (service, fake clock) | US1–US6 acceptance scenarios incl. boundaries 10:09:59/10:10:00, 59 s/60 s, 5th wrong, concurrent double verify, decoys, superseded email withdrawn, quiet-hours 23:00 IST send, D-05, contact unavailable, reset ends sessions; audit content scan | BR-CLI-04, BR-CLI-05, SC-001, SC-003 |
| Contract | `cmd/swastik/otp_contract_test.go`: operations, security, public allowlist, schemas vs contracts; secrets never in examples; oasdiff additive | FR-009, FR-016 |
| Handler (humatest) | uniform shapes/status for known vs unknown reset; Retry-After; `/v1/me/*` other-user 404; timing test median diff < 10% (SC-004, as 003) | D-07 |
| Component (TS) | `packages/domain/src/otp-error-codes.test.ts`: every Go code has wording; placeholder fill | FR-016 |
| E2E / UAT | out of scope here (024 screens); staging real-device SMS test + SC-002/SC-006 UAT recorded in runbook | SC-002, SC-006 |
| Golden | GS-01…04 unchanged, run once per pass | — |

Leak scan (SC-003): a test-wide log handler + audit/outbox/problem scan asserting no fixture email, mobile, code, handle, token or Firebase token appears (pattern of 003 `verification_secrets_test.go`). Coverage: 100% branches + mutation ≥ 85% on `internal/otp` (Tier A auth).

## Performance and security notes

- Status/verify: 2–4 indexed statements; p95 well under 200 ms. Send: one tx + a Resend call (~0.3–0.8 s) inside the 1.5 s floor; DeliverNow bounded by the outbox 5 s send timeout.
- Firebase JWKS cached by go-oidc (honours `Cache-Control`); verification happens outside the DB tx.
- Per-IP burst limiter is per instance; the durable `otp_limits` holds across instances (FR-004).
- Threats: enumeration (I-2/I-3), code brute force (5 tries, 60 checks/h/IP, 10⁶ space), SMS pumping (email first, Firebase region policy), token replay (fingerprint, 5 min), outbox leak (sealed + erased), log leak (scan). Security review required (Tier A).

## Owner gates

- **G-MIG** migration `00006_otp.sql` (CODEOWNERS). **G-OUTBOX** outbox change + ADR 0003 Am. 2 (security-sensitive, approved in principle as Q2). **G-SECRETS** secret creation by the owner (`secrets.sh --with-otp`) and `otp_enabled=true` per env. **G-PG17** `fix/postgres-17-compat` merged before 00006 reaches staging. **G-AUTH** additive `auth` API (ADR 0004: auth PRs need owner approval). No new dependency.

## Complexity Tracking

| Deviation | Why | Simpler alternative rejected |
|---|---|---|
| No `Idempotency-Key` on OTP mutations (constitution V) | Replaying a stored response would require storing the reset token or code readably; operations are single-use and cooldown-guarded, so retries are harmless | Store responses: violates FR-013/D-08 |
| Decoy rows for unknown identifiers | Only way to keep later status/resend/verify replies identical (D-07) | Stateless random handles: status would reveal "unknown" |
| Response floor on public sends | In-request delivery is needed for SC-002 but would leak account existence by timing | Async delivery: CPU is throttled after the response on Cloud Run |
