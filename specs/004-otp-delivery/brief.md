# Brief: 004 OTP delivery  ·  Tier A

**Goal (2–3 lines):** Prove a client controls an email (6-digit code by email via the outbox and Resend, delivered in the request) or a mobile (Firebase phone sign-in ID token verified by the API), with cooldown, attempt and durable rate limits, for sign-up (005), contact changes (007), forgot password and the client app (024).

**Business rules:** BR-CLI-04, BR-CLI-05 ([business-rules](../../docs/product/business-rules.md)); golden scenarios affected: none (GS-01…04 must keep passing).

**Acceptance criteria (IDs from spec.md):**
- US1 sign-up email code: issue, 10-min expiry, single use, 5 wrong entries (D-01, D-02)
- US2 resend: 60 s cooldown, per contact/user/address limits, quiet-hours bypass (D-03, Q1)
- US3 mobile via Firebase proof: fresh, unused, our project, same number, email first (D-04, D-05)
- US4 forgot password: code to account email, uniform replies (decoys + 1.5 s floor), reset ends all sessions (D-06, D-07)
- US5 change-contact proof for 007, no account change until approval (D-09)
- US6 audit without contacts, codes or proofs (D-08)

**Public surface:** (details: `contracts/go-module-api.md`, `contracts/otp.openapi.yaml`, `contracts/error-codes.md`)
- Go `internal/otp`: `Start`, `Deliver`, `Get`, `Cancel`, `NotifyOldContact`, `DailyCounts`; handle ops `Status`, `Resend`, `VerifyEmail`, `VerifyMobile`, `StartReset`, `CompleteReset`; `Sender()`; `Register`, `RegisterJobs` (`otp.housekeeping`).
- New platform: `platform/email` (`Mailer`, `NewResend`, `Discard`), `platform/firebaseauth` (`Verifier`). Additive: `outbox.Message.SensitivePayload`, `outbox.DeliverNow`; `auth.FindUser`, `auth.DefaultOrg`; `httpx.ProblemRetry`; `config.OTPConfig`.
- HTTP: POST `/v1/verifications/{status,resend,verify-email,verify-mobile}` (public, handle in body), POST `/v1/password-reset/{start,complete}` (public), POST `/v1/me/verifications/{status,resend,verify-email,verify-mobile}` (client).
- DB: `00006_otp.sql`: `otp_verifications`, `otp_email_codes`, `otp_used_proofs`, `otp_limits`, `otp_daily_counts`; outbox `sensitive_payload` + erase trigger (`data-model.md`).

**Files to touch:** `apps/api/internal/otp/**`, `apps/api/internal/platform/{email,firebaseauth}/**`, `apps/api/internal/{outbox,auth}/` (additive), `apps/api/internal/platform/{httpx,config}/`, `apps/api/migrations/00006_otp.sql`, `apps/api/queries/{otp,outbox,outbox_admin}.sql`, `apps/api/cmd/swastik/{main,jobs}.go`, `apps/api/.golangci.yml`, `scripts/check-lint-boundaries.sh`, `packages/domain/src/otp-error-codes.ts`, `packages/api-client` (generated), `infra/bootstrap/{secrets,test}.sh`, `infra/tofu/modules/env/*`, `docs/engineering/runbook.md`.

**Depends on:** 003 (users, FR-051/053, audit, crypto), 002 (outbox: quiet-hours exemption, expiry, withdraw), `fix/postgres-17-compat` (uuidv7 on PG 17); see `docs/engineering/codemap.md`.

**Owner gates:** migration 00006 (G-MIG), outbox change + ADR 0003 Am. 2 (G-OUTBOX), secrets `RESEND_API_KEY`, `OTP_HMAC_KEY` + `otp_enabled` (G-SECRETS), additive auth API (G-AUTH), PG17 fix merged (G-PG17).

**Risks and non-goals:** Resend 100/day shared cap; Firebase iPhone PWA spike and real-device SMS test before 024 (Q3); timing uniformity relies on the response floor. Non-goals: SMS sent by us, WhatsApp, passwordless login, admin reset, screens, SME, automated applying.
