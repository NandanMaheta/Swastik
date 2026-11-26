# Brief: 004 OTP delivery  ·  Tier A

<!-- One page maximum. Draft from the spec step; the architect completes Public surface and Files to touch with the plan. -->

**Goal (2–3 lines):** Prove a client controls an email (6-digit code by email via the outbox relay and Resend) or a mobile (Firebase phone sign-in proof checked by the API), with resend cooldown, attempt limits and rate limits, for sign-up (005), contact changes (007), forgot password and the client app (024).

**Business rules:** BR-CLI-04, BR-CLI-05 ([business-rules](../../docs/product/business-rules.md)); golden scenarios affected: none (GS-01…04 must keep passing).

**Acceptance criteria (IDs from spec.md):**
- US1 sign-up email code: issue, 10-min expiry, single use, 5 wrong entries (D-01, D-02)
- US2 resend: 60 s cooldown, per contact/user/address limits, quiet-hours bypass (D-03, Q1)
- US3 mobile via Firebase proof: fresh, unused, our project, same number, email first (D-04, D-05)
- US4 forgot password: code to account email, uniform replies, reset ends all sessions (D-06, D-07)
- US5 change-contact proof for 007, no account change until approval (D-09)
- US6 audit without contacts, codes or proofs (D-08)

**Public surface:** (plan to fill) service: start / status / cancel verification, old-contact notice; HTTP: status, resend, verify email, verify mobile, start/complete password reset (spec "Capabilities offered").

**Files to touch:** (plan to fill) `apps/api/internal/...`, migration, queries, `packages/domain` error codes, `infra/bootstrap/secrets.sh` + tofu secret names.

**Depends on:** 003 (users, FR-051/053/055, throttles, audit, crypto), 002 (outbox relay: exemption, expiry, withdraw); see `docs/engineering/codemap.md`.

**Risks and non-goals:** Owner questions Q1–Q3 in spec.md; Resend 100/day shared cap; Firebase iPhone PWA spike before 024; new secrets `RESEND_API_KEY`, `OTP_HMAC_KEY`. Non-goals: SMS sent by us, WhatsApp, passwordless login, admin reset, SME, automated applying.
