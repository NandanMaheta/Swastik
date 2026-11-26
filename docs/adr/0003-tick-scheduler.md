# ADR 0003: Tick-driven scheduler on scale-to-zero hosting

- Status: Accepted (2026-11-13)

## Context

Reminders every 1–2 hours, status changes by IPO dates, due dates and overdue escalation — on Cloud Run, which scales to zero, at ₹0/month.

## Decision

Cloud Scheduler calls `POST /internal/tick` every 5 minutes (authenticated with an OIDC token). Each tick claims due rows from `scheduled_jobs` with `FOR UPDATE SKIP LOCKED` and runs them idempotently. Notifications are written to an outbox table in the same transaction as the change that causes them. Business logic receives an injected clock.

## Consequences

±5 minute precision (acceptable). No Redis or always-on worker. The tick keeps the Supabase free project active. If we move to an always-on VM, River can replace the job table without changing module code.

## Amendment 1 (2026-11-13, feature 002): implementation choices

Status of the amendment: Proposed in `specs/002-scheduler-tick/plan.md`; takes effect when the owner approves that plan. It refines the decision above and does not reverse it.

- **Job table, not River.** `scheduled_jobs` is an in-repo table. Each tick claims one due row at a time with `FOR UPDATE SKIP LOCKED` in a short transaction that sets a lease (`locked_until`) and a fencing token (`lock_token`). The handler's database effects and the "done" mark are committed in one transaction guarded by the token, so a job that lost its lease cannot commit a second effect. River v0.51.x was evaluated and deferred: it brings its own migration set, long-lived worker goroutines and LISTEN/NOTIFY session connections, none of which fit request-scoped CPU on a scale-to-zero service. Modules only use `scheduler.Schedule/Reschedule/Cancel` and `scheduler.Register`, so swapping the engine later stays local to `internal/scheduler`.
- **Outbox.** `outbox_messages` is written in the caller's transaction (`outbox.Add`) and relayed by the same tick after the jobs phase, through per-topic `Sender`s. Delivery is at-least-once; the de-duplication key travels to the sender.
- **Tick authentication.** The Cloud Run service stays publicly invokable (the client API must be reachable); `/internal/tick` is protected in the application by verifying the Google-signed OIDC ID token (issuer, audience, expiry, signature against Google's JWKS) and the caller's service-account email. Library: `github.com/coreos/go-oidc/v3` (subject to owner approval as a new runtime dependency). A shared-token "dev" mode exists for `APP_ENV=local|ci` only; the service refuses to start with it in staging or production.
- **Time.** Every scheduling comparison uses a `now` passed from the injected Go clock; SQL `now()` is never used for scheduling decisions.
- **Pooler.** Assumes the Supabase session pooler (port 5432), so pgx prepared statements stay on. Session-level advisory locks and LISTEN/NOTIFY are not used, so a later move to the transaction pooler only needs a pgx exec-mode change in `platform/db`.
- `scheduled_jobs`, `outbox_messages`, `tick_runs` and `quiet_hours` are mutable operational tables and do not get `forbid_mutation()` (owner decision, spec 002 Clarifications). Admin actions on them write `audit_log`.

## Amendment 2 (2026-11-26, feature 004): sensitive payloads and immediate delivery

Status of the amendment: Proposed in `specs/004-otp-delivery/plan.md`; takes effect when the owner approves that plan (owner decisions Q1 and Q2 of the 004 spec). It extends Amendment 1 and reverses nothing.

- **Sensitive payloads.** A message may be recorded with `SensitivePayload` (column `outbox_messages.sensitive_payload`). Its payload must already be encrypted by the owning feature (PII key ring); a database trigger replaces it with `{}` as soon as the message reaches `sent`, `dead`, `withdrawn` or `expired`, and a CHECK keeps it that way. Admins cannot retry such a message after it died (its content is gone). First user: 004 one-time codes.
- **Expiry is final.** A message past `expires_at` is never handed to a sender, including one whose send lease ran out (the expiry sweep now also covers stale `sending` rows).
- **Immediate delivery.** `outbox.DeliverNow(org, topic, key)` lets a request deliver its own just-committed message with the same fenced claim, timeout and failure bookkeeping as the tick relay. Reason: Cloud Run throttles CPU outside requests (`cpu_idle`) and the tick runs every 5 minutes, which is too slow for a 10-minute code (004 SC-002). If immediate delivery fails, the normal tick relay retries. Delivery remains at-least-once with the dedupe key as the provider idempotency key.
- Quiet-hours exemption per message already existed (`ExemptFromQuietHours`); 004's code emails use it (owner decision Q1).
