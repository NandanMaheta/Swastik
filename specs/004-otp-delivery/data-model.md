# Data model: 004 OTP delivery

Migration `apps/api/migrations/00005_otp.sql` (expand-only; owner gate). Queries: `apps/api/queries/otp.sql` (new) and `apps/api/queries/outbox.sql` (edited, section 6). Times are written from the injected clock via `@now` parameters; `now()` defaults are only a safety net. PostgreSQL 17 in staging/production: `DEFAULT uuidv7()` relies on the function added by `fix/postgres-17-compat` (must merge first; see plan gate G-PG17).

The `otp_*` tables are mutable operational tables owned by `internal/otp` (no `forbid_mutation()`); every business event is recorded in the existing append-only `audit_log`. No other module reads them (constitution IV).

## 1. `otp_verifications`

One verification flow for one user and purpose. Interpretation I-1 (plan): spec FR-001's "sign-up email" and "sign-up mobile" are the two contacts of one `signup` verification, which is what the spec's Key Entities ("state per contact") and US3.1 ("a sign-up verification with email verified") describe.

| Column | Type | Rule |
|---|---|---|
| `id` | uuid PK `DEFAULT uuidv7()` | |
| `org_id` | uuid NOT NULL FK `orgs` | |
| `user_id` | uuid FK `users` | NULL only for a password-reset decoy (D-06/D-07, section 7) |
| `purpose` | text NOT NULL | CHECK IN (`signup`, `change_email`, `change_mobile`, `password_reset`) |
| `handle_hash` | bytea NOT NULL UNIQUE | SHA-256 of the opaque handle `ovh_…` (`crypto.NewToken`); 32 bytes |
| `email` | text | target email; same normalisation CHECK as `users.email` |
| `mobile` | text | target mobile; CHECK `^\+91[6-9][0-9]{9}$` |
| `email_done_at` | timestamptz | signup: verified; change_email: proved; reset: code accepted |
| `mobile_done_at` | timestamptz | signup: verified; change_mobile: proved |
| `reset_token_hash` | bytea | SHA-256 of `prt_…` one-time permission (FR-008); 32 bytes |
| `reset_token_expires_at` | timestamptz | `email_done_at + 10 min` |
| `finished_at` | timestamptz | all contacts done (signup, change) or reset completed |
| `cancelled_at`, `cancel_reason` | timestamptz, text | reason CHECK IN (`cancelled`, `superseded`) |
| `created_at`, `expires_at`, `updated_at` | timestamptz NOT NULL | `expires_at = created_at + 24 h` (FR-001) |

Constraints:
- `otp_verifications_targets_ck`: signup ⇒ user, email and mobile set; change_email ⇒ user and email set, mobile NULL; change_mobile ⇒ user and mobile set, email NULL; password_reset ⇒ mobile NULL and `(user_id IS NULL) = (email IS NULL)`.
- `…_reset_only_ck`: `reset_token_*` NULL unless purpose = password_reset; `(reset_token_hash IS NULL) = (reset_token_expires_at IS NULL)`.
- `…_done_ck`: `email_done_at` requires `email`; `mobile_done_at` requires `mobile`.
- `…_cancel_ck`: `(cancelled_at IS NULL) = (cancel_reason IS NULL)`; `NOT (cancelled_at IS NOT NULL AND finished_at IS NOT NULL)`.
- `…_expiry_ck`: `expires_at > created_at`.

Indexes: `otp_verifications_open_uq` UNIQUE (`user_id`, `purpose`) WHERE `user_id IS NOT NULL AND cancelled_at IS NULL AND finished_at IS NULL` (one live flow per user and purpose; `Start` supersedes the previous one in the same transaction); `otp_verifications_expires_idx` (`expires_at`) for housekeeping.

State (derived, never stored): `cancelled` if `cancelled_at`; else `completed` if `finished_at`; else `expired` if `now ≥ expires_at`; else `open`. Per contact: `done` (`verified` for signup, `proved` for change), `pending`, or `expired` with the verification.

## 2. `otp_email_codes`

| Column | Type | Rule |
|---|---|---|
| `id` | uuid PK `DEFAULT uuidv7()` | code id, bound into the digest |
| `org_id` | uuid NOT NULL FK `orgs` | |
| `verification_id` | uuid NOT NULL FK `otp_verifications` ON DELETE CASCADE | |
| `code_digest` | bytea NOT NULL | `HMAC-SHA-256(OTP_HMAC_KEY, "otp.code" ‖ 0x00 ‖ purpose ‖ "|" ‖ verification_id ‖ "|" ‖ code_id ‖ "|" ‖ code)` via `crypto.BlindIndexer`; 32 bytes (D-08) |
| `issued_at`, `expires_at` | timestamptz NOT NULL | `expires_at = issued_at + 10 min`; CHECK `expires_at > issued_at` |
| `wrong_attempts` | smallint NOT NULL DEFAULT 0 | CHECK 0..5 (D-02) |
| `outbox_key` | text | dedupe key `otp:code:<id>`; NULL for decoys (no email) |
| `ended_at`, `end_reason` | timestamptz, text | reason CHECK IN (`used`, `superseded`, `used_up`, `cancelled`); `(ended_at IS NULL) = (end_reason IS NULL)` |

Indexes: `otp_email_codes_live_uq` UNIQUE (`verification_id`) WHERE `ended_at IS NULL` (one live code; a newer code supersedes, D-01). Codes are valid iff `ended_at IS NULL AND now < expires_at` (10:09:59 accepted, 10:10:00 refused). Verify locks the live row `FOR UPDATE` (single use under concurrency, US1.3).

## 3. `otp_used_proofs`

| Column | Type | Rule |
|---|---|---|
| `fingerprint` | bytea PK | `HMAC(OTP_HMAC_KEY, "otp.proof", sub ‖ "|" ‖ auth_time)`; 32 bytes; one Firebase sign-in proves once (FR-005) |
| `org_id` | uuid NOT NULL FK `orgs` | |
| `verification_id` | uuid NOT NULL FK `otp_verifications` ON DELETE CASCADE | |
| `used_at` | timestamptz NOT NULL | |

Inserted in the success transaction with `ON CONFLICT DO NOTHING`; zero rows ⇒ `replayed_proof`. Only accepted proofs are recorded.

## 4. `otp_limits` (durable send/check limits, D-03, FR-004)

| Column | Type | Rule |
|---|---|---|
| `org_id` | uuid NOT NULL FK `orgs` | |
| `scope` | text NOT NULL | CHECK IN (`send_contact`, `send_user`, `send_ip`, `check_ip`) |
| `subject` | bytea NOT NULL | `HMAC(OTP_HMAC_KEY, "otp.limit", scope ‖ "|" ‖ key)`; 32 bytes; key = normalised contact, user id or client IP (never stored readable) |
| `events` | timestamptz[] NOT NULL DEFAULT '{}' | CHECK `cardinality(events) <= 60`; accepted events only, oldest first |
| `updated_at` | timestamptz NOT NULL | |

PK (`org_id`, `scope`, `subject`); index (`updated_at`) for housekeeping. No FK to users: unknown identifiers need rows too (as `auth_throttles`). Rows are locked `INSERT … ON CONFLICT DO NOTHING` + `SELECT … FOR UPDATE`, in a fixed scope order (contact, user, ip) to avoid deadlocks.

Policies (pure `otp.ApplyLimits`, property-tested):

| Scope | Window | Limit | Also |
|---|---|---|---|
| `send_contact` | rolling 1 h | 5 | cooldown: refused while `now < last + 60 s` (D-02) |
| `send_contact` | IST day (resets 00:00 IST) | 10 | same row |
| `send_user` | IST day | 10 | known users only |
| `send_ip` | rolling 1 h | 20 | |
| `check_ip` | rolling 1 h | 60 | verify-email, verify-mobile, reset-complete |

Rolling windows count events with `now − e < window`. `retry_after` = cooldown end, `oldest counted + window`, or next 00:00 IST, whichever refusal applies (largest wins). A refused request adds no event. Events older than both windows are dropped on write.

## 5. `otp_daily_counts` (FR-017, no identifiers)

PK (`org_id`, `day` date IST, `metric`); `metric` CHECK IN (`email_sent`, `email_failed`, `limit_refused`, `proof_accepted`, `proof_refused`); `count` int NOT NULL CHECK ≥ 0. Upsert-increment. `email_*` are written by the otp Sender in its own short transaction after the provider call (best effort, logged on failure); the others in the request transaction.

## 6. Outbox change (002 tables; ADR 0003 Amendment 2; owner gate)

- `ALTER TABLE outbox_messages ADD COLUMN sensitive_payload boolean NOT NULL DEFAULT false` (old app versions never set it).
- Trigger `outbox_erase_sensitive_payload` BEFORE INSERT OR UPDATE OF `status`: when `NEW.sensitive_payload AND NEW.status IN ('sent','dead','withdrawn','expired')` set `NEW.payload = '{}'`. Covers every terminal path (relay, withdraw by key/subject, expiry sweep, admin cancel) without editing those queries.
- CHECK `outbox_messages_sensitive_erased_ck`: `NOT sensitive_payload OR status IN ('pending','sending') OR payload = '{}'::jsonb`.
- Query edits: `InsertMessage` takes `sensitive_payload`; `ExpireDueMessages` also expires `sending` rows whose lease ran out and whose `expires_at <= @now`; `ClaimMessage`'s lease-takeover branch requires `expires_at IS NULL OR expires_at > @now` (an expired code is never sent); `AdminRetryMessage` excludes `sensitive_payload` rows (payload gone → `ErrConflict`); new `ClaimMessageByKey` (same claim as `ClaimMessage` for one `org, topic, dedupe_key`, `FOR UPDATE SKIP LOCKED`) for `DeliverNow`.
- Down migration drops trigger, function, CHECK and column.

## 7. Decoys (D-06, D-07)

`StartReset` with an unknown identifier, or a user who is not an `active` client, inserts a `password_reset` verification with `user_id`, `email` NULL and a live code whose digest covers a random code nobody receives (`outbox_key` NULL). Status, resend and verify then run the same statements and limits as for a real account; verify always ends in `wrong_code`/`used_up`. No audit entry and no email for decoys (003 FR-091). Purged like any verification.

## 8. Housekeeping (FR-015)

Recurring job `otp.housekeeping` daily at 03:15 IST (`scheduler.KindOptions{Recurring: otp.HousekeepingNext}`), bounded batches of 5,000:
- delete verifications with `expires_at < now − 24 h` (codes and proofs cascade);
- delete `otp_used_proofs` older than 24 h;
- delete `otp_limits` with `updated_at < now − 48 h`;
- delete `otp_daily_counts` older than 400 days.
Audit rows are never touched; one `otp.housekeeping.purged` audit entry with counts (actor system).

## 9. Audit entries (US6, FR-010)

Entity `user`, entity id = user id, actor = the client (system for housekeeping, the calling feature's actor for `Start`/`Cancel`/notice). `After` = `{verification_id, purpose, outcome, reason?, ip?}`; never a contact, code, handle, token or proof. Actions: `otp.verification.started`, `otp.code.issued` (first and resend), `otp.send.refused` (`cooldown`, `rate_limited`), `otp.email.verified`, `otp.mobile.verified`, `otp.contact.proved`, `otp.check.failed` (`wrong_code`, `expired`, `used_up`, `number_mismatch`, `stale_proof`, `replayed_proof`, `contact_unavailable`, `rate_limited`), `otp.reset.code_accepted`, `otp.reset.completed`, `otp.verification.cancelled`, `otp.notice.queued`, `otp.housekeeping.purged`. Decoys and unmatched identifiers write nothing.
