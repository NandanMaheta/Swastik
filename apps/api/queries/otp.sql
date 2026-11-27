-- OTP delivery queries (feature 004). Every statement filters by org_id; every instant is a
-- parameter taken from the injected clock (an empty limit row is created at the epoch, so the
-- purge treats it as garbage until it is saved).

-- name: InsertOtpVerification :one
INSERT INTO otp_verifications (org_id, user_id, purpose, handle_hash, email, mobile, created_at, expires_at, updated_at)
VALUES (@org_id, sqlc.narg('user_id'), @purpose, @handle_hash, sqlc.narg('email'), sqlc.narg('mobile'), @now, @expires_at, @now)
RETURNING *;

-- name: GetOtpVerification :one
SELECT * FROM otp_verifications WHERE id = @id AND org_id = @org_id;

-- name: GetOtpVerificationByHandle :one
SELECT * FROM otp_verifications WHERE org_id = @org_id AND handle_hash = @handle_hash;

-- name: LockOtpVerificationByHandle :one
SELECT * FROM otp_verifications WHERE org_id = @org_id AND handle_hash = @handle_hash FOR UPDATE;

-- name: LockOtpVerification :one
SELECT * FROM otp_verifications WHERE id = @id AND org_id = @org_id FOR UPDATE;

-- name: LockOpenOtpVerification :one
SELECT * FROM otp_verifications
WHERE org_id = @org_id AND user_id = @user_id AND purpose = @purpose AND cancelled_at IS NULL AND finished_at IS NULL
FOR UPDATE;

-- The first instant is kept when the contact is already done.
-- name: MarkOtpEmailDone :execrows
UPDATE otp_verifications SET email_done_at = COALESCE(email_done_at, @now), updated_at = @now
WHERE id = @id AND org_id = @org_id;

-- name: MarkOtpMobileDone :execrows
UPDATE otp_verifications SET mobile_done_at = COALESCE(mobile_done_at, @now), updated_at = @now
WHERE id = @id AND org_id = @org_id;

-- name: FinishOtpVerification :execrows
UPDATE otp_verifications SET finished_at = @now, updated_at = @now
WHERE id = @id AND org_id = @org_id AND cancelled_at IS NULL AND finished_at IS NULL;

-- name: CancelOtpVerification :execrows
UPDATE otp_verifications SET cancelled_at = @now, cancel_reason = @reason, updated_at = @now
WHERE id = @id AND org_id = @org_id AND cancelled_at IS NULL AND finished_at IS NULL;

-- name: SetOtpResetGrant :execrows
UPDATE otp_verifications SET reset_token_hash = @token_hash, reset_token_expires_at = @token_expires_at, updated_at = @now
WHERE id = @id AND org_id = @org_id;

-- name: InsertOtpCode :one
INSERT INTO otp_email_codes (id, org_id, verification_id, code_digest, issued_at, expires_at, outbox_key)
VALUES (@id, @org_id, @verification_id, @code_digest, @issued_at, @expires_at, sqlc.narg('outbox_key'))
RETURNING *;

-- name: GetLiveOtpCode :one
SELECT * FROM otp_email_codes
WHERE org_id = @org_id AND verification_id = @verification_id AND ended_at IS NULL;

-- name: LockLiveOtpCode :one
SELECT * FROM otp_email_codes
WHERE org_id = @org_id AND verification_id = @verification_id AND ended_at IS NULL
FOR UPDATE;

-- name: EndLiveOtpCode :one
UPDATE otp_email_codes SET ended_at = @now, end_reason = @reason
WHERE org_id = @org_id AND verification_id = @verification_id AND ended_at IS NULL
RETURNING *;

-- The counter never passes the limit of 5 (the row CHECK); a full or ended code is "no live code".
-- name: AddOtpWrongAttempt :one
UPDATE otp_email_codes SET wrong_attempts = wrong_attempts + 1
WHERE id = @id AND org_id = @org_id AND ended_at IS NULL AND wrong_attempts < @max_attempts::smallint
RETURNING wrong_attempts;

-- name: InsertOtpProof :execrows
INSERT INTO otp_used_proofs (fingerprint, org_id, verification_id, used_at)
VALUES (@fingerprint, @org_id, @verification_id, @now)
ON CONFLICT (fingerprint) DO NOTHING;

-- name: EnsureOtpLimit :exec
INSERT INTO otp_limits (org_id, scope, subject, updated_at)
VALUES (@org_id, @scope, @subject, to_timestamp(0))
ON CONFLICT (org_id, scope, subject) DO NOTHING;

-- name: LockOtpLimit :one
SELECT * FROM otp_limits WHERE org_id = @org_id AND scope = @scope AND subject = @subject FOR UPDATE;

-- name: SaveOtpLimit :execrows
UPDATE otp_limits SET events = @events::timestamptz[], updated_at = @now
WHERE org_id = @org_id AND scope = @scope AND subject = @subject;

-- name: IncrementOtpCount :exec
INSERT INTO otp_daily_counts (org_id, day, metric, count)
VALUES (@org_id, @day::date, @metric, 1)
ON CONFLICT (org_id, day, metric) DO UPDATE SET count = otp_daily_counts.count + 1;

-- name: GetOtpCounts :many
SELECT metric, count FROM otp_daily_counts WHERE org_id = @org_id AND day = @day::date;

-- Purges: bounded batches, oldest first (FR-015).
-- name: PurgeOtpVerifications :execrows
DELETE FROM otp_verifications
WHERE id IN (
    SELECT v.id FROM otp_verifications v
    WHERE v.org_id = @org_id AND v.expires_at < @cutoff
    ORDER BY v.expires_at, v.id
    LIMIT @row_limit
);

-- name: PurgeOtpProofs :execrows
DELETE FROM otp_used_proofs
WHERE fingerprint IN (
    SELECT p.fingerprint FROM otp_used_proofs p
    WHERE p.org_id = @org_id AND p.used_at < @cutoff
    ORDER BY p.used_at
    LIMIT @row_limit
);

-- name: PurgeOtpLimits :execrows
DELETE FROM otp_limits l
USING (
    SELECT o.org_id, o.scope, o.subject FROM otp_limits o
    WHERE o.org_id = @org_id AND o.updated_at < @cutoff
    ORDER BY o.updated_at
    LIMIT @row_limit
) d
WHERE l.org_id = d.org_id AND l.scope = d.scope AND l.subject = d.subject;

-- name: PurgeOtpCounts :execrows
DELETE FROM otp_daily_counts c
USING (
    SELECT o.org_id, o.day, o.metric FROM otp_daily_counts o
    WHERE o.org_id = @org_id AND o.day < @cutoff::date
    ORDER BY o.day
    LIMIT @row_limit
) d
WHERE c.org_id = d.org_id AND c.day = d.day AND c.metric = d.metric;
