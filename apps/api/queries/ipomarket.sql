-- IPO market data (feature 009). Every query filters by org_id. GMP and snapshot tables are
-- append-only; "effective" GMP entries are those no later entry corrects.

-- name: LockIPOMarket :exec
SELECT pg_advisory_xact_lock(hashtextextended('ipomarket:' || @ipo_id::text, 0));

-- name: InsertGMPEntry :one
INSERT INTO ipo_gmp_entries (org_id, ipo_id, gmp_paise, note, corrects_entry_id, source,
                             actor_kind, actor_id, idempotency_key, request_hash, recorded_at)
VALUES (@org_id, @ipo_id, @gmp_paise, @note, @corrects_entry_id, @source,
        @actor_kind, @actor_id, @idempotency_key, @request_hash, @recorded_at)
RETURNING *;

-- name: FindGMPByIdemKey :one
SELECT * FROM ipo_gmp_entries
WHERE org_id = @org_id AND ipo_id = @ipo_id AND idempotency_key = @idempotency_key;

-- name: CurrentGMP :one
SELECT e.* FROM ipo_gmp_entries e
WHERE e.org_id = @org_id AND e.ipo_id = @ipo_id
  AND NOT EXISTS (SELECT 1 FROM ipo_gmp_entries c WHERE c.corrects_entry_id = e.id)
ORDER BY e.recorded_at DESC, e.id DESC
LIMIT 1;

-- name: IsGMPCorrected :one
SELECT EXISTS (SELECT 1 FROM ipo_gmp_entries c
               WHERE c.org_id = @org_id AND c.corrects_entry_id = @entry_id) AS corrected;

-- name: ListGMPHistory :many
SELECT e.*, c.id AS corrected_by_entry_id
FROM ipo_gmp_entries e
LEFT JOIN ipo_gmp_entries c ON c.corrects_entry_id = e.id
WHERE e.org_id = @org_id AND e.ipo_id = @ipo_id
  AND (NOT @cursor_set::boolean OR (e.recorded_at, e.id) < (@cursor_at::timestamptz, @cursor_id::uuid))
ORDER BY e.recorded_at DESC, e.id DESC
LIMIT @row_limit;

-- name: ListGMPTrend :many
SELECT * FROM (
    SELECT e.* FROM ipo_gmp_entries e
    WHERE e.org_id = @org_id AND e.ipo_id = @ipo_id
      AND NOT EXISTS (SELECT 1 FROM ipo_gmp_entries c WHERE c.corrects_entry_id = e.id)
    ORDER BY e.recorded_at DESC, e.id DESC
    LIMIT 500
) newest
ORDER BY recorded_at, id;

-- name: CurrentGMPBatch :many
SELECT DISTINCT ON (e.ipo_id) e.*
FROM ipo_gmp_entries e
WHERE e.org_id = @org_id AND e.ipo_id = ANY(@ids::uuid[])
  AND NOT EXISTS (SELECT 1 FROM ipo_gmp_entries c WHERE c.corrects_entry_id = e.id)
ORDER BY e.ipo_id, e.recorded_at DESC, e.id DESC;

-- name: InsertSubscription :one
INSERT INTO ipo_subscription_snapshots (org_id, ipo_id, as_of, total_x100, qib_x100, nii_x100, bnii_x100,
                                        snii_x100, retail_x100, employee_x100, source, actor_kind, actor_id,
                                        idempotency_key, request_hash, recorded_at)
VALUES (@org_id, @ipo_id, @as_of, @total_x100, @qib_x100, @nii_x100, @bnii_x100,
        @snii_x100, @retail_x100, @employee_x100, @source, @actor_kind, @actor_id,
        @idempotency_key, @request_hash, @recorded_at)
RETURNING *;

-- name: FindSubscriptionByIdemKey :one
SELECT * FROM ipo_subscription_snapshots
WHERE org_id = @org_id AND ipo_id = @ipo_id AND idempotency_key = @idempotency_key;

-- name: CurrentSubscription :one
SELECT * FROM ipo_subscription_snapshots
WHERE org_id = @org_id AND ipo_id = @ipo_id
ORDER BY as_of DESC, recorded_at DESC, id DESC
LIMIT 1;

-- name: CurrentSubscriptionBatch :many
SELECT DISTINCT ON (ipo_id) *
FROM ipo_subscription_snapshots
WHERE org_id = @org_id AND ipo_id = ANY(@ids::uuid[])
ORDER BY ipo_id, as_of DESC, recorded_at DESC, id DESC;

-- name: ListSubscriptionHistory :many
SELECT * FROM ipo_subscription_snapshots
WHERE org_id = @org_id AND ipo_id = @ipo_id
  AND (NOT @cursor_set::boolean
       OR (as_of, recorded_at, id) < (@cursor_as_of::timestamptz, @cursor_recorded_at::timestamptz, @cursor_id::uuid))
ORDER BY as_of DESC, recorded_at DESC, id DESC
LIMIT @row_limit;
