# Data model: 009 GMP, expected profit and subscription snapshots

Migration `apps/api/migrations/00005_ipo_market.sql` (expand-only: two new tables, two triggers using the existing `forbid_mutation()` from `00001_platform.sql`). Rules: `.claude/rules/sql.md`. Instants come from the injected app clock, never `now()` in business logic.

## 1. `ipo_gmp_entries` (append-only)

| Column | Type | Constraint |
|---|---|---|
| `id` | uuid | PK, `DEFAULT uuidv7()` |
| `org_id` | uuid | NOT NULL, FK `orgs(id)` |
| `ipo_id` | uuid | NOT NULL, FK `ipos(id)` (RESTRICT; ever-published IPOs cannot be deleted anyway, 008 trigger) |
| `gmp_paise` | bigint | NOT NULL, `CHECK (gmp_paise BETWEEN -1000000000 AND 1000000000)` |
| `note` | text | NULL, `CHECK (char_length(btrim(note)) BETWEEN 1 AND 200)` |
| `corrects_entry_id` | uuid | NULL, `UNIQUE`, `CHECK (corrects_entry_id <> id)`; composite FK `(ipo_id, corrects_entry_id) → ipo_gmp_entries(ipo_id, id)` so a correction stays inside one IPO |
| `source` | text | NOT NULL DEFAULT `'manual'`, `CHECK (source = 'manual' OR source ~ '^import:[a-z0-9_]{1,32}$')` |
| `actor_kind` | text | NOT NULL, `CHECK (actor_kind IN ('admin','system'))` |
| `actor_id` | uuid | NULL; `CHECK ((actor_kind = 'admin') = (actor_id IS NOT NULL))` |
| `idempotency_key` | text | NULL, `CHECK (char_length(idempotency_key) BETWEEN 8 AND 200)` |
| `request_hash` | text | NULL, `CHECK (request_hash ~ '^[0-9a-f]{64}$')`; `CHECK ((idempotency_key IS NULL) = (request_hash IS NULL))` |
| `recorded_at` | timestamptz | NOT NULL (app clock) |

Indexes:

- `UNIQUE (ipo_id, id)` — target of the composite self-FK.
- `ipo_gmp_entries_ipo_idx (org_id, ipo_id, recorded_at DESC, id DESC)` — current value, history pages, trend, batch `DISTINCT ON`.
- `ipo_gmp_entries_idem_uq UNIQUE (org_id, ipo_id, idempotency_key) WHERE idempotency_key IS NOT NULL`.
- The `UNIQUE (corrects_entry_id)` constraint also serves the "is corrected" anti-join.

Trigger: `ipo_gmp_entries_append_only BEFORE UPDATE OR DELETE ... EXECUTE FUNCTION forbid_mutation()`.

Derived (never stored):

- **effective** = no row has `corrects_entry_id = id`.
- **current** = effective row with the greatest `(recorded_at, id)`.
- **expected profit per lot** = `gmp_paise × ipos.lot_size` (Go `int64`, computed in `ExpectedProfitPerLot`; bounds give |x| ≤ 10^15).

## 2. `ipo_subscription_snapshots` (append-only)

| Column | Type | Constraint |
|---|---|---|
| `id` | uuid | PK, `DEFAULT uuidv7()` |
| `org_id`, `ipo_id` | uuid | NOT NULL, FKs as above |
| `as_of` | timestamptz | NOT NULL (validated in Go: ≤ now + 5 min, ≥ open date 00:00 IST) |
| `total_x100` | integer | NOT NULL, `CHECK (total_x100 BETWEEN 0 AND 10000000)` |
| `qib_x100`, `nii_x100`, `bnii_x100`, `snii_x100`, `retail_x100`, `employee_x100` | integer | NULL, same CHECK range |
| `source`, `actor_kind`, `actor_id`, `idempotency_key`, `request_hash`, `recorded_at` | | as in §1 |

`x100` = times subscribed × 100 (12.34× → 1234). Never a float in storage or on the wire.

Indexes: `ipo_subscription_ipo_idx (org_id, ipo_id, as_of DESC, recorded_at DESC, id DESC)`; `ipo_subscription_idem_uq UNIQUE (org_id, ipo_id, idempotency_key) WHERE idempotency_key IS NOT NULL`. Trigger as in §1.

**current** = greatest `(as_of, recorded_at, id)`.

## 3. Serialisation and idempotency

Every write runs in one transaction (`db.TxRunner.InTx`):

1. `ipos.Service.Get` (008 public API): org check, `FirstPublishedAt`, `Status`, `LotSize`, prices. No read of the `ipos` table from this module.
2. `SELECT pg_advisory_xact_lock(hashtextextended('ipomarket:' || @ipo_id::text, 0))` — serialises writes per IPO (correction "latest only" check, idempotency lookup).
3. Idempotency lookup by `(org_id, ipo_id, idempotency_key)` in the table of the action: same `request_hash` → replay the stored row; different → 422.
4. Validate (status, published, correction target is current and not corrected, values) → insert → `audit.Write` → commit.

Request hash = SHA-256 of the canonical request (action, ipo id, body fields), as in 008.

## 4. Audit entries (`audit_log`, entity `ipo`, entity_id = IPO id)

| action | after |
|---|---|
| `ipo.gmp_recorded` | `{entry_id, gmp_paise, corrects_entry_id, note, source, idempotency_key, request_hash}` |
| `ipo.subscription_recorded` | `{snapshot_id, as_of, total_x100, qib_x100, nii_x100, bnii_x100, snii_x100, retail_x100, employee_x100, source, idempotency_key, request_hash}` |

## 5. Queries (`apps/api/queries/ipomarket.sql`)

`LockIPOMarket :exec`, `InsertGMPEntry :one`, `FindGMPByIdemKey :one`, `CurrentGMP :one`, `IsGMPCorrected :one`, `ListGMPHistory :many` (keyset `(recorded_at, id)`), `ListGMPTrend :many` (effective only, ascending, limit 500), `CurrentGMPBatch :many` (`DISTINCT ON (ipo_id)` over effective rows, `ipo_id = ANY(@ids)`), `InsertSubscription :one`, `FindSubscriptionByIdemKey :one`, `CurrentSubscription :one`, `CurrentSubscriptionBatch :many`, `ListSubscriptionHistory :many`.

Published filtering and lot sizes for batch ids come from one call to the new additive 008 read `ipos.Service.GetMany` (query `GetIPOsByIDs`: `WHERE org_id = @org_id AND id = ANY(@ids)`, in `queries/ipos.sql`), so this module never joins or reads the `ipos` table.
