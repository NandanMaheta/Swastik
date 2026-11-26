# HTTP contract: 009 `ipomarket` (OpenAPI diff)

All operations are added to the generated OpenAPI 3.1 document (tag `ipomarket`); nothing existing changes, so oasdiff reports additions only. Errors are RFC 9457 in 008's format (`specs/008-ipo-catalogue/contracts/error-codes.md`): stable `code`, `type = urn:swastik:problem:<code>`, `errors[]` of `{location, message}`. Money fields end in `_paise` (int64), multiples in `_x100` (int32), instants are RFC 3339 `date-time` (UTC on the wire, shown in IST by clients).

## Operations

| operationId | Method + path | Security | Request | Success |
|---|---|---|---|---|
| `ipomarket-record-gmp` | `POST /v1/admin/ipos/{ipoId}/gmp` | `authz.Require(admin)` | header `Idempotency-Key` (optional, 8–200, `^[A-Za-z0-9._:-]+$`); body `GMPEntryInput` | 201 `GMPRecordResult` (200 on replay) |
| `ipomarket-list-gmp` | `GET /v1/admin/ipos/{ipoId}/gmp` | admin | query `cursor`, `limit` 1–200 (default 50) | 200 `AdminGMPPage` |
| `ipomarket-record-subscription` | `POST /v1/admin/ipos/{ipoId}/subscription` | admin | `Idempotency-Key`; body `SubscriptionInput` | 201 `SubscriptionRecordResult` (200 on replay) |
| `ipomarket-list-subscription` | `GET /v1/admin/ipos/{ipoId}/subscription` | admin | `cursor`, `limit` | 200 `AdminSubscriptionPage` |
| `ipomarket-admin-summaries` | `GET /v1/admin/ipos/market?ipo_ids=a,b` | admin | `ipo_ids` 1–200 uuids, comma-separated | 200 `{items: MarketSummary[]}` (drafts included) |
| `ipomarket-get` | `GET /v1/ipos/{ipoId}/market` | `authz.Require()` (any signed-in user) | — | 200 `ClientMarketView` |
| `ipomarket-summaries` | `GET /v1/ipos/market?ipo_ids=a,b` | any signed-in user | `ipo_ids` 1–200 | 200 `{items: MarketSummary[]}` (published only; others omitted) |

The literal `/market` segment does not clash with `{ipoId}` (Go 1.22 mux picks the more specific pattern, as 008 does with `date-suggestions`).

## Schemas

```text
GMPEntryInput      { gmp_paise: int64 [-1e9, 1e9], note?: string 1..200, corrects_entry_id?: uuid }
SubscriptionInput  { as_of: date-time, total_x100: int32 [0, 1e7],
                     qib_x100?, nii_x100?, bnii_x100?, snii_x100?, retail_x100?, employee_x100?: int32 [0, 1e7] }

CurrentGMP         { gmp_paise: int64, expected_profit_per_lot_paise: int64|null, lot_size: int32|null, updated_at: date-time }
Subscription       { as_of: date-time, total_x100, qib_x100|null, nii_x100|null, bnii_x100|null,
                     snii_x100|null, retail_x100|null, employee_x100|null }
TrendPoint         { gmp_paise: int64, expected_profit_per_lot_paise: int64|null, at: date-time }

AdminGMPEntry      { id, gmp_paise, expected_profit_per_lot_paise|null, note|null, corrects_entry_id|null,
                     corrected_by_entry_id|null, source, actor: {kind, id|null}, recorded_at }
AdminSubscription  Subscription + { id, source, actor: {kind, id|null}, recorded_at }
GMPRecordResult    { entry: AdminGMPEntry, current: CurrentGMP, warnings: Warning[] }
SubscriptionRecordResult { snapshot: AdminSubscription, current: Subscription }
AdminGMPPage / AdminSubscriptionPage { items: [...], next_cursor: string|null }

ClientMarketView   { ipo_id, current_gmp: CurrentGMP|null, trend: TrendPoint[] (effective, oldest first, ≤ 500),
                     subscription: Subscription|null }
MarketSummary      { ipo_id, current_gmp: CurrentGMP|null, subscription_total_x100: int32|null, subscription_as_of: date-time|null }
Warning            008's schema `{code, fields[], detail, params}` (reused, not redefined)
```

Client schemas have no `note`, `actor`, `source`, `corrects_entry_id` or idempotency fields (FR-014). `expected_profit_per_lot_paise` uses the IPO's current lot size (null when unset).

## Idempotency

`Idempotency-Key` on both POSTs, scoped per org + IPO + action. The service stores the key and a SHA-256 of the canonical request on the entry row. Same key + same request → 200 with the original entry and the *current* state, no new row, no audit. Same key + different request → 422 `ipomarket.idempotency_key_reused`. No key → every request is a new entry.

## Problem codes

| code | HTTP | When | Spec |
|---|---|---|---|
| `validation_failed` | 422 | Huma schema checks (types, ranges, lengths, uuid list size/format, bad cursor) | FR-001, FR-008 |
| `ipomarket.invalid_value` | 422 | Blank note after trim; `as_of` > now + 5 min or before open date 00:00 IST (duplicate ids in `ipo_ids` are de-duplicated, not an error) | FR-001, FR-008, US4.4 |
| `ipomarket.idempotency_key_reused` | 422 | See above | FR-010 |
| `ipomarket.not_published_yet` | 409 | IPO never published (Q3) | FR-006, US1.8 |
| `ipomarket.frozen` | 409 | IPO status LISTED or SETTLED | FR-006, US1.7 |
| `ipomarket.correction_not_latest` | 409 | `corrects_entry_id` unknown for this IPO, not the current effective entry, or already corrected | FR-005, US3.2 |
| `not_found` | 404 | Unknown IPO, other org; client `ipomarket-get` on an unpublished IPO (identical body) | FR-013, US2.3 |
| `auth.unauthenticated` / `auth.forbidden` | 401 / 403 | 003 middleware (client on admin operation) | FR-015 |
| `internal` | 500 | Unexpected | — |

## Warnings

| code | When | params |
|---|---|---|
| `ipomarket.gmp_exceeds_price` | `abs(gmp_paise)` > issue price, else band cap (no warning when both unknown) | `gmp_paise`, `price_paise` |

Codes are mirrored in `packages/domain/src/ipo-market.ts` (`ipoMarketErrorMessages`) with `formatTimesSubscribed(x100)` (12.34×).
