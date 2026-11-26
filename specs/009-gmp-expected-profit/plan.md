# Implementation Plan: 009 GMP, expected profit and subscription snapshots

**Branch**: `feat/009-gmp-expected-profit` | **Date**: 2026-11-26 | **Spec**: [spec.md](./spec.md) | **Tier**: B | **Rules**: BR-IPO-04

Details live in [data-model.md](./data-model.md), [contracts/http-api.md](./contracts/http-api.md) and [contracts/go-module-api.md](./contracts/go-module-api.md). This file only records decisions, placement and the test strategy.

## Summary

A new Go module `internal/ipomarket` owns two append-only history tables: GMP entries (per share, integer paise, with author, time, optional correction link) and subscription snapshots (multiples as integer hundredths). Expected profit per lot = GMP × the IPO's current lot size, computed on read by one pure function (BR-IPO-04). Admins write and read full history; signed-in clients read published IPOs only (current value, "updated at", trend). The module reads IPO facts through 008's public Go API (`Get`, plus a new additive `GetMany`) and never touches the `ipos` table. No signals, outbox messages or scheduler jobs.

## Technical Context

- **Language**: Go 1.27 (Huma v2, pgx v5, sqlc, goose); TS only for `packages/domain` codes/formatters and the regenerated `packages/api-client`.
- **Storage**: PostgreSQL 18, migration `00005_ipo_market.sql` (expand-only).
- **Testing**: `go test -race`, `pgregory.net/rapid` (approved in 002), `dbtest.New` (testcontainers), humatest, Vitest for `packages/domain`.
- **Scale**: ~100 clients, tens of IPOs a year, a few GMP entries per IPO per day (< 500 per IPO). Budget: API p95 < 200 ms.
- **New dependencies**: none.

## Constitution Check

| Principle | Status |
|---|---|
| I Rules are truth | BR-IPO-04 formula used verbatim (no cost deduction). Owner questions Q1–Q3 at the top of the spec; defaults flagged. Every test touching the formula or history names `BR_IPO_04`. |
| II Money exact, history immutable | `bigint` paise, `int64` math, no rounding needed; both tables get `forbid_mutation()`; corrections are new rows; one `audit_log` row per write. |
| III Test-first | Test strategy below; clock injected (`clock.Func`). |
| IV Boundaries | `ipomarket → ipos` only through `IPOReader`; `ipos` never imports `ipomarket`; depguard rules added (below). |
| V Contract-first | 7 new operations, additions only (oasdiff clean); optional `Idempotency-Key` on both POSTs; RFC 9457 errors. |
| VI Security | Admin-only writes (`authz.Require(admin)`), org-scoped queries, no PII stored, client views strip author/note. |
| VII Simple | Computed-on-read expected profit; no cache; no new deps. |

Gate: pass. No ADR needed (no architectural decision changes; ADR 0008 signals deliberately not used, see D-05).

## Decisions

- **D-01 Module placement**: new package `apps/api/internal/ipomarket` (M3 IPOs). Keeping it out of `internal/ipos` keeps 008's large, approved module unchanged except one additive read, and gives 026 one small owner to write into. Rejected: extending `ipos` (bigger blast radius in a module under review).
- **D-02 Store GMP per share, compute expected profit on read** with the IPO's current lot size. One source of truth; a later lot-size fix updates every view. Rejected: storing expected profit or a lot-size snapshot per row (stale after edits, two numbers to reconcile).
- **D-03 Corrections are rows** (`corrects_entry_id`, unique, same IPO via composite FK, only the current effective entry). Keeps the client trend free of typos while the admin history keeps everything.
- **D-04 Writes need an ever-published IPO (Q3) and status before LISTED.** Append-only rows block deleting a draft (FK RESTRICT); 008 already forbids deleting ever-published IPOs, so the combination never fails a delete. Freeze at LISTED because the listing price makes estimates final (BR-SET-09).
- **D-05 No signals, no outbox.** No dependent must react in the same transaction: 018 reads `CurrentGMP` when it computes estimates; the admin home (023) reads the history API. Client notifications on GMP change are out of scope (no rule asks for them).
- **D-06 Per-IPO serialisation** with `pg_advisory_xact_lock(hashtextextended('ipomarket:'||ipo_id, 0))`, because this module cannot lock the `ipos` row. Covers the correction "latest only" check and the idempotency lookup. Accepted race: a write committing at the same instant as the LISTED step is kept (harmless; estimates switch to final anyway).
- **D-07 Idempotency on the entry row** (`idempotency_key`, `request_hash`, partial unique index per org + IPO), cleaner than 008's audit-log lookup; same semantics and problem code shape.
- **D-08 Subscription multiples as `int32` hundredths** on the wire and in storage (`total_x100`); no floats anywhere. TS formats `12.34×`.
- **D-09 Batch summaries** (`?ipo_ids=`, ≤ 200, matches 008's max page) so list cards need one extra request, not N. Visibility filtered through `ipos.GetMany`; unpublished ids are silently omitted (no existence oracle).
- **D-10 Typo guard** warning when |GMP| exceeds the issue price (else band cap), not an error.

## Data model (summary; full DDL in data-model.md)

- `ipo_gmp_entries`: `id`, `org_id` FK, `ipo_id` FK, `gmp_paise bigint` CHECK ±1e9, `note`, `corrects_entry_id` UNIQUE + composite self-FK, `source` CHECK (`manual` | `import:<name>`), `actor_kind`/`actor_id`, `idempotency_key`/`request_hash`, `recorded_at`. Index `(org_id, ipo_id, recorded_at DESC, id DESC)`; partial unique idem index; append-only trigger.
- `ipo_subscription_snapshots`: same envelope, `as_of`, `total_x100` NOT NULL, six optional category columns, CHECK 0..1e7. Index `(org_id, ipo_id, as_of DESC, recorded_at DESC, id DESC)`; idem index; append-only trigger.
- `org_id` on both; both rows `org_id` must match the IPO's org (checked in Go via `ipos.Get`, which is org-scoped).

## API operations (full schemas and errors in contracts/http-api.md)

| operationId | Method + path | Who | Idempotent |
|---|---|---|---|
| `ipomarket-record-gmp` | `POST /v1/admin/ipos/{ipoId}/gmp` | admin | `Idempotency-Key` |
| `ipomarket-list-gmp` | `GET /v1/admin/ipos/{ipoId}/gmp` | admin | read |
| `ipomarket-record-subscription` | `POST /v1/admin/ipos/{ipoId}/subscription` | admin | `Idempotency-Key` |
| `ipomarket-list-subscription` | `GET /v1/admin/ipos/{ipoId}/subscription` | admin | read |
| `ipomarket-admin-summaries` | `GET /v1/admin/ipos/market?ipo_ids=` | admin | read |
| `ipomarket-get` | `GET /v1/ipos/{ipoId}/market` | signed-in | read |
| `ipomarket-summaries` | `GET /v1/ipos/market?ipo_ids=` | signed-in | read |

Errors: `ipomarket.frozen`, `ipomarket.not_published_yet`, `ipomarket.correction_not_latest` (409); `ipomarket.invalid_value`, `ipomarket.idempotency_key_reused`, `validation_failed` (422); `not_found` (404). Warning `ipomarket.gmp_exceeds_price`.

## Module placement and dependencies

```text
apps/api/internal/ipomarket/
  doc.go model.go errors.go profit.go     // types, errors, ExpectedProfitPerLot
  service.go service_record.go service_read.go validate.go idem.go
  store.go                                // only file importing pgx / dbgen
  handler_admin.go handler_client.go problems.go api_types.go
  ipomarkettest/                          // fixtures: published IPO with lot size, recorder helpers
apps/api/queries/ipomarket.sql            apps/api/migrations/00005_ipo_market.sql
apps/api/internal/ipos/service_read.go    // + GetMany (additive)   apps/api/queries/ipos.sql (+ GetIPOsByIDs)
apps/api/cmd/swastik/main.go              // NewService + Register after ipos
apps/api/.golangci.yml                    // depguard rules below
packages/domain/src/ipo-market.ts         packages/api-client (regenerated)
```

Dependency direction: `cmd/swastik → ipomarket → ipos → platform`. Depguard additions:

- `platform-is-a-leaf`: deny `internal/ipomarket`.
- `ipomarket-boundaries` (strict, non-test): allow `$gostd`, huma, uuid, pgx, `internal/ipomarket`, `internal/ipos`, `internal/platform`.
- `ipomarket-pgx-only-in-store`: deny pgx outside `ipomarket/store.go` (tests excepted).
- `ipos-boundaries` stays strict and does not list `ipomarket`, so `ipos → ipomarket` fails lint. `scripts/check-lint-boundaries.sh` gets two deliberate-violation cases (platform → ipomarket, ipos → ipomarket).

## Scheduler jobs and outbox events

None (D-05). 026 will add its own import jobs that call `RecordSubscription` / `RecordGMP` with a system actor.

## Test strategy

| Layer | Where | Covers |
|---|---|---|
| Unit + property | `ipomarket/profit_test.go`: `TestExpectedProfitPerLot_BR_IPO_04_Property` (rapid, 10k: equals gmp×lot, sign follows gmp, zero lot impossible, bounds never overflow); table for US1.1/1.2/1.4 values | BR-IPO-04, FR-003, SC-001 |
| Unit | `validate_test.go`: note trim, as-of window (IST open date, +5 min), x100 ranges, typo-guard warning (issue price, band cap, none) | FR-001, FR-007, FR-008 |
| Integration (schema) | `ipomarket/schema_test.go` (`dbtest.New`): `TestSchema_BR_IPO_04_AppendOnly` (UPDATE/DELETE raise on both tables), correction unique + cross-IPO FK fails, CHECK bounds, actor/idem pair CHECKs, draft-delete still works when no rows | FR-002, FR-005 |
| Integration (service) | `service_record_test.go`: `TestRecordGMP_BR_IPO_04_AuthorAndTime` (US1.1–1.3), `TestRecordGMP_FR010_IdempotentReplayAndReuse` incl. two goroutines same key → one row, `TestRecordGMP_FR006_FrozenAndNotPublished`, `TestRecordGMP_FR005_Correction*` (US3), `TestRecord_FR011_OneAuditPerWrite` (none on replay/reject), concurrent correction vs new entry (D-06); `service_read_test.go`: current/effective/trend ordering ties, `CurrentGMP` none/ok, lot-size edit changes views, subscription latest by as-of then recording | BR-IPO-04, FR-001–FR-012, FR-016 |
| Contract (HTTP) | `handler_admin_test.go`, `handler_client_test.go` (humatest): every operation's status codes and problem codes; client 404 identical for draft/unknown/other org; client body has no note/actor/source (`TestClient_BR_IPO_04_LatestWithUpdatedAt`, `TestClient_FR014_NoAdminFields`); 403 for clients on admin ops; batch omits unpublished; ≤ 200 ids | FR-013–FR-015, US2 |
| Contract (OpenAPI) | regenerate `packages/api-client`; oasdiff in CI must show additions only | Constitution V |
| Lint boundaries | `scripts/check-lint-boundaries.sh` new cases | Constitution IV |
| Component (TS) | `packages/domain/src/ipo-market.test.ts`: every problem code has a message; `formatTimesSubscribed(1234) = "12.34×"`, 0, 10,000,000 | FR-008 |
| Performance | `perf_test.go` (short-skipped): 200 IPOs × 500 entries, summaries p95 < 200 ms locally | SC-003 |
| E2E | none in 009 (no UI; admin 023 and client 025 own Playwright/Maestro) | — |
| Golden | GS-01..04 unchanged; run the golden suite once per pass | — |

008 additive read: `ipos/service_read_test.go` gains `TestGetMany_*` (org scoping, drafts included, unknown ids absent).

## Performance and security notes

- All reads hit `(org_id, ipo_id, …)` indexes; batch uses `DISTINCT ON (ipo_id)` over ≤ 200 ids; trend capped at 500 points. Writes take one advisory lock per IPO (microseconds; contention only between admin tabs).
- Writes require admin; org comes from the principal, never from the body. Client endpoints share 008's not-found behaviour to avoid leaking drafts. Note text is admin-only. No secrets, no PII. Handler bodies capped by Huma limits.
- GMP is unofficial grey-market data (blueprint §6): clients see the "updated at" time; labelling as "unofficial" is a UI concern for 025.

## Suggested slices (planner finalises)

S01 skeleton (package, exported names from contracts, stubs, `GetMany` stub, wiring compiles) → S02 migration + schema tests → S03 profit/validate unit + property tests → S04 store + sqlc → S05 RecordGMP + idempotency + audit → S06 corrections + serialisation → S07 RecordSubscription → S08 reads (`CurrentGMP`, views, summaries, `ipos.GetMany`) → S09 handlers + problems + contract tests → S10 depguard, domain TS, api-client regen, perf test, codemap.

## Risks

- R-1 Owner answers Q1–Q3 differently: Q1 "no" adds `CHECK (gmp_paise >= 0)`; Q2 "latest only" drops `trend` from the client view; Q3 "yes" needs 008 Delete to map FK violation to 409 `ipo.has_market_history`. Each is one slice-sized change.
- R-2 Migration review: new tables only, no ledger/auth schema; still needs the owner's approval per constitution workflow 5.
