# Brief: 009 GMP, expected profit and subscription snapshots  ·  Tier B

**Goal:** the admin records the GMP (per share, paise) and live subscription figures for an IPO as append-only history with author and time; everyone sees expected profit per lot = GMP × lot size. Clients see published IPOs only: current value, "updated at", trend, latest subscription. 018 reads the current GMP for estimates.

**Business rules:** BR-IPO-04 ([business-rules.md](../../docs/product/business-rules.md)); feeds BR-SET-09 (018). Golden scenarios: none driven; GS-01..04 must keep passing. Owner questions Q1–Q3 at the top of `spec.md`.

**Acceptance criteria (spec.md):**
- US1 record GMP: author + server time, expected profit = GMP × lot (paise), repeat value allowed, negative allowed (Q1), unknown lot → null, idempotent replay / 422 reuse, 409 frozen at LISTED/SETTLED, 409 never published (Q3), typo-guard warning, DB refuses UPDATE/DELETE.
- US2 client view: current + updated-at + trend (Q2); null when none; unpublished = 404 like 008; batch ≤ 200 ids omits unpublished; no author/note.
- US3 correction of the current entry only, once; corrected entry hidden from clients, kept for admin.
- US4 subscription snapshot (total required; QIB, NII, bNII, sNII, retail, employee optional; x100 integers); latest as-of wins; as-of window.
- US5 `CurrentGMP` + `ExpectedProfitPerLot` for other modules.

**Public surface:**
- Go: package `internal/ipomarket`: `NewService(Deps)`, `Register`, `ExpectedProfitPerLot`, `CurrentGMP`, `RecordGMP`, `RecordSubscription`, reads, errors (see `contracts/go-module-api.md`); 008 gains additive `ipos.(*Service).GetMany`.
- HTTP: 7 operations `ipomarket-*`: `POST|GET /v1/admin/ipos/{ipoId}/gmp`, `POST|GET /v1/admin/ipos/{ipoId}/subscription`, `GET /v1/admin/ipos/market`, `GET /v1/ipos/{ipoId}/market`, `GET /v1/ipos/market` (see `contracts/http-api.md`).
- DB: migration `00005_ipo_market.sql`: `ipo_gmp_entries`, `ipo_subscription_snapshots`, both append-only (`forbid_mutation()`), see `data-model.md`.

**Files to touch:** `apps/api/internal/ipomarket/**`, `apps/api/queries/ipomarket.sql`, `apps/api/migrations/00005_ipo_market.sql`, `apps/api/internal/ipos/service_read.go` + `queries/ipos.sql` (`GetMany`), `apps/api/cmd/swastik/main.go`, `apps/api/.golangci.yml`, `scripts/check-lint-boundaries.sh`, `packages/domain/src/ipo-market.ts`, `packages/api-client`, `specs/008-ipo-catalogue/contracts/go-module-api.md` (GetMany line), `docs/product/modules.md`.

**Depends on:** 008 (merged: `ipos.Get`, `IPO.LotSize`, status, `FirstPublishedAt`), 002 (db, clock, audit), 003 (authz, httpx.Problem). See `docs/engineering/codemap.md`.

**Risks and non-goals:** migration needs owner approval; Q1–Q3 answers can each change one slice (plan R-1); per-IPO advisory lock (plan D-06). Non-goals: UI (023/025), GMP suggestion and subscription import (026), per-client estimates (018), client notifications on GMP change, signals/outbox/jobs.
