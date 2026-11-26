# Feature Specification: 009 GMP, expected profit and subscription snapshots

**Feature Branch**: `feat/009-gmp-expected-profit` · **Created**: 2026-11-26 · **Status**: Approved by owner 2026-11-26 · **Rules**: BR-IPO-04 · **Depends on**: 008 (merged)

## Open questions for the owner (defaults apply if you approve as is)

- **Q1 Negative GMP.** Can the GMP be negative (a grey-market discount), shown to clients as an expected loss per lot? *Default: yes; zero is allowed too. Settlement already handles G ≤ 0 (BR-SET-03/06).*
- **Q2 Client trend.** Do clients see the GMP trend (every value with its time), or only the latest value? *Default: the trend, as in blueprint §2.2. They never see who entered it or the admin's note.*
- **Q3 Drafts.** May the admin enter GMP and subscription on a draft IPO that has never been published? *Default: no. Entries are allowed once the IPO has been published at least once, because history is append-only and a draft with history could not be deleted (008 FR-008).*

## Clarifications (resolved from the rules, not guesses)

- Expected profit per lot = GMP per share × lot size, exactly as BR-IPO-04 says. No costs, brokerage or profit share are deducted here. Per-client "your share" estimates are 018's job (BR-SET-09), which reads the current GMP from this feature.
- GMP is per share, in integer paise. Expected profit is integer paise (no rounding needed: integer × integer).
- The lot size is the IPO's current lot size (008). If it is not set, expected profit is "unknown". If the admin later edits the lot size, every expected-profit value (current and trend) uses the new lot size.

## User Scenarios & Testing

### US1 Admin records the GMP and sees expected profit (P1)

The admin types today's GMP for an IPO. The system stores it as a new history entry with the admin and the time, and shows the expected profit per lot.

**Independent test**: record GMP on a published IPO via the API; check history, audit and the computed expected profit.

1. **Given** a published IPO with lot size 50, **When** the admin records GMP ₹30.00 (3000 paise), **Then** a new entry is stored with the admin as author and the server time, and the current expected profit per lot is ₹1,500.00 (150000 paise).
2. **Given** that entry, **When** the admin records ₹25.50 an hour later, **Then** both entries exist, the current GMP is ₹25.50, expected profit ₹1,275.00, and "updated at" is the new entry's time.
3. **Given** the same value as the current one, **When** the admin records it again, **Then** a new entry is stored (it confirms the value at a newer time).
4. **Given** GMP −₹10 (Q1), **When** recorded, **Then** expected profit is −₹500.00 for lot 50.
5. **Given** an IPO without a lot size, **When** GMP is recorded, **Then** it is stored and expected profit is "unknown" until the lot size is set.
6. **Given** a request with an Idempotency-Key, **When** it is sent twice, **Then** one entry and one audit row exist and the second response replays the first. The same key with a different body gives 422 `ipomarket.idempotency_key_reused`.
7. **Given** an IPO in status LISTED or SETTLED, **When** the admin records GMP, **Then** it is rejected with 409 `ipomarket.frozen` and nothing is stored.
8. **Given** a never-published draft (Q3), **When** the admin records GMP, **Then** 409 `ipomarket.not_published_yet`.
9. **Given** GMP larger in size than the issue price (or the band cap when no final price), **When** recorded, **Then** it is stored with warning `ipomarket.gmp_exceeds_price` (typo guard; not an error).
10. **Given** any stored entry, **When** anyone tries to update or delete it in the database, **Then** the database refuses.

### US2 Client sees the latest GMP, expected profit and trend (P1)

**Independent test**: as a client, fetch the market view and the batch summaries of published IPOs.

1. **Given** a published IPO with entries, **When** a client opens it, **Then** they see the current GMP, expected profit per lot and its "updated at" time, plus the trend (oldest to newest, values and times only).
2. **Given** an IPO with no GMP yet, **When** a client opens it, **Then** GMP and expected profit are absent (null), not zero.
3. **Given** a draft or unpublished IPO, **When** a client asks for its market view, **Then** 404 with the same body as an unknown id (008 FR-051).
4. **Given** a list of up to 200 IPO ids, **When** a client asks for summaries, **Then** only published IPOs are returned; other ids are left out silently.
5. **Given** any client response, **Then** it never contains author, note, corrected entries or idempotency data.

### US3 Admin corrects a mistyped GMP (P2)

1. **Given** the current entry ₹300 (typo for ₹30), **When** the admin records ₹30 as a correction of it, **Then** a new entry is stored that points to the wrong one; the wrong entry stays in admin history marked "corrected" and disappears from the current value and the client trend.
2. **Given** an entry that is not the current one, or one already corrected, **When** a correction targets it, **Then** 409 `ipomarket.correction_not_latest` and nothing is stored.

### US4 Subscription snapshot (P2)

The admin enters live subscription figures from the exchange website. Data import (026) will write the same snapshots later.

1. **Given** a published OPEN IPO, **When** the admin records as-of 14:30 IST with total 12.34×, QIB 20.10×, NII 15.00×, retail 6.25×, **Then** one snapshot is stored with the author and server time, figures as integer hundredths (1234, 2010, 1500, 625).
2. **Given** snapshots exist, **When** a client opens the IPO, **Then** they see the snapshot with the latest as-of time and that time; admins see the full history.
3. **Given** a wrong snapshot, **When** the admin records another with the same as-of time, **Then** the newer recording wins.
4. **Given** an as-of time more than 5 minutes in the future, or before the open date (00:00 IST), **Then** 422 `ipomarket.invalid_value`.
5. **Given** status LISTED or SETTLED, or a never-published draft, **Then** the same 409 codes as US1.7/1.8.

### US5 Other modules read the current GMP (P3)

1. **Given** entries for an IPO, **When** 018 calls `CurrentGMP`, **Then** it gets the latest effective entry (value, time) or "none", and `ExpectedProfitPerLot(gmp, lot)` gives the same number clients see.

### Edge cases

- Two admin tabs record at the same instant: both are stored, ordered by (recorded time, id); a correction racing a new entry is serialised per IPO, so the "latest only" rule holds.
- Lot size × GMP at the bounds (±₹1 crore × 10,00,000 shares) fits in int64; property-tested.
- An IPO unpublished after publishing: admin can still write (until LISTED); clients see nothing.
- An admin status override back from LISTED reopens writes.

## Requirements

### Functional Requirements

- **FR-001**: The admin MUST be able to record a GMP per share (integer paise, −1,000,000,000…1,000,000,000) with an optional private note (1–200 characters) for an IPO published at least once. Each record is a new entry with author and server time (BR-IPO-04).
- **FR-002**: GMP entries and subscription snapshots MUST be append-only; the database rejects UPDATE and DELETE.
- **FR-003**: Expected profit per lot MUST equal GMP × current lot size in integer paise, or unknown when the lot size is not set. No other deduction (BR-IPO-04).
- **FR-004**: The current GMP MUST be the newest effective entry by (recorded time, id). An entry is effective unless a later entry corrects it.
- **FR-005**: A correction MUST target the current effective entry of the same IPO; an entry can be corrected only once.
- **FR-006**: Writes MUST be rejected with 409 `ipomarket.frozen` while the IPO status is LISTED or SETTLED, and with 409 `ipomarket.not_published_yet` for a never-published IPO.
- **FR-007**: A GMP whose absolute value exceeds the issue price (else the band cap) MUST be stored with warning `ipomarket.gmp_exceeds_price`.
- **FR-008**: The admin MUST be able to record a subscription snapshot: as-of instant, total (required), QIB, NII, bNII, sNII, retail, employee (optional), each 0.00–100,000.00× stored as integer hundredths. As-of MUST be ≤ now + 5 min and ≥ open date 00:00 IST.
- **FR-009**: The current snapshot MUST be the one with the latest as-of; ties go to the later recording.
- **FR-010**: Every write MUST accept an optional Idempotency-Key (8–200 chars), scoped per org, IPO and action: same request replays, different request gives 422.
- **FR-011**: Every new entry MUST write exactly one `audit_log` row in the same transaction; replays and rejections write none.
- **FR-012**: Admins MUST be able to list GMP history (newest first, keyset pages, author, note, corrected-by, expected profit), list subscription history, and get summaries for up to 200 IPO ids including drafts.
- **FR-013**: Signed-in clients MUST be able to get the market view of a published IPO (current GMP, expected profit, updated-at, trend of effective entries, current snapshot) and summaries for up to 200 ids (unpublished and unknown ids omitted).
- **FR-014**: Client responses MUST NOT expose author, note, corrected entries or idempotency data.
- **FR-015**: Only admins write; every read and write is scoped to the caller's org.
- **FR-016**: The module MUST export `CurrentGMP` and the pure `ExpectedProfitPerLot` for other modules. It emits no signals and no outbox messages.

### Key entities

- **GMP entry**: IPO, GMP per share (paise), optional note, optional corrected entry, source (`manual` now; `import:<name>` reserved for 026), author, recorded time.
- **Subscription snapshot**: IPO, as-of instant, category multiples in hundredths, source, author, recorded time.

## Success Criteria

- **SC-001**: For every GMP and lot size in bounds, the expected profit shown equals GMP × lot exactly (property test, 10,000 cases).
- **SC-002**: 100% of stored entries have an author, a time and one audit row; no entry can be changed or removed.
- **SC-003**: Client summaries for 200 IPOs with 500 entries each return in p95 < 200 ms.
- **SC-004**: A recorded GMP is visible to clients on their next fetch (no server cache).

## Assumptions and non-goals

- Writes freeze at LISTED because the listing price makes amounts final (BR-SET-09). Accepted race: a write committing in the same instant as the LISTED step is kept.
- Clients are not notified of GMP changes (a notification feature may add it). The admin-home "recent GMP changes" widget (023) reads the history API.
- Non-goals: UI (023 admin, 025 client), GMP suggestions and subscription import (026), per-client estimates (018), quotas and other IPO facts.
