# Contract: Go API of `internal/ipomarket` (and the additive 008 read it needs)

Exported names and signatures below are binding; unexported helpers are not. No pgx or HTTP types appear outside `store.go` / handlers.

## Wiring (`cmd/swastik` only)

```go
type IPOReader interface { // satisfied by *ipos.Service (008)
    Get(ctx context.Context, org, id uuid.UUID) (ipos.IPO, error)
    GetMany(ctx context.Context, org uuid.UUID, ids []uuid.UUID) (map[uuid.UUID]ipos.IPO, error) // new in 009, see below
}
type Deps struct {
    Tx   db.TxRunner
    IPOs IPOReader
    Now  clock.Func
    Log  *slog.Logger
}
func NewService(d Deps) *Service
func Register(api huma.API, s *Service) // after authz.Install and ipos.Register
```

## Reads for other modules (018 estimates, 023/025 via HTTP, 026 later)

```go
// ExpectedProfitPerLot is BR-IPO-04: gmp × lot, exact int64 paise. Pure. Callers pass values within
// the stored bounds (|gmp| ≤ 1e9, lot ≤ 1e6), so the product cannot overflow.
func ExpectedProfitPerLot(gmpPaise int64, lotSize int32) int64

type GMP struct {
    EntryID    uuid.UUID
    GMPPaise   int64
    RecordedAt time.Time
    Source     string
}
// CurrentGMP returns the newest effective entry; ok=false when the IPO has none. It does not check
// publication (callers decide visibility). Joins the caller's transaction if there is one.
func (s *Service) CurrentGMP(ctx context.Context, org, ipoID uuid.UUID) (g GMP, ok bool, err error)
```

## Mutations (used by handlers; 026 later calls them with a system actor and `import:<name>` source)

```go
type GMPInput struct { GMPPaise int64; Note *string; CorrectsEntryID *uuid.UUID; Source string }
type SubscriptionInput struct {
    AsOf                                                   time.Time
    TotalX100                                              int32
    QIBX100, NIIX100, BNIIX100, SNIIX100, RetailX100, EmployeeX100 *int32
    Source                                                 string
}
type GMPResult struct { Entry GMPEntry; Current CurrentView; Warnings []Warning; Replayed bool }
type SubscriptionResult struct { Snapshot Snapshot; Current Snapshot; Replayed bool }

func (s *Service) RecordGMP(ctx context.Context, by audit.Actor, org, ipoID uuid.UUID, in GMPInput, idemKey string) (GMPResult, error)
func (s *Service) RecordSubscription(ctx context.Context, by audit.Actor, org, ipoID uuid.UUID, in SubscriptionInput, idemKey string) (SubscriptionResult, error)
func (s *Service) ListGMP(ctx context.Context, org, ipoID uuid.UUID, cursor string, limit int) (Page[GMPEntry], error)
func (s *Service) ListSubscriptions(ctx context.Context, org, ipoID uuid.UUID, cursor string, limit int) (Page[Snapshot], error)
func (s *Service) MarketView(ctx context.Context, org, ipoID uuid.UUID, publishedOnly bool) (View, error)
func (s *Service) Summaries(ctx context.Context, org uuid.UUID, ids []uuid.UUID, publishedOnly bool) ([]Summary, error)
```

`GMPEntry`, `Snapshot`, `CurrentView`, `View`, `Summary`, `Warning`, `Page[T]` mirror the HTTP schemas in [http-api.md](./http-api.md).

## Errors

```go
var (
    ErrNotFound          = errors.New("ipomarket: not found")           // 404 not_found
    ErrNotPublishedYet   = errors.New("ipomarket: IPO never published") // 409
    ErrFrozen            = errors.New("ipomarket: IPO listed or settled") // 409
    ErrCorrectionNotLatest = errors.New("ipomarket: correction target is not the current entry") // 409
    ErrKeyReused         = errors.New("ipomarket: idempotency key reused") // 422
)
type ValidationError struct { Code string; Issues []FieldIssue } // Code = ipomarket.invalid_value
```

## Signals and events

None emitted. The module listens to no 008 signal. Consumers read on demand (ADR 0008 signals are for same-transaction reactions; nothing needs one here).

## Additive change to 008 (`internal/ipos`)

```go
// GetMany returns the org's IPOs among ids (drafts included), keyed by id; unknown ids are absent.
// len(ids) ≤ 200. One query (GetIPOsByIDs). Read-only, no lock.
func (s *Service) GetMany(ctx context.Context, org uuid.UUID, ids []uuid.UUID) (map[uuid.UUID]IPO, error)
```

Add it to `specs/008-ipo-catalogue/contracts/go-module-api.md` under "Reads and capabilities for dependents".
