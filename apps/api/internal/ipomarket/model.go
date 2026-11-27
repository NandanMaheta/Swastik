package ipomarket

import (
	"time"

	"github.com/google/uuid"

	"github.com/NandanMaheta/swastik/apps/api/internal/platform/audit"
)

// GMP is the current effective GMP entry of an IPO.
type GMP struct {
	EntryID    uuid.UUID
	GMPPaise   int64
	RecordedAt time.Time
	Source     string
}

// GMPInput is one GMP record request.
type GMPInput struct {
	GMPPaise        int64
	Note            *string
	CorrectsEntryID *uuid.UUID
	Source          string
}

// SubscriptionInput is one subscription snapshot request (multiples are x100 integers).
type SubscriptionInput struct {
	AsOf                                                           time.Time
	TotalX100                                                      int32
	QIBX100, NIIX100, BNIIX100, SNIIX100, RetailX100, EmployeeX100 *int32
	Source                                                         string
}

// GMPEntry is one stored GMP entry (admin view).
type GMPEntry struct {
	ID                  uuid.UUID
	IPOID               uuid.UUID
	GMPPaise            int64
	ExpectedProfitPaise *int64
	Note                *string
	CorrectsEntryID     *uuid.UUID
	CorrectedByEntryID  *uuid.UUID
	Source              string
	Actor               audit.Actor
	RecordedAt          time.Time
}

// Snapshot is one subscription snapshot.
type Snapshot struct {
	ID                                                             uuid.UUID
	IPOID                                                          uuid.UUID
	AsOf                                                           time.Time
	TotalX100                                                      int32
	QIBX100, NIIX100, BNIIX100, SNIIX100, RetailX100, EmployeeX100 *int32
	Source                                                         string
	Actor                                                          audit.Actor
	RecordedAt                                                     time.Time
}

// CurrentView is the current GMP with its expected profit per lot.
type CurrentView struct {
	GMPPaise            int64
	ExpectedProfitPaise *int64
	LotSize             *int32
	UpdatedAt           time.Time
}

// TrendPoint is one effective GMP value over time.
type TrendPoint struct {
	GMPPaise            int64
	ExpectedProfitPaise *int64
	At                  time.Time
}

// View is the client market view of one IPO.
type View struct {
	IPOID        uuid.UUID
	CurrentGMP   *CurrentView
	Trend        []TrendPoint
	Subscription *Snapshot
}

// Summary is the one-line market state of an IPO in a batch.
type Summary struct {
	IPOID                 uuid.UUID
	CurrentGMP            *CurrentView
	SubscriptionTotalX100 *int32
	SubscriptionAsOf      *time.Time
}

// Warning is a non-blocking notice (same shape as the 008 warning).
type Warning struct {
	Code   string
	Fields []string
	Detail string
	Params map[string]int64
}

// Page is one keyset page.
type Page[T any] struct {
	Items      []T
	NextCursor string
}

// GMPResult is the outcome of RecordGMP.
type GMPResult struct {
	Entry    GMPEntry
	Current  CurrentView
	Warnings []Warning
	Replayed bool
}

// SubscriptionResult is the outcome of RecordSubscription.
type SubscriptionResult struct {
	Snapshot Snapshot
	Current  Snapshot
	Replayed bool
}
