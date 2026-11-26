package ipomarket

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/NandanMaheta/swastik/apps/api/internal/platform/audit"
)

// store is the only file that touches the database (sqlc in S07). Every method runs inside the
// transaction carried by ctx (db.TxRunner). Until S07 the methods are compile stubs.
type store struct{}

// newGMP is one GMP row to insert; IdemKey and RequestHash are both nil or both set.
type newGMP struct {
	GMPInput
	Actor                audit.Actor
	IdemKey, RequestHash *string
}

// newSnapshot is one subscription row to insert.
type newSnapshot struct {
	SubscriptionInput
	Actor                audit.Actor
	IdemKey, RequestHash *string
}

// pageAfter is the keyset position: rows strictly older than (At, ID). Zero value = first page.
type pageAfter struct {
	At         time.Time // recorded_at for GMP history; as_of for subscription history
	RecordedAt time.Time // subscription history only
	ID         uuid.UUID
}

func (s *store) lockIPO(ctx context.Context, ipoID uuid.UUID) error { return errNotImplemented }

func (s *store) insertGMP(ctx context.Context, org, ipoID uuid.UUID, n newGMP, now time.Time) (GMPEntry, error) {
	return GMPEntry{}, errNotImplemented
}

// findGMPByIdemKey returns the stored entry and its request hash; ErrNotFound when none.
func (s *store) findGMPByIdemKey(ctx context.Context, org, ipoID uuid.UUID, key string) (GMPEntry, string, error) {
	return GMPEntry{}, "", errNotImplemented
}

// currentGMP is the newest effective entry; ErrNotFound when none.
func (s *store) currentGMP(ctx context.Context, org, ipoID uuid.UUID) (GMPEntry, error) {
	return GMPEntry{}, errNotImplemented
}

func (s *store) isGMPCorrected(ctx context.Context, org, entryID uuid.UUID) (bool, error) {
	return false, errNotImplemented
}

// listGMPHistory returns up to limit rows (all, corrected too), newest first, CorrectedByEntryID set.
func (s *store) listGMPHistory(ctx context.Context, org, ipoID uuid.UUID, after pageAfter, limit int) ([]GMPEntry, error) {
	return nil, errNotImplemented
}

// listGMPTrend returns the newest 500 effective entries, ascending by (recorded_at, id).
func (s *store) listGMPTrend(ctx context.Context, org, ipoID uuid.UUID) ([]GMPEntry, error) {
	return nil, errNotImplemented
}

// currentGMPBatch returns the current effective entry per IPO id; IPOs without one are absent.
func (s *store) currentGMPBatch(ctx context.Context, org uuid.UUID, ids []uuid.UUID) (map[uuid.UUID]GMPEntry, error) {
	return nil, errNotImplemented
}

func (s *store) insertSnapshot(ctx context.Context, org, ipoID uuid.UUID, n newSnapshot, now time.Time) (Snapshot, error) {
	return Snapshot{}, errNotImplemented
}

func (s *store) findSnapshotByIdemKey(ctx context.Context, org, ipoID uuid.UUID, key string) (Snapshot, string, error) {
	return Snapshot{}, "", errNotImplemented
}

// currentSnapshot is the row with the greatest (as_of, recorded_at, id); ErrNotFound when none.
func (s *store) currentSnapshot(ctx context.Context, org, ipoID uuid.UUID) (Snapshot, error) {
	return Snapshot{}, errNotImplemented
}

func (s *store) currentSnapshotBatch(ctx context.Context, org uuid.UUID, ids []uuid.UUID) (map[uuid.UUID]Snapshot, error) {
	return nil, errNotImplemented
}

// listSnapshotHistory returns up to limit rows newest first by (as_of, recorded_at, id).
func (s *store) listSnapshotHistory(ctx context.Context, org, ipoID uuid.UUID, after pageAfter, limit int) ([]Snapshot, error) {
	return nil, errNotImplemented
}
