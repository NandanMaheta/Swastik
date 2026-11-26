package ipomarket

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/NandanMaheta/swastik/apps/api/internal/platform/audit"
	"github.com/NandanMaheta/swastik/apps/api/internal/platform/db"
	"github.com/NandanMaheta/swastik/apps/api/internal/platform/db/dbgen"
)

// store is the only file that touches the database (sqlc). Every method runs inside the
// transaction carried by ctx (db.TxRunner).
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

func (a pageAfter) set() bool { return a.ID != uuid.Nil }

func (s *store) q(ctx context.Context) (*dbgen.Queries, error) {
	tx, err := db.MustTx(ctx)
	if err != nil {
		return nil, fmt.Errorf("ipomarket: %w", err)
	}
	return dbgen.New(tx), nil
}

func queryErr(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	return fmt.Errorf("ipomarket: query: %w", err)
}

func (s *store) lockIPO(ctx context.Context, ipoID uuid.UUID) error {
	q, err := s.q(ctx)
	if err != nil {
		return err
	}
	if err := q.LockIPOMarket(ctx, ipoID.String()); err != nil {
		return fmt.Errorf("ipomarket: lock ipo: %w", err)
	}
	return nil
}

func (s *store) insertGMP(ctx context.Context, org, ipoID uuid.UUID, n newGMP, now time.Time) (GMPEntry, error) {
	q, err := s.q(ctx)
	if err != nil {
		return GMPEntry{}, err
	}
	row, err := q.InsertGMPEntry(ctx, dbgen.InsertGMPEntryParams{
		OrgID: org, IpoID: ipoID, GmpPaise: n.GMPPaise, Note: textPtr(n.Note),
		CorrectsEntryID: nullUUID(n.CorrectsEntryID), Source: n.Source,
		ActorKind: n.Actor.Kind, ActorID: uuid.NullUUID{UUID: n.Actor.ID, Valid: n.Actor.ID != uuid.Nil},
		IdempotencyKey: textPtr(n.IdemKey), RequestHash: textPtr(n.RequestHash), RecordedAt: db.Timestamptz(now),
	})
	if err != nil {
		return GMPEntry{}, fmt.Errorf("ipomarket: insert gmp: %w", err)
	}
	return toGMP(row, uuid.NullUUID{}), nil
}

// findGMPByIdemKey returns the stored entry and its request hash; ErrNotFound when none.
func (s *store) findGMPByIdemKey(ctx context.Context, org, ipoID uuid.UUID, key string) (GMPEntry, string, error) {
	q, err := s.q(ctx)
	if err != nil {
		return GMPEntry{}, "", err
	}
	row, err := q.FindGMPByIdemKey(ctx, dbgen.FindGMPByIdemKeyParams{OrgID: org, IpoID: ipoID, IdempotencyKey: db.Text(key)})
	if err != nil {
		return GMPEntry{}, "", queryErr(err)
	}
	return toGMP(row, uuid.NullUUID{}), row.RequestHash.String, nil
}

// currentGMP is the newest effective entry; ErrNotFound when none.
func (s *store) currentGMP(ctx context.Context, org, ipoID uuid.UUID) (GMPEntry, error) {
	q, err := s.q(ctx)
	if err != nil {
		return GMPEntry{}, err
	}
	row, err := q.CurrentGMP(ctx, dbgen.CurrentGMPParams{OrgID: org, IpoID: ipoID})
	if err != nil {
		return GMPEntry{}, queryErr(err)
	}
	return toGMP(row, uuid.NullUUID{}), nil
}

func (s *store) isGMPCorrected(ctx context.Context, org, entryID uuid.UUID) (bool, error) {
	q, err := s.q(ctx)
	if err != nil {
		return false, err
	}
	ok, err := q.IsGMPCorrected(ctx, dbgen.IsGMPCorrectedParams{OrgID: org, EntryID: uuid.NullUUID{UUID: entryID, Valid: true}})
	if err != nil {
		return false, queryErr(err)
	}
	return ok, nil
}

// listGMPHistory returns up to limit rows (all, corrected too), newest first, CorrectedByEntryID set.
func (s *store) listGMPHistory(ctx context.Context, org, ipoID uuid.UUID, after pageAfter, limit int) ([]GMPEntry, error) {
	q, err := s.q(ctx)
	if err != nil {
		return nil, err
	}
	rows, err := q.ListGMPHistory(ctx, dbgen.ListGMPHistoryParams{
		OrgID: org, IpoID: ipoID, CursorSet: after.set(), CursorAt: db.Timestamptz(after.At),
		CursorID: after.ID, RowLimit: int32(limit), //nolint:gosec // limit is a small page size
	})
	if err != nil {
		return nil, queryErr(err)
	}
	out := make([]GMPEntry, len(rows))
	for i, r := range rows {
		out[i] = toGMP(dbgen.IpoGmpEntry{
			ID: r.ID, OrgID: r.OrgID, IpoID: r.IpoID, GmpPaise: r.GmpPaise, Note: r.Note,
			CorrectsEntryID: r.CorrectsEntryID, Source: r.Source, ActorKind: r.ActorKind, ActorID: r.ActorID,
			IdempotencyKey: r.IdempotencyKey, RequestHash: r.RequestHash, RecordedAt: r.RecordedAt,
		}, r.CorrectedByEntryID)
	}
	return out, nil
}

// listGMPTrend returns the newest 500 effective entries, ascending by (recorded_at, id).
func (s *store) listGMPTrend(ctx context.Context, org, ipoID uuid.UUID) ([]GMPEntry, error) {
	q, err := s.q(ctx)
	if err != nil {
		return nil, err
	}
	rows, err := q.ListGMPTrend(ctx, dbgen.ListGMPTrendParams{OrgID: org, IpoID: ipoID})
	if err != nil {
		return nil, queryErr(err)
	}
	out := make([]GMPEntry, len(rows))
	for i, r := range rows {
		out[i] = toGMP(r, uuid.NullUUID{})
	}
	return out, nil
}

// currentGMPBatch returns the current effective entry per IPO id; IPOs without one are absent.
func (s *store) currentGMPBatch(ctx context.Context, org uuid.UUID, ids []uuid.UUID) (map[uuid.UUID]GMPEntry, error) {
	q, err := s.q(ctx)
	if err != nil {
		return nil, err
	}
	rows, err := q.CurrentGMPBatch(ctx, dbgen.CurrentGMPBatchParams{OrgID: org, Ids: ids})
	if err != nil {
		return nil, queryErr(err)
	}
	out := make(map[uuid.UUID]GMPEntry, len(rows))
	for _, r := range rows {
		out[r.IpoID] = toGMP(r, uuid.NullUUID{})
	}
	return out, nil
}

func (s *store) insertSnapshot(ctx context.Context, org, ipoID uuid.UUID, n newSnapshot, now time.Time) (Snapshot, error) {
	q, err := s.q(ctx)
	if err != nil {
		return Snapshot{}, err
	}
	row, err := q.InsertSubscription(ctx, dbgen.InsertSubscriptionParams{
		OrgID: org, IpoID: ipoID, AsOf: db.Timestamptz(n.AsOf), TotalX100: n.TotalX100,
		QibX100: int4(n.QIBX100), NiiX100: int4(n.NIIX100), BniiX100: int4(n.BNIIX100),
		SniiX100: int4(n.SNIIX100), RetailX100: int4(n.RetailX100), EmployeeX100: int4(n.EmployeeX100),
		Source: n.Source, ActorKind: n.Actor.Kind,
		ActorID:        uuid.NullUUID{UUID: n.Actor.ID, Valid: n.Actor.ID != uuid.Nil},
		IdempotencyKey: textPtr(n.IdemKey), RequestHash: textPtr(n.RequestHash), RecordedAt: db.Timestamptz(now),
	})
	if err != nil {
		return Snapshot{}, fmt.Errorf("ipomarket: insert subscription: %w", err)
	}
	return toSnapshot(row), nil
}

func (s *store) findSnapshotByIdemKey(ctx context.Context, org, ipoID uuid.UUID, key string) (Snapshot, string, error) {
	q, err := s.q(ctx)
	if err != nil {
		return Snapshot{}, "", err
	}
	row, err := q.FindSubscriptionByIdemKey(ctx, dbgen.FindSubscriptionByIdemKeyParams{OrgID: org, IpoID: ipoID, IdempotencyKey: db.Text(key)})
	if err != nil {
		return Snapshot{}, "", queryErr(err)
	}
	return toSnapshot(row), row.RequestHash.String, nil
}

// currentSnapshot is the row with the greatest (as_of, recorded_at, id); ErrNotFound when none.
func (s *store) currentSnapshot(ctx context.Context, org, ipoID uuid.UUID) (Snapshot, error) {
	q, err := s.q(ctx)
	if err != nil {
		return Snapshot{}, err
	}
	row, err := q.CurrentSubscription(ctx, dbgen.CurrentSubscriptionParams{OrgID: org, IpoID: ipoID})
	if err != nil {
		return Snapshot{}, queryErr(err)
	}
	return toSnapshot(row), nil
}

func (s *store) currentSnapshotBatch(ctx context.Context, org uuid.UUID, ids []uuid.UUID) (map[uuid.UUID]Snapshot, error) {
	q, err := s.q(ctx)
	if err != nil {
		return nil, err
	}
	rows, err := q.CurrentSubscriptionBatch(ctx, dbgen.CurrentSubscriptionBatchParams{OrgID: org, Ids: ids})
	if err != nil {
		return nil, queryErr(err)
	}
	out := make(map[uuid.UUID]Snapshot, len(rows))
	for _, r := range rows {
		out[r.IpoID] = toSnapshot(r)
	}
	return out, nil
}

// listSnapshotHistory returns up to limit rows newest first by (as_of, recorded_at, id).
func (s *store) listSnapshotHistory(ctx context.Context, org, ipoID uuid.UUID, after pageAfter, limit int) ([]Snapshot, error) {
	q, err := s.q(ctx)
	if err != nil {
		return nil, err
	}
	rows, err := q.ListSubscriptionHistory(ctx, dbgen.ListSubscriptionHistoryParams{
		OrgID: org, IpoID: ipoID, CursorSet: after.set(), CursorAsOf: db.Timestamptz(after.At),
		CursorRecordedAt: db.Timestamptz(after.RecordedAt), CursorID: after.ID,
		RowLimit: int32(limit), //nolint:gosec // limit is a small page size
	})
	if err != nil {
		return nil, queryErr(err)
	}
	out := make([]Snapshot, len(rows))
	for i, r := range rows {
		out[i] = toSnapshot(r)
	}
	return out, nil
}

func textPtr(p *string) pgtype.Text {
	if p == nil {
		return pgtype.Text{}
	}
	return db.Text(*p)
}

func nullUUID(p *uuid.UUID) uuid.NullUUID {
	if p == nil {
		return uuid.NullUUID{}
	}
	return uuid.NullUUID{UUID: *p, Valid: true}
}

func uuidPtr(n uuid.NullUUID) *uuid.UUID {
	if !n.Valid {
		return nil
	}
	return &n.UUID
}

func int4(p *int32) pgtype.Int4 {
	if p == nil {
		return pgtype.Int4{}
	}
	return pgtype.Int4{Int32: *p, Valid: true}
}

func int4Ptr(p pgtype.Int4) *int32 {
	if !p.Valid {
		return nil
	}
	return &p.Int32
}

func toGMP(r dbgen.IpoGmpEntry, correctedBy uuid.NullUUID) GMPEntry {
	return GMPEntry{
		ID: r.ID, IPOID: r.IpoID, GMPPaise: r.GmpPaise, Note: db.TextPtr(r.Note),
		CorrectsEntryID: uuidPtr(r.CorrectsEntryID), CorrectedByEntryID: uuidPtr(correctedBy),
		Source: r.Source, Actor: audit.Actor{ID: r.ActorID.UUID, Kind: r.ActorKind},
		RecordedAt: db.Time(r.RecordedAt),
	}
}

func toSnapshot(r dbgen.IpoSubscriptionSnapshot) Snapshot {
	return Snapshot{
		ID: r.ID, IPOID: r.IpoID, AsOf: db.Time(r.AsOf), TotalX100: r.TotalX100,
		QIBX100: int4Ptr(r.QibX100), NIIX100: int4Ptr(r.NiiX100), BNIIX100: int4Ptr(r.BniiX100),
		SNIIX100: int4Ptr(r.SniiX100), RetailX100: int4Ptr(r.RetailX100), EmployeeX100: int4Ptr(r.EmployeeX100),
		Source: r.Source, Actor: audit.Actor{ID: r.ActorID.UUID, Kind: r.ActorKind},
		RecordedAt: db.Time(r.RecordedAt),
	}
}
