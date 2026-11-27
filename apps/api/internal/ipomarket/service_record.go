package ipomarket

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/NandanMaheta/swastik/apps/api/internal/ipos"
	"github.com/NandanMaheta/swastik/apps/api/internal/platform/audit"
)

// Audit actions (data-model section 4).
const (
	actGMPRecorded          = "ipo.gmp_recorded"
	actSubscriptionRecorded = "ipo.subscription_recorded"
)

// loadIPO returns the org's IPO; ErrNotFound for unknown or foreign ids.
func (s *Service) loadIPO(ctx context.Context, org, ipoID uuid.UUID) (ipos.IPO, error) {
	ipo, err := s.d.IPOs.Get(ctx, org, ipoID)
	if errors.Is(err, ipos.ErrNotFound) {
		return ipos.IPO{}, ErrNotFound
	}
	return ipo, err
}

// checkWritable refuses LISTED or SETTLED IPOs (ErrFrozen) and never-published ones.
func checkWritable(ipo ipos.IPO) error {
	if ipo.Status == ipos.StatusListed || ipo.Status == ipos.StatusSettled {
		return ErrFrozen
	}
	if ipo.FirstPublishedAt == nil {
		return ErrNotPublishedYet
	}
	return nil
}

func currentView(ipo ipos.IPO, e GMPEntry) CurrentView {
	return CurrentView{GMPPaise: e.GMPPaise, ExpectedProfitPaise: profitOf(ipo.LotSize, e.GMPPaise), LotSize: ipo.LotSize, UpdatedAt: e.RecordedAt}
}

func profitOf(lot *int32, gmp int64) *int64 {
	if lot == nil {
		return nil
	}
	p := ExpectedProfitPerLot(gmp, *lot)
	return &p
}

func withProfit(ipo ipos.IPO, e GMPEntry) GMPEntry {
	e.ExpectedProfitPaise = profitOf(ipo.LotSize, e.GMPPaise)
	return e
}

// RecordGMP appends a GMP entry (or a correction of the current one).
func (s *Service) RecordGMP(ctx context.Context, by audit.Actor, org, ipoID uuid.UUID, in GMPInput, idemKey string) (GMPResult, error) {
	var out GMPResult
	err := s.d.Tx.InTx(ctx, func(ctx context.Context) error {
		ipo, err := s.loadIPO(ctx, org, ipoID)
		if err != nil {
			return err
		}
		in, warns, err := validateGMP(in, ipo)
		if err != nil {
			return err
		}
		if err := s.store.lockIPO(ctx, ipoID); err != nil {
			return err
		}
		hash := requestHash(actGMPRecorded, ipoID, in.GMPPaise, derefStr(in.Note), derefUUID(in.CorrectsEntryID), in.Source)
		if idemKey != "" {
			stored, storedHash, err := s.store.findGMPByIdemKey(ctx, org, ipoID, idemKey)
			switch {
			case err == nil:
				if storedHash != hash {
					return ErrKeyReused
				}
				cur, err := s.store.currentGMP(ctx, org, ipoID)
				if err != nil {
					return err
				}
				out = GMPResult{Entry: withProfit(ipo, stored), Current: currentView(ipo, cur), Replayed: true}
				return nil
			case !errors.Is(err, ErrNotFound):
				return err
			}
		}
		if err := checkWritable(ipo); err != nil {
			return err
		}
		if err := s.checkCorrection(ctx, org, ipoID, in.CorrectsEntryID); err != nil {
			return err
		}
		var key, h *string
		if idemKey != "" {
			key, h = optKey(idemKey), &hash
		}
		e, err := s.store.insertGMP(ctx, org, ipoID, newGMP{GMPInput: in, Actor: by, IdemKey: key, RequestHash: h}, s.d.Now())
		if err != nil {
			return err
		}
		after := map[string]any{
			"entry_id": e.ID.String(), "gmp_paise": e.GMPPaise, "corrects_entry_id": derefUUID(e.CorrectsEntryID),
			"note": derefStr(e.Note), "source": e.Source, "idempotency_key": nil, "request_hash": nil,
		}
		if key != nil {
			after["idempotency_key"], after["request_hash"] = *key, hash
		}
		if err := audit.Write(ctx, audit.Entry{OrgID: org, Actor: by, Entity: "ipo", EntityID: ipoID, Action: actGMPRecorded, After: after}); err != nil {
			return err
		}
		cur, err := s.store.currentGMP(ctx, org, ipoID)
		if err != nil {
			return err
		}
		out = GMPResult{Entry: withProfit(ipo, e), Current: currentView(ipo, cur), Warnings: warns}
		return nil
	})
	if err != nil {
		return GMPResult{}, err
	}
	return out, nil
}

// checkCorrection requires the target to be the current effective entry of the IPO (FR-005); an
// unknown, foreign, older or already corrected target gives ErrCorrectionNotLatest. The caller
// holds the per-IPO lock (D-06), so the answer cannot change before the insert.
func (s *Service) checkCorrection(ctx context.Context, org, ipoID uuid.UUID, target *uuid.UUID) error {
	if target == nil {
		return nil
	}
	cur, err := s.store.currentGMP(ctx, org, ipoID)
	if errors.Is(err, ErrNotFound) || (err == nil && cur.ID != *target) {
		return ErrCorrectionNotLatest
	}
	return err
}

// RecordSubscription appends a subscription snapshot.
func (s *Service) RecordSubscription(ctx context.Context, by audit.Actor, org, ipoID uuid.UUID, in SubscriptionInput, idemKey string) (SubscriptionResult, error) {
	var out SubscriptionResult
	err := s.d.Tx.InTx(ctx, func(ctx context.Context) error {
		ipo, err := s.loadIPO(ctx, org, ipoID)
		if err != nil {
			return err
		}
		if err := s.store.lockIPO(ctx, ipoID); err != nil {
			return err
		}
		hash := requestHash(actSubscriptionRecorded, ipoID, in.AsOf.UTC().Format(time.RFC3339Nano), in.TotalX100,
			derefInt32(in.QIBX100), derefInt32(in.NIIX100), derefInt32(in.BNIIX100), derefInt32(in.SNIIX100),
			derefInt32(in.RetailX100), derefInt32(in.EmployeeX100), in.Source)
		if idemKey != "" {
			stored, storedHash, err := s.store.findSnapshotByIdemKey(ctx, org, ipoID, idemKey)
			switch {
			case err == nil:
				if storedHash != hash {
					return ErrKeyReused
				}
				cur, err := s.store.currentSnapshot(ctx, org, ipoID)
				if err != nil {
					return err
				}
				out = SubscriptionResult{Snapshot: stored, Current: cur, Replayed: true}
				return nil
			case !errors.Is(err, ErrNotFound):
				return err
			}
		}
		if err := validateSubscription(in, ipo, s.d.Now()); err != nil {
			return err
		}
		if err := checkWritable(ipo); err != nil {
			return err
		}
		var key, h *string
		if idemKey != "" {
			key, h = optKey(idemKey), &hash
		}
		snap, err := s.store.insertSnapshot(ctx, org, ipoID, newSnapshot{SubscriptionInput: in, Actor: by, IdemKey: key, RequestHash: h}, s.d.Now())
		if err != nil {
			return err
		}
		after := map[string]any{
			"snapshot_id": snap.ID.String(), "as_of": snap.AsOf.UTC().Format(time.RFC3339Nano), "total_x100": snap.TotalX100,
			"qib_x100": derefInt32(snap.QIBX100), "nii_x100": derefInt32(snap.NIIX100), "bnii_x100": derefInt32(snap.BNIIX100),
			"snii_x100": derefInt32(snap.SNIIX100), "retail_x100": derefInt32(snap.RetailX100),
			"employee_x100": derefInt32(snap.EmployeeX100), "source": snap.Source,
			"idempotency_key": nil, "request_hash": nil,
		}
		if key != nil {
			after["idempotency_key"], after["request_hash"] = *key, hash
		}
		if err := audit.Write(ctx, audit.Entry{OrgID: org, Actor: by, Entity: "ipo", EntityID: ipoID, Action: actSubscriptionRecorded, After: after}); err != nil {
			return err
		}
		cur, err := s.store.currentSnapshot(ctx, org, ipoID)
		if err != nil {
			return err
		}
		out = SubscriptionResult{Snapshot: snap, Current: cur}
		return nil
	})
	if err != nil {
		return SubscriptionResult{}, err
	}
	return out, nil
}
