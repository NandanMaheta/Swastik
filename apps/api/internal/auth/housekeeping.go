package auth

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	"github.com/NandanMaheta/swastik/apps/api/internal/platform/audit"
	"github.com/NandanMaheta/swastik/apps/api/internal/platform/db"
)

// Housekeep purges stale throttles, expired challenges and dead refresh families of the org (P-20).
// It runs inside the job transaction and returns db.ErrNoTx without one. Each table is one bounded
// single-table DELETE, in the order throttles, challenges, refresh tokens, and none of them touches users or
// device_sessions. Correctness never depends on it: expiry and lock state are computed on read.
func (s *Service) Housekeep(ctx context.Context, orgID uuid.UUID) (PurgeCounts, error) {
	if _, err := db.MustTx(ctx); err != nil {
		return PurgeCounts{}, fmt.Errorf("auth: housekeep: %w", err)
	}
	now := s.now()
	var c PurgeCounts
	var err error
	if c.Throttles, err = s.store.PurgeStaleThrottles(ctx, orgID, now); err != nil {
		return PurgeCounts{}, err
	}
	if c.Challenges, err = s.store.PurgeExpiredChallenges(ctx, orgID, now); err != nil {
		return PurgeCounts{}, err
	}
	if c.RefreshTokens, err = s.store.PurgeDeadFamilyTokens(ctx, orgID, now); err != nil {
		return PurgeCounts{}, err
	}
	if c == (PurgeCounts{}) {
		return c, nil
	}
	err = audit.Write(ctx, audit.Entry{
		OrgID: orgID, Actor: systemActor, Entity: EntityAuth, Action: ActionHousekeepingPurged, At: now,
		After: HousekeepingPurgedAfter(c),
	})
	if err != nil {
		return PurgeCounts{}, fmt.Errorf("auth: audit housekeeping: %w", err)
	}
	return c, nil
}
