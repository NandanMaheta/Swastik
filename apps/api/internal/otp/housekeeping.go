package otp

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/NandanMaheta/swastik/apps/api/internal/platform/audit"
	"github.com/NandanMaheta/swastik/apps/api/internal/platform/db"
	"github.com/NandanMaheta/swastik/apps/api/internal/platform/istdate"
	"github.com/NandanMaheta/swastik/apps/api/internal/scheduler"
)

// JobRegistrar is satisfied by *scheduler.Service.
type JobRegistrar interface {
	Register(kind string, h scheduler.Handler, opts scheduler.KindOptions)
}

// Purge rules of data-model section 8, and the bound of one run per table.
const (
	purgeBatch         = 5000
	verificationGrace  = 24 * time.Hour
	proofRetention     = 24 * time.Hour
	limitRetention     = 48 * time.Hour
	countRetentionDays = 400
	entityOTP          = "otp"
)

// HousekeepingNext is the next run after now: 03:15 IST every day.
func HousekeepingNext(now time.Time) time.Time {
	return istdate.NextDailyAt(now, istdate.WallClock{Hour: 3, Minute: 15})
}

// RegisterJobs registers the recurring otp.housekeeping job (data-model section 8).
func RegisterJobs(r JobRegistrar, s *Service) {
	r.Register(HousekeepingKind, func(ctx context.Context, job scheduler.Job) error {
		return s.Housekeep(ctx, job.OrgID)
	}, scheduler.KindOptions{Recurring: HousekeepingNext})
}

// purgeCounts is the After of the purge audit entry: counts only.
type purgeCounts struct {
	Verifications int `json:"verifications"`
	Proofs        int `json:"proofs"`
	Limits        int `json:"limits"`
	DailyCounts   int `json:"daily_counts"`
}

// Housekeep purges what has expired, in bounded batches, and keeps every audit row (FR-015). It
// runs in the job transaction. One audit entry with the counts is written when anything went.
func (s *Service) Housekeep(ctx context.Context, org uuid.UUID) error {
	if _, err := db.MustTx(ctx); err != nil {
		return fmt.Errorf("otp: housekeep: %w", err)
	}
	now := s.now()
	var c purgeCounts
	var err error
	if c.Verifications, err = s.st.PurgeVerifications(ctx, org, now.Add(-verificationGrace), purgeBatch); err != nil {
		return err
	}
	if c.Proofs, err = s.st.PurgeProofs(ctx, org, now.Add(-proofRetention), purgeBatch); err != nil {
		return err
	}
	if c.Limits, err = s.st.PurgeLimits(ctx, org, now.Add(-limitRetention), purgeBatch); err != nil {
		return err
	}
	if c.DailyCounts, err = s.st.PurgeCounts(ctx, org, istdate.DateOf(now).AddDays(-countRetentionDays), purgeBatch); err != nil {
		return err
	}
	if c == (purgeCounts{}) {
		return nil
	}
	err = audit.Write(ctx, audit.Entry{
		OrgID: org, Actor: audit.Actor{Kind: audit.KindSystem}, Entity: entityOTP, Action: "otp.housekeeping.purged", After: c, At: now,
	})
	if err != nil {
		return fmt.Errorf("otp: audit housekeeping: %w", err)
	}
	return nil
}
