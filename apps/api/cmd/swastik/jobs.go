package main

import (
	"context"

	"github.com/NandanMaheta/swastik/apps/api/internal/auth"
	"github.com/NandanMaheta/swastik/apps/api/internal/scheduler"
)

// registerAuthJobs registers the auth.housekeeping job (plan P-20): a recurring job per
// organisation that runs daily at 03:30 IST, after the scheduler's own retention job. The
// adapter lives here because internal/auth does not import internal/scheduler.
func registerAuthJobs(sch *scheduler.Service, svc *auth.Service) {
	sch.Register(auth.HousekeepingKind, func(ctx context.Context, job scheduler.Job) error {
		_, err := svc.Housekeep(ctx, job.OrgID)
		return err
	}, scheduler.KindOptions{Recurring: auth.HousekeepingNext})
}
