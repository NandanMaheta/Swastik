package main

import (
	"context"

	"github.com/NandanMaheta/swastik/apps/api/internal/auth"
	"github.com/NandanMaheta/swastik/apps/api/internal/otp"
	"github.com/NandanMaheta/swastik/apps/api/internal/outbox"
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

// registerOTPJobs registers the otp.housekeeping job (feature 004): a recurring job per
// organisation that runs daily at 03:15 IST.
func registerOTPJobs(sch *scheduler.Service, svc *otp.Service) { otp.RegisterJobs(sch, svc) }

// registerOTPSenders registers the otp Sender for both outbox topics with 3 attempts: a code that
// cannot be sent is retried until it expires (10 minutes), never for hours.
func registerOTPSenders(ob *outbox.Service, svc *otp.Service) {
	ob.RegisterSender(otp.TopicEmailCode, svc.Sender(), 3)
	ob.RegisterSender(otp.TopicContactNotice, svc.Sender(), 3)
}
