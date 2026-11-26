package otp

import (
	"time"

	"github.com/NandanMaheta/swastik/apps/api/internal/scheduler"
)

// JobRegistrar is satisfied by *scheduler.Service.
type JobRegistrar interface {
	Register(kind string, h scheduler.Handler, opts scheduler.KindOptions)
}

// HousekeepingNext is the next run after now: 03:15 IST every day.
func HousekeepingNext(_ time.Time) time.Time { panic(errNotImplemented) }

// RegisterJobs registers the recurring otp.housekeeping job (data-model section 8).
func RegisterJobs(_ JobRegistrar, _ *Service) { panic(errNotImplemented) }
