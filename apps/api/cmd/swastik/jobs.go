package main

import (
	"github.com/NandanMaheta/swastik/apps/api/internal/auth"
	"github.com/NandanMaheta/swastik/apps/api/internal/scheduler"
)

// Compile stub (S17, test-engineer): S19 registers the auth.housekeeping job here (plan P-20):
//
//	sch.Register(auth.HousekeepingKind, adapter calling svc.Housekeep(ctx, job.OrgID),
//	    scheduler.KindOptions{Recurring: auth.HousekeepingNext})
func registerAuthJobs(_ *scheduler.Service, _ *auth.Service) {}
