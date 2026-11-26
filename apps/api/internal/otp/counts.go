package otp

import (
	"context"

	"github.com/google/uuid"

	"github.com/NandanMaheta/swastik/apps/api/internal/platform/istdate"
)

// DailyCounts returns the delivery counters of one IST day (FR-017).
func (s *Service) DailyCounts(_ context.Context, _ uuid.UUID, _ istdate.Date) (DailyCounts, error) {
	return DailyCounts{}, errNotImplemented
}
