package otp

import (
	"context"

	"github.com/google/uuid"

	"github.com/NandanMaheta/swastik/apps/api/internal/platform/istdate"
)

// DailyCounts returns the delivery counters of one IST day (FR-017).
func (s *Service) DailyCounts(ctx context.Context, org uuid.UUID, day istdate.Date) (DailyCounts, error) {
	return s.st.GetCounts(ctx, org, day)
}
