package ipomarket

import (
	"context"

	"github.com/google/uuid"

	"github.com/NandanMaheta/swastik/apps/api/internal/platform/audit"
)

// RecordGMP appends a GMP entry (or a correction of the current one).
func (s *Service) RecordGMP(ctx context.Context, by audit.Actor, org, ipoID uuid.UUID, in GMPInput, idemKey string) (GMPResult, error) {
	return GMPResult{}, errNotImplemented
}

// RecordSubscription appends a subscription snapshot.
func (s *Service) RecordSubscription(ctx context.Context, by audit.Actor, org, ipoID uuid.UUID, in SubscriptionInput, idemKey string) (SubscriptionResult, error) {
	return SubscriptionResult{}, errNotImplemented
}
