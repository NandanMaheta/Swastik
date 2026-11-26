package ipomarket

import (
	"context"

	"github.com/google/uuid"
)

// CurrentGMP returns the newest effective entry; ok=false when the IPO has none. It does not check
// publication.
func (s *Service) CurrentGMP(ctx context.Context, org, ipoID uuid.UUID) (g GMP, ok bool, err error) {
	return GMP{}, false, errNotImplemented
}

// ListGMP returns one keyset page of the admin GMP history.
func (s *Service) ListGMP(ctx context.Context, org, ipoID uuid.UUID, cursor string, limit int) (Page[GMPEntry], error) {
	return Page[GMPEntry]{}, errNotImplemented
}

// ListSubscriptions returns one keyset page of the admin subscription history.
func (s *Service) ListSubscriptions(ctx context.Context, org, ipoID uuid.UUID, cursor string, limit int) (Page[Snapshot], error) {
	return Page[Snapshot]{}, errNotImplemented
}

// MarketView returns the market view of one IPO; publishedOnly hides unpublished ones as ErrNotFound.
func (s *Service) MarketView(ctx context.Context, org, ipoID uuid.UUID, publishedOnly bool) (View, error) {
	return View{}, errNotImplemented
}

// Summaries returns the batch summaries (at most 200 ids).
func (s *Service) Summaries(ctx context.Context, org uuid.UUID, ids []uuid.UUID, publishedOnly bool) ([]Summary, error) {
	return nil, errNotImplemented
}
