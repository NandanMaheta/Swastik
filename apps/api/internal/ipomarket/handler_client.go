package ipomarket

import (
	"context"
	"net/http"

	"github.com/danielgtaylor/huma/v2"

	"github.com/NandanMaheta/swastik/apps/api/internal/platform/authz"
)

type marketOutput struct{ Body ClientMarketView }

// registerClient registers ipomarket-get and ipomarket-summaries (published only, any signed-in user).
func registerClient(api huma.API, s *Service) {
	huma.Register(api, huma.Operation{
		OperationID: "ipomarket-get", Method: http.MethodGet, Path: "/v1/ipos/{ipoId}/market", Tags: []string{tagIPOMarket},
		Summary: "Current GMP, trend and latest subscription of a published IPO", Security: authz.Require(),
	}, func(ctx context.Context, in *IPOPath) (*marketOutput, error) {
		if err := ready(s); err != nil {
			return nil, err
		}
		v, err := s.MarketView(ctx, authz.MustPrincipal(ctx).OrgID, parseID(in.ID), true)
		if err != nil {
			return nil, fail(ctx, s, err)
		}
		return &marketOutput{Body: viewOut(v)}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "ipomarket-summaries", Method: http.MethodGet, Path: "/v1/ipos/market", Tags: []string{tagIPOMarket},
		Summary: "Market summaries of up to 200 published IPOs (others omitted)", Security: authz.Require(),
	}, func(ctx context.Context, in *idsQuery) (*summariesOutput, error) {
		return summaries(ctx, s, in, true)
	})
}
