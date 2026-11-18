package ipos

import (
	"context"
	"net/http"

	"github.com/danielgtaylor/huma/v2"

	"github.com/NandanMaheta/swastik/apps/api/internal/platform/authz"
)

type clientListInput struct {
	Status string `query:"status" enum:"UPCOMING,OPEN,CLOSED,ALLOTMENT_OUT,LISTED,SETTLED"`
	Limit  int    `query:"limit" minimum:"1" maximum:"200" default:"50"`
	Cursor string `query:"cursor" maxLength:"200"`
}

type clientListOutput struct{ Body ClientIPOPage }

type clientGetOutput struct{ Body ClientIPO }

// registerClient registers ipos-list and ipos-get (published only, any signed-in user).
func registerClient(api huma.API, s *Service) {
	huma.Register(api, huma.Operation{
		OperationID: "ipos-list", Method: http.MethodGet, Path: "/v1/ipos", Tags: []string{tagIPOs},
		Summary: "List published IPOs", Security: authz.Require(),
	}, func(ctx context.Context, in *clientListInput) (*clientListOutput, error) {
		if err := ready(s); err != nil {
			return nil, err
		}
		f := ClientFilter{Cursor: in.Cursor, Limit: in.Limit}
		if in.Status != "" {
			st := Status(in.Status)
			f.Status = &st
		}
		page, err := s.ListPublished(ctx, authz.MustPrincipal(ctx).OrgID, f)
		if err != nil {
			return nil, fail(ctx, s, err)
		}
		out := &clientListOutput{Body: ClientIPOPage{Items: make([]ClientIPO, 0, len(page.Items)), NextCursor: cursorOut(page.NextCursor)}}
		for _, i := range page.Items {
			out.Body.Items = append(out.Body.Items, clientOut(i))
		}
		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "ipos-get", Method: http.MethodGet, Path: "/v1/ipos/{ipoId}", Tags: []string{tagIPOs},
		Summary: "Fetch a published IPO (drafts and unknown ids are both 404)", Security: authz.Require(),
	}, func(ctx context.Context, in *adminGetInput) (*clientGetOutput, error) {
		if err := ready(s); err != nil {
			return nil, err
		}
		i, err := s.GetPublished(ctx, authz.MustPrincipal(ctx).OrgID, parseID(in.ID))
		if err != nil {
			return nil, fail(ctx, s, err)
		}
		return &clientGetOutput{Body: clientOut(i)}, nil
	})
}
