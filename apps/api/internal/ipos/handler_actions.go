package ipos

import (
	"context"
	"net/http"

	"github.com/danielgtaylor/huma/v2"

	"github.com/NandanMaheta/swastik/apps/api/internal/platform/authz"
)

type versionInput struct {
	IdemInput
	IDPath
	Body VersionBody
}

type statusInput struct {
	IdemInput
	IDPath
	Body StatusBody
}

type deleteInput struct {
	IdemInput
	IDPath
	Version int32 `query:"version" required:"true" minimum:"1"`
}

// registerActions registers publish, unpublish, status override and delete.
func registerActions(api huma.API, s *Service) {
	huma.Register(api, huma.Operation{
		OperationID: "ipos-publish", Method: http.MethodPost, Path: "/v1/admin/ipos/{ipoId}/publish", Tags: []string{tagIPOs},
		Summary: "Publish an IPO to clients", Security: authz.Require(authz.RoleAdmin),
	}, func(ctx context.Context, in *versionInput) (*mutationOutput, error) {
		if err := ready(s); err != nil {
			return nil, err
		}
		p := authz.MustPrincipal(ctx)
		res, err := s.Publish(ctx, p.AuditActor(), p.OrgID, parseID(in.ID), in.Body.Version, in.IdempotencyKey)
		if err != nil {
			return nil, fail(ctx, s, err)
		}
		return mutation(res), nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "ipos-unpublish", Method: http.MethodPost, Path: "/v1/admin/ipos/{ipoId}/unpublish", Tags: []string{tagIPOs},
		Summary: "Hide an IPO from clients", Security: authz.Require(authz.RoleAdmin),
	}, func(ctx context.Context, in *versionInput) (*mutationOutput, error) {
		if err := ready(s); err != nil {
			return nil, err
		}
		p := authz.MustPrincipal(ctx)
		res, err := s.Unpublish(ctx, p.AuditActor(), p.OrgID, parseID(in.ID), in.Body.Version, in.IdempotencyKey)
		if err != nil {
			return nil, fail(ctx, s, err)
		}
		return mutation(res), nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "ipos-override-status", Method: http.MethodPost, Path: "/v1/admin/ipos/{ipoId}/status", Tags: []string{tagIPOs},
		Summary: "Manually set the lifecycle status (forward or backward) with a reason", Security: authz.Require(authz.RoleAdmin),
	}, func(ctx context.Context, in *statusInput) (*mutationOutput, error) {
		if err := ready(s); err != nil {
			return nil, err
		}
		p := authz.MustPrincipal(ctx)
		res, err := s.OverrideStatus(ctx, p.AuditActor(), p.OrgID, parseID(in.ID), in.Body.Version, Status(in.Body.Status), in.Body.Reason, in.IdempotencyKey)
		if err != nil {
			return nil, fail(ctx, s, err)
		}
		return mutation(res), nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "ipos-delete", Method: http.MethodDelete, Path: "/v1/admin/ipos/{ipoId}", Tags: []string{tagIPOs},
		Summary: "Delete a never-published draft", Security: authz.Require(authz.RoleAdmin),
		DefaultStatus: http.StatusNoContent,
	}, func(ctx context.Context, in *deleteInput) (*struct{}, error) {
		if err := ready(s); err != nil {
			return nil, err
		}
		p := authz.MustPrincipal(ctx)
		if _, err := s.Delete(ctx, p.AuditActor(), p.OrgID, parseID(in.ID), in.Version, in.IdempotencyKey); err != nil {
			return nil, fail(ctx, s, err)
		}
		return &struct{}{}, nil
	})
}
