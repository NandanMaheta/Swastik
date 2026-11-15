package auth

import (
	"context"
	"net/http"

	"github.com/danielgtaylor/huma/v2"

	"github.com/NandanMaheta/swastik/apps/api/internal/platform/authz"
)

// Admin control over another user's sessions (US-8). Every operation is admin-only and acts inside
// the admin's organisation; an unknown user and one of another organisation are both 404.

type (
	userIDInput struct {
		UserID string `path:"userId" format:"uuid"`
	}
	userDeviceInput struct {
		UserID    string `path:"userId" format:"uuid"`
		SessionID string `path:"sessionId" format:"uuid"`
	}
)

func (h *handlers) registerAdmin(api huma.API) {
	huma.Register(api, huma.Operation{
		OperationID: "auth-admin-user-devices-list", Method: http.MethodGet, Path: "/v1/admin/users/{userId}/devices",
		Tags: []string{"Admin users"}, Summary: "List a user's live device sessions", Security: authz.Require(authz.RoleAdmin),
	}, h.adminDevices)
	huma.Register(api, huma.Operation{
		OperationID: "auth-admin-user-device-revoke", Method: http.MethodDelete, Path: "/v1/admin/users/{userId}/devices/{sessionId}",
		Tags: []string{"Admin users"}, Summary: "End one device session of a user", Security: authz.Require(authz.RoleAdmin),
		DefaultStatus: http.StatusNoContent,
	}, h.adminRevoke)
	huma.Register(api, huma.Operation{
		OperationID: "auth-admin-user-sessions-end-all", Method: http.MethodPost, Path: "/v1/admin/users/{userId}/sessions/end-all",
		Tags: []string{"Admin users"}, Summary: "End every session of a user", Security: authz.Require(authz.RoleAdmin),
		DefaultStatus: http.StatusNoContent,
	}, h.adminEndAll)
}

func (h *handlers) adminDevices(ctx context.Context, in *userIDInput) (*deviceListOutput, error) {
	if err := h.ready(); err != nil {
		return nil, err
	}
	list, err := h.svc.AdminListDevices(ctx, authz.MustPrincipal(ctx), parseUUID(in.UserID))
	if err != nil {
		return nil, h.fail(ctx, err)
	}
	return &deviceListOutput{Body: toDeviceList(list)}, nil
}

func (h *handlers) adminRevoke(ctx context.Context, in *userDeviceInput) (*struct{}, error) {
	if err := h.ready(); err != nil {
		return nil, err
	}
	if err := h.svc.AdminRevokeDevice(ctx, authz.MustPrincipal(ctx), parseUUID(in.UserID), parseUUID(in.SessionID)); err != nil {
		return nil, h.fail(ctx, err)
	}
	return &struct{}{}, nil
}

func (h *handlers) adminEndAll(ctx context.Context, in *userIDInput) (*struct{}, error) {
	if err := h.ready(); err != nil {
		return nil, err
	}
	if _, err := h.svc.AdminEndAllSessions(ctx, authz.MustPrincipal(ctx), parseUUID(in.UserID)); err != nil {
		return nil, h.fail(ctx, err)
	}
	return &struct{}{}, nil
}
