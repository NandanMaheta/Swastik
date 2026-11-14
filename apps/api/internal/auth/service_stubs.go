package auth

import (
	"context"

	"github.com/google/uuid"

	"github.com/NandanMaheta/swastik/apps/api/internal/platform/authz"
)

// Compile stubs for S14 (refresh, sessions, verifiers, password change); S14 replaces them.

func (s *Service) Refresh(context.Context, RefreshInput) (SessionTokens, error) {
	return SessionTokens{}, errNotImplemented
}
func (s *Service) SignOut(context.Context, authz.Principal) error { return errNotImplemented }
func (s *Service) SignOutEverywhere(context.Context, authz.Principal) (int, error) {
	return 0, errNotImplemented
}
func (s *Service) ListDevices(context.Context, authz.Principal) ([]Device, error) {
	return nil, errNotImplemented
}
func (s *Service) RevokeDevice(context.Context, authz.Principal, uuid.UUID) error {
	return errNotImplemented
}
func (s *Service) AdminListDevices(context.Context, authz.Principal, uuid.UUID) ([]Device, error) {
	return nil, errNotImplemented
}
func (s *Service) AdminRevokeDevice(context.Context, authz.Principal, uuid.UUID, uuid.UUID) error {
	return errNotImplemented
}
func (s *Service) AdminEndAllSessions(context.Context, authz.Principal, uuid.UUID) (int, error) {
	return 0, errNotImplemented
}
func (s *Service) ChangePassword(context.Context, authz.Principal, string, string) error {
	return errNotImplemented
}
func (s *Service) BearerVerifier() authz.Verifier    { return nil }
func (s *Service) ChallengeVerifier() authz.Verifier { return nil }
