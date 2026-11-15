package auth

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	"github.com/NandanMaheta/swastik/apps/api/internal/platform/authz"
)

// SignOut ends the caller's own session. It is naturally idempotent: a session that already
// ended stays as it is and writes nothing.
func (s *Service) SignOut(ctx context.Context, p authz.Principal) error {
	return s.inTx(ctx, func(ctx context.Context) error {
		if _, err := s.store.LockUser(ctx, p.UserID); err != nil {
			return fmt.Errorf("auth: lock user: %w", err)
		}
		ss, err := s.store.LockSession(ctx, p.SessionID)
		if err != nil {
			return fmt.Errorf("auth: lock session: %w", err)
		}
		if ss.UserID != p.UserID {
			return ErrSessionNotFound
		}
		ended, err := s.store.EndSession(ctx, ss.ID, "signed_out", s.now())
		if err != nil {
			return fmt.Errorf("auth: end session: %w", err)
		}
		if !ended {
			return nil
		}
		return s.writeAudit(ctx, p.OrgID, p.AuditActor(), p.UserID, ActionSessionSignedOut, nil, SessionEventAfter{SessionID: ss.ID})
	})
}

// SignOutEverywhere ends every session of the caller, the current one included (D-12), and
// returns how many it ended.
func (s *Service) SignOutEverywhere(ctx context.Context, p authz.Principal) (int, error) {
	return s.endAll(ctx, p, p.UserID, "signed_out_everywhere", ActionSessionSignedOutEverywhere)
}

// AdminEndAllSessions ends every session of the user and returns how many it ended.
func (s *Service) AdminEndAllSessions(ctx context.Context, p authz.Principal, userID uuid.UUID) (int, error) {
	if err := s.requireOrgUser(ctx, p, userID); err != nil {
		return 0, err
	}
	return s.endAll(ctx, p, userID, "ended_by_admin", ActionSessionEndedAllByAdmin)
}

// endAll ends all not-ended sessions of a user under the user lock and audits them as one event.
func (s *Service) endAll(ctx context.Context, p authz.Principal, userID uuid.UUID, reason, action string) (int, error) {
	var n int
	err := s.inTx(ctx, func(ctx context.Context) error {
		if _, err := s.store.LockUser(ctx, userID); err != nil {
			return fmt.Errorf("auth: lock user: %w", err)
		}
		ids, err := s.store.EndUserSessions(ctx, userID, uuid.Nil, reason, s.now())
		if err != nil {
			return fmt.Errorf("auth: end sessions: %w", err)
		}
		n = len(ids)
		if n == 0 {
			return nil
		}
		return s.writeAudit(ctx, p.OrgID, p.AuditActor(), userID, action, nil, SessionsEndedAfter{SessionIDs: ids})
	})
	if err != nil {
		return 0, err
	}
	return n, nil
}

// ListDevices lists the caller's live sessions, most recently active first.
func (s *Service) ListDevices(ctx context.Context, p authz.Principal) ([]Device, error) {
	return s.listDevices(ctx, p.UserID, p.SessionID)
}

// AdminListDevices lists any user's live sessions of the admin's org (ErrUserNotFound otherwise).
func (s *Service) AdminListDevices(ctx context.Context, p authz.Principal, userID uuid.UUID) ([]Device, error) {
	if err := s.requireOrgUser(ctx, p, userID); err != nil {
		return nil, err
	}
	return s.listDevices(ctx, userID, uuid.Nil)
}

func (s *Service) listDevices(ctx context.Context, userID, current uuid.UUID) ([]Device, error) {
	rows, err := s.store.ListLiveSessions(ctx, userID, s.now())
	if err != nil {
		return nil, fmt.Errorf("auth: list sessions: %w", err)
	}
	out := make([]Device, 0, len(rows))
	for _, r := range rows {
		out = append(out, Device{
			SessionID: r.ID, DeviceName: r.DeviceName, Platform: r.Platform, SignedInAt: r.CreatedAt,
			LastActiveAt: r.LastActiveAt, IsCurrent: current != uuid.Nil && r.ID == current,
		})
	}
	return out, nil
}

// RevokeDevice ends one of the caller's own sessions: ErrSessionNotFound when it is absent, ended
// or owned by someone else.
func (s *Service) RevokeDevice(ctx context.Context, p authz.Principal, sessionID uuid.UUID) error {
	return s.revoke(ctx, p, p.UserID, sessionID, "revoked_by_user", "user")
}

// AdminRevokeDevice ends one session of the user (ErrUserNotFound, ErrSessionNotFound).
func (s *Service) AdminRevokeDevice(ctx context.Context, p authz.Principal, userID, sessionID uuid.UUID) error {
	if err := s.requireOrgUser(ctx, p, userID); err != nil {
		return err
	}
	return s.revoke(ctx, p, userID, sessionID, "revoked_by_admin", "admin")
}

func (s *Service) revoke(ctx context.Context, p authz.Principal, owner, sessionID uuid.UUID, reason, by string) error {
	return s.inTx(ctx, func(ctx context.Context) error {
		if _, err := s.store.LockUser(ctx, owner); err != nil {
			return fmt.Errorf("auth: lock user: %w", err)
		}
		ss, err := s.store.LockSession(ctx, sessionID)
		if err != nil {
			return fmt.Errorf("auth: lock session: %w", err)
		}
		if ss.UserID != owner || ss.EndedAt != nil {
			return ErrSessionNotFound // someone else's, ended or absent: indistinguishable
		}
		if _, err := s.store.EndSession(ctx, ss.ID, reason, s.now()); err != nil {
			return fmt.Errorf("auth: end session: %w", err)
		}
		return s.writeAudit(ctx, p.OrgID, p.AuditActor(), owner, ActionSessionRevoked, nil, SessionRevokedAfter{SessionID: ss.ID, By: by})
	})
}

// requireOrgUser is ErrUserNotFound unless the user exists in the admin's org.
func (s *Service) requireOrgUser(ctx context.Context, p authz.Principal, userID uuid.UUID) error {
	u, err := s.store.GetUser(ctx, userID)
	if err != nil {
		return fmt.Errorf("auth: read user: %w", err)
	}
	if u.OrgID != p.OrgID {
		return ErrUserNotFound
	}
	return nil
}
