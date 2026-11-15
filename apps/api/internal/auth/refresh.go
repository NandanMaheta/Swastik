package auth

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"

	"github.com/NandanMaheta/swastik/apps/api/internal/platform/crypto"
)

// Refresh rotates a refresh credential (P-03). Every failure is ErrRefreshRejected; reuse and
// device mismatch also end the session, which is committed before the rejection is returned.
func (s *Service) Refresh(ctx context.Context, in RefreshInput) (SessionTokens, error) {
	if in.RefreshToken == "" || len(in.RefreshToken) > maxTokenLength {
		return SessionTokens{}, ErrRefreshRejected
	}
	// 1. Find the token without a lock; an unknown token has nothing to attribute.
	row, err := s.store.FindRefreshByHash(ctx, crypto.Digest(in.RefreshToken))
	switch {
	case errors.Is(err, ErrRefreshNotFound):
		return SessionTokens{}, ErrRefreshRejected
	case err != nil:
		return SessionTokens{}, fmt.Errorf("auth: find refresh token: %w", err)
	}
	pre, err := s.store.GetSession(ctx, row.SessionID)
	if err != nil {
		return SessionTokens{}, fmt.Errorf("auth: read session: %w", err)
	}

	var out SessionTokens
	rejected := false
	err = s.inTx(ctx, func(ctx context.Context) error {
		var err error
		out, rejected, err = s.rotate(ctx, in, pre.UserID, row.ID, row.SessionID)
		return err
	})
	if err != nil {
		return SessionTokens{}, err
	}
	if rejected {
		return SessionTokens{}, ErrRefreshRejected
	}
	return out, nil
}

// rotate is steps 2 to 9 of P-03 under the locks users, device_sessions, refresh_tokens (in that
// order), re-reading every row once its lock is held. A rejection returns nil error so that the
// session end and audit entry of reuse and device mismatch commit.
func (s *Service) rotate(ctx context.Context, in RefreshInput, userID, tokenID, sessionID uuid.UUID) (SessionTokens, bool, error) {
	u, err := s.store.LockUser(ctx, userID)
	if err != nil {
		return SessionTokens{}, false, fmt.Errorf("auth: lock user: %w", err)
	}
	ss, err := s.store.LockSession(ctx, sessionID)
	if err != nil {
		return SessionTokens{}, false, fmt.Errorf("auth: lock session: %w", err)
	}
	rr, err := s.store.LockRefresh(ctx, tokenID)
	if err != nil {
		return SessionTokens{}, false, fmt.Errorf("auth: lock refresh token: %w", err)
	}
	now := s.now()
	switch {
	case ss.EndedAt != nil:
		return SessionTokens{}, true, nil
	case rr.UsedAt != nil: // reuse: the whole family dies, wherever the replay came from
		return SessionTokens{}, true, s.endAndAudit(ctx, u, ss.ID, "refresh_reuse", ActionRefreshReuseDetected, in.IP)
	case in.DeviceID != ss.DeviceID:
		return SessionTokens{}, true, s.endAndAudit(ctx, u, ss.ID, "device_mismatch", ActionDeviceMismatch, in.IP)
	case in.ClientType != ss.ClientType: // cannot happen legitimately; changes nothing
		return SessionTokens{}, true, nil
	case !now.Before(ss.IdleExpiresAt) || !now.Before(ss.AbsoluteExpiresAt): // expiry is computed, not written
		return SessionTokens{}, true, nil
	case u.Status != StatusActive:
		return SessionTokens{}, true, nil
	}
	// A lock on the account does not block refresh (D-08): the throttle table is not read here.
	refresh, digest, err := crypto.NewToken(refreshPrefix)
	if err != nil {
		return SessionTokens{}, false, fmt.Errorf("auth: refresh token: %w", err)
	}
	if _, err := s.store.RotateRefresh(ctx, rr.ID, digest, now); err != nil {
		return SessionTokens{}, false, fmt.Errorf("auth: rotate refresh token: %w", err)
	}
	idle := now.Add(idleLifetime(u.Role))
	if err := s.store.TouchSession(ctx, ss.ID, now, idle); err != nil {
		return SessionTokens{}, false, fmt.Errorf("auth: touch session: %w", err)
	}
	if err := s.writeAudit(ctx, u.OrgID, actorOf(u), u.ID, ActionSessionRefreshed, nil,
		SessionEventAfter{SessionID: ss.ID, IP: in.IP}); err != nil {
		return SessionTokens{}, false, err
	}
	ss.IdleExpiresAt = idle
	tokens, err := s.sessionTokens(u, ss, refresh)
	return tokens, false, err
}

// endAndAudit ends a session for a security reason and records the event under the system actor.
func (s *Service) endAndAudit(ctx context.Context, u UserRow, sessionID uuid.UUID, reason, action, ip string) error {
	if _, err := s.store.EndSession(ctx, sessionID, reason, s.now()); err != nil {
		return fmt.Errorf("auth: end session: %w", err)
	}
	return s.writeAudit(ctx, u.OrgID, systemActor, u.ID, action, nil, SessionEventAfter{SessionID: sessionID, IP: ip})
}
