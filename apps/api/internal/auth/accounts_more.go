package auth

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	"github.com/NandanMaheta/swastik/apps/api/internal/platform/audit"
)

// featureEndedReason is the end_reason of sessions a feature ended through EndAllSessions.
const featureEndedReason = "ended_by_feature"

// ResetPassword sets a new password after 004 verified the person (FR-053): all sessions end and
// the lock and counter are cleared (D-08, D-13). The hash is computed before the transaction.
func (s *Service) ResetPassword(ctx context.Context, id uuid.UUID, newPassword string, by audit.Actor) error {
	pre, err := s.store.GetUser(ctx, id)
	if err != nil {
		return fmt.Errorf("auth: read user: %w", err)
	}
	if err := CheckPolicy(newPassword, pre.Email, pre.Mobile); err != nil {
		return err
	}
	phc, err := s.hasher.Hash(ctx, NormalizePassword(newPassword))
	if err != nil {
		return fmt.Errorf("auth: hash password: %w", err)
	}
	return s.inTx(ctx, func(ctx context.Context) error {
		u, err := s.store.LockUser(ctx, id)
		if err != nil {
			return fmt.Errorf("auth: lock user: %w", err)
		}
		now := s.now()
		if err := s.store.ChangePassword(ctx, id, phc, now); err != nil {
			return fmt.Errorf("auth: change password: %w", err)
		}
		ended, err := s.store.EndUserSessions(ctx, id, uuid.Nil, "password_reset", now)
		if err != nil {
			return fmt.Errorf("auth: end sessions: %w", err)
		}
		if _, err := s.store.InvalidateUserChallenges(ctx, id, now); err != nil {
			return err
		}
		subject := s.throttleSubject(scopeSignIn, userThrottleKey(id))
		st, err := s.store.GetThrottle(ctx, u.OrgID, scopeSignIn, subject)
		if err != nil {
			return fmt.Errorf("auth: read throttle: %w", err)
		}
		if err := s.store.DeleteThrottle(ctx, u.OrgID, scopeSignIn, subject); err != nil {
			return fmt.Errorf("auth: clear throttle: %w", err)
		}
		return s.writeAudit(ctx, u.OrgID, by, id, ActionPasswordReset, nil,
			PasswordResetAfter{EndedSessionIDs: ended, LockCleared: st.Locked(now)})
	})
}

// EndAllSessions ends every session of a user on behalf of a feature (FR-054) and returns how
// many it ended.
func (s *Service) EndAllSessions(ctx context.Context, id uuid.UUID, feature string, by audit.Actor) (int, error) {
	var n int
	err := s.inTx(ctx, func(ctx context.Context) error {
		u, err := s.store.LockUser(ctx, id)
		if err != nil {
			return fmt.Errorf("auth: lock user: %w", err)
		}
		ended, err := s.store.EndUserSessions(ctx, id, uuid.Nil, featureEndedReason, s.now())
		if err != nil {
			return fmt.Errorf("auth: end sessions: %w", err)
		}
		n = len(ended)
		if n == 0 {
			return nil
		}
		return s.writeAudit(ctx, u.OrgID, by, id, ActionSessionEndedByFeature, nil,
			SessionsEndedAfter{SessionIDs: ended, Feature: feature})
	})
	if err != nil {
		return 0, err
	}
	return n, nil
}

// ReplaceEmail replaces a stored email after 007 approved it (FR-055). Status and sessions stay.
func (s *Service) ReplaceEmail(ctx context.Context, id uuid.UUID, email string, by audit.Actor) error {
	value, err := NormalizeEmail(email)
	if err != nil {
		return err
	}
	return s.replaceContact(ctx, id, KindEmail, value, by)
}

// ReplaceMobile replaces a stored mobile after 007 approved it (FR-055). Status and sessions stay.
func (s *Service) ReplaceMobile(ctx context.Context, id uuid.UUID, mobile string, by audit.Actor) error {
	value, err := NormalizeMobile(mobile)
	if err != nil {
		return err
	}
	return s.replaceContact(ctx, id, KindMobile, value, by)
}

func (s *Service) replaceContact(ctx context.Context, id uuid.UUID, kind IdentifierKind, value string, by audit.Actor) error {
	return s.inTx(ctx, func(ctx context.Context) error {
		u, err := s.store.LockUser(ctx, id)
		if err != nil {
			return fmt.Errorf("auth: lock user: %w", err)
		}
		if err := s.store.ReplaceContact(ctx, id, kind, value, s.now()); err != nil {
			return fmt.Errorf("auth: replace contact: %w", err)
		}
		before, after := ContactValue{Email: u.Email}, ContactValue{Email: value}
		if kind == KindMobile {
			before, after = ContactValue{Mobile: u.Mobile}, ContactValue{Mobile: value}
		}
		return s.writeAudit(ctx, u.OrgID, by, id, ActionUserContactReplaced, before, after)
	})
}

// FindUser returns the user whose email or mobile equals identifier after normalisation, in any
// status and role (the caller decides what a status or role means). It reads only, on the
// caller's transaction when there is one. ErrInvalidIdentifier for a malformed identifier,
// ErrUserNotFound for an unknown one; errors never echo the identifier.
func (s *Service) FindUser(ctx context.Context, identifier string) (UserView, error) {
	kind, value, err := NormalizeIdentifier(identifier)
	if err != nil {
		return UserView{}, fmt.Errorf("auth: find user: %w", err)
	}
	u, err := s.store.FindUserByIdentifier(ctx, kind, value)
	if err != nil {
		return UserView{}, fmt.Errorf("auth: find user: %w", err)
	}
	return viewOf(u), nil
}

// DefaultOrg returns the id of the one organisation of the deployment (ErrNoOrg when there is
// none, ErrMultipleOrgs when there are several).
func (s *Service) DefaultOrg(ctx context.Context) (uuid.UUID, error) {
	return s.store.DefaultOrg(ctx)
}
