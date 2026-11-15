package auth

import (
	"context"
	"errors"
	"fmt"

	"github.com/NandanMaheta/swastik/apps/api/internal/platform/authz"
)

// errPasswordChanged is raised inside the change transaction when the stored hash is no longer the
// one the current password was verified against.
var errPasswordChanged = errors.New("auth: password changed concurrently")

// ChangePassword changes the caller's password (P-06): ErrReauthFailed for a wrong or locked
// current password, *PolicyError for a weak new one. All other sessions end, the current one
// stays. Argon2 runs outside any transaction.
func (s *Service) ChangePassword(ctx context.Context, p authz.Principal, current, next string) error {
	// One retry when the hash moved between the verify and the lock.
	for range 2 {
		err := s.changePasswordOnce(ctx, p, NormalizePassword(current), NormalizePassword(next))
		if !errors.Is(err, errPasswordChanged) {
			return err
		}
	}
	return ErrBusy
}

func (s *Service) changePasswordOnce(ctx context.Context, p authz.Principal, current, next string) error {
	user, err := s.store.GetUser(ctx, p.UserID)
	if err != nil {
		return fmt.Errorf("auth: read user: %w", err)
	}
	subject := s.throttleSubject(scopeSignIn, userThrottleKey(user.ID))
	st, err := s.store.GetThrottle(ctx, user.OrgID, scopeSignIn, subject)
	if err != nil {
		return fmt.Errorf("auth: read throttle: %w", err)
	}
	if st.Locked(s.now()) { // no verification at all while locked (Constitution Check I)
		return ErrReauthFailed
	}
	if err := CheckPolicy(next, user.Email, user.Mobile); err != nil {
		return err
	}
	ok, err := s.hasher.Verify(ctx, user.PasswordHash, current)
	if err != nil {
		return fmt.Errorf("auth: verify password: %w", err)
	}
	if !ok {
		// Safe retry: the change already happened if the new password is the stored one.
		if done, err := s.hasher.Verify(ctx, user.PasswordHash, next); err == nil && done {
			return nil
		}
		return s.failReauth(ctx, user, subject, p.IP)
	}
	if current == next {
		return &PolicyError{Code: PolicyUnchanged}
	}
	phc, err := s.hasher.Hash(ctx, next)
	if err != nil {
		return fmt.Errorf("auth: hash password: %w", err)
	}
	return s.inTx(ctx, func(ctx context.Context) error {
		u, err := s.store.LockUser(ctx, user.ID)
		if err != nil {
			return fmt.Errorf("auth: lock user: %w", err)
		}
		if u.PasswordHash != user.PasswordHash {
			return errPasswordChanged
		}
		now := s.now()
		if err := s.store.ChangePassword(ctx, u.ID, phc, now); err != nil {
			return fmt.Errorf("auth: change password: %w", err)
		}
		ended, err := s.store.EndUserSessions(ctx, u.ID, p.SessionID, "password_changed", now)
		if err != nil {
			return fmt.Errorf("auth: end sessions: %w", err)
		}
		if _, err := s.store.InvalidateUserChallenges(ctx, u.ID, now); err != nil {
			return err
		}
		return s.writeAudit(ctx, u.OrgID, p.AuditActor(), u.ID, ActionPasswordChanged, nil, EndedSessionsAfter{EndedSessionIDs: ended})
	})
}

// failReauth counts a wrong current password toward the account lockout (D-08) and audits it.
func (s *Service) failReauth(ctx context.Context, u UserRow, subject []byte, ip string) error {
	return s.failReauthWith(ctx, u, subject, ReasonWrongCurrentPassword, ip)
}

// accountIdentifierKind is the kind of the identifier an account signs in with: the email, or the
// mobile number for an account without one.
func accountIdentifierKind(u UserRow) IdentifierKind {
	if u.Email == "" && u.Mobile != "" {
		return KindMobile
	}
	return KindEmail
}

// failReauthWith counts one failed re-authentication (a wrong password or second factor) toward
// the account lockout and audits it with the internal reason. It always returns ErrReauthFailed
// unless the bookkeeping itself fails.
func (s *Service) failReauthWith(ctx context.Context, u UserRow, subject []byte, reason, ip string) error {
	err := s.inTx(ctx, func(ctx context.Context) error {
		next, started, err := s.applyFailure(ctx, u.OrgID, scopeSignIn, subject, signInPolicy)
		if err != nil {
			return err
		}
		if err := s.writeAudit(ctx, u.OrgID, systemActor, u.ID, ActionSignInFailed, nil,
			SignInFailedAfter{Reason: reason, IdentifierKind: string(accountIdentifierKind(u)), IP: ip}); err != nil {
			return err
		}
		if !started {
			return nil
		}
		return s.writeAudit(ctx, u.OrgID, systemActor, u.ID, ActionLockoutStarted, nil,
			LockoutStartedAfter{LockedUntil: *next.LockedUntil})
	})
	if err != nil {
		return err
	}
	return ErrReauthFailed
}
