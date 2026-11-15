package auth

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// scopeSignIn is the auth_throttles scope of sign-in, change-password and (later) MFA failures.
const scopeSignIn = "signin"

// signInPolicy is the lockout of D-08: 5 counted failures within 15 minutes lock for 15 minutes.
var signInPolicy = ThrottlePolicy{MaxFailures: 5, Window: 15 * time.Minute, Lock: 15 * time.Minute}

// throttleSubject is the stored subject of a key: the blind index of "scope|key", so the key
// (an email, a mobile) is never stored as given (plan P-07).
func (s *Service) throttleSubject(scope, key string) []byte {
	return s.blind.Index("throttle", []byte(scope+"|"+key))
}

// userThrottleKey is the key of an account that matched: the lock is per account, so a client's
// email and mobile share one counter.
func userThrottleKey(id uuid.UUID) string { return "user|" + id.String() }

// applyFailure records one counted failure under the row lock of the subject and returns the new
// state. It requires a transaction (the store returns db.ErrNoTx otherwise).
func (s *Service) applyFailure(ctx context.Context, org uuid.UUID, scope string, subject []byte, p ThrottlePolicy) (ThrottleState, bool, error) {
	now := s.now()
	st, err := s.store.LockThrottle(ctx, org, scope, subject, now)
	if err != nil {
		return ThrottleState{}, false, fmt.Errorf("auth: lock throttle: %w", err)
	}
	next, started := ApplyThrottle(st, now, p)
	if err := s.store.SaveThrottle(ctx, org, scope, subject, next, now); err != nil {
		return ThrottleState{}, false, fmt.Errorf("auth: save throttle: %w", err)
	}
	return next, started, nil
}

// Check reports until when the subject is locked, nil when it is not.
func (s *Service) Check(ctx context.Context, orgID uuid.UUID, scope, key string) (*time.Time, error) {
	st, err := s.store.GetThrottle(ctx, orgID, scope, s.throttleSubject(scope, key))
	if err != nil {
		return nil, fmt.Errorf("auth: check throttle: %w", err)
	}
	return lockedUntil(st, s.now()), nil
}

// Fail records one counted failure for the subject. It requires a transaction in ctx.
func (s *Service) Fail(ctx context.Context, orgID uuid.UUID, scope, key string, p ThrottlePolicy) (bool, *time.Time, error) {
	st, started, err := s.applyFailure(ctx, orgID, scope, s.throttleSubject(scope, key), p)
	if err != nil {
		return false, nil, err
	}
	return started, lockedUntil(st, s.now()), nil
}

// Clear removes the failure record of the subject. It requires a transaction in ctx.
func (s *Service) Clear(ctx context.Context, orgID uuid.UUID, scope, key string) error {
	if err := s.store.DeleteThrottle(ctx, orgID, scope, s.throttleSubject(scope, key)); err != nil {
		return fmt.Errorf("auth: clear throttle: %w", err)
	}
	return nil
}

// lockedUntil is the end of the lock when st is locked at now, otherwise nil.
func lockedUntil(st ThrottleState, now time.Time) *time.Time {
	if !st.Locked(now) {
		return nil
	}
	until := *st.LockedUntil
	return &until
}
