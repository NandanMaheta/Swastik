package auth

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/NandanMaheta/swastik/apps/api/internal/platform/crypto"
)

// Session lifetimes by role (D-06): idle time is measured from sign-in or the last refresh, the
// absolute limit from sign-in.
const (
	clientIdleLifetime     = 30 * 24 * time.Hour
	clientAbsoluteLifetime = 90 * 24 * time.Hour
	adminIdleLifetime      = 12 * time.Hour
	adminAbsoluteLifetime  = 7 * 24 * time.Hour

	challengeLifetime = 5 * time.Minute
	challengePrefix   = "dmc_"
	refreshPrefix     = "drt_"
)

func idleLifetime(role string) time.Duration {
	if role == roleAdmin {
		return adminIdleLifetime
	}
	return clientIdleLifetime
}

func absoluteLifetime(role string) time.Duration {
	if role == roleAdmin {
		return adminAbsoluteLifetime
	}
	return clientAbsoluteLifetime
}

// Raised inside the success transaction when the state changed while the password was hashed.
var (
	errRecheckNotActive = errors.New("auth: user is no longer active")
	errRecheckLocked    = errors.New("auth: user became locked")
)

// attempt is what one sign-in knows about its subject; the failure path needs nothing else.
type attempt struct {
	org     uuid.UUID
	userID  uuid.UUID // uuid.Nil when no account matched
	kind    IdentifierKind
	subject []byte
	ip      string
}

// SignIn is the password step for clients and admins (P-08). It performs exactly one Argon2
// verify, real or dummy, outside any transaction; every failure is the same ErrInvalidCredentials.
func (s *Service) SignIn(ctx context.Context, in SignInInput) (SignInResult, error) {
	kind, value, err := NormalizeIdentifier(in.Identifier)
	if err != nil {
		return SignInResult{}, err // validation, not an attempt: nothing counted, nothing audited
	}
	org, err := s.store.DefaultOrg(ctx)
	if err != nil {
		return SignInResult{}, fmt.Errorf("auth: default org: %w", err)
	}
	user, matched, err := s.findUser(ctx, kind, value)
	if err != nil {
		return SignInResult{}, err
	}
	key, phc := string(kind)+"|"+value, ""
	if matched {
		key, phc = userThrottleKey(user.ID), user.PasswordHash
	}
	a := attempt{org: org, kind: kind, subject: s.throttleSubject(scopeSignIn, key), ip: in.IP}
	if matched {
		a.userID = user.ID
	}
	st, err := s.store.GetThrottle(ctx, org, scopeSignIn, a.subject)
	if err != nil {
		return SignInResult{}, fmt.Errorf("auth: read throttle: %w", err)
	}
	locked := st.Locked(s.now())

	// The one Argon2 run of this attempt; with no account it runs against the dummy hash.
	password := NormalizePassword(in.Password)
	ok, err := s.hasher.Verify(ctx, phc, password)
	if err != nil {
		return SignInResult{}, fmt.Errorf("auth: verify password: %w", err)
	}

	switch {
	case locked:
		return SignInResult{}, s.failSignIn(ctx, a, ReasonLocked, false)
	case !matched:
		return SignInResult{}, s.failSignIn(ctx, a, ReasonUnknownIdentifier, true)
	case !ok:
		return SignInResult{}, s.failSignIn(ctx, a, ReasonWrongPassword, true)
	case user.Status != StatusActive:
		return SignInResult{}, s.failSignIn(ctx, a, ReasonNotActive, false)
	}

	newPHC := ""
	if s.hasher.NeedsRehash(user.PasswordHash) {
		if newPHC, err = s.hasher.Hash(ctx, password); err != nil {
			s.log.WarnContext(ctx, "auth: rehash skipped", "err", err)
			newPHC = ""
		}
	}
	var res SignInResult
	err = s.inTx(ctx, func(ctx context.Context) error {
		var err error
		res, err = s.completeSignIn(ctx, a, user, in, newPHC)
		return err
	})
	switch {
	case errors.Is(err, errRecheckNotActive):
		return SignInResult{}, s.failSignIn(ctx, a, ReasonNotActive, false)
	case errors.Is(err, errRecheckLocked):
		return SignInResult{}, s.failSignIn(ctx, a, ReasonLocked, false)
	case err != nil:
		return SignInResult{}, err
	}
	return res, nil
}

// findUser looks the identifier up. An admin found by mobile counts as no match: admins sign in
// with email only (D-04).
func (s *Service) findUser(ctx context.Context, kind IdentifierKind, value string) (UserRow, bool, error) {
	u, err := s.store.FindUserByIdentifier(ctx, kind, value)
	switch {
	case errors.Is(err, ErrUserNotFound):
		return UserRow{}, false, nil
	case err != nil:
		return UserRow{}, false, fmt.Errorf("auth: find user: %w", err)
	case kind == KindMobile && u.Role == roleAdmin:
		return UserRow{}, false, nil
	}
	return u, true, nil
}

// failSignIn records a failed attempt in one short transaction and returns the generic failure.
// A counted failure also advances the lockout and audits the lock when it starts.
func (s *Service) failSignIn(ctx context.Context, a attempt, reason string, count bool) error {
	err := s.inTx(ctx, func(ctx context.Context) error {
		var started bool
		var lockedUntil time.Time
		if count {
			next, st, err := s.applyFailure(ctx, a.org, scopeSignIn, a.subject, signInPolicy)
			if err != nil {
				return err
			}
			started = st
			if next.LockedUntil != nil {
				lockedUntil = *next.LockedUntil
			}
		}
		ref := ""
		if a.userID == uuid.Nil { // the typed identifier is never stored, only a correlation reference
			ref = hex.EncodeToString(a.subject[:8])
		}
		if err := s.writeAudit(ctx, a.org, systemActor, a.userID, ActionSignInFailed, nil,
			SignInFailedAfter{Reason: reason, IdentifierKind: string(a.kind), SubjectRef: ref, IP: a.ip}); err != nil {
			return err
		}
		if !started {
			return nil
		}
		return s.writeAudit(ctx, a.org, systemActor, a.userID, ActionLockoutStarted, nil,
			LockoutStartedAfter{LockedUntil: lockedUntil, SubjectRef: ref, IP: a.ip})
	})
	if err != nil {
		return err
	}
	return ErrInvalidCredentials
}

// completeSignIn is the success transaction (P-08 step 5): lock the user, re-check status and
// lock, then open a session (client) or issue a challenge (admin).
func (s *Service) completeSignIn(ctx context.Context, a attempt, user UserRow, in SignInInput, newPHC string) (SignInResult, error) {
	u, err := s.store.LockUser(ctx, user.ID)
	if err != nil {
		return SignInResult{}, fmt.Errorf("auth: lock user: %w", err)
	}
	now := s.now()
	if u.Status != StatusActive {
		return SignInResult{}, errRecheckNotActive
	}
	st, err := s.store.GetThrottle(ctx, a.org, scopeSignIn, a.subject)
	if err != nil {
		return SignInResult{}, fmt.Errorf("auth: read throttle: %w", err)
	}
	if st.Locked(now) {
		return SignInResult{}, errRecheckLocked
	}
	if newPHC != "" { // compare and set: a concurrent change of the hash wins
		if _, err := s.store.Rehash(ctx, u.ID, user.PasswordHash, newPHC, now); err != nil {
			return SignInResult{}, fmt.Errorf("auth: rehash: %w", err)
		}
	}
	if u.Role == roleAdmin {
		return s.issueChallenge(ctx, a, u, in, now)
	}
	tokens, err := s.openSession(ctx, a, u, in, now)
	if err != nil {
		return SignInResult{}, err
	}
	return SignInResult{NextStep: NextStepSignedIn, Session: &tokens}, nil
}

// openSession ends the installation's previous session, creates the new one with its first
// refresh token, and audits the sign-in. Signing the access token needs no database, so it
// happens here inside the transaction without holding it open on slow work.
func (s *Service) openSession(ctx context.Context, a attempt, u UserRow, in SignInInput, now time.Time) (SessionTokens, error) {
	return s.openSessionFor(ctx, a, u, sessionOrigin{Device: in.Device, ClientType: in.ClientType}, now)
}

// sessionOrigin is the installation and transport a session opens for, and for an admin the
// second factor that completed it (MFAMethod "" for a client).
type sessionOrigin struct {
	Device     DeviceInfo
	ClientType string
	MFAMethod  string
}

func (s *Service) openSessionFor(ctx context.Context, a attempt, u UserRow, in sessionOrigin, now time.Time) (SessionTokens, error) {
	// Every not-ended session counts, expired or not: the live-device unique index does.
	existing, err := s.store.ListLiveSessions(ctx, u.ID, time.Unix(0, 0))
	if err != nil {
		return SessionTokens{}, fmt.Errorf("auth: list sessions: %w", err)
	}
	var replaced *uuid.UUID
	for _, ex := range existing {
		if ex.DeviceID != in.Device.ID {
			continue
		}
		if _, err := s.store.EndSession(ctx, ex.ID, "replaced", now); err != nil {
			return SessionTokens{}, fmt.Errorf("auth: end replaced session: %w", err)
		}
		id := ex.ID
		replaced = &id
	}
	sess, err := s.store.CreateSession(ctx, NewSession{
		OrgID: u.OrgID, UserID: u.ID, DeviceID: in.Device.ID, DeviceName: in.Device.Name, Platform: in.Device.Platform,
		ClientType: in.ClientType, MFAMethod: in.MFAMethod, Now: now,
		IdleExpiresAt: now.Add(idleLifetime(u.Role)), AbsoluteExpiresAt: now.Add(absoluteLifetime(u.Role)),
	})
	if err != nil {
		return SessionTokens{}, fmt.Errorf("auth: create session: %w", err)
	}
	refresh, digest, err := crypto.NewToken(refreshPrefix)
	if err != nil {
		return SessionTokens{}, fmt.Errorf("auth: refresh token: %w", err)
	}
	if _, err := s.store.InsertRefresh(ctx, u.OrgID, sess.ID, digest, now); err != nil {
		return SessionTokens{}, fmt.Errorf("auth: insert refresh token: %w", err)
	}
	if err := s.store.RecordSignIn(ctx, u.ID, now); err != nil {
		return SessionTokens{}, fmt.Errorf("auth: record sign-in: %w", err)
	}
	// A success clears the counter of the account (D-08).
	if err := s.store.DeleteThrottle(ctx, a.org, scopeSignIn, a.subject); err != nil {
		return SessionTokens{}, fmt.Errorf("auth: clear throttle: %w", err)
	}
	if err := s.writeAudit(ctx, u.OrgID, actorOf(u), u.ID, ActionSignInSucceeded, nil,
		SignInSucceededAfter{SessionID: sess.ID, Platform: sess.Platform, ClientType: sess.ClientType, IP: a.ip, MFAMethod: in.MFAMethod, ReplacedSessionID: replaced}); err != nil {
		return SessionTokens{}, err
	}
	return s.sessionTokens(u, sess, refresh)
}

// issueChallenge gives an admin with a correct password the interim proof for the second factor.
// It is not counted as a success: the counter clears when the second factor completes.
func (s *Service) issueChallenge(ctx context.Context, a attempt, u UserRow, in SignInInput, now time.Time) (SignInResult, error) {
	purpose, next := "enrol", NextStepMFAEnrolmentNeeded
	switch m, err := s.store.GetMFA(ctx, u.ID); {
	case err == nil && m.EnrolledAt != nil:
		purpose, next = "verify", NextStepMFARequired
	case err != nil && !errors.Is(err, ErrMFANotFound):
		return SignInResult{}, fmt.Errorf("auth: read authenticator: %w", err)
	}
	token, digest, err := crypto.NewToken(challengePrefix)
	if err != nil {
		return SignInResult{}, fmt.Errorf("auth: challenge token: %w", err)
	}
	expires := now.Add(challengeLifetime)
	if _, err := s.store.CreateChallenge(ctx, NewChallenge{
		OrgID: u.OrgID, UserID: u.ID, DeviceID: in.Device.ID, TokenHash: digest, Purpose: purpose,
		DeviceName: in.Device.Name, Platform: in.Device.Platform, ClientType: in.ClientType, Now: now, ExpiresAt: expires,
	}); err != nil {
		return SignInResult{}, fmt.Errorf("auth: create challenge: %w", err)
	}
	if err := s.writeAudit(ctx, u.OrgID, systemActor, u.ID, ActionMFAChallengeIssued, nil,
		ChallengeIssuedAfter{Purpose: purpose, Platform: in.Device.Platform, IP: a.ip}); err != nil {
		return SignInResult{}, err
	}
	return SignInResult{NextStep: next, Challenge: &Challenge{Token: token, ExpiresAt: expires}}, nil
}

// sessionTokens signs the access token of a session and assembles the response.
func (s *Service) sessionTokens(u UserRow, sess SessionRow, refresh string) (SessionTokens, error) {
	access, err := s.tokens.Issue(AccessSubject{UserID: u.ID, SessionID: sess.ID, OrgID: sess.OrgID, Role: u.Role}, sess.AbsoluteExpiresAt)
	if err != nil {
		return SessionTokens{}, fmt.Errorf("auth: access token: %w", err)
	}
	return SessionTokens{
		AccessToken: access, AccessTokenExpiresAt: s.accessExpiry(sess.AbsoluteExpiresAt),
		RefreshToken: refresh, SessionID: sess.ID, SessionExpiresAt: sess.AbsoluteExpiresAt, IdleExpiresAt: sess.IdleExpiresAt,
		User: UserSummary{ID: u.ID, Role: u.Role, Name: u.Name, Email: u.Email},
	}, nil
}

// accessExpiry mirrors Tokens.Issue: min(now+15m, absolute limit) in whole seconds.
func (s *Service) accessExpiry(absolute time.Time) time.Time {
	return time.Unix(min(s.now().Add(accessLifetime).Unix(), absolute.Unix()), 0).UTC()
}
