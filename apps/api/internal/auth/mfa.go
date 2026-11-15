package auth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/NandanMaheta/swastik/apps/api/internal/platform/crypto"
)

// The admin second-factor flow (plan P-05, US-5): verify, enrolment, and the TOTP helpers shared
// with mfa_manage.go.

// ErrInvalidChallenge is every failure of the interim challenge proof at the service level: unknown,
// expired, already consumed, wrong purpose, or the user is no longer an active admin. It never
// names the cause; the HTTP layer answers it as auth.unauthenticated.
var ErrInvalidChallenge = errInvalidChallenge

// MFAVerifyInput completes the second factor of a sign-in. ChallengeToken is the raw dmc_ token
// from the Authorization header. Exactly one of Code and RecoveryCode is set. IP is the resolved
// client address.
type MFAVerifyInput struct {
	ChallengeToken string
	Code           string
	RecoveryCode   string
	IP             string
}

// TOTPEnrolment is a new authenticator secret, shown once.
type TOTPEnrolment struct {
	Secret     string // base32, no padding
	OTPAuthURI string
}

// EnrolmentConfirmInput confirms enrolment with a code from the pending secret.
type EnrolmentConfirmInput struct {
	ChallengeToken string
	Code           string
	IP             string
}

// EnrolmentResult is a completed enrolment: the admin session and the 10 recovery codes, shown once.
type EnrolmentResult struct {
	Session       SessionTokens
	RecoveryCodes []string
}

// Purposes of an mfa_challenges row and the mfa_method values of a session.
const (
	purposeVerify = "verify"
	purposeEnrol  = "enrol"

	methodTOTP         = "totp"
	methodRecoveryCode = "recovery_code"
	methodEnrolment    = "enrolment"
)

// Associated data of the sealed authenticator secrets (P-05). A confirmed secret is the pending
// envelope copied by the store, so a confirmed secret may open under either.
const (
	aadSecret  = "admin_mfa.secret:"
	aadPending = "admin_mfa.pending_secret:"
)

// errWrongFactor is raised inside a transaction that must roll back because the second factor was
// wrong; the caller counts the failure in a transaction of its own.
var errWrongFactor = errors.New("auth: wrong second factor")

// VerifyMFA completes an admin sign-in with a TOTP code or a recovery code (P-05). A wrong or
// replayed code, or a locked account, is ErrInvalidCredentials (a wrong code counts toward the
// lockout); a bad challenge is ErrInvalidChallenge. On success the challenge is consumed, the
// session is created with its first refresh token, the sign-in counter is cleared and
// auth.sign_in.succeeded (mfa_method totp or recovery_code) is audited.
func (s *Service) VerifyMFA(ctx context.Context, in MFAVerifyInput) (SessionTokens, error) {
	ch, _, err := s.challenge(ctx, in.ChallengeToken, purposeVerify)
	if err != nil {
		return SessionTokens{}, err
	}
	a := s.mfaAttempt(ch, in.IP)
	reason := ReasonWrongTOTP
	if in.RecoveryCode != "" {
		reason = ReasonWrongRecoveryCode
	}
	st, err := s.store.GetThrottle(ctx, ch.OrgID, scopeSignIn, a.subject)
	if err != nil {
		return SessionTokens{}, fmt.Errorf("auth: read throttle: %w", err)
	}
	if st.Locked(s.now()) { // a correct code is not even looked at while locked (D-08)
		return SessionTokens{}, s.failSignIn(ctx, a, ReasonLocked, false)
	}

	var out SessionTokens
	err = s.inTx(ctx, func(ctx context.Context) error {
		var err error
		out, err = s.completeVerify(ctx, a, ch, in)
		return err
	})
	switch {
	case errors.Is(err, errWrongFactor):
		return SessionTokens{}, s.failSignIn(ctx, a, reason, true)
	case errors.Is(err, errRecheckLocked):
		return SessionTokens{}, s.failSignIn(ctx, a, ReasonLocked, false)
	case err != nil:
		return SessionTokens{}, err
	}
	return out, nil
}

// completeVerify is the success transaction of VerifyMFA. The user row lock comes first and
// serialises everything that touches this admin's second factor (sign-in, disable, replacement),
// then the authenticator row, then the challenge.
func (s *Service) completeVerify(ctx context.Context, a attempt, ch ChallengeRow, in MFAVerifyInput) (SessionTokens, error) {
	u, err := s.store.LockUser(ctx, ch.UserID)
	if err != nil {
		return SessionTokens{}, fmt.Errorf("auth: lock user: %w", err)
	}
	if u.Role != roleAdmin || u.Status != StatusActive {
		return SessionTokens{}, ErrInvalidChallenge
	}
	now := s.now()
	if st, err := s.store.GetThrottle(ctx, a.org, scopeSignIn, a.subject); err != nil {
		return SessionTokens{}, fmt.Errorf("auth: read throttle: %w", err)
	} else if st.Locked(now) {
		return SessionTokens{}, errRecheckLocked
	}
	m, err := s.store.LockMFA(ctx, u.ID)
	switch {
	case errors.Is(err, ErrMFANotFound):
		return SessionTokens{}, ErrInvalidChallenge
	case err != nil:
		return SessionTokens{}, fmt.Errorf("auth: lock authenticator: %w", err)
	case m.EnrolledAt == nil || m.SecretEnc == nil:
		return SessionTokens{}, ErrInvalidChallenge
	}
	method, err := s.checkSecondFactor(ctx, u, m, in.Code, in.RecoveryCode, "sign_in", now)
	if err != nil {
		return SessionTokens{}, err
	}
	if ok, err := s.store.ConsumeChallenge(ctx, ch.ID, now); err != nil {
		return SessionTokens{}, fmt.Errorf("auth: consume challenge: %w", err)
	} else if !ok {
		return SessionTokens{}, ErrInvalidChallenge
	}
	return s.openSessionFor(ctx, a, u, sessionOrigin{
		Device:     DeviceInfo{ID: ch.DeviceID, Name: ch.DeviceName, Platform: ch.Platform},
		ClientType: ch.ClientType, MFAMethod: method,
	}, now)
}

// checkSecondFactor verifies exactly one of a TOTP code against the confirmed secret (advancing the
// replay guard) and a recovery code (consuming it and auditing the use), under the authenticator
// row lock the caller holds. It returns the session mfa_method, or errWrongFactor.
func (s *Service) checkSecondFactor(ctx context.Context, u UserRow, m MFARow, code, recovery, usedIn string, now time.Time) (string, error) {
	switch {
	case code != "" && recovery == "":
		secret, err := s.openSecret(u.ID, m.SecretEnc, aadSecret, aadPending)
		if err != nil {
			return "", err
		}
		step, ok := VerifyTOTP(secret, code, now, m.LastUsedStep)
		if !ok {
			return "", errWrongFactor
		}
		if advanced, err := s.store.AdvanceStep(ctx, u.ID, step, now); err != nil {
			return "", fmt.Errorf("auth: advance step: %w", err)
		} else if !advanced {
			return "", errWrongFactor
		}
		return methodTOTP, nil
	case recovery != "" && code == "":
		left, ok, err := s.store.UseRecoveryCode(ctx, u.ID, RecoveryCodeDigest(recovery), now)
		if err != nil {
			return "", fmt.Errorf("auth: use recovery code: %w", err)
		}
		if !ok {
			return "", errWrongFactor
		}
		if err := s.writeAudit(ctx, u.OrgID, actorOf(u), u.ID, ActionMFARecoveryCodeUsed, nil,
			RecoveryCodeUsedAfter{Remaining: left, Context: usedIn}); err != nil {
			return "", err
		}
		return methodRecoveryCode, nil
	}
	return "", errWrongFactor
}

// mfaAttempt is the throttle subject of a challenge's admin: the same per-account counter as the
// password step, so the two factors share one lockout.
func (s *Service) mfaAttempt(ch ChallengeRow, ip string) attempt {
	return attempt{
		org: ch.OrgID, userID: ch.UserID, kind: KindEmail, ip: ip,
		subject: s.throttleSubject(scopeSignIn, userThrottleKey(ch.UserID)),
	}
}

// challenge resolves a challenge token of the given purpose to its row and admin. Every problem
// (unknown, consumed, expired, wrong purpose, user no longer an active admin) is
// ErrInvalidChallenge and counts as nothing.
func (s *Service) challenge(ctx context.Context, token, purpose string) (ChallengeRow, UserRow, error) {
	if token == "" || len(token) > maxTokenLength {
		return ChallengeRow{}, UserRow{}, ErrInvalidChallenge
	}
	ch, err := s.store.FindChallengeByHash(ctx, crypto.Digest(token))
	switch {
	case errors.Is(err, ErrChallengeNotFound):
		return ChallengeRow{}, UserRow{}, ErrInvalidChallenge
	case err != nil:
		return ChallengeRow{}, UserRow{}, fmt.Errorf("auth: find challenge: %w", err)
	}
	if ch.Purpose != purpose || ch.ConsumedAt != nil || !s.now().Before(ch.ExpiresAt) {
		return ChallengeRow{}, UserRow{}, ErrInvalidChallenge
	}
	u, err := s.store.GetUser(ctx, ch.UserID)
	switch {
	case errors.Is(err, ErrUserNotFound):
		return ChallengeRow{}, UserRow{}, ErrInvalidChallenge
	case err != nil:
		return ChallengeRow{}, UserRow{}, fmt.Errorf("auth: read user: %w", err)
	case u.Role != roleAdmin || u.Status != StatusActive:
		return ChallengeRow{}, UserRow{}, ErrInvalidChallenge
	}
	return ch, u, nil
}

// openSecret opens a stored authenticator envelope under the first AAD that works.
func (s *Service) openSecret(user uuid.UUID, envelope []byte, aads ...string) (string, error) {
	for _, aad := range aads {
		if pt, err := s.keyring.Open(envelope, []byte(aad+user.String())); err == nil {
			return string(pt), nil
		}
	}
	return "", errors.New("auth: the authenticator secret does not open")
}

// newPendingSecret generates a TOTP secret for the admin and seals it as a pending secret.
func (s *Service) newPendingSecret(u UserRow) (TOTPEnrolment, []byte, error) {
	secret, uri, err := GenerateTOTP(u.Email)
	if err != nil {
		return TOTPEnrolment{}, nil, err
	}
	enc, err := s.keyring.Seal([]byte(secret), []byte(aadPending+u.ID.String()))
	if err != nil {
		return TOTPEnrolment{}, nil, fmt.Errorf("auth: seal authenticator secret: %w", err)
	}
	return TOTPEnrolment{Secret: secret, OTPAuthURI: uri}, enc, nil
}

// StartEnrolment creates (or replaces) the pending authenticator secret of the challenge's admin.
// The challenge must have purpose enrol (ErrInvalidChallenge otherwise) and is not consumed.
func (s *Service) StartEnrolment(ctx context.Context, token string) (TOTPEnrolment, error) {
	ch, u, err := s.challenge(ctx, token, purposeEnrol)
	if err != nil {
		return TOTPEnrolment{}, err
	}
	enrolment, enc, err := s.newPendingSecret(u)
	if err != nil {
		return TOTPEnrolment{}, err
	}
	err = s.inTx(ctx, func(ctx context.Context) error {
		if _, err := s.store.LockUser(ctx, u.ID); err != nil {
			return fmt.Errorf("auth: lock user: %w", err)
		}
		if m, err := s.store.GetMFA(ctx, u.ID); err == nil && m.EnrolledAt != nil {
			return ErrInvalidChallenge // enrolled meanwhile: this challenge is stale
		} else if err != nil && !errors.Is(err, ErrMFANotFound) {
			return fmt.Errorf("auth: read authenticator: %w", err)
		}
		return s.store.SetPendingSecret(ctx, ch.OrgID, u.ID, enc, s.now())
	})
	if err != nil {
		return TOTPEnrolment{}, err
	}
	return enrolment, nil
}

// ConfirmEnrolment confirms the pending secret with a valid code, stores it as the authenticator,
// issues 10 recovery codes and opens the admin session, consuming the challenge. ErrNoPendingSecret
// when there is no pending secret; ErrInvalidCredentials for a wrong code (nothing consumed).
func (s *Service) ConfirmEnrolment(ctx context.Context, in EnrolmentConfirmInput) (EnrolmentResult, error) {
	ch, _, err := s.challenge(ctx, in.ChallengeToken, purposeEnrol)
	if err != nil {
		return EnrolmentResult{}, err
	}
	a := s.mfaAttempt(ch, in.IP)
	st, err := s.store.GetThrottle(ctx, ch.OrgID, scopeSignIn, a.subject)
	if err != nil {
		return EnrolmentResult{}, fmt.Errorf("auth: read throttle: %w", err)
	}
	if st.Locked(s.now()) {
		return EnrolmentResult{}, s.failSignIn(ctx, a, ReasonLocked, false)
	}
	codes, err := GenerateRecoveryCodes()
	if err != nil {
		return EnrolmentResult{}, err
	}
	var out EnrolmentResult
	err = s.inTx(ctx, func(ctx context.Context) error {
		var err error
		out, err = s.completeEnrolment(ctx, a, ch, in, codes)
		return err
	})
	switch {
	case errors.Is(err, errWrongFactor):
		return EnrolmentResult{}, s.failSignIn(ctx, a, ReasonWrongTOTP, true)
	case errors.Is(err, errRecheckLocked):
		return EnrolmentResult{}, s.failSignIn(ctx, a, ReasonLocked, false)
	case err != nil:
		return EnrolmentResult{}, err
	}
	return out, nil
}

func (s *Service) completeEnrolment(ctx context.Context, a attempt, ch ChallengeRow, in EnrolmentConfirmInput, codes []string) (EnrolmentResult, error) {
	u, err := s.store.LockUser(ctx, ch.UserID)
	if err != nil {
		return EnrolmentResult{}, fmt.Errorf("auth: lock user: %w", err)
	}
	if u.Role != roleAdmin || u.Status != StatusActive {
		return EnrolmentResult{}, ErrInvalidChallenge
	}
	now := s.now()
	if st, err := s.store.GetThrottle(ctx, a.org, scopeSignIn, a.subject); err != nil {
		return EnrolmentResult{}, fmt.Errorf("auth: read throttle: %w", err)
	} else if st.Locked(now) {
		return EnrolmentResult{}, errRecheckLocked
	}
	m, err := s.store.LockMFA(ctx, u.ID)
	switch {
	case errors.Is(err, ErrMFANotFound):
		return EnrolmentResult{}, ErrNoPendingSecret
	case err != nil:
		return EnrolmentResult{}, fmt.Errorf("auth: lock authenticator: %w", err)
	case m.EnrolledAt != nil:
		return EnrolmentResult{}, ErrInvalidChallenge // enrolled meanwhile: this challenge is stale
	case m.PendingSecretEnc == nil:
		return EnrolmentResult{}, ErrNoPendingSecret
	}
	secret, err := s.openSecret(u.ID, m.PendingSecretEnc, aadPending)
	if err != nil {
		return EnrolmentResult{}, err
	}
	step, ok := VerifyTOTP(secret, in.Code, now, 0)
	if !ok {
		return EnrolmentResult{}, errWrongFactor
	}
	if err := s.store.ConfirmPending(ctx, u.ID, step, now); err != nil {
		return EnrolmentResult{}, fmt.Errorf("auth: confirm authenticator: %w", err)
	}
	hashes := make([][]byte, len(codes))
	for i, c := range codes {
		hashes[i] = RecoveryCodeDigest(c)
	}
	if _, err := s.store.ReplaceRecoveryCodes(ctx, u.OrgID, u.ID, uuid.New(), hashes, now); err != nil {
		return EnrolmentResult{}, fmt.Errorf("auth: store recovery codes: %w", err)
	}
	if consumed, err := s.store.ConsumeChallenge(ctx, ch.ID, now); err != nil {
		return EnrolmentResult{}, fmt.Errorf("auth: consume challenge: %w", err)
	} else if !consumed {
		return EnrolmentResult{}, ErrInvalidChallenge
	}
	tokens, err := s.openSessionFor(ctx, a, u, sessionOrigin{
		Device:     DeviceInfo{ID: ch.DeviceID, Name: ch.DeviceName, Platform: ch.Platform},
		ClientType: ch.ClientType, MFAMethod: methodEnrolment,
	}, now)
	if err != nil {
		return EnrolmentResult{}, err
	}
	if err := s.writeAudit(ctx, u.OrgID, actorOf(u), u.ID, ActionMFAEnrolled, nil, SessionEventAfter{SessionID: tokens.SessionID, IP: in.IP}); err != nil {
		return EnrolmentResult{}, err
	}
	return EnrolmentResult{Session: tokens, RecoveryCodes: codes}, nil
}
