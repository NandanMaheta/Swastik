package auth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/NandanMaheta/swastik/apps/api/internal/platform/authz"
)

// Admin management of the second factor by a signed-in admin (FR-062, FR-063, plan P-05).

// Reauth is the re-authentication of a signed-in admin: the password plus exactly one of a current
// TOTP code and an unused recovery code.
type Reauth struct {
	Password     string
	Code         string
	RecoveryCode string
}

// RegenerateRecoveryCodes re-authenticates with the password and a current TOTP code, then issues a
// new set of 10 codes and revokes the previous set (auth.mfa.recovery_codes_regenerated). A wrong
// password or code, or a locked account, is ErrReauthFailed; wrong attempts count toward the
// lockout.
func (s *Service) RegenerateRecoveryCodes(ctx context.Context, p authz.Principal, password, code string) ([]string, error) {
	codes, err := GenerateRecoveryCodes()
	if err != nil {
		return nil, err
	}
	batch := uuid.New()
	hashes := make([][]byte, len(codes))
	for i, c := range codes {
		hashes[i] = RecoveryCodeDigest(c)
	}
	err = s.reauthenticate(ctx, p, password, ReasonWrongTOTP, func(ctx context.Context, u UserRow, m MFARow, now time.Time) error {
		if _, err := s.checkSecondFactor(ctx, u, m, code, "", "", now); err != nil {
			return err
		}
		if _, err := s.store.ReplaceRecoveryCodes(ctx, u.OrgID, u.ID, batch, hashes, now); err != nil {
			return fmt.Errorf("auth: store recovery codes: %w", err)
		}
		return s.writeAudit(ctx, u.OrgID, p.AuditActor(), u.ID, ActionMFARecoveryRegenerated, nil,
			RecoveryCodesRegeneratedAfter{BatchID: batch, Count: len(codes)})
	})
	if err != nil {
		return nil, err
	}
	return codes, nil
}

// StartAuthenticatorReplace re-authenticates (a recovery code is consumed and audited) and stores
// a new pending secret; the old one keeps working until the replacement is confirmed.
func (s *Service) StartAuthenticatorReplace(ctx context.Context, p authz.Principal, in Reauth) (TOTPEnrolment, error) {
	var out TOTPEnrolment
	reason := ReasonWrongTOTP
	if in.RecoveryCode != "" {
		reason = ReasonWrongRecoveryCode
	}
	err := s.reauthenticate(ctx, p, in.Password, reason, func(ctx context.Context, u UserRow, m MFARow, now time.Time) error {
		if _, err := s.checkSecondFactor(ctx, u, m, in.Code, in.RecoveryCode, "replace", now); err != nil {
			return err
		}
		enrolment, enc, err := s.newPendingSecret(u)
		if err != nil {
			return err
		}
		if err := s.store.SetPendingSecret(ctx, u.OrgID, u.ID, enc, now); err != nil {
			return fmt.Errorf("auth: store pending secret: %w", err)
		}
		if err := s.writeAudit(ctx, u.OrgID, p.AuditActor(), u.ID, ActionMFAPendingSecretSet, nil,
			PendingSecretSetAfter{Context: "replace"}); err != nil {
			return err
		}
		out = enrolment
		return nil
	})
	if err != nil {
		return TOTPEnrolment{}, err
	}
	return out, nil
}

// reauthenticate runs fn for a signed-in admin who proved the password, in one transaction under
// the user and authenticator row locks. The password is verified first, outside any transaction;
// fn checks the second factor and does the work; a wrong factor is audited with factorReason. A wrong password, a wrong factor or a locked
// account is ErrReauthFailed; the first two count toward the lockout, and the locked case
// verifies nothing and consumes nothing.
func (s *Service) reauthenticate(ctx context.Context, p authz.Principal, password, factorReason string,
	fn func(ctx context.Context, u UserRow, m MFARow, now time.Time) error) error {
	user, err := s.store.GetUser(ctx, p.UserID)
	if err != nil {
		return fmt.Errorf("auth: read user: %w", err)
	}
	subject := s.throttleSubject(scopeSignIn, userThrottleKey(user.ID))
	if err := s.refuseWhileLocked(ctx, user, subject); err != nil {
		return err
	}
	ok, err := s.hasher.Verify(ctx, user.PasswordHash, NormalizePassword(password))
	if err != nil {
		return fmt.Errorf("auth: verify password: %w", err)
	}
	if !ok {
		return s.failReauthWith(ctx, user, subject, ReasonWrongPassword, p.IP)
	}
	err = s.inTx(ctx, func(ctx context.Context) error {
		u, err := s.store.LockUser(ctx, user.ID)
		if err != nil {
			return fmt.Errorf("auth: lock user: %w", err)
		}
		if u.Role != roleAdmin || u.Status != StatusActive {
			return ErrReauthFailed
		}
		now := s.now()
		if err := s.refuseWhileLocked(ctx, u, subject); err != nil {
			return err
		}
		m, err := s.store.LockMFA(ctx, u.ID)
		switch {
		case errors.Is(err, ErrMFANotFound):
			return ErrReauthFailed
		case err != nil:
			return fmt.Errorf("auth: lock authenticator: %w", err)
		case m.EnrolledAt == nil || m.SecretEnc == nil:
			return ErrReauthFailed
		}
		return fn(ctx, u, m, now)
	})
	if errors.Is(err, errWrongFactor) {
		return s.failReauthWith(ctx, user, subject, factorReason, p.IP)
	}
	return err
}

// refuseWhileLocked is ErrReauthFailed when the account is locked, without verifying anything.
func (s *Service) refuseWhileLocked(ctx context.Context, u UserRow, subject []byte) error {
	st, err := s.store.GetThrottle(ctx, u.OrgID, scopeSignIn, subject)
	if err != nil {
		return fmt.Errorf("auth: read throttle: %w", err)
	}
	if st.Locked(s.now()) {
		return ErrReauthFailed
	}
	return nil
}

// ConfirmAuthenticatorReplace swaps in the pending secret after a valid code from it, ends all
// other sessions of the admin (end_reason mfa_replaced) and audits auth.mfa.replaced.
// ErrNoPendingSecret without a pending secret; ErrReauthFailed for a wrong code.
func (s *Service) ConfirmAuthenticatorReplace(ctx context.Context, p authz.Principal, code string) error {
	user, err := s.store.GetUser(ctx, p.UserID)
	if err != nil {
		return fmt.Errorf("auth: read user: %w", err)
	}
	subject := s.throttleSubject(scopeSignIn, userThrottleKey(user.ID))
	if err := s.refuseWhileLocked(ctx, user, subject); err != nil {
		return err
	}
	err = s.inTx(ctx, func(ctx context.Context) error {
		u, err := s.store.LockUser(ctx, user.ID)
		if err != nil {
			return fmt.Errorf("auth: lock user: %w", err)
		}
		if u.Role != roleAdmin || u.Status != StatusActive {
			return ErrReauthFailed
		}
		now := s.now()
		if err := s.refuseWhileLocked(ctx, u, subject); err != nil {
			return err
		}
		m, err := s.store.LockMFA(ctx, u.ID)
		switch {
		case errors.Is(err, ErrMFANotFound):
			return ErrNoPendingSecret
		case err != nil:
			return fmt.Errorf("auth: lock authenticator: %w", err)
		case m.PendingSecretEnc == nil:
			return ErrNoPendingSecret
		}
		secret, err := s.openSecret(u.ID, m.PendingSecretEnc, aadPending)
		if err != nil {
			return err
		}
		// The new secret has never been used, so its own steps start from zero; the matched step
		// becomes the replay guard of the secret that is swapped in.
		step, ok := VerifyTOTP(secret, code, now, 0)
		if !ok {
			return errWrongFactor
		}
		if err := s.store.ConfirmPending(ctx, u.ID, step, now); err != nil {
			return fmt.Errorf("auth: confirm authenticator: %w", err)
		}
		ended, err := s.store.EndUserSessions(ctx, u.ID, p.SessionID, "mfa_replaced", now)
		if err != nil {
			return fmt.Errorf("auth: end sessions: %w", err)
		}
		return s.writeAudit(ctx, u.OrgID, p.AuditActor(), u.ID, ActionMFAReplaced, nil, EndedSessionsAfter{EndedSessionIDs: ended})
	})
	if errors.Is(err, errWrongFactor) {
		return s.failReauthWith(ctx, user, subject, ReasonWrongTOTP, p.IP)
	}
	return err
}
