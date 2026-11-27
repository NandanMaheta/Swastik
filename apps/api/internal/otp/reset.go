package otp

import (
	"context"
	"crypto/subtle"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/NandanMaheta/swastik/apps/api/internal/auth"
	"github.com/NandanMaheta/swastik/apps/api/internal/platform/crypto"
)

// StartReset starts a password reset for an email or mobile identifier. The answer is the same
// for known and unknown identifiers (decoys, D-06, D-07): an account that cannot reset (unknown,
// not an active client, an admin) gets a decoy flow, and every call answers no earlier than the
// response floor. Only a malformed identifier is refused, before anything is looked up.
func (s *Service) StartReset(ctx context.Context, ip, identifier string) (ResetStarted, error) {
	start := s.now()
	_, normalised, err := auth.NormalizeIdentifier(identifier)
	if err != nil {
		return ResetStarted{}, auth.ErrInvalidIdentifier
	}
	defer func() { s.wait(ctx, start.Add(responseFloor)) }()
	org, err := s.orgID(ctx)
	if err != nil {
		return ResetStarted{}, err
	}
	user, err := s.d.Accounts.FindUser(ctx, identifier)
	if err != nil && !errors.Is(err, auth.ErrUserNotFound) {
		return ResetStarted{}, err
	}
	eligible := err == nil && user.OrgID == org && user.Role == roleClient && user.Status == auth.StatusActive

	var out ResetStarted
	var outcome error
	var key string
	err = s.d.Tx.InTx(ctx, func(ctx context.Context) error {
		now := s.now()
		var err error
		contact, userID := normalised, uuid.Nil
		if eligible {
			contact, userID = user.Email, user.ID
		}
		// The open flow is locked first, as Resend does (one lock order: flow, then limits).
		var old VerificationRow
		hasOld := false
		if eligible {
			old, err = s.st.LockOpenVerification(ctx, org, userID, PurposePasswordReset)
			if hasOld = err == nil; err != nil && !errors.Is(err, ErrNotFound) {
				return err
			}
		}
		keys := []LimitKey{s.limitKey(ScopeSendContact, contact), s.limitKey(ScopeSendIP, ip)}
		if eligible {
			keys = append(keys, s.limitKey(ScopeSendUser, userID.String()))
		}
		refusal, err := s.applyLimits(ctx, org, keys, now)
		if err != nil {
			return err
		}
		if refusal != nil {
			outcome = refusal
			return s.refused(ctx, org, userID, uuid.Nil, PurposePasswordReset, ip, refusal, clientActor(userID))
		}
		if hasOld {
			if err := s.endFlow(ctx, old, EndSuperseded, CancelSuperseded); err != nil {
				return err
			}
		}
		handle, hash, err := crypto.NewToken("ovh_")
		if err != nil {
			return err
		}
		nv := NewVerification{OrgID: org, UserID: userID, Purpose: PurposePasswordReset, HandleHash: hash,
			Now: now, ExpiresAt: now.Add(VerificationTTL)}
		if eligible {
			nv.Email = user.Email
		}
		ver, err := s.st.InsertVerification(ctx, nv)
		if err != nil {
			return err
		}
		to := nv.Email
		if !eligible {
			// The decoy's own send row, so its resends meet the same cooldown and hourly limit.
			if _, err := s.applyLimits(ctx, org, []LimitKey{s.limitKey(ScopeSendContact, "decoy:"+ver.ID.String())}, now); err != nil {
				return err
			}
		}
		code, err := s.issueCode(ctx, ver, to, userID)
		if err != nil {
			return err
		}
		key = code.OutboxKey
		a := auditAfter{VerificationID: ver.ID.String(), Purpose: string(PurposePasswordReset), IP: ip}
		for _, act := range []struct{ action, outcome string }{{"otp.verification.started", "started"}, {"otp.code.issued", "issued"}} {
			a.Outcome = act.outcome
			if err := s.record(ctx, org, clientActor(userID), userID, act.action, a); err != nil {
				return err
			}
		}
		out = ResetStarted{Handle: handle, ExpiresAt: ver.ExpiresAt, NextResendAt: now.Add(ResendCooldown)}
		return nil
	})
	if err != nil {
		return ResetStarted{}, err
	}
	if outcome != nil {
		return ResetStarted{}, outcome
	}
	if err := s.deliverKey(ctx, org, key); err != nil {
		s.log.WarnContext(ctx, "otp: delivering a code failed; the relay will retry", "err", err)
	}
	return out, nil
}

// CompleteReset sets a new password once the reset token proves the code was entered. One answer,
// ErrResetTokenInvalid, covers a missing, wrong, foreign, spent or expired permission. The token
// is single use: the verification is finished in the same transaction as the password change, so
// a policy error leaves it usable and a success cannot be repeated.
func (s *Service) CompleteReset(ctx context.Context, ip, handle, resetToken, newPassword string) error {
	org, err := s.orgID(ctx)
	if err != nil {
		return err
	}
	if refusal, err := s.checkIP(ctx, org, ip, handle); err != nil || refusal != nil {
		return firstError(refusal, err)
	}
	var outcome error
	err = s.d.Tx.InTx(ctx, func(ctx context.Context) error {
		ver, err := s.st.LockVerificationByHandle(ctx, org, crypto.Digest(handle))
		if errors.Is(err, ErrNotFound) {
			outcome = ErrResetTokenInvalid
			return nil
		}
		if err != nil {
			return err
		}
		now := s.now()
		if !s.tokenValid(ver, resetToken, now) {
			outcome = ErrResetTokenInvalid
			return nil
		}
		actor := clientActor(ver.UserID)
		// ResetPassword joins this transaction: a policy error rolls everything back.
		if err := s.d.Accounts.ResetPassword(ctx, ver.UserID, newPassword, actor); err != nil {
			return err
		}
		if err := s.st.FinishVerification(ctx, org, ver.ID, now); err != nil {
			return err
		}
		return s.record(ctx, org, actor, ver.UserID, "otp.reset.completed", auditAfter{
			VerificationID: ver.ID.String(), Purpose: string(PurposePasswordReset), Outcome: "completed", IP: ip})
	})
	if err != nil {
		return err
	}
	return outcome
}

// tokenValid reports whether the token is the unspent, unexpired permission of a real reset flow.
func (s *Service) tokenValid(ver VerificationRow, token string, now time.Time) bool {
	if ver.Purpose != PurposePasswordReset || ver.UserID == uuid.Nil || ver.CancelledAt != nil || ver.FinishedAt != nil ||
		ver.ResetTokenHash == nil || ver.ResetTokenExpiresAt == nil || !now.Before(*ver.ResetTokenExpiresAt) {
		return false
	}
	return subtle.ConstantTimeCompare(crypto.Digest(token), ver.ResetTokenHash) == 1
}
