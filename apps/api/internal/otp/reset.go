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
//
// Everything a stranger can observe is keyed on what the stranger typed, never on the account: the
// flow a later start supersedes, the cooldown and the hourly limit all use a keyed digest of the
// normalised typed identifier, for a real flow and a decoy alike. The email is sent while the floor
// runs and the reply never waits for it (SC-004).
func (s *Service) StartReset(ctx context.Context, ip, identifier string) (ResetStarted, error) {
	start := s.now()
	_, normalised, err := auth.NormalizeIdentifier(identifier)
	if err != nil {
		return ResetStarted{}, auth.ErrInvalidIdentifier
	}
	var inflight <-chan struct{}
	defer func() {
		s.wait(ctx, start.Add(responseFloor))
		s.awaitSend(inflight)
	}()
	org, err := s.orgID(ctx)
	if err != nil {
		return ResetStarted{}, err
	}
	user, err := s.d.Accounts.FindUser(ctx, identifier)
	if err != nil && !errors.Is(err, auth.ErrUserNotFound) {
		return ResetStarted{}, err
	}
	eligible := err == nil && user.OrgID == org && user.Role == roleClient && user.Status == auth.StatusActive
	userID := uuid.Nil
	if eligible {
		userID = user.ID
	}
	typed := s.typedKey(normalised)

	var out ResetStarted
	var outcome error
	var key string
	err = s.d.Tx.InTx(ctx, func(ctx context.Context) error {
		now := s.now()
		// The open flow of this typed identifier is locked first, as Resend does (one lock order:
		// flow, then limits). A decoy is held and superseded exactly as a real flow is.
		old, err := s.st.LockOpenResetFlow(ctx, org, userID, typed)
		hasOld := err == nil
		if err != nil && !errors.Is(err, ErrNotFound) {
			return err
		}
		refusal, err := s.applyLimits(ctx, org, []LimitKey{{Scope: ScopeSendContact, Subject: typed}, s.limitKey(ScopeSendIP, ip)}, now)
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
			IdentifierKey: typed, Now: now, ExpiresAt: now.Add(VerificationTTL)}
		if eligible {
			nv.Email = user.Email
		}
		ver, err := s.st.InsertVerification(ctx, nv)
		if err != nil {
			return err
		}
		code, err := s.issueCode(ctx, ver, nv.Email, userID)
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
	inflight = s.deliverAsync(ctx, org, key)
	return out, nil
}

// typedKey is the keyed digest of a normalised typed identifier: the subject of the send limit of
// a reset and the identifier_key of its flow. A distinct HMAC domain keeps it apart from every
// other limit row.
func (s *Service) typedKey(normalised string) []byte {
	return s.d.Digests.Index("otp.reset.typed", []byte(normalised))
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
		// The code was proved while the account could reset; it may not be able to any more. The
		// answer is the same one, and the refusal leaves its trace in the audit log (FR-010).
		reason, err := s.resetBlocked(ctx, org, ver, now)
		if err != nil {
			return err
		}
		if reason != "" {
			outcome = ErrResetTokenInvalid
			if err := s.endFlow(ctx, ver, EndCancelled, CancelCancelled); err != nil {
				return err
			}
			return s.record(ctx, org, actor, ver.UserID, "otp.reset.refused", auditAfter{
				VerificationID: ver.ID.String(), Purpose: string(PurposePasswordReset), Outcome: "refused", Reason: reason, IP: ip})
		}
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

// resetBlocked says why a verified reset may no longer set a password ("" when it may): the
// verification passed its 24 hour expiry, or the user is no longer an active client of the org.
func (s *Service) resetBlocked(ctx context.Context, org uuid.UUID, ver VerificationRow, now time.Time) (string, error) {
	if !now.Before(ver.ExpiresAt) {
		return "flow_expired", nil
	}
	user, err := s.d.Accounts.GetUser(ctx, ver.UserID)
	switch {
	case errors.Is(err, auth.ErrUserNotFound):
		return "not_eligible", nil
	case err != nil:
		return "", err
	case user.OrgID != org || user.Role != roleClient || user.Status != auth.StatusActive:
		return "not_eligible", nil
	}
	return "", nil
}

// tokenValid reports whether the token is the unspent, unexpired permission of a real reset flow.
func (s *Service) tokenValid(ver VerificationRow, token string, now time.Time) bool {
	if ver.Purpose != PurposePasswordReset || ver.UserID == uuid.Nil || ver.CancelledAt != nil || ver.FinishedAt != nil ||
		ver.ResetTokenHash == nil || ver.ResetTokenExpiresAt == nil || !now.Before(*ver.ResetTokenExpiresAt) {
		return false
	}
	return subtle.ConstantTimeCompare(crypto.Digest(token), ver.ResetTokenHash) == 1
}
