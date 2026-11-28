package otp

import (
	"context"
	"crypto/subtle"
	"errors"

	"github.com/google/uuid"

	"github.com/NandanMaheta/swastik/apps/api/internal/auth"
	"github.com/NandanMaheta/swastik/apps/api/internal/platform/crypto"
)

// checkIP applies the per-address check limit (D-03) in its own transaction, so the event stays
// even when the request is refused later. A refusal is audited for a known user. The outcome is
// the refusal to return; the error is an infrastructure failure.
func (s *Service) checkIP(ctx context.Context, org uuid.UUID, ip, handle string) (outcome, err error) {
	err = s.d.Tx.InTx(ctx, func(ctx context.Context) error {
		now := s.now()
		refusal, err := s.applyLimits(ctx, org, []LimitKey{s.limitKey(ScopeCheckIP, ip)}, now)
		if err != nil || refusal == nil {
			return err
		}
		outcome = refusal
		if err := s.bump(ctx, org, MetricLimitRefused); err != nil {
			return err
		}
		ver, err := s.st.GetVerificationByHandle(ctx, org, crypto.Digest(handle))
		if err != nil {
			return nil //nolint:nilerr // an unknown handle names no user to audit
		}
		return s.record(ctx, org, clientActor(ver.UserID), ver.UserID, "otp.check.failed", auditAfter{
			VerificationID: ver.ID.String(), Purpose: string(ver.Purpose), Outcome: "failed", Reason: string(ReasonRateLimited), IP: ip})
	})
	return outcome, err
}

// failCheck audits a refused check of a known user and returns the refusal to give.
func (s *Service) failCheck(ctx context.Context, ver VerificationRow, reason, ip string, refusal error) error {
	err := s.record(ctx, ver.OrgID, clientActor(ver.UserID), ver.UserID, "otp.check.failed", auditAfter{
		VerificationID: ver.ID.String(), Purpose: string(ver.Purpose), Outcome: "failed", Reason: reason, IP: ip})
	if err != nil {
		return err
	}
	return refusal
}

// VerifyEmail checks the 6-digit code of the verification behind handle. Wrong entries, expiry and
// refusals commit their counters and audit rows; success marks the contact (sign-up), proves it
// (change) or grants the one-time reset token (password reset).
func (s *Service) VerifyEmail(ctx context.Context, c Caller, handle, code string) (VerifyEmailResult, error) {
	org, err := s.orgID(ctx)
	if err != nil {
		return VerifyEmailResult{}, err
	}
	if refusal, err := s.checkIP(ctx, org, c.IP, handle); err != nil || refusal != nil {
		return VerifyEmailResult{}, firstError(refusal, err)
	}
	var res VerifyEmailResult
	var outcome error
	err = s.d.Tx.InTx(ctx, func(ctx context.Context) error {
		ver, err := s.lockFlow(ctx, org, c, handle)
		if err != nil {
			return settle(&outcome, err)
		}
		live, err := s.st.LockLiveCode(ctx, org, ver.ID)
		now := s.now()
		switch {
		case errors.Is(err, ErrNoLiveCode), err == nil && !now.Before(live.ExpiresAt):
			outcome = s.failCheck(ctx, ver, "expired", c.IP, ErrCodeExpired)
			return nil
		case err != nil:
			return err
		}
		want := CodeDigest(s.d.Digests, ver.Purpose, ver.ID, live.ID, code)
		if subtle.ConstantTimeCompare(want, live.Digest) != 1 {
			outcome, err = s.wrongEntry(ctx, ver, live, c.IP)
			return err
		}
		if ver.Purpose == PurposeChangeEmail {
			if taken, err := s.contactTaken(ctx, ver); err != nil {
				return err
			} else if taken {
				outcome = s.failCheck(ctx, ver, "contact_unavailable", c.IP, ErrContactUnavailable)
				return nil
			}
		}
		if _, err := s.st.EndLiveCode(ctx, org, ver.ID, EndUsed, now); err != nil {
			return err
		}
		if err := s.st.MarkContactDone(ctx, org, ver.ID, ContactEmail, now); err != nil {
			return err
		}
		res, err = s.emailAccepted(ctx, ver, c.IP)
		return err
	})
	if err != nil {
		return VerifyEmailResult{}, err
	}
	if outcome != nil {
		return VerifyEmailResult{}, outcome
	}
	return res, nil
}

func firstError(a, b error) error {
	if b != nil {
		return b
	}
	return a
}

// wrongEntry counts a wrong code; the 5th ends it (D-02).
func (s *Service) wrongEntry(ctx context.Context, ver VerificationRow, live CodeRow, ip string) (outcome, err error) {
	n, err := s.st.AddWrongAttempt(ctx, ver.OrgID, live.ID, s.now())
	if errors.Is(err, ErrNoLiveCode) {
		return s.failCheck(ctx, ver, "expired", ip, ErrCodeExpired), nil
	}
	if err != nil {
		return nil, err
	}
	if n < MaxWrongAttempts {
		return s.failCheck(ctx, ver, "wrong_code", ip, ErrCodeWrong), nil
	}
	if _, err := s.st.EndLiveCode(ctx, ver.OrgID, ver.ID, EndUsedUp, s.now()); err != nil {
		return nil, err
	}
	return s.failCheck(ctx, ver, "used_up", ip, ErrCodeUsedUp), nil
}

// contactTaken reports whether the new contact of a change belongs to another user (003 D-18).
func (s *Service) contactTaken(ctx context.Context, ver VerificationRow) (bool, error) {
	target := ver.Email
	if ver.Purpose == PurposeChangeMobile {
		target = ver.Mobile
	}
	other, err := s.d.Accounts.FindUser(ctx, target)
	if errors.Is(err, auth.ErrUserNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return other.ID != ver.UserID, nil
}

// emailAccepted runs what a right code means for each purpose and returns the reply.
func (s *Service) emailAccepted(ctx context.Context, ver VerificationRow, ip string) (VerifyEmailResult, error) {
	now := s.now()
	a := auditAfter{VerificationID: ver.ID.String(), Purpose: string(ver.Purpose), Outcome: "accepted", IP: ip}
	actor := clientActor(ver.UserID)
	var res VerifyEmailResult
	switch ver.Purpose {
	case PurposeSignup:
		if _, err := s.d.Accounts.MarkEmailVerified(ctx, ver.UserID, actor); err != nil {
			return res, err
		}
		if ver.MobileDoneAt != nil {
			if err := s.st.FinishVerification(ctx, ver.OrgID, ver.ID, now); err != nil {
				return res, err
			}
		}
		if err := s.record(ctx, ver.OrgID, actor, ver.UserID, "otp.email.verified", a); err != nil {
			return res, err
		}
	case PurposeChangeEmail:
		if err := s.st.FinishVerification(ctx, ver.OrgID, ver.ID, now); err != nil {
			return res, err
		}
		if err := s.record(ctx, ver.OrgID, actor, ver.UserID, "otp.contact.proved", a); err != nil {
			return res, err
		}
	case PurposePasswordReset:
		token, hash, err := crypto.NewToken("prt_")
		if err != nil {
			return res, err
		}
		expires := now.Add(ResetTokenTTL)
		if err := s.st.SetResetGrant(ctx, ver.OrgID, ver.ID, hash, expires, now); err != nil {
			return res, err
		}
		if err := s.record(ctx, ver.OrgID, actor, ver.UserID, "otp.reset.code_accepted", a); err != nil {
			return res, err
		}
		res.ResetToken, res.ResetTokenExpiresAt = token, &expires
	case PurposeChangeMobile:
		return res, ErrNotFound // no email step: unreachable, the live code check refuses first
	}
	fresh, err := s.st.GetVerification(ctx, ver.OrgID, ver.ID)
	if err != nil {
		return res, err
	}
	res.Verification = viewOf(fresh, nil, now)
	return res, nil
}
