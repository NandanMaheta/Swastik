package otp

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/NandanMaheta/swastik/apps/api/internal/auth"
	"github.com/NandanMaheta/swastik/apps/api/internal/platform/audit"
	"github.com/NandanMaheta/swastik/apps/api/internal/platform/crypto"
)

const roleClient = "client"

// startTargets validates the purpose and the new contact of a Start and returns the two target
// contacts of the verification (the account's own ones for sign-up).
func startTargets(in StartInput, user auth.UserView) (email, mobile string, err error) {
	switch in.Purpose {
	case PurposeSignup:
		if user.Role != roleClient || user.Status != auth.StatusPendingVerification {
			return "", "", ErrNotAllowed
		}
		return user.Email, user.Mobile, nil
	case PurposeChangeEmail:
		if user.Role != roleClient || user.Status != auth.StatusActive {
			return "", "", ErrNotAllowed
		}
		return in.NewContact, "", nil
	case PurposeChangeMobile:
		if user.Role != roleClient || user.Status != auth.StatusActive {
			return "", "", ErrNotAllowed
		}
		return "", in.NewContact, nil
	case PurposePasswordReset:
		return "", "", ErrInvalidInput
	}
	return "", "", ErrInvalidInput
}

// validateStart checks everything that needs no database: the purpose and the new contact. It
// returns the normalised input.
func validateStart(in StartInput) (StartInput, error) {
	if in.OrgID == uuid.Nil || in.UserID == uuid.Nil {
		return in, ErrInvalidInput
	}
	switch in.Purpose {
	case PurposeSignup:
		return in, nil
	case PurposeChangeEmail:
		v, err := auth.NormalizeEmail(in.NewContact)
		if err != nil {
			return in, ErrInvalidInput
		}
		in.NewContact = v
		return in, nil
	case PurposeChangeMobile:
		v, err := auth.NormalizeMobile(in.NewContact)
		if err != nil {
			return in, ErrInvalidInput
		}
		in.NewContact = v
		return in, nil
	case PurposePasswordReset:
		return in, ErrInvalidInput
	}
	return in, ErrInvalidInput
}

// Start begins a verification for a user: signup needs a pending_verification client (else
// ErrNotAllowed) and targets the account email and mobile; it supersedes the user's open flow of
// the same purpose and queues the first email code, subject to the D-03 limits (*RetryError). A
// bad contact is ErrInvalidInput. It joins the caller's transaction.
func (s *Service) Start(ctx context.Context, in StartInput, by audit.Actor) (Started, error) {
	in, err := validateStart(in)
	if err != nil {
		return Started{}, err
	}
	var out Started
	var outcome error
	err = s.d.Tx.InTx(ctx, func(ctx context.Context) error {
		user, err := s.d.Accounts.GetUser(ctx, in.UserID)
		if errors.Is(err, auth.ErrUserNotFound) || (err == nil && user.OrgID != in.OrgID) {
			outcome = ErrNotFound
			return nil
		}
		if err != nil {
			return err
		}
		emailTarget, mobileTarget, err := startTargets(in, user)
		if err != nil {
			return settle(&outcome, err)
		}
		now := s.now()
		// The open flow is locked first, as Resend does (one lock order: flow, then limits).
		old, err := s.st.LockOpenVerification(ctx, in.OrgID, in.UserID, in.Purpose)
		hasOld := err == nil
		if err != nil && !errors.Is(err, ErrNotFound) {
			return err
		}
		sends := emailTarget != ""
		if sends {
			refusal, err := s.applyLimits(ctx, in.OrgID, []LimitKey{
				s.limitKey(ScopeSendContact, emailTarget),
				s.limitKey(ScopeSendUser, in.UserID.String()),
				s.limitKey(ScopeSendIP, in.IP),
			}, now)
			if err != nil {
				return err
			}
			if refusal != nil {
				outcome = refusal
				return s.refused(ctx, in.OrgID, in.UserID, uuid.Nil, in.Purpose, in.IP, refusal, by)
			}
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
		ver, err := s.st.InsertVerification(ctx, NewVerification{
			OrgID: in.OrgID, UserID: in.UserID, Purpose: in.Purpose, HandleHash: hash,
			Email: emailTarget, Mobile: mobileTarget, Now: now, ExpiresAt: now.Add(VerificationTTL),
		})
		if err != nil {
			return err
		}
		a := auditAfter{VerificationID: ver.ID.String(), Purpose: string(in.Purpose), IP: in.IP}
		a.Outcome = "started"
		if err := s.record(ctx, in.OrgID, by, in.UserID, "otp.verification.started", a); err != nil {
			return err
		}
		if sends {
			if _, err := s.issueCode(ctx, ver, emailTarget, in.UserID); err != nil {
				return err
			}
			a.Outcome = "issued"
			if err := s.record(ctx, in.OrgID, by, in.UserID, "otp.code.issued", a); err != nil {
				return err
			}
		}
		out = Started{ID: ver.ID, Handle: handle, ExpiresAt: ver.ExpiresAt}
		return nil
	})
	if err != nil {
		return Started{}, err
	}
	if outcome != nil {
		return Started{}, outcome
	}
	return out, nil
}

// refused records a send refused by a limit: an audit row for a known user and the daily counter.
func (s *Service) refused(ctx context.Context, org, user, verification uuid.UUID, p Purpose, ip string, r *RetryError, by audit.Actor) error {
	if err := s.bump(ctx, org, MetricLimitRefused); err != nil {
		return err
	}
	a := auditAfter{Purpose: string(p), Outcome: "refused", Reason: string(r.Reason), IP: ip}
	if verification != uuid.Nil {
		a.VerificationID = verification.String()
	}
	return s.record(ctx, org, by, user, "otp.send.refused", a)
}

// endFlow ends the live code of a verification (and withdraws its unsent email), then cancels the
// verification itself.
func (s *Service) endFlow(ctx context.Context, ver VerificationRow, codeReason, flowReason string) error {
	if err := s.endLiveCode(ctx, ver, codeReason); err != nil {
		return err
	}
	if err := s.st.CancelVerification(ctx, ver.OrgID, ver.ID, flowReason, s.now()); err != nil && !errors.Is(err, ErrNotFound) {
		return err
	}
	return nil
}

// endLiveCode ends the verification's live code, if any, and withdraws its unsent email.
func (s *Service) endLiveCode(ctx context.Context, ver VerificationRow, reason string) error {
	code, err := s.st.EndLiveCode(ctx, ver.OrgID, ver.ID, reason, s.now())
	if errors.Is(err, ErrNoLiveCode) {
		return nil
	}
	if err != nil {
		return err
	}
	if code.OutboxKey != "" {
		if _, err := s.d.Outbox.Withdraw(ctx, ver.OrgID, TopicEmailCode, code.OutboxKey); err != nil {
			return err
		}
	}
	return nil
}

// Cancel ends the live code of a verification and withdraws its email.
func (s *Service) Cancel(ctx context.Context, id uuid.UUID, by audit.Actor) error {
	org, err := s.orgID(ctx)
	if err != nil {
		return err
	}
	return s.d.Tx.InTx(ctx, func(ctx context.Context) error {
		ver, err := s.st.LockVerification(ctx, org, id)
		if err != nil {
			return err
		}
		if ver.CancelledAt != nil || ver.FinishedAt != nil {
			return nil
		}
		if err := s.endFlow(ctx, ver, EndCancelled, CancelCancelled); err != nil {
			return err
		}
		return s.record(ctx, org, by, ver.UserID, "otp.verification.cancelled", auditAfter{
			VerificationID: ver.ID.String(), Purpose: string(ver.Purpose), Outcome: "cancelled"})
	})
}

// Get returns a verification with its readable targets (in-process only).
func (s *Service) Get(ctx context.Context, id uuid.UUID) (View, error) {
	org, err := s.orgID(ctx)
	if err != nil {
		return View{}, err
	}
	ver, err := s.st.GetVerification(ctx, org, id)
	if err != nil {
		return View{}, err
	}
	return s.viewFor(ctx, ver)
}

// Status returns the state of the verification behind handle.
func (s *Service) Status(ctx context.Context, c Caller, handle string) (View, error) {
	org, err := s.orgID(ctx)
	if err != nil {
		return View{}, err
	}
	ver, err := s.st.GetVerificationByHandle(ctx, org, crypto.Digest(handle))
	if err != nil {
		return View{}, err
	}
	if !visibleTo(c, ver) {
		return View{}, ErrNotFound
	}
	return s.viewFor(ctx, ver)
}

// visibleTo reports whether the caller may see the verification. A public caller reaches sign-up
// and password-reset flows; a signed-in owner only their own change flows. Anything else reads as
// absent.
func visibleTo(c Caller, ver VerificationRow) bool {
	if c.UserID == nil {
		return ver.Purpose == PurposeSignup || ver.Purpose == PurposePasswordReset
	}
	return ver.UserID == *c.UserID && (ver.Purpose == PurposeChangeEmail || ver.Purpose == PurposeChangeMobile)
}

func (s *Service) viewFor(ctx context.Context, ver VerificationRow) (View, error) {
	code, err := s.st.GetLiveCode(ctx, ver.OrgID, ver.ID)
	if errors.Is(err, ErrNoLiveCode) {
		return viewOf(ver, nil, s.now()), nil
	}
	if err != nil {
		return View{}, err
	}
	return viewOf(ver, &code, s.now()), nil
}

// viewOf derives the View of a verification at now. State is never stored.
func viewOf(ver VerificationRow, code *CodeRow, now time.Time) View {
	v := View{ID: ver.ID, OrgID: ver.OrgID, Purpose: ver.Purpose, ExpiresAt: ver.ExpiresAt, TargetEmail: ver.Email, TargetMobile: ver.Mobile}
	if ver.UserID != uuid.Nil {
		id := ver.UserID
		v.UserID = &id
	}
	switch {
	case ver.CancelledAt != nil:
		v.State = FlowCancelled
	case ver.FinishedAt != nil:
		v.State = FlowCompleted
	case !now.Before(ver.ExpiresAt):
		v.State = FlowExpired
	default:
		v.State = FlowOpen
	}
	done := ContactVerified
	if ver.Purpose == PurposeChangeEmail || ver.Purpose == PurposeChangeMobile {
		done = ContactProved
	}
	contact := func(doneAt *time.Time, masked string) *ContactView {
		cv := &ContactView{State: ContactPending, Masked: masked}
		switch {
		case doneAt != nil:
			cv.State = done
		case v.State == FlowExpired || v.State == FlowCancelled:
			cv.State = ContactExpired
		}
		return cv
	}
	// A reset shows no masked contact, so a decoy and a real account answer alike (plan I-2).
	if ver.Email != "" || ver.Purpose == PurposePasswordReset {
		masked := ""
		if ver.Purpose != PurposePasswordReset {
			masked = MaskEmail(ver.Email)
		}
		cv := contact(ver.EmailDoneAt, masked)
		if cv.State == ContactPending && code != nil {
			next, exp := code.IssuedAt.Add(ResendCooldown), code.ExpiresAt
			cv.NextResendAt, cv.CodeExpiresAt = &next, &exp
		}
		v.Email = cv
	}
	if ver.Mobile != "" {
		v.Mobile = contact(ver.MobileDoneAt, MaskMobile(ver.Mobile))
	}
	return v
}
