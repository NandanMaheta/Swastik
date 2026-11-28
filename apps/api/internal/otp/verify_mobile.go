package otp

import (
	"context"
	"errors"
	"strconv"

	"github.com/NandanMaheta/swastik/apps/api/internal/auth"
	"github.com/NandanMaheta/swastik/apps/api/internal/platform/firebaseauth"
)

// VerifyMobile checks a Firebase phone sign-in ID token for the mobile of the verification behind
// handle (D-04). The token is verified outside any transaction; every refusal after it commits
// its audit row and counter, and only an accepted proof leaves a fingerprint (FR-005).
func (s *Service) VerifyMobile(ctx context.Context, c Caller, handle, idToken string) (View, error) {
	org, err := s.orgID(ctx)
	if err != nil {
		return View{}, err
	}
	if refusal, err := s.checkIP(ctx, org, c.IP, handle); err != nil || refusal != nil {
		return View{}, firstError(refusal, err)
	}
	if s.d.Proofs == nil {
		return View{}, ErrNotConfigured
	}
	proof, verr := s.d.Proofs.Verify(ctx, idToken)
	if errors.Is(verr, firebaseauth.ErrDisabled) {
		return View{}, ErrNotConfigured
	}
	if errors.Is(verr, firebaseauth.ErrUnavailable) {
		// Google's key set could not be fetched: the proof was not judged. Answer 503, count no
		// refusal and burn nothing, so the client can send the same proof again.
		s.log.WarnContext(ctx, "otp: the Firebase key set is unavailable")
		return View{}, ErrNotConfigured
	}

	var view View
	var outcome error
	err = s.d.Tx.InTx(ctx, func(ctx context.Context) error {
		ver, err := s.lockFlow(ctx, org, c, handle)
		if err != nil {
			return settle(&outcome, err)
		}
		switch {
		case ver.Purpose != PurposeSignup && ver.Purpose != PurposeChangeMobile:
			outcome = ErrNotFound
			return nil
		case ver.Purpose == PurposeSignup && ver.EmailDoneAt == nil:
			outcome = ErrEmailFirst
			return nil
		case ver.MobileDoneAt != nil:
			outcome = ErrNothingToSend
			return nil
		}
		refuse := func(reason string, refusal error) error {
			if err := s.bump(ctx, org, MetricProofRefused); err != nil {
				return err
			}
			outcome = s.failCheck(ctx, ver, reason, c.IP, refusal)
			return nil
		}
		now := s.now()
		switch {
		case verr != nil || proof.SignInProvider != "phone":
			return refuse("invalid_proof", ErrProofInvalid)
		case proof.AuthTime.After(now.Add(ProofClockLeeway)):
			return refuse("invalid_proof", ErrProofInvalid)
		case now.Sub(proof.AuthTime) >= ProofMaxAge:
			return refuse("stale_proof", ErrProofStale)
		}
		if number, err := auth.NormalizeMobile(proof.PhoneNumber); err != nil || number != ver.Mobile {
			return refuse("number_mismatch", ErrNumberMismatch)
		}
		if ver.Purpose == PurposeChangeMobile {
			if taken, err := s.contactTaken(ctx, ver); err != nil {
				return err
			} else if taken {
				return refuse("contact_unavailable", ErrContactUnavailable)
			}
		}
		fingerprint := s.d.Digests.Index("otp.proof", []byte(proof.Subject+"|"+strconv.FormatInt(proof.AuthTime.Unix(), 10)))
		fresh, err := s.st.InsertProof(ctx, org, fingerprint, ver.ID, now)
		if err != nil {
			return err
		}
		if !fresh {
			return refuse("replayed_proof", ErrProofReplayed)
		}
		view, err = s.mobileAccepted(ctx, ver, c.IP)
		return err
	})
	if err != nil {
		return View{}, err
	}
	if outcome != nil {
		return View{}, outcome
	}
	return view, nil
}

// mobileAccepted runs what an accepted proof means for each purpose and returns the new view.
func (s *Service) mobileAccepted(ctx context.Context, ver VerificationRow, ip string) (View, error) {
	now := s.now()
	actor := clientActor(ver.UserID)
	a := auditAfter{VerificationID: ver.ID.String(), Purpose: string(ver.Purpose), Outcome: "accepted", IP: ip}
	if err := s.st.MarkContactDone(ctx, ver.OrgID, ver.ID, ContactMobile, now); err != nil {
		return View{}, err
	}
	action := "otp.contact.proved"
	if ver.Purpose == PurposeSignup {
		action = "otp.mobile.verified"
		if _, err := s.d.Accounts.MarkMobileVerified(ctx, ver.UserID, actor); err != nil {
			return View{}, err
		}
	}
	// A sign-up finishes with its second contact; a change has only this one.
	if ver.Purpose == PurposeChangeMobile || ver.EmailDoneAt != nil {
		if err := s.st.FinishVerification(ctx, ver.OrgID, ver.ID, now); err != nil {
			return View{}, err
		}
	}
	if err := s.bump(ctx, ver.OrgID, MetricProofAccepted); err != nil {
		return View{}, err
	}
	if err := s.record(ctx, ver.OrgID, actor, ver.UserID, action, a); err != nil {
		return View{}, err
	}
	fresh, err := s.st.GetVerification(ctx, ver.OrgID, ver.ID)
	if err != nil {
		return View{}, err
	}
	return viewOf(fresh, nil, now), nil
}
