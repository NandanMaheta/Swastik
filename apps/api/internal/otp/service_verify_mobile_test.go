package otp_test

// S12 - VerifyMobile with Firebase phone sign-in proofs (feature 004; BR-CLI-04, BR-CLI-05;
// spec US1.5, US3.1-US3.5, US5.2, US5.3, D-04, D-05, D-08, D-09, FR-005, FR-006, FR-007, FR-010,
// FR-017). Proofs are RS256 tokens minted by otptest.Minter and verified through a local JWKS.

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/NandanMaheta/swastik/apps/api/internal/auth/authtest"
	"github.com/NandanMaheta/swastik/apps/api/internal/otp"
	"github.com/NandanMaheta/swastik/apps/api/internal/otp/otptest"
)

// svSignupWithEmailDone starts a sign-up for a new pending user and verifies the email step.
func svSignupWithEmailDone(t *testing.T, e *otptest.Env) (authtest.User, otp.Started) {
	t.Helper()
	u := e.Pending(t)
	st := e.StartSignup(t, u)
	if _, err := svVerifyEmail(e, st.Handle, e.PendingCode(t, st.ID)); err != nil {
		t.Fatalf("verify email: %v", err)
	}
	return u, st
}

func svVerifyMobile(e *otptest.Env, handle, token string) (otp.View, error) {
	return e.Svc.VerifyMobile(context.Background(), otptest.Caller(), handle, token)
}

func TestVerifyMobile_BR_CLI_04_SignupMarksTheMobileAndMovesToPendingApproval(t *testing.T) {
	e := otptest.NewEnv(t)
	u, st := svSignupWithEmailDone(t, e)
	token := e.Token(t, u.Mobile)

	v, err := svVerifyMobile(e, st.Handle, token)
	if err != nil {
		t.Fatalf("VerifyMobile: %v", err)
	}
	if v.Mobile == nil || v.Mobile.State != otp.ContactVerified || v.Email.State != otp.ContactVerified || v.State != otp.FlowCompleted {
		t.Errorf("view = %+v, want both contacts verified and the flow completed (US1.5)", v)
	}
	got := svUser(t, e, u.ID)
	if !got.MobileVerified || !got.EmailVerified || got.Status != "pending_approval" {
		t.Errorf("user = %+v, want both contacts verified and status pending_approval, not active (BR-CLI-04)", got)
	}
	if svVer(t, e, st.ID).Finished == nil {
		t.Error("finished_at not set once both contacts are done")
	}
	rows := svAuditOf(t, e, "otp.mobile.verified")
	if len(rows) != 1 {
		t.Fatalf("otp.mobile.verified audit rows = %d, want 1", len(rows))
	}
	svNoLeak(t, "audit", rows[0].After, u.Mobile, strings.TrimPrefix(u.Mobile, "+91"), token)
	if c := e.Counts(t); c.ProofAccepted != 1 || c.ProofRefused != 0 {
		t.Errorf("counts = %+v, want proof_accepted 1 (FR-017)", c)
	}
	if n := e.Count(t, `SELECT count(*) FROM otp_used_proofs`); n != 1 {
		t.Errorf("used proofs = %d, want 1 fingerprint", n)
	}
	var fpLen int
	var dump string
	if err := e.Pool.QueryRow(context.Background(), `SELECT octet_length(fingerprint), p::text FROM otp_used_proofs p`).Scan(&fpLen, &dump); err != nil || fpLen != 32 {
		t.Errorf("fingerprint length = %d, %v, want a 32-byte digest", fpLen, err)
	}
	svNoLeak(t, "otp_used_proofs", dump, token, "fb-user-")
}

func TestVerifyMobile_BR_CLI_04_EmailComesFirstAndTheProofIsNotConsumedByTheRefusal(t *testing.T) {
	e := otptest.NewEnv(t)
	u := e.Pending(t)
	st := e.StartSignup(t, u)
	token := e.Token(t, u.Mobile)

	if _, err := svVerifyMobile(e, st.Handle, token); !errors.Is(err, otp.ErrEmailFirst) {
		t.Fatalf("VerifyMobile before the email step: %v, want ErrEmailFirst (D-05, US3.2)", err)
	}
	if got := svUser(t, e, u.ID); got.MobileVerified || got.EmailVerified {
		t.Errorf("user = %+v, want nothing changed", got)
	}
	if n := e.Count(t, `SELECT count(*) FROM otp_used_proofs`); n != 0 {
		t.Errorf("used proofs = %d, want 0: only accepted proofs are recorded", n)
	}
	if _, err := svVerifyEmail(e, st.Handle, e.PendingCode(t, st.ID)); err != nil {
		t.Fatal(err)
	}
	if _, err := svVerifyMobile(e, st.Handle, token); err != nil {
		t.Errorf("the same proof after the email step: %v, want it accepted (it was never used)", err)
	}
}

func TestVerifyMobile_BR_CLI_04_ADifferentNumberIsRefusedWithoutEchoingEither(t *testing.T) {
	e := otptest.NewEnv(t)
	u, st := svSignupWithEmailDone(t, e)
	other := "+919812345679"
	token := e.Token(t, other)

	_, err := svVerifyMobile(e, st.Handle, token)
	if !errors.Is(err, otp.ErrNumberMismatch) {
		t.Fatalf("VerifyMobile: %v, want ErrNumberMismatch (US3.3)", err)
	}
	digits := strings.TrimPrefix(u.Mobile, "+91")
	svNoLeak(t, "error text", err.Error(), u.Mobile, digits, other, "9812345679")
	_, p := problemFor(t, err)
	svNoLeak(t, "problem body", p.Detail+p.Code, u.Mobile, digits, other, "9812345679")
	svNoLeak(t, "audit", svAuditText(t, e), u.Mobile, digits, other, "9812345679", token)
	svNoLeak(t, "logs", e.Logs.String(), u.Mobile, digits, other, "9812345679", token)
	rows := svAuditOf(t, e, "otp.check.failed")
	if len(rows) != 1 || otptest.AuditAfter(t, rows[0])["reason"] != "number_mismatch" {
		t.Errorf("check.failed audit = %+v, want one with reason number_mismatch", rows)
	}
	if svUser(t, e, u.ID).MobileVerified {
		t.Error("the mobile was verified by another number's proof")
	}
	if c := e.Counts(t); c.ProofRefused != 1 || c.ProofAccepted != 0 {
		t.Errorf("counts = %+v, want proof_refused 1", c)
	}
	// A refusal records no fingerprint: the right number can still prove with a fresh sign-in.
	if _, err := svVerifyMobile(e, st.Handle, e.Token(t, u.Mobile)); err != nil {
		t.Errorf("the right number afterwards: %v", err)
	}
}

func TestVerifyMobile_BR_CLI_04_ProofFreshnessIsFiveMinutesExclusive(t *testing.T) {
	cases := []struct {
		name string
		age  time.Duration
		want error
	}{
		{"4:59 old", otp.ProofMaxAge - time.Second, nil},
		{"5:00 old", otp.ProofMaxAge, otp.ErrProofStale},
		{"6 minutes old (US3.4)", 6 * time.Minute, otp.ErrProofStale},
		{"+30 s in the future (leeway)", -otp.ProofClockLeeway, nil},
		{"+31 s in the future", -otp.ProofClockLeeway - time.Second, otp.ErrProofInvalid},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := otptest.NewEnv(t)
			u, st := svSignupWithEmailDone(t, e)
			now := e.Clock.Now()
			token := e.Token(t, u.Mobile, func(c *otptest.Claims) {
				c.AuthTime, c.IssuedAt = now.Add(-tc.age), now.Add(-tc.age)
			})
			_, err := svVerifyMobile(e, st.Handle, token)
			if tc.want == nil {
				if err != nil {
					t.Fatalf("VerifyMobile: %v, want it accepted", err)
				}
				return
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("VerifyMobile: %v, want %v", err, tc.want)
			}
			if svUser(t, e, u.ID).MobileVerified || e.Count(t, `SELECT count(*) FROM otp_used_proofs`) != 0 {
				t.Error("a refused proof changed state")
			}
		})
	}
}

func TestVerifyMobile_BR_CLI_04_OnlyOurProjectsPhoneSignInsAreAccepted(t *testing.T) {
	e := otptest.NewEnv(t)
	u, st := svSignupWithEmailDone(t, e)
	now := e.Clock.Now()
	valid := func() otptest.Claims {
		c := e.Minter.Valid(now)
		c.PhoneNumber, c.Subject = u.Mobile, "fb-intruder"
		return c
	}
	other := valid()
	other.Issuer, other.Audience = "https://securetoken.google.com/someone-elses-project", "someone-elses-project"
	password, google, noProvider := valid(), valid(), valid()
	password.SignInProvider, google.SignInProvider, noProvider.SignInProvider = "password", "google.com", ""
	expired := valid()
	expired.Expires = now.Add(-time.Second)

	tokens := map[string]string{
		"another Firebase project": e.Minter.Token(t, other),
		"password provider":        e.Minter.Token(t, password),
		"google provider":          e.Minter.Token(t, google),
		"no provider":              e.Minter.Token(t, noProvider),
		"signed by an unknown key": e.Minter.ForeignToken(t, valid()),
		"expired":                  e.Minter.Token(t, expired),
		"not a token":              "definitely.not.ajwt",
	}
	for name, tok := range tokens {
		_, err := svVerifyMobile(e, st.Handle, tok)
		if !errors.Is(err, otp.ErrProofInvalid) {
			t.Errorf("%s: %v, want ErrProofInvalid (US3.4)", name, err)
		}
		if err != nil {
			svNoLeak(t, name+" error", err.Error(), tok, u.Mobile)
		}
	}
	if svUser(t, e, u.ID).MobileVerified || e.Count(t, `SELECT count(*) FROM otp_used_proofs`) != 0 {
		t.Error("a refused proof changed state")
	}
	rows := svAuditOf(t, e, "otp.check.failed")
	if len(rows) != len(tokens) || otptest.AuditAfter(t, rows[0])["reason"] != "invalid_proof" {
		t.Errorf("check.failed audit rows = %d (first reason %v), want %d with reason invalid_proof", len(rows), otptest.AuditAfter(t, rows[0])["reason"], len(tokens))
	}
	if c := e.Counts(t); c.ProofRefused != len(tokens) {
		t.Errorf("proof_refused = %d, want %d", c.ProofRefused, len(tokens))
	}
	for name, tok := range tokens {
		svNoLeak(t, "audit after "+name, svAuditText(t, e), tok)
		svNoLeak(t, "logs after "+name, e.Logs.String(), tok)
	}
}

func TestVerifyMobile_BR_CLI_05_AProofWorksOnlyOnce(t *testing.T) {
	e := otptest.NewEnv(t)
	owner := e.Active(t)
	const newMobile = "+919876543210"
	first := e.StartChange(t, owner, otp.PurposeChangeMobile, newMobile)
	token := e.Token(t, newMobile)
	if _, err := e.Svc.VerifyMobile(t.Context(), otptest.CallerOf(owner), first.Handle, token); err != nil {
		t.Fatalf("first use: %v", err)
	}
	second := e.StartChange(t, owner, otp.PurposeChangeMobile, newMobile)
	_, err := e.Svc.VerifyMobile(t.Context(), otptest.CallerOf(owner), second.Handle, token)
	if !errors.Is(err, otp.ErrProofReplayed) {
		t.Fatalf("the same sign-in a second time: %v, want ErrProofReplayed (US3.4, FR-005)", err)
	}
	if svVer(t, e, second.ID).MobileDone != nil {
		t.Error("a replayed proof proved the contact")
	}
	rows := svAuditOf(t, e, "otp.check.failed")
	if len(rows) != 1 || otptest.AuditAfter(t, rows[0])["reason"] != "replayed_proof" {
		t.Errorf("check.failed audit = %+v, want reason replayed_proof", rows)
	}
	if c := e.Counts(t); c.ProofAccepted != 1 || c.ProofRefused != 1 {
		t.Errorf("counts = %+v, want 1 accepted and 1 refused", c)
	}
}

func TestVerifyMobile_BR_CLI_04_AndroidAndIPhoneProofsAreTreatedAlike(t *testing.T) {
	e := otptest.NewEnv(t)
	for _, device := range []string{"android-app", "iphone-home-screen-app"} {
		u, st := svSignupWithEmailDone(t, e)
		token := e.Token(t, u.Mobile, func(c *otptest.Claims) { c.Subject = device })
		if _, err := svVerifyMobile(e, st.Handle, token); err != nil {
			t.Errorf("%s proof: %v, want accepted (US3.5)", device, err)
		}
		if got := svUser(t, e, u.ID); got.Status != "pending_approval" {
			t.Errorf("%s: status = %q, want pending_approval", device, got.Status)
		}
	}
}

func TestVerifyMobile_BR_CLI_05_AChangeIsProvedForTheOwnerOnlyAndLeavesTheAccountAlone(t *testing.T) {
	e := otptest.NewEnv(t)
	owner, other := e.Active(t), e.Active(t)
	const newMobile = "+919876543210"
	st := e.StartChange(t, owner, otp.PurposeChangeMobile, newMobile)
	token := e.Token(t, newMobile)
	before := svUser(t, e, owner.ID)

	if _, err := e.Svc.VerifyMobile(t.Context(), otptest.CallerOf(other), st.Handle, token); !errors.Is(err, otp.ErrNotFound) {
		t.Fatalf("another client's session: %v, want ErrNotFound (US5.2)", err)
	}
	if n := e.Count(t, `SELECT count(*) FROM otp_used_proofs`); n != 0 {
		t.Errorf("a stranger's attempt consumed the proof (%d fingerprints)", n)
	}
	v, err := e.Svc.VerifyMobile(t.Context(), otptest.CallerOf(owner), st.Handle, token)
	if err != nil {
		t.Fatalf("the owner: %v", err)
	}
	if v.Mobile == nil || v.Mobile.State != otp.ContactProved || v.State != otp.FlowCompleted {
		t.Errorf("view = %+v, want the mobile proved and the flow completed", v)
	}
	if after := svUser(t, e, owner.ID); after != before {
		t.Errorf("the account changed: %+v -> %+v", before, after)
	}
	if got, err := e.Svc.Get(t.Context(), st.ID); err != nil || got.TargetMobile != newMobile {
		t.Errorf("Get = %+v, %v, want the proved number for 007", got, err)
	}
	if rows := svAuditOf(t, e, "otp.contact.proved"); len(rows) != 1 {
		t.Errorf("otp.contact.proved audit rows = %d, want 1", len(rows))
	}
}

func TestVerifyMobile_BR_CLI_05_ANumberOfAnotherUserIsUnavailable(t *testing.T) {
	e := otptest.NewEnv(t)
	owner, holder := e.Active(t), e.Active(t)
	st := e.StartChange(t, owner, otp.PurposeChangeMobile, holder.Mobile)
	_, err := e.Svc.VerifyMobile(t.Context(), otptest.CallerOf(owner), st.Handle, e.Token(t, holder.Mobile))
	if !errors.Is(err, otp.ErrContactUnavailable) {
		t.Fatalf("VerifyMobile: %v, want ErrContactUnavailable (US5.3)", err)
	}
	svNoLeak(t, "error text", err.Error(), holder.ID.String(), holder.Mobile, strings.TrimPrefix(holder.Mobile, "+91"))
	if svVer(t, e, st.ID).MobileDone != nil {
		t.Error("the contact was marked proved")
	}
}

func TestVerifyMobile_BR_CLI_04_NoVerifierMeansNotConfigured(t *testing.T) {
	e := otptest.NewEnv(t, otptest.WithoutFirebase())
	u, st := svSignupWithEmailDone(t, e)
	_, err := svVerifyMobile(e, st.Handle, "any.token.here")
	if !errors.Is(err, otp.ErrNotConfigured) {
		t.Errorf("VerifyMobile without Firebase: %v, want ErrNotConfigured", err)
	}
	if svUser(t, e, u.ID).MobileVerified {
		t.Error("the mobile was verified without a verifier")
	}
}

func TestVerifyMobile_BR_CLI_04_ExpiredAndUnknownHandles(t *testing.T) {
	e := otptest.NewEnv(t)
	u, st := svSignupWithEmailDone(t, e)
	token := e.Token(t, u.Mobile)
	if _, err := svVerifyMobile(e, "ovh_unknown", token); !errors.Is(err, otp.ErrNotFound) {
		t.Errorf("unknown handle: %v, want ErrNotFound", err)
	}
	e.Clock.Advance(otp.VerificationTTL)
	token = e.Token(t, u.Mobile) // a fresh sign-in, so only the 24 h limit can refuse it
	if _, err := svVerifyMobile(e, st.Handle, token); !errors.Is(err, otp.ErrVerificationExpired) {
		t.Errorf("after 24 h: %v, want ErrVerificationExpired", err)
	}
	if svUser(t, e, u.ID).MobileVerified {
		t.Error("an expired verification verified the mobile")
	}
}
