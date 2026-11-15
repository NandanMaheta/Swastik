package auth_test

// S15 - concurrency of the second factor and of admin removal (plan P-05 "two parallel
// submissions of one code give exactly one success", data-model lock order, D-19). A start barrier
// releases N goroutines together on the real Store.

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/NandanMaheta/swastik/apps/api/internal/auth"
	"github.com/NandanMaheta/swastik/apps/api/internal/auth/authtest"
)

func TestMFAConcurrency_OneCodeSubmittedInParallelSucceedsOnce(t *testing.T) {
	for _, n := range []int{2, 4} {
		t.Run(fmt.Sprintf("%d goroutines", n), func(t *testing.T) {
			e := authtest.New(t)
			s := e.Service(t)
			a := mfEnrolled(t, e)
			tokens := make([]string, n) // one challenge per goroutine, as from n browsers
			for i := range tokens {
				tokens[i] = mfChallenge(t, e, s, a.User)
			}
			code := mfCode(t, e, a.Secret, 0)
			results := make([]auth.SessionTokens, n)
			errs := stRace(n, func(i int) (err error) {
				results[i], err = s.VerifyMFA(t.Context(), mfVerifyIn(tokens[i], code))
				return err
			})
			wins := 0
			for i, err := range errs {
				switch {
				case err == nil:
					wins++
				case !errors.Is(err, auth.ErrInvalidCredentials):
					t.Errorf("goroutine %d: err = %v, want ErrInvalidCredentials", i, err)
				}
			}
			if wins != 1 {
				t.Fatalf("successes = %d, want exactly 1 (FR-061)", wins)
			}
			if got := svLiveSessions(t, e, a.ID); got != 1 {
				t.Errorf("live sessions = %d, want 1", got)
			}
			if got := len(e.AuditOf(t, auth.ActionSignInSucceeded)); got != 1 {
				t.Errorf("sign-in succeeded audit rows = %d, want 1", got)
			}
			if m := mfMFARow(t, e, a.ID); m.LastUsedStep != auth.TOTPStepAt(e.Clock.Now()) {
				t.Errorf("last_used_step = %d, want %d", m.LastUsedStep, auth.TOTPStepAt(e.Clock.Now()))
			}
		})
	}
}

func TestMFAConcurrency_OneRecoveryCodeSubmittedInParallelSucceedsOnce(t *testing.T) {
	e := authtest.New(t)
	s := e.Service(t)
	a := mfEnrolled(t, e)
	const n = 4
	tokens := make([]string, n)
	for i := range tokens {
		tokens[i] = mfChallenge(t, e, s, a.User)
	}
	errs := stRace(n, func(i int) error {
		_, err := s.VerifyMFA(t.Context(), auth.MFAVerifyInput{ChallengeToken: tokens[i], RecoveryCode: a.Codes[0], IP: testIP})
		return err
	})
	wins := 0
	for i, err := range errs {
		switch {
		case err == nil:
			wins++
		case !errors.Is(err, auth.ErrInvalidCredentials):
			t.Errorf("goroutine %d: err = %v, want ErrInvalidCredentials", i, err)
		}
	}
	if wins != 1 {
		t.Fatalf("successes = %d, want exactly 1", wins)
	}
	if got := mfUsableCodes(t, e, a.User); got != 9 {
		t.Errorf("usable codes = %d, want 9", got)
	}
	if got := len(e.AuditOf(t, auth.ActionMFARecoveryCodeUsed)); got != 1 {
		t.Errorf("recovery_code_used audit rows = %d, want 1", got)
	}
}

func TestMFAConcurrency_SameChallengeParallelCompletesOnce(t *testing.T) {
	// One challenge, two different valid codes (steps N and N+1) at once: only one session.
	e := authtest.New(t)
	s := e.Service(t)
	a := mfEnrolled(t, e)
	tok := mfChallenge(t, e, s, a.User)
	codes := []string{mfCode(t, e, a.Secret, 0), mfCode(t, e, a.Secret, 30*time.Second)}
	errs := stRace(2, func(i int) error {
		_, err := s.VerifyMFA(t.Context(), mfVerifyIn(tok, codes[i]))
		return err
	})
	wins := 0
	for _, err := range errs {
		if err == nil {
			wins++
		}
	}
	if wins != 1 || svAllSessions(t, e, a.ID) != 1 {
		t.Fatalf("successes = %d sessions = %d, want exactly one of each (single-use challenge)", wins, svAllSessions(t, e, a.ID))
	}
}

func TestMFAConcurrency_ParallelDisableOfTheLastTwoAdminsLeavesOne(t *testing.T) {
	// D-19 under load: two active admins each disabled by the other at the same moment. Exactly one
	// Disable wins, the other is ErrLastAdmin, and one active admin remains.
	for round := range 5 {
		t.Run(fmt.Sprintf("round %d", round), func(t *testing.T) {
			e := authtest.New(t)
			s := e.Service(t)
			admins := []authtest.User{e.NewAdmin(t), e.NewAdmin(t)}
			errs := stRace(2, func(i int) error {
				return s.Disable(t.Context(), admins[i].ID, authtest.Admin(admins[1-i].ID))
			})
			wins, last := 0, 0
			for _, err := range errs {
				switch {
				case err == nil:
					wins++
				case errors.Is(err, auth.ErrLastAdmin):
					last++
				default:
					t.Errorf("unexpected error: %v", err)
				}
			}
			if wins != 1 || last != 1 {
				t.Fatalf("disables ok=%d last-admin=%d, want 1 and 1", wins, last)
			}
			if got := svCount(t, e, `SELECT count(*) FROM users WHERE role = 'admin' AND status = 'active'`); got != 1 {
				t.Errorf("active admins = %d, want 1", got)
			}
		})
	}
}

func TestMFAConcurrency_DisableRacingTheSecondFactorLeavesNoLiveSession(t *testing.T) {
	// An admin disabled while completing sign-in: either the sign-in wins and Disable ends the new
	// session, or Disable wins and the challenge is refused. Never a live session of a disabled admin.
	for round := range 5 {
		t.Run(fmt.Sprintf("round %d", round), func(t *testing.T) {
			e := authtest.New(t)
			s := e.Service(t)
			a := mfEnrolled(t, e)
			other := e.NewAdmin(t)
			tok := mfChallenge(t, e, s, a.User)
			code := mfCode(t, e, a.Secret, 0)
			stRace(2, func(i int) error {
				if i == 0 {
					_, err := s.VerifyMFA(t.Context(), mfVerifyIn(tok, code))
					return err
				}
				return s.Disable(t.Context(), a.ID, authtest.Admin(other.ID))
			})
			if got := svLiveSessions(t, e, a.ID); got != 0 {
				t.Fatalf("live sessions of the disabled admin = %d, want 0", got)
			}
			if st := svUserRow(t, e, a.ID).Status; st != auth.StatusDisabled {
				t.Errorf("status = %q, want disabled", st)
			}
		})
	}
}
