package auth_test

// S20 - SC-003 (the six generic sign-in failures cannot be told apart by timing) and the Argon2id
// cost benchmark behind SC-007 (plan P-06, research section 2).
//
// SC-003 asks for median response times within 10% of each other over 50 attempts per case. A single
// wall-clock comparison on a shared machine is noisy, so the check is built to be robust and to
// fail only on a real difference:
//   - the six cases are interleaved attempt by attempt (rotating the starting case), so load and
//     drift hit every case alike;
//   - the production Argon2id parameters are used, so hashing (about tens of milliseconds)
//     dominates the database round trips that differ slightly between paths;
//   - the statistic is the median, as the criterion says, after a warm-up;
//   - a measurement round that misses the tolerance is repeated up to three times, and the test
//     fails only if every round misses. A real leak (a path that skips the hash, say) costs 90% or
//     more of the response time, so it misses in every round.
// It is skipped under -short because it hashes about 300 times.

import (
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/NandanMaheta/swastik/apps/api/internal/auth"
	"github.com/NandanMaheta/swastik/apps/api/internal/auth/authtest"
)

const (
	timingAttempts  = 50
	timingWarmup    = 3
	timingTolerance = 0.10
	timingRounds    = 3
)

func median(ds []time.Duration) time.Duration {
	s := slices.Clone(ds)
	slices.Sort(s)
	return s[len(s)/2]
}

// tmCase is one of the six failure cases of D-09: how to build the attempt number i.
type tmCase struct {
	name string
	in   func(i int) auth.SignInInput
}

func tmCases(t *testing.T, e *authtest.Env, s *auth.Service, total int) []tmCase {
	t.Helper()
	pendingVerification := e.UserWithStatus(t, auth.StatusPendingVerification)
	pendingApproval := e.UserWithStatus(t, auth.StatusPendingApproval)
	disabled := e.UserWithStatus(t, auth.StatusDisabled)
	locked := e.UserWithStatus(t, auth.StatusActive)
	for range 5 {
		svWrong(t, s, locked)
	}
	wrongPw := make([]authtest.User, total)
	for i := range wrongPw {
		wrongPw[i] = e.UserWithStatus(t, auth.StatusActive) // one user per attempt: no lockout in the middle of a round
	}
	same := func(u authtest.User) func(int) auth.SignInInput {
		return func(int) auth.SignInInput { return svInput(u, uuid.New()) }
	}
	return []tmCase{
		{"unknown identifier", func(i int) auth.SignInInput {
			in := svInput(pendingApproval, uuid.New())
			in.Identifier = fmt.Sprintf("nobody.%d.%s@nowhere.test", i, uuid.NewString()[:8])
			return in
		}},
		{"wrong password", func(i int) auth.SignInInput {
			in := svInput(wrongPw[i], uuid.New())
			in.Password = wrongPassword
			return in
		}},
		{"locked", same(locked)},
		{"pending_verification", same(pendingVerification)},
		{"pending_approval", same(pendingApproval)},
		{"disabled", same(disabled)},
	}
}

func TestSignIn_SC003_GenericFailuresTakeTheSameTime(t *testing.T) {
	if testing.Short() {
		t.Skip("SC-003 timing check hashes ~300 passwords; skipped with -short")
	}
	e := authtest.New(t)
	// Production cost: Argon2id must dominate the response time as it does in production.
	e.Hasher = auth.NewHasher(auth.HasherOptions{})
	s := e.Service(t)

	var lastReport string
	for round := 1; round <= timingRounds; round++ {
		cases := tmCases(t, e, s, timingWarmup+timingAttempts)
		samples := make([][]time.Duration, len(cases))
		var firstErr error
		for i := range timingWarmup + timingAttempts {
			for k := range cases {
				c := (k + i) % len(cases) // rotate the starting case
				in := cases[c].in(i)
				start := time.Now()
				_, err := s.SignIn(t.Context(), in)
				took := time.Since(start)
				if !errors.Is(err, auth.ErrInvalidCredentials) {
					t.Fatalf("%s: err = %v, want the generic failure", cases[c].name, err)
				}
				if firstErr == nil {
					firstErr = err
				} else if err.Error() != firstErr.Error() {
					t.Fatalf("%s: error text %q differs from %q", cases[c].name, err.Error(), firstErr.Error())
				}
				if i >= timingWarmup {
					samples[c] = append(samples[c], took)
				}
			}
		}
		meds := make([]time.Duration, len(cases))
		for c := range cases {
			meds[c] = median(samples[c])
		}
		ref := median(meds)
		if ref < 2*time.Millisecond {
			t.Fatalf("median response %v is below 2ms: Argon2id is not running at production cost, the check proves nothing", ref)
		}
		worst, report := 0.0, ""
		for c := range cases {
			dev := float64(meds[c]-ref) / float64(ref)
			if dev < 0 {
				dev = -dev
			}
			worst = max(worst, dev)
			report += fmt.Sprintf("\n  %-22s median %v (%+.1f%%)", cases[c].name, meds[c].Round(10*time.Microsecond), 100*float64(meds[c]-ref)/float64(ref))
		}
		lastReport = fmt.Sprintf("round %d: reference median %v, worst deviation %.1f%% (tolerance %.0f%%)%s", round, ref.Round(10*time.Microsecond), 100*worst, 100*timingTolerance, report)
		t.Log(lastReport)
		if worst < timingTolerance {
			return
		}
	}
	t.Errorf("no round of %d kept the six failure cases within %.0f%% of each other:\n%s", timingRounds, 100*timingTolerance, lastReport)
}

// ---- Argon2id (SC-007, plan P-06) ----

func TestArgon2id_DefaultsMeetTheOWASPMinimumAndTheSignInBudget(t *testing.T) {
	p := auth.DefaultHasherParams
	if p.MemoryKiB < 19456 || p.Time < 2 || p.Threads < 1 {
		t.Fatalf("default parameters %+v are below the OWASP minimum (m=19456 KiB, t=2, p=1)", p)
	}
	if testing.Short() {
		t.Skip("latency check skipped with -short")
	}
	h := auth.NewHasher(auth.HasherOptions{})
	phc, err := h.Hash(t.Context(), "river-lantern-42-monsoon")
	if err != nil {
		t.Fatal(err)
	}
	const runs = 15
	var ds []time.Duration
	for range runs {
		start := time.Now()
		if ok, err := h.Verify(t.Context(), phc, "river-lantern-42-monsoon"); !ok || err != nil {
			t.Fatalf("verify = %v, %v", ok, err)
		}
		ds = append(ds, time.Since(start))
	}
	med := median(ds)
	// The criterion is p95 < 200 ms for the whole request (SC-007). A single verify must leave room for
	// the rest, and must not be cheap enough to be a weak hash. The bound is generous because this also
	// runs under the race detector on shared CI.
	if med < 2*time.Millisecond || med > 150*time.Millisecond {
		t.Errorf("median Argon2id verify = %v, want between 2ms (not a weak hash) and 150ms (leaves room in the 200ms budget)", med)
	}
	t.Logf("Argon2id %+v: median verify %v over %d runs", p, med, runs)
}

func BenchmarkArgon2id_Hash(b *testing.B) {
	h := auth.NewHasher(auth.HasherOptions{})
	for b.Loop() {
		if _, err := h.Hash(b.Context(), "river-lantern-42-monsoon"); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkArgon2id_Verify(b *testing.B) {
	h := auth.NewHasher(auth.HasherOptions{})
	phc, err := h.Hash(b.Context(), "river-lantern-42-monsoon")
	if err != nil {
		b.Fatal(err)
	}
	for b.Loop() {
		if ok, err := h.Verify(b.Context(), phc, "river-lantern-42-monsoon"); !ok || err != nil {
			b.Fatalf("verify = %v, %v", ok, err)
		}
	}
}

// BenchmarkArgon2id_VerifyNoAccount is the dummy-hash path: it must cost the same as a real verify.
func BenchmarkArgon2id_VerifyNoAccount(b *testing.B) {
	h := auth.NewHasher(auth.HasherOptions{})
	for b.Loop() {
		if ok, err := h.Verify(b.Context(), "", "river-lantern-42-monsoon"); ok || err != nil {
			b.Fatalf("verify = %v, %v", ok, err)
		}
	}
}

// BenchmarkArgon2id_VerifyBurst is a burst of sign-ins through the concurrency cap (default 4):
// throughput must hold without exhausting memory (4 x 19 MiB), which is what the cap is for.
func BenchmarkArgon2id_VerifyBurst(b *testing.B) {
	h := auth.NewHasher(auth.HasherOptions{WaitBound: time.Minute})
	phc, err := h.Hash(b.Context(), "river-lantern-42-monsoon")
	if err != nil {
		b.Fatal(err)
	}
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if ok, err := h.Verify(b.Context(), phc, "river-lantern-42-monsoon"); !ok || err != nil {
				b.Errorf("verify = %v, %v", ok, err)
				return
			}
		}
	})
}
