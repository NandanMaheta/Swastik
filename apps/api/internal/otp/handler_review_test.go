package otp_test

// Review-fix tests for feature 004 over HTTP (BR-CLI-04; spec D-06, D-07, SC-004, FR-009). Four
// findings of the review, each proved from what a stranger can observe:
//
//  1. a handle superseded by a later reset start must not tell a real account from an unknown one;
//  2. timing: the reply of a send operation waits for the response floor, never for the send itself
//     (a controllable floor and a slow mailer, no real sleeping and no medians);
//  3. rate limits are keyed on the typed identifier, so two different identifiers of one account are
//     not linked by a 429;
//  5. a Firebase key-set outage is a 503 and counts no refusal.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/NandanMaheta/swastik/apps/api/internal/auth/authtest"
	"github.com/NandanMaheta/swastik/apps/api/internal/otp"
)

var rvTimeRE = regexp.MustCompile(`[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.]+Z`)

// rvSeen is everything a stranger sees of a reply: status, content type, Retry-After and the body
// with its timestamps replaced by their offset from the start of the test clock.
func rvSeen(rec *httptest.ResponseRecorder) string {
	body := rvTimeRE.ReplaceAllStringFunc(rec.Body.String(), func(s string) string {
		tm, err := time.Parse(time.RFC3339Nano, s)
		if err != nil {
			return s
		}
		return fmt.Sprintf("T%+ds", int(tm.Sub(authtest.T0)/time.Second))
	})
	return fmt.Sprintf("%d %s retry-after=%q %s", rec.Code, rec.Header().Get("Content-Type"), rec.Header().Get("Retry-After"), body)
}

// ---- 1. superseded and decoy handles ---------------------------------------------------------

// rvHandleTrace starts a reset for a real active client (or, with real false, an unknown
// identifier), waits past the cooldown, optionally starts again, and then probes the first handle
// (and the second) with status, a wrong code and resend. It returns what a stranger saw.
func rvHandleTrace(t *testing.T, real, startAgain bool, wrong *string) []string {
	t.Helper()
	h := newHxEnv(t, 10_000)
	identifier := "nobody.at.all@example.com"
	if real {
		identifier = h.Active(t).Email
	}
	start := func() string {
		rec := h.post(pResetGo, map[string]any{"identifier": identifier})
		if rec.Code != http.StatusAccepted {
			t.Fatalf("start reset: %d %s", rec.Code, rec.Body.String())
		}
		return hxMap(t, rec)["handle"].(string)
	}
	first := start()
	if real && *wrong == "" {
		*wrong = svWrongOf(h.LastCode(t))
	}
	h.Clock.Advance(otp.ResendCooldown + time.Second)
	handles := []string{first}
	if startAgain {
		handles = append(handles, start())
	}
	var seen []string
	for i, handle := range handles {
		for _, step := range []struct {
			name, path string
			body       map[string]any
		}{
			{"status", pStatus, map[string]any{"handle": handle}},
			{"verify-email wrong code", pVerifyE, map[string]any{"handle": handle, "code": *wrong}},
			{"resend", pResend, map[string]any{"handle": handle}},
		} {
			seen = append(seen, fmt.Sprintf("handle #%d %s: %s", i+1, step.name, rvSeen(h.post(step.path, step.body))))
		}
	}
	return seen
}

func rvWantSameTrace(t *testing.T, what string, a, b []string) {
	t.Helper()
	if len(a) != len(b) {
		t.Fatalf("%s: %d vs %d observations", what, len(a), len(b))
	}
	for i := range a {
		if a[i] != b[i] {
			t.Errorf("%s: a stranger can tell a real account from an unknown one (D-07)\n  real:    %s\n  unknown: %s", what, a[i], b[i])
		}
	}
}

// The first handle of a reset that was started again after the cooldown answers status, a wrong
// code and resend exactly alike for a real active client and for an unknown identifier.
func TestHandler_BR_CLI_04_SupersededResetHandleDoesNotRevealTheAccount(t *testing.T) {
	var wrong string
	real := rvHandleTrace(t, true, true, &wrong)
	unknown := rvHandleTrace(t, false, true, &wrong)
	rvWantSameTrace(t, "superseded reset", real, unknown)
}

// A real flow and a decoy that is never superseded also answer alike (the control of the above).
func TestHandler_BR_CLI_04_RealAndDecoyResetHandlesAnswerAlike(t *testing.T) {
	var wrong string
	real := rvHandleTrace(t, true, false, &wrong)
	unknown := rvHandleTrace(t, false, false, &wrong)
	rvWantSameTrace(t, "single reset", real, unknown)
}

// ---- 2. timing: the reply waits for the floor, never for the send ------------------------------

// rvGate makes the response floor controllable and the mailer slow, without sleeping. Armed, the
// service's floor wait blocks until the test opens it, and every mail send blocks until released.
type rvGate struct {
	armed        atomic.Bool
	floorEntered chan struct{}
	floorOpen    chan struct{}
	mailRelease  chan struct{}
	mailsBlocked atomic.Int32
	once         sync.Once
	floorOnce    sync.Once
}

func newRvGate(t *testing.T, h *hxEnv) *rvGate {
	t.Helper()
	g := &rvGate{floorEntered: make(chan struct{}, 16), floorOpen: make(chan struct{}), mailRelease: make(chan struct{})}
	h.Waits.Hook = func(_ context.Context, _ time.Time) {
		if !g.armed.Load() {
			return
		}
		select {
		case g.floorEntered <- struct{}{}:
		default:
		}
		<-g.floorOpen
	}
	h.Mailer.Hook = func(_ context.Context) {
		if !g.armed.Load() {
			return
		}
		g.mailsBlocked.Add(1)
		defer g.mailsBlocked.Add(-1)
		<-g.mailRelease
	}
	t.Cleanup(g.releaseAll)
	return g
}

func (g *rvGate) releaseAll() {
	g.once.Do(func() {
		g.openFloor()
		close(g.mailRelease)
	})
	for i := 0; i < 400 && g.mailsBlocked.Load() > 0; i++ {
		<-time.After(5 * time.Millisecond) // let blocked sends finish before the database goes away
	}
}

// rvProbe sends one request with the gate armed and a mailer that never finishes. The request must
// reach the floor wait (not be held up by the send), must not answer before the floor opens, and
// must answer once it opens although the send is still in flight.
func rvProbe(t *testing.T, g *rvGate, send func() *httptest.ResponseRecorder) *httptest.ResponseRecorder {
	t.Helper()
	g.armed.Store(true)
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() { done <- send() }()
	select {
	case <-g.floorEntered:
	case <-time.After(5 * time.Second):
		t.Fatal("the request never reached the response floor: the reply is held up by the slow send, so its time reveals a real account (SC-004, D-07)")
	}
	select {
	case rec := <-done:
		t.Fatalf("answered before the response floor elapsed: %d", rec.Code)
	default:
	}
	g.openFloor() // the floor elapses; the mailer is still blocked
	select {
	case rec := <-done:
		g.armed.Store(false)
		return rec
	case <-time.After(5 * time.Second):
		t.Fatal("still no reply after the floor, while the send is in flight: the reply waits for the send (SC-004)")
	}
	return nil
}

func rvWantAlike(t *testing.T, what string, real, unknown *httptest.ResponseRecorder) {
	t.Helper()
	if real.Code != http.StatusAccepted || unknown.Code != http.StatusAccepted {
		t.Fatalf("%s: statuses real %d unknown %d, want 202 both: %s | %s", what, real.Code, unknown.Code, real.Body.String(), unknown.Body.String())
	}
	a, b := hxMap(t, real), hxMap(t, unknown)
	for _, k := range []string{"expires_at", "next_resend_at", "code_expires_at"} {
		if _, ok := a[k]; ok != (b[k] != nil) {
			t.Errorf("%s: field %s present for one and not the other", what, k)
		} else if ok && hxTime(t, a, k) != hxTime(t, b, k) {
			t.Errorf("%s: %s differs: %v vs %v", what, k, a[k], b[k])
		}
	}
}

func TestHandler_BR_CLI_04_SC004_ResetStartAnswersAtTheFloorWhateverTheSendTakes(t *testing.T) {
	probe := func(t *testing.T, real bool) *httptest.ResponseRecorder {
		h := newHxEnv(t, 10_000)
		g := newRvGate(t, h)
		identifier := "nobody.at.all@example.com"
		if real {
			identifier = h.Active(t).Email
		}
		return rvProbe(t, g, func() *httptest.ResponseRecorder { return h.post(pResetGo, map[string]any{"identifier": identifier}) })
	}
	rvWantAlike(t, "reset start", probe(t, true), probe(t, false))
}

func TestHandler_BR_CLI_04_SC004_PublicResendAnswersAtTheFloorWhateverTheSendTakes(t *testing.T) {
	probe := func(t *testing.T, real bool) *httptest.ResponseRecorder {
		h := newHxEnv(t, 10_000)
		g := newRvGate(t, h)
		identifier := "nobody.at.all@example.com"
		if real {
			identifier = h.Active(t).Email
		}
		rec := h.post(pResetGo, map[string]any{"identifier": identifier})
		if rec.Code != http.StatusAccepted {
			t.Fatalf("start reset: %d %s", rec.Code, rec.Body.String())
		}
		handle := hxMap(t, rec)["handle"].(string)
		h.Clock.Advance(otp.ResendCooldown + time.Second)
		return rvProbe(t, g, func() *httptest.ResponseRecorder { return h.post(pResend, map[string]any{"handle": handle}) })
	}
	rvWantAlike(t, "resend", probe(t, true), probe(t, false))
}

// ---- 3. limits are keyed on the typed identifier -----------------------------------------------

// Two starts within a minute by two different identifiers answer alike (both 202, same times)
// whether or not the identifiers belong to one account: no 429 links a mobile and an email of the
// same client. The same identifier twice is refused alike for known and unknown ones.
func TestHandler_BR_CLI_04_ResetLimitsDoNotLinkTheIdentifiersOfOneAccount(t *testing.T) {
	type ids func(t *testing.T, h *hxEnv) (first, second string)
	cases := []struct {
		name string
		ids  ids
	}{
		// The unknown pair comes first: it is the baseline every other pair must answer like.
		{"unknown mobile then unknown email", func(t *testing.T, h *hxEnv) (string, string) { return "+919123456789", "nobody.at.all@example.com" }},
		{"mobile then email of one account", func(t *testing.T, h *hxEnv) (string, string) { u := h.Active(t); return u.Mobile, u.Email }},
		{"email then mobile of one account", func(t *testing.T, h *hxEnv) (string, string) { u := h.Active(t); return u.Email, u.Mobile }},
		{"mobile then email of two accounts", func(t *testing.T, h *hxEnv) (string, string) {
			a, b := h.Active(t), h.Active(t)
			return a.Mobile, b.Email
		}},
	}
	var want string
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newHxEnv(t, 10_000)
			first, second := c.ids(t, h)
			if rec := h.post(pResetGo, map[string]any{"identifier": first}); rec.Code != http.StatusAccepted {
				t.Fatalf("first start: %d %s", rec.Code, rec.Body.String())
			}
			h.Clock.Advance(10 * time.Second)
			rec := h.post(pResetGo, map[string]any{"identifier": second})
			if rec.Code != http.StatusAccepted {
				t.Errorf("second start by a different identifier = %d %s, want 202: a limit linked the two identifiers (D-07)", rec.Code, rec.Body.String())
			}
			got := rvSeen(rec)
			got = regexp.MustCompile(`"handle":\s*"[^"]*"`).ReplaceAllString(got, `"handle":"-"`)
			if want == "" {
				want = got
			} else if got != want {
				t.Errorf("reply differs from the other cases (D-07)\n  got:  %s\n  want: %s", got, want)
			}
		})
	}
}

// The same typed identifier asked twice within the cooldown is refused, and refused identically for
// a known account and an unknown one.
func TestHandler_BR_CLI_04_ResetCooldownOfOneIdentifierIsTheSameForKnownAndUnknown(t *testing.T) {
	seen := func(t *testing.T, typed func(h *hxEnv) string) string {
		h := newHxEnv(t, 10_000)
		id := typed(h)
		h.post(pResetGo, map[string]any{"identifier": id})
		h.Clock.Advance(10 * time.Second)
		rec := h.post(pResetGo, map[string]any{"identifier": id})
		hxWantProblem(t, "second start within the cooldown", rec, http.StatusTooManyRequests, "otp.cooldown")
		return rvSeen(rec)
	}
	for _, kind := range []string{"email", "mobile"} {
		known := seen(t, func(h *hxEnv) string {
			u := h.Active(t)
			if kind == "mobile" {
				return u.Mobile
			}
			return u.Email
		})
		unknown := seen(t, func(h *hxEnv) string {
			if kind == "mobile" {
				return "+919123456789"
			}
			return "nobody.at.all@example.com"
		})
		if known != unknown {
			t.Errorf("%s: known %s, unknown %s: the cooldown answer differs (D-07)", kind, known, unknown)
		}
	}
}

// ---- 5. a key-set outage is a 503 and counts no refusal ------------------------------------------

func TestHandler_BR_CLI_04_FirebaseKeySetOutageIs503AndCountsNoRefusal(t *testing.T) {
	h := newHxEnv(t, 10_000)
	u := h.Pending(t)
	st := h.StartSignup(t, u)
	if rec := h.post(pVerifyE, map[string]any{"handle": st.Handle, "code": h.PendingCode(t, st.ID)}); rec.Code != http.StatusOK {
		t.Fatalf("verify-email: %d %s", rec.Code, rec.Body.String())
	}
	token := h.Token(t, u.Mobile)

	h.Minter.SetOutage(true)
	rec := h.post(pVerifyM, map[string]any{"handle": st.Handle, "firebase_id_token": token})
	p := hxProblem{}
	_ = json.Unmarshal(rec.Body.Bytes(), &p)
	if rec.Code != http.StatusServiceUnavailable || p.Code == "" || p.Code == "otp.proof_invalid" {
		t.Fatalf("verify-mobile during a key-set outage = %d code %q (%s), want 503 and not otp.proof_invalid", rec.Code, p.Code, rec.Body.String())
	}
	if c := h.Counts(t); c.ProofRefused != 0 || c.ProofAccepted != 0 {
		t.Errorf("counts = %+v, want no refusal counted for an outage on our side", c)
	}
	if n := h.Count(t, `SELECT count(*) FROM otp_used_proofs`); n != 0 {
		t.Errorf("used proofs = %d, want none", n)
	}

	h.Minter.SetOutage(false)
	if rec := h.post(pVerifyM, map[string]any{"handle": st.Handle, "firebase_id_token": token}); rec.Code != http.StatusOK {
		t.Errorf("the same proof after the outage = %d %s, want 200: the outage must not have burned it", rec.Code, rec.Body.String())
	}
}

func (g *rvGate) openFloor() { g.floorOnce.Do(func() { close(g.floorOpen) }) }
