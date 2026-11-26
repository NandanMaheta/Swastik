// Store tests of the otp module (feature 004, S08; BR-CLI-04, BR-CLI-05, FR-015, FR-017, D-01..D-03).
// Real PostgreSQL through dbtest; every call goes through the Store contract in store_types.go, with
// the fixtures (org, users) written as plain SQL so a Store bug cannot hide behind them.
package otp_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/NandanMaheta/swastik/apps/api/internal/otp"
	"github.com/NandanMaheta/swastik/apps/api/internal/platform/db"
	"github.com/NandanMaheta/swastik/apps/api/internal/platform/dbtest"
	"github.com/NandanMaheta/swastik/apps/api/internal/platform/istdate"
)

var st0 = time.Date(2026, time.November, 26, 4, 30, 0, 0, time.UTC) // 10:00 IST

type storeEnv struct {
	t     *testing.T
	pool  *pgxpool.Pool
	txr   db.TxRunner
	store otp.Store
	org   uuid.UUID
	user  uuid.UUID
	seq   int
}

func newStoreEnv(t *testing.T) *storeEnv {
	t.Helper()
	pool := dbtest.NewSized(t, 16)
	e := &storeEnv{t: t, pool: pool, txr: db.NewTxRunner(pool), org: uuid.New(), user: uuid.New()}
	e.exec(`INSERT INTO orgs (id, name) VALUES ($1, 'Swastik')`, e.org)
	e.addUser(e.org, e.user)
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("otp.NewPGStore: %v", r)
			}
		}()
		e.store = otp.NewPGStore(e.txr)
	}()
	return e
}

func (e *storeEnv) exec(sql string, args ...any) {
	e.t.Helper()
	if _, err := e.pool.Exec(context.Background(), sql, args...); err != nil {
		e.t.Fatalf("exec %q: %v", sql, err)
	}
}

func (e *storeEnv) addUser(org, id uuid.UUID) {
	e.t.Helper()
	e.seq++
	e.exec(`INSERT INTO users (id, org_id, role, status, name, email, mobile, password_hash, password_changed_at)
		VALUES ($1,$2,'client','pending_verification','Ravi Shah',$3,$4,'$argon2id$v=19$stub',$5)`,
		id, org, fmt.Sprintf("s%d@example.com", e.seq), fmt.Sprintf("+91981230%04d", e.seq), st0)
}

func (e *storeEnv) newOrg() uuid.UUID {
	e.t.Helper()
	id := uuid.New()
	e.exec(`INSERT INTO orgs (id, name) VALUES ($1, 'Other')`, id)
	return id
}

func (e *storeEnv) inTx(fn func(ctx context.Context) error) error {
	return e.txr.InTx(e.t.Context(), fn)
}

func (e *storeEnv) mustTx(fn func(ctx context.Context) error) {
	e.t.Helper()
	if err := e.inTx(fn); err != nil {
		e.t.Fatalf("transaction: %v", err)
	}
}

func handleHash(s string) []byte { h := sha256.Sum256([]byte(s)); return h[:] }

// newVer inserts a signup verification for the env's user with the given handle seed.
func (e *storeEnv) newVer(handle string) otp.VerificationRow {
	e.t.Helper()
	return e.insertVer(otp.NewVerification{
		OrgID: e.org, UserID: e.user, Purpose: otp.PurposeSignup, HandleHash: handleHash(handle),
		Email: "ravi@example.com", Mobile: "+919812345678", Now: st0, ExpiresAt: st0.Add(otp.VerificationTTL),
	})
}

func (e *storeEnv) insertVer(in otp.NewVerification) otp.VerificationRow {
	e.t.Helper()
	v, err := e.store.InsertVerification(e.t.Context(), in)
	if err != nil {
		e.t.Fatalf("InsertVerification: %v", err)
	}
	return v
}

func (e *storeEnv) newCode(ver otp.VerificationRow, key string) otp.CodeRow {
	e.t.Helper()
	c, err := e.store.InsertCode(e.t.Context(), otp.NewCode{
		ID: uuid.New(), OrgID: ver.OrgID, VerificationID: ver.ID, Digest: bytes.Repeat([]byte{0xD1}, 32),
		OutboxKey: key, IssuedAt: st0, ExpiresAt: st0.Add(otp.CodeTTL),
	})
	if err != nil {
		e.t.Fatalf("InsertCode: %v", err)
	}
	return c
}

func sameTime(a, b time.Time) bool { return a.Equal(b) }

// ---- verifications --------------------------------------------------------------------------

func TestStore_BR_CLI_04_InsertAndReadVerificationRoundTrip(t *testing.T) {
	e := newStoreEnv(t)
	v := e.newVer("handle-1")
	if v.ID == uuid.Nil || v.OrgID != e.org || v.UserID != e.user || v.Purpose != otp.PurposeSignup {
		t.Fatalf("inserted row = %+v", v)
	}
	if v.Email != "ravi@example.com" || v.Mobile != "+919812345678" {
		t.Errorf("targets = %q %q", v.Email, v.Mobile)
	}
	if !sameTime(v.CreatedAt, st0) || !sameTime(v.UpdatedAt, st0) || !sameTime(v.ExpiresAt, st0.Add(24*time.Hour)) {
		t.Errorf("times = created %v updated %v expires %v, want the caller's clock", v.CreatedAt, v.UpdatedAt, v.ExpiresAt)
	}
	if v.EmailDoneAt != nil || v.MobileDoneAt != nil || v.FinishedAt != nil || v.CancelledAt != nil || v.CancelReason != "" || v.ResetTokenHash != nil {
		t.Errorf("a new verification must be untouched: %+v", v)
	}
	got, err := e.store.GetVerification(t.Context(), e.org, v.ID)
	if err != nil || got.ID != v.ID || got.Email != v.Email {
		t.Fatalf("GetVerification = %+v, %v", got, err)
	}
}

func TestStore_BR_CLI_04_ChangePurposesAndDecoyShapes(t *testing.T) {
	e := newStoreEnv(t)
	ce := e.insertVer(otp.NewVerification{OrgID: e.org, UserID: e.user, Purpose: otp.PurposeChangeEmail, HandleHash: handleHash("ce"), Email: "new@example.com", Now: st0, ExpiresAt: st0.Add(time.Hour)})
	if ce.Email != "new@example.com" || ce.Mobile != "" {
		t.Errorf("change_email row = %+v", ce)
	}
	cm := e.insertVer(otp.NewVerification{OrgID: e.org, UserID: e.user, Purpose: otp.PurposeChangeMobile, HandleHash: handleHash("cm"), Mobile: "+919812345679", Now: st0, ExpiresAt: st0.Add(time.Hour)})
	if cm.Mobile != "+919812345679" || cm.Email != "" {
		t.Errorf("change_mobile row = %+v", cm)
	}
	d1 := e.insertVer(otp.NewVerification{OrgID: e.org, Purpose: otp.PurposePasswordReset, HandleHash: handleHash("d1"), Now: st0, ExpiresAt: st0.Add(time.Hour)})
	d2 := e.insertVer(otp.NewVerification{OrgID: e.org, Purpose: otp.PurposePasswordReset, HandleHash: handleHash("d2"), Now: st0, ExpiresAt: st0.Add(time.Hour)})
	if d1.UserID != uuid.Nil || d2.UserID != uuid.Nil || d1.Email != "" {
		t.Errorf("decoys = %+v / %+v, want no user and no email", d1, d2)
	}
}

func TestStore_BR_CLI_04_OnlyOneOpenFlowPerUserAndPurposeThenSupersede(t *testing.T) {
	e := newStoreEnv(t)
	first := e.newVer("h1")
	_, err := e.store.InsertVerification(t.Context(), otp.NewVerification{
		OrgID: e.org, UserID: e.user, Purpose: otp.PurposeSignup, HandleHash: handleHash("h2"),
		Email: "ravi@example.com", Mobile: "+919812345678", Now: st0, ExpiresAt: st0.Add(time.Hour)})
	if !errors.Is(err, otp.ErrOpenFlowExists) {
		t.Fatalf("second open flow error = %v, want ErrOpenFlowExists", err)
	}

	// Start's supersede sequence, in one transaction: lock the open flow, cancel it, insert the new one.
	var second otp.VerificationRow
	e.mustTx(func(ctx context.Context) error {
		old, err := e.store.LockOpenVerification(ctx, e.org, e.user, otp.PurposeSignup)
		if err != nil {
			return err
		}
		if old.ID != first.ID {
			t.Errorf("locked %v, want the open flow %v", old.ID, first.ID)
		}
		if err := e.store.CancelVerification(ctx, e.org, old.ID, otp.CancelSuperseded, st0.Add(time.Minute)); err != nil {
			return err
		}
		second, err = e.store.InsertVerification(ctx, otp.NewVerification{
			OrgID: e.org, UserID: e.user, Purpose: otp.PurposeSignup, HandleHash: handleHash("h2"),
			Email: "ravi@example.com", Mobile: "+919812345678", Now: st0.Add(time.Minute), ExpiresAt: st0.Add(time.Hour)})
		return err
	})
	old, _ := e.store.GetVerification(t.Context(), e.org, first.ID)
	if old.CancelledAt == nil || !sameTime(*old.CancelledAt, st0.Add(time.Minute)) || old.CancelReason != otp.CancelSuperseded {
		t.Errorf("superseded row = %+v", old)
	}
	e.mustTx(func(ctx context.Context) error {
		cur, err := e.store.LockOpenVerification(ctx, e.org, e.user, otp.PurposeSignup)
		if err == nil && cur.ID != second.ID {
			t.Errorf("open flow = %v, want the new one %v", cur.ID, second.ID)
		}
		return err
	})
	// Another purpose has no open flow.
	err = e.inTx(func(ctx context.Context) error {
		_, err := e.store.LockOpenVerification(ctx, e.org, e.user, otp.PurposeChangeEmail)
		return err
	})
	if !errors.Is(err, otp.ErrNotFound) {
		t.Errorf("LockOpenVerification with no flow = %v, want ErrNotFound", err)
	}
}

func TestStore_BR_CLI_04_LockByHandleHashRequiresATransactionAndFindsOnlyThatHandle(t *testing.T) {
	e := newStoreEnv(t)
	v := e.newVer("the-handle")
	e.newVer2("other-user-handle")

	if _, err := e.store.LockVerificationByHandle(t.Context(), e.org, handleHash("the-handle")); !errors.Is(err, db.ErrNoTx) {
		t.Fatalf("outside a tx error = %v, want db.ErrNoTx", err)
	}
	e.mustTx(func(ctx context.Context) error {
		got, err := e.store.LockVerificationByHandle(ctx, e.org, handleHash("the-handle"))
		if err != nil || got.ID != v.ID {
			t.Errorf("LockVerificationByHandle = %+v, %v, want %v", got, err, v.ID)
		}
		if _, err := e.store.LockVerificationByHandle(ctx, e.org, handleHash("unknown")); !errors.Is(err, otp.ErrNotFound) {
			t.Errorf("unknown handle error = %v, want ErrNotFound", err)
		}
		if _, err := e.store.LockVerificationByHandle(ctx, uuid.New(), handleHash("the-handle")); !errors.Is(err, otp.ErrNotFound) {
			t.Errorf("another org error = %v, want ErrNotFound", err)
		}
		byID, err := e.store.LockVerification(ctx, e.org, v.ID)
		if err != nil || byID.ID != v.ID {
			t.Errorf("LockVerification = %+v, %v", byID, err)
		}
		return nil
	})
	if _, err := e.store.LockVerification(t.Context(), e.org, v.ID); !errors.Is(err, db.ErrNoTx) {
		t.Errorf("LockVerification outside a tx = %v, want db.ErrNoTx", err)
	}
}

// newVer2 is a second user's signup flow.
func (e *storeEnv) newVer2(handle string) otp.VerificationRow {
	other := uuid.New()
	e.addUser(e.org, other)
	return e.insertVer(otp.NewVerification{OrgID: e.org, UserID: other, Purpose: otp.PurposeSignup, HandleHash: handleHash(handle),
		Email: "o@example.com", Mobile: "+919812300000", Now: st0, ExpiresAt: st0.Add(time.Hour)})
}

func TestStore_BR_CLI_04_VerificationLockSerialisesConcurrentTransactions(t *testing.T) {
	e := newStoreEnv(t)
	v := e.newVer("h")
	holding, release := make(chan struct{}), make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = e.inTx(func(ctx context.Context) error {
			if _, err := e.store.LockVerificationByHandle(ctx, e.org, handleHash("h")); err != nil {
				t.Errorf("first lock: %v", err)
			}
			close(holding)
			<-release
			return nil
		})
	}()
	<-holding
	acquired := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = e.inTx(func(ctx context.Context) error {
			_, err := e.store.LockVerification(ctx, e.org, v.ID)
			close(acquired)
			return err
		})
	}()
	select {
	case <-acquired:
		t.Fatal("a second transaction locked the verification while the first held it")
	case <-time.After(300 * time.Millisecond):
	}
	close(release)
	select {
	case <-acquired:
	case <-time.After(5 * time.Second):
		t.Fatal("the second transaction never got the lock after the first committed")
	}
	wg.Wait()
}

func TestStore_BR_CLI_04_MarkFinishCancelAndResetGrant(t *testing.T) {
	e := newStoreEnv(t)
	v := e.newVer("h")
	ctx := t.Context()

	if err := e.store.MarkContactDone(ctx, e.org, v.ID, otp.ContactEmail, st0.Add(time.Minute)); err != nil {
		t.Fatalf("MarkContactDone email: %v", err)
	}
	// Marking again keeps the first instant.
	if err := e.store.MarkContactDone(ctx, e.org, v.ID, otp.ContactEmail, st0.Add(time.Hour)); err != nil {
		t.Fatalf("MarkContactDone email again: %v", err)
	}
	if err := e.store.MarkContactDone(ctx, e.org, v.ID, otp.ContactMobile, st0.Add(2*time.Minute)); err != nil {
		t.Fatalf("MarkContactDone mobile: %v", err)
	}
	got, _ := e.store.GetVerification(ctx, e.org, v.ID)
	if got.EmailDoneAt == nil || !sameTime(*got.EmailDoneAt, st0.Add(time.Minute)) || got.MobileDoneAt == nil || !sameTime(*got.MobileDoneAt, st0.Add(2*time.Minute)) {
		t.Errorf("done times = %v %v", got.EmailDoneAt, got.MobileDoneAt)
	}
	if err := e.store.FinishVerification(ctx, e.org, v.ID, st0.Add(3*time.Minute)); err != nil {
		t.Fatalf("FinishVerification: %v", err)
	}
	got, _ = e.store.GetVerification(ctx, e.org, v.ID)
	if got.FinishedAt == nil || !sameTime(*got.FinishedAt, st0.Add(3*time.Minute)) || !sameTime(got.UpdatedAt, st0.Add(3*time.Minute)) {
		t.Errorf("finished = %v updated = %v", got.FinishedAt, got.UpdatedAt)
	}
	if err := e.store.CancelVerification(ctx, e.org, v.ID, otp.CancelCancelled, st0.Add(4*time.Minute)); !errors.Is(err, otp.ErrNotFound) {
		t.Errorf("cancelling a finished flow = %v, want ErrNotFound", err)
	}

	r := e.insertVer(otp.NewVerification{OrgID: e.org, UserID: e.user, Purpose: otp.PurposePasswordReset, HandleHash: handleHash("r"), Email: "ravi@example.com", Now: st0, ExpiresAt: st0.Add(time.Hour)})
	tok := handleHash("prt_token")
	if err := e.store.SetResetGrant(ctx, e.org, r.ID, tok, st0.Add(10*time.Minute), st0.Add(time.Minute)); err != nil {
		t.Fatalf("SetResetGrant: %v", err)
	}
	r, _ = e.store.GetVerification(ctx, e.org, r.ID)
	if !bytes.Equal(r.ResetTokenHash, tok) || r.ResetTokenExpiresAt == nil || !sameTime(*r.ResetTokenExpiresAt, st0.Add(10*time.Minute)) {
		t.Errorf("reset grant = %x %v", r.ResetTokenHash, r.ResetTokenExpiresAt)
	}
	if err := e.store.CancelVerification(ctx, e.org, r.ID, otp.CancelCancelled, st0.Add(5*time.Minute)); err != nil {
		t.Fatalf("CancelVerification: %v", err)
	}
	r, _ = e.store.GetVerification(ctx, e.org, r.ID)
	if r.CancelledAt == nil || r.CancelReason != otp.CancelCancelled {
		t.Errorf("cancelled row = %+v", r)
	}
	for name, err := range map[string]error{
		"mark unknown":   e.store.MarkContactDone(ctx, e.org, uuid.New(), otp.ContactEmail, st0),
		"finish unknown": e.store.FinishVerification(ctx, e.org, uuid.New(), st0),
		"cancel unknown": e.store.CancelVerification(ctx, e.org, uuid.New(), otp.CancelCancelled, st0),
		"grant unknown":  e.store.SetResetGrant(ctx, e.org, uuid.New(), tok, st0, st0),
	} {
		if !errors.Is(err, otp.ErrNotFound) {
			t.Errorf("%s: error = %v, want ErrNotFound", name, err)
		}
	}
}

// ---- codes ----------------------------------------------------------------------------------

func TestStore_BR_CLI_04_OneLiveCodeEndedWithItsReason(t *testing.T) {
	e := newStoreEnv(t)
	v := e.newVer("h")
	c := e.newCode(v, "otp:code:1")
	if c.WrongAttempts != 0 || c.EndedAt != nil || c.OutboxKey != "otp:code:1" || !sameTime(c.ExpiresAt, st0.Add(10*time.Minute)) {
		t.Fatalf("code = %+v", c)
	}
	_, err := e.store.InsertCode(t.Context(), otp.NewCode{ID: uuid.New(), OrgID: e.org, VerificationID: v.ID, Digest: bytes.Repeat([]byte{1}, 32), IssuedAt: st0, ExpiresAt: st0.Add(time.Minute)})
	if !errors.Is(err, otp.ErrLiveCodeExists) {
		t.Fatalf("second live code error = %v, want ErrLiveCodeExists", err)
	}

	ended, err := e.store.EndLiveCode(t.Context(), e.org, v.ID, otp.EndSuperseded, st0.Add(time.Minute))
	if err != nil || ended.ID != c.ID || ended.OutboxKey != "otp:code:1" || ended.EndReason != otp.EndSuperseded || ended.EndedAt == nil || !sameTime(*ended.EndedAt, st0.Add(time.Minute)) {
		t.Fatalf("EndLiveCode = %+v, %v (the key is returned so the caller can withdraw the email)", ended, err)
	}
	if _, err := e.store.EndLiveCode(t.Context(), e.org, v.ID, otp.EndUsed, st0); !errors.Is(err, otp.ErrNoLiveCode) {
		t.Errorf("EndLiveCode with none = %v, want ErrNoLiveCode", err)
	}
	c2 := e.newCode(v, "otp:code:2") // a newer code after the first ended (D-01)
	if c2.ID == c.ID {
		t.Error("new code reused the id")
	}
	for _, reason := range []string{otp.EndUsed, otp.EndUsedUp, otp.EndCancelled} {
		if _, err := e.store.EndLiveCode(t.Context(), e.org, v.ID, reason, st0); err != nil {
			t.Fatalf("EndLiveCode(%s): %v", reason, err)
		}
		e.newCode(v, "otp:code:x"+reason)
	}
}

func TestStore_BR_CLI_04_DecoyCodeHasNoOutboxKey(t *testing.T) {
	e := newStoreEnv(t)
	d := e.insertVer(otp.NewVerification{OrgID: e.org, Purpose: otp.PurposePasswordReset, HandleHash: handleHash("d"), Now: st0, ExpiresAt: st0.Add(time.Hour)})
	c := e.newCode(d, "")
	if c.OutboxKey != "" {
		t.Errorf("decoy code key = %q, want none", c.OutboxKey)
	}
}

func TestStore_BR_CLI_04_LiveCodeLockMakesDoubleEntrySingleUse(t *testing.T) {
	e := newStoreEnv(t)
	v := e.newVer("h")
	e.newCode(v, "k")

	if _, err := e.store.LockLiveCode(t.Context(), e.org, v.ID); !errors.Is(err, db.ErrNoTx) {
		t.Fatalf("LockLiveCode outside a tx = %v, want db.ErrNoTx", err)
	}
	// Two concurrent verifies: both lock the live code; only the first still finds it live.
	var wg sync.WaitGroup
	results := make([]error, 2)
	for i := range results {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i] = e.inTx(func(ctx context.Context) error {
				c, err := e.store.LockLiveCode(ctx, e.org, v.ID)
				if err != nil {
					return err
				}
				time.Sleep(150 * time.Millisecond) // widen the race window
				_, err = e.store.EndLiveCode(ctx, e.org, c.VerificationID, otp.EndUsed, st0)
				return err
			})
		}()
	}
	wg.Wait()
	wins, losses := 0, 0
	for _, err := range results {
		switch {
		case err == nil:
			wins++
		case errors.Is(err, otp.ErrNoLiveCode):
			losses++
		default:
			t.Errorf("unexpected error: %v", err)
		}
	}
	if wins != 1 || losses != 1 {
		t.Fatalf("results = %v, want exactly one success and one ErrNoLiveCode (US1.3)", results)
	}
}

func TestStore_BR_CLI_04_WrongAttemptsCountUpToTheLimit(t *testing.T) {
	e := newStoreEnv(t)
	v := e.newVer("h")
	c := e.newCode(v, "k")
	for want := 1; want <= otp.MaxWrongAttempts; want++ {
		got, err := e.store.AddWrongAttempt(t.Context(), e.org, c.ID, st0.Add(time.Duration(want)*time.Second))
		if err != nil || got != want {
			t.Fatalf("AddWrongAttempt #%d = %d, %v, want %d", want, got, err, want)
		}
	}
	e.mustTx(func(ctx context.Context) error {
		locked, err := e.store.LockLiveCode(ctx, e.org, v.ID)
		if err == nil && locked.WrongAttempts != otp.MaxWrongAttempts {
			t.Errorf("stored attempts = %d, want %d", locked.WrongAttempts, otp.MaxWrongAttempts)
		}
		return err
	})
	if _, err := e.store.EndLiveCode(t.Context(), e.org, v.ID, otp.EndUsedUp, st0); err != nil {
		t.Fatal(err)
	}
	if _, err := e.store.AddWrongAttempt(t.Context(), e.org, c.ID, st0); !errors.Is(err, otp.ErrNoLiveCode) {
		t.Errorf("AddWrongAttempt on an ended code = %v, want ErrNoLiveCode", err)
	}
	if _, err := e.store.AddWrongAttempt(t.Context(), e.org, uuid.New(), st0); !errors.Is(err, otp.ErrNoLiveCode) {
		t.Errorf("AddWrongAttempt on an unknown code = %v, want ErrNoLiveCode", err)
	}
}

// ---- proofs ---------------------------------------------------------------------------------

func TestStore_BR_CLI_04_ProofIsAcceptedOnceThenReplayed(t *testing.T) {
	e := newStoreEnv(t)
	v := e.newVer("h")
	fp := handleHash("sub|1700000000")
	ok, err := e.store.InsertProof(t.Context(), e.org, fp, v.ID, st0)
	if err != nil || !ok {
		t.Fatalf("first InsertProof = %v, %v, want true", ok, err)
	}
	ok, err = e.store.InsertProof(t.Context(), e.org, fp, v.ID, st0.Add(time.Second))
	if err != nil || ok {
		t.Fatalf("replayed InsertProof = %v, %v, want false, nil", ok, err)
	}
	// Even for another verification: one Firebase sign-in proves once.
	other := e.newVer2("o")
	if ok, err := e.store.InsertProof(t.Context(), e.org, fp, other.ID, st0); err != nil || ok {
		t.Errorf("proof reused on another verification = %v, %v, want false, nil", ok, err)
	}
	if ok, err := e.store.InsertProof(t.Context(), e.org, handleHash("another"), v.ID, st0); err != nil || !ok {
		t.Errorf("a different proof = %v, %v, want true", ok, err)
	}
}

func TestStore_BR_CLI_04_ConcurrentSameProofSucceedsOnce(t *testing.T) {
	e := newStoreEnv(t)
	v := e.newVer("h")
	fp := handleHash("race")
	var wg sync.WaitGroup
	var mu sync.Mutex
	accepted := 0
	for range 6 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ok, err := e.store.InsertProof(context.Background(), e.org, fp, v.ID, st0)
			if err != nil {
				t.Errorf("InsertProof: %v", err)
				return
			}
			if ok {
				mu.Lock()
				accepted++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if accepted != 1 {
		t.Fatalf("accepted = %d, want 1", accepted)
	}
}

// ---- limits ---------------------------------------------------------------------------------

func key(scope otp.LimitScope, b byte) otp.LimitKey {
	return otp.LimitKey{Scope: scope, Subject: bytes.Repeat([]byte{b}, 32)}
}

func TestStore_BR_CLI_04_LockLimitsCreatesRowsAndReturnsFixedScopeOrder(t *testing.T) {
	e := newStoreEnv(t)
	if _, err := e.store.LockLimits(t.Context(), e.org, []otp.LimitKey{key(otp.ScopeSendIP, 1)}); !errors.Is(err, db.ErrNoTx) {
		t.Fatalf("LockLimits outside a tx = %v, want db.ErrNoTx", err)
	}
	keys := []otp.LimitKey{key(otp.ScopeCheckIP, 4), key(otp.ScopeSendIP, 3), key(otp.ScopeSendUser, 2), key(otp.ScopeSendContact, 1)}
	e.mustTx(func(ctx context.Context) error {
		rows, err := e.store.LockLimits(ctx, e.org, keys)
		if err != nil {
			return err
		}
		var scopes []otp.LimitScope
		for _, r := range rows {
			scopes = append(scopes, r.Key.Scope)
			if len(r.Events) != 0 {
				t.Errorf("new row %s has events %v", r.Key.Scope, r.Events)
			}
		}
		if want := []otp.LimitScope{otp.ScopeSendContact, otp.ScopeSendUser, otp.ScopeSendIP, otp.ScopeCheckIP}; !slices.Equal(scopes, want) {
			t.Errorf("row order = %v, want the fixed order %v whatever the input order", scopes, want)
		}
		return e.store.SaveLimit(ctx, e.org, keys[3], []time.Time{st0.Add(-time.Minute), st0}, st0)
	})
	e.mustTx(func(ctx context.Context) error {
		rows, err := e.store.LockLimits(ctx, e.org, []otp.LimitKey{key(otp.ScopeSendContact, 1)})
		if err != nil {
			return err
		}
		if len(rows) != 1 {
			t.Fatalf("rows = %v, want exactly one", rows)
		}
		want := []time.Time{st0.Add(-time.Minute), st0}
		if len(rows[0].Events) != 2 || !sameTime(rows[0].Events[0], want[0]) || !sameTime(rows[0].Events[1], want[1]) || !sameTime(rows[0].UpdatedAt, st0) {
			t.Errorf("saved row = %+v, want events %v updated at %v", rows[0], want, st0)
		}
		return nil
	})
	// Same subject under another scope is another row.
	e.mustTx(func(ctx context.Context) error {
		rows, err := e.store.LockLimits(ctx, e.org, []otp.LimitKey{key(otp.ScopeSendIP, 1)})
		if err == nil && len(rows[0].Events) != 0 {
			t.Errorf("send_ip row with the contact's subject has events %v", rows[0].Events)
		}
		return err
	})
}

func TestStore_BR_CLI_04_LimitsOfAnotherOrgAreSeparateRows(t *testing.T) {
	e := newStoreEnv(t)
	other := e.newOrg()
	k := key(otp.ScopeSendContact, 7)
	e.mustTx(func(ctx context.Context) error {
		if _, err := e.store.LockLimits(ctx, e.org, []otp.LimitKey{k}); err != nil {
			return err
		}
		return e.store.SaveLimit(ctx, e.org, k, []time.Time{st0}, st0)
	})
	e.mustTx(func(ctx context.Context) error {
		rows, err := e.store.LockLimits(ctx, other, []otp.LimitKey{k})
		if err == nil && len(rows[0].Events) != 0 {
			t.Errorf("another org sees events %v", rows[0].Events)
		}
		return err
	})
}

// Concurrent callers locking overlapping keys in opposite input orders must never deadlock.
func TestStore_BR_CLI_04_LockLimitsCannotDeadlockOnOppositeInputOrders(t *testing.T) {
	e := newStoreEnv(t)
	contact, ip := key(otp.ScopeSendContact, 1), key(otp.ScopeSendIP, 2)
	for round := range 25 {
		var wg sync.WaitGroup
		errs := make([]error, 2)
		for i, keys := range [][]otp.LimitKey{{contact, ip}, {ip, contact}} {
			wg.Add(1)
			go func() {
				defer wg.Done()
				errs[i] = e.inTx(func(ctx context.Context) error {
					if _, err := e.store.LockLimits(ctx, e.org, keys); err != nil {
						return err
					}
					time.Sleep(20 * time.Millisecond)
					return nil
				})
			}()
		}
		wg.Wait()
		for _, err := range errs {
			if err != nil {
				t.Fatalf("round %d: %v (lock order must be fixed)", round, err)
			}
		}
	}
}

// ---- daily counts ---------------------------------------------------------------------------

func TestStore_BR_CLI_04_CountsUpsertPerDayMetricAndOrg(t *testing.T) {
	e := newStoreEnv(t)
	other := e.newOrg()
	d1, d2 := istdate.Date{Year: 2026, Month: time.November, Day: 26}, istdate.Date{Year: 2026, Month: time.November, Day: 27}
	ctx := t.Context()
	for range 3 {
		if err := e.store.IncrementCount(ctx, e.org, d1, otp.MetricEmailSent, st0); err != nil {
			t.Fatal(err)
		}
	}
	for _, m := range []otp.Metric{otp.MetricEmailFailed, otp.MetricLimitRefused, otp.MetricProofAccepted, otp.MetricProofRefused} {
		if err := e.store.IncrementCount(ctx, e.org, d1, m, st0); err != nil {
			t.Fatal(err)
		}
	}
	_ = e.store.IncrementCount(ctx, e.org, d1, otp.MetricProofRefused, st0)
	_ = e.store.IncrementCount(ctx, e.org, d2, otp.MetricEmailSent, st0)
	_ = e.store.IncrementCount(ctx, other, d1, otp.MetricEmailSent, st0)

	got, err := e.store.GetCounts(ctx, e.org, d1)
	want := otp.DailyCounts{EmailSent: 3, EmailFailed: 1, LimitRefused: 1, ProofAccepted: 1, ProofRefused: 2}
	if err != nil || got != want {
		t.Fatalf("GetCounts day 1 = %+v, %v, want %+v", got, err, want)
	}
	if got, _ := e.store.GetCounts(ctx, e.org, d2); got != (otp.DailyCounts{EmailSent: 1}) {
		t.Errorf("GetCounts day 2 = %+v", got)
	}
	if got, _ := e.store.GetCounts(ctx, e.org, d1.AddDays(5)); got != (otp.DailyCounts{}) {
		t.Errorf("an empty day = %+v, want zeros", got)
	}
	if got, _ := e.store.GetCounts(ctx, other, d1); got != (otp.DailyCounts{EmailSent: 1}) {
		t.Errorf("other org = %+v, want only its own count", got)
	}
}

func TestStore_BR_CLI_04_ConcurrentIncrementsAreNotLost(t *testing.T) {
	e := newStoreEnv(t)
	day := istdate.Date{Year: 2026, Month: time.November, Day: 26}
	var wg sync.WaitGroup
	for range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := e.store.IncrementCount(context.Background(), e.org, day, otp.MetricEmailSent, st0); err != nil {
				t.Errorf("IncrementCount: %v", err)
			}
		}()
	}
	wg.Wait()
	if got, _ := e.store.GetCounts(t.Context(), e.org, day); got.EmailSent != 12 {
		t.Errorf("EmailSent = %d, want 12", got.EmailSent)
	}
}

// ---- purge ----------------------------------------------------------------------------------

func TestStore_BR_CLI_04_PurgeVerificationsInBatchesCascadingAndExclusiveOfTheCutoff(t *testing.T) {
	e := newStoreEnv(t)
	other := e.newOrg()
	mk := func(org uuid.UUID, n int, expires time.Time) []otp.VerificationRow {
		var out []otp.VerificationRow
		for i := range n {
			e.seq++
			u := uuid.New()
			e.addUser(org, u)
			out = append(out, e.insertVer(otp.NewVerification{OrgID: org, UserID: u, Purpose: otp.PurposeChangeEmail,
				HandleHash: handleHash(fmt.Sprintf("p%d-%d-%d", e.seq, i, expires.Unix())), Email: "n@example.com", Now: st0.Add(-48 * time.Hour), ExpiresAt: expires}))
		}
		return out
	}
	cutoff := st0.Add(-24 * time.Hour)
	old := mk(e.org, 5, cutoff.Add(-time.Second))
	edge := mk(e.org, 1, cutoff) // expires_at == cutoff is kept
	fresh := mk(e.org, 2, st0.Add(time.Hour))
	foreign := mk(other, 2, cutoff.Add(-time.Hour))
	for _, v := range old[:2] {
		e.newCode(v, "k")
		if _, err := e.store.InsertProof(t.Context(), e.org, handleHash(v.ID.String()), v.ID, st0); err != nil {
			t.Fatal(err)
		}
	}
	e.newCode(fresh[0], "keep")

	var batches []int
	for {
		n, err := e.store.PurgeVerifications(t.Context(), e.org, cutoff, 2)
		if err != nil {
			t.Fatalf("PurgeVerifications: %v", err)
		}
		if n == 0 {
			break
		}
		batches = append(batches, n)
		if len(batches) > 5 {
			t.Fatal("purge does not terminate")
		}
	}
	if !slices.Equal(batches, []int{2, 2, 1}) {
		t.Errorf("batches = %v, want [2 2 1] (bounded by the limit)", batches)
	}
	left := func(rows []otp.VerificationRow) int {
		n := 0
		for _, r := range rows {
			if _, err := e.store.GetVerification(t.Context(), r.OrgID, r.ID); err == nil {
				n++
			}
		}
		return n
	}
	if left(old) != 0 || left(edge) != 1 || left(fresh) != 2 || left(foreign) != 2 {
		t.Errorf("survivors old/edge/fresh/foreign = %d/%d/%d/%d, want 0/1/2/2", left(old), left(edge), left(fresh), left(foreign))
	}
	var codes, proofs int
	_ = e.pool.QueryRow(t.Context(), `SELECT (SELECT count(*) FROM otp_email_codes), (SELECT count(*) FROM otp_used_proofs)`).Scan(&codes, &proofs)
	if codes != 1 || proofs != 0 {
		t.Errorf("codes/proofs left = %d/%d, want 1/0 (cascade removed the purged ones only)", codes, proofs)
	}
}

func TestStore_BR_CLI_04_PurgeProofsLimitsAndCounts(t *testing.T) {
	e := newStoreEnv(t)
	other := e.newOrg()
	v := e.newVer("h")
	cutoff := st0
	ctx := t.Context()

	for i, at := range []time.Time{cutoff.Add(-time.Hour), cutoff.Add(-time.Second), cutoff, cutoff.Add(time.Hour)} {
		if ok, err := e.store.InsertProof(ctx, e.org, handleHash(fmt.Sprint("proof", i)), v.ID, at); err != nil || !ok {
			t.Fatalf("InsertProof: %v %v", ok, err)
		}
	}
	if n, err := e.store.PurgeProofs(ctx, e.org, cutoff, 1); err != nil || n != 1 {
		t.Fatalf("PurgeProofs batch = %d, %v, want 1 (limit)", n, err)
	}
	if n, err := e.store.PurgeProofs(ctx, e.org, cutoff, 100); err != nil || n != 1 {
		t.Fatalf("PurgeProofs rest = %d, %v, want 1 (used_at < cutoff only)", n, err)
	}

	for i, at := range []time.Time{cutoff.Add(-49 * time.Hour), cutoff.Add(-time.Second), cutoff} {
		k := key(otp.ScopeSendIP, byte(10+i))
		e.mustTx(func(ctx context.Context) error {
			if _, err := e.store.LockLimits(ctx, e.org, []otp.LimitKey{k}); err != nil {
				return err
			}
			return e.store.SaveLimit(ctx, e.org, k, []time.Time{at}, at)
		})
	}
	foreign := key(otp.ScopeSendIP, 99)
	e.mustTx(func(ctx context.Context) error {
		if _, err := e.store.LockLimits(ctx, other, []otp.LimitKey{foreign}); err != nil {
			return err
		}
		return e.store.SaveLimit(ctx, other, foreign, []time.Time{cutoff.Add(-72 * time.Hour)}, cutoff.Add(-72*time.Hour))
	})
	if n, err := e.store.PurgeLimits(ctx, e.org, cutoff, 100); err != nil || n != 2 {
		t.Fatalf("PurgeLimits = %d, %v, want 2 (updated_at < cutoff, own org)", n, err)
	}
	var foreignRows int
	_ = e.pool.QueryRow(ctx, `SELECT count(*) FROM otp_limits WHERE org_id = $1`, other).Scan(&foreignRows)
	if foreignRows != 1 {
		t.Errorf("another org's limit rows = %d, want 1 untouched", foreignRows)
	}

	d := func(day int) istdate.Date { return istdate.Date{Year: 2026, Month: time.November, Day: day} }
	for _, day := range []int{20, 24, 25, 26} {
		if err := e.store.IncrementCount(ctx, e.org, d(day), otp.MetricEmailSent, st0); err != nil {
			t.Fatal(err)
		}
	}
	_ = e.store.IncrementCount(ctx, other, d(1), otp.MetricEmailSent, st0)
	if n, err := e.store.PurgeCounts(ctx, e.org, d(25), 2); err != nil || n != 2 {
		t.Fatalf("PurgeCounts = %d, %v, want 2 (days 20 and 24; day < cutoff)", n, err)
	}
	if got, _ := e.store.GetCounts(ctx, e.org, d(25)); got.EmailSent != 1 {
		t.Errorf("the cutoff day itself must stay: %+v", got)
	}
	if got, _ := e.store.GetCounts(ctx, other, d(1)); got.EmailSent != 1 {
		t.Errorf("another org's count was purged: %+v", got)
	}
}

// ---- org isolation --------------------------------------------------------------------------

func TestStore_BR_CLI_04_AnotherOrgNeverSeesOrChangesRows(t *testing.T) {
	e := newStoreEnv(t)
	other := e.newOrg()
	v := e.newVer("h")
	c := e.newCode(v, "k")
	ctx := t.Context()

	if _, err := e.store.GetVerification(ctx, other, v.ID); !errors.Is(err, otp.ErrNotFound) {
		t.Errorf("GetVerification other org = %v, want ErrNotFound", err)
	}
	if _, err := e.store.LockLiveCode(ctx, other, v.ID); !errors.Is(err, db.ErrNoTx) {
		// Outside a tx the guard fires first; inside one the org filter must hide the row.
		t.Errorf("LockLiveCode outside a tx = %v, want db.ErrNoTx", err)
	}
	err := e.inTx(func(ctx context.Context) error {
		if _, err := e.store.LockLiveCode(ctx, other, v.ID); !errors.Is(err, otp.ErrNoLiveCode) {
			t.Errorf("LockLiveCode other org = %v, want ErrNoLiveCode", err)
		}
		if _, err := e.store.LockOpenVerification(ctx, other, e.user, otp.PurposeSignup); !errors.Is(err, otp.ErrNotFound) {
			t.Errorf("LockOpenVerification other org = %v, want ErrNotFound", err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.store.MarkContactDone(ctx, other, v.ID, otp.ContactEmail, st0); !errors.Is(err, otp.ErrNotFound) {
		t.Errorf("MarkContactDone other org = %v, want ErrNotFound", err)
	}
	if err := e.store.CancelVerification(ctx, other, v.ID, otp.CancelCancelled, st0); !errors.Is(err, otp.ErrNotFound) {
		t.Errorf("CancelVerification other org = %v, want ErrNotFound", err)
	}
	if _, err := e.store.EndLiveCode(ctx, other, v.ID, otp.EndUsed, st0); !errors.Is(err, otp.ErrNoLiveCode) {
		t.Errorf("EndLiveCode other org = %v, want ErrNoLiveCode", err)
	}
	if _, err := e.store.AddWrongAttempt(ctx, other, c.ID, st0); !errors.Is(err, otp.ErrNoLiveCode) {
		t.Errorf("AddWrongAttempt other org = %v, want ErrNoLiveCode", err)
	}
	if n, _ := e.store.PurgeVerifications(ctx, other, st0.Add(100*24*time.Hour), 100); n != 0 {
		t.Errorf("another org purged %d rows of ours", n)
	}
	// Our row is exactly as it was.
	got, _ := e.store.GetVerification(ctx, e.org, v.ID)
	if got.EmailDoneAt != nil || got.CancelledAt != nil {
		t.Errorf("verification changed by another org: %+v", got)
	}
}
