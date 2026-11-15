package auth_test

// S20 - verification of US-11 / FR-090: every event of the audit table writes exactly the specified
// audit entries (action, actor kind, actor, affected user, session when there is one, time) in the
// same unit of work. The table drives every event through the real Service on a real database and
// compares the audit rows the call added with the expected ones. A guard compares the actions the
// table triggered with the constants of the catalogue in audit.go, so a new action cannot ship
// without a row here. Secrets and unmatched identifiers are scanned at the end (US-11 s2, SC-006).

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/NandanMaheta/swastik/apps/api/internal/auth"
	"github.com/NandanMaheta/swastik/apps/api/internal/auth/authtest"
	"github.com/NandanMaheta/swastik/apps/api/internal/platform/audit"
)

// wantAudit is one expected audit row. Entity defaults to "user"; EntityID uuid.Nil means NULL;
// Session says the "after" payload must name a device session.
type wantAudit struct {
	Action   string
	Actor    string // "client" | "admin" | "system"
	ActorID  uuid.UUID
	Entity   string
	EntityID uuid.UUID
	Session  bool
	AnyID    bool // the affected user is created by the step: any non-NULL entity id
}

func vaSystem(action string, entity uuid.UUID) wantAudit {
	return wantAudit{Action: action, Actor: "system", EntityID: entity}
}

func vaBy(action string, actor authtest.User, entity uuid.UUID) wantAudit {
	return wantAudit{Action: action, Actor: actor.Role, ActorID: actor.ID, EntityID: entity}
}

func (w wantAudit) withSession() wantAudit { w.Session = true; return w }

// vaRunner runs steps and records which actions the table has triggered.
type vaRunner struct {
	t         *testing.T
	e         *authtest.Env
	triggered map[string]bool
}

// step runs fn and requires that exactly the wanted audit rows were added, each stamped with the
// injected clock, then advances the clock past every replay and lockout window.
func (r *vaRunner) step(name string, want []wantAudit, fn func()) {
	r.t.Helper()
	before := len(r.e.AuditRows(r.t))
	stamp := r.e.Clock.Now().UTC().Format("2006-01-02 15:04:05")
	fn()
	rows := r.e.AuditRows(r.t)
	if len(rows) < before {
		r.t.Fatalf("%s: audit rows shrank from %d to %d (the log is append-only)", name, before, len(rows))
	}
	got := rows[before:]
	if len(got) != len(want) {
		r.t.Errorf("%s: wrote %d audit rows %v, want %d %v", name, len(got), vaActions(got), len(want), vaWantActions(want))
	} else {
		r.match(name, got, want, stamp)
	}
	for _, g := range got {
		r.triggered[g.Action] = true
	}
	r.e.Clock.Advance(time.Minute)
}

// match pairs each wanted row with one written row of the same action and checks its fields.
func (r *vaRunner) match(name string, got []authtest.AuditRow, want []wantAudit, stamp string) {
	r.t.Helper()
	used := make([]bool, len(got))
	for _, w := range want {
		idx := -1
		for i, g := range got {
			if !used[i] && g.Action == w.Action {
				idx = i
				break
			}
		}
		if idx < 0 {
			r.t.Errorf("%s: no audit row %q among %v", name, w.Action, vaActions(got))
			continue
		}
		used[idx] = true
		g := got[idx]
		entity := w.Entity
		if entity == "" {
			entity = auth.EntityUser
		}
		wantID := w.EntityID
		if w.AnyID && g.EntityID != uuid.Nil {
			wantID = g.EntityID
		}
		if g.ActorKind != w.Actor || g.ActorID != w.ActorID || g.Entity != entity || g.EntityID != wantID {
			r.t.Errorf("%s: %s row = actor %s/%v entity %s/%v, want actor %s/%v entity %s/%v",
				name, w.Action, g.ActorKind, g.ActorID, g.Entity, g.EntityID, w.Actor, w.ActorID, entity, w.EntityID)
		}
		if !strings.HasPrefix(g.CreatedAt, stamp) {
			r.t.Errorf("%s: %s created_at = %q, want the injected clock %q", name, w.Action, g.CreatedAt, stamp)
		}
		if w.Session {
			after := mfAfterOf(r.t, g)
			if id, _ := after["session_id"].(string); id == "" {
				if ids, _ := after["session_ids"].([]any); len(ids) == 0 {
					r.t.Errorf("%s: %s row names no device session: %s", name, w.Action, g.After)
				}
			}
		}
	}
}

func mfAfterOf(t *testing.T, r authtest.AuditRow) map[string]any {
	t.Helper()
	if r.After == "" {
		return map[string]any{}
	}
	return mfAfter(t, r)
}

func vaActions(rows []authtest.AuditRow) []string {
	out := make([]string, len(rows))
	for i, r := range rows {
		out[i] = r.Action
	}
	return out
}

func vaWantActions(ws []wantAudit) []string {
	out := make([]string, len(ws))
	for i, w := range ws {
		out[i] = w.Action
	}
	return out
}

// vaCatalogue parses the Action* constants of audit.go, so the guard follows the source.
func vaCatalogue(t *testing.T) []string {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), "audit.go", nil, 0)
	if err != nil {
		t.Fatalf("parse audit.go: %v", err)
	}
	var out []string
	for _, d := range f.Decls {
		gd, ok := d.(*ast.GenDecl)
		if !ok || gd.Tok != token.CONST {
			continue
		}
		for _, spec := range gd.Specs {
			vs := spec.(*ast.ValueSpec)
			for i, n := range vs.Names {
				if !strings.HasPrefix(n.Name, "Action") || i >= len(vs.Values) {
					continue
				}
				lit, ok := vs.Values[i].(*ast.BasicLit)
				if !ok {
					continue
				}
				v, err := strconv.Unquote(lit.Value)
				if err != nil {
					t.Fatalf("audit.go %s: %v", n.Name, err)
				}
				out = append(out, v)
			}
		}
	}
	sort.Strings(out)
	if len(out) < 20 {
		t.Fatalf("parsed only %d audit actions from audit.go", len(out))
	}
	return out
}

func vaWrongRecovery() string { return "0000-0000-0000-0000" }

func TestAuditTrail_US11_EveryEventWritesItsSpecifiedEntries(t *testing.T) {
	e := authtest.New(t)
	s := e.Service(t)
	r := &vaRunner{t: t, e: e, triggered: map[string]bool{}}
	ctx := t.Context()

	client := e.NewUser(t, authtest.UserSpec{})
	adm := mfEnrolled(t, e)
	_, adminP := mfSession(t, e, adm.User)
	cl := func(action string) wantAudit { return vaBy(action, client, client.ID) }
	byAdmin := func(action string, entity uuid.UUID) wantAudit { return vaBy(action, adm.User, entity) }

	// ---- sign-in success, refresh, reuse and device mismatch (client) ----
	dev1 := uuid.New()
	var tok auth.SessionTokens
	r.step("client sign-in", []wantAudit{cl(auth.ActionSignInSucceeded).withSession()}, func() { tok = svSignIn(t, s, client, dev1) })
	e.Secrets.Add("access token", tok.AccessToken)
	e.Secrets.Add("refresh token", tok.RefreshToken)

	var tok2 auth.SessionTokens
	r.step("refresh", []wantAudit{cl(auth.ActionSessionRefreshed).withSession()}, func() {
		var err error
		if tok2, err = s.Refresh(ctx, svRefreshIn(dev1, tok.RefreshToken)); err != nil {
			t.Fatalf("Refresh: %v", err)
		}
	})
	e.Secrets.Add("refresh token", tok2.RefreshToken)
	r.step("refresh reuse", []wantAudit{vaSystem(auth.ActionRefreshReuseDetected, client.ID).withSession()}, func() {
		if _, err := s.Refresh(ctx, svRefreshIn(dev1, tok.RefreshToken)); !errors.Is(err, auth.ErrRefreshRejected) {
			t.Fatalf("reused refresh token: err = %v, want ErrRefreshRejected", err)
		}
	})
	devB := uuid.New()
	tokB := svSignIn(t, s, client, devB)
	e.Secrets.Add("refresh token", tokB.RefreshToken)
	r.step("device mismatch", []wantAudit{vaSystem(auth.ActionDeviceMismatch, client.ID).withSession()}, func() {
		if _, err := s.Refresh(ctx, svRefreshIn(uuid.New(), tokB.RefreshToken)); !errors.Is(err, auth.ErrRefreshRejected) {
			t.Fatalf("mismatched device: err = %v, want ErrRefreshRejected", err)
		}
	})

	// ---- sign-out, devices, sign-out everywhere, admin ends all ----
	sess := func() auth.SessionTokens { return svSignIn(t, s, client, uuid.New()) }
	a1 := sess()
	r.step("sign-out", []wantAudit{cl(auth.ActionSessionSignedOut).withSession()}, func() {
		if err := s.SignOut(ctx, svPrincipal(e, client, a1.SessionID)); err != nil {
			t.Fatalf("SignOut: %v", err)
		}
	})
	own, victim := sess(), sess()
	r.step("device revoked by the user", []wantAudit{cl(auth.ActionSessionRevoked).withSession()}, func() {
		if err := s.RevokeDevice(ctx, svPrincipal(e, client, own.SessionID), victim.SessionID); err != nil {
			t.Fatalf("RevokeDevice: %v", err)
		}
	})
	victim2 := sess()
	r.step("device revoked by the admin", []wantAudit{byAdmin(auth.ActionSessionRevoked, client.ID).withSession()}, func() {
		if err := s.AdminRevokeDevice(ctx, adminP, client.ID, victim2.SessionID); err != nil {
			t.Fatalf("AdminRevokeDevice: %v", err)
		}
	})
	r.step("signed out everywhere", []wantAudit{cl(auth.ActionSessionSignedOutEverywhere).withSession()}, func() {
		if _, err := s.SignOutEverywhere(ctx, svPrincipal(e, client, own.SessionID)); err != nil {
			t.Fatalf("SignOutEverywhere: %v", err)
		}
	})
	sess()
	r.step("all sessions ended by the admin", []wantAudit{byAdmin(auth.ActionSessionEndedAllByAdmin, client.ID).withSession()}, func() {
		if _, err := s.AdminEndAllSessions(ctx, adminP, client.ID); err != nil {
			t.Fatalf("AdminEndAllSessions: %v", err)
		}
	})
	sess()
	r.step("sessions ended by a feature", []wantAudit{vaSystem(auth.ActionSessionEndedByFeature, client.ID).withSession()}, func() {
		if _, err := s.EndAllSessions(ctx, client.ID, "verification", authtest.System()); err != nil {
			t.Fatalf("EndAllSessions: %v", err)
		}
	})

	// ---- password changed and reset ----
	pw := sess()
	const changed, reset = "monsoon-lantern-77-river", "granite-meadow-58-kestrel"
	e.Secrets.Add("new password", changed)
	e.Secrets.Add("reset password", reset)
	r.step("password changed", []wantAudit{cl(auth.ActionPasswordChanged)}, func() {
		if err := s.ChangePassword(ctx, svPrincipal(e, client, pw.SessionID), client.Password, changed); err != nil {
			t.Fatalf("ChangePassword: %v", err)
		}
	})
	client.Password = changed
	r.step("password reset", []wantAudit{vaSystem(auth.ActionPasswordReset, client.ID)}, func() {
		if err := s.ResetPassword(ctx, client.ID, reset, authtest.System()); err != nil {
			t.Fatalf("ResetPassword: %v", err)
		}
	})
	client.Password = reset

	// ---- sign-in failures (every reason) and lockout ----
	ghost := "ghost.user.7731@nowhere.test"
	e.Secrets.Add("unmatched identifier as typed", ghost)
	e.Secrets.Add("unmatched identifier as typed (normalised)", strings.ToLower(ghost))
	r.step("failure: unknown identifier", []wantAudit{vaSystem(auth.ActionSignInFailed, uuid.Nil)}, func() {
		in := svInput(client, uuid.New())
		in.Identifier = ghost
		if _, err := s.SignIn(ctx, in); !errors.Is(err, auth.ErrInvalidCredentials) {
			t.Fatalf("unknown identifier: err = %v", err)
		}
	})
	r.step("failure: wrong password", []wantAudit{vaSystem(auth.ActionSignInFailed, client.ID)}, func() { svWrong(t, s, client) })
	e.Clock.Advance(16 * time.Minute)
	for i := 1; i <= 4; i++ {
		svWrong(t, s, client)
	}
	r.step("lockout started (5th failure)", []wantAudit{vaSystem(auth.ActionSignInFailed, client.ID), vaSystem(auth.ActionLockoutStarted, client.ID)}, func() { svWrong(t, s, client) })
	r.step("failure: locked", []wantAudit{vaSystem(auth.ActionSignInFailed, client.ID)}, func() {
		if _, err := s.SignIn(ctx, svInput(client, uuid.New())); !errors.Is(err, auth.ErrInvalidCredentials) {
			t.Fatalf("locked sign-in: err = %v", err)
		}
	})
	e.Clock.Advance(16 * time.Minute)
	pending := e.UserWithStatus(t, auth.StatusPendingApproval)
	r.step("failure: not active", []wantAudit{vaSystem(auth.ActionSignInFailed, pending.ID)}, func() {
		if _, err := s.SignIn(ctx, svInput(pending, uuid.New())); !errors.Is(err, auth.ErrInvalidCredentials) {
			t.Fatalf("pending_approval sign-in: err = %v", err)
		}
	})

	// ---- admin: challenge, second-factor failures, recovery code, sign-in success ----
	var chal string
	r.step("admin password step", []wantAudit{vaSystem(auth.ActionMFAChallengeIssued, adm.ID)}, func() { chal = mfChallenge(t, e, s, adm.User) })
	r.step("failure: wrong code", []wantAudit{vaSystem(auth.ActionSignInFailed, adm.ID)}, func() {
		if _, err := s.VerifyMFA(ctx, mfVerifyIn(chal, mfWrong(t, e, adm.Secret))); !errors.Is(err, auth.ErrInvalidCredentials) {
			t.Fatalf("wrong code: err = %v", err)
		}
	})
	e.Clock.Advance(16 * time.Minute)
	chal = mfChallenge(t, e, s, adm.User)
	r.step("failure: wrong recovery code", []wantAudit{vaSystem(auth.ActionSignInFailed, adm.ID)}, func() {
		in := mfVerifyIn(chal, "")
		in.RecoveryCode = vaWrongRecovery()
		if _, err := s.VerifyMFA(ctx, in); !errors.Is(err, auth.ErrInvalidCredentials) {
			t.Fatalf("wrong recovery code: err = %v", err)
		}
	})
	e.Clock.Advance(16 * time.Minute)
	chal = mfChallenge(t, e, s, adm.User)
	r.step("admin sign-in after the second factor", []wantAudit{byAdmin(auth.ActionSignInSucceeded, adm.ID).withSession()}, func() {
		res, err := s.VerifyMFA(ctx, mfVerifyIn(chal, mfCode(t, e, adm.Secret, 0)))
		if err != nil {
			t.Fatalf("VerifyMFA: %v", err)
		}
		e.Secrets.Add("access token", res.AccessToken)
		e.Secrets.Add("refresh token", res.RefreshToken)
	})
	chal = mfChallenge(t, e, s, adm.User)
	r.step("recovery code used", []wantAudit{byAdmin(auth.ActionMFARecoveryCodeUsed, adm.ID), byAdmin(auth.ActionSignInSucceeded, adm.ID).withSession()}, func() {
		in := mfVerifyIn(chal, "")
		in.RecoveryCode = adm.Codes[0]
		res, err := s.VerifyMFA(ctx, in)
		if err != nil {
			t.Fatalf("VerifyMFA with a recovery code: %v", err)
		}
		e.Secrets.Add("access token", res.AccessToken)
		e.Secrets.Add("refresh token", res.RefreshToken)
	})

	// ---- recovery codes regenerated, authenticator replaced ----
	r.step("recovery codes regenerated", []wantAudit{byAdmin(auth.ActionMFARecoveryRegenerated, adm.ID)}, func() {
		codes, err := s.RegenerateRecoveryCodes(ctx, adminP, authtest.Password, mfCode(t, e, adm.Secret, 0))
		if err != nil {
			t.Fatalf("RegenerateRecoveryCodes: %v", err)
		}
		for _, c := range codes {
			e.Secrets.Add("recovery code", c)
		}
	})
	e.Clock.Advance(time.Minute)
	start, err := s.StartAuthenticatorReplace(ctx, adminP, auth.Reauth{Password: authtest.Password, Code: mfCode(t, e, adm.Secret, 0)})
	if err != nil {
		t.Fatalf("StartAuthenticatorReplace: %v", err)
	}
	e.Secrets.AddTOTPSecret(start.Secret)
	e.Clock.Advance(90 * time.Second)
	r.step("authenticator replaced", []wantAudit{byAdmin(auth.ActionMFAReplaced, adm.ID)}, func() {
		if err := s.ConfirmAuthenticatorReplace(ctx, adminP, authtest.TOTPCode(t, start.Secret, e.Clock.Now())); err != nil {
			t.Fatalf("ConfirmAuthenticatorReplace: %v", err)
		}
	})

	// ---- TOTP enrolled (first sign-in of a new admin) ----
	fresh := e.NewAdmin(t)
	enrolTok := mfChallenge(t, e, s, fresh)
	enrolment, err := s.StartEnrolment(ctx, enrolTok)
	if err != nil {
		t.Fatalf("StartEnrolment: %v", err)
	}
	e.Secrets.AddTOTPSecret(enrolment.Secret)
	r.step("TOTP enrolled", []wantAudit{vaBy(auth.ActionMFAEnrolled, fresh, fresh.ID).withSession(), vaBy(auth.ActionSignInSucceeded, fresh, fresh.ID).withSession()}, func() {
		res, err := s.ConfirmEnrolment(ctx, auth.EnrolmentConfirmInput{ChallengeToken: enrolTok, Code: authtest.TOTPCode(t, enrolment.Secret, e.Clock.Now()), IP: testIP})
		if err != nil {
			t.Fatalf("ConfirmEnrolment: %v", err)
		}
		for _, c := range res.RecoveryCodes {
			e.Secrets.Add("recovery code", c)
		}
	})

	// ---- account lifecycle (called by 004/005/007; the caller names the actor) ----
	var id uuid.UUID
	const newClientPassword = "juniper-harbor-31-lantern"
	e.Secrets.Add("new client password", newClientPassword)
	r.step("user created", []wantAudit{{Action: auth.ActionUserCreated, Actor: "system", AnyID: true}}, func() {
		var err error
		id, err = s.CreateClient(ctx, auth.NewClient{OrgID: e.Org, Name: "Meera Shah", Email: "meera.shah@example.com", Mobile: "+919876500011", Password: newClientPassword}, authtest.System())
		if err != nil {
			t.Fatalf("CreateClient: %v", err)
		}
	})
	r.step("email marked verified", []wantAudit{vaSystem(auth.ActionUserEmailVerified, id)}, func() {
		if _, err := s.MarkEmailVerified(ctx, id, authtest.System()); err != nil {
			t.Fatalf("MarkEmailVerified: %v", err)
		}
	})
	r.step("mobile marked verified", []wantAudit{vaSystem(auth.ActionUserMobileVerified, id)}, func() {
		if _, err := s.MarkMobileVerified(ctx, id, authtest.System()); err != nil {
			t.Fatalf("MarkMobileVerified: %v", err)
		}
	})
	r.step("approved", []wantAudit{byAdmin(auth.ActionUserStatusChanged, id)}, func() {
		if err := s.Approve(ctx, id, authtest.Admin(adm.ID)); err != nil {
			t.Fatalf("Approve: %v", err)
		}
	})
	r.step("disabled", []wantAudit{byAdmin(auth.ActionUserStatusChanged, id)}, func() {
		if err := s.Disable(ctx, id, authtest.Admin(adm.ID)); err != nil {
			t.Fatalf("Disable: %v", err)
		}
	})
	r.step("re-enabled", []wantAudit{byAdmin(auth.ActionUserStatusChanged, id)}, func() {
		if err := s.Enable(ctx, id, authtest.Admin(adm.ID)); err != nil {
			t.Fatalf("Enable: %v", err)
		}
	})
	r.step("email replaced", []wantAudit{byAdmin(auth.ActionUserContactReplaced, id)}, func() {
		if err := s.ReplaceEmail(ctx, id, "meera.s@example.com", authtest.Admin(adm.ID)); err != nil {
			t.Fatalf("ReplaceEmail: %v", err)
		}
	})
	r.step("mobile replaced", []wantAudit{byAdmin(auth.ActionUserContactReplaced, id)}, func() {
		if err := s.ReplaceMobile(ctx, id, "+919876500022", authtest.Admin(adm.ID)); err != nil {
			t.Fatalf("ReplaceMobile: %v", err)
		}
	})

	// ---- housekeeping and bootstrap ----
	hkThrottle(t, e, e.Org, "stale", e.Clock.Now().Add(-time.Hour), nil, e.Clock.Now().Add(-time.Hour))
	r.step("housekeeping purged", []wantAudit{{Action: auth.ActionHousekeepingPurged, Actor: "system", Entity: auth.EntityAuth}}, func() {
		if c := hkRun(t, e, s, e.Org); c.Throttles == 0 {
			t.Fatalf("housekeeping purged nothing: %+v", c)
		}
	})
	// Bootstrap runs on an installation with no organisation, so it gets its own world.
	boot := bsEmptyEnv(t)
	rb := &vaRunner{t: t, e: boot, triggered: r.triggered}
	rb.step("admin bootstrapped", []wantAudit{{Action: auth.ActionAdminBootstrapped, Actor: "system", AnyID: true}}, func() {
		if _, err := bsBootstrapper(t, boot).CreateAdmin(ctx, bsInput("owner@example.com")); err != nil {
			t.Fatalf("CreateAdmin: %v", err)
		}
	})
	boot.Secrets.ScanAuditLog(ctx, t, boot.Pool)

	// ---- the catalogue is covered, nothing else was written ----
	var want []string
	want = append(want, vaCatalogue(t)...)
	got := make([]string, 0, len(r.triggered))
	for a := range r.triggered {
		got = append(got, a)
	}
	sort.Strings(got)
	if !slices.Equal(want, got) {
		t.Errorf("audit actions of the catalogue not triggered by this table: %v; triggered but not in the catalogue: %v",
			vaDiff(want, got), vaDiff(got, want))
	}

	// ---- US-11 s2: no secret and no unmatched identifier in any entry ----
	e.Secrets.ScanAuditLog(ctx, t, e.Pool)
	for _, row := range e.AuditRows(t) {
		if row.Action == auth.ActionSignInFailed && row.EntityID == uuid.Nil {
			after := mfAfterOf(t, row)
			if after["identifier_kind"] == nil || after["subject_ref"] == nil || len(after) != 4 {
				t.Errorf("unknown-identifier failure payload = %s, want kind, reason, subject_ref and ip only", row.After)
			}
		}
		if row.ActorKind != audit.KindSystem && row.ActorID == uuid.Nil {
			t.Errorf("%s: a %s actor has no id", row.Action, row.ActorKind)
		}
	}
}

func vaDiff(a, b []string) []string {
	var out []string
	for _, x := range a {
		if !slices.Contains(b, x) {
			out = append(out, x)
		}
	}
	return out
}

// Audit entries are never changed or deleted (US-11 s3, constitution II): the platform guarantee
// still holds for the rows this feature writes.
func TestAuditTrail_US11_EntriesCannotBeChangedOrDeleted(t *testing.T) {
	e := authtest.New(t)
	s := e.Service(t)
	u := e.NewUser(t, authtest.UserSpec{})
	svSignIn(t, s, u, uuid.New())
	if n := len(e.AuditRows(t)); n != 1 {
		t.Fatalf("audit rows = %d, want 1", n)
	}
	for name, sql := range map[string]string{
		"update": `UPDATE audit_log SET action = 'auth.tampered'`,
		"delete": `DELETE FROM audit_log`,
	} {
		if _, err := e.Pool.Exec(context.Background(), sql); err == nil {
			t.Errorf("%s of an audit row succeeded, want it refused", name)
		}
	}
	if rows := e.AuditRows(t); len(rows) != 1 || rows[0].Action != auth.ActionSignInSucceeded {
		t.Errorf("audit rows after tampering = %v, want the original one", vaActions(rows))
	}
}
