package auth_test

// S17 - HTTP handlers of admin control over a user's sessions (US-8, US-2 s3, FR-049):
// auth-admin-user-devices-list, auth-admin-user-device-revoke, auth-admin-user-sessions-end-all.

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/NandanMaheta/swastik/apps/api/internal/auth"
)

func hUserPath(user uuid.UUID, rest string) string { return "/v1/admin/users/" + user.String() + rest }

func TestHandler_AdminListsAUsersDevices(t *testing.T) {
	h := newHandlerEnv(t)
	adm := hAdmin(t, h)
	u := h.UserWithStatus(t, auth.StatusActive)
	a := hMobileSignIn(t, h, u, uuid.New())
	h.Clock.Advance(time.Minute)
	b := hMobileSignIn(t, h, u, uuid.New())

	rec := h.get(hUserPath(u.ID, "/devices"), bearer(adm.Token))
	hOK(t, rec, http.StatusOK)
	items, _ := hMap(t, rec)["items"].([]any)
	if len(items) != 2 {
		t.Fatalf("items = %d, want both of the client's devices: %s", len(items), hBody(rec))
	}
	ids := map[string]bool{}
	for _, it := range items {
		m := it.(map[string]any)
		ids[m["session_id"].(string)] = true
		if m["is_current"] != false {
			t.Errorf("is_current = %v in an admin listing of another user, want false", m["is_current"])
		}
	}
	if !ids[a.SessionID.String()] || !ids[b.SessionID.String()] {
		t.Errorf("devices = %v", ids)
	}
}

func TestHandler_AdminOperationsRefuseClientsAndUnknownUsers(t *testing.T) {
	h := newHandlerEnv(t)
	adm := hAdmin(t, h)
	u := h.UserWithStatus(t, auth.StatusActive)
	victim := h.UserWithStatus(t, auth.StatusActive)
	clientSess := hMobileSignIn(t, h, u, uuid.New())
	victimSess := hMobileSignIn(t, h, victim, uuid.New())

	// A client is forbidden, and nothing changes (US-2 s3).
	for _, call := range []func() *httptest.ResponseRecorder{
		func() *httptest.ResponseRecorder {
			return h.get(hUserPath(victim.ID, "/devices"), bearer(clientSess.AccessToken))
		},
		func() *httptest.ResponseRecorder {
			return h.del(hUserPath(victim.ID, "/devices/"+victimSess.SessionID.String()), bearer(clientSess.AccessToken))
		},
		func() *httptest.ResponseRecorder {
			return h.post(hUserPath(victim.ID, "/sessions/end-all"), nil, bearer(clientSess.AccessToken))
		},
	} {
		hProblem(t, call(), http.StatusForbidden, "auth.forbidden")
	}
	if svSession(t, h.Env, victimSess.SessionID).EndedAt != nil {
		t.Fatal("a client ended another user's session")
	}

	// Unknown users, and users of another organisation, are not found.
	otherOrg := uuid.New()
	h.Exec(t, `INSERT INTO orgs (id, name) VALUES ($1, 'Other')`, otherOrg)
	foreign := uuid.New()
	h.Exec(t, `INSERT INTO users (id, org_id, role, status, name, email, mobile, email_verified_at, mobile_verified_at, password_hash, password_changed_at)
		VALUES ($1,$2,'client','active','Foreign','foreign@example.com','+919000000001',now(),now(),'$argon2id$v=19$m=8,t=1,p=1$c2FsdHNhbHQ$YWJj',now())`, foreign, otherOrg)
	for _, id := range []uuid.UUID{uuid.New(), foreign} {
		hProblem(t, h.get(hUserPath(id, "/devices"), bearer(adm.Token)), http.StatusNotFound, "auth.user_not_found")
		hProblem(t, h.del(hUserPath(id, "/devices/"+uuid.NewString()), bearer(adm.Token)), http.StatusNotFound, "auth.user_not_found")
		hProblem(t, h.post(hUserPath(id, "/sessions/end-all"), nil, bearer(adm.Token)), http.StatusNotFound, "auth.user_not_found")
	}
	hProblem(t, h.get("/v1/admin/users/not-a-uuid/devices", bearer(adm.Token)), http.StatusUnprocessableEntity, "validation_failed")
}

func TestHandler_AdminRevokesOneDevice(t *testing.T) {
	h := newHandlerEnv(t)
	adm := hAdmin(t, h)
	u := h.UserWithStatus(t, auth.StatusActive)
	other := h.UserWithStatus(t, auth.StatusActive)
	a := hMobileSignIn(t, h, u, uuid.New())
	b := hMobileSignIn(t, h, u, uuid.New())
	theirs := hMobileSignIn(t, h, other, uuid.New())

	hOK(t, h.del(hUserPath(u.ID, "/devices/"+a.SessionID.String()), bearer(adm.Token)), http.StatusNoContent)
	if ss := svSession(t, h.Env, a.SessionID); ss.EndedAt == nil || ss.EndReason != "revoked_by_admin" {
		t.Errorf("session = ended %v reason %q, want revoked_by_admin", ss.EndedAt, ss.EndReason)
	}
	row := mfOnly(t, h.Env, auth.ActionSessionRevoked)
	if after := mfAfter(t, row); row.ActorKind != "admin" || row.ActorID != adm.ID || row.EntityID != u.ID || after["by"] != "admin" {
		t.Errorf("audit = %+v %v", row, after)
	}
	h.Clock.Advance(time.Second)
	hProblem(t, h.get("/v1/auth/devices", bearer(a.AccessToken)), http.StatusUnauthorized, "auth.unauthenticated")
	hOK(t, h.get("/v1/auth/devices", bearer(b.AccessToken)), http.StatusOK)

	// Another user's session, an ended one and a random one are all "device not found".
	for _, id := range []uuid.UUID{theirs.SessionID, a.SessionID, uuid.New()} {
		hProblem(t, h.del(hUserPath(u.ID, "/devices/"+id.String()), bearer(adm.Token)), http.StatusNotFound, "auth.device_not_found")
	}
	if svSession(t, h.Env, theirs.SessionID).EndedAt != nil {
		t.Error("a session of another user was ended through this user's path")
	}
}

func TestHandler_AdminEndsAllSessionsOfAUser(t *testing.T) {
	h := newHandlerEnv(t)
	adm := hAdmin(t, h)
	u := h.UserWithStatus(t, auth.StatusActive)
	other := h.UserWithStatus(t, auth.StatusActive)
	a := hMobileSignIn(t, h, u, uuid.New())
	_, web := hWebSignIn(t, h, u, uuid.New())
	theirs := hMobileSignIn(t, h, other, uuid.New())

	rec := h.post(hUserPath(u.ID, "/sessions/end-all"), nil, bearer(adm.Token))
	hOK(t, rec, http.StatusNoContent)
	if rec.Header().Get("Set-Cookie") != "" {
		t.Error("an admin ending a user's sessions must not touch the admin's own cookie")
	}
	h.Clock.Advance(time.Second)
	for _, tok := range []string{a.AccessToken, web.AccessToken} {
		hProblem(t, h.get("/v1/auth/devices", bearer(tok)), http.StatusUnauthorized, "auth.unauthenticated")
	}
	hOK(t, h.get("/v1/auth/devices", bearer(theirs.AccessToken)), http.StatusOK)
	hOK(t, h.get("/v1/auth/devices", bearer(adm.Token)), http.StatusOK)
	row := mfOnly(t, h.Env, auth.ActionSessionEndedAllByAdmin)
	if row.ActorKind != "admin" || row.ActorID != adm.ID || row.EntityID != u.ID {
		t.Errorf("audit = %+v", row)
	}
	hOK(t, h.post(hUserPath(u.ID, "/sessions/end-all"), nil, bearer(adm.Token)), http.StatusNoContent) // naturally idempotent
}
