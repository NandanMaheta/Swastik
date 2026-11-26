package ipos

import (
	"reflect"
	"testing"

	"github.com/google/uuid"
)

// S06 (feature 009): the additive batch read GetMany (contracts/go-module-api.md, "Additive change
// to 008"): the org's IPOs among ids, drafts included, keyed by id; unknown ids and other orgs'
// ids are absent; one query, read-only, works without a caller transaction. The "len(ids) <= 200"
// precondition is the caller's; its behaviour above 200 is not specified and not tested.

func (e *svcEnv) otherOrgIPO() IPO {
	e.t.Helper()
	var org uuid.UUID
	if err := e.h.Pool.QueryRow(e.ctx(), `INSERT INTO orgs (name) VALUES ('Other') RETURNING id`).Scan(&org); err != nil {
		e.t.Fatalf("insert org: %v", err)
	}
	res, err := e.svc.Create(e.ctx(), e.admin, org, acme(), e.key())
	if err != nil {
		e.t.Fatalf("Create in other org: %v", err)
	}
	return res.IPO
}

func TestGetMany_BR_IPO_04_DraftsAndPublishedByID(t *testing.T) {
	e := newSvcEnv(t)
	draft := e.create(minimalDraft("Draft"))
	pub := e.published(acme(), FlagApply)

	got, err := e.svc.GetMany(e.ctx(), e.org, []uuid.UUID{draft.ID, pub.ID})
	if err != nil {
		t.Fatalf("GetMany: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d IPOs, want 2 (drafts included)", len(got))
	}
	for _, want := range []IPO{e.currentID(draft.ID), e.currentID(pub.ID)} {
		if !reflect.DeepEqual(got[want.ID], want) {
			t.Errorf("GetMany[%s] differs from Get:\n got  %+v\n want %+v", want.ID, got[want.ID], want)
		}
	}
	if g := got[pub.ID]; !g.Published || g.FirstPublishedAt == nil || g.LotSize == nil || *g.LotSize != 14 {
		t.Errorf("published IPO lacks publication or lot size: %+v", g)
	}
	if g := got[draft.ID]; g.Published || g.FirstPublishedAt != nil {
		t.Errorf("draft shows as published: %+v", g)
	}
}

func TestGetMany_BR_IPO_04_UnknownAndForeignIDsAreAbsent(t *testing.T) {
	e := newSvcEnv(t)
	mine := e.create(minimalDraft("Mine"))
	foreign := e.otherOrgIPO()
	got, err := e.svc.GetMany(e.ctx(), e.org, []uuid.UUID{mine.ID, foreign.ID, uuid.New()})
	if err != nil {
		t.Fatalf("GetMany: %v", err)
	}
	if _, ok := got[mine.ID]; !ok || len(got) != 1 {
		t.Fatalf("got %d entries %v, want only %s", len(got), got, mine.ID)
	}
	if _, ok := got[foreign.ID]; ok {
		t.Error("another org's IPO is visible (org scoping)")
	}
	// The other org sees only its own.
	back, err := e.svc.GetMany(e.ctx(), foreign.OrgID, []uuid.UUID{mine.ID, foreign.ID})
	if err != nil || len(back) != 1 || back[foreign.ID].ID != foreign.ID {
		t.Errorf("other org GetMany = %v, %v; want only its own IPO", back, err)
	}
}

func TestGetMany_BR_IPO_04_EmptyAndDuplicateIDs(t *testing.T) {
	e := newSvcEnv(t)
	a := e.create(minimalDraft("A"))
	for _, ids := range [][]uuid.UUID{nil, {}} {
		got, err := e.svc.GetMany(e.ctx(), e.org, ids)
		if err != nil || len(got) != 0 {
			t.Errorf("GetMany(%v) = %v, %v; want empty map, no error", ids, got, err)
		}
	}
	got, err := e.svc.GetMany(e.ctx(), e.org, []uuid.UUID{a.ID, a.ID, a.ID})
	if err != nil || len(got) != 1 || got[a.ID].ID != a.ID {
		t.Errorf("duplicate ids = %v, %v; want one entry", got, err)
	}
}

func TestGetMany_BR_IPO_04_UpToTwoHundredIDs(t *testing.T) {
	e := newSvcEnv(t)
	a, b := e.create(minimalDraft("A")), e.create(minimalDraft("B"))
	ids := []uuid.UUID{a.ID, b.ID}
	for len(ids) < 200 {
		ids = append(ids, uuid.New())
	}
	got, err := e.svc.GetMany(e.ctx(), e.org, ids)
	if err != nil {
		t.Fatalf("GetMany(200 ids): %v", err)
	}
	if len(got) != 2 || got[a.ID].Name != "A" || got[b.ID].Name != "B" {
		t.Errorf("GetMany(200 ids) = %d entries, want the 2 known IPOs", len(got))
	}
}

func TestGetMany_BR_IPO_04_ReflectsLatestState(t *testing.T) {
	e := newSvcEnv(t)
	pub := e.published(acme(), FlagApply)
	moved := e.override(pub, StatusListed, "test")
	got, err := e.svc.GetMany(e.ctx(), e.org, []uuid.UUID{pub.ID})
	if err != nil || got[pub.ID].Status != StatusListed || got[pub.ID].Version != moved.Version {
		t.Fatalf("GetMany = %+v, %v; want status LISTED at version %d", got[pub.ID], err, moved.Version)
	}
}
