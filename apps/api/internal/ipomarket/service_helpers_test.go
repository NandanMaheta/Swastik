package ipomarket

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/NandanMaheta/swastik/apps/api/internal/ipos"
	"github.com/NandanMaheta/swastik/apps/api/internal/platform/audit"
)

// Shared helpers for the service and HTTP tests (slices S08, S10, S12, S14, S16). The Service runs
// over the real store, the real 008 reader (ipos.NewService, which needs no scheduler for reads)
// and a settable clock; state is arranged and read back with raw SQL so no assertion depends on
// the code under test, except where a read is the subject.
//
// Assumptions the contracts leave open (the implementation must satisfy them):
//   - NewService(Deps{Tx, IPOs, Now, Log}) alone is enough (the service builds its own store).
//   - Writes and reads work without a caller transaction (the service opens its own).
//   - Audit rows are entity 'ipo', entity_id = IPO id, actions ipo.gmp_recorded and
//     ipo.subscription_recorded; `after` holds the keys of data-model section 4.
//   - A correction whose target is unknown, of another IPO, not current or already corrected gives
//     ErrCorrectionNotLatest; ErrNotFound is only for an unknown IPO (or another org's).

type svcEnv struct {
	*mEnv
	svc *Service
	mu  sync.Mutex
	clk time.Time
	adm audit.Actor
}

func newSvcEnv(t *testing.T) *svcEnv {
	t.Helper()
	m := newMEnv(t)
	e := &svcEnv{mEnv: m, clk: m.now, adm: audit.Actor{ID: uuid.New(), Kind: audit.KindAdmin}}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	reader := ipos.NewService(ipos.Deps{Tx: m.tx, Now: e.now_, Log: log})
	e.svc = NewService(Deps{Tx: m.tx, IPOs: reader, Now: e.now_, Log: log})
	return e
}

func (e *svcEnv) now_() time.Time {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.clk
}

func (e *svcEnv) setNow(at time.Time) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.clk = at
}

func (e *svcEnv) ctx() context.Context { return e.t.Context() }

// gmp records one entry through the service and fails the test on an error.
func (e *svcEnv) gmp(ipo uuid.UUID, v int64) GMPResult {
	e.t.Helper()
	r, err := e.svc.RecordGMP(e.ctx(), e.adm, e.org, ipo, GMPInput{GMPPaise: v, Source: "manual"}, "")
	if err != nil {
		e.t.Fatalf("RecordGMP(%d): %v", v, err)
	}
	return r
}

func (e *svcEnv) sub(ipo uuid.UUID, asOf time.Time, total int32) SubscriptionResult {
	e.t.Helper()
	r, err := e.svc.RecordSubscription(e.ctx(), e.adm, e.org, ipo,
		SubscriptionInput{AsOf: asOf, TotalX100: total, Source: "manual"}, "")
	if err != nil {
		e.t.Fatalf("RecordSubscription: %v", err)
	}
	return r
}

// onceUnpublished is an IPO that was published once and then unpublished, optionally without lot
// size (publication needs a lot size, unpublishing does not).
func (e *svcEnv) onceUnpublished(clearLot bool) uuid.UUID {
	e.t.Helper()
	id := e.publishedIPO()
	q := `UPDATE ipos SET published = false WHERE id = $1`
	if clearLot {
		q = `UPDATE ipos SET published = false, lot_size = NULL WHERE id = $1`
	}
	if _, err := e.pool.Exec(e.ctx(), q, id); err != nil {
		e.t.Fatalf("unpublish: %v", err)
	}
	return id
}

func (e *svcEnv) setStatus(ipo uuid.UUID, status string) {
	e.t.Helper()
	if _, err := e.pool.Exec(e.ctx(), `UPDATE ipos SET status = $2 WHERE id = $1`, ipo, status); err != nil {
		e.t.Fatalf("set status: %v", err)
	}
}

func (e *svcEnv) count(table string, ipo uuid.UUID) int {
	e.t.Helper()
	var n int
	if err := e.pool.QueryRow(e.ctx(), `SELECT count(*) FROM `+table+` WHERE ipo_id = $1`, ipo).Scan(&n); err != nil {
		e.t.Fatalf("count %s: %v", table, err)
	}
	return n
}

func (e *svcEnv) gmpRows(ipo uuid.UUID) int { return e.count("ipo_gmp_entries", ipo) }
func (e *svcEnv) subRows(ipo uuid.UUID) int { return e.count("ipo_subscription_snapshots", ipo) }

type auditRow struct {
	Action, ActorKind string
	ActorID           *uuid.UUID
	After             map[string]any
}

func (e *svcEnv) audits(ipo uuid.UUID) []auditRow {
	e.t.Helper()
	rows, err := e.pool.Query(e.ctx(), `SELECT action, actor_kind, actor_id, after FROM audit_log
		WHERE entity = 'ipo' AND entity_id = $1 AND (action = 'ipo.gmp_recorded' OR action = 'ipo.subscription_recorded')
		ORDER BY id`, ipo)
	if err != nil {
		e.t.Fatalf("read audit: %v", err)
	}
	defer rows.Close()
	var out []auditRow
	for rows.Next() {
		var a auditRow
		var raw []byte
		if err := rows.Scan(&a.Action, &a.ActorKind, &a.ActorID, &raw); err != nil {
			e.t.Fatalf("scan audit: %v", err)
		}
		if raw != nil {
			_ = json.Unmarshal(raw, &a.After)
		}
		out = append(out, a)
	}
	return out
}

func (e *svcEnv) wantAudits(ipo uuid.UUID, n int) {
	e.t.Helper()
	if got := len(e.audits(ipo)); got != n {
		e.t.Fatalf("audit rows = %d, want %d", got, n)
	}
}

func (e *svcEnv) wantNoWrites(ipo uuid.UUID) {
	e.t.Helper()
	if e.gmpRows(ipo) != 0 || e.subRows(ipo) != 0 {
		e.t.Fatalf("rows written for a rejected request: gmp=%d sub=%d", e.gmpRows(ipo), e.subRows(ipo))
	}
	e.wantAudits(ipo, 0)
}
