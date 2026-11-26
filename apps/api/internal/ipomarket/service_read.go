package ipomarket

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
)

const (
	defaultPageSize = 50
	maxPageSize     = 200
)

// ErrBadCursor is returned for a cursor that does not decode (HTTP 422 validation_failed).
var ErrBadCursor = errors.New("ipomarket: invalid cursor")

type cursorJSON struct {
	At         time.Time `json:"a"`
	RecordedAt time.Time `json:"r,omitzero"`
	ID         uuid.UUID `json:"i"`
}

func encodeCursor(a pageAfter) string {
	b, _ := json.Marshal(cursorJSON{At: a.At.UTC(), RecordedAt: a.RecordedAt.UTC(), ID: a.ID})
	return base64.RawURLEncoding.EncodeToString(b)
}

func decodeCursor(c string) (pageAfter, error) {
	if c == "" {
		return pageAfter{}, nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(c)
	if err != nil {
		return pageAfter{}, ErrBadCursor
	}
	var j cursorJSON
	if err := json.Unmarshal(raw, &j); err != nil || j.ID == uuid.Nil {
		return pageAfter{}, ErrBadCursor
	}
	return pageAfter(j), nil
}

func pageSize(limit int) int {
	switch {
	case limit <= 0:
		return defaultPageSize
	case limit > maxPageSize:
		return maxPageSize
	}
	return limit
}

// CurrentGMP returns the newest effective entry; ok=false when the IPO has none. It does not check
// publication.
func (s *Service) CurrentGMP(ctx context.Context, org, ipoID uuid.UUID) (g GMP, ok bool, err error) {
	err = s.d.Tx.InTx(ctx, func(ctx context.Context) error {
		e, err := s.store.currentGMP(ctx, org, ipoID)
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		g, ok = GMP{EntryID: e.ID, GMPPaise: e.GMPPaise, RecordedAt: e.RecordedAt, Source: e.Source}, true
		return nil
	})
	if err != nil {
		return GMP{}, false, err
	}
	return g, ok, nil
}

// ListGMP returns one keyset page of the admin GMP history (newest first, corrected entries kept).
func (s *Service) ListGMP(ctx context.Context, org, ipoID uuid.UUID, cursor string, limit int) (Page[GMPEntry], error) {
	after, err := decodeCursor(cursor)
	if err != nil {
		return Page[GMPEntry]{}, err
	}
	n := pageSize(limit)
	var out Page[GMPEntry]
	err = s.d.Tx.InTx(ctx, func(ctx context.Context) error {
		ipo, err := s.loadIPO(ctx, org, ipoID)
		if err != nil {
			return err
		}
		rows, err := s.store.listGMPHistory(ctx, org, ipoID, after, n+1)
		if err != nil {
			return err
		}
		if len(rows) > n {
			rows = rows[:n]
			last := rows[n-1]
			out.NextCursor = encodeCursor(pageAfter{At: last.RecordedAt, ID: last.ID})
		}
		for i := range rows {
			rows[i] = withProfit(ipo, rows[i])
		}
		out.Items = rows
		return nil
	})
	if err != nil {
		return Page[GMPEntry]{}, err
	}
	return out, nil
}

// ListSubscriptions returns one keyset page of the admin subscription history (latest as-of first).
func (s *Service) ListSubscriptions(ctx context.Context, org, ipoID uuid.UUID, cursor string, limit int) (Page[Snapshot], error) {
	after, err := decodeCursor(cursor)
	if err != nil {
		return Page[Snapshot]{}, err
	}
	n := pageSize(limit)
	var out Page[Snapshot]
	err = s.d.Tx.InTx(ctx, func(ctx context.Context) error {
		if _, err := s.loadIPO(ctx, org, ipoID); err != nil {
			return err
		}
		rows, err := s.store.listSnapshotHistory(ctx, org, ipoID, after, n+1)
		if err != nil {
			return err
		}
		if len(rows) > n {
			rows = rows[:n]
			last := rows[n-1]
			out.NextCursor = encodeCursor(pageAfter{At: last.AsOf, RecordedAt: last.RecordedAt, ID: last.ID})
		}
		out.Items = rows
		return nil
	})
	if err != nil {
		return Page[Snapshot]{}, err
	}
	return out, nil
}

// MarketView returns the market view of one IPO; publishedOnly hides unpublished ones as ErrNotFound.
func (s *Service) MarketView(ctx context.Context, org, ipoID uuid.UUID, publishedOnly bool) (View, error) {
	v := View{IPOID: ipoID, Trend: []TrendPoint{}}
	err := s.d.Tx.InTx(ctx, func(ctx context.Context) error {
		ipo, err := s.loadIPO(ctx, org, ipoID)
		if err != nil {
			return err
		}
		if publishedOnly && !ipo.Published {
			return ErrNotFound
		}
		cur, err := s.store.currentGMP(ctx, org, ipoID)
		switch {
		case err == nil:
			c := currentView(ipo, cur)
			v.CurrentGMP = &c
		case !errors.Is(err, ErrNotFound):
			return err
		}
		trend, err := s.store.listGMPTrend(ctx, org, ipoID)
		if err != nil {
			return err
		}
		for _, e := range trend {
			v.Trend = append(v.Trend, TrendPoint{GMPPaise: e.GMPPaise, ExpectedProfitPaise: profitOf(ipo.LotSize, e.GMPPaise), At: e.RecordedAt})
		}
		snap, err := s.store.currentSnapshot(ctx, org, ipoID)
		switch {
		case err == nil:
			v.Subscription = &snap
		case !errors.Is(err, ErrNotFound):
			return err
		}
		return nil
	})
	if err != nil {
		return View{}, err
	}
	return v, nil
}

// Summaries returns the batch summaries (at most 200 ids), in first-seen order of the ids. Unknown
// and other orgs' ids are absent; with publishedOnly so are unpublished IPOs.
func (s *Service) Summaries(ctx context.Context, org uuid.UUID, ids []uuid.UUID, publishedOnly bool) ([]Summary, error) {
	seen := make(map[uuid.UUID]bool, len(ids))
	uniq := make([]uuid.UUID, 0, len(ids))
	for _, id := range ids {
		if !seen[id] {
			seen[id] = true
			uniq = append(uniq, id)
		}
	}
	if len(uniq) == 0 {
		return []Summary{}, nil
	}
	out := []Summary{}
	err := s.d.Tx.InTx(ctx, func(ctx context.Context) error {
		found, err := s.d.IPOs.GetMany(ctx, org, uniq)
		if err != nil {
			return err
		}
		visible := make([]uuid.UUID, 0, len(found))
		for _, id := range uniq {
			if ipo, ok := found[id]; ok && (!publishedOnly || ipo.Published) {
				visible = append(visible, id)
			}
		}
		if len(visible) == 0 {
			return nil
		}
		gmps, err := s.store.currentGMPBatch(ctx, org, visible)
		if err != nil {
			return err
		}
		subs, err := s.store.currentSnapshotBatch(ctx, org, visible)
		if err != nil {
			return err
		}
		for _, id := range visible {
			sum := Summary{IPOID: id}
			if e, ok := gmps[id]; ok {
				c := currentView(found[id], e)
				sum.CurrentGMP = &c
			}
			if sn, ok := subs[id]; ok {
				total, asOf := sn.TotalX100, sn.AsOf
				sum.SubscriptionTotalX100, sum.SubscriptionAsOf = &total, &asOf
			}
			out = append(out, sum)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
