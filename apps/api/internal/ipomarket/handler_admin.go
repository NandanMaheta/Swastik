package ipomarket

import (
	"context"
	"net/http"
	"strings"

	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"

	"github.com/NandanMaheta/swastik/apps/api/internal/platform/authz"
)

const tagIPOMarket = "ipomarket"

// Register adds the HTTP operations. It accepts a nil service: the operations are then documented
// but answer 503 (the openapi command and the static contract walk).
func Register(api huma.API, s *Service) {
	registerAdmin(api, s)
	registerClient(api, s)
}

// IdemInput is the optional Idempotency-Key header of the mutations (FR-010).
type IdemInput struct {
	IdempotencyKey string `header:"Idempotency-Key" required:"false" minLength:"8" maxLength:"200" pattern:"^[A-Za-z0-9._:-]+$" doc:"Repeats with the same key return the first result."`
}

// IPOPath is the {ipoId} path parameter.
type IPOPath struct {
	ID string `path:"ipoId" format:"uuid"`
}

// PageQuery is the keyset paging query of the history lists.
type PageQuery struct {
	Limit  int    `query:"limit" minimum:"1" maximum:"200" default:"50"`
	Cursor string `query:"cursor" maxLength:"300"`
}

type idsQuery struct {
	IPOIDs string `query:"ipo_ids" required:"true" doc:"Comma-separated IPO ids, 1 to 200"`
}

func parseID(s string) uuid.UUID {
	id, _ := uuid.Parse(s) // the schema validated the format
	return id
}

// parseIDs splits a comma-separated list of 1 to 200 uuids.
func parseIDs(s string) ([]uuid.UUID, error) {
	parts := strings.Split(s, ",")
	if len(parts) > 200 {
		return nil, validationFailed("query.ipo_ids", "at most 200 ids")
	}
	out := make([]uuid.UUID, 0, len(parts))
	for _, p := range parts {
		id, err := uuid.Parse(strings.TrimSpace(p))
		if err != nil {
			return nil, validationFailed("query.ipo_ids", "must be comma-separated uuids")
		}
		out = append(out, id)
	}
	return out, nil
}

type recordGMPInput struct {
	IdemInput
	IPOPath
	Body GMPEntryInput
}

type recordGMPOutput struct {
	Status int
	Body   GMPRecordResult
}

type recordSubInput struct {
	IdemInput
	IPOPath
	Body SubscriptionBody
}

type recordSubOutput struct {
	Status int
	Body   SubscriptionRecordResult
}

type listGMPInput struct {
	IPOPath
	PageQuery
}

type listGMPOutput struct{ Body AdminGMPPage }

type listSubOutput struct{ Body AdminSubscriptionPage }

type summariesOutput struct{ Body MarketSummaries }

func registerAdmin(api huma.API, s *Service) {
	huma.Register(api, huma.Operation{
		OperationID: "ipomarket-record-gmp", Method: http.MethodPost, Path: "/v1/admin/ipos/{ipoId}/gmp", Tags: []string{tagIPOMarket},
		Summary: "Record a GMP entry (or correct the current one)", Security: authz.Require(authz.RoleAdmin),
		DefaultStatus: http.StatusCreated,
		Responses:     map[string]*huma.Response{"200": {Description: "Idempotent replay (original entry, current state)"}},
	}, func(ctx context.Context, in *recordGMPInput) (*recordGMPOutput, error) {
		if err := ready(s); err != nil {
			return nil, err
		}
		g := GMPInput{GMPPaise: in.Body.GMPPaise, Note: in.Body.Note, Source: "manual"}
		if in.Body.CorrectsEntryID != nil {
			id := parseID(*in.Body.CorrectsEntryID)
			g.CorrectsEntryID = &id
		}
		p := authz.MustPrincipal(ctx)
		r, err := s.RecordGMP(ctx, p.AuditActor(), p.OrgID, parseID(in.ID), g, in.IdempotencyKey)
		if err != nil {
			return nil, fail(ctx, s, err)
		}
		return &recordGMPOutput{Status: statusOf(r.Replayed), Body: GMPRecordResult{
			Entry: gmpEntryOut(r.Entry), Current: currentOut(r.Current), Warnings: warningsOut(r.Warnings)}}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "ipomarket-list-gmp", Method: http.MethodGet, Path: "/v1/admin/ipos/{ipoId}/gmp", Tags: []string{tagIPOMarket},
		Summary: "GMP history of an IPO, newest first (corrected entries included)", Security: authz.Require(authz.RoleAdmin),
	}, func(ctx context.Context, in *listGMPInput) (*listGMPOutput, error) {
		if err := ready(s); err != nil {
			return nil, err
		}
		page, err := s.ListGMP(ctx, authz.MustPrincipal(ctx).OrgID, parseID(in.ID), in.Cursor, in.Limit)
		if err != nil {
			return nil, fail(ctx, s, err)
		}
		out := &listGMPOutput{Body: AdminGMPPage{Items: make([]AdminGMPEntry, 0, len(page.Items)), NextCursor: cursorOut(page.NextCursor)}}
		for _, e := range page.Items {
			out.Body.Items = append(out.Body.Items, gmpEntryOut(e))
		}
		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "ipomarket-record-subscription", Method: http.MethodPost, Path: "/v1/admin/ipos/{ipoId}/subscription", Tags: []string{tagIPOMarket},
		Summary: "Record a subscription snapshot", Security: authz.Require(authz.RoleAdmin),
		DefaultStatus: http.StatusCreated,
		Responses:     map[string]*huma.Response{"200": {Description: "Idempotent replay (original snapshot, current state)"}},
	}, func(ctx context.Context, in *recordSubInput) (*recordSubOutput, error) {
		if err := ready(s); err != nil {
			return nil, err
		}
		b := in.Body
		sub := SubscriptionInput{AsOf: b.AsOf, TotalX100: b.TotalX100, QIBX100: b.QIBX100, NIIX100: b.NIIX100,
			BNIIX100: b.BNIIX100, SNIIX100: b.SNIIX100, RetailX100: b.RetailX100, EmployeeX100: b.EmployeeX100, Source: "manual"}
		p := authz.MustPrincipal(ctx)
		r, err := s.RecordSubscription(ctx, p.AuditActor(), p.OrgID, parseID(in.ID), sub, in.IdempotencyKey)
		if err != nil {
			return nil, fail(ctx, s, err)
		}
		return &recordSubOutput{Status: statusOf(r.Replayed), Body: SubscriptionRecordResult{
			Snapshot: adminSubOut(r.Snapshot), Current: subViewOut(r.Current)}}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "ipomarket-list-subscription", Method: http.MethodGet, Path: "/v1/admin/ipos/{ipoId}/subscription", Tags: []string{tagIPOMarket},
		Summary: "Subscription history of an IPO, latest as-of first", Security: authz.Require(authz.RoleAdmin),
	}, func(ctx context.Context, in *listGMPInput) (*listSubOutput, error) {
		if err := ready(s); err != nil {
			return nil, err
		}
		page, err := s.ListSubscriptions(ctx, authz.MustPrincipal(ctx).OrgID, parseID(in.ID), in.Cursor, in.Limit)
		if err != nil {
			return nil, fail(ctx, s, err)
		}
		out := &listSubOutput{Body: AdminSubscriptionPage{Items: make([]AdminSubscription, 0, len(page.Items)), NextCursor: cursorOut(page.NextCursor)}}
		for _, e := range page.Items {
			out.Body.Items = append(out.Body.Items, adminSubOut(e))
		}
		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "ipomarket-admin-summaries", Method: http.MethodGet, Path: "/v1/admin/ipos/market", Tags: []string{tagIPOMarket},
		Summary: "Market summaries of up to 200 IPOs (drafts included)", Security: authz.Require(authz.RoleAdmin),
	}, func(ctx context.Context, in *idsQuery) (*summariesOutput, error) {
		return summaries(ctx, s, in, false)
	})
}

func statusOf(replayed bool) int {
	if replayed {
		return http.StatusOK
	}
	return http.StatusCreated
}

func summaries(ctx context.Context, s *Service, in *idsQuery, publishedOnly bool) (*summariesOutput, error) {
	if err := ready(s); err != nil {
		return nil, err
	}
	ids, err := parseIDs(in.IPOIDs)
	if err != nil {
		return nil, err
	}
	out, err := s.Summaries(ctx, authz.MustPrincipal(ctx).OrgID, ids, publishedOnly)
	if err != nil {
		return nil, fail(ctx, s, err)
	}
	return &summariesOutput{Body: summariesOut(out)}, nil
}
