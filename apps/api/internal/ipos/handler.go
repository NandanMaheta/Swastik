package ipos

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"

	"github.com/NandanMaheta/swastik/apps/api/internal/platform/authz"
	"github.com/NandanMaheta/swastik/apps/api/internal/platform/httpx"
	"github.com/NandanMaheta/swastik/apps/api/internal/platform/istdate"
)

// Register adds the HTTP operations (admin and client). It accepts a nil service: the operations
// are then documented but answer 503 (the openapi command and the static contract walk).
func Register(api huma.API, s *Service) {
	registerAdmin(api, s)
	registerActions(api, s)
	registerClient(api, s)
}

const tagIPOs = "IPOs"

// IdemInput is the optional Idempotency-Key header of every mutation (FR-007).
type IdemInput struct {
	IdempotencyKey string `header:"Idempotency-Key" required:"false" minLength:"8" maxLength:"200" pattern:"^[A-Za-z0-9._:-]+$" doc:"Repeats with the same key return the first result."`
}

// IDPath is the {ipoId} path parameter.
type IDPath struct {
	ID string `path:"ipoId" format:"uuid"`
}

func parseID(s string) uuid.UUID {
	id, _ := uuid.Parse(s) // the schema validated the format
	return id
}

// ready refuses an operation on an API built without a service.
func ready(s *Service) error {
	if s == nil {
		return httpx.Problem(http.StatusServiceUnavailable, codeNotConfigured, "The IPO service is not configured.")
	}
	return nil
}

// fail maps a service error to its problem and logs an unexpected one (without echoing it).
func fail(ctx context.Context, s *Service, err error) error {
	p := problemFor(err)
	if se, ok := p.(huma.StatusError); ok && se.GetStatus() >= http.StatusInternalServerError {
		s.d.Log.ErrorContext(ctx, "ipos: unexpected error", slog.Any("err", err))
	}
	return p
}

type mutationOutput struct {
	Status int
	Body   IPOMutationResult
}

func mutation(r Result) *mutationOutput {
	return &mutationOutput{Status: http.StatusOK, Body: resultOut(r)}
}

type createInput struct {
	IdemInput
	Body IPODraft
}

type updateInput struct {
	IdemInput
	IDPath
	Body IPOReplace
}

type adminListInput struct {
	Status    string `query:"status" enum:"UPCOMING,OPEN,CLOSED,ALLOTMENT_OUT,LISTED,SETTLED"`
	Published string `query:"published" enum:"true,false"`
	Flag      string `query:"flag" enum:"APPLY,DO_NOT_APPLY,NONE"`
	Month     string `query:"month" pattern:"^[0-9]{4}-(0[1-9]|1[0-2])$" doc:"Open-date month (IST civil), YYYY-MM"`
	Limit     int    `query:"limit" minimum:"1" maximum:"200" default:"50"`
	Cursor    string `query:"cursor" maxLength:"200"`
}

type adminListOutput struct{ Body AdminIPOPage }

type adminGetInput struct{ IDPath }

type adminGetOutput struct{ Body AdminIPO }

type suggestInput struct {
	CloseDate string `query:"close_date" format:"date" required:"true"`
}

type suggestOutput struct{ Body dateSuggestionBody }

func registerAdmin(api huma.API, s *Service) {
	huma.Register(api, huma.Operation{
		OperationID: "ipos-create", Method: http.MethodPost, Path: "/v1/admin/ipos", Tags: []string{tagIPOs},
		Summary: "Create an IPO draft (mainboard only)", Security: authz.Require(authz.RoleAdmin),
		DefaultStatus: http.StatusCreated,
		Responses:     map[string]*huma.Response{"200": {Description: "Idempotent replay (current state)"}},
	}, func(ctx context.Context, in *createInput) (*mutationOutput, error) {
		if err := ready(s); err != nil {
			return nil, err
		}
		p := authz.MustPrincipal(ctx)
		res, err := s.Create(ctx, p.AuditActor(), p.OrgID, in.Body.draft(), in.IdempotencyKey)
		if err != nil {
			return nil, fail(ctx, s, err)
		}
		out := mutation(res)
		if res.Replayed {
			out.Status = http.StatusOK
		} else {
			out.Status = http.StatusCreated
		}
		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "ipos-admin-list", Method: http.MethodGet, Path: "/v1/admin/ipos", Tags: []string{tagIPOs},
		Summary: "List all IPOs of the org (drafts and published)", Security: authz.Require(authz.RoleAdmin),
	}, func(ctx context.Context, in *adminListInput) (*adminListOutput, error) {
		if err := ready(s); err != nil {
			return nil, err
		}
		f := AdminFilter{Cursor: in.Cursor, Limit: in.Limit}
		if in.Status != "" {
			st := Status(in.Status)
			f.Status = &st
		}
		if in.Published != "" {
			b := in.Published == "true"
			f.Published = &b
		}
		if in.Flag != "" {
			f.Flag = &in.Flag
		}
		if in.Month != "" {
			start, err := istdate.ParseDate(in.Month + "-01")
			if err != nil {
				return nil, fail(ctx, s, err)
			}
			end := start.AddDays(31)
			end = istdate.Date{Year: end.Year, Month: end.Month, Day: 1}.AddDays(-1)
			f.MonthStart, f.MonthEnd = &start, &end
		}
		page, err := s.List(ctx, authz.MustPrincipal(ctx).OrgID, f)
		if err != nil {
			return nil, fail(ctx, s, err)
		}
		out := &adminListOutput{Body: AdminIPOPage{Items: make([]AdminIPO, 0, len(page.Items)), NextCursor: cursorOut(page.NextCursor)}}
		for _, i := range page.Items {
			out.Body.Items = append(out.Body.Items, adminOut(i))
		}
		return out, nil
	})

	// The literal path is registered before /{ipoId} (route precedence).
	huma.Register(api, huma.Operation{
		OperationID: "ipos-suggest-dates", Method: http.MethodGet, Path: "/v1/admin/ipos/date-suggestions", Tags: []string{tagIPOs},
		Summary:  "Suggest allotment, refund, credit and listing dates from a close date (weekdays only; nothing is saved)",
		Security: authz.Require(authz.RoleAdmin),
	}, func(ctx context.Context, in *suggestInput) (*suggestOutput, error) {
		if err := ready(s); err != nil {
			return nil, err
		}
		closeDate, err := istdate.ParseDate(in.CloseDate)
		if err != nil {
			return nil, httpx.Problem(http.StatusUnprocessableEntity, "validation_failed", "close_date must be YYYY-MM-DD.")
		}
		d := SuggestDates(closeDate)
		return &suggestOutput{Body: dateSuggestionBody{
			CloseDate: d.Close.String(), AllotmentDate: d.Allotment.String(), RefundDate: d.Refund.String(),
			DematCreditDate: d.DematCredit.String(), ListingDate: d.Listing.String(),
			NoticeCode: "ipo.weekdays_only", Notice: d.Notice,
		}}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "ipos-admin-get", Method: http.MethodGet, Path: "/v1/admin/ipos/{ipoId}", Tags: []string{tagIPOs},
		Summary: "Fetch any IPO of the org", Security: authz.Require(authz.RoleAdmin),
	}, func(ctx context.Context, in *adminGetInput) (*adminGetOutput, error) {
		if err := ready(s); err != nil {
			return nil, err
		}
		i, err := s.Get(ctx, authz.MustPrincipal(ctx).OrgID, parseID(in.ID))
		if err != nil {
			return nil, fail(ctx, s, err)
		}
		return &adminGetOutput{Body: adminOut(i)}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "ipos-update", Method: http.MethodPut, Path: "/v1/admin/ipos/{ipoId}", Tags: []string{tagIPOs},
		Summary: "Replace the catalogue facts of an IPO (all keys required, null clears)", Security: authz.Require(authz.RoleAdmin),
	}, func(ctx context.Context, in *updateInput) (*mutationOutput, error) {
		if err := ready(s); err != nil {
			return nil, err
		}
		p := authz.MustPrincipal(ctx)
		res, err := s.Update(ctx, p.AuditActor(), p.OrgID, parseID(in.ID), in.Body.Version, in.Body.draft(), in.IdempotencyKey)
		if err != nil {
			return nil, fail(ctx, s, err)
		}
		return mutation(res), nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "ipos-set-flag", Method: http.MethodPut, Path: "/v1/admin/ipos/{ipoId}/flag", Tags: []string{tagIPOs},
		Summary: "Set or change APPLY / DO NOT APPLY and the client-visible note", Security: authz.Require(authz.RoleAdmin),
	}, func(ctx context.Context, in *flagInput) (*mutationOutput, error) {
		if err := ready(s); err != nil {
			return nil, err
		}
		p := authz.MustPrincipal(ctx)
		var flag *ApplyFlag
		if in.Body.ApplyFlag != nil {
			f := ApplyFlag(*in.Body.ApplyFlag)
			flag = &f
		}
		res, err := s.SetFlag(ctx, p.AuditActor(), p.OrgID, parseID(in.ID), in.Body.Version, flag, in.Body.FlagNote, in.IdempotencyKey)
		if err != nil {
			return nil, fail(ctx, s, err)
		}
		return mutation(res), nil
	})
}

type flagInput struct {
	IdemInput
	IDPath
	Body FlagBody
}
