package ipomarket

import (
	"context"
	"errors"
	"log/slog"
	"net/http"

	"github.com/danielgtaylor/huma/v2"

	"github.com/NandanMaheta/swastik/apps/api/internal/platform/httpx"
)

// RFC 9457 problem codes (contracts/http-api.md).
const (
	codeKeyReused        = "ipomarket.idempotency_key_reused"
	codeNotPublishedYet  = "ipomarket.not_published_yet"
	codeFrozen           = "ipomarket.frozen"
	codeCorrectionLatest = "ipomarket.correction_not_latest"
	codeNotConfigured    = "ipomarket.not_configured"
)

func located(location, message string) *huma.ErrorDetail {
	return &huma.ErrorDetail{Location: location, Message: message}
}

func withErrors(p error, errs ...*huma.ErrorDetail) error {
	var em *httpx.ErrorModel
	if errors.As(p, &em) {
		em.Errors = append(em.Errors, errs...)
	}
	return p
}

// validationFailed is the 422 for a request the schema accepts but the handler cannot parse.
func validationFailed(location, message string) error {
	return withErrors(httpx.Problem(http.StatusUnprocessableEntity, "validation_failed", "The request is not valid."), located(location, message))
}

// problemFor maps a service error to a problem; unknown errors become a bare 500.
func problemFor(err error) error {
	var ve *ValidationError
	switch {
	case errors.As(err, &ve):
		errs := make([]*huma.ErrorDetail, 0, len(ve.Issues))
		for _, is := range ve.Issues {
			errs = append(errs, located("body."+is.Field, is.Message))
		}
		return withErrors(httpx.Problem(http.StatusUnprocessableEntity, ve.Code, "A value is not valid."), errs...)
	case errors.Is(err, ErrKeyReused):
		return withErrors(httpx.Problem(http.StatusUnprocessableEntity, codeKeyReused, "This Idempotency-Key was already used for a different request; use a new key."),
			located("header.Idempotency-Key", "this key was already used for a different request"))
	case errors.Is(err, ErrNotPublishedYet):
		return httpx.Problem(http.StatusConflict, codeNotPublishedYet, "The IPO has never been published.")
	case errors.Is(err, ErrFrozen):
		return httpx.Problem(http.StatusConflict, codeFrozen, "The IPO is listed or settled; market data is final.")
	case errors.Is(err, ErrCorrectionNotLatest):
		return httpx.Problem(http.StatusConflict, codeCorrectionLatest, "Only the current GMP entry can be corrected, once.")
	case errors.Is(err, ErrNotFound):
		return httpx.Problem(http.StatusNotFound, "not_found", "The IPO was not found.")
	case errors.Is(err, ErrBadCursor):
		return validationFailed("query.cursor", "not a valid cursor")
	}
	return httpx.Problem(http.StatusInternalServerError, "internal", "An unexpected error occurred.")
}

func fail(ctx context.Context, s *Service, err error) error {
	p := problemFor(err)
	var se huma.StatusError
	if errors.As(p, &se) && se.GetStatus() >= http.StatusInternalServerError {
		s.d.Log.ErrorContext(ctx, "ipomarket: unexpected error", slog.Any("err", err))
	}
	return p
}

// ready refuses an operation on an API built without a service (openapi command, contract walks).
func ready(s *Service) error {
	if s == nil {
		return httpx.Problem(http.StatusServiceUnavailable, codeNotConfigured, "The IPO market service is not configured.")
	}
	return nil
}
