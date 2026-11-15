package ipos

import (
	"errors"
	"net/http"

	"github.com/danielgtaylor/huma/v2"

	"github.com/NandanMaheta/swastik/apps/api/internal/platform/httpx"
)

// codeNotConfigured answers an operation called on an API built without a service.
const codeNotConfigured = "ipo.not_configured"

// problemFor maps a service error to an RFC 9457 problem (contracts/error-codes.md). Unknown
// errors become a bare 500 that reveals nothing.
func problemFor(err error) error {
	var (
		ve *ValidationError
		re *RejectedError
	)
	switch {
	case errors.As(err, &ve):
		errs := make([]*huma.ErrorDetail, 0, len(ve.Issues))
		for _, is := range ve.Issues {
			errs = append(errs, locatedError("body."+is.Field, is.Message))
		}
		return withErrors(httpx.Problem(http.StatusUnprocessableEntity, ve.Code, validationDetail(ve.Code)), errs...)
	case errors.As(err, &re):
		return httpx.Problem(http.StatusConflict, re.Code, re.Detail)
	case errors.Is(err, ErrStaleVersion):
		return httpx.Problem(http.StatusConflict, "ipo.stale_version", "The IPO was changed by someone else; reload and try again.")
	case errors.Is(err, ErrNoChange):
		return httpx.Problem(http.StatusConflict, "ipo.no_change", "The IPO is already in the requested state.")
	case errors.Is(err, ErrPublishedNotDeletable):
		return httpx.Problem(http.StatusConflict, "ipo.published_not_deletable", "A published IPO cannot be deleted; unpublish it instead.")
	case errors.Is(err, ErrNotFound):
		return httpx.Problem(http.StatusNotFound, "not_found", "The IPO was not found.")
	case errors.Is(err, ErrBadCursor):
		return withErrors(httpx.Problem(http.StatusUnprocessableEntity, "validation_failed", "The request is not valid."),
			locatedError("query.cursor", "not a valid cursor"))
	}
	return httpx.Problem(http.StatusInternalServerError, "internal", "An unexpected error occurred.")
}

func validationDetail(code string) string {
	switch code {
	case "ipo.sme_not_allowed":
		return "SME segments are not supported; only NSE and BSE mainboard IPOs."
	case "ipo.invalid_segment":
		return "The segments must be NSE_MAINBOARD, BSE_MAINBOARD or both, without repeats."
	case "ipo.date_order":
		return "The dates are out of order."
	case "ipo.publish_incomplete":
		return "The IPO is missing what it needs to be published."
	case codeKeyReused:
		return "This Idempotency-Key was already used for a different request; use a new key."
	default:
		return "A value is not valid."
	}
}

func locatedError(location, message string) *huma.ErrorDetail {
	return &huma.ErrorDetail{Location: location, Message: message}
}

// withErrors adds located error items to a problem built by httpx.Problem.
func withErrors(p error, errs ...*huma.ErrorDetail) error {
	var em *httpx.ErrorModel
	if errors.As(p, &em) {
		em.Errors = append(em.Errors, errs...)
	}
	return p
}
