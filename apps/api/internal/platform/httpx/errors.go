package httpx

import (
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/danielgtaylor/huma/v2"
)

// problemTypePrefix turns a stable code into the RFC 9457 type URI.
const problemTypePrefix = "urn:swastik:problem:"

// ErrorModel is the RFC 9457 problem returned by every non-2xx response. It is Huma's error model
// plus a stable, language-neutral Code that UIs translate. The OpenAPI schema name stays
// "ErrorModel", so the change is additive.
type ErrorModel struct {
	huma.ErrorModel
	Code string `json:"code" doc:"Stable, language-neutral problem code; UIs translate it." example:"validation_failed"`
	// RetryAfterSeconds is set by ProblemRetry together with the Retry-After header.
	RetryAfterSeconds int `json:"retry_after_seconds,omitempty" minimum:"1" doc:"Seconds to wait before retrying; same value as the Retry-After header." example:"60"`
}

// Problem builds a problem with an explicit code. It is a huma.StatusError, so handlers can
// return it directly. The type is derived from the code.
func Problem(status int, code, detail string) error {
	return &ErrorModel{
		ErrorModel: huma.ErrorModel{
			Type:   problemTypePrefix + code,
			Title:  http.StatusText(status),
			Status: status,
			Detail: detail,
		},
		Code: code,
	}
}

// ProblemRetry is Problem for a refusal that clears with time: the response carries Retry-After
// (whole seconds, rounded up) and retry_after_seconds. It implements huma.HeadersError.
func ProblemRetry(status int, code, detail string, after time.Duration) error {
	secs := int((after + time.Second - 1) / time.Second)
	if after <= 0 || secs < 1 {
		secs = 1
	}
	m := Problem(status, code, detail).(*ErrorModel)
	m.RetryAfterSeconds = secs
	h := http.Header{}
	h.Set("Retry-After", strconv.Itoa(secs))
	return &retryError{ErrorModel: m, headers: h}
}

// retryError is an ErrorModel that also sets response headers (huma.HeadersError).
type retryError struct {
	*ErrorModel
	headers http.Header
}

// GetHeaders implements huma.HeadersError.
func (e *retryError) GetHeaders() http.Header { return e.headers }

var installOnce sync.Once

// InstallErrors makes every Huma-generated error (validation, parse, 404, ...) a problem with a
// code, and drops ErrorDetail.Value so submitted data (passwords, tokens) is never echoed. Errors
// with status 500 or above carry no details. Safe to call repeatedly.
func InstallErrors() {
	installOnce.Do(func() {
		huma.NewError = newError
		huma.NewErrorWithContext = func(_ huma.Context, status int, msg string, errs ...error) huma.StatusError {
			return newError(status, msg, errs...)
		}
	})
}

func newError(status int, msg string, errs ...error) huma.StatusError {
	code := defaultCode(status)
	m := &ErrorModel{
		ErrorModel: huma.ErrorModel{
			Type:   problemTypePrefix + code,
			Title:  http.StatusText(status),
			Status: status,
			Detail: msg,
		},
		Code: code,
	}
	if status >= http.StatusInternalServerError {
		// Never reveal the cause of a server error (connection strings, SQL, hosts).
		if status == http.StatusInternalServerError {
			m.Detail = "An unexpected error occurred."
		}
		return m
	}
	for _, err := range errs {
		if err == nil {
			continue
		}
		var d huma.ErrorDetail
		if det, ok := err.(huma.ErrorDetailer); ok && det.ErrorDetail() != nil {
			d = *det.ErrorDetail()
		} else {
			d.Message = err.Error()
		}
		m.Errors = append(m.Errors, &huma.ErrorDetail{Message: d.Message, Location: d.Location}) // Value dropped on purpose
	}
	return m
}

func defaultCode(status int) string {
	switch status {
	case http.StatusBadRequest:
		return "bad_request"
	case http.StatusUnauthorized:
		return "auth.unauthenticated"
	case http.StatusForbidden:
		return "auth.forbidden"
	case http.StatusNotFound:
		return "not_found"
	case http.StatusUnsupportedMediaType:
		return "unsupported_media_type"
	case http.StatusUnprocessableEntity:
		return "validation_failed"
	case http.StatusTooManyRequests:
		return "rate_limited"
	case http.StatusInternalServerError:
		return "internal"
	}
	// Other statuses: a stable slug of the status text, for example "method_not_allowed".
	text := strings.ToLower(http.StatusText(status))
	if text == "" {
		return "error"
	}
	return strings.NewReplacer(" ", "_", "-", "_", "'", "").Replace(text)
}
