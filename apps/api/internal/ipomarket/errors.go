package ipomarket

import "errors"

// Sentinel errors; HTTP mapping in contracts/http-api.md.
var (
	ErrNotFound            = errors.New("ipomarket: not found")
	ErrNotPublishedYet     = errors.New("ipomarket: IPO never published")
	ErrFrozen              = errors.New("ipomarket: IPO listed or settled")
	ErrCorrectionNotLatest = errors.New("ipomarket: correction target is not the current entry")
	ErrKeyReused           = errors.New("ipomarket: idempotency key reused")

	errNotImplemented = errors.New("ipomarket: not implemented")
)

// FieldIssue is one field-level validation problem.
type FieldIssue struct{ Field, Message string }

// ValidationError Code is ipomarket.invalid_value.
type ValidationError struct {
	Code   string
	Issues []FieldIssue
}

func (e *ValidationError) Error() string { return "ipomarket: validation failed: " + e.Code }
