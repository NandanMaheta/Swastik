// Package observe wires error reporting (Sentry) for the API. Empty DSN means off.
package observe

import (
	"errors"
	"log/slog"
)

var errNotImplemented = errors.New("observe: not implemented")

// Init configures error reporting. Stub until 027 T017.
func Init(dsn, environment, version string) (func(), error) {
	_, _, _ = dsn, environment, version
	return func() {}, errNotImplemented
}

// NewHandler wraps next so ERROR records are forwarded. Stub until 027 T017.
func NewHandler(next slog.Handler) slog.Handler {
	return next
}
