package otp

import "github.com/NandanMaheta/swastik/apps/api/internal/platform/db"

// Store is the persistence of the module; store.go is the only file allowed to use pgx and dbgen
// (depguard otp-pgx-only-in-store). Methods arrive with slices S08 and S09.
type Store interface{}

// NewPGStore returns the PostgreSQL Store over the transaction runner.
func NewPGStore(_ db.TxRunner) Store { panic(errNotImplemented) }
