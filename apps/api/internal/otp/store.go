package otp

import "github.com/NandanMaheta/swastik/apps/api/internal/platform/db"

// NewPGStore returns the PostgreSQL Store over the transaction runner. store.go is the only file
// allowed to use pgx and dbgen (depguard otp-pgx-only-in-store); the Store contract itself is in
// store_types.go.
func NewPGStore(_ db.TxRunner) Store { panic(errNotImplemented) }
