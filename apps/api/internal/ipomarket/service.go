package ipomarket

import (
	"context"
	"log/slog"

	"github.com/google/uuid"

	"github.com/NandanMaheta/swastik/apps/api/internal/ipos"
	"github.com/NandanMaheta/swastik/apps/api/internal/platform/clock"
	"github.com/NandanMaheta/swastik/apps/api/internal/platform/db"
)

// IPOReader is the 008 read capability the module needs; satisfied by *ipos.Service.
type IPOReader interface {
	Get(ctx context.Context, org, id uuid.UUID) (ipos.IPO, error)
	GetMany(ctx context.Context, org uuid.UUID, ids []uuid.UUID) (map[uuid.UUID]ipos.IPO, error)
}

// Deps are the collaborators of the Service.
type Deps struct {
	Tx   db.TxRunner
	IPOs IPOReader
	Now  clock.Func
	Log  *slog.Logger
}

// Service records and reads IPO market data.
type Service struct {
	d     Deps
	store *store
}

// NewService builds the Service.
func NewService(d Deps) *Service { return &Service{d: d, store: &store{}} }
