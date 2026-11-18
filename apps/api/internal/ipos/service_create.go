package ipos

import (
	"context"

	"github.com/google/uuid"

	"github.com/NandanMaheta/swastik/apps/api/internal/platform/audit"
)

// Create validates and stores a draft, schedules its lifecycle steps and audits it, in one
// transaction. A repeated idemKey returns the IPO it first created with Replayed set (FR-007).
func (s *Service) Create(ctx context.Context, by audit.Actor, org uuid.UUID, in Draft, idemKey string) (Result, error) {
	if err := validateDraft(in); err != nil {
		return Result{}, err
	}
	hash := requestHash("create", facts(in))
	var res Result
	err := s.inTx(ctx, func(ctx context.Context) error {
		now := s.d.Now()
		i, created, err := s.store.InsertIPOHashed(ctx, org, in, optKey(idemKey), hash, now)
		if err != nil {
			return err
		}
		if !created {
			if stored, err := s.store.GetCreateRequestHash(ctx, org, idemKey); err != nil {
				return err
			} else if stored != "" && stored != hash {
				return keyReused()
			}
			i, err = s.store.GetIPOByCreateKey(ctx, org, idemKey)
			if err != nil {
				return err
			}
			res = Result{IPO: i, Warnings: warnings(i), Replayed: true}
			return nil
		}
		if err := s.syncSteps(ctx, org, i.ID, Dates{}, i.Dates, now); err != nil {
			return err
		}
		if err := s.writeAudit(ctx, by, org, i.ID, actCreated, nil, withKey(snapshot(i), idemKey, hash)); err != nil {
			return err
		}
		res = Result{IPO: i, Warnings: warnings(i)}
		return nil
	})
	if err != nil {
		return Result{}, err
	}
	return res, nil
}
