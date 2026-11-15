package auth

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/uuid"

	"github.com/NandanMaheta/swastik/apps/api/internal/platform/audit"
)

const (
	roleAdmin  = "admin"
	roleClient = "client"
)

// CreateClient creates a client in pending_verification (FR-050). The password is hashed before
// the transaction is joined, so a caller's transaction is never held open during hashing.
func (s *Service) CreateClient(ctx context.Context, in NewClient, by audit.Actor) (uuid.UUID, error) {
	email, err := NormalizeEmail(in.Email)
	if err != nil {
		return uuid.Nil, err
	}
	mobile, err := NormalizeMobile(in.Mobile)
	if err != nil {
		return uuid.Nil, err
	}
	if err := CheckPolicy(in.Password, email, mobile); err != nil {
		return uuid.Nil, err
	}
	phc, err := s.hasher.Hash(ctx, NormalizePassword(in.Password))
	if err != nil {
		return uuid.Nil, fmt.Errorf("auth: hash password: %w", err)
	}
	var id uuid.UUID
	err = s.inTx(ctx, func(ctx context.Context) error {
		u, err := s.store.CreateUser(ctx, NewUser{
			OrgID: in.OrgID, Role: roleClient, Status: StatusPendingVerification, Name: strings.TrimSpace(in.Name),
			Email: email, Mobile: mobile, PasswordHash: phc, Now: s.now(),
		})
		if err != nil {
			return fmt.Errorf("auth: create user: %w", err)
		}
		id = u.ID
		return s.writeAudit(ctx, in.OrgID, by, u.ID, ActionUserCreated, nil,
			UserCreatedAfter{Role: roleClient, Status: StatusPendingVerification, Email: email, Mobile: mobile})
	})
	if err != nil {
		return uuid.Nil, err
	}
	return id, nil
}

// MarkEmailVerified records a verified email and returns the resulting status (FR-051).
func (s *Service) MarkEmailVerified(ctx context.Context, id uuid.UUID, by audit.Actor) (Status, error) {
	return s.markVerified(ctx, id, KindEmail, ActionUserEmailVerified, by)
}

// MarkMobileVerified records a verified mobile and returns the resulting status (FR-051).
func (s *Service) MarkMobileVerified(ctx context.Context, id uuid.UUID, by audit.Actor) (Status, error) {
	return s.markVerified(ctx, id, KindMobile, ActionUserMobileVerified, by)
}

// markVerified stamps one contact and, once both are verified, moves pending_verification to
// pending_approval. It is idempotent: a repeat keeps the first timestamp and writes nothing.
func (s *Service) markVerified(ctx context.Context, id uuid.UUID, kind IdentifierKind, action string, by audit.Actor) (Status, error) {
	var out Status
	err := s.inTx(ctx, func(ctx context.Context) error {
		u, err := s.store.LockUser(ctx, id)
		if err != nil {
			return fmt.Errorf("auth: lock user: %w", err)
		}
		out = u.Status
		before, after := StatusBefore{Status: u.Status}, StatusAfter{Status: u.Status}
		now := s.now()
		changed, err := s.store.MarkVerified(ctx, id, kind, now)
		if err != nil {
			return fmt.Errorf("auth: mark verified: %w", err)
		}
		if !changed {
			return nil
		}
		cur, err := s.store.GetUser(ctx, id)
		if err != nil {
			return fmt.Errorf("auth: read user: %w", err)
		}
		if both := cur.EmailVerifiedAt != nil && cur.MobileVerifiedAt != nil; both {
			switch {
			case u.Status == StatusPendingVerification:
				out = StatusPendingApproval
				after.Status = out
				if err := s.store.SetStatus(ctx, id, out, "", now); err != nil {
					return fmt.Errorf("auth: set status: %w", err)
				}
			case u.Status == StatusDisabled && u.StatusBeforeDisabled == StatusPendingVerification:
				// Stay disabled, but remember the status a later Enable must restore.
				if err := s.store.SetStatus(ctx, id, StatusDisabled, StatusPendingApproval, now); err != nil {
					return fmt.Errorf("auth: set status: %w", err)
				}
				before.StatusBeforeDisabled, after.StatusBeforeDisabled = u.StatusBeforeDisabled, StatusPendingApproval
			}
		}
		return s.writeAudit(ctx, u.OrgID, by, id, action, before, after)
	})
	if err != nil {
		return "", err
	}
	return out, nil
}

// Approve moves a pending_approval user to active (FR-052).
func (s *Service) Approve(ctx context.Context, id uuid.UUID, by audit.Actor) error {
	return s.inTx(ctx, func(ctx context.Context) error {
		u, err := s.store.LockUser(ctx, id)
		if err != nil {
			return fmt.Errorf("auth: lock user: %w", err)
		}
		if u.Status != StatusPendingApproval {
			return ErrInvalidTransition
		}
		if err := s.store.SetStatus(ctx, id, StatusActive, "", s.now()); err != nil {
			return fmt.Errorf("auth: set status: %w", err)
		}
		return s.writeAudit(ctx, u.OrgID, by, id, ActionUserStatusChanged,
			StatusBefore{Status: u.Status}, StatusAfter{Status: StatusActive})
	})
}

// Disable disables a user and ends all their sessions (FR-052). The last active admin cannot be
// disabled (D-19).
func (s *Service) Disable(ctx context.Context, id uuid.UUID, by audit.Actor) error {
	// The role decides which rows to lock: all admins in id order for an admin (the last-admin
	// guard), otherwise just the user. Roles never change, so the unlocked read is safe.
	pre, err := s.store.GetUser(ctx, id)
	if err != nil {
		return fmt.Errorf("auth: read user: %w", err)
	}
	return s.inTx(ctx, func(ctx context.Context) error {
		u, err := s.lockForDisable(ctx, pre)
		if err != nil {
			return err
		}
		if u.Status == StatusDisabled {
			return ErrInvalidTransition
		}
		now := s.now()
		if err := s.store.SetStatus(ctx, id, StatusDisabled, u.Status, now); err != nil {
			return fmt.Errorf("auth: set status: %w", err)
		}
		ended, err := s.store.EndUserSessions(ctx, id, uuid.Nil, "disabled", now)
		if err != nil {
			return fmt.Errorf("auth: end sessions: %w", err)
		}
		return s.writeAudit(ctx, u.OrgID, by, id, ActionUserStatusChanged,
			StatusBefore{Status: u.Status}, StatusAfter{Status: StatusDisabled, EndedSessionIDs: ended})
	})
}

// lockForDisable locks the user (or every admin of the org) and applies the last-admin guard.
func (s *Service) lockForDisable(ctx context.Context, pre UserRow) (UserRow, error) {
	if pre.Role != roleAdmin {
		u, err := s.store.LockUser(ctx, pre.ID)
		if err != nil {
			return UserRow{}, fmt.Errorf("auth: lock user: %w", err)
		}
		return u, nil
	}
	admins, err := s.store.LockAdmins(ctx, pre.OrgID)
	if err != nil {
		return UserRow{}, fmt.Errorf("auth: lock admins: %w", err)
	}
	var target UserRow
	othersActive := 0
	for _, a := range admins {
		switch {
		case a.ID == pre.ID:
			target = a
		case a.Status == StatusActive:
			othersActive++
		}
	}
	if target.ID == uuid.Nil {
		return UserRow{}, ErrUserNotFound
	}
	if target.Status == StatusActive && othersActive == 0 {
		return UserRow{}, ErrLastAdmin
	}
	return target, nil
}

// Enable restores the status a disabled user had before (FR-052). Ended sessions stay ended.
func (s *Service) Enable(ctx context.Context, id uuid.UUID, by audit.Actor) error {
	return s.inTx(ctx, func(ctx context.Context) error {
		u, err := s.store.LockUser(ctx, id)
		if err != nil {
			return fmt.Errorf("auth: lock user: %w", err)
		}
		if u.Status != StatusDisabled {
			return ErrInvalidTransition
		}
		restored := u.StatusBeforeDisabled
		if restored == "" {
			restored = StatusPendingVerification // never straight to active
		}
		if err := s.store.SetStatus(ctx, id, restored, "", s.now()); err != nil {
			return fmt.Errorf("auth: set status: %w", err)
		}
		return s.writeAudit(ctx, u.OrgID, by, id, ActionUserStatusChanged,
			StatusBefore{Status: u.Status}, StatusAfter{Status: restored})
	})
}

// GetUser returns the read-only view of a user; it never carries secrets.
func (s *Service) GetUser(ctx context.Context, id uuid.UUID) (UserView, error) {
	u, err := s.store.GetUser(ctx, id)
	if err != nil {
		return UserView{}, fmt.Errorf("auth: read user: %w", err)
	}
	return UserView{
		ID: u.ID, OrgID: u.OrgID, Name: u.Name, Email: u.Email, Mobile: u.Mobile, Role: u.Role, Status: u.Status,
		EmailVerified: u.EmailVerifiedAt != nil, MobileVerified: u.MobileVerifiedAt != nil,
		CreatedAt: u.CreatedAt, LastSignInAt: u.LastSignInAt,
	}, nil
}
