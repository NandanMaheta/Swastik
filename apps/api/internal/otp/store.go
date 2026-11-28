package otp

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/NandanMaheta/swastik/apps/api/internal/platform/db"
	"github.com/NandanMaheta/swastik/apps/api/internal/platform/db/dbgen"
	"github.com/NandanMaheta/swastik/apps/api/internal/platform/istdate"
)

// pgStore is the PostgreSQL Store. store.go is the only file allowed to use pgx and dbgen
// (depguard otp-pgx-only-in-store); the Store contract itself is in store_types.go. Reads and
// plain writes use the transaction in ctx when there is one and the pool otherwise; the methods
// documented "requires a tx" go through db.MustTx and return db.ErrNoTx.
type pgStore struct{ txr db.TxRunner }

// NewPGStore returns the PostgreSQL Store over the transaction runner.
func NewPGStore(txr db.TxRunner) Store { return &pgStore{txr: txr} }

var _ Store = (*pgStore)(nil)

// Constraint names of migration 00006 that carry a domain meaning.
const (
	constraintOpenFlow  = "otp_verifications_open_uq"
	constraintOpenDecoy = "otp_verifications_open_decoy_uq"
	constraintLiveCode  = "otp_email_codes_live_uq"
)

func (s *pgStore) q(ctx context.Context) *dbgen.Queries { return dbgen.New(s.txr.Conn(ctx)) }

func (s *pgStore) qTx(ctx context.Context) (*dbgen.Queries, error) {
	tx, err := db.MustTx(ctx)
	if err != nil {
		return nil, fmt.Errorf("otp: %w", err)
	}
	return dbgen.New(tx), nil
}

func uniqueViolation(err error) string {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return pgErr.ConstraintName
	}
	return ""
}

func nullText(s string) pgtype.Text { return pgtype.Text{String: s, Valid: s != ""} }

func nullUUID(id uuid.UUID) uuid.NullUUID { return uuid.NullUUID{UUID: id, Valid: id != uuid.Nil} }

func pgDate(d istdate.Date) pgtype.Date {
	return pgtype.Date{Time: time.Date(d.Year, d.Month, d.Day, 0, 0, 0, 0, time.UTC), Valid: true}
}

func verificationRow(v dbgen.OtpVerification) VerificationRow {
	return VerificationRow{
		ID: v.ID, OrgID: v.OrgID, UserID: v.UserID.UUID, Purpose: Purpose(v.Purpose),
		Email: v.Email.String, Mobile: v.Mobile.String,
		EmailDoneAt: db.TimePtr(v.EmailDoneAt), MobileDoneAt: db.TimePtr(v.MobileDoneAt),
		IdentifierKey: v.IdentifierKey, ResetTokenHash: v.ResetTokenHash, ResetTokenExpiresAt: db.TimePtr(v.ResetTokenExpiresAt),
		FinishedAt: db.TimePtr(v.FinishedAt), CancelledAt: db.TimePtr(v.CancelledAt), CancelReason: v.CancelReason.String,
		CreatedAt: db.Time(v.CreatedAt), ExpiresAt: db.Time(v.ExpiresAt), UpdatedAt: db.Time(v.UpdatedAt),
	}
}

func codeRow(c dbgen.OtpEmailCode) CodeRow {
	return CodeRow{
		ID: c.ID, OrgID: c.OrgID, VerificationID: c.VerificationID, Digest: c.CodeDigest,
		IssuedAt: db.Time(c.IssuedAt), ExpiresAt: db.Time(c.ExpiresAt), WrongAttempts: int(c.WrongAttempts),
		OutboxKey: c.OutboxKey.String, EndedAt: db.TimePtr(c.EndedAt), EndReason: c.EndReason.String,
	}
}

// oneVerification maps pgx.ErrNoRows to ErrNotFound.
func oneVerification(v dbgen.OtpVerification, err error, op string) (VerificationRow, error) {
	if errors.Is(err, pgx.ErrNoRows) {
		return VerificationRow{}, ErrNotFound
	}
	if err != nil {
		return VerificationRow{}, fmt.Errorf("otp: %s: %w", op, err)
	}
	return verificationRow(v), nil
}

// affected turns a row count into ErrNotFound when nothing matched.
func affected(n int64, err error, op string) error {
	if err != nil {
		return fmt.Errorf("otp: %s: %w", op, err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// ---- verifications ----

func (s *pgStore) InsertVerification(ctx context.Context, in NewVerification) (VerificationRow, error) {
	v, err := s.q(ctx).InsertOtpVerification(ctx, dbgen.InsertOtpVerificationParams{
		OrgID: in.OrgID, UserID: nullUUID(in.UserID), Purpose: string(in.Purpose), HandleHash: in.HandleHash,
		Email: nullText(in.Email), Mobile: nullText(in.Mobile), IdentifierKey: in.IdentifierKey, Now: db.Timestamptz(in.Now), ExpiresAt: db.Timestamptz(in.ExpiresAt),
	})
	if c := uniqueViolation(err); c == constraintOpenFlow || c == constraintOpenDecoy {
		return VerificationRow{}, ErrOpenFlowExists
	}
	if err != nil {
		return VerificationRow{}, fmt.Errorf("otp: insert verification: %w", err)
	}
	return verificationRow(v), nil
}

func (s *pgStore) GetVerification(ctx context.Context, org, id uuid.UUID) (VerificationRow, error) {
	v, err := s.q(ctx).GetOtpVerification(ctx, dbgen.GetOtpVerificationParams{ID: id, OrgID: org})
	return oneVerification(v, err, "get verification")
}

func (s *pgStore) GetVerificationByHandle(ctx context.Context, org uuid.UUID, handleHash []byte) (VerificationRow, error) {
	v, err := s.q(ctx).GetOtpVerificationByHandle(ctx, dbgen.GetOtpVerificationByHandleParams{OrgID: org, HandleHash: handleHash})
	return oneVerification(v, err, "get verification by handle")
}

func (s *pgStore) LockVerificationByHandle(ctx context.Context, org uuid.UUID, handleHash []byte) (VerificationRow, error) {
	q, err := s.qTx(ctx)
	if err != nil {
		return VerificationRow{}, err
	}
	v, err := q.LockOtpVerificationByHandle(ctx, dbgen.LockOtpVerificationByHandleParams{OrgID: org, HandleHash: handleHash})
	return oneVerification(v, err, "lock verification by handle")
}

func (s *pgStore) LockVerification(ctx context.Context, org, id uuid.UUID) (VerificationRow, error) {
	q, err := s.qTx(ctx)
	if err != nil {
		return VerificationRow{}, err
	}
	v, err := q.LockOtpVerification(ctx, dbgen.LockOtpVerificationParams{ID: id, OrgID: org})
	return oneVerification(v, err, "lock verification")
}

func (s *pgStore) LockOpenVerification(ctx context.Context, org, user uuid.UUID, p Purpose) (VerificationRow, error) {
	q, err := s.qTx(ctx)
	if err != nil {
		return VerificationRow{}, err
	}
	v, err := q.LockOpenOtpVerification(ctx, dbgen.LockOpenOtpVerificationParams{OrgID: org, UserID: nullUUID(user), Purpose: string(p)})
	return oneVerification(v, err, "lock open verification")
}

func (s *pgStore) LockOpenResetFlow(ctx context.Context, org, user uuid.UUID, identifierKey []byte) (VerificationRow, error) {
	q, err := s.qTx(ctx)
	if err != nil {
		return VerificationRow{}, err
	}
	v, err := q.LockOpenOtpResetFlow(ctx, dbgen.LockOpenOtpResetFlowParams{OrgID: org, IdentifierKey: identifierKey, UserID: nullUUID(user)})
	return oneVerification(v, err, "lock open reset flow")
}

func (s *pgStore) MarkContactDone(ctx context.Context, org, id uuid.UUID, c ContactKind, now time.Time) error {
	q := s.q(ctx)
	if c == ContactMobile {
		n, err := q.MarkOtpMobileDone(ctx, dbgen.MarkOtpMobileDoneParams{ID: id, OrgID: org, Now: db.Timestamptz(now)})
		return affected(n, err, "mark mobile done")
	}
	n, err := q.MarkOtpEmailDone(ctx, dbgen.MarkOtpEmailDoneParams{ID: id, OrgID: org, Now: db.Timestamptz(now)})
	return affected(n, err, "mark email done")
}

func (s *pgStore) FinishVerification(ctx context.Context, org, id uuid.UUID, now time.Time) error {
	n, err := s.q(ctx).FinishOtpVerification(ctx, dbgen.FinishOtpVerificationParams{ID: id, OrgID: org, Now: db.Timestamptz(now)})
	return affected(n, err, "finish verification")
}

func (s *pgStore) CancelVerification(ctx context.Context, org, id uuid.UUID, reason string, now time.Time) error {
	n, err := s.q(ctx).CancelOtpVerification(ctx, dbgen.CancelOtpVerificationParams{
		ID: id, OrgID: org, Reason: db.Text(reason), Now: db.Timestamptz(now)})
	return affected(n, err, "cancel verification")
}

func (s *pgStore) SetResetGrant(ctx context.Context, org, id uuid.UUID, tokenHash []byte, expires, now time.Time) error {
	n, err := s.q(ctx).SetOtpResetGrant(ctx, dbgen.SetOtpResetGrantParams{
		ID: id, OrgID: org, TokenHash: tokenHash, TokenExpiresAt: db.Timestamptz(expires), Now: db.Timestamptz(now)})
	return affected(n, err, "set reset grant")
}

// ---- codes ----

func (s *pgStore) InsertCode(ctx context.Context, in NewCode) (CodeRow, error) {
	c, err := s.q(ctx).InsertOtpCode(ctx, dbgen.InsertOtpCodeParams{
		ID: in.ID, OrgID: in.OrgID, VerificationID: in.VerificationID, CodeDigest: in.Digest,
		IssuedAt: db.Timestamptz(in.IssuedAt), ExpiresAt: db.Timestamptz(in.ExpiresAt), OutboxKey: nullText(in.OutboxKey),
	})
	if uniqueViolation(err) == constraintLiveCode {
		return CodeRow{}, ErrLiveCodeExists
	}
	if err != nil {
		return CodeRow{}, fmt.Errorf("otp: insert code: %w", err)
	}
	return codeRow(c), nil
}

func (s *pgStore) GetLiveCode(ctx context.Context, org, verificationID uuid.UUID) (CodeRow, error) {
	c, err := s.q(ctx).GetLiveOtpCode(ctx, dbgen.GetLiveOtpCodeParams{OrgID: org, VerificationID: verificationID})
	if errors.Is(err, pgx.ErrNoRows) {
		return CodeRow{}, ErrNoLiveCode
	}
	if err != nil {
		return CodeRow{}, fmt.Errorf("otp: get live code: %w", err)
	}
	return codeRow(c), nil
}

func (s *pgStore) LockLiveCode(ctx context.Context, org, verificationID uuid.UUID) (CodeRow, error) {
	q, err := s.qTx(ctx)
	if err != nil {
		return CodeRow{}, err
	}
	c, err := q.LockLiveOtpCode(ctx, dbgen.LockLiveOtpCodeParams{OrgID: org, VerificationID: verificationID})
	if errors.Is(err, pgx.ErrNoRows) {
		return CodeRow{}, ErrNoLiveCode
	}
	if err != nil {
		return CodeRow{}, fmt.Errorf("otp: lock live code: %w", err)
	}
	return codeRow(c), nil
}

func (s *pgStore) EndLiveCode(ctx context.Context, org, verificationID uuid.UUID, reason string, now time.Time) (CodeRow, error) {
	c, err := s.q(ctx).EndLiveOtpCode(ctx, dbgen.EndLiveOtpCodeParams{
		OrgID: org, VerificationID: verificationID, Reason: db.Text(reason), Now: db.Timestamptz(now)})
	if errors.Is(err, pgx.ErrNoRows) {
		return CodeRow{}, ErrNoLiveCode
	}
	if err != nil {
		return CodeRow{}, fmt.Errorf("otp: end live code: %w", err)
	}
	return codeRow(c), nil
}

func (s *pgStore) AddWrongAttempt(ctx context.Context, org, codeID uuid.UUID, _ time.Time) (int, error) {
	n, err := s.q(ctx).AddOtpWrongAttempt(ctx, dbgen.AddOtpWrongAttemptParams{ID: codeID, OrgID: org, MaxAttempts: MaxWrongAttempts})
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, ErrNoLiveCode
	}
	if err != nil {
		return 0, fmt.Errorf("otp: add wrong attempt: %w", err)
	}
	return int(n), nil
}

// ---- proofs ----

func (s *pgStore) InsertProof(ctx context.Context, org uuid.UUID, fingerprint []byte, verificationID uuid.UUID, now time.Time) (bool, error) {
	n, err := s.q(ctx).InsertOtpProof(ctx, dbgen.InsertOtpProofParams{
		Fingerprint: fingerprint, OrgID: org, VerificationID: verificationID, Now: db.Timestamptz(now)})
	if err != nil {
		return false, fmt.Errorf("otp: insert proof: %w", err)
	}
	return n == 1, nil
}

// ---- limits ----

var scopeOrder = map[LimitScope]int{ScopeSendContact: 0, ScopeSendUser: 1, ScopeSendIP: 2, ScopeCheckIP: 3}

func (s *pgStore) LockLimits(ctx context.Context, org uuid.UUID, keys []LimitKey) ([]LimitRow, error) {
	q, err := s.qTx(ctx)
	if err != nil {
		return nil, err
	}
	sorted := slices.Clone(keys)
	slices.SortFunc(sorted, func(a, b LimitKey) int {
		if c := scopeOrder[a.Scope] - scopeOrder[b.Scope]; c != 0 {
			return c
		}
		return slices.Compare(a.Subject, b.Subject)
	})
	out := make([]LimitRow, 0, len(sorted))
	for _, k := range sorted {
		if err := q.EnsureOtpLimit(ctx, dbgen.EnsureOtpLimitParams{OrgID: org, Scope: string(k.Scope), Subject: k.Subject}); err != nil {
			return nil, fmt.Errorf("otp: ensure limit: %w", err)
		}
		row, err := q.LockOtpLimit(ctx, dbgen.LockOtpLimitParams{OrgID: org, Scope: string(k.Scope), Subject: k.Subject})
		if err != nil {
			return nil, fmt.Errorf("otp: lock limit: %w", err)
		}
		events := make([]time.Time, 0, len(row.Events))
		for _, e := range row.Events {
			events = append(events, db.Time(e))
		}
		out = append(out, LimitRow{Key: k, Events: events, UpdatedAt: db.Time(row.UpdatedAt)})
	}
	return out, nil
}

func (s *pgStore) SaveLimit(ctx context.Context, org uuid.UUID, key LimitKey, events []time.Time, now time.Time) error {
	ev := make([]pgtype.Timestamptz, 0, len(events))
	for _, e := range events {
		ev = append(ev, db.Timestamptz(e))
	}
	n, err := s.q(ctx).SaveOtpLimit(ctx, dbgen.SaveOtpLimitParams{
		OrgID: org, Scope: string(key.Scope), Subject: key.Subject, Events: ev, Now: db.Timestamptz(now)})
	return affected(n, err, "save limit")
}

// ---- daily counts ----

func (s *pgStore) IncrementCount(ctx context.Context, org uuid.UUID, day istdate.Date, m Metric, _ time.Time) error {
	if err := s.q(ctx).IncrementOtpCount(ctx, dbgen.IncrementOtpCountParams{OrgID: org, Day: pgDate(day), Metric: string(m)}); err != nil {
		return fmt.Errorf("otp: increment count: %w", err)
	}
	return nil
}

func (s *pgStore) GetCounts(ctx context.Context, org uuid.UUID, day istdate.Date) (DailyCounts, error) {
	rows, err := s.q(ctx).GetOtpCounts(ctx, dbgen.GetOtpCountsParams{OrgID: org, Day: pgDate(day)})
	if err != nil {
		return DailyCounts{}, fmt.Errorf("otp: get counts: %w", err)
	}
	var c DailyCounts
	for _, r := range rows {
		n := int(r.Count)
		switch Metric(r.Metric) {
		case MetricEmailSent:
			c.EmailSent = n
		case MetricEmailFailed:
			c.EmailFailed = n
		case MetricLimitRefused:
			c.LimitRefused = n
		case MetricProofAccepted:
			c.ProofAccepted = n
		case MetricProofRefused:
			c.ProofRefused = n
		}
	}
	return c, nil
}

// ---- purges ----

func (s *pgStore) PurgeVerifications(ctx context.Context, org uuid.UUID, cutoff time.Time, limit int) (int, error) {
	n, err := s.q(ctx).PurgeOtpVerifications(ctx, dbgen.PurgeOtpVerificationsParams{OrgID: org, Cutoff: db.Timestamptz(cutoff), RowLimit: batch(limit)})
	return purged(n, err, "verifications")
}

func (s *pgStore) PurgeProofs(ctx context.Context, org uuid.UUID, cutoff time.Time, limit int) (int, error) {
	n, err := s.q(ctx).PurgeOtpProofs(ctx, dbgen.PurgeOtpProofsParams{OrgID: org, Cutoff: db.Timestamptz(cutoff), RowLimit: batch(limit)})
	return purged(n, err, "proofs")
}

func (s *pgStore) PurgeLimits(ctx context.Context, org uuid.UUID, cutoff time.Time, limit int) (int, error) {
	n, err := s.q(ctx).PurgeOtpLimits(ctx, dbgen.PurgeOtpLimitsParams{OrgID: org, Cutoff: db.Timestamptz(cutoff), RowLimit: batch(limit)})
	return purged(n, err, "limits")
}

func (s *pgStore) PurgeCounts(ctx context.Context, org uuid.UUID, cutoff istdate.Date, limit int) (int, error) {
	n, err := s.q(ctx).PurgeOtpCounts(ctx, dbgen.PurgeOtpCountsParams{OrgID: org, Cutoff: pgDate(cutoff), RowLimit: batch(limit)})
	return purged(n, err, "counts")
}

// batch clamps a purge batch size to the int32 the query takes.
func batch(limit int) int32 {
	const maxBatch = 1 << 20
	return int32(max(0, min(limit, maxBatch))) //nolint:gosec // clamped to 0..2^20
}

func purged(n int64, err error, what string) (int, error) {
	if err != nil {
		return 0, fmt.Errorf("otp: purge %s: %w", what, err)
	}
	return int(n), nil
}
