package otp_test

// Shared helpers of the service tests (feature 004, S10/S12/S14). Everything runs on the real
// auth Service, the real outbox and a real PostgreSQL through otptest, with the fake clock
// (authtest.T0 = 2026-07-01 10:00 UTC = 15:30 IST). Policy numbers come from the otp constants.

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/NandanMaheta/swastik/apps/api/internal/auth/authtest"
	"github.com/NandanMaheta/swastik/apps/api/internal/otp"
	"github.com/NandanMaheta/swastik/apps/api/internal/otp/otptest"
	"github.com/NandanMaheta/swastik/apps/api/internal/platform/istdate"
)

var (
	svHandleRE          = regexp.MustCompile(`^ovh_[A-Za-z0-9_-]{43}$`)
	svResetRE           = regexp.MustCompile(`^prt_[A-Za-z0-9_-]{43}$`)
	svSixDigits         = regexp.MustCompile(`^[0-9]{6}$`)
	svSixDigitsAnywhere = regexp.MustCompile(`[0-9]{6}`)
)

// svFloor is the fixed response floor of the public send operations (plan I-3).
const svFloor = 1500 * time.Millisecond

// svIST is the instant of the given IST wall-clock time on 2026-07-01 (the clock's day) plus days.
func svIST(days, hour, minute int) time.Time {
	return istdate.Date{Year: 2026, Month: time.July, Day: 1}.AddDays(days).At(hour, minute)
}

// svRetry requires err to be a *otp.RetryError of the reason and returns it.
func svRetry(t *testing.T, err error, reason otp.RetryReason) *otp.RetryError {
	t.Helper()
	var re *otp.RetryError
	if !errors.As(err, &re) {
		t.Fatalf("err = %v, want *otp.RetryError(%s)", err, reason)
	}
	if re.Reason != reason {
		t.Fatalf("retry reason = %q, want %q", re.Reason, reason)
	}
	return re
}

// svWrongOf returns a 6-digit code that differs from code.
func svWrongOf(code string) string {
	if code == "000000" {
		return "000001"
	}
	return "000000"
}

// svVerRow is the columns of otp_verifications the tests read.
type svVerRow struct {
	Purpose                                                      string
	UserID                                                       *uuid.UUID
	Email, Mobile                                                *string
	EmailDone, MobileDone, Finished, Cancelled, ResetTokenExpiry *time.Time
	CancelReason                                                 *string
	ResetHash                                                    []byte
}

func svVer(t *testing.T, e *otptest.Env, id uuid.UUID) svVerRow {
	t.Helper()
	var r svVerRow
	err := e.Pool.QueryRow(context.Background(), `SELECT purpose, user_id, email, mobile, email_done_at, mobile_done_at, finished_at,
		cancelled_at, reset_token_expires_at, cancel_reason, reset_token_hash FROM otp_verifications WHERE id = $1`, id).
		Scan(&r.Purpose, &r.UserID, &r.Email, &r.Mobile, &r.EmailDone, &r.MobileDone, &r.Finished, &r.Cancelled,
			&r.ResetTokenExpiry, &r.CancelReason, &r.ResetHash)
	if err != nil {
		t.Fatalf("read verification %s: %v", id, err)
	}
	return r
}

// svCodeRow is one otp_email_codes row.
type svCodeRow struct {
	ID        uuid.UUID
	Digest    []byte
	Wrong     int
	OutboxKey *string
	EndedAt   *time.Time
	EndReason *string
	IssuedAt  time.Time
	ExpiresAt time.Time
}

// svCodes returns the codes of a verification, oldest first.
func svCodes(t *testing.T, e *otptest.Env, ver uuid.UUID) []svCodeRow {
	t.Helper()
	rows, err := e.Pool.Query(context.Background(), `SELECT id, code_digest, wrong_attempts, outbox_key, ended_at, end_reason, issued_at, expires_at
		FROM otp_email_codes WHERE verification_id = $1 ORDER BY issued_at, id`, ver)
	if err != nil {
		t.Fatalf("read codes: %v", err)
	}
	defer rows.Close()
	var out []svCodeRow
	for rows.Next() {
		var r svCodeRow
		if err := rows.Scan(&r.ID, &r.Digest, &r.Wrong, &r.OutboxKey, &r.EndedAt, &r.EndReason, &r.IssuedAt, &r.ExpiresAt); err != nil {
			t.Fatalf("scan code: %v", err)
		}
		out = append(out, r)
	}
	return out
}

// svLive returns the live (not ended) code of the verification.
func svLive(t *testing.T, e *otptest.Env, ver uuid.UUID) svCodeRow {
	t.Helper()
	for _, c := range svCodes(t, e, ver) {
		if c.EndedAt == nil {
			return c
		}
	}
	t.Fatalf("verification %s has no live code", ver)
	return svCodeRow{}
}

// svNoLeak fails when haystack holds any of the needles (contacts, codes, handles, tokens).
func svNoLeak(t *testing.T, where, haystack string, needles ...string) {
	t.Helper()
	for _, n := range needles {
		if n != "" && strings.Contains(haystack, n) {
			t.Errorf("%s contains a value that must never appear there (%d chars, starts %q...)", where, len(n), n[:min(2, len(n))])
		}
	}
}

// svAuditText is every otp audit row of the world as one string (action, entity, before, after).
func svAuditText(t *testing.T, e *otptest.Env) string {
	t.Helper()
	var b strings.Builder
	for _, r := range e.OTPAudit(t) {
		b.WriteString(r.Action + " " + r.Entity + " " + r.Before + " " + r.After + "\n")
	}
	return b.String()
}

// svAuditOf returns the otp audit rows of one action.
func svAuditOf(t *testing.T, e *otptest.Env, action string) []authtest.AuditRow {
	t.Helper()
	var out []authtest.AuditRow
	for _, r := range e.OTPAudit(t) {
		if r.Action == action {
			out = append(out, r)
		}
	}
	return out
}

// svMustPanicFree runs fn and fails the test (instead of crashing the binary) when it panics, so a
// not-implemented stub reads as one failing test.
func svMustPanicFree(t *testing.T, what string, fn func()) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("%s panicked: %v", what, r)
		}
	}()
	fn()
}
