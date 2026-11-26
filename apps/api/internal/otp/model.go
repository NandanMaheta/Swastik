package otp

import (
	"time"

	"github.com/google/uuid"
)

// Purpose is why a verification exists.
type Purpose string

// The four purposes (data-model section 1).
const (
	PurposeSignup        Purpose = "signup"         // email code + Firebase mobile proof (BR-CLI-04)
	PurposeChangeEmail   Purpose = "change_email"   // code to the NEW email (BR-CLI-05)
	PurposeChangeMobile  Purpose = "change_mobile"  // Firebase proof of the NEW mobile
	PurposePasswordReset Purpose = "password_reset" // code to the account email (D-06)
)

// FlowState is the derived state of a verification; it is never stored.
type FlowState string

// Flow states.
const (
	FlowOpen      FlowState = "open"
	FlowCompleted FlowState = "completed"
	FlowExpired   FlowState = "expired"
	FlowCancelled FlowState = "cancelled"
)

// ContactState is the state of one contact of a verification.
type ContactState string

// Contact states: verified for sign-up, proved for a contact change.
const (
	ContactPending  ContactState = "pending"
	ContactVerified ContactState = "verified"
	ContactProved   ContactState = "proved"
	ContactExpired  ContactState = "expired"
)

// ContactView is one contact as shown to a client: masked, never readable.
type ContactView struct {
	State         ContactState
	Masked        string // "r***@gmail.com" or "+91 ******5678"; empty for password_reset
	NextResendAt  *time.Time
	CodeExpiresAt *time.Time
}

// View is the state of one verification. Target* are the readable contacts for 007 (in-process
// only; the handlers never copy them).
type View struct {
	ID            uuid.UUID
	OrgID         uuid.UUID
	UserID        *uuid.UUID
	Purpose       Purpose
	State         FlowState
	ExpiresAt     time.Time
	Email, Mobile *ContactView
	TargetEmail   string
	TargetMobile  string
}

// StartInput starts a verification for a known user (in-process capability for 005 and 007).
type StartInput struct {
	OrgID, UserID uuid.UUID
	Purpose       Purpose // signup | change_email | change_mobile (password_reset only via StartReset)
	NewContact    string  // change_* only; normalised with auth.NormalizeEmail/NormalizeMobile
	IP            string  // httpx.ClientIP of the request that caused the start (D-03)
}

// Started is the result of Start; Handle is shown once.
type Started struct {
	ID        uuid.UUID
	Handle    string
	ExpiresAt time.Time
}

// Caller identifies who calls a handle-keyed operation. UserID is set on /v1/me/* and must own
// the handle (purpose change_*).
type Caller struct {
	IP     string
	UserID *uuid.UUID
}

// ResendResult is the answer to Resend.
type ResendResult struct {
	NextResendAt, CodeExpiresAt time.Time
}

// VerifyEmailResult is the answer to VerifyEmail; the reset token is set for password_reset only.
type VerifyEmailResult struct {
	Verification        View
	ResetToken          string
	ResetTokenExpiresAt *time.Time
}

// ResetStarted is the uniform answer to StartReset, for known and unknown identifiers alike.
type ResetStarted struct {
	Handle       string
	ExpiresAt    time.Time
	NextResendAt time.Time
}

// ContactNotice tells the old email that a contact is being changed (FR-014).
type ContactNotice struct {
	OrgID, UserID uuid.UUID
	OldEmail      string
	Changed       string // "email" | "mobile"
}

// DailyCounts are the delivery counters of one IST day (FR-017); they hold no identifiers.
type DailyCounts struct {
	EmailSent, EmailFailed, LimitRefused, ProofAccepted, ProofRefused int
}

// MaskEmail hides most of an email: "r***@gmail.com".
func MaskEmail(_ string) string { panic(errNotImplemented) }

// MaskMobile hides most of a mobile: "+91 ******5678".
func MaskMobile(_ string) string { panic(errNotImplemented) }
