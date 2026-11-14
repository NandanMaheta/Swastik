package auth

import (
	"time"

	"github.com/google/uuid"
)

// Value types of the sign-in, refresh and session operations of Service.

// Client types: the refresh transport of a session (P-04). On a RefreshInput it names the
// transport the request used: "mobile" = token in the body, "web" = token from the cookie.
const (
	ClientTypeMobile = "mobile"
	ClientTypeWeb    = "web"
)

// Platforms of a device session.
const (
	PlatformAndroid = "android"
	PlatformIPhone  = "iphone"
	PlatformWeb     = "web"
)

// NextStep values of SignInResult.
const (
	NextStepSignedIn           = "signed_in"
	NextStepMFARequired        = "mfa_required"
	NextStepMFAEnrolmentNeeded = "mfa_enrolment_required"
)

// DeviceInfo is the installation that signs in.
type DeviceInfo struct {
	ID       uuid.UUID
	Name     string
	Platform string
}

// SignInInput is one sign-in attempt. Password is raw and never logged. IP is the client address
// already resolved by httpx.ClientIP.
type SignInInput struct {
	Identifier, Password string
	ClientType           string
	Device               DeviceInfo
	IP                   string
}

// UserSummary is the user part of SessionTokens.
type UserSummary struct {
	ID                uuid.UUID
	Role, Name, Email string
}

// SessionTokens is the result of a successful sign-in, refresh or MFA completion. RefreshToken is
// always set; the HTTP layer keeps it out of the body for web sessions.
type SessionTokens struct {
	AccessToken          string
	AccessTokenExpiresAt time.Time
	RefreshToken         string
	SessionID            uuid.UUID
	SessionExpiresAt     time.Time // absolute
	IdleExpiresAt        time.Time
	User                 UserSummary
}

// Challenge is the interim proof of an admin after the password step.
type Challenge struct {
	Token     string // dmc_...
	ExpiresAt time.Time
}

// SignInResult is the outcome of a correct password: a session (client) or a challenge (admin).
type SignInResult struct {
	NextStep  string
	Session   *SessionTokens
	Challenge *Challenge
}

// RefreshInput is one refresh attempt. ClientType is the transport used (ClientTypeMobile: token
// in the body, ClientTypeWeb: token from the cookie).
type RefreshInput struct {
	DeviceID     uuid.UUID
	RefreshToken string
	ClientType   string
	IP           string
}

// Device is one live device session as listed to its user or to an admin.
type Device struct {
	SessionID    uuid.UUID
	DeviceName   string
	Platform     string
	SignedInAt   time.Time
	LastActiveAt time.Time
	IsCurrent    bool
}
