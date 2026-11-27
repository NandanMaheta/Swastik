package otp

import "time"

// Wire types of contracts/otp.openapi.yaml (snake_case JSON). Handles, codes, tokens and
// passwords travel only in request bodies, never in paths or queries.

// HandleRequest names a verification.
type HandleRequest struct {
	Handle string `json:"handle" pattern:"^ovh_[A-Za-z0-9_-]{43}$" doc:"Opaque verification handle; stored only as SHA-256."`
}

// VerifyEmailRequest enters the 6-digit email code.
type VerifyEmailRequest struct {
	Handle string `json:"handle" pattern:"^ovh_[A-Za-z0-9_-]{43}$" doc:"Opaque verification handle."`
	Code   string `json:"code" pattern:"^[0-9]{6}$" doc:"The 6-digit code from the email."`
}

// VerifyMobileRequest carries the Firebase phone sign-in ID token.
type VerifyMobileRequest struct {
	Handle          string `json:"handle" pattern:"^ovh_[A-Za-z0-9_-]{43}$" doc:"Opaque verification handle."`
	FirebaseIDToken string `json:"firebase_id_token" minLength:"1" maxLength:"4096" doc:"Firebase ID token of the phone sign-in on the device."`
}

// ResetStartRequest starts a password reset.
type ResetStartRequest struct {
	Identifier string `json:"identifier" minLength:"1" maxLength:"254" doc:"Email or Indian mobile; never echoed."`
}

// ResetCompleteRequest sets the new password with the one-time reset token.
type ResetCompleteRequest struct {
	Handle      string `json:"handle" pattern:"^ovh_[A-Za-z0-9_-]{43}$" doc:"Opaque verification handle."`
	ResetToken  string `json:"reset_token" pattern:"^prt_[A-Za-z0-9_-]{43}$" doc:"One-time permission from verify-email."`
	NewPassword string `json:"new_password" minLength:"1" maxLength:"1024" format:"password" doc:"The password policy is enforced with specific codes."`
}

// ResetStartedResponse is the uniform answer to a reset start.
type ResetStartedResponse struct {
	Handle       string    `json:"handle" pattern:"^ovh_[A-Za-z0-9_-]{43}$"`
	ExpiresAt    time.Time `json:"expires_at"`
	NextResendAt time.Time `json:"next_resend_at"`
}

// ResendResponse is the answer to a resend.
type ResendResponse struct {
	NextResendAt  time.Time `json:"next_resend_at"`
	CodeExpiresAt time.Time `json:"code_expires_at"`
}

// ContactStatus is one contact of a verification.
type ContactStatus struct {
	State         string     `json:"state" enum:"pending,verified,proved,expired"`
	Masked        string     `json:"masked,omitempty" doc:"For example r***@gmail.com or +91 ******5678; omitted for a password reset."`
	NextResendAt  *time.Time `json:"next_resend_at,omitempty" doc:"Email contacts with a live flow only."`
	CodeExpiresAt *time.Time `json:"code_expires_at,omitempty"`
}

// VerificationStatus is the state of a verification.
type VerificationStatus struct {
	Purpose   string         `json:"purpose" enum:"signup,change_email,change_mobile,password_reset"`
	State     string         `json:"state" enum:"open,completed,expired,cancelled"`
	ExpiresAt time.Time      `json:"expires_at"`
	Email     *ContactStatus `json:"email,omitempty"`
	Mobile    *ContactStatus `json:"mobile,omitempty"`
}

// VerifyEmailResponse is the answer to a right email code.
type VerifyEmailResponse struct {
	Verification        VerificationStatus `json:"verification"`
	ResetToken          string             `json:"reset_token,omitempty" doc:"Password reset only; shown once, valid 10 minutes."`
	ResetTokenExpiresAt *time.Time         `json:"reset_token_expires_at,omitempty"`
}

func contactStatus(c *ContactView) *ContactStatus {
	if c == nil {
		return nil
	}
	out := &ContactStatus{State: string(c.State), Masked: c.Masked}
	if c.NextResendAt != nil {
		t := c.NextResendAt.UTC()
		out.NextResendAt = &t
	}
	if c.CodeExpiresAt != nil {
		t := c.CodeExpiresAt.UTC()
		out.CodeExpiresAt = &t
	}
	return out
}

func statusOf(v View) VerificationStatus {
	return VerificationStatus{
		Purpose: string(v.Purpose), State: string(v.State), ExpiresAt: v.ExpiresAt.UTC(),
		Email: contactStatus(v.Email), Mobile: contactStatus(v.Mobile),
	}
}
