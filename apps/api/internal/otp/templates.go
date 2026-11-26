package otp

import (
	"fmt"

	"github.com/NandanMaheta/swastik/apps/api/internal/platform/email"
)

// codeMail renders the code email (subject "Your Swastik code: 123456"). The sender sets the
// idempotency key.
//
//nolint:unused // used by the sender in a later slice
func codeMail(to, code, purpose string) email.Mail {
	var what string
	switch Purpose(purpose) {
	case PurposeSignup:
		what = "to finish signing up"
	case PurposeChangeEmail:
		what = "to confirm your new email address"
	case PurposePasswordReset:
		what = "to reset your password"
	case PurposeChangeMobile:
		what = "to confirm this request"
	default:
		what = "to confirm this request"
	}
	return email.Mail{
		To:      to,
		Subject: "Your Swastik code: " + code,
		Text: fmt.Sprintf("Your Swastik code is %s. Use it %s.\n\n"+
			"The code expires in %d minutes. Never share it with anyone, including the operator.\n\n"+
			"If you did not ask for this code, ignore this email.\n", code, what, int(CodeTTL.Minutes())),
	}
}

// noticeMail renders the contact-change notice (no code, no new contact). changed is "email" or
// "mobile".
//
//nolint:unused // used by the sender in a later slice
func noticeMail(to, changed string) email.Mail {
	what := "email address"
	if changed == "mobile" {
		what = "mobile number"
	}
	return email.Mail{
		To:      to,
		Subject: fmt.Sprintf("The %s on your Swastik account is being changed", what),
		Text: fmt.Sprintf("The %s on your Swastik account is being changed.\n\n"+
			"If this was not you, contact the operator right away.\n", what),
	}
}
