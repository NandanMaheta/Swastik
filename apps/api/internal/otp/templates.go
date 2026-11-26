package otp

import "github.com/NandanMaheta/swastik/apps/api/internal/platform/email"

// codeMail renders the code email (subject "Your Swastik code: 123456").
//
//nolint:unused // used by the sender in a later slice
func codeMail(_, _, _ string) email.Mail { panic(errNotImplemented) }

// noticeMail renders the contact-change notice (no code, no new contact).
//
//nolint:unused // used by the sender in a later slice
func noticeMail(_, _ string) email.Mail { panic(errNotImplemented) }
