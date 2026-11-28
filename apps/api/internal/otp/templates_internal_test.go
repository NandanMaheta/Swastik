package otp

// Tests for the email templates (feature 004, S06; BR-CLI-04, BR-CLI-05, FR-014, D-08).
//
// Assumed parameter order of the unexported renderers (the skeleton's three and two strings):
//
//	codeMail(to, code, purpose string) email.Mail     // purpose is the string of a Purpose
//	noticeMail(to, changed string) email.Mail         // changed is "email" or "mobile"
//
// Contract (go-module-api.md section 2): subject "Your Swastik code: 123456"; the body says what
// the code is for, "expires in 10 minutes", "never share it" and "ignore if you did not ask". The
// notice says the contact is being changed and "contact the operator"; it holds no code and no
// new contact. The sender fills IdempotencyKey, so the renderers leave it empty.

import (
	"regexp"
	"slices"
	"strings"
	"testing"
)

var anySixDigits = regexp.MustCompile(`[0-9]{6}`)

func TestTemplate_BR_CLI_04_CodeMailSubjectAndBody(t *testing.T) {
	m := codeMail("ravi@example.com", "482913", string(PurposeSignup))
	if m.To != "ravi@example.com" {
		t.Errorf("To = %q", m.To)
	}
	if m.Subject != "Your Swastik code: 482913" {
		t.Errorf("Subject = %q, want %q", m.Subject, "Your Swastik code: 482913")
	}
	if m.IdempotencyKey != "" {
		t.Errorf("IdempotencyKey = %q, want empty (the sender sets it)", m.IdempotencyKey)
	}
	body := strings.ToLower(m.Text)
	for _, want := range []string{"482913", "expires in 10 minutes", "never share", "ignore"} {
		if !strings.Contains(body, want) {
			t.Errorf("body lacks %q:\n%s", want, m.Text)
		}
	}
}

func TestTemplate_BR_CLI_04_ExpiryTextFollowsTheCodeTTL(t *testing.T) {
	m := codeMail("a@example.com", "000111", string(PurposeSignup))
	want := "expires in " + itoa(int(CodeTTL.Minutes())) + " minutes"
	if !strings.Contains(strings.ToLower(m.Text), want) {
		t.Errorf("body lacks %q:\n%s", want, m.Text)
	}
}

func TestTemplate_BR_CLI_04_PurposeIsNamedInTheBody(t *testing.T) {
	cases := map[Purpose]string{
		PurposeSignup:        "sign",
		PurposeChangeEmail:   "email",
		PurposePasswordReset: "password",
	}
	var bodies []string
	for p, word := range cases {
		m := codeMail("a@example.com", "123456", string(p))
		if !strings.Contains(strings.ToLower(m.Text), word) {
			t.Errorf("%s: body lacks %q:\n%s", p, word, m.Text)
		}
		if slices.Contains(bodies, m.Text) {
			t.Errorf("%s renders the same body as another purpose", p)
		}
		bodies = append(bodies, m.Text)
	}
}

func TestTemplate_BR_CLI_05_NoticeHasNoCodeAndNoNewContact(t *testing.T) {
	for _, changed := range []string{"email", "mobile"} {
		m := noticeMail("old@example.com", changed)
		if m.To != "old@example.com" || m.IdempotencyKey != "" {
			t.Errorf("%s: To = %q key = %q", changed, m.To, m.IdempotencyKey)
		}
		whole := m.Subject + "\n" + m.Text
		if anySixDigits.MatchString(whole) {
			t.Errorf("%s: notice contains a 6-digit number: %s", changed, whole)
		}
		if strings.Contains(strings.ToLower(whole), "code") && strings.Contains(strings.ToLower(whole), "your swastik code") {
			t.Errorf("%s: notice looks like a code mail", changed)
		}
		if strings.Contains(whole, "@") || strings.Contains(whole, "+91") {
			t.Errorf("%s: notice carries a contact: %s", changed, whole)
		}
		low := strings.ToLower(m.Text)
		for _, want := range []string{changed, "being changed", "contact the operator", "not you"} {
			if !strings.Contains(low, want) {
				t.Errorf("%s: body lacks %q:\n%s", changed, want, m.Text)
			}
		}
		if m.Subject == "" {
			t.Errorf("%s: empty subject", changed)
		}
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for ; n > 0; n /= 10 {
		b = append([]byte{byte('0' + n%10)}, b...)
	}
	return string(b)
}
