// Tests for MaskEmail and MaskMobile (feature 004, S06; BR-CLI-04, D-08): the app shows which
// contact a code went to without revealing it.
package otp_test

import (
	"strings"
	"testing"

	"pgregory.net/rapid"

	"github.com/NandanMaheta/swastik/apps/api/internal/otp"
)

func TestMaskEmail_BR_CLI_04_Table(t *testing.T) {
	tests := []struct{ in, want string }{
		{"ravi@gmail.com", "r***@gmail.com"},
		{"ravi.shah@example.co.in", "r***@example.co.in"},
		{"ab@x.in", "a***@x.in"},
		{"a+tag@mail.example.com", "a***@mail.example.com"},
	}
	for _, tt := range tests {
		if got := otp.MaskEmail(tt.in); got != tt.want {
			t.Errorf("MaskEmail(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestMaskEmail_BR_CLI_04_ShortAndMalformedInputsNeverPanicOrLeak(t *testing.T) {
	if got := otp.MaskEmail("a@x.in"); got == "a@x.in" || !strings.HasSuffix(got, "@x.in") || !strings.Contains(got, "***") {
		t.Errorf("MaskEmail(a@x.in) = %q, want a masked local part and the domain kept", got)
	}
	for _, in := range []string{"", "no-at-sign", "@", "@x.in", "a@", "two@@x.in"} {
		got := otp.MaskEmail(in)
		if in != "" && got == in {
			t.Errorf("MaskEmail(%q) returned the input unchanged", in)
		}
	}
}

func TestMaskMobile_BR_CLI_04_Table(t *testing.T) {
	tests := []struct{ in, want string }{
		{"+919812345678", "+91 ******5678"},
		{"+916000000001", "+91 ******0001"},
	}
	for _, tt := range tests {
		if got := otp.MaskMobile(tt.in); got != tt.want {
			t.Errorf("MaskMobile(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
	for _, in := range []string{"", "123", "not a number"} {
		if got := otp.MaskMobile(in); in != "" && got == in {
			t.Errorf("MaskMobile(%q) returned the input unchanged", in)
		}
	}
}

func TestMask_BR_CLI_04_PropertyOnlyFirstCharAndDomainOrLastFourSurvive(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		local := rapid.StringMatching(`[a-z][0-9.]{3,14}`).Draw(t, "local")
		domain := rapid.StringMatching(`[a-z]{3,8}\.(com|in|co\.in)`).Draw(t, "domain")
		got := otp.MaskEmail(local + "@" + domain)
		if got != local[:1]+"***@"+domain {
			t.Fatalf("MaskEmail(%s@%s) = %q", local, domain, got)
		}
		if strings.Contains(got, local[1:]) {
			t.Fatalf("masked email %q leaks the local part", got)
		}

		digits := rapid.StringMatching(`[6-9][0-9]{9}`).Draw(t, "digits")
		m := otp.MaskMobile("+91" + digits)
		if m != "+91 ******"+digits[6:] {
			t.Fatalf("MaskMobile(+91%s) = %q", digits, m)
		}
		if strings.Contains(m, digits[:6]) {
			t.Fatalf("masked mobile %q leaks leading digits", m)
		}
	})
}
