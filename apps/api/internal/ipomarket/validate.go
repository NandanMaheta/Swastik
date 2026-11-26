package ipomarket

import (
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/NandanMaheta/swastik/apps/api/internal/ipos"
)

const (
	codeInvalidValue   = "ipomarket.invalid_value"
	codeGMPExceedsCost = "ipomarket.gmp_exceeds_price"

	maxGMPPaise   = 1_000_000_000
	maxX100       = 10_000_000
	maxNoteChars  = 200
	asOfFutureEps = 5 * time.Minute
)

var sourcePattern = regexp.MustCompile(`^(manual|import:[a-z0-9_]{1,32})$`)

func invalid(issues []FieldIssue) error {
	if len(issues) == 0 {
		return nil
	}
	return &ValidationError{Code: codeInvalidValue, Issues: issues}
}

func checkSource(source string, issues *[]FieldIssue) {
	if !sourcePattern.MatchString(source) {
		*issues = append(*issues, FieldIssue{Field: "source", Message: "must be manual or import:<name>"})
	}
}

// validateGMP checks a GMP input against the IPO (FR-001, FR-007). It returns the input with the
// note trimmed and any typo-guard warnings.
func validateGMP(in GMPInput, ipo ipos.IPO) (GMPInput, []Warning, error) {
	var issues []FieldIssue
	if in.GMPPaise < -maxGMPPaise || in.GMPPaise > maxGMPPaise {
		issues = append(issues, FieldIssue{Field: "gmp_paise", Message: "out of range"})
	}
	if in.Note != nil {
		n := strings.TrimSpace(*in.Note)
		if c := utf8.RuneCountInString(n); c < 1 || c > maxNoteChars {
			issues = append(issues, FieldIssue{Field: "note", Message: "must be 1 to 200 characters"})
		}
		in.Note = &n
	}
	checkSource(in.Source, &issues)
	if err := invalid(issues); err != nil {
		return GMPInput{}, nil, err
	}

	var price int64
	switch {
	case ipo.IssuePricePaise != nil:
		price = *ipo.IssuePricePaise
	case ipo.PriceBandCapPaise != nil:
		price = *ipo.PriceBandCapPaise
	}
	var warns []Warning
	abs := in.GMPPaise
	if abs < 0 {
		abs = -abs
	}
	if price > 0 && abs > price {
		warns = append(warns, Warning{
			Code:   codeGMPExceedsCost,
			Fields: []string{"gmp_paise"},
			Detail: "GMP is larger than the issue price; check for a typo",
			Params: map[string]int64{"gmp_paise": in.GMPPaise, "price_paise": price},
		})
	}
	return in, warns, nil
}

// validateSubscription checks a snapshot input (FR-008) at instant now.
func validateSubscription(in SubscriptionInput, ipo ipos.IPO, now time.Time) error {
	var issues []FieldIssue
	if in.AsOf.After(now.Add(asOfFutureEps)) {
		issues = append(issues, FieldIssue{Field: "as_of", Message: "cannot be in the future"})
	} else if ipo.Dates.Open != nil && in.AsOf.Before(ipo.Dates.Open.At(0, 0)) {
		issues = append(issues, FieldIssue{Field: "as_of", Message: "cannot be before the open date"})
	}
	bad := func(field string, v int32) {
		if v < 0 || v > maxX100 {
			issues = append(issues, FieldIssue{Field: field, Message: "out of range"})
		}
	}
	bad("total_x100", in.TotalX100)
	for _, c := range []struct {
		field string
		v     *int32
	}{
		{"qib_x100", in.QIBX100}, {"nii_x100", in.NIIX100}, {"bnii_x100", in.BNIIX100},
		{"snii_x100", in.SNIIX100}, {"retail_x100", in.RetailX100}, {"employee_x100", in.EmployeeX100},
	} {
		if c.v != nil {
			bad(c.field, *c.v)
		}
	}
	checkSource(in.Source, &issues)
	return invalid(issues)
}
