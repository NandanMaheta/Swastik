package ipomarket

import (
	"time"

	"github.com/NandanMaheta/swastik/apps/api/internal/ipos"
)

// validateGMP checks a GMP input against the IPO (FR-001, FR-007). It returns the input with the
// note trimmed and any typo-guard warnings. Compile stub until S05.
func validateGMP(in GMPInput, ipo ipos.IPO) (GMPInput, []Warning, error) {
	return GMPInput{}, nil, errNotImplemented
}

// validateSubscription checks a snapshot input (FR-008) at instant now. Compile stub until S05.
func validateSubscription(in SubscriptionInput, ipo ipos.IPO, now time.Time) error {
	return errNotImplemented
}
