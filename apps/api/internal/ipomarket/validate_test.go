package ipomarket

import (
	"errors"
	"sort"
	"strings"
	"testing"
	"time"

	"pgregory.net/rapid"

	"github.com/NandanMaheta/swastik/apps/api/internal/ipos"
	"github.com/NandanMaheta/swastik/apps/api/internal/platform/istdate"
)

// S04: input validation (FR-001, FR-007, FR-008, contracts/http-api.md error table).
//
// Signatures under test (compile stubs in validate.go until S05):
//
//	validateGMP(in GMPInput, ipo ipos.IPO) (GMPInput, []Warning, error)   // returns the note trimmed
//	validateSubscription(in SubscriptionInput, ipo ipos.IPO, now time.Time) error
//
// Failures are *ValidationError with Code "ipomarket.invalid_value" and one FieldIssue per bad
// field, named like the JSON field: note, gmp_paise, source, as_of, total_x100, qib_x100, nii_x100,
// bnii_x100, snii_x100, retail_x100, employee_x100.

const invalidValue = "ipomarket.invalid_value"

func issueFields(err error) []string {
	var ve *ValidationError
	if !errors.As(err, &ve) {
		return nil
	}
	out := make([]string, 0, len(ve.Issues))
	for _, i := range ve.Issues {
		out = append(out, strings.TrimPrefix(i.Field, "body."))
	}
	sort.Strings(out)
	return out
}

func wantInvalid(t fataler, err error, fields ...string) {
	t.Helper()
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("want *ValidationError %s, got %T %v", invalidValue, err, err)
	}
	if ve.Code != invalidValue {
		t.Fatalf("code = %q, want %q", ve.Code, invalidValue)
	}
	want := append([]string(nil), fields...)
	sort.Strings(want)
	if got := issueFields(err); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("issue fields = %v, want %v", got, want)
	}
}

func priced(issue, capPaise *int64) ipos.IPO {
	return ipos.IPO{LotSize: p32(50), IssuePricePaise: issue, PriceBandCapPaise: capPaise}
}

// ---- GMP ----

func TestValidate_BR_IPO_04_GMPNote(t *testing.T) {
	ipo := priced(p64(100_000), nil)
	ok := []struct {
		name string
		note *string
		want *string
	}{
		{"no note", nil, nil},
		{"one char", pStr("x"), pStr("x")},
		{"trimmed", pStr("  from broker A \n"), pStr("from broker A")},
		{"200 chars", pStr(strings.Repeat("n", 200)), pStr(strings.Repeat("n", 200))},
		{"200 chars after trimming", pStr("  " + strings.Repeat("n", 200) + "  "), pStr(strings.Repeat("n", 200))},
	}
	for _, c := range ok {
		t.Run(c.name, func(t *testing.T) {
			got, _, err := validateGMP(GMPInput{GMPPaise: 3000, Note: c.note, Source: "manual"}, ipo)
			if err != nil {
				t.Fatalf("validateGMP: %v", err)
			}
			switch {
			case c.want == nil && got.Note != nil:
				t.Errorf("note = %q, want none", *got.Note)
			case c.want != nil && (got.Note == nil || *got.Note != *c.want):
				t.Errorf("note = %v, want %q", got.Note, *c.want)
			}
			if got.GMPPaise != 3000 {
				t.Errorf("GMPPaise = %d, want 3000 (validation must not change the value)", got.GMPPaise)
			}
		})
	}
	for name, note := range map[string]string{"empty": "", "blank": " \t\n ", "201 chars": strings.Repeat("n", 201)} {
		t.Run("rejects "+name, func(t *testing.T) {
			_, _, err := validateGMP(GMPInput{GMPPaise: 3000, Note: &note, Source: "manual"}, ipo)
			wantInvalid(t, err, "note")
		})
	}
}

func TestValidate_BR_IPO_04_GMPValueAndSource(t *testing.T) {
	ipo := priced(p64(2_000_000_000), nil) // price above the bounds so no warning interferes
	for _, v := range []int64{-1_000_000_000, -1, 0, 1, 1_000_000_000} {
		if _, _, err := validateGMP(GMPInput{GMPPaise: v, Source: "manual"}, ipo); err != nil {
			t.Errorf("gmp %d rejected: %v", v, err)
		}
	}
	for _, v := range []int64{-1_000_000_001, 1_000_000_001} {
		_, _, err := validateGMP(GMPInput{GMPPaise: v, Source: "manual"}, ipo)
		wantInvalid(t, err, "gmp_paise")
	}
	for _, s := range []string{"manual", "import:nse_feed"} {
		if _, _, err := validateGMP(GMPInput{GMPPaise: 1, Source: s}, ipo); err != nil {
			t.Errorf("source %q rejected: %v", s, err)
		}
	}
	for _, s := range []string{"import:Bad", "import:", "scrape:x"} {
		_, _, err := validateGMP(GMPInput{GMPPaise: 1, Source: s}, ipo)
		wantInvalid(t, err, "source")
	}
	// All bad fields are reported together.
	blank := " "
	_, _, err := validateGMP(GMPInput{GMPPaise: 2_000_000_000, Note: &blank, Source: "x"}, ipo)
	wantInvalid(t, err, "gmp_paise", "note", "source")
}

func TestValidate_BR_IPO_04_GMPTypoGuardWarning(t *testing.T) {
	tests := []struct {
		name      string
		ipo       ipos.IPO
		gmp       int64
		wantPrice int64 // 0 = no warning
	}{
		{"above issue price", priced(p64(100_000), nil), 100_001, 100_000},
		{"equal to issue price is fine", priced(p64(100_000), nil), 100_000, 0},
		{"below issue price", priced(p64(100_000), nil), 3000, 0},
		{"negative beyond issue price uses the absolute value", priced(p64(100_000), nil), -100_001, 100_000},
		{"negative within issue price", priced(p64(100_000), nil), -100_000, 0},
		{"band cap when no issue price", priced(nil, p64(105_000)), 105_001, 105_000},
		{"band cap equal is fine", priced(nil, p64(105_000)), 105_000, 0},
		{"issue price wins over band cap", priced(p64(90_000), p64(105_000)), 95_000, 90_000},
		{"no price known gives no warning", priced(nil, nil), 1_000_000_000, 0},
		{"zero GMP", priced(p64(100_000), nil), 0, 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, ws, err := validateGMP(GMPInput{GMPPaise: tc.gmp, Source: "manual"}, tc.ipo)
			if err != nil {
				t.Fatalf("typo guard must not be an error: %v", err)
			}
			if tc.wantPrice == 0 {
				if len(ws) != 0 {
					t.Fatalf("warnings = %+v, want none", ws)
				}
				return
			}
			if len(ws) != 1 {
				t.Fatalf("warnings = %+v, want exactly one", ws)
			}
			w := ws[0]
			if w.Code != "ipomarket.gmp_exceeds_price" {
				t.Errorf("code = %q, want ipomarket.gmp_exceeds_price", w.Code)
			}
			if strings.Join(w.Fields, ",") != "gmp_paise" {
				t.Errorf("fields = %v, want [gmp_paise]", w.Fields)
			}
			if got, ok := w.Params["price_paise"]; !ok || got != tc.wantPrice {
				t.Errorf("params[price_paise] = %d (present %v), want %d", got, ok, tc.wantPrice)
			}
			if _, ok := w.Params["gmp_paise"]; !ok {
				t.Errorf("params lack gmp_paise: %v", w.Params)
			}
		})
	}
}

func TestValidate_BR_IPO_04_GMPTypoGuardProperty(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		price := rapid.Int64Range(1, 1_000_000_000).Draw(rt, "price")
		gmp := rapid.Int64Range(-1_000_000_000, 1_000_000_000).Draw(rt, "gmp")
		_, ws, err := validateGMP(GMPInput{GMPPaise: gmp, Source: "manual"}, priced(p64(price), p64(price+1)))
		if err != nil {
			rt.Fatalf("validateGMP(%d): %v", gmp, err)
		}
		abs := gmp
		if abs < 0 {
			abs = -abs
		}
		if want := abs > price; (len(ws) == 1) != want || len(ws) > 1 {
			rt.Fatalf("gmp %d price %d: warnings %+v, want warning=%v", gmp, price, ws, want)
		}
	})
}

// ---- Subscription ----

var (
	valNow  = istdate.Date{Year: 2026, Month: time.November, Day: 14}.At(10, 0) // Sat 14 Nov 2026 10:00 IST
	openDay = istdate.Date{Year: 2026, Month: time.November, Day: 11}
)

func openingOn(d *istdate.Date) ipos.IPO {
	return ipos.IPO{Dates: ipos.Dates{Open: d}}
}

func subAt(asOf time.Time) SubscriptionInput {
	return SubscriptionInput{AsOf: asOf, TotalX100: 1234, Source: "manual"}
}

func TestValidate_BR_IPO_04_SubscriptionAsOfWindow(t *testing.T) {
	ipo := openingOn(&openDay)
	openMidnight := openDay.At(0, 0)
	tests := []struct {
		name string
		asOf time.Time
		ok   bool
	}{
		{"now", valNow, true},
		{"now + 5 min is the limit", valNow.Add(5 * time.Minute), true},
		{"now + 5 min + 1 s", valNow.Add(5*time.Minute + time.Second), false},
		{"a day ahead", valNow.Add(24 * time.Hour), false},
		{"open date 00:00 IST is the lower limit", openMidnight, true},
		{"one second before open date 00:00 IST", openMidnight.Add(-time.Second), false},
		{"the day before the open date", openMidnight.Add(-12 * time.Hour), false},
		{"open date 00:00 given in UTC (18:30 the day before UTC) is the same instant", openMidnight.UTC(), true},
		{"US4.1 14:30 IST on a day after open", istdate.Date{Year: 2026, Month: time.November, Day: 12}.At(14, 30), true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateSubscription(subAt(tc.asOf), ipo, valNow)
			if tc.ok {
				if err != nil {
					t.Fatalf("validateSubscription: %v", err)
				}
				return
			}
			wantInvalid(t, err, "as_of")
		})
	}
	t.Run("no open date means no lower limit", func(t *testing.T) {
		if err := validateSubscription(subAt(valNow.Add(-1000*time.Hour)), openingOn(nil), valNow); err != nil {
			t.Fatalf("validateSubscription: %v", err)
		}
	})
}

func TestValidate_BR_IPO_04_SubscriptionRanges(t *testing.T) {
	ipo := openingOn(&openDay)
	type setter func(*SubscriptionInput, *int32)
	cats := map[string]setter{
		"qib_x100":      func(s *SubscriptionInput, v *int32) { s.QIBX100 = v },
		"nii_x100":      func(s *SubscriptionInput, v *int32) { s.NIIX100 = v },
		"bnii_x100":     func(s *SubscriptionInput, v *int32) { s.BNIIX100 = v },
		"snii_x100":     func(s *SubscriptionInput, v *int32) { s.SNIIX100 = v },
		"retail_x100":   func(s *SubscriptionInput, v *int32) { s.RetailX100 = v },
		"employee_x100": func(s *SubscriptionInput, v *int32) { s.EmployeeX100 = v },
	}
	t.Run("total at both limits", func(t *testing.T) {
		for _, v := range []int32{0, 1, 10_000_000} {
			in := subAt(valNow)
			in.TotalX100 = v
			if err := validateSubscription(in, ipo, valNow); err != nil {
				t.Errorf("total %d rejected: %v", v, err)
			}
		}
		for _, v := range []int32{-1, 10_000_001} {
			in := subAt(valNow)
			in.TotalX100 = v
			wantInvalid(t, validateSubscription(in, ipo, valNow), "total_x100")
		}
	})
	for field, set := range cats {
		t.Run(field, func(t *testing.T) {
			for _, v := range []int32{0, 2010, 10_000_000} {
				in := subAt(valNow)
				set(&in, p32(v))
				if err := validateSubscription(in, ipo, valNow); err != nil {
					t.Errorf("%s %d rejected: %v", field, v, err)
				}
			}
			for _, v := range []int32{-1, 10_000_001} {
				in := subAt(valNow)
				set(&in, p32(v))
				wantInvalid(t, validateSubscription(in, ipo, valNow), field)
			}
		})
	}
	t.Run("US4.1 figures pass", func(t *testing.T) {
		in := SubscriptionInput{AsOf: istdate.Date{Year: 2026, Month: time.November, Day: 12}.At(14, 30), TotalX100: 1234,
			QIBX100: p32(2010), NIIX100: p32(1500), RetailX100: p32(625), Source: "manual"}
		if err := validateSubscription(in, ipo, valNow); err != nil {
			t.Fatalf("validateSubscription: %v", err)
		}
	})
	t.Run("every bad field is reported", func(t *testing.T) {
		in := subAt(valNow.Add(time.Hour))
		in.TotalX100, in.QIBX100, in.RetailX100, in.Source = -5, p32(10_000_001), p32(-1), "nope"
		wantInvalid(t, validateSubscription(in, ipo, valNow), "as_of", "total_x100", "qib_x100", "retail_x100", "source")
	})
	t.Run("source", func(t *testing.T) {
		for _, s := range []string{"manual", "import:nse_feed"} {
			in := subAt(valNow)
			in.Source = s
			if err := validateSubscription(in, ipo, valNow); err != nil {
				t.Errorf("source %q rejected: %v", s, err)
			}
		}
		in := subAt(valNow)
		in.Source = "import:Bad"
		wantInvalid(t, validateSubscription(in, ipo, valNow), "source")
	})
}

func TestValidate_BR_IPO_04_SubscriptionRangeProperty(t *testing.T) {
	ipo := openingOn(&openDay)
	wide := rapid.Int32Range(-20_000_000, 20_000_000)
	inRange := func(v int32) bool { return v >= 0 && v <= 10_000_000 }
	rapid.Check(t, func(rt *rapid.T) {
		in := subAt(valNow)
		in.TotalX100 = wide.Draw(rt, "total")
		wantOK := inRange(in.TotalX100)
		var bad []string
		if !wantOK {
			bad = append(bad, "total_x100")
		}
		if rapid.Bool().Draw(rt, "hasQIB") {
			v := wide.Draw(rt, "qib")
			in.QIBX100 = &v
			if !inRange(v) {
				wantOK = false
				bad = append(bad, "qib_x100")
			}
		}
		err := validateSubscription(in, ipo, valNow)
		if wantOK {
			if err != nil {
				rt.Fatalf("in-range input rejected: %v", err)
			}
			return
		}
		var ve *ValidationError
		if !errors.As(err, &ve) {
			rt.Fatalf("out-of-range input gave %v, want *ValidationError", err)
		}
		wantInvalid(rt, err, bad...)
	})
}
