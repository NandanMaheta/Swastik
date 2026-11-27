package ipomarket

import (
	"flag"
	"math/big"
	"testing"

	"pgregory.net/rapid"
)

// S04: BR-IPO-04 expected profit per lot = GMP per share x lot size, exact integer paise, no other
// deduction. An unknown lot size is the caller's concern (the service gives null, see S08).

// fataler is satisfied by *testing.T and *rapid.T.
type fataler interface {
	Helper()
	Fatalf(format string, args ...any)
}

// expectedProfit calls the function under test and turns a skeleton panic into a failure.
func expectedProfit(t fataler, gmp int64, lot int32) (out int64) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("ExpectedProfitPerLot(%d, %d) panicked: %v", gmp, lot, r)
		}
	}()
	return ExpectedProfitPerLot(gmp, lot)
}

func TestExpectedProfitPerLot_BR_IPO_04_Values(t *testing.T) {
	tests := []struct {
		name string
		gmp  int64
		lot  int32
		want int64
	}{
		{"US1.1 30.00 x 50", 3000, 50, 150_000},
		{"US1.2 25.50 x 50", 2550, 50, 127_500},
		{"US1.4 negative -10.00 x 50 is an expected loss", -1000, 50, -50_000},
		{"zero GMP is zero profit", 0, 50, 0},
		{"one paise, lot 1", 1, 1, 1},
		{"minus one paise, lot 1", -1, 1, -1},
		{"lot 1 returns the GMP", 123_456, 1, 123_456},
		{"max GMP x max lot", 1_000_000_000, 1_000_000, 1_000_000_000_000_000},
		{"min GMP x max lot", -1_000_000_000, 1_000_000, -1_000_000_000_000_000},
		{"max GMP x lot 1", 1_000_000_000, 1, 1_000_000_000},
		{"odd values", 7, 13, 91},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := expectedProfit(t, tc.gmp, tc.lot); got != tc.want {
				t.Errorf("ExpectedProfitPerLot(%d, %d) = %d, want %d", tc.gmp, tc.lot, got, tc.want)
			}
		})
	}
}

// SC-001: for every GMP and lot size in the stored bounds the value equals GMP x lot exactly,
// 10,000 cases.
func TestExpectedProfitPerLot_BR_IPO_04_Property(t *testing.T) {
	if f := flag.Lookup("rapid.checks"); f != nil {
		old := f.Value.String()
		if err := flag.Set("rapid.checks", "10000"); err != nil {
			t.Fatalf("set rapid.checks: %v", err)
		}
		t.Cleanup(func() { _ = flag.Set("rapid.checks", old) })
	}
	gmpGen := rapid.Int64Range(-1_000_000_000, 1_000_000_000)
	lotGen := rapid.Int32Range(1, 1_000_000)
	rapid.Check(t, func(rt *rapid.T) {
		gmp, lot := gmpGen.Draw(rt, "gmp"), lotGen.Draw(rt, "lot")
		got := expectedProfit(rt, gmp, lot)

		want := new(big.Int).Mul(big.NewInt(gmp), big.NewInt(int64(lot)))
		if !want.IsInt64() || got != want.Int64() {
			rt.Fatalf("ExpectedProfitPerLot(%d, %d) = %d, want %s", gmp, lot, got, want)
		}
		switch {
		case gmp > 0 && got <= 0, gmp < 0 && got >= 0, gmp == 0 && got != 0:
			rt.Fatalf("sign of %d does not follow the GMP %d", got, gmp)
		}
		if got%int64(lot) != 0 || got/int64(lot) != gmp {
			rt.Fatalf("%d is not exactly gmp %d x lot %d", got, gmp, lot)
		}
		if abs := got; abs > 1_000_000_000_000_000 || abs < -1_000_000_000_000_000 {
			rt.Fatalf("%d outside the 1e15 bound", got)
		}
		if one := expectedProfit(rt, gmp, 1); one != gmp {
			rt.Fatalf("lot 1 gives %d, want the GMP %d", one, gmp)
		}
	})
}

func TestExpectedProfitPerLot_BR_IPO_04_PropertyLinearInGMP(t *testing.T) {
	half := rapid.Int64Range(-500_000_000, 500_000_000)
	lotGen := rapid.Int32Range(1, 1_000_000)
	rapid.Check(t, func(rt *rapid.T) {
		a, b, lot := half.Draw(rt, "a"), half.Draw(rt, "b"), lotGen.Draw(rt, "lot")
		if got, want := expectedProfit(rt, a+b, lot), expectedProfit(rt, a, lot)+expectedProfit(rt, b, lot); got != want {
			rt.Fatalf("f(%d+%d, %d) = %d, want sum %d", a, b, lot, got, want)
		}
		if got, want := expectedProfit(rt, -a, lot), -expectedProfit(rt, a, lot); got != want {
			rt.Fatalf("f(-%d, %d) = %d, want %d", a, lot, got, want)
		}
	})
}
