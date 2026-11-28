// Tests for code generation and the stored code digest (feature 004, S06; BR-CLI-04, D-01, D-08, FR-002).
package otp_test

import (
	"bytes"
	"errors"
	"io"
	"math/rand/v2"
	"regexp"
	"testing"

	"github.com/google/uuid"
	"pgregory.net/rapid"

	"github.com/NandanMaheta/swastik/apps/api/internal/otp"
	"github.com/NandanMaheta/swastik/apps/api/internal/platform/crypto"
)

var sixDigits = regexp.MustCompile(`^[0-9]{6}$`)

// seeded is a deterministic byte stream (never used for production secrets).
func seeded(seed uint64) io.Reader {
	return &prngReader{r: rand.New(rand.NewPCG(seed, seed^0x9e3779b97f4a7c15))}
}

type prngReader struct{ r *rand.Rand }

func (p *prngReader) Read(b []byte) (int, error) {
	for i := range b {
		b[i] = byte(p.r.Uint32())
	}
	return len(b), nil
}

type failingReader struct {
	after int // bytes served before failing
	err   error
	n     int
}

func (f *failingReader) Read(b []byte) (int, error) {
	if f.n >= f.after {
		return 0, f.err
	}
	k := min(len(b), f.after-f.n)
	for i := 0; i < k; i++ {
		b[i] = 0x37
	}
	f.n += k
	return k, nil
}

func TestGenerateCode_BR_CLI_04_IsSixDigitsFromTheSystemRandomSource(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		code, err := otp.GenerateCode(seeded(rapid.Uint64().Draw(t, "seed")))
		if err != nil {
			t.Fatalf("GenerateCode: %v", err)
		}
		if !sixDigits.MatchString(code) {
			t.Fatalf("code %q is not 6 digits", code)
		}
	})
}

func TestGenerateCode_BR_CLI_04_KeepsLeadingZeros(t *testing.T) {
	code, err := otp.GenerateCode(bytes.NewReader(make([]byte, 64)))
	if err != nil {
		t.Fatalf("GenerateCode: %v", err)
	}
	if code != "000000" {
		t.Errorf("code from an all-zero stream = %q, want 000000 (leading zeros are digits)", code)
	}
}

// Uniformity: a gross bias (a missing digit, a short alphabet) shows in the digit and bucket counts.
func TestGenerateCode_BR_CLI_04_PropertyDigitsAndBucketsAreUniform(t *testing.T) {
	const samples = 8000
	rapid.Check(t, func(t *rapid.T) {
		src := seeded(rapid.Uint64().Draw(t, "seed"))
		var first, last [10]int
		var bucket [100]int
		for range samples {
			code, err := otp.GenerateCode(src)
			if err != nil || !sixDigits.MatchString(code) {
				t.Fatalf("GenerateCode = %q, %v", code, err)
			}
			first[code[0]-'0']++
			last[code[5]-'0']++
			bucket[int(code[0]-'0')*10+int(code[1]-'0')]++
		}
		if x := chi2(first[:], samples); x > 60 { // df 9, p ~ 1e-9
			t.Fatalf("first-digit chi-square %.1f over threshold: %v", x, first)
		}
		if x := chi2(last[:], samples); x > 60 {
			t.Fatalf("last-digit chi-square %.1f over threshold: %v", x, last)
		}
		if x := chi2(bucket[:], samples); x > 200 { // df 99
			t.Fatalf("two-digit chi-square %.1f over threshold", x)
		}
	})
}

func chi2(counts []int, total int) float64 {
	exp := float64(total) / float64(len(counts))
	var x float64
	for _, c := range counts {
		d := float64(c) - exp
		x += d * d / exp
	}
	return x
}

func TestGenerateCode_BR_CLI_04_ReaderErrorsAreReturnedWithoutACode(t *testing.T) {
	boom := errors.New("entropy source down")
	for name, r := range map[string]io.Reader{
		"fails at once":    &failingReader{after: 0, err: boom},
		"fails mid-stream": &failingReader{after: 2, err: boom},
		"empty then EOF":   bytes.NewReader(nil),
		"short then EOF":   bytes.NewReader([]byte{1, 2}),
	} {
		t.Run(name, func(t *testing.T) {
			code, err := otp.GenerateCode(r)
			if err == nil {
				t.Fatalf("GenerateCode succeeded with %q from a failing reader", code)
			}
			if code != "" {
				t.Errorf("code = %q on error, want empty", code)
			}
			if name == "fails at once" && !errors.Is(err, boom) {
				t.Errorf("error %v does not wrap the reader error", err)
			}
		})
	}
}

// ---- digest ---------------------------------------------------------------------------------

func indexer(t testing.TB, b byte) crypto.BlindIndexer {
	t.Helper()
	d, err := crypto.NewBlindIndexer(bytes.Repeat([]byte{b}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestCodeDigest_BR_CLI_04_MatchesTheDocumentedConstruction(t *testing.T) {
	d := indexer(t, 0x21)
	ver, code := uuid.MustParse("0198a1b2-0000-7000-8000-000000000001"), uuid.MustParse("0198a1b2-0000-7000-8000-000000000002")
	want := d.Index("otp.code", []byte("signup|"+ver.String()+"|"+code.String()+"|123456"))
	got := otp.CodeDigest(d, otp.PurposeSignup, ver, code, "123456")
	if !bytes.Equal(got, want) || len(got) != 32 {
		t.Fatalf("digest = %x, want HMAC(key, otp.code 0x00 purpose|verification|code id|code) = %x", got, want)
	}
}

func TestCodeDigest_BR_CLI_04_BindsEveryComponent(t *testing.T) {
	d := indexer(t, 0x21)
	ver, cid := uuid.New(), uuid.New()
	base := otp.CodeDigest(d, otp.PurposeSignup, ver, cid, "123456")

	if !bytes.Equal(base, otp.CodeDigest(d, otp.PurposeSignup, ver, cid, "123456")) {
		t.Fatal("digest is not deterministic")
	}
	others := map[string][]byte{
		"code":          otp.CodeDigest(d, otp.PurposeSignup, ver, cid, "123457"),
		"purpose":       otp.CodeDigest(d, otp.PurposePasswordReset, ver, cid, "123456"),
		"verification":  otp.CodeDigest(d, otp.PurposeSignup, uuid.New(), cid, "123456"),
		"code id":       otp.CodeDigest(d, otp.PurposeSignup, ver, uuid.New(), "123456"),
		"key":           otp.CodeDigest(indexer(t, 0x22), otp.PurposeSignup, ver, cid, "123456"),
		"leading zeros": otp.CodeDigest(d, otp.PurposeSignup, ver, cid, "012345"),
	}
	for name, got := range others {
		if bytes.Equal(base, got) {
			t.Errorf("digest ignores the %s", name)
		}
	}
}

func TestCodeDigest_BR_CLI_04_PropertyNeverEchoesTheCode(t *testing.T) {
	d := indexer(t, 0x21)
	rapid.Check(t, func(t *rapid.T) {
		code := rapid.StringMatching(`[0-9]{6}`).Draw(t, "code")
		p := rapid.SampledFrom([]otp.Purpose{otp.PurposeSignup, otp.PurposeChangeEmail, otp.PurposeChangeMobile, otp.PurposePasswordReset}).Draw(t, "purpose")
		got := otp.CodeDigest(d, p, uuid.New(), uuid.New(), code)
		if len(got) != 32 || bytes.Contains(got, []byte(code)) {
			t.Fatalf("digest %x is not an opaque 32-byte value", got)
		}
	})
}
