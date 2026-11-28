package otp

import (
	"encoding/binary"
	"fmt"
	"io"

	"github.com/google/uuid"

	"github.com/NandanMaheta/swastik/apps/api/internal/platform/crypto"
)

const (
	codeDigits = 6
	codeSpace  = 1_000_000
	// codeLimit is the largest multiple of codeSpace below 2^32: samples at or above it are
	// rejected so every code is equally likely.
	codeLimit = (1 << 32) / codeSpace * codeSpace
)

// GenerateCode returns 6 uniformly random digits read from r (rejection sampling).
func GenerateCode(r io.Reader) (string, error) {
	var buf [4]byte
	for {
		if _, err := io.ReadFull(r, buf[:]); err != nil {
			return "", fmt.Errorf("otp: read random bytes: %w", err)
		}
		if n := binary.BigEndian.Uint32(buf[:]); n < codeLimit {
			return fmt.Sprintf("%0*d", codeDigits, n%codeSpace), nil
		}
	}
}

// CodeDigest is the stored form of a code (D-08, data-model section 2):
// HMAC-SHA-256 under OTP_HMAC_KEY of "otp.code" 0x00 purpose "|" verificationID "|" codeID "|" code,
// through the blind indexer (32 bytes). It binds the code to its verification, purpose and row.
// Callers compare digests with crypto/subtle.ConstantTimeCompare.
func CodeDigest(d crypto.BlindIndexer, p Purpose, verificationID, codeID uuid.UUID, code string) []byte {
	return d.Index("otp.code", []byte(string(p)+"|"+verificationID.String()+"|"+codeID.String()+"|"+code))
}
