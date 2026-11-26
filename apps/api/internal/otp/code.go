package otp

import (
	"io"

	"github.com/google/uuid"

	"github.com/NandanMaheta/swastik/apps/api/internal/platform/crypto"
)

// GenerateCode returns 6 uniformly random digits read from r (rejection sampling).
func GenerateCode(_ io.Reader) (string, error) { return "", errNotImplemented }

// CodeDigest is the stored form of a code (D-08, data-model section 2):
// HMAC-SHA-256 under OTP_HMAC_KEY of "otp.code" 0x00 purpose "|" verificationID "|" codeID "|" code,
// through the blind indexer (32 bytes). It binds the code to its verification, purpose and row.
func CodeDigest(_ crypto.BlindIndexer, _ Purpose, _, _ uuid.UUID, _ string) []byte {
	panic(errNotImplemented)
}
