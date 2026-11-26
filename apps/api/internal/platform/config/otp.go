package config

import (
	"log/slog"

	"github.com/NandanMaheta/swastik/apps/api/internal/platform/crypto"
)

// OTPConfig carries the settings of OTP delivery (feature 004). Staging and production set all of
// RESEND_API_KEY, OTP_HMAC_KEY, OTP_EMAIL_FROM and FIREBASE_PROJECT_ID, or none (Enabled false).
type OTPConfig struct {
	Enabled           bool
	Digests           crypto.BlindIndexer // OTP_HMAC_KEY
	ResendAPIKey      string              // never logged
	EmailFrom         string
	FirebaseProjectID string
	FirebaseJWKSURL   string // local and ci only
}

// LogValue implements slog.LogValuer: names and flags only, never a key.
func (OTPConfig) LogValue() slog.Value { return slog.GroupValue() }
