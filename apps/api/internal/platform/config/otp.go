package config

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"

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
func (o OTPConfig) LogValue() slog.Value {
	return slog.GroupValue(
		slog.Bool("enabled", o.Enabled),
		slog.Bool("resend_key_set", o.ResendAPIKey != ""),
		slog.String("email_from", o.EmailFrom),
		slog.String("firebase_project_id", o.FirebaseProjectID),
		slog.Bool("firebase_jwks_override", o.FirebaseJWKSURL != ""),
	)
}

// loadOTP reads the OTP settings. Errors name variables and never show a value.
func loadOTP(appEnv string) (OTPConfig, error) {
	strict := appEnv == "staging" || appEnv == "production"
	o := OTPConfig{
		ResendAPIKey:      os.Getenv("RESEND_API_KEY"),
		EmailFrom:         os.Getenv("OTP_EMAIL_FROM"),
		FirebaseProjectID: os.Getenv("FIREBASE_PROJECT_ID"),
		FirebaseJWKSURL:   os.Getenv("FIREBASE_JWKS_URL"),
	}
	hmacRaw := os.Getenv("OTP_HMAC_KEY")

	if strict {
		if o.FirebaseJWKSURL != "" {
			return OTPConfig{}, errors.New("FIREBASE_JWKS_URL is not allowed in staging or production")
		}
		set := map[string]string{
			"RESEND_API_KEY": o.ResendAPIKey, "OTP_HMAC_KEY": hmacRaw,
			"OTP_EMAIL_FROM": o.EmailFrom, "FIREBASE_PROJECT_ID": o.FirebaseProjectID,
		}
		var missing []string
		for _, name := range []string{"RESEND_API_KEY", "OTP_HMAC_KEY", "OTP_EMAIL_FROM", "FIREBASE_PROJECT_ID"} {
			if set[name] == "" {
				missing = append(missing, name)
			}
		}
		switch len(missing) {
		case 0:
		case len(set):
			return OTPConfig{}, nil // OTP is off: operations answer otp.not_configured
		default:
			return OTPConfig{}, fmt.Errorf("OTP settings are partial; missing %s", strings.Join(missing, ", "))
		}
	}

	var key []byte
	if hmacRaw == "" {
		var err error
		if key, err = randomKey(); err != nil {
			return OTPConfig{}, err
		}
	} else {
		var err error
		if key, err = decodeKey(hmacRaw); err != nil {
			return OTPConfig{}, errors.New("OTP_HMAC_KEY must be standard base64 of exactly 32 bytes")
		}
	}
	digests, err := crypto.NewBlindIndexer(key)
	if err != nil {
		return OTPConfig{}, errors.New("OTP_HMAC_KEY must be exactly 32 bytes")
	}
	o.Digests, o.Enabled = digests, true
	return o, nil
}
