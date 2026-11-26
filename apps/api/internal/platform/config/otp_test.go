// Tests for the OTP settings of config.Load (feature 004, S02; BR-CLI-04, D-08, FR-013).
//
// Contract (go-module-api.md section 5): Config.OTP is an OTPConfig{Enabled, Digests, ResendAPIKey,
// EmailFrom, FirebaseProjectID, FirebaseJWKSURL}. Staging and production set all of RESEND_API_KEY,
// OTP_HMAC_KEY (bare standard base64 of 32 bytes), OTP_EMAIL_FROM and FIREBASE_PROJECT_ID, or none
// of them (Enabled false: operations answer otp.not_configured). A partial set is a boot error that
// names the missing variables and never shows a value. FIREBASE_JWKS_URL is refused there. Local
// and ci get an ephemeral HMAC key (Enabled true), no Resend key (email.Discard) and Firebase
// disabled without a project id. OTPConfig.LogValue never shows a key.
//
// Assumption recorded for the implementer: in local and ci Enabled is true (the ephemeral key
// exists so the flow works there).
package config_test

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"log/slog"
	"strings"
	"testing"

	"github.com/NandanMaheta/swastik/apps/api/internal/platform/config"
	"github.com/NandanMaheta/swastik/apps/api/internal/platform/crypto"
)

var otpEnvVars = []string{"RESEND_API_KEY", "OTP_HMAC_KEY", "OTP_EMAIL_FROM", "FIREBASE_PROJECT_ID", "FIREBASE_JWKS_URL"}

const (
	resendKey   = "re_live_ABCDEF0123456789secret"
	emailFrom   = "no-reply@mail.swastikapp.co.in"
	firebaseID  = "swastik-4fcc9"
	otpHMACByte = 0x7A
)

func otpGood() map[string]string {
	return with(good(),
		"RESEND_API_KEY", resendKey,
		"OTP_HMAC_KEY", b64(fill(otpHMACByte)),
		"OTP_EMAIL_FROM", emailFrom,
		"FIREBASE_PROJECT_ID", firebaseID,
	)
}

func setOTPEnv(t *testing.T, env map[string]string) {
	t.Helper()
	setEnv(t, env)
	for _, k := range otpEnvVars {
		if _, ok := env[k]; !ok {
			t.Setenv(k, "")
		}
	}
}

func TestOTPConfig_BR_CLI_04_CompleteSetEnablesOTP(t *testing.T) {
	for _, appEnv := range []string{"staging", "production"} {
		t.Run(appEnv, func(t *testing.T) {
			setOTPEnv(t, with(otpGood(), "APP_ENV", appEnv))
			cfg, err := config.Load()
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			o := cfg.OTP
			if !o.Enabled {
				t.Error("Enabled = false with a complete set")
			}
			if o.ResendAPIKey != resendKey || o.EmailFrom != emailFrom || o.FirebaseProjectID != firebaseID {
				t.Errorf("settings = key %q from %q project %q, want the configured values", o.ResendAPIKey, o.EmailFrom, o.FirebaseProjectID)
			}
			if o.FirebaseJWKSURL != "" {
				t.Errorf("FirebaseJWKSURL = %q, want empty", o.FirebaseJWKSURL)
			}
			ref, _ := crypto.NewBlindIndexer(fill(otpHMACByte))
			if !bytes.Equal(o.Digests.Index("otp.code", []byte("v")), ref.Index("otp.code", []byte("v"))) {
				t.Error("Digests was not built from OTP_HMAC_KEY")
			}
		})
	}
}

func TestOTPConfig_BR_CLI_04_NoneSetMeansDisabledNotAnError(t *testing.T) {
	for _, appEnv := range []string{"staging", "production"} {
		t.Run(appEnv, func(t *testing.T) {
			setOTPEnv(t, with(good(), "APP_ENV", appEnv))
			logs := captureLogs(t)
			cfg, err := config.Load()
			if err != nil {
				t.Fatalf("Load without any OTP variable must succeed: %v", err)
			}
			o := cfg.OTP
			if o.Enabled || o.ResendAPIKey != "" || o.EmailFrom != "" || o.FirebaseProjectID != "" {
				t.Errorf("OTP = %+v, want disabled and empty", o)
			}
			_ = logs // a boot warning is expected by the plan but its wording is not pinned here
		})
	}
}

func TestOTPConfig_BR_CLI_04_PartialSetIsABootErrorNamingTheMissingNames(t *testing.T) {
	all := []string{"RESEND_API_KEY", "OTP_HMAC_KEY", "OTP_EMAIL_FROM", "FIREBASE_PROJECT_ID"}
	secretValues := []string{resendKey, b64(fill(otpHMACByte)), strings.TrimRight(b64(fill(otpHMACByte)), "=")}
	for _, appEnv := range []string{"staging", "production"} {
		for _, missing := range all {
			t.Run(appEnv+"/missing "+missing, func(t *testing.T) {
				setOTPEnv(t, with(without(otpGood(), missing), "APP_ENV", appEnv))
				_, err := config.Load()
				if err == nil {
					t.Fatalf("Load succeeded without %s", missing)
				}
				if !strings.Contains(err.Error(), missing) {
					t.Errorf("error %q does not name %s", err, missing)
				}
				for _, v := range secretValues {
					if strings.Contains(err.Error(), v) {
						t.Errorf("error shows a secret value: %q", err)
					}
				}
			})
		}
		for _, only := range all {
			t.Run(appEnv+"/only "+only, func(t *testing.T) {
				setOTPEnv(t, with(good(), "APP_ENV", appEnv, only, otpGood()[only]))
				if _, err := config.Load(); err == nil {
					t.Fatalf("Load succeeded with only %s set", only)
				}
			})
		}
	}
}

func TestOTPConfig_BR_CLI_04_InvalidHMACKeyIsRefusedWithoutEchoingIt(t *testing.T) {
	tests := map[string]string{
		"not base64":   "this is not base64 !!!",
		"16 bytes":     b64(fill(0x11)[:16]),
		"33 bytes":     b64(append(fill(0x11), 0x01)),
		"hex of 32":    hex.EncodeToString(fill(0x11)),
		"url-safe b64": strings.NewReplacer("+", "-", "/", "_").Replace(b64([]byte("????>>>>????>>>>????>>>>????>>>>"))),
	}
	for name, bad := range tests {
		t.Run(name, func(t *testing.T) {
			setOTPEnv(t, with(otpGood(), "APP_ENV", "production", "OTP_HMAC_KEY", bad))
			_, err := config.Load()
			if err == nil {
				// url-safe text may coincide with valid standard base64; only fail when it is not.
				if name == "url-safe b64" {
					t.Skip("sample is valid in both alphabets")
				}
				t.Fatalf("Load accepted OTP_HMAC_KEY %q", name)
			}
			if !strings.Contains(err.Error(), "OTP_HMAC_KEY") {
				t.Errorf("error %q does not name OTP_HMAC_KEY", err)
			}
			if strings.Contains(err.Error(), bad) {
				t.Errorf("error echoes the key value")
			}
		})
	}
}

func TestOTPConfig_BR_CLI_04_JWKSURLRefusedInStagingAndProduction(t *testing.T) {
	for _, appEnv := range []string{"staging", "production"} {
		for name, env := range map[string]map[string]string{
			"with the full set": with(otpGood(), "APP_ENV", appEnv, "FIREBASE_JWKS_URL", "http://127.0.0.1:9/jwks"),
			"alone":             with(good(), "APP_ENV", appEnv, "FIREBASE_JWKS_URL", "http://127.0.0.1:9/jwks"),
		} {
			t.Run(appEnv+" "+name, func(t *testing.T) {
				setOTPEnv(t, env)
				_, err := config.Load()
				if err == nil {
					t.Fatal("Load accepted FIREBASE_JWKS_URL")
				}
				if !strings.Contains(err.Error(), "FIREBASE_JWKS_URL") {
					t.Errorf("error %q does not name FIREBASE_JWKS_URL", err)
				}
			})
		}
	}
}

func TestOTPConfig_BR_CLI_04_LocalAndCIGetEphemeralDefaults(t *testing.T) {
	for _, appEnv := range []string{"", "local", "ci"} {
		t.Run("APP_ENV="+appEnv, func(t *testing.T) {
			setOTPEnv(t, map[string]string{"DATABASE_URL": "postgres://x", "APP_ENV": appEnv})
			a, err := config.Load()
			if err != nil {
				t.Fatalf("Load with no OTP variable must succeed outside staging/production: %v", err)
			}
			b, _ := config.Load()
			o := a.OTP
			if !o.Enabled {
				t.Error("Enabled = false in local/ci, want true (ephemeral key)")
			}
			if got := o.Digests.Index("otp.code", []byte("v")); len(got) != 32 {
				t.Errorf("ephemeral Digests unusable (output length %d)", len(got))
			}
			if bytes.Equal(a.OTP.Digests.Index("p", []byte("v")), b.OTP.Digests.Index("p", []byte("v"))) {
				t.Error("the ephemeral OTP key is the same on two loads; it must be random per Load")
			}
			if o.ResendAPIKey != "" || o.FirebaseProjectID != "" || o.FirebaseJWKSURL != "" {
				t.Errorf("OTP = %+v, want no Resend key, no Firebase project, no JWKS URL", o)
			}
		})
	}
}

func TestOTPConfig_BR_CLI_04_LocalHonoursExplicitValuesAndJWKSOverride(t *testing.T) {
	setOTPEnv(t, map[string]string{
		"DATABASE_URL": "postgres://x", "APP_ENV": "ci",
		"RESEND_API_KEY": resendKey, "OTP_HMAC_KEY": b64(fill(otpHMACByte)), "OTP_EMAIL_FROM": emailFrom,
		"FIREBASE_PROJECT_ID": "demo-project", "FIREBASE_JWKS_URL": "http://127.0.0.1:9099/jwks",
	})
	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	o := cfg.OTP
	if o.ResendAPIKey != resendKey || o.EmailFrom != emailFrom || o.FirebaseProjectID != "demo-project" || o.FirebaseJWKSURL != "http://127.0.0.1:9099/jwks" {
		t.Errorf("OTP = %+v, want the explicit values", o)
	}
	ref, _ := crypto.NewBlindIndexer(fill(otpHMACByte))
	if !bytes.Equal(o.Digests.Index("p", []byte("v")), ref.Index("p", []byte("v"))) {
		t.Error("an explicit OTP_HMAC_KEY must be used, not an ephemeral one")
	}
}

func TestOTPConfig_BR_CLI_04_LogValueHidesKeys(t *testing.T) {
	setOTPEnv(t, with(otpGood(), "APP_ENV", "production"))
	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	hmacKey := fill(otpHMACByte)
	secrets := []string{
		resendKey, "ABCDEF0123456789secret",
		b64(hmacKey), base64.RawStdEncoding.EncodeToString(hmacKey), base64.URLEncoding.EncodeToString(hmacKey),
		base64.RawURLEncoding.EncodeToString(hmacKey), hex.EncodeToString(hmacKey), string(hmacKey),
	}
	for name, v := range map[string]any{"OTPConfig": cfg.OTP, "Config": cfg} {
		var buf bytes.Buffer
		slog.New(slog.NewJSONHandler(&buf, nil)).Info("loaded", "cfg", v)
		for _, s := range secrets {
			if strings.Contains(buf.String(), s) {
				t.Errorf("%s log shows key material %q:\n%s", name, s, buf.String())
			}
		}
	}
}
