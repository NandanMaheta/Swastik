// Review-fix tests for the OTP settings (feature 004, D-08, FR-013): OTP_HMAC_KEY keys the digests of
// codes, limits and proof fingerprints, so it must be a key of its own. Reusing BLIND_INDEX_KEY (the
// email/mobile lookup index) or a PII encryption key would make one leak open two protections.
package config_test

import (
	"strings"
	"testing"

	"github.com/NandanMaheta/swastik/apps/api/internal/platform/config"
)

func TestOTPConfig_BR_CLI_04_HMACKeyMustDifferFromTheOtherKeys(t *testing.T) {
	for _, appEnv := range []string{"staging", "production"} {
		for name, shared := range map[string][]byte{
			"BLIND_INDEX_KEY":    blind,
			"a PII key (1)":      pii1,
			"the active PII key": pii2,
		} {
			t.Run(appEnv+"/equals "+name, func(t *testing.T) {
				setOTPEnv(t, with(otpGood(), "APP_ENV", appEnv, "OTP_HMAC_KEY", b64(shared)))
				_, err := config.Load()
				if err == nil {
					t.Fatalf("Load accepted an OTP_HMAC_KEY equal to %s", name)
				}
				if !strings.Contains(err.Error(), "OTP_HMAC_KEY") {
					t.Errorf("error %q does not name OTP_HMAC_KEY", err)
				}
				if strings.Contains(err.Error(), b64(shared)) {
					t.Errorf("error shows a key value: %q", err)
				}
			})
		}
	}
}

func TestOTPConfig_BR_CLI_04_AKeyOfItsOwnIsAccepted(t *testing.T) {
	setOTPEnv(t, with(otpGood(), "APP_ENV", "production"))
	if _, err := config.Load(); err != nil {
		t.Fatalf("Load with a distinct OTP_HMAC_KEY: %v", err)
	}
}
