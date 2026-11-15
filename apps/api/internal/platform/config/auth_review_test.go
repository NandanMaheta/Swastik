// Review-fix tests for the auth settings of config.Load (feature 003 review pass; owner decision
// 2026-11-15_proxy_key).
//
// API assumptions (the implementer must match these names):
//
//	AuthConfig.ProxySharedSecrets []string  // PROXY_SHARED_SECRETS split on commas, entries trimmed, in order
//
// PROXY_SHARED_SECRETS is a comma-separated list (two entries while a secret is being rotated).
// Each entry is at least 32 characters. The variable is required in staging and production and
// optional in local and ci (absent means no proxy key is trusted). Errors name the variable but
// never echo a secret; AuthConfig's LogValue never prints one. WEB_ORIGINS must be https in
// staging and production; plain http is accepted only in local and ci.
package config_test

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/NandanMaheta/swastik/apps/api/internal/platform/config"
)

func TestProxySecrets_ParsedAsATrimmedListInOrder(t *testing.T) {
	for _, appEnv := range []string{"staging", "production"} {
		t.Run(appEnv, func(t *testing.T) {
			setEnv(t, with(good(), "APP_ENV", appEnv, "PROXY_SHARED_SECRETS", " "+proxySecretA+" , "+proxySecretB+" "))
			cfg, err := config.Load()
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if got, want := cfg.Auth.ProxySharedSecrets, []string{proxySecretA, proxySecretB}; !equalStrings(got, want) {
				t.Errorf("ProxySharedSecrets = %q, want %q", got, want)
			}
		})
	}
}

func TestProxySecrets_SingleSecretIsAccepted(t *testing.T) {
	setEnv(t, with(good(), "APP_ENV", "production"))
	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := cfg.Auth.ProxySharedSecrets; !equalStrings(got, []string{proxySecretA}) {
		t.Errorf("ProxySharedSecrets = %q, want just the one secret", got)
	}
}

func TestProxySecrets_RequiredInStagingAndProduction(t *testing.T) {
	for _, appEnv := range []string{"staging", "production"} {
		for name, env := range map[string]map[string]string{
			"absent": without(good(), "PROXY_SHARED_SECRETS"),
			"empty":  with(good(), "PROXY_SHARED_SECRETS", ""),
			"blank":  with(good(), "PROXY_SHARED_SECRETS", "   "),
		} {
			t.Run(appEnv+" "+name, func(t *testing.T) {
				setEnv(t, with(env, "APP_ENV", appEnv))
				_, err := config.Load()
				if err == nil {
					t.Fatalf("Load succeeded in %s without PROXY_SHARED_SECRETS", appEnv)
				}
				if !strings.Contains(err.Error(), "PROXY_SHARED_SECRETS") {
					t.Errorf("error %q does not name PROXY_SHARED_SECRETS", err)
				}
			})
		}
	}
}

func TestProxySecrets_OptionalLocallyAndInCI(t *testing.T) {
	for _, appEnv := range []string{"local", "ci"} {
		t.Run(appEnv, func(t *testing.T) {
			setEnv(t, map[string]string{"DATABASE_URL": "postgres://u:p@h/db", "APP_ENV": appEnv})
			cfg, err := config.Load()
			if err != nil {
				t.Fatalf("Load without PROXY_SHARED_SECRETS in %s: %v", appEnv, err)
			}
			if len(cfg.Auth.ProxySharedSecrets) != 0 {
				t.Errorf("ProxySharedSecrets = %q, want none (no proxy key is trusted by default)", cfg.Auth.ProxySharedSecrets)
			}
		})
	}
	t.Run("a configured secret is still read locally", func(t *testing.T) {
		setEnv(t, map[string]string{"DATABASE_URL": "postgres://u:p@h/db", "APP_ENV": "local", "PROXY_SHARED_SECRETS": proxySecretA})
		cfg, err := config.Load()
		if err != nil || !equalStrings(cfg.Auth.ProxySharedSecrets, []string{proxySecretA}) {
			t.Fatalf("Load = %q, %v", cfg.Auth.ProxySharedSecrets, err)
		}
	})
}

func TestProxySecrets_InvalidValuesAreRejected(t *testing.T) {
	short31 := strings.Repeat("s", 31)
	tests := []struct{ name, value string }{
		{"31 characters", short31},
		{"one short entry among good ones", proxySecretA + "," + short31},
		{"empty entry", proxySecretA + ",," + proxySecretB},
		{"trailing comma", proxySecretA + ","},
		{"leading comma", "," + proxySecretA},
	}
	for _, tt := range tests {
		for _, appEnv := range []string{"production", "local"} {
			t.Run(tt.name+" in "+appEnv, func(t *testing.T) {
				setEnv(t, with(good(), "APP_ENV", appEnv, "PROXY_SHARED_SECRETS", tt.value))
				_, err := config.Load()
				if err == nil {
					t.Fatalf("Load accepted PROXY_SHARED_SECRETS=%q", tt.value)
				}
				if !strings.Contains(err.Error(), "PROXY_SHARED_SECRETS") {
					t.Errorf("error %q does not name PROXY_SHARED_SECRETS", err)
				}
				for _, secret := range []string{proxySecretA, proxySecretB, short31} {
					if strings.Contains(err.Error(), secret) {
						t.Errorf("error echoes a proxy secret: %v", err)
					}
				}
			})
		}
	}
}

func TestProxySecrets_Boundary32CharactersIsAccepted(t *testing.T) {
	setEnv(t, with(good(), "APP_ENV", "production", "PROXY_SHARED_SECRETS", strings.Repeat("k", 32)))
	if _, err := config.Load(); err != nil {
		t.Fatalf("a 32-character secret was rejected: %v", err)
	}
}

func TestProxySecrets_LogValueNeverPrintsASecret(t *testing.T) {
	setEnv(t, with(good(), "APP_ENV", "production", "PROXY_SHARED_SECRETS", proxySecretA+","+proxySecretB))
	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	for name, v := range map[string]any{"config": cfg, "auth": cfg.Auth, "config pointer": &cfg} {
		var buf bytes.Buffer
		slog.New(slog.NewJSONHandler(&buf, nil)).Info("loaded", name, v)
		slog.New(slog.NewTextHandler(&buf, nil)).Info("loaded", name, v)
		out := buf.String()
		for _, secret := range []string{proxySecretA, proxySecretB} {
			if strings.Contains(out, secret) || strings.Contains(out, secret[:20]) {
				t.Errorf("%s: log output contains a proxy secret: %s", name, out)
			}
		}
	}
}

func TestWebOrigins_MustBeHTTPSInStagingAndProduction(t *testing.T) {
	bad := []string{
		"http://admin.example.in",
		"https://admin.example.in,http://localhost:5173",
		"http://localhost:5173",
		"HTTP://admin.example.in",
	}
	for _, appEnv := range []string{"staging", "production"} {
		for _, origins := range bad {
			t.Run(appEnv+" "+origins, func(t *testing.T) {
				setEnv(t, with(good(), "APP_ENV", appEnv, "WEB_ORIGINS", origins))
				_, err := config.Load()
				if err == nil {
					t.Fatalf("Load accepted WEB_ORIGINS=%q in %s", origins, appEnv)
				}
				if !strings.Contains(err.Error(), "WEB_ORIGINS") {
					t.Errorf("error %q does not name WEB_ORIGINS", err)
				}
			})
		}
		t.Run(appEnv+" https list", func(t *testing.T) {
			setEnv(t, with(good(), "APP_ENV", appEnv, "WEB_ORIGINS", "https://admin.example.in,https://app.example.in:8443"))
			if _, err := config.Load(); err != nil {
				t.Fatalf("https origins rejected: %v", err)
			}
		})
	}
}

func TestWebOrigins_LocalhostHTTPAllowedLocallyAndInCI(t *testing.T) {
	for _, appEnv := range []string{"local", "ci"} {
		t.Run(appEnv, func(t *testing.T) {
			setEnv(t, with(good(), "APP_ENV", appEnv, "WEB_ORIGINS", "http://localhost:5173,https://admin.example.in"))
			cfg, err := config.Load()
			if err != nil {
				t.Fatalf("http://localhost rejected in %s: %v", appEnv, err)
			}
			if got, want := cfg.Auth.WebOrigins, []string{"http://localhost:5173", "https://admin.example.in"}; !equalStrings(got, want) {
				t.Errorf("WebOrigins = %q, want %q", got, want)
			}
		})
	}
}
