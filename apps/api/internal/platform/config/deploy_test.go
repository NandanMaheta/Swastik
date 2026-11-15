// Deploy manifest contract (review fix, feature 003): every setting that config.Load requires in
// staging and production is supplied by .github/workflows/deploy.yml, secrets through
// --set-secrets (Secret Manager) and plain settings through --set-env-vars, and the proxy
// settings are present: TRUSTED_PROXY_HOPS=1 (Cloud Run's front end appends one X-Forwarded-For
// entry) and PROXY_SHARED_SECRETS as a secret, never as a plain value.
package config_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func deployYAML(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "..", ".github", "workflows", "deploy.yml"))
	if err != nil {
		t.Fatalf("read deploy.yml: %v", err)
	}
	return string(b)
}

// flagValue returns the value of a gcloud flag on the swastik-api deploy command.
func flagValue(t *testing.T, doc, flag string) string {
	t.Helper()
	i := strings.Index(doc, "gcloud run deploy swastik-api")
	if i < 0 {
		t.Fatal("deploy.yml has no `gcloud run deploy swastik-api` step")
	}
	rest := doc[i:]
	if j := strings.Index(rest, "gcloud run deploy swastik-worker"); j > 0 {
		rest = rest[:j]
	}
	m := regexp.MustCompile(regexp.QuoteMeta(flag) + `\s+("[^"]*"|\S+)`).FindStringSubmatch(rest)
	if m == nil {
		t.Fatalf("the swastik-api deploy has no %s flag", flag)
	}
	return strings.Trim(m[1], `"`)
}

func TestDeploy_SecretsAreMountedFromSecretManager(t *testing.T) {
	secrets := flagValue(t, deployYAML(t), "--set-secrets")
	for _, name := range []string{
		"DATABASE_URL", "JWT_SIGNING_KEYS", "PII_ENCRYPTION_KEYS", "BLIND_INDEX_KEY", "PROXY_SHARED_SECRETS",
	} {
		if !regexp.MustCompile(`(^|,)` + name + `=[A-Za-z0-9_-]+:[A-Za-z0-9_]+(,|$)`).MatchString(secrets) {
			t.Errorf("--set-secrets does not map %s to a Secret Manager secret: %s", name, secrets)
		}
	}
}

func TestDeploy_PlainSettingsAreSetAsEnvVars(t *testing.T) {
	envs := flagValue(t, deployYAML(t), "--set-env-vars")
	for _, name := range []string{"APP_ENV", "JWT_ACTIVE_KID", "PII_ACTIVE_KEY_ID", "WEB_ORIGINS", "TRUSTED_PROXY_HOPS"} {
		if !strings.Contains(envs, name+"=") {
			t.Errorf("--set-env-vars does not set %s: %s", name, envs)
		}
	}
}

func TestDeploy_TrustedProxyHopsIsOne(t *testing.T) {
	envs := flagValue(t, deployYAML(t), "--set-env-vars")
	if !regexp.MustCompile(`(^|[;,"^])TRUSTED_PROXY_HOPS=1($|[;,"])`).MatchString(envs) {
		t.Errorf("--set-env-vars must set TRUSTED_PROXY_HOPS=1 exactly: %s", envs)
	}
}

func TestDeploy_ProxySharedSecretsIsASecretNeverAPlainValue(t *testing.T) {
	doc := deployYAML(t)
	if envs := flagValue(t, doc, "--set-env-vars"); strings.Contains(envs, "PROXY_SHARED_SECRETS") {
		t.Errorf("PROXY_SHARED_SECRETS is a plain env var; it must come from --set-secrets: %s", envs)
	}
	if !strings.Contains(flagValue(t, doc, "--set-secrets"), "PROXY_SHARED_SECRETS=") {
		t.Error("--set-secrets does not reference PROXY_SHARED_SECRETS")
	}
}

// The migrate job reads only DATABASE_URL (LoadDB) and must not be given application secrets.
func TestDeploy_MigrateJobGetsOnlyTheDatabaseSecret(t *testing.T) {
	doc := deployYAML(t)
	i := strings.Index(doc, "gcloud run jobs deploy swastik-migrate")
	if i < 0 {
		t.Fatal("deploy.yml has no migrate job")
	}
	line := doc[i:]
	if j := strings.Index(line, "gcloud run deploy swastik-api"); j > 0 {
		line = line[:j]
	}
	if strings.Contains(line, "PROXY_SHARED_SECRETS") || strings.Contains(line, "JWT_SIGNING_KEYS") {
		t.Errorf("the migrate job is given application secrets: %s", line)
	}
}
