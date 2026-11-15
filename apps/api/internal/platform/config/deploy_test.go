// Deploy manifest contract (feature 003, retargeted by 027): OpenTofu owns the Cloud Run env vars
// and secrets (infra/tofu/modules/env/cloudrun.tf). Every setting config.Load requires in staging
// and production is supplied there: secrets only through secret_key_ref (Secret Manager), plain
// settings as env values, TRUSTED_PROXY_HOPS resolves to 1 (Cloud Run's front end appends one
// X-Forwarded-For entry), and PROXY_SHARED_SECRETS is never a plain value. deploy.yml only ships
// the image; its migration step gets only the migration database URL.
package config_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func repoFile(t *testing.T, parts ...string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(append([]string{"..", "..", "..", "..", ".."}, parts...)...))
	if err != nil {
		t.Fatalf("read %s: %v", filepath.Join(parts...), err)
	}
	return string(b)
}

func cloudRunTF(t *testing.T) string {
	return repoFile(t, "infra", "tofu", "modules", "env", "cloudrun.tf")
}

// block returns the text from the first occurrence of start to the matching end of its
// brace-delimited block.
func block(t *testing.T, doc, start string) string {
	t.Helper()
	i := strings.Index(doc, start)
	if i < 0 {
		t.Fatalf("cloudrun.tf has no %q", start)
	}
	depth, opened := 0, false
	for j := i; j < len(doc); j++ {
		switch doc[j] {
		case '{':
			depth++
			opened = true
		case '}':
			depth--
			if opened && depth == 0 {
				return doc[i : j+1]
			}
		}
	}
	t.Fatalf("unterminated block %q", start)
	return ""
}

// plainEnv is the plain_env map; secretEnv is the secret_env map; the Cloud Run service block is
// where secret_key_ref and the PROXY_SHARED_SECRETS env live.
func plainEnv(t *testing.T) string { return block(t, cloudRunTF(t), "plain_env = ") }
func secretEnv(t *testing.T) string {
	doc := cloudRunTF(t)
	i := strings.Index(doc, "secret_env = ")
	j := strings.Index(doc, `resource "google_cloud_run_v2_service"`)
	if i < 0 || j < i {
		t.Fatal("cloudrun.tf has no secret_env local")
	}
	return doc[i:j]
}
func service(t *testing.T) string {
	return block(t, cloudRunTF(t), `resource "google_cloud_run_v2_service" "api"`)
}

func TestDeploy_SecretsAreMountedFromSecretManager(t *testing.T) {
	svc := service(t)
	if !strings.Contains(svc, "secret_key_ref") {
		t.Fatal("cloudrun.tf mounts no secret_key_ref")
	}
	// The dynamic env block over secret_env must use value_source/secret_key_ref, not value.
	dyn := block(t, svc, `for_each = local.secret_env`)
	if !strings.Contains(dyn, "secret_key_ref") || regexp.MustCompile(`(?m)^\s*value\s*=`).MatchString(dyn) {
		t.Errorf("secret_env entries must be secret_key_ref only: %s", dyn)
	}
	secrets := secretEnv(t)
	for _, name := range []string{"DATABASE_URL", "JWT_SIGNING_KEYS", "PII_ENCRYPTION_KEYS", "BLIND_INDEX_KEY"} {
		if !regexp.MustCompile(`\b` + name + `\s*=\s*"[a-z_]+"`).MatchString(secrets) {
			t.Errorf("secret_env does not map %s to a Secret Manager secret: %s", name, secrets)
		}
	}
}

func TestDeploy_PlainSettingsAreSetAsEnvVars(t *testing.T) {
	plain := plainEnv(t)
	for _, name := range []string{
		"APP_ENV", "JWT_ACTIVE_KID", "PII_ACTIVE_KEY_ID", "WEB_ORIGINS", "TRUSTED_PROXY_HOPS",
		"TICK_AUTH", "TICK_AUDIENCE", "TICK_SERVICE_ACCOUNT",
	} {
		if !regexp.MustCompile(`(?m)^\s*` + name + `\s*=`).MatchString(plain) {
			t.Errorf("plain_env does not set %s: %s", name, plain)
		}
	}
	// None of the secrets may leak into plain env.
	for _, name := range []string{"DATABASE_URL", "JWT_SIGNING_KEYS", "PII_ENCRYPTION_KEYS", "BLIND_INDEX_KEY", "PROXY_SHARED_SECRETS"} {
		if strings.Contains(plain, name) {
			t.Errorf("secret %s is in plain_env", name)
		}
	}
}

func TestDeploy_TrustedProxyHopsIsOne(t *testing.T) {
	if !regexp.MustCompile(`TRUSTED_PROXY_HOPS\s*=\s*var\.trusted_proxy_hops`).MatchString(plainEnv(t)) &&
		!regexp.MustCompile(`TRUSTED_PROXY_HOPS\s*=\s*"1"`).MatchString(plainEnv(t)) {
		t.Fatal("plain_env must set TRUSTED_PROXY_HOPS from var.trusted_proxy_hops or \"1\"")
	}
	vars := repoFile(t, "infra", "tofu", "modules", "env", "variables.tf")
	v := block(t, vars, `variable "trusted_proxy_hops"`)
	if !regexp.MustCompile(`default\s*=\s*"1"`).MatchString(v) {
		t.Errorf("trusted_proxy_hops must default to \"1\": %s", v)
	}
}

func TestDeploy_ProxySharedSecretsIsASecretNeverAPlainValue(t *testing.T) {
	if strings.Contains(plainEnv(t), "PROXY_SHARED_SECRETS") {
		t.Error("PROXY_SHARED_SECRETS is in plain_env; it must come from Secret Manager")
	}
	var env string
	svc := service(t)
	i := strings.Index(svc, `name = "PROXY_SHARED_SECRETS"`)
	if i < 0 {
		t.Fatal("cloudrun.tf does not set PROXY_SHARED_SECRETS")
	}
	env = svc[i:]
	if j := strings.Index(env, "}\n        }\n      }"); j > 0 {
		env = env[:j]
	}
	if !strings.Contains(env, "secret_key_ref") {
		t.Errorf("PROXY_SHARED_SECRETS is not a secret_key_ref: %s", env)
	}
	if regexp.MustCompile(`(?m)^\s*value\s*=`).MatchString(env) {
		t.Errorf("PROXY_SHARED_SECRETS has a plain value: %s", env)
	}
}

// The migration step reads only DATABASE_URL (LoadDB) and must not be given application secrets.
func TestDeploy_MigrateJobGetsOnlyTheDatabaseSecret(t *testing.T) {
	doc := repoFile(t, ".github", "workflows", "deploy.yml")
	i := strings.Index(doc, "name: Apply migrations")
	if i < 0 {
		t.Fatal("deploy.yml has no migration step")
	}
	step := doc[i+1:]
	if j := strings.Index(step, "\n      - name:"); j > 0 {
		step = step[:j]
	}
	if !strings.Contains(step, "MIGRATE_DATABASE_URL") {
		t.Errorf("migration step does not use MIGRATE_DATABASE_URL: %s", step)
	}
	for _, name := range []string{"PROXY_SHARED_SECRETS", "JWT_SIGNING_KEYS", "PII_ENCRYPTION_KEYS", "BLIND_INDEX_KEY"} {
		if strings.Contains(step, name) {
			t.Errorf("the migration step is given application secret %s: %s", name, step)
		}
	}
}
