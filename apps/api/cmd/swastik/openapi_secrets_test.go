package main

// S20 - SC-006 / FR-091 for the published contract: no example, default, enum or description in the
// generated OpenAPI document, nor in the hand-written contract it came from, carries a real
// credential. Credentials appear only as shapes ("drt_…"), never as values: a token with its
// prefix and a body, a JWT, an authenticator secret or an otpauth URI with a secret in it.

import (
	"encoding/json"
	"os"
	"regexp"
	"strings"
	"testing"
)

// credentialShapes are values a real credential would have, but a documentation placeholder would not.
var credentialShapes = map[string]*regexp.Regexp{
	"refresh token":          regexp.MustCompile(`drt_[A-Za-z0-9_-]{16,}`),
	"challenge token":        regexp.MustCompile(`dmc_[A-Za-z0-9_-]{16,}`),
	"JWT":                    regexp.MustCompile(`eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}`),
	"authenticator secret":   regexp.MustCompile(`\b[A-Z2-7]{26,}\b`),
	"otpauth secret":         regexp.MustCompile(`otpauth://[^\s"]*[?&]secret=[A-Za-z0-9]{8,}`),
	"recovery code":          regexp.MustCompile(`\b[0-9A-HJKMNP-TV-Z]{4}(-[0-9A-HJKMNP-TV-Z]{4}){3}\b`),
	"bearer value":           regexp.MustCompile(`(?i)bearer\s+[A-Za-z0-9._-]{24,}`),
	"password-like example":  regexp.MustCompile(`(?i)"(password|current_password|new_password)"\s*:\s*"[^"]{4,}"`),
	"private key or seed":    regexp.MustCompile(`(?i)(-----BEGIN [A-Z ]*PRIVATE KEY|[0-9a-f]{64})`),
	"raw credential literal": regexp.MustCompile(`(?i)(access_token|refresh_token|challenge_token)"\s*:\s*"[^"]{12,}"`),
}

func scanShapes(t *testing.T, where, text string) {
	t.Helper()
	for name, re := range credentialShapes {
		if loc := re.FindStringIndex(text); loc != nil {
			t.Errorf("%s contains what looks like a %s (at offset %d)", where, name, loc[0])
		}
	}
}

// documentedValues collects every example, examples, default, const and enum value of a JSON tree.
func documentedValues(v any, key string, out *[]string) {
	switch x := v.(type) {
	case map[string]any:
		for k, val := range x {
			documentedValues(val, k, out)
		}
	case []any:
		for _, val := range x {
			documentedValues(val, key, out)
		}
	default:
		switch key {
		case "example", "examples", "default", "const", "enum":
			b, _ := json.Marshal(x)
			*out = append(*out, string(b))
		}
	}
}

func TestOpenAPI_SC006_NoCredentialsInExamplesOrDescriptions(t *testing.T) {
	doc := openAPIJSON(t)
	b, err := json.MarshalIndent(doc, "", " ")
	if err != nil {
		t.Fatal(err)
	}
	scanShapes(t, "the generated OpenAPI document", string(b))

	var values []string
	documentedValues(doc, "", &values)
	for _, v := range values {
		scanShapes(t, "the documented value "+v, v)
	}
}

func TestOpenAPI_SC006_TheContractFileCarriesNoCredentials(t *testing.T) {
	b, err := os.ReadFile("../../../../specs/003-auth-core/contracts/openapi-auth.yaml")
	if err != nil {
		t.Fatalf("read contract: %v", err)
	}
	text := string(b)
	if !strings.Contains(text, "auth-sign-in") {
		t.Fatalf("the contract file does not look like openapi-auth.yaml")
	}
	scanShapes(t, "contracts/openapi-auth.yaml", text)
}

// The detector itself must see what it is meant to see.
func TestOpenAPI_SC006_TheScannerRecognisesCredentials(t *testing.T) {
	for name, sample := range map[string]string{
		"refresh token":        "drt_WnqU4uvK0BZ7tgMA5-ZWSro-uHT7jRaVCVM5ir8GcII",
		"challenge token":      "dmc_WnqU4uvK0BZ7tgMA5-ZWSro-uHT7jRaVCVM5ir8GcII",
		"JWT":                  "eyJhbGciOiJFZERTQSIs.eyJhdWQiOiJzd2FzdGlr",
		"authenticator secret": "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP",
		"otpauth secret":       "otpauth://totp/Swastik:a@b.c?secret=JBSWY3DPEHPK3PXP&issuer=Swastik",
		"recovery code":        "7K2M-XQ4D-9HPT-B3ZV",
	} {
		re := credentialShapes[name]
		if re == nil || !re.MatchString(sample) {
			t.Errorf("the %s pattern does not match its sample %q", name, sample)
		}
	}
}
