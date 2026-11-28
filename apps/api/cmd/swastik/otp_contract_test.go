package main

// S16 - the 004 OpenAPI contract and wiring (plan "API operations", contracts/otp.openapi.yaml,
// contracts/error-codes.md; FR-009, FR-016, constitution V). buildAPI(deps{}) must register the ten
// operations without a Service, like the auth module, so the static walk and `swastik openapi`
// run without a database. The 401/403 runtime walk of contract_test.go covers the four /v1/me/*
// operations as soon as they are registered. contract_test.go's public allowlist now holds the six
// public operations; deps.OTP, registerOTPJobs and registerOTPSenders are the wiring seams.

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"os"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/danielgtaylor/huma/v2/humatest"
	"github.com/google/uuid"

	"github.com/NandanMaheta/swastik/apps/api/internal/otp"
	"github.com/NandanMaheta/swastik/apps/api/internal/otp/otptest"
	"github.com/NandanMaheta/swastik/apps/api/internal/outbox"
	"github.com/NandanMaheta/swastik/apps/api/internal/scheduler"
)

type otpOp struct {
	id, path string
	public   bool
	retry    bool // documents a 429 with Retry-After
}

var otpOperations = []otpOp{
	{"verification-status", "/v1/verifications/status", true, false},
	{"verification-resend", "/v1/verifications/resend", true, true},
	{"verification-verify-email", "/v1/verifications/verify-email", true, true},
	{"verification-verify-mobile", "/v1/verifications/verify-mobile", true, true},
	{"password-reset-start", "/v1/password-reset/start", true, true},
	{"password-reset-complete", "/v1/password-reset/complete", true, true},
	{"my-verification-status", "/v1/me/verifications/status", false, false},
	{"my-verification-resend", "/v1/me/verifications/resend", false, true},
	{"my-verification-verify-email", "/v1/me/verifications/verify-email", false, true},
	{"my-verification-verify-mobile", "/v1/me/verifications/verify-mobile", false, true},
}

func otpWalked(t *testing.T) map[string]walkedOp {
	t.Helper()
	got := map[string]walkedOp{}
	for _, o := range staticAPI(t) {
		for _, want := range otpOperations {
			if o.ID == want.id {
				got[o.ID] = o
			}
		}
		if strings.HasPrefix(o.Path, "/v1/verifications/") || strings.HasPrefix(o.Path, "/v1/password-reset/") || strings.HasPrefix(o.Path, "/v1/me/verifications/") {
			if _, ok := got[o.ID]; !ok {
				t.Errorf("unexpected operation %s %s under the otp surface", o.Method, o.Path)
			}
		}
	}
	return got
}

func TestOTPContract_TenOperationsWithMethodPathAndSecurity(t *testing.T) {
	got := otpWalked(t)
	for _, want := range otpOperations {
		o, ok := got[want.id]
		if !ok {
			t.Errorf("operation %s is not registered", want.id)
			continue
		}
		if o.Method != http.MethodPost || o.Path != want.path {
			t.Errorf("%s = %s %s, want POST %s", want.id, o.Method, o.Path, want.path)
		}
		scheme, roles := schemeOf(o)
		switch {
		case want.public && (o.Security == nil || len(o.Security) != 0):
			t.Errorf("%s: security = %v, want an explicit empty list (public, FR-030 allowlist)", want.id, o.Security)
		case !want.public && (scheme != "bearer" || !slices.Equal(roles, []string{"client"})):
			t.Errorf("%s: security = %s %v, want bearer [client]", want.id, scheme, roles)
		}
		if o.Op.Metadata["idempotency"] != "exempt" {
			t.Errorf("%s: Metadata[idempotency] = %v, want \"exempt\" (plan Complexity Tracking: credential-like operations)", want.id, o.Op.Metadata["idempotency"])
		}
		if len(o.Op.Parameters) != 0 || strings.ContainsAny(o.Path, "{}") {
			t.Errorf("%s: handles, codes and tokens travel in the JSON body, never in the URL", want.id)
		}
	}
	if len(got) != len(otpOperations) {
		t.Errorf("registered otp operations = %d, want %d", len(got), len(otpOperations))
	}
}

func TestOTPContract_NoOperationMentionsASecretInItsPathOrId(t *testing.T) {
	for _, o := range staticAPI(t) {
		if strings.Contains(o.Path, "{") && (strings.Contains(o.Path, "verification") || strings.Contains(o.Path, "password-reset")) {
			t.Errorf("%s %s has a path parameter", o.Method, o.Path)
		}
	}
}

// ---- schemas against contracts/otp.openapi.yaml -----------------------------------------------

type wantSchema struct {
	props, required []string
	patterns        map[string]string // property -> pattern
	maxLen          map[string]int
	minLen          map[string]int
	enums           map[string][]string
	noExtra         bool // additionalProperties: false (requests)
}

var (
	handlePattern = `^ovh_[A-Za-z0-9_-]{43}$`
	tokenPattern  = `^prt_[A-Za-z0-9_-]{43}$`
)

var otpRequestSchemas = map[string]wantSchema{
	"handle": {props: []string{"handle"}, required: []string{"handle"}, patterns: map[string]string{"handle": handlePattern}, noExtra: true},
	"verify-email": {props: []string{"handle", "code"}, required: []string{"handle", "code"},
		patterns: map[string]string{"handle": handlePattern, "code": `^[0-9]{6}$`}, noExtra: true},
	"verify-mobile": {props: []string{"handle", "firebase_id_token"}, required: []string{"handle", "firebase_id_token"},
		patterns: map[string]string{"handle": handlePattern}, maxLen: map[string]int{"firebase_id_token": 4096}, minLen: map[string]int{"firebase_id_token": 1}, noExtra: true},
	"reset-start": {props: []string{"identifier"}, required: []string{"identifier"},
		maxLen: map[string]int{"identifier": 254}, minLen: map[string]int{"identifier": 1}, noExtra: true},
	"reset-complete": {props: []string{"handle", "reset_token", "new_password"}, required: []string{"handle", "reset_token", "new_password"},
		patterns: map[string]string{"handle": handlePattern, "reset_token": tokenPattern}, maxLen: map[string]int{"new_password": 1024}, noExtra: true},
}

var otpResponseSchemas = map[string]wantSchema{
	"status": {props: []string{"purpose", "state", "expires_at", "email", "mobile"}, required: []string{"purpose", "state", "expires_at"},
		enums: map[string][]string{"purpose": {"signup", "change_email", "change_mobile", "password_reset"}, "state": {"open", "completed", "expired", "cancelled"}}},
	"resend":       {props: []string{"next_resend_at", "code_expires_at"}, required: []string{"next_resend_at", "code_expires_at"}},
	"verify-email": {props: []string{"verification", "reset_token", "reset_token_expires_at"}, required: []string{"verification"}},
	"reset-start":  {props: []string{"handle", "expires_at", "next_resend_at"}, required: []string{"handle", "expires_at", "next_resend_at"}},
	"contact": {props: []string{"state", "masked", "next_resend_at", "code_expires_at"}, required: []string{"state"},
		enums: map[string][]string{"state": {"pending", "verified", "proved", "expired"}}},
}

// otpRequestKinds and otpResponseKinds map each operation to the schema it must use.
var otpRequestKinds = map[string]string{
	"verification-status": "handle", "verification-resend": "handle", "verification-verify-email": "verify-email",
	"verification-verify-mobile": "verify-mobile", "password-reset-start": "reset-start", "password-reset-complete": "reset-complete",
	"my-verification-status": "handle", "my-verification-resend": "handle", "my-verification-verify-email": "verify-email",
	"my-verification-verify-mobile": "verify-mobile",
}

var otpResponseKinds = map[string]struct {
	code, kind string
}{
	"verification-status": {"200", "status"}, "verification-resend": {"202", "resend"}, "verification-verify-email": {"200", "verify-email"},
	"verification-verify-mobile": {"200", "status"}, "password-reset-start": {"202", "reset-start"}, "password-reset-complete": {"204", ""},
	"my-verification-status": {"200", "status"}, "my-verification-resend": {"202", "resend"}, "my-verification-verify-email": {"200", "verify-email"},
	"my-verification-verify-mobile": {"200", "status"},
}

// resolve follows one $ref of the document.
func resolve(t *testing.T, doc, node map[string]any) map[string]any {
	t.Helper()
	ref, ok := node["$ref"].(string)
	if !ok {
		return node
	}
	name := strings.TrimPrefix(ref, "#/components/schemas/")
	return at(t, doc, "components", "schemas", name).(map[string]any)
}

func jsonSchema(t *testing.T, doc map[string]any, content any) map[string]any {
	t.Helper()
	c, ok := content.(map[string]any)
	if !ok {
		t.Fatalf("no content: %v", content)
	}
	media, ok := c["application/json"].(map[string]any)
	if !ok {
		t.Fatalf("no application/json media type in %v", c)
	}
	return resolve(t, doc, media["schema"].(map[string]any))
}

func checkSchema(t *testing.T, doc map[string]any, where string, schema map[string]any, w wantSchema) {
	t.Helper()
	props, _ := schema["properties"].(map[string]any)
	var got []string
	for k := range props {
		if k != "$schema" {
			got = append(got, k)
		}
	}
	sort.Strings(got)
	want := slices.Clone(w.props)
	sort.Strings(want)
	if !slices.Equal(got, want) {
		t.Errorf("%s: properties = %v, want %v (contracts/otp.openapi.yaml)", where, got, want)
	}
	var req []string
	for _, r := range schema["required"].([]any) {
		req = append(req, r.(string))
	}
	sort.Strings(req)
	wantReq := slices.Clone(w.required)
	sort.Strings(wantReq)
	if !slices.Equal(req, wantReq) {
		t.Errorf("%s: required = %v, want %v", where, req, wantReq)
	}
	if w.noExtra && schema["additionalProperties"] != false {
		t.Errorf("%s: additionalProperties = %v, want false", where, schema["additionalProperties"])
	}
	for name, pattern := range w.patterns {
		if p, _ := resolve(t, doc, props[name].(map[string]any))["pattern"].(string); p != pattern {
			t.Errorf("%s.%s: pattern = %q, want %q", where, name, p, pattern)
		}
	}
	num := func(m map[string]any, key string) float64 { v, _ := m[key].(float64); return v }
	for name, n := range w.maxLen {
		if got := num(resolve(t, doc, props[name].(map[string]any)), "maxLength"); int(got) != n {
			t.Errorf("%s.%s: maxLength = %v, want %d", where, name, got, n)
		}
	}
	for name, n := range w.minLen {
		if got := num(resolve(t, doc, props[name].(map[string]any)), "minLength"); int(got) != n {
			t.Errorf("%s.%s: minLength = %v, want %d", where, name, got, n)
		}
	}
	for name, values := range w.enums {
		var got []string
		for _, v := range resolve(t, doc, props[name].(map[string]any))["enum"].([]any) {
			got = append(got, v.(string))
		}
		sort.Strings(got)
		wantEnum := slices.Clone(values)
		sort.Strings(wantEnum)
		if !slices.Equal(got, wantEnum) {
			t.Errorf("%s.%s: enum = %v, want %v", where, name, got, wantEnum)
		}
	}
}

func TestOTPContract_RequestAndResponseSchemasMatchTheContract(t *testing.T) {
	doc := openAPIJSON(t)
	for _, op := range otpOperations {
		item := at(t, doc, "paths", op.path, "post").(map[string]any)
		checkSchema(t, doc, op.id+" request", jsonSchema(t, doc, at(t, item, "requestBody", "content").(map[string]any)), otpRequestSchemas[otpRequestKinds[op.id]])
		want := otpResponseKinds[op.id]
		resp, ok := at(t, item, "responses").(map[string]any)[want.code].(map[string]any)
		if !ok {
			t.Errorf("%s: no %s response documented", op.id, want.code)
			continue
		}
		if want.kind == "" {
			if _, has := resp["content"]; has {
				t.Errorf("%s: a %s response must have no body", op.id, want.code)
			}
			continue
		}
		checkSchema(t, doc, op.id+" response", jsonSchema(t, doc, resp["content"]), otpResponseSchemas[want.kind])
	}
	// The nested objects the replies share.
	status := jsonSchema(t, doc, at(t, doc, "paths", "/v1/verifications/status", "post", "responses", "200", "content"))
	for _, c := range []string{"email", "mobile"} {
		checkSchema(t, doc, "ContactStatus "+c, resolve(t, doc, status["properties"].(map[string]any)[c].(map[string]any)), otpResponseSchemas["contact"])
	}
}

func TestOTPContract_ErrorsAreDocumentedWithRetryAfterWhereTheContractSaysSo(t *testing.T) {
	doc := openAPIJSON(t)
	props := at(t, doc, "components", "schemas", "ErrorModel", "properties").(map[string]any)
	if ra, ok := props["retry_after_seconds"].(map[string]any); !ok || ra["type"] != "integer" {
		t.Errorf("ErrorModel.retry_after_seconds = %v, want an additive integer property", props["retry_after_seconds"])
	}
	for _, op := range otpOperations {
		responses := at(t, doc, "paths", op.path, "post", "responses").(map[string]any)
		r429, ok := responses["429"].(map[string]any)
		if !ok {
			t.Errorf("%s: no 429 response documented", op.id)
			continue
		}
		if op.retry {
			if _, has := r429["headers"].(map[string]any)["Retry-After"]; !has {
				t.Errorf("%s: the 429 response does not document the Retry-After header", op.id)
			}
		}
	}
}

func TestOTPContract_FileAndDocumentCarryNoHandleTokenOrCodeValues(t *testing.T) {
	b, err := os.ReadFile("../../../../specs/004-otp-delivery/contracts/otp.openapi.yaml")
	if err != nil {
		t.Fatalf("read contract: %v", err)
	}
	for _, id := range otpOperationIDs() {
		if !strings.Contains(string(b), "operationId: "+id) {
			t.Errorf("contracts/otp.openapi.yaml lacks operationId %s: this test table and the contract must agree", id)
		}
	}
	shapes := map[string]*regexp.Regexp{
		"handle value":      regexp.MustCompile(`ovh_[A-Za-z0-9_-]{20,}`),
		"reset token value": regexp.MustCompile(`prt_[A-Za-z0-9_-]{20,}`),
		"six-digit code":    regexp.MustCompile(`(?i)(example|default|const)s?"?:\s*\[?"?[0-9]{6}"?`),
		"password example":  regexp.MustCompile(`(?i)"new_password"\s*:\s*"[^"]{4,}"`),
	}
	doc, err := json.MarshalIndent(openAPIJSON(t), "", " ")
	if err != nil {
		t.Fatal(err)
	}
	for name, re := range shapes {
		if re.Match(b) {
			t.Errorf("contracts/otp.openapi.yaml carries a %s", name)
		}
		if re.Match(doc) {
			t.Errorf("the generated document carries a %s", name)
		}
	}
	var values []string
	documentedValues(openAPIJSON(t), "", &values)
	for _, v := range values {
		for name, re := range shapes {
			if re.MatchString(v) || regexp.MustCompile(`^"[0-9]{6}"$`).MatchString(v) {
				t.Errorf("the documented value %s looks like a %s", v, name)
			}
		}
	}
}

func otpOperationIDs() []string {
	var ids []string
	for _, o := range otpOperations {
		ids = append(ids, o.id)
	}
	return ids
}

func TestOTPContract_CommandBuildsTheDocumentWithZeroDependencies(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://nobody:nothing@127.0.0.1:1/none?connect_timeout=1")
	t.Setenv("APP_ENV", "production")
	t.Setenv("RESEND_API_KEY", "")
	t.Setenv("OTP_HMAC_KEY", "")
	t.Setenv("FIREBASE_PROJECT_ID", "")
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	out := openAPIFromCommand(t)
	for _, id := range otpOperationIDs() {
		if !strings.Contains(out, "operationId: "+id) {
			t.Errorf("`swastik openapi` output has no operation %s", id)
		}
	}
}

func TestOTPContract_ErrorsCarryStableCodesThroughBuildAPI(t *testing.T) {
	e := otptest.NewEnv(t)
	api := humatest.Wrap(t, buildAPI(deps{Auth: e.Auth, OTP: e.Svc, TrustedProxyHops: 1}))
	rec := api.Post("/v1/verifications/status", "X-Forwarded-For: 203.0.113.9", map[string]any{"handle": "ovh_" + strings.Repeat("Q", 43)})
	if rec.Code != http.StatusNotFound || problemCode(t, rec) != "otp.verification_invalid" {
		t.Errorf("unknown handle through buildAPI: %d %s, want 404 otp.verification_invalid", rec.Code, rec.Body.String())
	}
	rec = api.Post("/v1/verifications/status", "X-Forwarded-For: 203.0.113.9", map[string]any{"handle": "short"})
	if rec.Code != http.StatusUnprocessableEntity || problemCode(t, rec) != "validation_failed" {
		t.Errorf("malformed handle: %d %s, want 422 validation_failed", rec.Code, rec.Body.String())
	}
	rec = api.Post("/v1/me/verifications/status", "X-Forwarded-For: 203.0.113.9", map[string]any{"handle": "ovh_" + strings.Repeat("Q", 43)})
	if rec.Code != http.StatusUnauthorized || problemCode(t, rec) != "auth.unauthenticated" {
		t.Errorf("/v1/me without a session: %d %s, want 401 auth.unauthenticated", rec.Code, rec.Body.String())
	}
}

func TestWiring_OTPBuildAPIRegistersTheOperationsWithoutAnyDependency(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("buildAPI(deps{}) panicked: %v", r)
		}
	}()
	if got := otpWalked(t); len(got) != len(otpOperations) {
		t.Errorf("otp operations registered with deps{} = %d, want %d", len(got), len(otpOperations))
	}
}

// ---- wiring -------------------------------------------------------------------------------------

func TestWiring_OTPSendersAreRegisteredForBothTopicsWithThreeAttempts(t *testing.T) {
	e := otptest.NewEnv(t)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	ob := outbox.New(e.Tx, e.Clock.Now, log, outbox.DefaultOptions())
	registerOTPSenders(ob, e.Svc)

	add := func(topic, key string) {
		t.Helper()
		err := e.Tx.InTx(context.Background(), func(ctx context.Context) error {
			_, err := ob.Add(ctx, outbox.Message{OrgID: e.Org, Topic: topic, Recipient: outbox.Recipient{Kind: "admin"},
				Subject: "otp:wiring", DedupeKey: key, Payload: map[string]any{"v": 1}, SensitivePayload: true})
			return err
		})
		if err != nil {
			t.Fatalf("Add(%s): %v", topic, err)
		}
	}
	add(otp.TopicEmailCode, "otp:code:"+uuid.NewString())
	add(otp.TopicContactNotice, "otp:notice:"+uuid.NewString())
	add("task.reminder", "control")
	for topic, want := range map[string]int{otp.TopicEmailCode: 3, otp.TopicContactNotice: 3, "task.reminder": 8} {
		var got int
		if err := e.Pool.QueryRow(context.Background(), `SELECT max_attempts FROM outbox_messages WHERE topic = $1`, topic).Scan(&got); err != nil || got != want {
			t.Errorf("max_attempts of %s = %d (%v), want %d: the otp sender is registered for the topic with 3 attempts, others keep the default", topic, got, err, want)
		}
	}
}

func TestWiring_OTPHousekeepingJobIsRecurringAndRunsDailyAt0315IST(t *testing.T) {
	e := otptest.NewEnv(t)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	sch := scheduler.New(e.Tx, e.Outbox, e.Clock.Now, log, "otp-wiring-test", scheduler.DefaultOptions())
	registerOTPJobs(sch, e.Svc)

	now := e.Clock.Now() // 2026-07-01 10:00 UTC = 15:30 IST
	old := uuid.New()
	e.Exec(t, `INSERT INTO otp_verifications (id, org_id, purpose, handle_hash, created_at, expires_at, updated_at)
		VALUES ($1, $2, 'password_reset', decode(repeat('cd', 32), 'hex'), $3, $4, $3)`, old, e.Org, now.Add(-100*time.Hour), now.Add(-76*time.Hour))
	count := func(sql string, args ...any) int { return e.Count(t, sql, args...) }
	tick := func() scheduler.TickSummary {
		t.Helper()
		sum, err := sch.Tick(context.Background())
		if err != nil {
			t.Fatalf("Tick: %v", err)
		}
		return sum
	}

	tick() // the first tick creates the recurring row for the organisation
	nextRun := time.Date(2026, time.July, 1, 21, 45, 0, 0, time.UTC)
	if n := count(`SELECT count(*) FROM scheduled_jobs WHERE org_id = $1 AND kind = $2 AND recurring AND status = 'pending' AND run_at = $3`,
		e.Org, otp.HousekeepingKind, nextRun); n != 1 {
		t.Fatalf("pending recurring %s rows due at %s = %d, want 1 (registered with Recurring: otp.HousekeepingNext?)", otp.HousekeepingKind, nextRun, n)
	}
	if count(`SELECT count(*) FROM otp_verifications WHERE id = $1`, old) != 1 {
		t.Fatal("the stale verification was purged before the job was due")
	}
	e.Clock.Set(nextRun)
	if sum := tick(); sum.Jobs.Run < 1 {
		t.Fatalf("the tick at 03:15 IST ran %d jobs, want the housekeeping job", sum.Jobs.Run)
	}
	if count(`SELECT count(*) FROM otp_verifications WHERE id = $1`, old) != 0 {
		t.Error("the stale verification survived the job")
	}
	if n := count(`SELECT count(*) FROM scheduled_jobs WHERE org_id = $1 AND kind = $2 AND status = 'pending' AND run_at = $3`,
		e.Org, otp.HousekeepingKind, nextRun.Add(24*time.Hour)); n != 1 {
		t.Errorf("pending %s rows due tomorrow = %d, want 1 (the job reschedules itself)", otp.HousekeepingKind, n)
	}
}
