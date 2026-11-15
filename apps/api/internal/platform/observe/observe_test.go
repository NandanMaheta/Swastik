package observe_test

// 027 T005 - observe (FR-015, plan D-13). Black box: no sentry import; a local HTTP server stands in
// for Sentry ingest, so the real SDK's wire output is what is checked.
//
// Contract: Init("", env, version) is a no-op (no network, nil error, non-nil flush); Init(dsn, ...) with
// a bad DSN returns an error and a usable no-op flush; NewHandler(next) forwards every record to next
// unchanged and additionally reports ERROR (and above) records to Sentry; INFO/WARN are never sent;
// attributes whose KEY looks sensitive, and URL userinfo credentials, never reach the event.
//
// The tests share the SDK's global client, so they must not run in parallel.

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/NandanMaheta/swastik/apps/api/internal/platform/observe"
)

type ingest struct {
	srv *httptest.Server
	mu  sync.Mutex
	bod []string
}

func newIngest(t *testing.T) *ingest {
	t.Helper()
	in := &ingest{}
	in.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		in.mu.Lock()
		in.bod = append(in.bod, string(b))
		in.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"1"}`))
	}))
	t.Cleanup(in.srv.Close)
	return in
}

func (in *ingest) dsn() string {
	return "http://publickey@" + strings.TrimPrefix(in.srv.URL, "http://") + "/1"
}

func (in *ingest) all() string {
	in.mu.Lock()
	defer in.mu.Unlock()
	return strings.Join(in.bod, "\n")
}

func (in *ingest) count() int {
	in.mu.Lock()
	defer in.mu.Unlock()
	return len(in.bod)
}

// recorder is a slog.Handler capturing what the wrapped handler still receives.
type recorder struct {
	mu   sync.Mutex
	recs []slog.Record
	with []slog.Attr
	min  slog.Level
}

func (r *recorder) Enabled(_ context.Context, l slog.Level) bool { return l >= r.min }
func (r *recorder) Handle(_ context.Context, rec slog.Record) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.recs = append(r.recs, rec)
	return nil
}
func (r *recorder) WithAttrs(a []slog.Attr) slog.Handler {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.with = append(r.with, a...)
	return r
}
func (r *recorder) WithGroup(string) slog.Handler { return r }
func (r *recorder) messages() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []string
	for _, rec := range r.recs {
		out = append(out, rec.Level.String()+":"+rec.Message)
	}
	return out
}

func TestObserve_FR015_EmptyDSNIsNoOp(t *testing.T) {
	flush, err := observe.Init("", "staging", "v1")
	if err != nil {
		t.Fatalf("empty DSN must be a silent no-op, got %v", err)
	}
	if flush == nil {
		t.Fatal("flush must never be nil")
	}
	rec := &recorder{}
	log := slog.New(observe.NewHandler(rec))
	log.Error("boom", "k", "v")
	flush() // must not block or panic
	if got := rec.messages(); len(got) != 1 || got[0] != "ERROR:boom" {
		t.Fatalf("records must still reach the wrapped handler, got %v", got)
	}
}

func TestObserve_FR015_BadDSNReturnsErrorAndSafeFlush(t *testing.T) {
	flush, err := observe.Init("::not a dsn::", "staging", "v1")
	if err == nil {
		t.Fatal("an invalid DSN must be reported")
	}
	if flush == nil {
		t.Fatal("flush must be non-nil even on error so callers can defer it")
	}
	flush()
}

func TestObserve_FR015_ErrorForwardedInfoAndWarnNot(t *testing.T) {
	in := newIngest(t)
	flush, err := observe.Init(in.dsn(), "staging", "v1.2.3")
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	rec := &recorder{}
	log := slog.New(observe.NewHandler(rec))

	log.Info("info-line-marker", "a", 1)
	log.Warn("warn-line-marker")
	flush()
	if n := in.count(); n != 0 {
		t.Fatalf("INFO/WARN produced %d Sentry requests: %s", n, in.all())
	}

	log.Error("error-line-marker", "order", "o1")
	flush()
	body := in.all()
	if !strings.Contains(body, "error-line-marker") {
		t.Fatalf("ERROR record not reported; ingest saw: %q", body)
	}
	if strings.Contains(body, "info-line-marker") || strings.Contains(body, "warn-line-marker") {
		t.Error("lower level records leaked into the ERROR event")
	}
	if !strings.Contains(body, "staging") || !strings.Contains(body, "v1.2.3") {
		t.Errorf("event must carry environment and release: %q", body)
	}
	got := rec.messages()
	want := []string{"INFO:info-line-marker", "WARN:warn-line-marker", "ERROR:error-line-marker"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("wrapped handler must still see every record: got %v want %v", got, want)
	}
}

func TestObserve_FR015_NoSecretFieldsInEvents(t *testing.T) {
	in := newIngest(t)
	flush, err := observe.Init(in.dsn(), "staging", "v1")
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	log := slog.New(observe.NewHandler(&recorder{}))
	log.Error("leak-check",
		"password", "hunter2-value",
		"authorization", "Bearer abc.def.ghi-value",
		"token", "tok-value-123",
		"secret", "shh-value",
		"api_key", "key-value-456",
		"cookie", "sid=cookie-value-789",
		"pan", "ABCDE1234F",
		"mobile", "9876543210",
		"email", "person@example.com",
		"database_url", "postgresql://swastik_app:dbpass-value@host:5432/postgres",
		"jwt_signing_keys", "keyring-value",
		"order_id", "ok-field-value",
	)
	flush()
	body := in.all()
	if !strings.Contains(body, "leak-check") {
		t.Fatalf("event not delivered: %q", body)
	}
	for _, leaked := range []string{
		"hunter2-value", "abc.def.ghi-value", "tok-value-123", "shh-value", "key-value-456",
		"cookie-value-789", "ABCDE1234F", "9876543210", "person@example.com", "dbpass-value", "keyring-value",
	} {
		if strings.Contains(body, leaked) {
			t.Errorf("sensitive value %q reached Sentry", leaked)
		}
	}
	if !strings.Contains(body, "ok-field-value") {
		t.Error("harmless attributes should still be attached for debugging")
	}
}

func TestObserve_FR015_WithAttrsAndGroupsKeepWorking(t *testing.T) {
	in := newIngest(t)
	flush, err := observe.Init(in.dsn(), "staging", "v1")
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	rec := &recorder{}
	log := slog.New(observe.NewHandler(rec)).With("request_id", "req-77").WithGroup("g")
	log.Error("grouped-error", "k", "v")
	flush()
	if !strings.Contains(in.all(), "grouped-error") {
		t.Error("derived loggers must still report ERROR records")
	}
	if !strings.Contains(in.all(), "req-77") {
		t.Error("attributes added with With() should be on the event")
	}
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if len(rec.with) == 0 {
		t.Error("WithAttrs must be forwarded to the wrapped handler")
	}
}

func TestObserve_FR015_EnabledFollowsWrappedHandler(t *testing.T) {
	rec := &recorder{min: slog.LevelWarn}
	h := observe.NewHandler(rec)
	if h.Enabled(context.Background(), slog.LevelInfo) {
		t.Error("handler must not enable levels the wrapped handler disables")
	}
	if !h.Enabled(context.Background(), slog.LevelError) {
		t.Error("ERROR must be enabled")
	}
}
