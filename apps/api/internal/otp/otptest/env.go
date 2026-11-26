package otptest

// The test world of the otp service and handler tests (feature 004): a migrated database with one
// org (authtest), the real auth Service, the real outbox Service with the otp Sender registered
// for both topics, a recording fake mailer, a local Firebase JWKS and a fake clock. Everything is
// built through the public constructors, so a missing implementation fails here with the reason.
//
// It imports otp, so only external test packages (otp_test, main) may import otptest.

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"regexp"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/NandanMaheta/swastik/apps/api/internal/auth"
	"github.com/NandanMaheta/swastik/apps/api/internal/auth/authtest"
	"github.com/NandanMaheta/swastik/apps/api/internal/otp"
	"github.com/NandanMaheta/swastik/apps/api/internal/outbox"
	"github.com/NandanMaheta/swastik/apps/api/internal/platform/audit"
	"github.com/NandanMaheta/swastik/apps/api/internal/platform/clock"
	"github.com/NandanMaheta/swastik/apps/api/internal/platform/crypto"
	"github.com/NandanMaheta/swastik/apps/api/internal/platform/firebaseauth"
	"github.com/NandanMaheta/swastik/apps/api/internal/platform/istdate"
)

// ProjectID is the Firebase project of the test world.
const ProjectID = "swastik-test"

// DefaultIP is the network address of requests that do not name one.
const DefaultIP = "203.0.113.5"

// WaitLog records the response-floor waits of the service (Deps.Wait) without sleeping.
type WaitLog struct {
	mu     sync.Mutex
	untils []time.Time
}

// Wait is the Deps.Wait of the test world: it records and returns at once.
func (w *WaitLog) Wait(_ context.Context, until time.Time) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.untils = append(w.untils, until)
}

// Untils returns the recorded targets, oldest first.
func (w *WaitLog) Untils() []time.Time {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]time.Time(nil), w.untils...)
}

// Reset forgets what was recorded.
func (w *WaitLog) Reset() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.untils = nil
}

// LogSink is a goroutine-safe log buffer (the otp service logs here at debug level).
type LogSink struct {
	mu sync.Mutex
	b  bytes.Buffer
}

// Write implements io.Writer.
func (l *LogSink) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

// String returns everything logged so far.
func (l *LogSink) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// Option changes how NewEnv builds the world.
type Option func(*options)

type options struct {
	noFirebase bool
	realClock  bool
	realWait   bool
}

// WithoutFirebase builds the service with no proof verifier (mobile proofs answer ErrNotConfigured).
func WithoutFirebase() Option { return func(o *options) { o.noFirebase = true } }

// WithRealClock runs the service and auth on the machine clock and the real response floor (the
// SC-004 timing test); Env.Clock is then not the service's clock.
func WithRealClock() Option { return func(o *options) { o.realClock, o.realWait = true, true } }

// Env is one otp test world.
type Env struct {
	*authtest.Env
	Auth    *auth.Service
	Outbox  *outbox.Service
	Svc     *otp.Service
	Mailer  *Mailer
	Minter  *Minter
	Digests crypto.BlindIndexer
	Logs    *LogSink
	Waits   *WaitLog

	proofSeq atomic.Int64
}

// NewEnv builds the world. A failure to construct the service fails the test with its reason.
func NewEnv(t *testing.T, opts ...Option) *Env {
	t.Helper()
	var o options
	for _, f := range opts {
		f(&o)
	}
	base := authtest.New(t)
	now := base.Clock.Now
	if o.realClock {
		now = clock.Real
	}
	digests, err := crypto.NewBlindIndexer(bytes.Repeat([]byte{0x66}, 32))
	if err != nil {
		t.Fatalf("otptest: digest key: %v", err)
	}
	e := &Env{Env: base, Mailer: &Mailer{}, Digests: digests, Logs: &LogSink{}, Waits: &WaitLog{}}

	ad := base.Deps()
	ad.Now = now
	e.Auth = base.ServiceWith(t, ad)
	e.Outbox = outbox.New(base.Tx, now, slog.New(slog.NewTextHandler(io.Discard, nil)), outbox.DefaultOptions())

	d := otp.Deps{
		Tx: base.Tx, Now: now, Accounts: e.Auth, Outbox: e.Outbox, Keyring: base.Keyring, Digests: digests,
		Mailer: e.Mailer, Log: slog.New(slog.NewJSONHandler(e.Logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
	}
	if !o.realWait {
		d.Wait = e.Waits.Wait
	}
	if !o.noFirebase {
		e.Minter = NewMinter(t, ProjectID)
		d.Proofs = firebaseauth.New(t.Context(), ProjectID, now, firebaseauth.WithJWKSURL(e.Minter.JWKSURL))
	}
	svc, err := otp.New(d)
	if err != nil {
		t.Fatalf("otp.New: %v", err)
	}
	e.Svc = svc
	e.Outbox.RegisterSender(otp.TopicEmailCode, svc.Sender(), 3)
	e.Outbox.RegisterSender(otp.TopicContactNotice, svc.Sender(), 3)
	return e
}

// ---- users and actors ----------------------------------------------------------------------

// Pending is a client awaiting verification of both contacts.
func (e *Env) Pending(t *testing.T) authtest.User {
	return e.UserWithStatus(t, auth.StatusPendingVerification)
}

// Active is an active client (both contacts verified).
func (e *Env) Active(t *testing.T) authtest.User { return e.UserWithStatus(t, auth.StatusActive) }

// ActorOf is the audit actor of a client acting for themselves.
func ActorOf(u authtest.User) audit.Actor { return audit.Actor{ID: u.ID, Kind: audit.KindClient} }

// ---- starting flows ------------------------------------------------------------------------

// TryStart runs Start in one transaction, as feature 005/007 do.
func (e *Env) TryStart(in otp.StartInput, by audit.Actor) (otp.Started, error) {
	var out otp.Started
	if in.OrgID == uuid.Nil {
		in.OrgID = e.Org
	}
	if in.IP == "" {
		in.IP = DefaultIP
	}
	err := e.Tx.InTx(context.Background(), func(ctx context.Context) error {
		var err error
		out, err = e.Svc.Start(ctx, in, by)
		return err
	})
	return out, err
}

// Start is TryStart that fails the test on error.
func (e *Env) Start(t *testing.T, in otp.StartInput, by audit.Actor) otp.Started {
	t.Helper()
	s, err := e.TryStart(in, by)
	if err != nil {
		t.Fatalf("Start(%s): %v", in.Purpose, err)
	}
	return s
}

// StartSignup starts a sign-up verification for a pending user.
func (e *Env) StartSignup(t *testing.T, u authtest.User) otp.Started {
	t.Helper()
	return e.Start(t, otp.StartInput{UserID: u.ID, Purpose: otp.PurposeSignup}, ActorOf(u))
}

// StartChange starts a change verification of an active user towards a new contact.
func (e *Env) StartChange(t *testing.T, u authtest.User, p otp.Purpose, newContact string) otp.Started {
	t.Helper()
	return e.Start(t, otp.StartInput{UserID: u.ID, Purpose: p, NewContact: newContact}, ActorOf(u))
}

// Caller is a public caller from the default address.
func Caller() otp.Caller { return otp.Caller{IP: DefaultIP} }

// CallerOf is the owner's caller on /v1/me/*.
func CallerOf(u authtest.User) otp.Caller {
	id := u.ID
	return otp.Caller{IP: DefaultIP, UserID: &id}
}

// ---- mail and codes ------------------------------------------------------------------------

var codeInSubject = regexp.MustCompile(`Your Swastik code: ([0-9]{6})`)

// LastCode returns the code of the last mail the fake mailer accepted.
func (e *Env) LastCode(t *testing.T) string {
	t.Helper()
	mails := e.Mailer.Mails()
	if len(mails) == 0 {
		t.Fatal("no email was sent")
	}
	m := codeInSubject.FindStringSubmatch(mails[len(mails)-1].Subject)
	if m == nil {
		t.Fatalf("the last email has no code in its subject: %q", mails[len(mails)-1].Subject)
	}
	return m[1]
}

// PendingCode opens the sealed outbox message of the verification's live code and returns the code,
// without sending anything. It fails when that message is no longer pending.
func (e *Env) PendingCode(t *testing.T, verification uuid.UUID) string {
	t.Helper()
	var topic, key string
	var payload []byte
	err := e.Pool.QueryRow(context.Background(), `SELECT o.topic, o.dedupe_key, o.payload::text::bytea
		FROM otp_email_codes c JOIN outbox_messages o ON o.dedupe_key = c.outbox_key AND o.org_id = c.org_id
		WHERE c.verification_id = $1 AND c.ended_at IS NULL AND o.status IN ('pending','sending')`, verification).
		Scan(&topic, &key, &payload)
	if err != nil {
		t.Fatalf("no pending code message for verification %s: %v", verification, err)
	}
	plain := e.OpenBox(t, payload, topic, key)
	code, _ := plain["code"].(string)
	if code == "" {
		t.Fatalf("the sealed payload has no code: keys %v", keysOf(plain))
	}
	return code
}

// OpenBox opens {"v":1,"box":"<base64>"} with the PII ring and aad "topic|dedupe_key" and returns
// the plain JSON object.
func (e *Env) OpenBox(t *testing.T, payload []byte, topic, key string) map[string]any {
	t.Helper()
	var wrapper struct {
		V   int    `json:"v"`
		Box string `json:"box"`
	}
	if err := json.Unmarshal(payload, &wrapper); err != nil || wrapper.V != 1 || wrapper.Box == "" {
		t.Fatalf("payload is not {\"v\":1,\"box\":...}: %v (keys of a decoded copy unavailable)", err)
	}
	var raw []byte
	var err error
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if raw, err = enc.DecodeString(wrapper.Box); err == nil {
			break
		}
	}
	if err != nil {
		t.Fatalf("box is not base64: %v", err)
	}
	plain, err := e.Keyring.Open(raw, []byte(topic+"|"+key))
	if err != nil {
		t.Fatalf("box does not open with aad topic|dedupe_key: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal(plain, &out); err != nil {
		t.Fatalf("sealed payload is not a JSON object: %v", err)
	}
	return out
}

func keysOf(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// Deliver runs Service.Deliver after commit (no transaction) and fails the test on error.
func (e *Env) Deliver(t *testing.T, id uuid.UUID) {
	t.Helper()
	if err := e.Svc.Deliver(t.Context(), id); err != nil {
		t.Fatalf("Deliver: %v", err)
	}
}

// Relay runs one outbox relay pass (the tick's fallback path) and returns its summary.
func (e *Env) Relay(t *testing.T) outbox.RelaySummary {
	t.Helper()
	sum, err := e.Outbox.Relay(t.Context(), outbox.RelayBudget{MaxMessages: 50})
	if err != nil {
		t.Fatalf("Relay: %v", err)
	}
	return sum
}

// ---- reading the database ------------------------------------------------------------------

// OutboxRow is one outbox_messages row as the tests read it.
type OutboxRow struct {
	ID                   uuid.UUID
	Topic, Key, Subject  string
	Status               string
	Payload              []byte
	Sensitive, RespectsQ bool
	AvailableAt          time.Time
	ExpiresAt            *time.Time
	RecipientID          *uuid.UUID
	Attempts, MaxAtt     int
	LastError            string
}

// OutboxRows returns the org's outbox rows of a topic ("" = all), oldest first.
func (e *Env) OutboxRows(t *testing.T, topic string) []OutboxRow {
	t.Helper()
	rows, err := e.Pool.Query(context.Background(), `SELECT id, topic, dedupe_key, subject, status, payload::text,
		sensitive_payload, respects_quiet_hours, available_at, expires_at, recipient_id, attempts, max_attempts, COALESCE(last_error, '')
		FROM outbox_messages WHERE org_id = $1 AND ($2 = '' OR topic = $2) ORDER BY created_at, id`, e.Org, topic)
	if err != nil {
		t.Fatalf("outbox rows: %v", err)
	}
	defer rows.Close()
	var out []OutboxRow
	for rows.Next() {
		var r OutboxRow
		var payload string
		if err := rows.Scan(&r.ID, &r.Topic, &r.Key, &r.Subject, &r.Status, &payload, &r.Sensitive, &r.RespectsQ,
			&r.AvailableAt, &r.ExpiresAt, &r.RecipientID, &r.Attempts, &r.MaxAtt, &r.LastError); err != nil {
			t.Fatalf("scan outbox row: %v", err)
		}
		r.Payload = []byte(payload)
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("outbox rows: %v", err)
	}
	return out
}

// Envelope is what the relay would hand the sender for this row.
func (r OutboxRow) Envelope(org uuid.UUID) outbox.Envelope {
	return outbox.Envelope{ID: r.ID, OrgID: org, Topic: r.Topic, DedupeKey: r.Key, Subject: r.Subject, Payload: r.Payload, Attempt: 1}
}

// Count runs a COUNT query.
func (e *Env) Count(t *testing.T, sql string, args ...any) int {
	t.Helper()
	var n int
	if err := e.Pool.QueryRow(context.Background(), sql, args...).Scan(&n); err != nil {
		t.Fatalf("count %q: %v", sql, err)
	}
	return n
}

// Counts reads the daily counters of the IST day of the clock's current time.
func (e *Env) Counts(t *testing.T) otp.DailyCounts {
	t.Helper()
	return e.CountsOn(t, e.Clock.Now())
}

// AuditAfter decodes the After JSON of an audit row (nil when empty).
func AuditAfter(t *testing.T, r authtest.AuditRow) map[string]any {
	t.Helper()
	if r.After == "" {
		return nil
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(r.After), &m); err != nil {
		t.Fatalf("audit after of %s is not an object: %v", r.Action, err)
	}
	return m
}

// OTPAudit returns the audit rows whose action starts with "otp.", in write order.
func (e *Env) OTPAudit(t *testing.T) []authtest.AuditRow {
	t.Helper()
	var out []authtest.AuditRow
	for _, r := range e.AuditRows(t) {
		if len(r.Action) >= 4 && r.Action[:4] == "otp." {
			out = append(out, r)
		}
	}
	return out
}

// ---- Firebase proofs -----------------------------------------------------------------------

// Token mints a valid phone sign-in token for the number at the clock's current time (signed in
// one minute ago, a fresh subject each call). mutate may edit the claims.
func (e *Env) Token(t *testing.T, phone string, mutate ...func(*Claims)) string {
	t.Helper()
	if e.Minter == nil {
		t.Fatal("this world has no Firebase minter")
	}
	c := e.Minter.Valid(e.Clock.Now())
	c.PhoneNumber = phone
	c.Subject = fmt.Sprintf("fb-user-%d", e.proofSeq.Add(1))
	for _, m := range mutate {
		m(&c)
	}
	return e.Minter.Token(t, c)
}

// CountsOn reads the daily counters of the IST day containing at.
func (e *Env) CountsOn(t *testing.T, at time.Time) otp.DailyCounts {
	t.Helper()
	c, err := e.Svc.DailyCounts(t.Context(), e.Org, istdate.DateOf(at))
	if err != nil {
		t.Fatalf("DailyCounts: %v", err)
	}
	return c
}
