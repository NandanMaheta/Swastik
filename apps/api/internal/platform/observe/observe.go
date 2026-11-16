// Package observe wires error reporting (Sentry) for the API. Empty DSN means off.
// It is the only package that imports the Sentry SDK (depguard). Events never carry values whose
// attribute key looks sensitive, nor credentials embedded in URLs.
package observe

import (
	"context"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"sync/atomic"
	"time"

	"github.com/getsentry/sentry-go"
)

const flushTimeout = 2 * time.Second

var enabled atomic.Bool

// Init configures error reporting. An empty dsn is a silent no-op. The returned flush function is
// never nil, so callers can always defer it.
func Init(dsn, environment, version string) (func(), error) {
	noop := func() {}
	enabled.Store(false)
	if dsn == "" {
		return noop, nil
	}
	err := sentry.Init(sentry.ClientOptions{
		Dsn:              dsn,
		Environment:      environment,
		Release:          version,
		AttachStacktrace: true,
		BeforeSend:       beforeSend,
	})
	if err != nil {
		return noop, fmt.Errorf("observe: init sentry: %w", err)
	}
	enabled.Store(true)
	return func() { sentry.Flush(flushTimeout) }, nil
}

// NewHandler wraps next so ERROR (and above) records are also reported. Every record still goes to
// next unchanged.
func NewHandler(next slog.Handler) slog.Handler {
	return &handler{next: next}
}

type handler struct {
	next   slog.Handler
	prefix string
	attrs  map[string]string
}

func (h *handler) Enabled(ctx context.Context, l slog.Level) bool {
	return h.next.Enabled(ctx, l)
}

func (h *handler) Handle(ctx context.Context, r slog.Record) error {
	if r.Level >= slog.LevelError && enabled.Load() {
		extra := make(map[string]any, len(h.attrs)+r.NumAttrs())
		for k, v := range h.attrs {
			extra[k] = v
		}
		r.Attrs(func(a slog.Attr) bool {
			collect(extra, h.prefix, a)
			return true
		})
		ev := sentry.NewEvent()
		ev.Level = sentry.LevelError
		ev.Message = r.Message
		ev.Timestamp = r.Time
		ev.Contexts = map[string]sentry.Context{"log": extra}
		sentry.CaptureEvent(ev)
	}
	return h.next.Handle(ctx, r) //nolint:wrapcheck // pass-through of the wrapped handler's error
}

func (h *handler) WithAttrs(as []slog.Attr) slog.Handler {
	merged := make(map[string]any, len(h.attrs)+len(as))
	for k, v := range h.attrs {
		merged[k] = v
	}
	for _, a := range as {
		collect(merged, h.prefix, a)
	}
	attrs := make(map[string]string, len(merged))
	for k, v := range merged {
		attrs[k], _ = v.(string)
	}
	return &handler{next: h.next.WithAttrs(as), prefix: h.prefix, attrs: attrs}
}

func (h *handler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	return &handler{next: h.next.WithGroup(name), prefix: h.prefix + name + ".", attrs: h.attrs}
}

// collect flattens a (possibly grouped) attribute into out under prefix, dropping sensitive ones.
func collect(out map[string]any, prefix string, a slog.Attr) {
	v := a.Value.Resolve()
	if v.Kind() == slog.KindGroup {
		p := prefix
		if a.Key != "" {
			p += a.Key + "."
		}
		for _, g := range v.Group() {
			collect(out, p, g)
		}
		return
	}
	if a.Key == "" || sensitiveKey(a.Key) {
		return
	}
	out[prefix+a.Key] = scrubValue(v.String())
}

var sensitiveTokens = map[string]bool{
	"password": true, "passwd": true, "pwd": true, "secret": true, "secrets": true, "token": true,
	"authorization": true, "auth": true, "cookie": true, "key": true, "keys": true, "pan": true,
	"mobile": true, "phone": true, "email": true, "dsn": true, "otp": true, "pii": true,
	"aadhaar": true, "aadhar": true, "credential": true, "credentials": true, "url": true, "uri": true,
	"bearer": true, "session": true, "jwt": true,
}

func sensitiveKey(k string) bool {
	parts := strings.FieldsFunc(strings.ToLower(k), func(r rune) bool {
		return r == '_' || r == '-' || r == '.' || r == ' '
	})
	for _, p := range parts {
		if sensitiveTokens[p] {
			return true
		}
	}
	return false
}

var (
	urlUserinfo = regexp.MustCompile(`([a-zA-Z][a-zA-Z0-9+.-]*://)[^/\s@]*@`)
	jwtValue    = regexp.MustCompile(`eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*`)
	bearerValue = regexp.MustCompile(`(?i)\bbearer\s+[A-Za-z0-9._~+/=-]+`)
	emailValue  = regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}`)
	panValue    = regexp.MustCompile(`\b[A-Z]{5}[0-9]{4}[A-Z]\b`)
	mobileValue = regexp.MustCompile(`\+91[ -]?[6-9][0-9]{9}\b|\b[6-9][0-9]{9}\b`)
)

// scrubValue removes credentials embedded in URLs and personal values (email, Indian mobile, PAN, JWT,
// bearer token) from free text that is otherwise kept.
func scrubValue(s string) string {
	s = urlUserinfo.ReplaceAllString(s, "${1}[redacted]@")
	s = jwtValue.ReplaceAllString(s, "[jwt]")
	s = bearerValue.ReplaceAllString(s, "Bearer [token]")
	s = emailValue.ReplaceAllString(s, "[email]")
	s = panValue.ReplaceAllString(s, "[pan]")
	return mobileValue.ReplaceAllString(s, "[mobile]")
}

// beforeSend is the SDK hook: it drops identifying fields and scrubs values in the message, exception
// values, and breadcrumbs.
func beforeSend(ev *sentry.Event, _ *sentry.EventHint) *sentry.Event {
	ev.ServerName = ""
	ev.User = sentry.User{}
	ev.Request = nil
	ev.Message = scrubValue(ev.Message)
	for i := range ev.Exception {
		ev.Exception[i].Value = scrubValue(ev.Exception[i].Value)
	}
	for _, b := range ev.Breadcrumbs {
		if b == nil {
			continue
		}
		b.Message = scrubValue(b.Message)
		for k, v := range b.Data {
			if str, ok := v.(string); ok {
				b.Data[k] = scrubValue(str)
			}
		}
	}
	return ev
}
