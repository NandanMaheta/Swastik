package observe

// 027 review fix 6 (white box): the SDK's before-send hook must scrub VALUES in the message, exception
// values and breadcrumbs. Contract: the hook is the package-level func
// beforeSend(*sentry.Event, *sentry.EventHint) *sentry.Event that Init installs.

import (
	"strings"
	"testing"

	"github.com/getsentry/sentry-go"
)

func TestObserve_Review_BeforeSendScrubsValues(t *testing.T) {
	secrets := []string{"kavita.sharma@example.com", "9876543210", "9876501234", "ABCDE1234F",
		"eyJhbGciOiJIUzI1NiJ9", "c2lnbmF0dXJlLXZhbHVl", "s3cr3t-opaque-token-9f8e7d"}
	jwt := "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NSJ9.c2lnbmF0dXJlLXZhbHVl"
	ev := sentry.NewEvent()
	ev.Message = "boom for kavita.sharma@example.com"
	ev.Exception = []sentry.Exception{
		{Type: "PgError", Value: "duplicate pan ABCDE1234F"},
		{Type: "AuthError", Value: "bad header Bearer s3cr3t-opaque-token-9f8e7d"},
	}
	ev.Breadcrumbs = []*sentry.Breadcrumb{
		{Category: "http", Message: "GET /x?email=kavita.sharma@example.com"},
		{Category: "log", Message: "called +919876543210 and 9876501234 jwt " + jwt,
			Data: map[string]interface{}{"who": "kavita.sharma@example.com"}},
	}
	out := beforeSend(ev, nil)
	if out == nil {
		t.Fatal("beforeSend must keep the event")
	}
	var all strings.Builder
	all.WriteString(out.Message)
	for _, e := range out.Exception {
		all.WriteString(" " + e.Value)
	}
	for _, b := range out.Breadcrumbs {
		all.WriteString(" " + b.Message)
		for _, v := range b.Data {
			if s, ok := v.(string); ok {
				all.WriteString(" " + s)
			}
		}
	}
	for _, s := range secrets {
		if strings.Contains(all.String(), s) {
			t.Errorf("value %q survived beforeSend: %s", s, all.String())
		}
	}
	if !strings.Contains(out.Message, "boom") || len(out.Exception) != 2 || len(out.Breadcrumbs) != 2 {
		t.Errorf("structure and harmless text must be kept: %+v", out)
	}
}
