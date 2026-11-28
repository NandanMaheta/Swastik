// Tests for ApplyLimits, the pure send/check limit policy (feature 004, S06; BR-CLI-04, D-02, D-03,
// FR-004, SC-001). Policy table (data-model section 4):
//
//	send_contact  rolling 1 h: 5   IST day: 10   cooldown 60 s after the last accepted send
//	send_user     IST day: 10
//	send_ip       rolling 1 h: 20
//	check_ip      rolling 1 h: 60
//
// Rolling windows count events with now-e < window (an event exactly one window old no longer
// counts); the cooldown refuses while now < last+60 s. RetryAfter is the largest of the applicable
// refusal ends (cooldown end, oldest counted + window, next 00:00 IST); Reason is cooldown when the
// cooldown decides, else rate_limited. A refusal adds no event. Events returned = retained old
// events (those inside the 1 h or IST-day window the scope uses) plus now when Allowed, oldest first.
package otp_test

import (
	"slices"
	"testing"
	"time"

	"pgregory.net/rapid"

	"github.com/NandanMaheta/swastik/apps/api/internal/otp"
	"github.com/NandanMaheta/swastik/apps/api/internal/platform/istdate"
)

func ist(day, hour, minute int) time.Time {
	return istdate.Date{Year: 2026, Month: time.November, Day: day}.At(hour, minute)
}

// at returns n events spaced step apart, the last one ending lastAgo before now.
func evenly(now time.Time, n int, step, lastAgo time.Duration) []time.Time {
	out := make([]time.Time, n)
	for i := range out {
		out[i] = now.Add(-lastAgo - time.Duration(n-1-i)*step)
	}
	return out
}

func TestApplyLimits_BR_CLI_04_ResendCooldownBoundary(t *testing.T) {
	now := ist(26, 10, 0)
	tests := []struct {
		name    string
		ago     time.Duration
		allowed bool
		retry   time.Duration
	}{
		{"59 s after the last send (US2.1)", 59 * time.Second, false, time.Second},
		{"59.999 s", 59*time.Second + 999*time.Millisecond, false, time.Millisecond},
		{"exactly 60 s", 60 * time.Second, true, 0},
		{"61 s", 61 * time.Second, true, 0},
		{"just sent", 0, false, 60 * time.Second},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := otp.ApplyLimits(otp.LimitInput{Scope: otp.ScopeSendContact, Events: []time.Time{now.Add(-tt.ago)}}, now)
			if d.Allowed != tt.allowed {
				t.Fatalf("Allowed = %v, want %v (%+v)", d.Allowed, tt.allowed, d)
			}
			if !tt.allowed {
				if d.Reason != otp.ReasonCooldown || d.RetryAfter != tt.retry {
					t.Errorf("refusal = %s after %v, want cooldown after %v", d.Reason, d.RetryAfter, tt.retry)
				}
				if len(d.Events) != 1 {
					t.Errorf("Events = %v, want the old event only (a refusal adds none)", d.Events)
				}
			}
		})
	}
}

func TestApplyLimits_BR_CLI_04_FirstSendIsAllowedAndRecorded(t *testing.T) {
	now := ist(26, 10, 0)
	for _, s := range []otp.LimitScope{otp.ScopeSendContact, otp.ScopeSendUser, otp.ScopeSendIP, otp.ScopeCheckIP} {
		d := otp.ApplyLimits(otp.LimitInput{Scope: s}, now)
		if !d.Allowed || d.RetryAfter != 0 || !slices.Equal(d.Events, []time.Time{now}) {
			t.Errorf("%s: decision = %+v, want allowed with exactly [now]", s, d)
		}
	}
}

func TestApplyLimits_BR_CLI_04_HourlyLimitPerContact(t *testing.T) {
	now := ist(26, 14, 0)
	t.Run("five in the hour refuse the sixth with the exact wait (US2.2)", func(t *testing.T) {
		ev := evenly(now, 5, 10*time.Minute, 10*time.Minute) // 50, 40, 30, 20, 10 minutes ago
		d := otp.ApplyLimits(otp.LimitInput{Scope: otp.ScopeSendContact, Events: ev}, now)
		if d.Allowed || d.Reason != otp.ReasonRateLimited || d.RetryAfter != 10*time.Minute {
			t.Fatalf("decision = %+v, want rate_limited after 10m (oldest + 1h)", d)
		}
		if !slices.Equal(d.Events, ev) {
			t.Errorf("Events = %v, want unchanged %v", d.Events, ev)
		}
	})
	t.Run("the oldest event exactly one hour old no longer counts", func(t *testing.T) {
		ev := evenly(now, 5, 15*time.Minute, 0)[:0]
		ev = append(ev, now.Add(-time.Hour), now.Add(-45*time.Minute), now.Add(-30*time.Minute), now.Add(-15*time.Minute), now.Add(-5*time.Minute))
		d := otp.ApplyLimits(otp.LimitInput{Scope: otp.ScopeSendContact, Events: ev}, now)
		if !d.Allowed {
			t.Fatalf("decision = %+v, want allowed: only 4 events are inside the hour", d)
		}
		if got := d.Events[len(d.Events)-1]; !got.Equal(now) {
			t.Errorf("last event = %v, want now", got)
		}
	})
	t.Run("one nanosecond younger than an hour still counts", func(t *testing.T) {
		ev := []time.Time{now.Add(-time.Hour + time.Nanosecond), now.Add(-45 * time.Minute), now.Add(-30 * time.Minute), now.Add(-15 * time.Minute), now.Add(-5 * time.Minute)}
		d := otp.ApplyLimits(otp.LimitInput{Scope: otp.ScopeSendContact, Events: ev}, now)
		if d.Allowed || d.RetryAfter != time.Nanosecond {
			t.Fatalf("decision = %+v, want refused for 1ns", d)
		}
	})
	t.Run("cooldown and hourly limit together: the longer wait and its reason win", func(t *testing.T) {
		ev := evenly(now, 5, 2*time.Minute, 10*time.Second) // last 10 s ago, oldest 8m10s ago
		d := otp.ApplyLimits(otp.LimitInput{Scope: otp.ScopeSendContact, Events: ev}, now)
		want := ev[0].Add(time.Hour).Sub(now)
		if d.Allowed || d.Reason != otp.ReasonRateLimited || d.RetryAfter != want {
			t.Fatalf("decision = %+v, want rate_limited after %v", d, want)
		}
	})
}

func TestApplyLimits_BR_CLI_04_DailyLimitResetsAtMidnightIST(t *testing.T) {
	// Ten sends on 26 Nov IST, two hours apart (at most one per hour window), the last at 21:00.
	day := func(h int) time.Time { return ist(26, h, 0) }
	ten := []time.Time{day(1), day(3), day(5), day(7), day(9), day(11), day(13), day(15), day(17), day(19)}

	tests := []struct {
		name    string
		now     time.Time
		events  []time.Time
		allowed bool
		retry   time.Duration
	}{
		{"ten today refuse the eleventh until midnight", ist(26, 21, 0), ten, false, 3 * time.Hour},
		{"nine today allow the tenth", ist(26, 21, 0), ten[1:], true, 0},
		{"one second before midnight IST", ist(26, 23, 59).Add(59 * time.Second), ten, false, time.Second},
		{"at 00:00 IST the day starts afresh", ist(27, 0, 0), ten, true, 0},
		{"midnight in UTC is not the reset", time.Date(2026, 11, 26, 18, 29, 59, 0, time.UTC), ten, false, time.Second},
		{"18:30 UTC is 00:00 IST", time.Date(2026, 11, 26, 18, 30, 0, 0, time.UTC), ten, true, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := otp.ApplyLimits(otp.LimitInput{Scope: otp.ScopeSendContact, Events: tt.events}, tt.now)
			if d.Allowed != tt.allowed {
				t.Fatalf("Allowed = %v, want %v (%+v)", d.Allowed, tt.allowed, d)
			}
			if !tt.allowed && (d.Reason != otp.ReasonRateLimited || d.RetryAfter != tt.retry) {
				t.Errorf("refusal = %s after %v, want rate_limited after %v", d.Reason, d.RetryAfter, tt.retry)
			}
		})
	}
}

func TestApplyLimits_BR_CLI_04_PerUserIsTenPerISTDayWithoutCooldown(t *testing.T) {
	now := ist(26, 12, 0)
	burst := make([]time.Time, 9)
	for i := range burst {
		burst[i] = now.Add(-time.Duration(9-i) * time.Second) // nine sends in nine seconds
	}
	d := otp.ApplyLimits(otp.LimitInput{Scope: otp.ScopeSendUser, Events: burst}, now)
	if !d.Allowed {
		t.Fatalf("tenth send of the day refused: %+v (the user scope has no cooldown or hourly cap)", d)
	}
	ten := append(slices.Clone(burst), now.Add(-time.Second/2))
	d = otp.ApplyLimits(otp.LimitInput{Scope: otp.ScopeSendUser, Events: ten}, now)
	if d.Allowed || d.Reason != otp.ReasonRateLimited || d.RetryAfter != 12*time.Hour {
		t.Fatalf("decision = %+v, want rate_limited for 12h (to 00:00 IST)", d)
	}
}

func TestApplyLimits_BR_CLI_04_PerAddressHourlyLimits(t *testing.T) {
	now := ist(26, 12, 0)
	for _, tt := range []struct {
		scope otp.LimitScope
		limit int
	}{{otp.ScopeSendIP, 20}, {otp.ScopeCheckIP, 60}} {
		t.Run(string(tt.scope), func(t *testing.T) {
			below := evenly(now, tt.limit-1, time.Second, time.Second)
			if d := otp.ApplyLimits(otp.LimitInput{Scope: tt.scope, Events: below}, now); !d.Allowed {
				t.Fatalf("%d in the hour (below the limit): %+v", tt.limit-1, d)
			}
			full := evenly(now, tt.limit, time.Second, time.Second)
			d := otp.ApplyLimits(otp.LimitInput{Scope: tt.scope, Events: full}, now)
			wantWait := full[0].Add(time.Hour).Sub(now)
			if d.Allowed || d.Reason != otp.ReasonRateLimited || d.RetryAfter != wantWait {
				t.Fatalf("%d in the hour: %+v, want rate_limited after %v", tt.limit, d, wantWait)
			}
			// An address is not limited per day or by cooldown: spread over the day it is fine.
			yesterday := []time.Time{now.Add(-61 * time.Minute)}
			if d := otp.ApplyLimits(otp.LimitInput{Scope: tt.scope, Events: yesterday}, now); !d.Allowed {
				t.Errorf("an event older than an hour blocked the address: %+v", d)
			}
		})
	}
}

func TestApplyLimits_BR_CLI_04_OldEventsAreDroppedOnWrite(t *testing.T) {
	now := ist(26, 12, 0)
	old := ist(24, 12, 0)         // two days ago: older than both windows
	yesterday := ist(25, 23, 30)  // older than 1 h and outside today
	earlierToday := ist(26, 2, 0) // older than 1 h but inside today
	recent := now.Add(-20 * time.Minute)
	in := []time.Time{old, yesterday, earlierToday, recent}

	d := otp.ApplyLimits(otp.LimitInput{Scope: otp.ScopeSendContact, Events: in}, now)
	if !d.Allowed {
		t.Fatalf("decision = %+v", d)
	}
	if want := []time.Time{earlierToday, recent, now}; !slices.Equal(d.Events, want) {
		t.Errorf("send_contact events = %v, want %v (kept: inside the hour or the IST day)", d.Events, want)
	}
	d = otp.ApplyLimits(otp.LimitInput{Scope: otp.ScopeSendUser, Events: in}, now)
	if want := []time.Time{earlierToday, recent, now}; !slices.Equal(d.Events, want) {
		t.Errorf("send_user events = %v, want %v (IST day)", d.Events, want)
	}
	d = otp.ApplyLimits(otp.LimitInput{Scope: otp.ScopeSendIP, Events: in}, now)
	if want := []time.Time{recent, now}; !slices.Equal(d.Events, want) {
		t.Errorf("send_ip events = %v, want %v (1 h window only)", d.Events, want)
	}
	d = otp.ApplyLimits(otp.LimitInput{Scope: otp.ScopeCheckIP, Events: in}, now)
	if want := []time.Time{recent, now}; !slices.Equal(d.Events, want) {
		t.Errorf("check_ip events = %v, want %v", d.Events, want)
	}
}

// ---- properties -----------------------------------------------------------------------------

type policy struct {
	hour, day int           // 0 = no limit
	cooldown  time.Duration // 0 = none
}

var policies = map[otp.LimitScope]policy{
	otp.ScopeSendContact: {hour: 5, day: 10, cooldown: otp.ResendCooldown},
	otp.ScopeSendUser:    {day: 10},
	otp.ScopeSendIP:      {hour: 20},
	otp.ScopeCheckIP:     {hour: 60},
}

func dayStart(t time.Time) time.Time { return istdate.DateOf(t).At(0, 0) }

// drive feeds a random request stream through ApplyLimits and returns every accepted instant.
func drive(t *rapid.T, scope otp.LimitScope, n int, maxGap time.Duration) (accepted []time.Time, last otp.LimitDecision) {
	now := ist(26, 0, 0).Add(time.Duration(rapid.Int64Range(0, int64(48*time.Hour)).Draw(t, "start")))
	var events []time.Time
	for i := 0; i < n; i++ {
		now = now.Add(time.Duration(rapid.Int64Range(0, int64(maxGap)).Draw(t, "gap")))
		d := otp.ApplyLimits(otp.LimitInput{Scope: scope, Events: events}, now)
		if d.Allowed {
			accepted = append(accepted, now)
			if !slices.Equal(d.Events[len(d.Events)-1:], []time.Time{now}) {
				t.Fatalf("allowed decision does not end with now: %v", d.Events)
			}
		} else if slices.Contains(d.Events, now) && !slices.Contains(events, now) {
			t.Fatalf("refusal recorded the refused request: %v", d.Events)
		}
		if !slices.IsSortedFunc(d.Events, func(a, b time.Time) int { return a.Compare(b) }) {
			t.Fatalf("Events not oldest first: %v", d.Events)
		}
		if len(d.Events) > 60 {
			t.Fatalf("Events has %d entries; the row CHECK allows 60", len(d.Events))
		}
		events, last = d.Events, d
	}
	return accepted, last
}

func TestApplyLimits_BR_CLI_04_PropertyNeverMoreThanTheLimitPerWindow(t *testing.T) {
	scopes := []otp.LimitScope{otp.ScopeSendContact, otp.ScopeSendUser, otp.ScopeSendIP, otp.ScopeCheckIP}
	rapid.Check(t, func(t *rapid.T) {
		scope := rapid.SampledFrom(scopes).Draw(t, "scope")
		p := policies[scope]
		maxGap := rapid.SampledFrom([]time.Duration{time.Second, 30 * time.Second, 5 * time.Minute, 2 * time.Hour}).Draw(t, "maxGap")
		accepted, _ := drive(t, scope, 150, maxGap)

		for i, at := range accepted {
			inHour, inDay := 0, 0
			for _, e := range accepted[:i+1] {
				if at.Sub(e) < time.Hour {
					inHour++
				}
				if !e.Before(dayStart(at)) {
					inDay++
				}
			}
			if p.hour > 0 && inHour > p.hour {
				t.Fatalf("%s: %d accepted within an hour ending %v, limit %d", scope, inHour, at, p.hour)
			}
			if p.day > 0 && inDay > p.day {
				t.Fatalf("%s: %d accepted on one IST day ending %v, limit %d", scope, inDay, at, p.day)
			}
			if p.cooldown > 0 && i > 0 && at.Sub(accepted[i-1]) < p.cooldown {
				t.Fatalf("%s: accepted %v after the previous send, cooldown %v", scope, at.Sub(accepted[i-1]), p.cooldown)
			}
		}
	})
}

func TestApplyLimits_BR_CLI_04_PropertyRetryAfterIsExact(t *testing.T) {
	scopes := []otp.LimitScope{otp.ScopeSendContact, otp.ScopeSendUser, otp.ScopeSendIP, otp.ScopeCheckIP}
	rapid.Check(t, func(t *rapid.T) {
		scope := rapid.SampledFrom(scopes).Draw(t, "scope")
		now := ist(26, 0, 0).Add(time.Duration(rapid.Int64Range(0, int64(48*time.Hour)).Draw(t, "start")))
		var events []time.Time
		maxGap := rapid.SampledFrom([]time.Duration{time.Second, 30 * time.Second, 5 * time.Minute, 20 * time.Minute}).Draw(t, "maxGap")
		// Build a valid history by requesting until one request is refused.
		for range 400 {
			now = now.Add(time.Duration(rapid.Int64Range(0, int64(maxGap)).Draw(t, "gap")))
			d := otp.ApplyLimits(otp.LimitInput{Scope: scope, Events: events}, now)
			if d.Allowed {
				events = d.Events
				continue
			}
			if d.RetryAfter <= 0 {
				t.Fatalf("refusal without a positive RetryAfter: %+v", d)
			}
			if d.Reason != otp.ReasonCooldown && d.Reason != otp.ReasonRateLimited {
				t.Fatalf("refusal reason %q", d.Reason)
			}
			before := otp.ApplyLimits(otp.LimitInput{Scope: scope, Events: d.Events}, now.Add(d.RetryAfter-time.Nanosecond))
			if before.Allowed {
				t.Fatalf("%s: allowed %v before the promised time (retry_after %v)", scope, time.Nanosecond, d.RetryAfter)
			}
			after := otp.ApplyLimits(otp.LimitInput{Scope: scope, Events: d.Events}, now.Add(d.RetryAfter))
			if !after.Allowed {
				t.Fatalf("%s: still refused at the promised time: %+v (retry_after %v)", scope, after, d.RetryAfter)
			}
			return
		}
	})
}

func TestApplyLimits_BR_CLI_04_PropertyRefusalAddsNoEvent(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		scope := rapid.SampledFrom([]otp.LimitScope{otp.ScopeSendContact, otp.ScopeSendUser, otp.ScopeSendIP, otp.ScopeCheckIP}).Draw(t, "scope")
		now := ist(26, 12, 0)
		var events []time.Time
		for range 100 {
			d := otp.ApplyLimits(otp.LimitInput{Scope: scope, Events: events}, now) // same instant, hammering
			if !d.Allowed {
				if !slices.Equal(d.Events, events) {
					t.Fatalf("refusal changed the events: %v -> %v", events, d.Events)
				}
				return
			}
			events = d.Events
		}
	})
}
