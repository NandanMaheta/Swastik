package otp

import (
	"slices"
	"time"

	"github.com/NandanMaheta/swastik/apps/api/internal/platform/istdate"
)

// LimitScope is the kind of durable limit (data-model section 4).
type LimitScope string

// Limit scopes.
const (
	ScopeSendContact LimitScope = "send_contact"
	ScopeSendUser    LimitScope = "send_user"
	ScopeSendIP      LimitScope = "send_ip"
	ScopeCheckIP     LimitScope = "check_ip"
)

// LimitInput is one limit row: the accepted events so far, oldest first.
type LimitInput struct {
	Scope  LimitScope
	Events []time.Time
}

// LimitDecision is the verdict of ApplyLimits. Events is the new event list to store: it holds
// the new event only when Allowed, and drops events older than both windows.
type LimitDecision struct {
	Allowed    bool
	Reason     RetryReason
	RetryAfter time.Duration
	Events     []time.Time
}

// policy is one scope's row of the table in data-model section 4; zero means no such limit.
type policy struct {
	perHour, perDay int
	cooldown        time.Duration
}

func policyOf(s LimitScope) policy {
	switch s {
	case ScopeSendContact:
		return policy{perHour: 5, perDay: 10, cooldown: ResendCooldown}
	case ScopeSendUser:
		return policy{perDay: 10}
	case ScopeSendIP:
		return policy{perHour: 20}
	case ScopeCheckIP:
		return policy{perHour: 60}
	}
	// An unknown scope gets the strictest policy rather than none.
	return policy{perHour: 1, perDay: 1, cooldown: ResendCooldown}
}

// ApplyLimits applies the policy table of data-model section 4 at now. A refusal adds no event.
func ApplyLimits(in LimitInput, now time.Time) LimitDecision {
	p := policyOf(in.Scope)
	today := istdate.DateOf(now)
	dayStart, nextDay := today.At(0, 0), today.AddDays(1).At(0, 0)

	events := slices.Clone(in.Events)
	slices.SortFunc(events, func(a, b time.Time) int { return a.Compare(b) })

	var inHour []time.Time // rolling hour, oldest first
	var kept []time.Time
	inDay := 0
	for _, e := range events {
		hourly := now.Sub(e) < time.Hour
		daily := !e.Before(dayStart)
		if hourly {
			inHour = append(inHour, e)
		}
		if daily {
			inDay++
		}
		if (p.perHour > 0 && hourly) || (p.perDay > 0 && daily) {
			kept = append(kept, e)
		}
	}

	var wait time.Duration
	var reason RetryReason
	if p.perHour > 0 && len(inHour) >= p.perHour {
		// The (len-perHour+1)th oldest counted event must leave the window.
		wait, reason = inHour[len(inHour)-p.perHour].Add(time.Hour).Sub(now), ReasonRateLimited
	}
	if p.perDay > 0 && inDay >= p.perDay {
		if w := nextDay.Sub(now); w > wait {
			wait, reason = w, ReasonRateLimited
		}
	}
	if p.cooldown > 0 && len(events) > 0 {
		if w := events[len(events)-1].Add(p.cooldown).Sub(now); w > wait {
			wait, reason = w, ReasonCooldown
		}
	}
	if wait > 0 {
		return LimitDecision{Reason: reason, RetryAfter: wait, Events: kept}
	}
	return LimitDecision{Allowed: true, Events: append(kept, now)}
}
