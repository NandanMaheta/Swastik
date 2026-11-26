package otp

import "time"

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

// ApplyLimits applies the policy table of data-model section 4 at now. A refusal adds no event.
func ApplyLimits(_ LimitInput, _ time.Time) LimitDecision { panic(errNotImplemented) }
