package outbox_test

// Review fix (feature 004, BR-CLI-04, ADR 0003 Am. 2): sensitive_payload is one way. The erase
// trigger only looks at sensitive rows, so a row that could be flipped to false while its status
// becomes terminal would keep a readable code. Contract: an UPDATE that sets sensitive_payload from
// true to false is either rejected, or leaves the payload erased once the row is terminal.

import (
	"testing"
)

func TestOutboxSensitive_BR_CLI_04_FlagCannotBeClearedToKeepAReadablePayload(t *testing.T) {
	const readable = `{"code":"123456"}`
	cases := []struct {
		name     string
		prepare  func(e *env, key string)
		update   string // run against the row
		terminal bool   // the row is terminal after the update, so its payload must read {}
	}{
		{
			"clear the flag and finish the row in one statement",
			func(e *env, key string) {},
			`UPDATE outbox_messages SET sensitive_payload = false, status = 'withdrawn', finished_at = now(), payload = '` + readable + `' WHERE dedupe_key = $1`,
			true,
		},
		{
			"finish the row first (trigger erases), then clear the flag and restore the payload",
			func(e *env, key string) {
				e.exec(`UPDATE outbox_messages SET status = 'withdrawn', finished_at = now() WHERE dedupe_key = $1`, key)
			},
			`UPDATE outbox_messages SET sensitive_payload = false, payload = '` + readable + `' WHERE dedupe_key = $1`,
			true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t)
			e.add(e.sensitiveMsg("k"))
			c.prepare(e, "k")
			_, err := e.pool.Exec(t.Context(), c.update, "k")
			r := e.sens("k")
			if err != nil {
				// Rejected: the row must be exactly as it was, still sensitive.
				if !r.Sensitive {
					t.Errorf("the update was rejected (%v) but the flag changed: %+v", err, r)
				}
				return
			}
			if c.terminal && r.Payload != "{}" {
				t.Errorf("row = %+v: the flag was cleared and the payload is readable on a finished row", r)
			}
		})
	}
}

// Clearing the flag on a row that is still unsent must not stay possible either: it would leave a
// payload that no later terminal status erases.
func TestOutboxSensitive_BR_CLI_04_FlagCannotBeClearedOnAnUnsentRow(t *testing.T) {
	e := newEnv(t)
	e.add(e.sensitiveMsg("k"))
	_, err := e.pool.Exec(t.Context(), `UPDATE outbox_messages SET sensitive_payload = false WHERE dedupe_key = 'k'`)
	if err == nil {
		// Allowed only if finishing the row afterwards still erases the payload.
		e.exec(`UPDATE outbox_messages SET status = 'withdrawn', finished_at = now() WHERE dedupe_key = 'k'`)
		if r := e.sens("k"); r.Payload != "{}" {
			t.Errorf("row = %+v: a sensitive row whose flag was cleared kept its payload when it was withdrawn", r)
		}
	}
}
