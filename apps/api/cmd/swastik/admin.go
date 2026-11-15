package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"

	"github.com/NandanMaheta/swastik/apps/api/internal/platform/clock"
)

// Compile stub (S15, test-engineer): the shape of the bootstrap command that admin_test.go is
// written against. S16 implements it (contracts/cli.md).

// adminEnv is everything runAdmin touches besides the database: the standard streams, the clock
// and the logger, so tests can inject them. A reader that is not a terminal is read as one line.
type adminEnv struct {
	In  io.Reader
	Out io.Writer
	Err io.Writer
	Now clock.Func
	Log *slog.Logger
}

// runAdmin runs `swastik admin <args...>` (args exclude "admin") and returns the exit status:
// 0 on success, 1 on any refusal or error, 2 on usage errors.
func runAdmin(_ context.Context, _ []string, env adminEnv) int {
	_, _ = fmt.Fprintln(env.Err, "error: not implemented")
	return 1
}
