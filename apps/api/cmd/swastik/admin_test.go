package main

// S15 - `swastik admin create` (contracts/cli.md, spec US-9, FR-080, plan P-13). The command is
// driven through runAdmin(ctx, args, adminEnv) (compile stub in admin.go) with an injected stdin
// (a non-terminal reader: one line is the password), stdout, stderr, clock and logger, against a
// real PostgreSQL (dbtest). Only DATABASE_URL (and APP_ENV) are read from the environment.

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/NandanMaheta/swastik/apps/api/internal/platform/clock"
	"github.com/NandanMaheta/swastik/apps/api/internal/platform/dbtest"
)

const (
	cliPassword = "river-lantern-42-monsoon"
	cliEmail    = "Owner@Example.com"
)

var cliT0 = time.Date(2026, time.July, 1, 10, 0, 0, 0, time.UTC)

type cliRun struct {
	code           int
	out, err, logs string
}

// cliSetup returns an empty migrated database (no organisation) and points the command at it.
func cliSetup(t *testing.T) *pgxpool.Pool {
	t.Helper()
	pool := dbtest.New(t)
	t.Setenv("DATABASE_URL", pool.Config().ConnString())
	t.Setenv("APP_ENV", "local")
	return pool
}

func cliExec(t *testing.T, pool *pgxpool.Pool, args []string, stdin string) cliRun {
	t.Helper()
	var out, errb, logs bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	code := runAdmin(context.Background(), args, adminEnv{
		In: strings.NewReader(stdin), Out: &out, Err: &errb, Now: clock.NewFake(cliT0).Now, Log: log,
	})
	return cliRun{code: code, out: out.String(), err: errb.String(), logs: logs.String()}
}

func cliCreate(t *testing.T, pool *pgxpool.Pool, stdin string, extra ...string) cliRun {
	t.Helper()
	args := append([]string{"create", "--email", cliEmail, "--name", "Asha Owner"}, extra...)
	return cliExec(t, pool, args, stdin)
}

func cliCount(t *testing.T, pool *pgxpool.Pool, sql string, args ...any) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(), sql, args...).Scan(&n); err != nil {
		t.Fatalf("%q: %v", sql, err)
	}
	return n
}

func cliState(t *testing.T, pool *pgxpool.Pool) string {
	t.Helper()
	return fmt.Sprintf("orgs=%d users=%d mfa=%d audit=%d",
		cliCount(t, pool, `SELECT count(*) FROM orgs`), cliCount(t, pool, `SELECT count(*) FROM users`),
		cliCount(t, pool, `SELECT count(*) FROM admin_mfa`), cliCount(t, pool, `SELECT count(*) FROM audit_log`))
}

// noSecret fails if the password shows in anything the command produced or stored (US-9 s5).
func noSecret(t *testing.T, pool *pgxpool.Pool, r cliRun, secrets ...string) {
	t.Helper()
	var audit string
	rows, err := pool.Query(context.Background(), `SELECT a::text FROM audit_log a`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			t.Fatal(err)
		}
		audit += s
	}
	for _, secret := range secrets {
		for where, text := range map[string]string{"stdout": r.out, "stderr": r.err, "logs": r.logs, "audit_log": audit} {
			if strings.Contains(text, secret) {
				t.Errorf("the password appears in %s", where)
			}
		}
	}
}

func TestAdminCreate_SuccessCreatesOrgAndActiveAdmin(t *testing.T) {
	pool := cliSetup(t)
	// Only DATABASE_URL matters: broken auth variables must not matter (contracts/cli.md "Config").
	t.Setenv("JWT_SIGNING_KEYS", "garbage")
	t.Setenv("PII_ENCRYPTION_KEYS", "garbage")
	t.Setenv("BLIND_INDEX_KEY", "garbage")

	r := cliCreate(t, pool, cliPassword+"\n")
	if r.code != 0 {
		t.Fatalf("exit = %d, stderr = %q", r.code, r.err)
	}
	if !regexp.MustCompile(`^admin created: id=[0-9a-f-]{36} email=owner@example\.com\n$`).MatchString(r.out) {
		t.Errorf("stdout = %q, want \"admin created: id=<uuid> email=owner@example.com\"", r.out)
	}
	if r.err != "" {
		t.Errorf("stderr = %q, want empty", r.err)
	}
	var id uuid.UUID
	var role, status, orgName string
	var verified, created time.Time
	err := pool.QueryRow(context.Background(), `SELECT u.id, u.role, u.status, o.name, u.email_verified_at, u.created_at
		FROM users u JOIN orgs o ON o.id = u.org_id WHERE u.email = 'owner@example.com'`).Scan(&id, &role, &status, &orgName, &verified, &created)
	if err != nil {
		t.Fatalf("read the admin: %v", err)
	}
	if role != "admin" || status != "active" || orgName != "Swastik" || !verified.Equal(cliT0) || !created.Equal(cliT0) {
		t.Errorf("admin = %s/%s org %q verified %v created %v, want an active admin in org Swastik at the injected clock", role, status, orgName, verified, created)
	}
	if !strings.Contains(r.out, id.String()) {
		t.Errorf("stdout does not carry the new id %v", id)
	}
	if got := cliCount(t, pool, `SELECT count(*) FROM admin_mfa`); got != 0 {
		t.Errorf("admin_mfa rows = %d, want 0", got)
	}
	var kind string
	var actor *uuid.UUID
	var at time.Time
	if err := pool.QueryRow(context.Background(), `SELECT actor_kind, actor_id, created_at FROM audit_log WHERE action = 'auth.admin.bootstrapped'`).Scan(&kind, &actor, &at); err != nil {
		t.Fatalf("bootstrapped audit row: %v", err)
	}
	if kind != "system" || actor != nil || !at.Equal(cliT0) {
		t.Errorf("audit actor = %s/%v at %v, want the system actor at the injected clock", kind, actor, at)
	}
	noSecret(t, pool, r, cliPassword)
}

func TestAdminCreate_OrgNameAppliesOnlyWhenNoOrgExists(t *testing.T) {
	pool := cliSetup(t)
	if r := cliCreate(t, pool, cliPassword+"\n", "--org-name", "Acme Traders"); r.code != 0 {
		t.Fatalf("exit = %d, stderr = %q", r.code, r.err)
	}
	if got := cliCount(t, pool, `SELECT count(*) FROM orgs WHERE name = 'Acme Traders'`); got != 1 {
		t.Errorf("orgs named Acme Traders = %d, want 1", got)
	}

	pool2 := cliSetup(t)
	if _, err := pool2.Exec(context.Background(), `INSERT INTO orgs (id, name) VALUES (gen_random_uuid(), 'Existing')`); err != nil {
		t.Fatal(err)
	}
	if r := cliCreate(t, pool2, cliPassword+"\n", "--org-name", "Ignored"); r.code != 0 {
		t.Fatalf("exit = %d, stderr = %q", r.code, r.err)
	}
	if got := cliCount(t, pool2, `SELECT count(*) FROM orgs`); got != 1 {
		t.Errorf("orgs = %d, want the existing one reused (--org-name ignored)", got)
	}
}

func TestAdminCreate_RefusesWhenAnAdminExists(t *testing.T) {
	pool := cliSetup(t)
	if r := cliCreate(t, pool, cliPassword+"\n"); r.code != 0 {
		t.Fatalf("setup: exit = %d, stderr = %q", r.code, r.err)
	}
	before := cliState(t, pool)
	r := cliExec(t, pool, []string{"create", "--email", "second@example.com", "--name", "Second"}, cliPassword+"\n")
	if r.code != 1 {
		t.Fatalf("exit = %d, want 1 (US-9 s2)", r.code)
	}
	if !regexp.MustCompile(`^error: bootstrap\.admin_exists: .+\n$`).MatchString(r.err) {
		t.Errorf("stderr = %q, want \"error: bootstrap.admin_exists: <message>\"", r.err)
	}
	if r.out != "" {
		t.Errorf("stdout = %q, want empty on a refusal", r.out)
	}
	if after := cliState(t, pool); after != before {
		t.Errorf("a refused run changed the database: %s -> %s", before, after)
	}
	noSecret(t, pool, r, cliPassword)
}

func TestAdminCreate_PolicyFailureNamesTheRule(t *testing.T) {
	long := strings.Repeat("a1b2", 65)
	for _, tt := range []struct{ name, password, code string }{
		{"too short", "short1", "auth.password_too_short"},
		{"too long", long, "auth.password_too_long"},
		{"too common", "1234567890", "auth.password_too_common"},
		{"equals the email", "owner@example.com", "auth.password_matches_identifier"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			pool := cliSetup(t)
			r := cliCreate(t, pool, tt.password+"\n")
			if r.code != 1 || r.out != "" {
				t.Fatalf("exit = %d stdout = %q, want 1 and no stdout (US-9 s3)", r.code, r.out)
			}
			if !strings.HasPrefix(r.err, "error: "+tt.code+": ") || strings.Count(r.err, "\n") != 1 {
				t.Errorf("stderr = %q, want one line \"error: %s: <message>\"", r.err, tt.code)
			}
			if got := cliState(t, pool); got != "orgs=0 users=0 mfa=0 audit=0" {
				t.Errorf("a policy failure left rows behind: %s", got)
			}
			if len(tt.password) > 12 {
				noSecret(t, pool, r, tt.password)
			}
		})
	}
}

func TestAdminCreate_TakenAndInvalidContactData(t *testing.T) {
	pool := cliSetup(t)
	org := uuid.New()
	if _, err := pool.Exec(context.Background(), `INSERT INTO orgs (id, name) VALUES ($1, 'Swastik')`, org); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(context.Background(), `INSERT INTO users (org_id, role, status, name, email, mobile, email_verified_at, mobile_verified_at, password_hash, password_changed_at)
		VALUES ($1, 'client', 'active', 'Client', 'taken@example.com', '+919876543210', now(), now(), '$argon2id$v=19$m=8,t=1,p=1$c2FsdHNhbHQ$YWJj', now())`, org); err != nil {
		t.Fatal(err)
	}
	before := cliState(t, pool)
	for _, tt := range []struct {
		name string
		args []string
		code string
	}{
		{"email of a client", []string{"create", "--email", "Taken@Example.com", "--name", "A"}, "auth.email_taken"},
		{"mobile of a client", []string{"create", "--email", "new@example.com", "--name", "A", "--mobile", "98765 43210"}, "auth.mobile_taken"},
		{"not an email", []string{"create", "--email", "not-an-email", "--name", "A"}, "auth.identifier_invalid"},
		{"bad mobile", []string{"create", "--email", "new@example.com", "--name", "A", "--mobile", "12345"}, "auth.identifier_invalid"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r := cliExec(t, pool, tt.args, cliPassword+"\n")
			if r.code != 1 || r.out != "" || !strings.HasPrefix(r.err, "error: "+tt.code+": ") {
				t.Fatalf("exit = %d stdout = %q stderr = %q, want 1, empty and error: %s: ... (US-9 s4)", r.code, r.out, r.err, tt.code)
			}
			if after := cliState(t, pool); after != before {
				t.Errorf("a refused run changed the database: %s -> %s", before, after)
			}
			noSecret(t, pool, r, cliPassword)
		})
	}
}

func TestAdminCreate_SeveralOrgsNeedOrgID(t *testing.T) {
	pool := cliSetup(t)
	a, b := uuid.New(), uuid.New()
	if _, err := pool.Exec(context.Background(), `INSERT INTO orgs (id, name) VALUES ($1, 'A'), ($2, 'B')`, a, b); err != nil {
		t.Fatal(err)
	}
	r := cliCreate(t, pool, cliPassword+"\n")
	if r.code != 1 || !strings.HasPrefix(r.err, "error: bootstrap.org_ambiguous: ") {
		t.Fatalf("exit = %d stderr = %q, want 1 and bootstrap.org_ambiguous", r.code, r.err)
	}
	if got := cliCount(t, pool, `SELECT count(*) FROM users`); got != 0 {
		t.Errorf("users = %d, want 0", got)
	}
	r = cliCreate(t, pool, cliPassword+"\n", "--org-id", b.String())
	if r.code != 0 {
		t.Fatalf("with --org-id: exit = %d stderr = %q", r.code, r.err)
	}
	if got := cliCount(t, pool, `SELECT count(*) FROM users WHERE org_id = $1 AND role = 'admin'`, b); got != 1 {
		t.Errorf("admins in the chosen org = %d, want 1", got)
	}
}

func TestAdminCreate_PasswordFromStdin(t *testing.T) {
	t.Run("empty stdin", func(t *testing.T) {
		pool := cliSetup(t)
		for _, in := range []string{"", "\n"} {
			r := cliCreate(t, pool, in)
			if r.code != 1 || !strings.HasPrefix(r.err, "error: bootstrap.no_password: ") {
				t.Errorf("stdin %q: exit = %d stderr = %q, want 1 and bootstrap.no_password", in, r.code, r.err)
			}
		}
		if got := cliState(t, pool); got != "orgs=0 users=0 mfa=0 audit=0" {
			t.Errorf("a refused run left rows behind: %s", got)
		}
	})
	t.Run("no trailing newline", func(t *testing.T) {
		pool := cliSetup(t)
		if r := cliCreate(t, pool, cliPassword); r.code != 0 {
			t.Fatalf("exit = %d stderr = %q", r.code, r.err)
		}
	})
	t.Run("exactly one line is read", func(t *testing.T) {
		pool := cliSetup(t)
		r := cliCreate(t, pool, cliPassword+"\nsecond-line-ignored-99\n")
		if r.code != 0 {
			t.Fatalf("exit = %d stderr = %q", r.code, r.err)
		}
		noSecret(t, pool, r, cliPassword, "second-line-ignored-99")
	})
}

func TestAdminCreate_UsageErrorsExitTwoAndTouchNothing(t *testing.T) {
	pool := cliSetup(t)
	for _, tt := range []struct {
		name string
		args []string
	}{
		{"no subcommand", []string{}},
		{"unknown subcommand", []string{"frobnicate"}},
		{"missing --email", []string{"create", "--name", "A"}},
		{"missing --name", []string{"create", "--email", "a@example.com"}},
		{"unknown flag", []string{"create", "--email", "a@example.com", "--name", "A", "--verbose"}},
		{"password as a flag", []string{"create", "--email", "a@example.com", "--name", "A", "--password", "flag-secret-12345"}},
		{"bad --org-id", []string{"create", "--email", "a@example.com", "--name", "A", "--org-id", "not-a-uuid"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r := cliExec(t, pool, tt.args, cliPassword+"\n")
			if r.code != 2 {
				t.Errorf("exit = %d, want 2 (usage error); stderr = %q", r.code, r.err)
			}
			if r.out != "" || strings.Contains(r.err+r.logs, "flag-secret-12345") {
				t.Errorf("stdout = %q; a flag value must never be echoed", r.out)
			}
		})
	}
	if got := cliState(t, pool); got != "orgs=0 users=0 mfa=0 audit=0" {
		t.Errorf("a usage error touched the database: %s", got)
	}
}

func TestAdminCreate_NeedsADatabaseURL(t *testing.T) {
	t.Setenv("DATABASE_URL", "")
	t.Setenv("APP_ENV", "local")
	var out, errb bytes.Buffer
	code := runAdmin(context.Background(), []string{"create", "--email", "a@example.com", "--name", "A"}, adminEnv{
		In: strings.NewReader(cliPassword + "\n"), Out: &out, Err: &errb, Now: clock.NewFake(cliT0).Now,
		Log: slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)),
	})
	if code != 1 || !strings.HasPrefix(errb.String(), "error: ") || out.Len() != 0 {
		t.Errorf("exit = %d stderr = %q stdout = %q, want 1 and an error line", code, errb.String(), out.String())
	}
	if strings.Contains(errb.String(), cliPassword) {
		t.Error("the password is in stderr")
	}
}

func TestAdminCreate_TwoConcurrentRunsOnAnEmptyDatabaseExactlyOneWins(t *testing.T) {
	pool := cliSetup(t)
	const n = 4
	runs := make([]cliRun, n)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			args := []string{"create", "--email", fmt.Sprintf("owner%d@example.com", i), "--name", "Owner"}
			runs[i] = cliExec(t, pool, args, cliPassword+"\n")
		}()
	}
	close(start)
	wg.Wait()
	wins := 0
	for i, r := range runs {
		switch {
		case r.code == 0:
			wins++
		case r.code != 1 || !strings.HasPrefix(r.err, "error: bootstrap.admin_exists: "):
			t.Errorf("run %d: exit = %d stderr = %q, want 1 and bootstrap.admin_exists", i, r.code, r.err)
		}
	}
	if wins != 1 {
		t.Fatalf("successful runs = %d, want exactly 1 (advisory lock)", wins)
	}
	if got := cliState(t, pool); got != "orgs=1 users=1 mfa=0 audit=1" {
		t.Errorf("database after the race: %s, want one org, one admin and one audit row", got)
	}
}
