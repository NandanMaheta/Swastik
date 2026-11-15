package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"

	"github.com/google/uuid"
	"golang.org/x/term"

	"github.com/NandanMaheta/swastik/apps/api/internal/auth"
	"github.com/NandanMaheta/swastik/apps/api/internal/platform/clock"
	"github.com/NandanMaheta/swastik/apps/api/internal/platform/config"
	"github.com/NandanMaheta/swastik/apps/api/internal/platform/db"
)

// Exit statuses of `swastik admin` (contracts/cli.md).
const (
	exitOK      = 0
	exitFailure = 1
	exitUsage   = 2
)

// adminEnv is everything runAdmin touches besides the database: the standard streams, the clock
// and the logger, so tests can inject them. A reader that is not a terminal is read as one line.
type adminEnv struct {
	In  io.Reader
	Out io.Writer
	Err io.Writer
	Now clock.Func
	Log *slog.Logger
}

const adminUsage = "usage: swastik admin create --email <email> --name <name> [--mobile <mobile>] [--org-name <name>] [--org-id <uuid>]"

// runAdmin runs `swastik admin <args...>` (args exclude "admin") and returns the exit status:
// 0 on success, 1 on any refusal or error, 2 on usage errors. It reads only DATABASE_URL and
// APP_ENV, takes the password from the terminal or one line of stdin (never a flag or the
// environment), and never writes the password anywhere.
func runAdmin(ctx context.Context, args []string, env adminEnv) int {
	if len(args) == 0 || args[0] != "create" {
		return usageError(env, "expected the subcommand create")
	}
	fs := flag.NewFlagSet("create", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var email, name, mobile, orgName, orgID string
	fs.StringVar(&email, "email", "", "")
	fs.StringVar(&name, "name", "", "")
	fs.StringVar(&mobile, "mobile", "", "")
	fs.StringVar(&orgName, "org-name", "", "")
	fs.StringVar(&orgID, "org-id", "", "")
	if err := fs.Parse(args[1:]); err != nil {
		return usageError(env, "invalid flags") // flag errors name the flag, never a value
	}
	if fs.NArg() > 0 || strings.TrimSpace(email) == "" || strings.TrimSpace(name) == "" {
		return usageError(env, "--email and --name are required and nothing else is accepted")
	}
	org := uuid.Nil
	if orgID != "" {
		var err error
		if org, err = uuid.Parse(orgID); err != nil {
			return usageError(env, "--org-id must be a UUID")
		}
	}

	cfg, err := config.LoadDB()
	if err != nil {
		return refuse(env, "bootstrap.not_configured", "DATABASE_URL is not set or is invalid")
	}
	password, err := readPassword(env)
	if err != nil {
		return refuse(env, "bootstrap.no_password", err.Error())
	}
	pool, err := db.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		env.Log.ErrorContext(ctx, "admin create: cannot open the database", "err", err)
		return refuse(env, "bootstrap.database", "the database is not reachable")
	}
	defer pool.Close()

	txr := db.NewTxRunner(pool)
	boot, err := auth.NewBootstrapper(auth.BootstrapDeps{
		Store: auth.NewPGStore(txr), Tx: txr, Now: env.Now, Hasher: auth.NewHasher(auth.HasherOptions{}),
	})
	if err != nil {
		env.Log.ErrorContext(ctx, "admin create: wiring", "err", err)
		return refuse(env, "bootstrap.internal", "the command could not start")
	}
	res, err := boot.CreateAdmin(ctx, auth.BootstrapInput{
		Email: email, Name: name, Mobile: mobile, Password: password, OrgName: orgName, OrgID: org,
	})
	if err != nil {
		code, msg := bootstrapProblem(err)
		if code == "bootstrap.internal" {
			env.Log.ErrorContext(ctx, "admin create failed", "err", err)
		}
		return refuse(env, code, msg)
	}
	_, _ = fmt.Fprintf(env.Out, "admin created: id=%s email=%s\n", res.UserID, res.Email)
	return exitOK
}

func usageError(env adminEnv, msg string) int {
	_, _ = fmt.Fprintf(env.Err, "error: %s\n%s\n", msg, adminUsage)
	return exitUsage
}

// refuse prints the one-line refusal of contracts/cli.md and returns exit status 1.
func refuse(env adminEnv, code, msg string) int {
	_, _ = fmt.Fprintf(env.Err, "error: %s: %s\n", code, msg)
	return exitFailure
}

// bootstrapProblem maps a CreateAdmin error to its code and an English message that names the
// failed rule and never echoes input.
func bootstrapProblem(err error) (code, msg string) {
	var policy *auth.PolicyError
	switch {
	case errors.As(err, &policy):
		return policy.Code, policyMessage(policy.Code)
	case errors.Is(err, auth.ErrInvalidIdentifier):
		return auth.CodeIdentifierInvalid, "the email or mobile number is not valid"
	case errors.Is(err, auth.ErrEmailTaken):
		return auth.CodeEmailTaken, "the email address is already used by another account"
	case errors.Is(err, auth.ErrMobileTaken):
		return auth.CodeMobileTaken, "the mobile number is already used by another account"
	case errors.Is(err, auth.ErrAdminExists):
		return "bootstrap.admin_exists", "an admin already exists in this organisation; create further admins in the panel"
	case errors.Is(err, auth.ErrOrgAmbiguous):
		return "bootstrap.org_ambiguous", "more than one organisation exists; pass --org-id"
	case errors.Is(err, auth.ErrNoOrg):
		return "bootstrap.org_not_found", "the organisation given by --org-id does not exist"
	default:
		return "bootstrap.internal", "the admin could not be created"
	}
}

func policyMessage(code string) string {
	switch code {
	case auth.PolicyTooShort:
		return "the password must have at least 10 characters"
	case auth.PolicyTooLong:
		return "the password must have at most 256 characters"
	case auth.PolicyTooCommon:
		return "the password is on the list of commonly used passwords"
	case auth.PolicyMatchesIdentifier:
		return "the password must not equal the email address or mobile number"
	default:
		return "the password does not meet the policy"
	}
}

// readPassword prompts twice without echo on a terminal, otherwise reads exactly one line.
func readPassword(env adminEnv) (string, error) {
	if f, ok := env.In.(*os.File); ok && term.IsTerminal(int(f.Fd())) { //nolint:gosec // a file descriptor fits in int
		_, _ = fmt.Fprint(env.Err, "Password: ")
		first, err := term.ReadPassword(int(f.Fd())) //nolint:gosec // as above
		_, _ = fmt.Fprintln(env.Err)
		if err != nil {
			return "", errors.New("the password could not be read")
		}
		_, _ = fmt.Fprint(env.Err, "Repeat password: ")
		second, err := term.ReadPassword(int(f.Fd())) //nolint:gosec // as above
		_, _ = fmt.Fprintln(env.Err)
		if err != nil {
			return "", errors.New("the password could not be read")
		}
		if string(first) != string(second) {
			return "", errors.New("the two passwords differ")
		}
		return nonEmpty(string(first))
	}
	line, err := bufio.NewReader(env.In).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", errors.New("the password could not be read")
	}
	return nonEmpty(strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r"))
}

func nonEmpty(password string) (string, error) {
	if password == "" {
		return "", errors.New("no password was given; pipe it on stdin or type it at the prompt")
	}
	return password, nil
}
