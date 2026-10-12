package app

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/offsetsecurity/cipherhorizon/internal/auth"
	"github.com/offsetsecurity/cipherhorizon/internal/store"
)

// userCmd implements "cipherhorizon user": account recovery and set-up from the server's own
// console (ADR-0018). Whoever can run it can already read the database, so it needs no sign-in;
// a password is read from standard input, never from an argument (which the process list shows).
func userCmd(args []string, env Env) int {
	if len(args) == 0 {
		_, _ = fmt.Fprint(env.Stderr, userUsage)
		return ExitFatal
	}
	sub := args[0]
	fl := flag.NewFlagSet("user "+sub, flag.ContinueOnError)
	fl.SetOutput(env.Stderr)
	dbPath := fl.String("db", "", dbFlagHelp())
	role := fl.String("role", store.RoleAdmin, "role for a new account: admin, analyst or viewer")
	if err := fl.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return ExitOK
		}
		return ExitFatal
	}
	var err error
	if *dbPath, err = resolveDB(*dbPath, env); err != nil {
		return fatalf(env, "choosing the database: %v", err)
	}
	if _, err := os.Stat(*dbPath); err != nil {
		return fatalf(env, "%s: %v (start the server once to create it)", *dbPath, err)
	}
	st, err := store.Open(*dbPath)
	if err != nil {
		return fatalf(env, "opening the database: %v", err)
	}
	defer st.Close() //nolint:errcheck // nothing useful to do on close at exit

	name := strings.TrimSpace(fl.Arg(0))
	switch sub {
	case "list":
		us, err := st.ListUsers()
		if err != nil {
			return fatalf(env, "%v", err)
		}
		tw := tabwriter.NewWriter(env.Stdout, 0, 2, 2, ' ', 0)
		_, _ = fmt.Fprintln(tw, "USERNAME\tROLE\tSTATE\tLAST SIGN-IN")
		for _, u := range us {
			state := "enabled"
			switch {
			case u.Disabled:
				state = "disabled"
			case u.LockedUntil != nil:
				state = "locked until " + u.LockedUntil.Format("2006-01-02 15:04")
			}
			last := "never"
			if u.LastLoginAt != nil {
				last = u.LastLoginAt.Format("2006-01-02 15:04")
			}
			_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", u.Username, u.Role, state, last)
		}
		_ = tw.Flush()
		return ExitOK
	case "add", "reset-password", "unlock":
	default:
		_, _ = fmt.Fprint(env.Stderr, userUsage)
		return ExitFatal
	}
	if name == "" {
		return fatalf(env, "name the account: cipherhorizon user %s [--db FILE] USERNAME", sub)
	}
	if sub == "unlock" {
		u, err := st.UserByName(name)
		if err != nil {
			return fatalf(env, "no account %q", name)
		}
		if err := st.UnlockUser(u.ID); err != nil {
			return fatalf(env, "%v", err)
		}
		_ = st.AddAuthEvent(store.AuthEvent{Kind: "user-unlocked", Username: u.Username, Actor: "console"})
		_, _ = fmt.Fprintf(env.Stdout, "unlocked %s\n", u.Username)
		return ExitOK
	}
	_, _ = fmt.Fprintf(env.Stderr, "password for %s (at least %d characters), then Enter: ", name, auth.MinPasswordLen)
	pw, err := readLine(os.Stdin)
	if err != nil {
		return fatalf(env, "reading the password: %v", err)
	}
	if err := auth.CheckPassword(pw, name); err != nil {
		return fatalf(env, "%v", err)
	}
	hash, err := auth.Hash(pw)
	if err != nil {
		return fatalf(env, "%v", err)
	}
	if sub == "add" {
		if err := auth.CheckUsername(name); err != nil {
			return fatalf(env, "%v", err)
		}
		if *role != store.RoleAdmin && *role != store.RoleAnalyst && *role != store.RoleViewer {
			return fatalf(env, "--role must be admin, analyst or viewer")
		}
		u, err := st.CreateUser(name, "", *role, hash, false, "console")
		if err != nil {
			return fatalf(env, "%v", err)
		}
		_ = st.AddAuthEvent(store.AuthEvent{Kind: "user-created", Username: u.Username, Actor: "console", Detail: "role " + u.Role})
		_, _ = fmt.Fprintf(env.Stdout, "added %s (%s)\n", u.Username, u.Role)
		return ExitOK
	}
	u, err := st.UserByName(name)
	if err != nil {
		return fatalf(env, "no account %q", name)
	}
	if err := st.SetPassword(u.ID, hash, false, 0); err != nil {
		return fatalf(env, "%v", err)
	}
	_ = st.AddAuthEvent(store.AuthEvent{Kind: "password-reset", Username: u.Username, Actor: "console", Detail: "sessions ended"})
	_, _ = fmt.Fprintf(env.Stdout, "password set for %s; their other sessions are signed out\n", u.Username)
	return ExitOK
}

func readLine(r io.Reader) (string, error) {
	line, err := bufio.NewReader(r).ReadString('\n')
	if err != nil && (!errors.Is(err, io.EOF) || line == "") {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

const userUsage = `usage: cipherhorizon user COMMAND [--db FILE] [USERNAME]

Manage accounts from the server's console (for recovery, or to script set-up):
  list                    list accounts, their roles and state
  add USERNAME [--role R] add an account (admin, analyst or viewer); the password is read from standard input
  reset-password USERNAME set a new password (read from standard input) and sign the account out everywhere
  unlock USERNAME         clear a lockout after repeated failed sign-ins
`
