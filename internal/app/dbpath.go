package app

import (
	"fmt"

	"github.com/offsetsecurity/cipherhorizon/internal/datadir"
)

// dbFlagHelp is the --db help text shared by the commands that open the database.
func dbFlagHelp() string {
	return "SQLite database file (default: $" + datadir.EnvVar + ", else " + datadir.File +
		" if one is in the current folder, else " + datadir.DefaultPath() + ")"
}

// resolveDB turns a --db value into the database path (see internal/datadir) and, when an old
// database in the working directory was chosen, says so: the default location has moved.
func resolveDB(flagValue string, env Env) (string, error) {
	p, src, err := datadir.Resolve(flagValue)
	if err != nil {
		return "", err
	}
	if src == datadir.FromWorkingDir {
		_, _ = fmt.Fprintf(env.Stderr, "note: using %s in the current folder. New installs keep it in %s; move it there, "+
			"or keep naming it with --db or %s.\n", datadir.File, datadir.DefaultPath(), datadir.EnvVar)
	}
	return p, nil
}
