package app

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"

	"github.com/example/cipherhorizon/internal/store"
)

// dbCmd runs maintenance on the database file. The estate graph is a projection of
// the stored documents (PRD-003 REQ-MOD-1), so it can always be dropped and rebuilt.
func dbCmd(args []string, env Env) int {
	if len(args) == 0 {
		dbUsage(env.Stderr)
		return ExitFatal
	}
	fl := flag.NewFlagSet("db "+args[0], flag.ContinueOnError)
	fl.SetOutput(io.Discard)
	dbPath := fl.String("db", "cipherhorizon.db", "SQLite database file")
	if err := fl.Parse(args[1:]); err != nil || fl.NArg() != 0 {
		dbUsage(env.Stderr)
		return ExitFatal
	}
	switch args[0] {
	case "rebuild-graph", "stats":
	default:
		dbUsage(env.Stderr)
		return ExitFatal
	}
	st, err := store.Open(*dbPath)
	if err != nil {
		return fatalf(env, "opening the database: %v", err)
	}
	defer st.Close() //nolint:errcheck // exiting
	switch args[0] {
	case "rebuild-graph":
		c, err := st.RebuildGraph()
		if err != nil {
			return fatalf(env, "rebuilding the graph: %v", err)
		}
		_, _ = fmt.Fprintf(env.Stdout, "rebuilt the estate graph from the stored documents: %d sources, %d entities, %d observations\n", c.Sources, c.Entities, c.Observations)
	case "stats":
		s, err := st.Stats()
		if err != nil {
			return fatalf(env, "reading the graph: %v", err)
		}
		b, _ := json.MarshalIndent(s, "", "  ")
		_, _ = fmt.Fprintln(env.Stdout, string(b))
	}
	return ExitOK
}

func dbUsage(w io.Writer) {
	_, _ = fmt.Fprint(w, `usage: cipherhorizon db rebuild-graph|stats [--db FILE]

  rebuild-graph  drop the estate graph and rebuild it from the stored scan reports and
                 host uploads (the documents themselves are never changed)
  stats          print what the graph holds
`)
}
