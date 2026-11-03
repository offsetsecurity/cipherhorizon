package app

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/offsetsecurity/cipherhorizon/internal/store"
)

// dbCmd runs maintenance on the database file: upgrading it, checking it, backing it up and
// restoring it (PRD-016), and rebuilding the estate graph, which is a projection of the stored
// documents (PRD-003 REQ-MOD-1) and so can always be dropped and rebuilt.
func dbCmd(args []string, env Env) int {
	if len(args) == 0 {
		dbUsage(env.Stderr)
		return ExitFatal
	}
	sub := args[0]
	fl := flag.NewFlagSet("db "+sub, flag.ContinueOnError)
	fl.SetOutput(io.Discard)
	dbPath := fl.String("db", "", dbFlagHelp())
	asJSON := fl.Bool("json", false, "print JSON (status, check)")
	dryRun := fl.Bool("dry-run", false, "say what migrate would do, and change nothing")
	takesFile := sub == "backup" || sub == "restore"
	if err := fl.Parse(args[1:]); err != nil || (fl.NArg() != 0) != takesFile || fl.NArg() > 1 {
		dbUsage(env.Stderr)
		return ExitFatal
	}
	switch sub {
	case "rebuild-graph", "stats", "backup", "status", "check", "migrate", "restore":
	default:
		dbUsage(env.Stderr)
		return ExitFatal
	}
	if *asJSON && sub != "status" && sub != "check" {
		dbUsage(env.Stderr)
		return ExitFatal
	}
	if *dryRun && sub != "migrate" {
		dbUsage(env.Stderr)
		return ExitFatal
	}
	var err error
	if *dbPath, err = resolveDB(*dbPath, env); err != nil {
		return fatalf(env, "choosing the database: %v", err)
	}

	// These read or replace the file without opening it the usual way, so they never upgrade it.
	switch sub {
	case "status":
		return dbStatus(*dbPath, *asJSON, env)
	case "check":
		return dbCheck(*dbPath, *asJSON, env)
	case "restore":
		return dbRestore(*dbPath, fl.Arg(0), env)
	case "migrate":
		if *dryRun {
			return dbMigrateDryRun(*dbPath, env)
		}
	}

	if sub == "backup" || sub == "migrate" {
		if _, err := os.Stat(*dbPath); err != nil {
			return fatalf(env, "no database at %s (name it with --db)", *dbPath)
		}
	}
	var before store.Status
	if sub == "migrate" {
		if before, err = store.Inspect(*dbPath); err != nil {
			return fatalf(env, "reading %s: %v", *dbPath, err)
		}
	}
	st, err := store.Open(*dbPath)
	if err != nil {
		return fatalf(env, "opening the database: %v", err)
	}
	defer st.Close() //nolint:errcheck // exiting
	switch sub {
	case "migrate":
		// Open did the work (backup, steps, checks); this reports it.
		if len(before.Pending) == 0 {
			_, _ = fmt.Fprintf(env.Stdout, "%s is already at schema %d, this version's; nothing to do\n", *dbPath, before.Schema)
			break
		}
		_ = st.Close()
		after, err := store.Inspect(*dbPath)
		if err != nil {
			return fatalf(env, "reading the database: %v", err)
		}
		backup := ""
		if len(after.Upgrades) > 0 {
			backup = after.Upgrades[0].Backup
		}
		_, _ = fmt.Fprintf(env.Stdout, "upgraded %s from schema %d to %d and checked it; the backup made first is %s\n", *dbPath, before.Schema, after.Schema, backup)
	case "rebuild-graph":
		c, err := st.RebuildGraph()
		if err != nil {
			return fatalf(env, "rebuilding the graph: %v", err)
		}
		_, _ = fmt.Fprintf(env.Stdout, "rebuilt the estate graph from the stored documents: %d sources, %d entities, %d observations\n", c.Sources, c.Entities, c.Observations)
	case "backup":
		dst := fl.Arg(0)
		if err := st.BackupTo(dst); err != nil {
			return fatalf(env, "backing up: %v", err)
		}
		_, _ = fmt.Fprintf(env.Stdout, "wrote a consistent copy of %s to %s (readable by its owner only); it opens like any database: cipherhorizon serve --db %s\n", *dbPath, dst, dst)
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

func dbStatus(path string, asJSON bool, env Env) int {
	s, err := store.Inspect(path)
	if err != nil {
		return fatalf(env, "reading %s: %v", path, err)
	}
	if asJSON {
		b, _ := json.MarshalIndent(s, "", "  ")
		_, _ = fmt.Fprintln(env.Stdout, string(b))
		return ExitOK
	}
	w := env.Stdout
	if !s.Exists {
		_, _ = fmt.Fprintf(w, "database:  %s (not created yet; the server creates it at its first start)\n", path)
		return ExitOK
	}
	_, _ = fmt.Fprintf(w, "database:  %s (%s)\n", path, sizeText(s.Size))
	switch {
	case s.Newer:
		_, _ = fmt.Fprintf(w, "schema:    %d, made by a newer version; this one (schema %d) will not open it\n", s.Schema, s.ProgramSchema)
	case len(s.Pending) > 0:
		_, _ = fmt.Fprintf(w, "schema:    %d; this version upgrades it to %d at its next start (migrations %s), after a backup\n",
			s.Schema, s.ProgramSchema, stepsText(s.Pending))
	default:
		_, _ = fmt.Fprintf(w, "schema:    %d, this version's\n", s.Schema)
	}
	if s.StructureOK != nil && !*s.StructureOK {
		_, _ = fmt.Fprintln(w, "structure: differs from what this version builds; run cipherhorizon db check for details")
	}
	if s.InUse {
		who := s.InUseBy
		if who == "" {
			who = "another process"
		}
		_, _ = fmt.Fprintf(w, "in use:    yes, by %s\n", who)
	} else {
		_, _ = fmt.Fprintln(w, "in use:    no")
	}
	if len(s.Backups) == 0 {
		_, _ = fmt.Fprintln(w, "backups:   none made before an upgrade")
	} else {
		_, _ = fmt.Fprintln(w, "backups made before an upgrade (restore one with cipherhorizon db restore):")
		for _, b := range s.Backups {
			_, _ = fmt.Fprintf(w, "  %s  schema %d  %s  %s\n", b.Modified.UTC().Format("2006-01-02 15:04Z"), b.Schema, sizeText(b.Size), b.Path)
		}
	}
	if len(s.Upgrades) > 0 {
		_, _ = fmt.Fprintln(w, "history:")
		for _, u := range s.Upgrades {
			what := fmt.Sprintf("upgraded from schema %d to %d", u.FromSchema, u.ToSchema)
			if u.FromSchema == 0 {
				what = fmt.Sprintf("created at schema %d", u.ToSchema)
			}
			_, _ = fmt.Fprintf(w, "  %s  %s by version %s\n", u.At.UTC().Format("2006-01-02 15:04Z"), what, u.AppVersion)
		}
	}
	return ExitOK
}

func dbCheck(path string, asJSON bool, env Env) int {
	if _, err := os.Stat(path); err != nil {
		return fatalf(env, "no database at %s (name it with --db)", path)
	}
	res, err := store.Check(path)
	if err != nil {
		return fatalf(env, "checking %s: %v", path, err)
	}
	if asJSON {
		b, _ := json.MarshalIndent(struct {
			store.CheckResult
			OK bool `json:"ok"`
		}{res, res.OK()}, "", "  ")
		_, _ = fmt.Fprintln(env.Stdout, string(b))
	} else {
		w := env.Stdout
		mark := func(ok bool) string {
			if ok {
				return "ok  "
			}
			return "FAIL"
		}
		_, _ = fmt.Fprintf(w, "%s consistency (SQLite integrity_check)\n", mark(len(res.Integrity) == 0))
		for _, m := range res.Integrity {
			_, _ = fmt.Fprintf(w, "       %s\n", m)
		}
		_, _ = fmt.Fprintf(w, "%s references between rows (%d pointing at rows that do not exist)\n", mark(res.FKViolations == 0), res.FKViolations)
		switch {
		case res.Schema > res.ProgramSchema:
			_, _ = fmt.Fprintf(w, "FAIL schema %d is newer than this version's (%d): check it with the version that made it\n", res.Schema, res.ProgramSchema)
		case res.StructureOK == nil:
			_, _ = fmt.Fprintf(w, "-    structure not compared: schema %d is older than this version's %d (it is upgraded at the next start)\n", res.Schema, res.ProgramSchema)
		default:
			_, _ = fmt.Fprintf(w, "%s structure matches what this version builds (schema %d)\n", mark(*res.StructureOK), res.Schema)
			for _, d := range res.Differences {
				_, _ = fmt.Fprintf(w, "       %s\n", d)
			}
		}
	}
	if !res.OK() {
		return ExitIncomplete
	}
	return ExitOK
}

func dbMigrateDryRun(path string, env Env) int {
	s, err := store.Inspect(path)
	if err != nil {
		return fatalf(env, "reading %s: %v", path, err)
	}
	switch {
	case !s.Exists:
		return fatalf(env, "no database at %s (name it with --db)", path)
	case s.Newer:
		return fatalf(env, "%s is at schema %d, newer than this version's %d: it cannot be migrated by this version", path, s.Schema, s.ProgramSchema)
	case len(s.Pending) == 0:
		_, _ = fmt.Fprintf(env.Stdout, "%s is already at schema %d, this version's; nothing to do\n", path, s.Schema)
	default:
		_, _ = fmt.Fprintf(env.Stdout, "would back up %s (%s) next to it, then upgrade it from schema %d to %d (migrations %s) and check it; nothing was changed\n",
			path, sizeText(s.Size), s.Schema, s.ProgramSchema, stepsText(s.Pending))
		if s.InUse {
			_, _ = fmt.Fprintf(env.Stdout, "it is in use (%s): stop that first\n", s.InUseBy)
		}
	}
	return ExitOK
}

func dbRestore(path, backup string, env Env) int {
	res, err := store.Restore(path, backup)
	if errors.Is(err, store.ErrLocked) {
		return fatalf(env, "%v", err)
	}
	if err != nil {
		return fatalf(env, "restoring %s: %v", backup, err)
	}
	_, _ = fmt.Fprintf(env.Stdout, "restored %s from %s (schema %d)", path, backup, res.Schema)
	if res.MovedTo != "" {
		_, _ = fmt.Fprintf(env.Stdout, "; the database it replaced was kept as %s", res.MovedTo)
	}
	_, _ = fmt.Fprintln(env.Stdout)
	if res.Schema < store.SchemaVersion() {
		_, _ = fmt.Fprintf(env.Stdout, "it is at schema %d: this version upgrades it again at its next start; to stay on it, run the version that made it\n", res.Schema)
	}
	return ExitOK
}

func stepsText(steps []int) string {
	if len(steps) == 1 {
		return fmt.Sprint(steps[0])
	}
	return fmt.Sprintf("%d-%d", steps[0], steps[len(steps)-1])
}

func sizeText(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1f GiB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MiB", float64(n)/(1<<20))
	default:
		return fmt.Sprintf("%d KiB", (n+1023)/1024)
	}
}

func dbUsage(w io.Writer) {
	_, _ = fmt.Fprint(w, strings.TrimLeft(`
usage: cipherhorizon db status|check [--db FILE] [--json]
       cipherhorizon db migrate [--db FILE] [--dry-run]
       cipherhorizon db backup [--db FILE] BACKUP-FILE
       cipherhorizon db restore [--db FILE] BACKUP-FILE
       cipherhorizon db rebuild-graph|stats [--db FILE]

  status         the database's schema, whether this version would upgrade it, the backups made
                 before upgrades, its upgrade history and whether a server is using it. Changes nothing
  check          a thorough check, changing nothing: SQLite's integrity check, references between
                 rows, and the structure against this version's. Exit 2 if it finds a problem
  migrate        upgrade the database to this version now (the server otherwise does it at start,
                 unless run with --migrate refuse). A backup is made first, the result is checked,
                 and a failed upgrade is put back. --dry-run says what it would do
  backup         write a consistent copy of the database to BACKUP-FILE, safe while the
                 server runs; BACKUP-FILE must not exist. The copy holds password and
                 session hashes: keep it as carefully as the database
  restore        put BACKUP-FILE in place of the database. The server must be stopped. The
                 database it replaces is kept beside it, never deleted
  rebuild-graph  drop the estate graph and rebuild it from the stored scan reports and
                 host uploads (the documents themselves are never changed)
  stats          print what the graph holds
`, "\n"))
}
