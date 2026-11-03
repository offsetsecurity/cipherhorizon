package app_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/offsetsecurity/cipherhorizon/internal/app"
	"github.com/offsetsecurity/cipherhorizon/internal/store"
)

// oldDB copies the database written by the real 0.1.0 release (internal/store/testdata/upgrade).
func oldDB(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("../store/testdata/upgrade/v0.1.0.db")
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "cipherhorizon.db")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// PRD-016 U-07: an operator can see, rehearse, run and check an upgrade, and go back, with the same
// commands on every platform.
func TestDBUpgradeCommands(t *testing.T) {
	db := oldDB(t)
	want := store.SchemaVersion()

	code, out, errOut := run(t, "db", "status", "--db", db)
	if code != 0 || !strings.Contains(out, "schema:    14; this version upgrades it to") || !strings.Contains(out, "in use:    no") {
		t.Fatalf("status of a 0.1.0 database: %d %q %q", code, out, errOut)
	}
	code, out, _ = run(t, "db", "migrate", "--dry-run", "--db", db)
	if code != 0 || !strings.Contains(out, "would back up") || !strings.Contains(out, "nothing was changed") {
		t.Fatalf("migrate --dry-run: %d %q", code, out)
	}
	if st, _ := store.Inspect(db); st.Schema != 14 {
		t.Fatalf("--dry-run changed the schema to %d", st.Schema)
	}

	code, out, errOut = run(t, "db", "migrate", "--db", db)
	if code != 0 || !strings.Contains(out, "upgraded") || !strings.Contains(out, ".bak-v14-") {
		t.Fatalf("migrate: %d %q %q", code, out, errOut)
	}
	code, out, _ = run(t, "db", "migrate", "--db", db)
	if code != 0 || !strings.Contains(out, "nothing to do") {
		t.Errorf("second migrate: %d %q", code, out)
	}

	code, out, _ = run(t, "db", "status", "--db", db, "--json")
	var st store.Status
	if code != 0 || json.Unmarshal([]byte(out), &st) != nil || st.Schema != want || len(st.Upgrades) != 1 || st.Upgrades[0].FromSchema != 14 || len(st.Backups) != 1 {
		t.Fatalf("status --json after the upgrade: %d %q", code, out)
	}

	code, out, _ = run(t, "db", "check", "--db", db)
	if code != 0 || strings.Contains(out, "FAIL") || !strings.Contains(out, "structure matches") {
		t.Fatalf("check: %d %q", code, out)
	}

	// Back to the copy made before the upgrade: the server would then upgrade it again at its
	// next start, and the restore says so.
	code, out, errOut = run(t, "db", "restore", "--db", db, st.Backups[0].Path)
	if code != 0 || !strings.Contains(out, "restored") || !strings.Contains(out, "kept as") || !strings.Contains(out, "schema 14") {
		t.Fatalf("restore: %d %q %q", code, out, errOut)
	}
	if s, _ := store.Inspect(db); s.Schema != 14 {
		t.Errorf("after restore: schema %d, want 14", s.Schema)
	}

	for _, args := range [][]string{
		{"db", "restore", "--db", db},                     // no file
		{"db", "status", "--db", db, "extra"},             // stray argument
		{"db", "migrate", "--json", "--db", db},           // --json is for status and check
		{"db", "check", "--dry-run", "--db", db},          // --dry-run is for migrate
		{"db", "migrate", "--db", db + ".does-not-exist"}, // nothing to migrate
	} {
		if code, _, _ := run(t, args...); code != app.ExitFatal {
			t.Errorf("%v: exit %d, want %d", args, code, app.ExitFatal)
		}
	}
}

func TestDBCheckReportsAProblem(t *testing.T) {
	db := filepath.Join(t.TempDir(), "x.db")
	if code, _, _ := run(t, "db", "stats", "--db", db); code != 0 {
		t.Fatal("creating the database failed")
	}
	sqldb, err := sql.Open("sqlite", "file:"+db)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sqldb.Exec(`CREATE INDEX hand_made ON assets(host)`); err != nil {
		t.Fatal(err)
	}
	_ = sqldb.Close()
	code, out, _ := run(t, "db", "check", "--db", db)
	if code != app.ExitIncomplete || !strings.Contains(out, "FAIL structure") || !strings.Contains(out, "hand_made") {
		t.Errorf("check of a hand-edited database: %d %q", code, out)
	}
}

func TestServeMigrateRefuse(t *testing.T) {
	db := oldDB(t)
	code, _, errOut := run(t, "serve", "--addr", "127.0.0.1:0", "--db", db, "--migrate", "refuse")
	if code != app.ExitFatal || !strings.Contains(errOut, "cipherhorizon db migrate") {
		t.Fatalf("serve --migrate refuse on a 0.1.0 database: %d %q", code, errOut)
	}
	if st, _ := store.Inspect(db); st.Schema != 14 || len(st.Backups) != 0 {
		t.Errorf("refuse changed the database: schema %d, %d backups", st.Schema, len(st.Backups))
	}
	if code, _, errOut := run(t, "serve", "--addr", "127.0.0.1:0", "--db", db, "--migrate", "sometimes"); code != app.ExitFatal || !strings.Contains(errOut, "--migrate must be") {
		t.Errorf("bad --migrate: %d %q", code, errOut)
	}
}

// The user's question, answered by test: point serve at an old database and it upgrades it at
// launch, then serves; a second server on the same file is refused while the first runs.
func TestServeUpgradesAtLaunchAndHoldsTheDatabase(t *testing.T) {
	t.Setenv("CIPHERHORIZON_TOKEN", "")
	db := oldDB(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errb := &lockedBuf{}
	done := make(chan int, 1)
	go func() {
		done <- app.Main(ctx, []string{"serve", "--addr", "127.0.0.1:0", "--db", db}, app.Env{Stdout: io.Discard, Stderr: errb})
	}()
	re := regexp.MustCompile(`on http://127\.0\.0\.1:\d+`)
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) && !re.MatchString(errb.String()) {
		time.Sleep(20 * time.Millisecond)
	}
	if !re.MatchString(errb.String()) {
		t.Fatalf("server never started; stderr:\n%s", errb.String())
	}
	if !strings.Contains(errb.String(), "upgraded the database") || !strings.Contains(errb.String(), "backed up the database") {
		t.Errorf("the upgrade at launch was not logged:\n%s", errb.String())
	}

	code, _, errOut := run(t, "serve", "--addr", "127.0.0.1:0", "--db", db)
	if code != app.ExitFatal || !strings.Contains(errOut, "another CipherHorizon process") || !strings.Contains(errOut, "pid ") {
		t.Errorf("second server on the same database: %d %q", code, errOut)
	}
	code, out, _ := run(t, "db", "status", "--db", db)
	if code != 0 || !strings.Contains(out, "in use:    yes, by pid") {
		t.Errorf("status while serving: %d %q", code, out)
	}
	// A backup while it serves still works (no upgrade needed, so no lock).
	if code, _, errOut := run(t, "db", "backup", "--db", db, filepath.Join(t.TempDir(), "live.db")); code != 0 {
		t.Errorf("backup while serving: %d %q", code, errOut)
	}

	cancel()
	select {
	case code := <-done:
		if code != app.ExitOK {
			t.Errorf("exit %d; stderr:\n%s", code, errb.String())
		}
	case <-time.After(15 * time.Second):
		t.Fatal("server did not shut down")
	}
}
