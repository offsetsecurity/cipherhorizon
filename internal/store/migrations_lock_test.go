package store

import (
	"bufio"
	"crypto/sha256"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
)

// lockRelease, when set, appends every migration not yet in migrations.lock to it as shipped by that
// release. scripts/prepare-release.sh runs it; nothing else should.
var lockRelease = flag.String("lock-release", "", "append unlocked migrations to migrations.lock as shipped by this version")

const migrationsLockFile = "migrations.lock"

type lockedStep struct {
	version int
	sum     string
	release string
}

func readMigrationsLock(t *testing.T) []lockedStep {
	t.Helper()
	f, err := os.Open(migrationsLockFile)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close() //nolint:errcheck // read-only
	var out []lockedStep
	sc := bufio.NewScanner(f)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fs := strings.Fields(line)
		if len(fs) != 3 {
			t.Fatalf("%s:%d: want \"<step> <sha256> <release>\", got %q", migrationsLockFile, n, line)
		}
		v, err := strconv.Atoi(fs[0])
		if err != nil {
			t.Fatalf("%s:%d: step %q is not a number", migrationsLockFile, n, fs[0])
		}
		out = append(out, lockedStep{v, fs[1], fs[2]})
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

func migrationSum(v int) string { return fmt.Sprintf("%x", sha256.Sum256([]byte(migrations[v-1]))) }

// TestMigrationsLock is the rule that makes skipping versions safe: a migration that has shipped is
// history. An install that already ran it never runs it again, so editing it would make that install
// and a fresh one disagree for ever. Fix forward with a new step instead.
func TestMigrationsLock(t *testing.T) {
	locked := readMigrationsLock(t)
	for i, l := range locked {
		if l.version != i+1 {
			t.Fatalf("%s: entry %d is step %d; steps must be listed in order from 1 with none missing", migrationsLockFile, i+1, l.version)
		}
		if l.version > len(migrations) {
			t.Fatalf("step %d (shipped in %s) is missing from migrations: a released step is never removed", l.version, l.release)
		}
		if got := migrationSum(l.version); got != l.sum {
			t.Errorf("step %d shipped in %s and has been edited (sha256 %s, locked %s). Released migrations are never edited: undo the change and add a new step", l.version, l.release, got, l.sum)
		}
	}
	if *lockRelease == "" {
		return
	}
	rel := "v" + strings.TrimPrefix(*lockRelease, "v")
	f, err := os.OpenFile(migrationsLockFile, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close() //nolint:errcheck // checked below via the writes
	for v := len(locked) + 1; v <= len(migrations); v++ {
		if _, err := fmt.Fprintf(f, "%d %s %s\n", v, migrationSum(v), rel); err != nil {
			t.Fatal(err)
		}
		t.Logf("locked step %d as shipped in %s", v, rel)
	}
}

// TestUnreleasedMigrationsHaveUpgradeNotes: a release that changes the database tells operators what
// the upgrade does before they run it (PRD-016 §5.2). While a migration is not yet in migrations.lock,
// CHANGELOG.md's [Unreleased] section must hold an "### Upgrade notes" heading.
func TestUnreleasedMigrationsHaveUpgradeNotes(t *testing.T) {
	locked := len(readMigrationsLock(t))
	if locked >= len(migrations) {
		return
	}
	b, err := os.ReadFile("../../CHANGELOG.md")
	if err != nil {
		t.Fatal(err)
	}
	text := strings.ReplaceAll(string(b), "\r\n", "\n")
	start := strings.Index(text, "## [Unreleased]")
	if start < 0 {
		t.Fatal("CHANGELOG.md has no [Unreleased] section")
	}
	section := text[start+len("## [Unreleased]"):]
	if end := strings.Index(section, "\n## ["); end >= 0 {
		section = section[:end]
	}
	if !strings.Contains(section, "\n### Upgrade notes") {
		t.Errorf("migrations %d-%d are not released yet, and CHANGELOG.md [Unreleased] has no \"### Upgrade notes\": say what the upgrade does to the database (new tables, rewritten values, how long it may take)", locked+1, len(migrations))
	}
}
