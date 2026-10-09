package store_test

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/example/cipherhorizon/internal/store"
)

// PRD-007 REQ-TR-5 (audit L-14): a migration keeps the newest three backups, deletes the rest,
// and the log names each one it made or deleted.
func TestOldBackupsArePruned(t *testing.T) {
	path, _ := legacy(t)
	old := time.Now().Add(-30 * 24 * time.Hour)
	var planted []string
	for i := range 5 {
		name := path + ".bak-v" + string(rune('1'+i%2)) + "-2025010" + string(rune('1'+i)) + "T000000Z"
		if err := os.WriteFile(name, []byte("old copy"), 0o600); err != nil {
			t.Fatal(err)
		}
		at := old.Add(time.Duration(i) * time.Hour) // planted[4] is the newest of them
		if err := os.Chtimes(name, at, at); err != nil {
			t.Fatal(err)
		}
		planted = append(planted, name)
	}
	// A file that only looks related is never touched.
	other := path + ".backup-notes"
	if err := os.WriteFile(other, []byte("mine"), 0o600); err != nil {
		t.Fatal(err)
	}

	s, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	var logged bytes.Buffer
	s.SetLogger(slog.New(slog.NewTextHandler(&logged, nil)))
	_ = s.Close()

	left, _ := filepath.Glob(path + ".bak-v*")
	sort.Strings(left)
	var fresh string
	for _, n := range left {
		if strings.HasPrefix(n, path+".bak-v3-") {
			fresh = n
		}
	}
	want := []string{planted[3], planted[4], fresh}
	sort.Strings(want)
	if fresh == "" || strings.Join(left, "\n") != strings.Join(want, "\n") {
		t.Fatalf("backups left:\n  %s\nwant the new one and the two newest planted:\n  %s", strings.Join(left, "\n  "), strings.Join(want, "\n  "))
	}
	if _, err := os.Stat(other); err != nil {
		t.Errorf("an unrelated file was removed: %v", err)
	}
	log := logged.String()
	if !strings.Contains(log, "backed up the database before migrating it") || !strings.Contains(log, filepath.Base(fresh)) {
		t.Errorf("the log does not name the new backup:\n%s", log)
	}
	for _, gone := range planted[:3] {
		if !strings.Contains(log, filepath.Base(gone)) {
			t.Errorf("the log does not name the deleted %s:\n%s", filepath.Base(gone), log)
		}
	}
	if n := strings.Count(log, "deleted an old backup"); n != 3 {
		t.Errorf("%d deletions logged, want 3:\n%s", n, log)
	}
}
