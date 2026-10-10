package store

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestOpenCreatesOwnerOnlyDatabase(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("mode bits are not enforced on Windows")
	}
	path := filepath.Join(t.TempDir(), "ch.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close() //nolint:errcheck // test
	for _, p := range []string{path, path + "-wal", path + "-shm"} {
		fi, err := os.Stat(p)
		if err != nil {
			continue // the side files exist only while the database is busy
		}
		if perm := fi.Mode().Perm(); perm&0o077 != 0 {
			t.Errorf("%s has mode %o; want no group or other access", filepath.Base(p), perm)
		}
	}
}

func TestOpenTightensAnExistingDatabase(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("mode bits are not enforced on Windows")
	}
	path := filepath.Join(t.TempDir(), "old.db")
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close() //nolint:errcheck // test
	fi, _ := os.Stat(path)
	if fi.Mode().Perm()&0o077 != 0 {
		t.Errorf("existing database left at mode %o", fi.Mode().Perm())
	}
}

func TestRestrictFileIgnoresMemoryAndURIs(t *testing.T) {
	for _, p := range []string{"", ":memory:", "file:x?mode=memory"} {
		if err := restrictFile(p); err != nil {
			t.Errorf("%q: %v", p, err)
		}
	}
}
