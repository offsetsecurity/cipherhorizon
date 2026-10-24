package osfile_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/offsetsecurity/cipherhorizon/internal/osfile"
)

func TestTryLockIsExclusiveAndReleased(t *testing.T) {
	p := filepath.Join(t.TempDir(), "x.lock")
	a, err := os.OpenFile(p, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := osfile.TryLock(a); err != nil {
		t.Fatal(err)
	}
	if _, err := a.WriteAt([]byte("pid 1\n"), 0); err != nil {
		t.Fatal(err)
	}
	b, err := os.OpenFile(p, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close() //nolint:errcheck // test
	if err := osfile.TryLock(b); !errors.Is(err, osfile.ErrLocked) {
		t.Fatalf("second lock = %v, want ErrLocked", err)
	}
	// The holder's note stays readable while the lock is held.
	if note, err := os.ReadFile(p); err != nil || !strings.HasPrefix(string(note), "pid 1") {
		t.Errorf("reading the note while locked: %q, %v", note, err)
	}
	if err := osfile.Unlock(a); err != nil {
		t.Fatal(err)
	}
	_ = a.Close()
	if err := osfile.TryLock(b); err != nil {
		t.Fatalf("after release: %v", err)
	}
}

func TestFreeBytes(t *testing.T) {
	n, err := osfile.FreeBytes(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if n == 0 {
		t.Error("no free space reported in a writable folder")
	}
}
