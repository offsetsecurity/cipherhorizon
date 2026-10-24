package store

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/offsetsecurity/cipherhorizon/internal/osfile"
	"github.com/offsetsecurity/cipherhorizon/internal/version"
)

// ErrLocked means another process holds the database's lock: a running server, or another
// command in the middle of migrating it.
var ErrLocked = errors.New("another CipherHorizon process is using this database")

// LockedError says who holds the lock, as far as the lock file tells.
type LockedError struct {
	Path   string
	Holder string // "pid 123, version 0.5.0, since …", or "" when the file could not be read
}

func (e *LockedError) Error() string {
	who := ""
	if e.Holder != "" {
		who = " (" + e.Holder + ")"
	}
	return fmt.Sprintf("another CipherHorizon process%s is using %s; stop it first, or point this one at another database with --db", who, strings.TrimSuffix(e.Path, ".lock"))
}

func (e *LockedError) Unwrap() error { return ErrLocked }

// fileLock is an OS lock on "<database>.lock". The OS releases it when the process ends, however
// it ends, so a crash never leaves the database locked; the file itself stays (deleting it would
// race with the next process taking it) and is harmless.
type fileLock struct {
	f *os.File
}

// lockPath is where a database's lock lives.
func lockPath(dbPath string) string { return dbPath + ".lock" }

// lockable reports whether a path names a file this package can lock (not memory, not a URI).
func lockable(dbPath string) bool {
	return dbPath != "" && dbPath != ":memory:" && !strings.HasPrefix(dbPath, "file:")
}

// acquireLock takes the database's lock without waiting. It fails with a *LockedError when another
// process (or another Store in this process) holds it.
func acquireLock(dbPath string) (*fileLock, error) {
	p := lockPath(dbPath)
	if err := restrictFile(p); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(p, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("store: opening the lock %s: %w", p, err)
	}
	if err := osfile.TryLock(f); err != nil {
		_ = f.Close()
		if errors.Is(err, osfile.ErrLocked) {
			return nil, &LockedError{Path: p, Holder: readHolder(p)}
		}
		return nil, fmt.Errorf("store: locking %s: %w", p, err)
	}
	// Say who holds it, for the next process's message. Best effort: the lock is what matters.
	if err := f.Truncate(0); err == nil {
		_, _ = f.WriteAt([]byte(fmt.Sprintf("pid %d, version %s, since %s\n", os.Getpid(), version.Version, time.Now().UTC().Format(time.RFC3339))), 0)
	}
	return &fileLock{f: f}, nil
}

// release gives the lock back. Safe on nil.
func (l *fileLock) release() {
	if l == nil || l.f == nil {
		return
	}
	_ = osfile.Unlock(l.f)
	_ = l.f.Close()
	l.f = nil
}

// readHolder reads what the holder wrote into the lock file.
func readHolder(p string) string {
	b, err := os.ReadFile(p)
	if err != nil {
		return ""
	}
	s := strings.TrimSpace(string(b))
	if len(s) > 200 || strings.ContainsAny(s, "\r\n") {
		return ""
	}
	return s
}

// LockHolder reports whether another process holds the database's lock and, if so, who. It takes
// the lock for a moment to find out, so it must not be called while this process holds it.
func LockHolder(dbPath string) (held bool, holder string, err error) {
	if !lockable(dbPath) {
		return false, "", nil
	}
	l, err := acquireLock(dbPath)
	var le *LockedError
	if errors.As(err, &le) {
		return true, le.Holder, nil
	}
	if err != nil {
		return false, "", err
	}
	l.release()
	return false, "", nil
}
