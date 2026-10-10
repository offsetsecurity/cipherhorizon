package store

import (
	"errors"
	"os"
	"strings"
)

// restrictFile makes sure the database file exists and is readable by its owner
// only. In-memory and URI paths are left alone.
func restrictFile(path string) error {
	if path == "" || path == ":memory:" || strings.HasPrefix(path, "file:") {
		return nil
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Chmod(path, 0o600); err != nil && !errors.Is(err, os.ErrPermission) {
		return err
	}
	return nil
}
