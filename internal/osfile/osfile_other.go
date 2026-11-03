//go:build !unix && !windows

package osfile

import "os"

// TryLock always succeeds: there is no OS file lock here (every release target is unix or windows).
func TryLock(*os.File) error { return nil }

// Unlock does nothing.
func Unlock(*os.File) error { return nil }

// FreeBytes is not known here.
func FreeBytes(string) (uint64, error) { return 0, ErrUnsupported }
