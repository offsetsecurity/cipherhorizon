// Package osfile is the platform layer for two things the database needs from the operating system
// and the standard library does not offer: an exclusive lock on a file that the OS releases when the
// process ends, and the free space in a folder. Like internal/hostinfo, internal/winapi and
// internal/winsvc it is where operating-system code lives, so nothing else has to import
// x/sys/windows (enforced by internal/archtest). It imports nothing else from this module.
package osfile

import "errors"

// ErrLocked is returned by TryLock when another open of the file (in any process) holds the lock.
var ErrLocked = errors.New("the file is locked by another process")

// ErrUnsupported is returned where an operation does not exist on this operating system.
var ErrUnsupported = errors.New("not supported on this operating system")
