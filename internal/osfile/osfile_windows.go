//go:build windows

package osfile

import (
	"errors"
	"os"

	"golang.org/x/sys/windows"
)

// The lock covers one byte far past anything written, so a note at the start of the file stays
// readable by a process that was refused (a locked range cannot be read on Windows).
const (
	lockOffsetLow  = 0
	lockOffsetHigh = 0x7fff
)

// TryLock takes an exclusive LockFileEx lock on f without waiting. Windows locks belong to the handle,
// so a second open of the same file, in this process or another, is refused too.
func TryLock(f *os.File) error {
	ol := &windows.Overlapped{Offset: lockOffsetLow, OffsetHigh: lockOffsetHigh}
	err := windows.LockFileEx(windows.Handle(f.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, ol)
	if errors.Is(err, windows.ERROR_LOCK_VIOLATION) || errors.Is(err, windows.ERROR_IO_PENDING) {
		return ErrLocked
	}
	return err
}

// Unlock gives the lock back (closing f does too).
func Unlock(f *os.File) error {
	ol := &windows.Overlapped{Offset: lockOffsetLow, OffsetHigh: lockOffsetHigh}
	return windows.UnlockFileEx(windows.Handle(f.Fd()), 0, 1, 0, ol)
}

// FreeBytes is how much space the calling user may still write on dir's volume.
func FreeBytes(dir string) (uint64, error) {
	p, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return 0, err
	}
	var avail, total, free uint64
	if err := windows.GetDiskFreeSpaceEx(p, &avail, &total, &free); err != nil {
		return 0, err
	}
	return avail, nil
}
