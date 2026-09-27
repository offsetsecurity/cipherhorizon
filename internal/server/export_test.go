package server

import "time"

// SetExecPathForTest points collector-binary discovery at a fixture path instead of this test
// binary's own location, and returns a function that restores it.
func SetExecPathForTest(fn func() (string, error)) (restore func()) {
	old := execPath
	execPath = fn
	return func() { execPath = old }
}

// SetAuthFailDelay changes how long a failed authentication is held, and returns a
// function that restores it. Tests that make hundreds of deliberately failing calls use
// it so the delay (which exists to slow a guesser down) does not slow the suite down.
func SetAuthFailDelay(d time.Duration) (restore func()) {
	old := authFailDelay
	authFailDelay = d
	return func() { authFailDelay = old }
}
