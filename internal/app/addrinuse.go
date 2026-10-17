package app

import (
	"errors"
	"syscall"
)

// isAddrInUse reports whether a listen failed because something already holds the address.
// Windows reports WSAEADDRINUSE (10048), which is not syscall.EADDRINUSE there.
func isAddrInUse(err error) bool {
	const wsaeAddrInUse = syscall.Errno(10048)
	return errors.Is(err, syscall.EADDRINUSE) || errors.Is(err, wsaeAddrInUse)
}
