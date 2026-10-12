// Package winsvc is the platform layer for running as a Windows service: it talks to the
// Service Control Manager and sets folder permissions, and knows nothing else about the
// program (internal/app decides what the service runs and where its files go). Like
// internal/winapi it may not run subprocesses, use the network, or import this module.
// Everything is Windows-only; on other systems the package is empty.
package winsvc
