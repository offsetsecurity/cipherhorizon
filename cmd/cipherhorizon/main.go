// Command cipherhorizon is a cryptographic posture tool: it inventories the
// cryptography installed on a host as a CycloneDX CBOM, actively scans TLS/SSL
// endpoints, and serves a web UI over both. All behaviour lives in internal/app;
// this file only wires the process to it. (The built-in sensors are linked in by
// internal/app.)
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/example/cipherhorizon/internal/app"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := app.Main(ctx, os.Args[1:], app.Env{Stdout: os.Stdout, Stderr: os.Stderr})
	stop()
	os.Exit(code)
}
