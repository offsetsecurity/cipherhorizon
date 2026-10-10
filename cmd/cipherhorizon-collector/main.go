// Command cipherhorizon-collector inventories the cryptographic software on the machine it
// runs on and writes a CycloneDX CBOM. It is the program to deploy on endpoints: read-only,
// no subprocess, no network, no web server, no database, no TLS scanner. Everything else
// (the scanner, the UI, the store) lives in cmd/cipherhorizon, which is the full product
// and is not needed on a machine being inventoried.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/offsetsecurity/cipherhorizon/internal/hostcmd"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := hostcmd.Main(ctx, os.Args[1:], hostcmd.Env{Stdout: os.Stdout, Stderr: os.Stderr, Prog: "cipherhorizon-collector"})
	stop()
	os.Exit(code)
}
