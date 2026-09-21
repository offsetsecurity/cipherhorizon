// Command cbom-scan inventories the cryptography installed on a host as a
// CycloneDX CBOM. All behaviour lives in internal/app; this file only wires the
// process to it and links in the built-in plugins.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/example/cbom-scan/internal/app"
	_ "github.com/example/cbom-scan/internal/plugins/all" // register built-in collectors
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := app.Main(ctx, os.Args[1:], app.Env{Stdout: os.Stdout, Stderr: os.Stderr})
	stop()
	os.Exit(code)
}
