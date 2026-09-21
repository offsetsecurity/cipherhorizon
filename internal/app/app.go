// Package app implements the command-line interface. cmd/cbom-scan/main.go is a
// thin shim over Main so that everything here is testable in-process, with the
// clock, serial number, hostname and output streams injected.
package app

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"text/tabwriter"
	"time"

	"github.com/example/cbom-scan/internal/cbom"
	"github.com/example/cbom-scan/internal/collector"
	"github.com/example/cbom-scan/internal/config"
	"github.com/example/cbom-scan/internal/pqc"
	"github.com/example/cbom-scan/internal/scan"
	"github.com/example/cbom-scan/internal/version"
)

// Exit codes.
const (
	ExitOK         = 0 // success
	ExitFatal      = 1 // nothing was produced: bad usage, bad config, I/O error, interrupted
	ExitIncomplete = 2 // a CBOM was written, but a plugin failed or was cut short
)

// Env carries everything Main needs from the outside world.
type Env struct {
	Stdout io.Writer // the CBOM goes here unless an output file is configured
	Stderr io.Writer // progress, warnings and the PQC summary

	Registry  *collector.Registry // nil means collector.Default
	Now       func() time.Time    // nil means time.Now
	NewSerial func() string       // nil means a random UUID
	Hostname  func() (string, error)
}

// Main runs the CLI and returns the process exit code.
func Main(ctx context.Context, args []string, env Env) int {
	if env.Registry == nil {
		env.Registry = collector.Default
	}
	if env.Hostname == nil {
		env.Hostname = os.Hostname
	}

	if len(args) == 0 {
		usage(env.Stderr)
		return ExitFatal
	}
	switch args[0] {
	case "run":
		return runCmd(ctx, args[1:], env)
	case "plugins":
		return pluginsCmd(env)
	case "tls":
		return tlsCmd(ctx, args[1:], env)
	case "serve":
		return serveCmd(ctx, args[1:], env)
	case "version", "-version", "--version":
		_, _ = fmt.Fprintln(env.Stdout, "cbom-scan", version.Version)
		return ExitOK
	case "help", "-h", "-help", "--help":
		usage(env.Stdout)
		return ExitOK
	default:
		_, _ = fmt.Fprintf(env.Stderr, "cbom-scan: unknown command %q\n\n", args[0])
		usage(env.Stderr)
		return ExitFatal
	}
}

func usage(w io.Writer) {
	_, _ = fmt.Fprint(w, `cbom-scan: cryptographic inventory (CycloneDX CBOM), TLS posture and post-quantum readiness.

Usage:
  cbom-scan run [--config FILE] [-o FILE] [--root DIR]
  cbom-scan tls scan [flags] HOST[:PORT]...
  cbom-scan serve [--addr HOST:PORT] [--db FILE] [--token TOKEN]
  cbom-scan plugins
  cbom-scan version

run flags:
  --config FILE   YAML configuration (default: built-in defaults)
  -o, --output FILE  write the CBOM here, atomically (default: stdout)
  --root DIR      the host filesystem's location, e.g. /host inside a container

tls scan probes each target's TLS/SSL support: protocol versions, every cipher suite,
key-exchange groups (including post-quantum hybrids) and certificates. Flags go before
targets: --json, --timeout, --concurrency, --max-connections, --min-interval, --no-certs.
Scan only systems you are authorised to test.

serve runs the web UI and API: add endpoints, scan them, watch progress, see history and
post-quantum readiness. It listens on 127.0.0.1:8080 by default and refuses any other
address unless --token (or CBOM_SCAN_TOKEN) is set. Data is kept in --db (SQLite).

Exit codes: 0 success; 1 fatal error; 2 result produced, but incomplete or a target failed.
`)
}

func runCmd(ctx context.Context, args []string, env Env) int {
	fl := flag.NewFlagSet("run", flag.ContinueOnError)
	fl.SetOutput(env.Stderr)
	cfgPath := fl.String("config", "", "")
	var outPath string
	fl.StringVar(&outPath, "output", "", "")
	fl.StringVar(&outPath, "o", "", "")
	root := fl.String("root", "", "")
	if err := fl.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return ExitOK
		}
		return ExitFatal
	}
	if fl.NArg() > 0 {
		return fatalf(env, "unexpected argument %q", fl.Arg(0))
	}

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return fatalf(env, "%v", err)
	}
	if outPath != "" {
		cfg.Output.Path = outPath
	}
	if *root != "" {
		cfg.Host.Root = *root
	}
	if err := cfg.Validate(); err != nil {
		return fatalf(env, "%v", err)
	}

	hostName := cfg.Host.Name
	if hostName == "" {
		if hostName, err = env.Hostname(); err != nil {
			warnf(env, "cannot determine hostname (%v); CBOM will have no subject component", err)
		}
	}

	res, err := scan.Run(ctx, env.Registry, scan.Options{
		Host:     collector.Host{FS: os.DirFS(cfg.Host.Root)},
		Enabled:  cfg.Plugins.Enabled,
		Disabled: cfg.Plugins.Disabled,
		Timeout:  cfg.Plugins.Timeout,
	})
	if err != nil {
		return fatalf(env, "%v", err)
	}
	if ctx.Err() != nil {
		return fatalf(env, "interrupted")
	}
	report(env, res)

	bom, warnings := cbom.Build(res.Assets, cbom.Options{
		Tool:      cbom.Tool{Name: "cbom-scan", Version: version.Version},
		HostName:  hostName,
		Now:       env.Now,
		NewSerial: env.NewSerial,
	})
	for _, w := range warnings {
		warnf(env, "%s", w)
	}

	if cfg.PQC.Enabled {
		rep := pqc.Analyze(bom)
		pqc.Annotate(bom, rep)
		_, _ = fmt.Fprint(env.Stderr, rep.Summary())
	}

	var buf bytes.Buffer
	if err := cbom.Encode(&buf, bom, cfg.Output.Pretty); err != nil {
		return fatalf(env, "encoding CBOM: %v", err)
	}
	if cfg.Output.Path == "" {
		if _, err := env.Stdout.Write(buf.Bytes()); err != nil {
			return fatalf(env, "writing CBOM: %v", err)
		}
	} else if err := writeFileAtomic(cfg.Output.Path, buf.Bytes()); err != nil {
		return fatalf(env, "writing CBOM: %v", err)
	}

	if res.Incomplete() {
		return ExitIncomplete
	}
	return ExitOK
}

func report(env Env, res scan.Result) {
	for _, r := range res.Runs {
		switch r.Status {
		case scan.StatusOK:
			_, _ = fmt.Fprintf(env.Stderr, "plugin %s: ok, %d assets\n", r.Name, r.Assets)
		case scan.StatusSkipped:
			_, _ = fmt.Fprintf(env.Stderr, "plugin %s: skipped (not detected on this host)\n", r.Name)
		default:
			_, _ = fmt.Fprintf(env.Stderr, "plugin %s: %s, %d assets: %v\n", r.Name, r.Status, r.Assets, r.Err)
		}
	}
}

func pluginsCmd(env Env) int {
	tw := tabwriter.NewWriter(env.Stdout, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "NAME\tVERSION\tSOURCE TYPE")
	for _, name := range env.Registry.Names() {
		c, err := env.Registry.New(name, collector.Host{FS: os.DirFS("/")})
		if err != nil {
			return fatalf(env, "%v", err)
		}
		info := c.Metadata()
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\n", info.Name, info.Version, info.SourceType)
	}
	if err := tw.Flush(); err != nil {
		return fatalf(env, "%v", err)
	}
	return ExitOK
}

// writeFileAtomic writes data to path via a temporary file in the same
// directory and a rename, so a reader (or a crash) never sees a half-written CBOM.
func writeFileAtomic(path string, data []byte) (err error) {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".cbom-*.tmp")
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = tmp.Close()
			_ = os.Remove(tmp.Name())
		}
	}()
	if _, err = tmp.Write(data); err != nil {
		return err
	}
	if err = tmp.Chmod(0o644); err != nil {
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func fatalf(env Env, format string, args ...any) int {
	_, _ = fmt.Fprintf(env.Stderr, "cbom-scan: "+format+"\n", args...)
	return ExitFatal
}

func warnf(env Env, format string, args ...any) {
	_, _ = fmt.Fprintf(env.Stderr, "warning: "+format+"\n", args...)
}
