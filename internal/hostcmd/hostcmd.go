// Package hostcmd implements the host-inventory command line: `run`, `plugins` and
// `version`. It is shared by two programs:
//
//   - cmd/cipherhorizon-collector, the small program to deploy on endpoints. It links
//     only this package's dependencies: no web server, no database, no TLS scanner;
//   - cmd/cipherhorizon, the full product, whose `run` command is this same code.
//
// Keeping it in its own package is what lets the collector stay small and auditable
// (internal/archtest fails the build if the collector links the server, the store or
// the scanner).
package hostcmd

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/example/cipherhorizon/internal/cbom"
	"github.com/example/cipherhorizon/internal/config"
	"github.com/example/cipherhorizon/internal/discover"
	"github.com/example/cipherhorizon/internal/hostinfo"
	"github.com/example/cipherhorizon/internal/pqc"
	"github.com/example/cipherhorizon/internal/sense"
	_ "github.com/example/cipherhorizon/internal/sense/all" // registers the built-in sensors
	"github.com/example/cipherhorizon/internal/version"
)

// Exit codes.
const (
	ExitOK         = 0 // success
	ExitFatal      = 1 // nothing was produced: bad usage, bad config, I/O error, interrupted
	ExitIncomplete = 2 // a CBOM was written, but a sensor failed or a budget was hit
)

// Env carries everything the commands need from the outside world.
type Env struct {
	Stdout io.Writer // the CBOM goes here unless an output file is configured
	Stderr io.Writer // progress, warnings and the PQC summary

	// Prog is the program name used in messages ("cipherhorizon" by default).
	Prog string

	Registry  *sense.Registry  // nil means sense.Default
	Now       func() time.Time // nil means time.Now
	NewSerial func() string    // nil means a random UUID
	Hostname  func() (string, error)

	// OS is the host's operating system family, "linux" or "windows"; empty means
	// this process's own. Tier reports the privilege of the run ("user" or
	// "admin"); nil means the process's real privilege. Both exist so tests are
	// deterministic on any machine.
	OS   string
	Tier func() string
}

func (e Env) withDefaults() Env {
	if e.Prog == "" {
		e.Prog = "cipherhorizon"
	}
	if e.Registry == nil {
		e.Registry = sense.Default
	}
	if e.OS == "" {
		e.OS = runtime.GOOS
	}
	if e.Tier == nil {
		e.Tier = hostinfo.CurrentTier
	}
	if e.Hostname == nil {
		e.Hostname = os.Hostname
	}
	return e
}

// Main is the collector program's whole command line: run, plugins, version, help.
func Main(ctx context.Context, args []string, env Env) int {
	env = env.withDefaults()
	if env.Prog == "cipherhorizon" {
		env.Prog = "cipherhorizon-collector"
	}
	if len(args) == 0 {
		Usage(env.Stderr, env.Prog)
		return ExitFatal
	}
	switch args[0] {
	case "run":
		return Run(ctx, args[1:], env)
	case "plugins":
		return Plugins(env)
	case "version", "-version", "--version":
		_, _ = fmt.Fprintln(env.Stdout, env.Prog, version.Get())
		return ExitOK
	case "help", "-h", "-help", "--help":
		Usage(env.Stdout, env.Prog)
		return ExitOK
	default:
		_, _ = fmt.Fprintf(env.Stderr, "%s: unknown command %q\n\n", env.Prog, args[0])
		Usage(env.Stderr, env.Prog)
		return ExitFatal
	}
}

// Usage prints the help for the host commands.
func Usage(w io.Writer, prog string) {
	_, _ = fmt.Fprintf(w, `%[1]s: inventory the cryptographic software on this machine as a CycloneDX CBOM.

Usage:
  %[1]s run [--config FILE] [-o FILE] [--root DIR] [--redact-host]
  %[1]s plugins       list the built-in sensors
  %[1]s version

run flags:
  --config FILE   YAML configuration (default: built-in defaults)
  -o, --output FILE  write the CBOM here, atomically (default: stdout)
  --root DIR      the host filesystem's location, e.g. /host inside a container
  --redact-host   record a stable label derived from the machine id instead of the host name

run reports what is present and what it can do, never what it is used for. Running without
elevated privileges is allowed and may leave results incomplete; run as Administrator (Windows)
or root (Linux) for a fuller result. It never reads keys or secrets, runs no subprocess and
makes no network connection.

Exit codes: 0 success; 1 fatal error; 2 result produced, but incomplete.
`, prog)
}

// Run implements `run`: discover the host's cryptography and write a CBOM.
func Run(ctx context.Context, args []string, env Env) int {
	env = env.withDefaults()
	fl := flag.NewFlagSet("run", flag.ContinueOnError)
	fl.SetOutput(env.Stderr)
	cfgPath := fl.String("config", "", "")
	var outPath string
	fl.StringVar(&outPath, "output", "", "")
	fl.StringVar(&outPath, "o", "", "")
	root := fl.String("root", "", "")
	redact := fl.Bool("redact-host", false, "")
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
	if *redact {
		cfg.Host.Redact = true
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

	res, err := discover.Run(ctx, env.Registry, discover.Options{
		FS:         os.DirFS(cfg.Host.Root),
		OS:         env.OS,
		Tier:       env.Tier(),
		HostName:   hostName,
		RedactHost: cfg.Host.Redact,
		Enabled:    cfg.Plugins.Enabled,
		Disabled:   cfg.Plugins.Disabled,
		Timeout:    cfg.Plugins.Timeout,
	})
	if err != nil {
		return fatalf(env, "%v", err)
	}
	if ctx.Err() != nil {
		return fatalf(env, "interrupted")
	}
	report(env, res.Run)
	if res.PrivilegeNote != "" {
		warnf(env, "%s", res.PrivilegeNote)
	}

	assets, props, err := cbom.FromHostGraph(res.Graph, cbom.HostOptions{PrivilegeNote: res.PrivilegeNote})
	if err != nil {
		return fatalf(env, "%v", err)
	}
	bom, warnings := cbom.Build(assets, cbom.Options{
		Tool:               cbom.Tool{Name: "cipherhorizon", Version: version.Version},
		HostName:           res.Graph.Host.Name,
		MetadataProperties: props,
		Now:                env.Now,
		NewSerial:          env.NewSerial,
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
	if cfg.Output.Path != "" {
		// Say what happens next: people otherwise stop at a file and wonder what it is for.
		_, _ = fmt.Fprintf(env.Stderr, "\nwrote %s\nnext: open the Hosts page of your CipherHorizon server and upload it there.\n", cfg.Output.Path)
	}

	if res.Run.Incomplete() {
		return ExitIncomplete
	}
	return ExitOK
}

func report(env Env, res sense.Result) {
	for _, r := range res.Runs {
		switch r.Status {
		case sense.StatusOK:
			_, _ = fmt.Fprintf(env.Stderr, "plugin %s: ok, %d observations\n", r.Name, r.Observations)
		case sense.StatusSkipped:
			_, _ = fmt.Fprintf(env.Stderr, "plugin %s: skipped (not detected on this host)\n", r.Name)
		default:
			_, _ = fmt.Fprintf(env.Stderr, "plugin %s: %s, %d observations: %v\n", r.Name, r.Status, r.Observations, r.Err)
		}
	}
}

// Plugins implements `plugins`: list the built-in sensors and the methods they use.
func Plugins(env Env) int {
	env = env.withDefaults()
	tw := tabwriter.NewWriter(env.Stdout, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "NAME\tVERSION\tMETHODS")
	for _, name := range env.Registry.Names() {
		s, err := env.Registry.New(name, sense.Env{FS: os.DirFS(config.DefaultRoot()), OS: env.OS, Tier: env.Tier()})
		if err != nil {
			return fatalf(env, "%v", err)
		}
		info := s.Info()
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\n", info.Name, info.Version, strings.Join(info.Methods, ", "))
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
	// Owner-only: a host inventory should not be readable by every local user.
	if err = tmp.Chmod(0o600); err != nil {
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func fatalf(env Env, format string, args ...any) int {
	_, _ = fmt.Fprintf(env.Stderr, env.Prog+": "+format+"\n", args...)
	return ExitFatal
}

func warnf(env Env, format string, args ...any) {
	_, _ = fmt.Fprintf(env.Stderr, "warning: "+format+"\n", args...)
}
