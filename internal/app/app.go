// Package app implements the command-line interface. cmd/cipherhorizon/main.go is a
// thin shim over Main so that everything here is testable in-process, with the
// clock, serial number, hostname and output streams injected.
package app

import (
	"context"
	"fmt"
	"io"
	"os"
	"runtime"
	"time"

	"github.com/offsetsecurity/cipherhorizon/internal/hostcmd"
	"github.com/offsetsecurity/cipherhorizon/internal/hostinfo"
	"github.com/offsetsecurity/cipherhorizon/internal/sense"
	"github.com/offsetsecurity/cipherhorizon/internal/version"
)

// Exit codes.
const (
	ExitOK         = hostcmd.ExitOK         // success
	ExitFatal      = hostcmd.ExitFatal      // nothing was produced: bad usage, bad config, I/O error, interrupted
	ExitIncomplete = hostcmd.ExitIncomplete // a CBOM was written, but a sensor failed or a budget was hit
)

// Env carries everything Main needs from the outside world.
type Env struct {
	Stdout io.Writer // the CBOM goes here unless an output file is configured
	Stderr io.Writer // progress, warnings and the PQC summary

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

// Main runs the CLI and returns the process exit code.
func Main(ctx context.Context, args []string, env Env) int {
	if env.Registry == nil {
		env.Registry = sense.Default
	}
	if env.OS == "" {
		env.OS = runtime.GOOS
	}
	if env.Tier == nil {
		env.Tier = hostinfo.CurrentTier
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
		return hostcmd.Run(ctx, args[1:], hostEnv(env))
	case "plugins":
		return hostcmd.Plugins(hostEnv(env))
	case "tls":
		return tlsCmd(ctx, args[1:], env)
	case "serve":
		return serveCmd(ctx, args[1:], env)
	case "import":
		return importCmd(ctx, args[1:], env)
	case "db":
		return dbCmd(args[1:], env)
	case "scripts":
		return scriptsCmd(args[1:], env)
	case "user", "users":
		return userCmd(args[1:], env)
	case "healthcheck":
		return healthcheckCmd(ctx, args[1:], env)
	case "version", "-version", "--version":
		_, _ = fmt.Fprintln(env.Stdout, "cipherhorizon", version.Get())
		_, _ = fmt.Fprintln(env.Stdout, OneLiner)
		return ExitOK
	case "help", "-h", "-help", "--help":
		usage(env.Stdout)
		return ExitOK
	default:
		_, _ = fmt.Fprintf(env.Stderr, "cipherhorizon: unknown command %q\n\n", args[0])
		usage(env.Stderr)
		return ExitFatal
	}
}

// hostEnv hands the host-inventory commands what they need from the full program's Env.
func hostEnv(e Env) hostcmd.Env {
	return hostcmd.Env{
		Stdout: e.Stdout, Stderr: e.Stderr, Prog: "cipherhorizon",
		Registry: e.Registry, Now: e.Now, NewSerial: e.NewSerial, Hostname: e.Hostname, OS: e.OS, Tier: e.Tier,
	}
}

// OneLiner says what the product is, the same words everywhere it introduces itself: --help,
// version, the container image's description, the README (PRD-007 REQ-ST-4).
const OneLiner = "Post-quantum readiness for every TLS endpoint you run: a deep TLS scan, a readiness level from L0 to L4, and a CycloneDX CBOM, self-hosted."

func usage(w io.Writer) {
	_, _ = fmt.Fprint(w, "CipherHorizon by Offset Security. "+OneLiner+`

Usage:
  cipherhorizon run [--config FILE] [-o FILE] [--root DIR] [--redact-host]
  cipherhorizon tls scan [flags] HOST[:PORT]...
  cipherhorizon serve [--addr HOST:PORT] [--db FILE] [--tls-cert F --tls-key F] [--token TOKEN] [--no-login]
  cipherhorizon import [--server URL] (--system ID | --new-system NAME) FILE|-
  cipherhorizon db rebuild-graph|stats|backup [--db FILE] [BACKUP-FILE]
  cipherhorizon scripts list|export DIR   the inventory scripts' hashes, from this binary
  cipherhorizon user list|add|reset-password|unlock [--db FILE] [USERNAME]
  cipherhorizon plugins       list the built-in sensors
  cipherhorizon healthcheck [--addr HOST:PORT] [--tls]   for a container orchestrator; see below
  cipherhorizon version

run flags:
  --config FILE   YAML configuration (default: built-in defaults)
  -o, --output FILE  write the CBOM here, atomically (default: stdout)
  --root DIR      the host filesystem's location, e.g. /host inside a container
  --redact-host   record a stable label derived from the machine id instead of the host name

run inventories the cryptographic software on this machine and reports what is present
and what it can do, never what it is used for. Running without elevated privileges is
allowed and may leave results incomplete; run as Administrator (Windows) or root (Linux)
for a fuller result. It never reads keys or secrets.

tls scan probes each target's TLS/SSL support (protocol versions, every cipher suite,
key-exchange groups including post-quantum hybrids, certificates) and prints the verdict
first: post-quantum readiness level, TLS hygiene score, what was checked, and what to do,
worst first. Flags go before targets:
  --details       also print the protocols, suites, groups and certificates behind the verdict
  --json          one {target, report, evaluation} per target, as a JSON array
  --cbom          what was observed as a CycloneDX CBOM, for exactly one target
  --fail-on COND  exit 3 when a target meets COND (repeatable, or comma separated):
                  level<L3, score<70, severity>=high, finding=PROTO.TLS10; a target that
                  cannot be scanned also fails. For CI: see docs/CI.md
  --timeout, --concurrency, --max-connections, --min-interval, --no-certs, --http-checks
Scan only systems you are authorised to test.

serve runs the web UI and API: add endpoints, scan them, watch progress, see history and
post-quantum readiness. Sign-in is off until someone turns it on in Settings, which creates
the administrator; --sign-in on requires it from the start (the log then prints a one-time
setup code), --sign-in off never. A database with accounts keeps sign-in on. It listens on 127.0.0.1:8080 by default. Any other address
needs HTTPS (--tls-cert and --tls-key) or --plain-http when a TLS-terminating proxy is in
front (name that proxy with --trusted-proxy so rate limits see real client addresses);
Beyond loopback without sign-in the server refuses to start unless --open-network says it
is meant to be open. --token (or CIPHERHORIZON_TOKEN) adds an automation
token for scripts, which act as an analyst. Data is kept in --db (SQLite).

healthcheck asks a running "serve" for its health, without a token, and exits 0 or 1; it is
what the container image's HEALTHCHECK runs, since the distroless base has no shell or curl.

Exit codes: 0 success; 1 fatal error; 2 result produced, but incomplete or a target failed;
3 a --fail-on condition was met.
`)
}

func fatalf(env Env, format string, args ...any) int {
	_, _ = fmt.Fprintf(env.Stderr, "cipherhorizon: "+format+"\n", args...)
	return ExitFatal
}

func warnf(env Env, format string, args ...any) {
	_, _ = fmt.Fprintf(env.Stderr, "warning: "+format+"\n", args...)
}
