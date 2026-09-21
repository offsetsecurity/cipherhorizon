package app

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"time"

	"github.com/example/cbom-scan/internal/tlsprobe"
)

const tlsNotice = `notice: "tls scan" connects to each target and makes a few hundred short handshakes.
        Scan only systems you own or are authorised to test.
`

// tlsCmd implements "cbom-scan tls scan [flags] TARGET...".
func tlsCmd(ctx context.Context, args []string, env Env) int {
	if len(args) == 0 || args[0] != "scan" {
		_, _ = fmt.Fprintln(env.Stderr, "usage: cbom-scan tls scan [flags] HOST[:PORT]...")
		return ExitFatal
	}

	fl := flag.NewFlagSet("tls scan", flag.ContinueOnError)
	fl.SetOutput(env.Stderr)
	asJSON := fl.Bool("json", false, "print the reports as a JSON array instead of text")
	timeout := fl.Duration("timeout", 8*time.Second, "per-connection timeout")
	concurrency := fl.Int("concurrency", 4, "connections in flight to a target at once")
	maxConns := fl.Int("max-connections", 2000, "hard cap on connections per target")
	interval := fl.Duration("min-interval", 0, "minimum spacing between connection starts (rate limit)")
	noCerts := fl.Bool("no-certs", false, "skip the certificate and negotiation steps")
	fl.Usage = func() {
		_, _ = fmt.Fprintln(env.Stderr, "usage: cbom-scan tls scan [flags] HOST[:PORT]...  (flags must come before targets)")
		fl.PrintDefaults()
	}
	if err := fl.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return ExitOK
		}
		return ExitFatal
	}
	if fl.NArg() == 0 {
		fl.Usage()
		return ExitFatal
	}

	targets := make([]tlsprobe.Target, 0, fl.NArg())
	for _, a := range fl.Args() {
		t, err := tlsprobe.ParseTarget(a)
		if err != nil {
			return fatalf(env, "%v", err)
		}
		targets = append(targets, t)
	}

	_, _ = fmt.Fprint(env.Stderr, tlsNotice)

	code := ExitOK
	var reports []*tlsprobe.Report
	for i, t := range targets {
		if ctx.Err() != nil {
			return fatalf(env, "interrupted")
		}
		_, _ = fmt.Fprintf(env.Stderr, "scanning %s:%d\n", t.Host, t.Port)
		rep, err := tlsprobe.Scan(ctx, t, tlsprobe.Options{
			Timeout: *timeout, Concurrency: *concurrency, MaxConnections: *maxConns,
			MinInterval: *interval, SkipCertificates: *noCerts,
			Progress: func(msg string) { _, _ = fmt.Fprintf(env.Stderr, "  %s\n", msg) },
			Now:      env.Now,
		})
		if err != nil {
			warnf(env, "%s:%d: %v", t.Host, t.Port, err)
			code = ExitIncomplete
		}
		if rep == nil {
			continue
		}
		if rep.Incomplete {
			code = ExitIncomplete
		}
		if *asJSON {
			reports = append(reports, rep)
			continue
		}
		if i > 0 {
			_, _ = fmt.Fprintln(env.Stdout)
		}
		if err := rep.WriteText(env.Stdout); err != nil {
			return fatalf(env, "writing report: %v", err)
		}
	}

	if *asJSON {
		enc := json.NewEncoder(env.Stdout)
		enc.SetIndent("", "  ")
		enc.SetEscapeHTML(false)
		if err := enc.Encode(reports); err != nil {
			return fatalf(env, "writing report: %v", err)
		}
	}
	if ctx.Err() != nil {
		return fatalf(env, "interrupted")
	}
	return code
}
