package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"time"

	"github.com/example/cipherhorizon/internal/cbom"
	"github.com/example/cipherhorizon/internal/pqc"
	"github.com/example/cipherhorizon/internal/tlscbom"
	"github.com/example/cipherhorizon/internal/tlsprobe"
	"github.com/example/cipherhorizon/internal/version"
)

const tlsNotice = `notice: "tls scan" connects to each target and makes a few hundred short handshakes.
        Scan only systems you own or are authorised to test.
        This result is not saved anywhere: run "cipherhorizon serve" for history, scheduling and a fleet dashboard.
`

// tlsCmd implements "cipherhorizon tls scan [flags] TARGET...".
func tlsCmd(ctx context.Context, args []string, env Env) int {
	if len(args) == 0 || args[0] != "scan" {
		_, _ = fmt.Fprintln(env.Stderr, "usage: cipherhorizon tls scan [flags] HOST[:PORT]...")
		return ExitFatal
	}

	fl := flag.NewFlagSet("tls scan", flag.ContinueOnError)
	fl.SetOutput(env.Stderr)
	asJSON := fl.Bool("json", false, "print the reports as a JSON array instead of text")
	asCBOM := fl.Bool("cbom", false, "print a CycloneDX CBOM of what was observed instead of text (exactly one target)")
	spec := fl.String("spec", cbom.DefaultSpec, "CycloneDX version of the CBOM: 1.7 or 1.6")
	timeout := fl.Duration("timeout", 8*time.Second, "per-connection timeout")
	concurrency := fl.Int("concurrency", 4, "connections in flight to a target at once")
	maxConns := fl.Int("max-connections", 2000, "hard cap on connections per target")
	interval := fl.Duration("min-interval", 0, "minimum spacing between connection starts (rate limit)")
	noCerts := fl.Bool("no-certs", false, "skip the certificate and negotiation steps")
	httpChecks := fl.Bool("http-checks", false, "after the handshake, send one plain HTTP GET / and read the Strict-Transport-Security header. "+
		"This is the only check that sends anything beyond a TLS handshake: it makes a real HTTP request to the target. Off by default.")
	fl.Usage = func() {
		_, _ = fmt.Fprintln(env.Stderr, "usage: cipherhorizon tls scan [flags] HOST[:PORT]...  (flags must come before targets)")
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
	if *asJSON && *asCBOM {
		return fatalf(env, "--json and --cbom are mutually exclusive")
	}
	if *asCBOM && fl.NArg() > 1 {
		return fatalf(env, "--cbom takes exactly one target; a CBOM has one subject. Run it once per endpoint")
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
			MinInterval: *interval, SkipCertificates: *noCerts, HTTPChecks: *httpChecks,
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
		if *asCBOM {
			if err := writeTLSCBOM(env, rep, t, *spec); err != nil {
				return fatalf(env, "%v", err)
			}
			continue
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

// writeTLSCBOM turns one scan's report into a CycloneDX CBOM (protocols, cipher
// suites, key-exchange groups, certificates: what was observed, not a verdict)
// and writes it to env.Stdout. Algorithm components are PQC-annotated exactly as
// a host inventory's are, since that classification is about the algorithm, not
// about who found it; the readiness level and TLS hygiene score stay out of it,
// the same way a host CBOM carries no verdict beyond the algorithm's own.
func writeTLSCBOM(env Env, rep *tlsprobe.Report, t tlsprobe.Target, spec string) error {
	bom, warnings := cbom.Build(tlscbom.FromTLSReport(rep), cbom.Options{
		Tool:      cbom.Tool{Name: "cipherhorizon", Version: version.Version},
		Endpoint:  fmt.Sprintf("%s:%d", t.Host, t.Port),
		Now:       env.Now,
		NewSerial: env.NewSerial,
	})
	for _, w := range warnings {
		warnf(env, "%s", w)
	}
	pqcRep := pqc.Analyze(bom)
	pqc.Annotate(bom, pqcRep)
	_, _ = fmt.Fprint(env.Stderr, pqcRep.Summary())

	var buf bytes.Buffer
	if err := cbom.EncodeSpec(&buf, bom, spec, true); err != nil {
		return fmt.Errorf("encoding CBOM: %w", err)
	}
	_, err := env.Stdout.Write(buf.Bytes())
	return err
}
