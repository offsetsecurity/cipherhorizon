package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"time"

	"github.com/offsetsecurity/cipherhorizon/internal/cbom"
	"github.com/offsetsecurity/cipherhorizon/internal/eval"
	"github.com/offsetsecurity/cipherhorizon/internal/pqc"
	"github.com/offsetsecurity/cipherhorizon/internal/tlscbom"
	"github.com/offsetsecurity/cipherhorizon/internal/tlsprobe"
	"github.com/offsetsecurity/cipherhorizon/internal/version"
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
	asJSON := fl.Bool("json", false, "print a JSON array with one {target, report, evaluation} per target instead of text")
	starttls := fl.String("starttls", "auto", "negotiate STARTTLS before TLS: auto (by well-known port: 25, 587, 143, 110, 21, 5222, 389, 5432), "+
		"none, smtp, imap, pop3, ftp, xmpp, ldap or postgres. A target may also name it as a scheme: smtp://mail.example.com")
	details := fl.Bool("details", false, "after the verdict, print the raw probe results: protocols, every cipher suite, groups and certificates")
	var failOn stringList
	fl.Var(&failOn, "fail-on", "exit 3 when a target meets this condition (repeatable, or comma separated): "+
		"level<L3, score<70, severity>=high, finding=PROTO.TLS10. A target that cannot be scanned also fails")
	asCBOM := fl.Bool("cbom", false, "print a CycloneDX CBOM of what was observed instead of text (exactly one target)")
	spec := fl.String("spec", cbom.DefaultSpec, "CycloneDX version of the CBOM: 1.7 or 1.6")
	timeout := fl.Duration("timeout", 8*time.Second, "per-connection timeout")
	concurrency := fl.Int("concurrency", 4, "connections in flight to a target at once")
	maxConns := fl.Int("max-connections", 2000, "hard cap on connections per target")
	interval := fl.Duration("min-interval", 0, "minimum spacing between connection starts (rate limit)")
	noCerts := fl.Bool("no-certs", false, "skip the certificate and negotiation steps")
	httpChecks := fl.Bool("http-checks", true, "after the handshake, send one plain HTTP GET / and read the Strict-Transport-Security header. "+
		"This is the only check that sends anything beyond a TLS handshake: one real HTTP request to the target, whose answer is read for headers only. "+
		"On by default; --http-checks=false turns it off")
	osTrust := fl.Bool("os-trust", false, "also check each chain against this machine's trust store. Off by default: on some systems the OS verifier "+
		"fetches missing intermediates from the network, contacting hosts other than the target")
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
	policy, err := parsePolicy(failOn)
	if err == nil {
		err = policyFor(policy, "")
	}
	if err != nil {
		return fatalf(env, "%v", err)
	}
	if *asCBOM && len(policy) > 0 {
		return fatalf(env, "--fail-on judges the evaluation, which a CBOM does not carry; use it with text or --json output")
	}

	targets := make([]tlsprobe.Target, 0, fl.NArg())
	for _, a := range fl.Args() {
		t, err := tlsprobe.ParseTargetStartTLS(a, *starttls)
		if err != nil {
			return fatalf(env, "%v", err)
		}
		targets = append(targets, t)
	}

	_, _ = fmt.Fprint(env.Stderr, tlsNotice)

	code := ExitOK
	failed := false
	type jsonResult struct {
		Target     string           `json:"target"`
		Report     *tlsprobe.Report `json:"report"`
		Evaluation *eval.Evaluation `json:"evaluation"`
	}
	results := []jsonResult{}
	for i, t := range targets {
		name := fmt.Sprintf("%s:%d", t.Host, t.Port)
		if ctx.Err() != nil {
			return fatalf(env, "interrupted")
		}
		_, _ = fmt.Fprintf(env.Stderr, "scanning %s\n", targetName(t))
		rep, err := tlsprobe.Scan(ctx, t, tlsprobe.Options{
			Timeout: *timeout, Concurrency: *concurrency, MaxConnections: *maxConns,
			MinInterval: *interval, SkipCertificates: *noCerts, HTTPChecks: *httpChecks, OSTrust: *osTrust,
			Progress: func(msg string) { _, _ = fmt.Fprintf(env.Stderr, "  %s\n", msg) },
			Now:      env.Now,
		})
		if err != nil {
			warnf(env, "%s:%d: %v", t.Host, t.Port, err)
			code = ExitIncomplete
		}
		// A target that answered nothing has no verdict to judge: with a policy, it fails as such.
		unscanned := rep == nil || (err != nil && !anySupported(rep))
		if unscanned && len(policy) > 0 {
			failed = true
			_, _ = fmt.Fprintf(env.Stderr, "policy: %s fails: it could not be scanned\n", name)
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
		now := time.Now
		if env.Now != nil {
			now = env.Now
		}
		ev := eval.Evaluate(rep, now())
		for _, why := range breaches(policy, ev) {
			if unscanned {
				break
			}
			failed = true
			_, _ = fmt.Fprintf(env.Stderr, "policy: %s fails: %s\n", name, why)
		}
		if *asJSON {
			results = append(results, jsonResult{Target: name, Report: rep, Evaluation: &ev})
			continue
		}
		if i > 0 {
			_, _ = fmt.Fprintln(env.Stdout)
		}
		if unscanned {
			// No verdict to give: say so, rather than an empty list that reads as "nothing to fix".
			_, _ = fmt.Fprintf(env.Stdout, "%s\n\n  Could not be scanned: %v\n", targetName(t), err)
			continue
		}
		if err := writeVerdict(env.Stdout, targetName(t), ev); err != nil {
			return fatalf(env, "writing report: %v", err)
		}
		if *details {
			_, _ = fmt.Fprintln(env.Stdout)
			if err := rep.WriteTextWith(env.Stdout, strengthAnnotations(ev)); err != nil {
				return fatalf(env, "writing report: %v", err)
			}
		}
	}
	if !*asJSON && !*asCBOM && !*details {
		_, _ = fmt.Fprintln(env.Stderr, "(--details prints the protocols, cipher suites, groups and certificates behind this verdict)")
	}

	if *asJSON {
		enc := json.NewEncoder(env.Stdout)
		enc.SetIndent("", "  ")
		enc.SetEscapeHTML(false)
		if err := enc.Encode(results); err != nil {
			return fatalf(env, "writing report: %v", err)
		}
	}
	if ctx.Err() != nil {
		return fatalf(env, "interrupted")
	}
	if failed {
		return ExitPolicy
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
		Tool:     cbom.Tool{Name: "cipherhorizon", Version: version.Version},
		Endpoint: fmt.Sprintf("%s:%d", t.Host, t.Port),
		// What the scan covered, so an absent component is not read as an absent capability.
		MetadataProperties: tlscbom.Coverage(rep),
		Now:                env.Now,
		NewSerial:          env.NewSerial,
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

// anySupported reports whether the target accepted any protocol version at all.
func anySupported(rep *tlsprobe.Report) bool {
	for _, p := range rep.Protocols {
		if p.Supported {
			return true
		}
	}
	return false
}

// strengthAnnotations print, beside each suite and group of --details, the classical strength the
// evaluation gives it (PRD-010 REQ-STR-5): "strong 128 (AES-128-GCM)", "weak 112 (3DES)".
func strengthAnnotations(ev eval.Evaluation) tlsprobe.Annotations {
	return tlsprobe.Annotations{
		Suite: func(s tlsprobe.SuiteResult) string {
			for _, r := range ev.SuiteStrength {
				if r.Version == s.Version && r.ID == s.ID {
					if r.Bits > 0 {
						return fmt.Sprintf("%s %d (%s)", r.Word, r.Bits, r.Weakest)
					}
					return r.Word + " (" + r.Weakest + ")"
				}
			}
			return ""
		},
		Group: func(g tlsprobe.GroupResult) string {
			for _, k := range ev.KeyStrength {
				if k.Kind == "group" && k.Version == g.Version && k.Name == g.Name {
					return k.Strength.Words()
				}
			}
			return ""
		},
	}
}
