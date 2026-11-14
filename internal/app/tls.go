package app

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/offsetsecurity/cipherhorizon/internal/cbom"
	"github.com/offsetsecurity/cipherhorizon/internal/eval"
	"github.com/offsetsecurity/cipherhorizon/internal/pqc"
	"github.com/offsetsecurity/cipherhorizon/internal/refdata"
	"github.com/offsetsecurity/cipherhorizon/internal/revocation"
	"github.com/offsetsecurity/cipherhorizon/internal/server"
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
	if len(args) > 0 && args[0] == "standards" {
		return standardsCmd(env, "tls")
	}
	if len(args) == 0 || args[0] != "scan" {
		_, _ = fmt.Fprintln(env.Stderr, "usage: cipherhorizon tls scan [flags] HOST[:PORT]...\n       cipherhorizon tls standards")
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
		"level<L3, score<70, standard=bcp195, severity>=high, finding=PROTO.TLS10. A target that cannot be scanned also fails")
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
	crl := fl.Bool("revocation", false, "fetch the CRL each certificate on the served path names and report whether it is revoked. "+
		"Off by default: it contacts the CA's CRL server (plain HTTP), a host other than the target. Private and loopback addresses are refused "+
		"unless --revocation-private is set")
	crlPrivate := fl.Bool("revocation-private", false, "with --revocation, also fetch CRLs from private (RFC 1918, unique-local) and loopback addresses: an internal CA's CRL server")
	public := fl.Bool("public", false, "connect only to addresses on the public internet. Every target's address is checked before the first connection, "+
		"and again on each connection. A loopback, private, carrier-NAT, link-local, unique-local, documentation, reserved or cloud-metadata address "+
		"ends the command: exit 1, nothing on stdout, and one line on stderr that starts \"cipherhorizon: target address is not allowed\"")
	connectTo := fl.String("connect-to", "", "scan this `ADDRESS` instead of resolving the target's name: one IPv4 or IPv6 address, no port and no brackets. "+
		"The target's host name is still the server name in every handshake and the name the certificate is judged against; no name lookup is made. "+
		"Exactly one target, which must be a host name; its port is the port scanned")
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
	if *public && *crlPrivate {
		return fatalf(env, "--revocation-private fetches from private addresses and cannot be combined with --public")
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

	var crlFetcher tlsprobe.CRLFetcher
	var crlIssuers []*x509.Certificate
	if *crl {
		crlFetcher = revocation.New(revocation.Policy{AllowPrivate: *crlPrivate, AllowLoopback: *crlPrivate})
		crlIssuers = refdata.RootCertificates()
	}

	dial, lookup := env.Dial, env.LookupIP
	var pinned net.IP // the --connect-to address
	connectToSet := false
	fl.Visit(func(f *flag.Flag) { connectToSet = connectToSet || f.Name == "connect-to" })
	if connectToSet { // also when it was given empty: that is an error, not "resolve the name"
		pinned, err = connectToAddress(*connectTo, targets)
		if err != nil {
			return fatalf(env, "%v", err)
		}
		// The scan asks for the name's addresses once; this is the whole answer, so no DNS
		// query is made.
		lookup = func(context.Context, string) ([]net.IP, error) { return []net.IP{pinned}, nil }
	}

	// With --public no connection is made, and nothing is printed, until every target's address
	// is known to be public. A refusal in the dial hook alone would not end the command: the
	// scan would report the target as not reached.
	if *public {
		guard := server.Guard{Public: true}
		if pinned != nil {
			if err := guard.CheckIP(pinned); err != nil {
				return fatalf(env, "%v", err)
			}
		} else {
			lookup, err = publicTargets(ctx, guard, targets, lookup, *timeout)
			if err != nil {
				return fatalf(env, "%v", err)
			}
		}
		dial = guardDial(guard, dial)
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
			CRL: crlFetcher, CRLIssuers: crlIssuers, Dial: dial, LookupIP: lookup,
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
			writeAlgorithms(env.Stdout, ev)
			writeStandardsDetail(env.Stdout, ev)
			writeClientsDetail(env.Stdout, ev)
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

type (
	dialFunc   = func(ctx context.Context, network, addr string) (net.Conn, error)
	lookupFunc = func(ctx context.Context, host string) ([]net.IP, error)
)

// connectToAddress reads --connect-to: one IP literal, for exactly one target that is a host name.
func connectToAddress(arg string, targets []tlsprobe.Target) (net.IP, error) {
	addr, err := netip.ParseAddr(arg)
	if err != nil || addr.Zone() != "" {
		return nil, fmt.Errorf("--connect-to %q: not an IPv4 or IPv6 address (give the address alone: no port, no brackets, no zone)", arg)
	}
	if len(targets) != 1 {
		return nil, errors.New("--connect-to takes exactly one target: the address is where that one name is scanned")
	}
	if net.ParseIP(targets[0].Host) != nil {
		return nil, fmt.Errorf("--connect-to needs a host name as the target, and %s is an address; scan the address itself, without the flag", targets[0].Host)
	}
	return net.IP(addr.AsSlice()), nil
}

// publicTargets is the --public check made before any connection: every target's address, or
// every address its name resolves to, must be allowed by the guard. The first refusal is
// returned; it wraps server.ErrBlocked, whose text starts the stderr line callers match on.
//
// The lookup it returns answers from what was checked, so the scan connects to an address that
// was judged and the name is resolved once. A name that does not resolve is not a refusal: the
// scan reports it as it does without --public.
func publicTargets(ctx context.Context, g server.Guard, targets []tlsprobe.Target, lookup lookupFunc, timeout time.Duration) (lookupFunc, error) {
	if lookup == nil {
		lookup = func(ctx context.Context, host string) ([]net.IP, error) {
			return net.DefaultResolver.LookupIP(ctx, "ip", host)
		}
	}
	type answer struct {
		ips []net.IP
		err error
	}
	checked := map[string]answer{}
	for _, t := range targets {
		if ip := net.ParseIP(t.Host); ip != nil {
			if err := g.CheckIP(ip); err != nil {
				return nil, err
			}
			continue
		}
		if _, done := checked[t.Host]; done {
			continue
		}
		lctx, cancel := context.WithTimeout(ctx, timeout)
		ips, err := lookup(lctx, t.Host)
		cancel()
		for _, ip := range ips {
			if err := g.CheckIP(ip); err != nil {
				return nil, fmt.Errorf("%w (%s resolves to it)", err, t.Host)
			}
		}
		checked[t.Host] = answer{ips, err}
	}
	return func(_ context.Context, host string) ([]net.IP, error) {
		a, ok := checked[host]
		if !ok {
			return nil, fmt.Errorf("%w: %s was not checked", server.ErrBlocked, host)
		}
		return a.ips, a.err
	}, nil
}

// guardDial is the second line of --public: every connection of the scan is checked again.
// The default dialer checks the real remote address as it connects; an injected one is checked
// by the address it is asked for, which the scan always gives as an IP literal.
func guardDial(g server.Guard, inner dialFunc) dialFunc {
	if inner == nil {
		return g.Dial
	}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", server.ErrBlocked, err)
		}
		if err := g.CheckIP(net.ParseIP(host)); err != nil {
			return nil, err
		}
		return inner(ctx, network, addr)
	}
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

// writeAlgorithms prints, after --details, every algorithm the endpoint uses by class, and each
// suite's parts (PRD-011 REQ-CLS-8): what the report's Algorithms in use card and the strength
// cells show.
func writeAlgorithms(w io.Writer, ev eval.Evaluation) {
	if len(ev.Algorithms) == 0 {
		return
	}
	_, _ = fmt.Fprintln(w, "\nAlgorithms in use, by class")
	class := ""
	for _, a := range ev.Algorithms {
		if a.Class != class {
			class = a.Class
			_, _ = fmt.Fprintf(w, "  %s\n", strings.ToUpper(class[:1])+class[1:])
		}
		st := a.Strength.Words()
		if a.Weakest {
			st += " (weakest)"
		}
		pq := a.PQC
		if pq == "" {
			pq = "-"
		}
		_, _ = fmt.Fprintf(w, "    %-34s %-17s %-24s %-19s %s\n", a.Name, a.Role, st, pq, strings.Join(a.UsedBy, ", "))
	}
	_, _ = fmt.Fprintln(w, "\nSuite parts (a suite is as strong as its weakest part)")
	for _, s := range ev.SuiteStrength {
		parts := make([]string, 0, len(s.Parts))
		for _, p := range s.Parts {
			part := fmt.Sprintf("%s %s %s", p.Role, p.Name, p.Strength.Words())
			if p.Name == s.Weakest {
				part += " (weakest)"
			}
			parts = append(parts, part)
		}
		_, _ = fmt.Fprintf(w, "  %s %s: %s\n", s.Version, s.Name, strings.Join(parts, "; "))
	}
}
