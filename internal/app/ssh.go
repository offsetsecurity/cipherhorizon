package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/offsetsecurity/cipherhorizon/internal/cbom"
	"github.com/offsetsecurity/cipherhorizon/internal/eval"
	"github.com/offsetsecurity/cipherhorizon/internal/pqc"
	"github.com/offsetsecurity/cipherhorizon/internal/sshcbom"
	"github.com/offsetsecurity/cipherhorizon/internal/sshprobe"
	"github.com/offsetsecurity/cipherhorizon/internal/sshprobe/registry"
	"github.com/offsetsecurity/cipherhorizon/internal/version"
)

const sshNotice = `notice: "ssh scan" connects to each target a handful of times: it reads the server's identification
        and algorithm lists and runs one key exchange per host key type. It never logs in.
        Scan only systems you own or are authorised to test.
`

// sshCmd implements "cipherhorizon ssh scan [flags] HOST[:PORT]..." (PRD-008 REQ-SHO-4). It shares
// --fail-on, the verdict and the exit codes with "tls scan".
func sshCmd(ctx context.Context, args []string, env Env) int {
	if len(args) > 0 && args[0] == "baselines" {
		return sshBaselinesCmd(env)
	}
	if len(args) == 0 || args[0] != "scan" {
		_, _ = fmt.Fprintln(env.Stderr, "usage: cipherhorizon ssh scan [flags] HOST[:PORT]...\n       cipherhorizon ssh baselines")
		return ExitFatal
	}
	fl := flag.NewFlagSet("ssh scan", flag.ContinueOnError)
	fl.SetOutput(env.Stderr)
	asJSON := fl.Bool("json", false, "print a JSON array with one {target, report, evaluation} per target instead of text")
	details := fl.Bool("details", false, "after the verdict, print the algorithm lists and host keys behind it")
	var failOn stringList
	fl.Var(&failOn, "fail-on", "exit 3 when a target meets this condition (repeatable, or comma separated): "+
		"level<L3, baseline, severity>=high, finding=SSH.KEX-SHA1. A target that cannot be scanned also fails")
	baseline := fl.String("baseline", eval.BaselineDefault, "the SSH baseline to judge against (list them with: cipherhorizon ssh baselines)")
	asCBOM := fl.Bool("cbom", false, "print a CycloneDX CBOM of what was observed instead of text (exactly one target)")
	spec := fl.String("spec", cbom.DefaultSpec, "CycloneDX version of the CBOM: 1.7 or 1.6")
	timeout := fl.Duration("timeout", 8*time.Second, "per-connection timeout")
	maxConns := fl.Int("max-connections", sshprobe.MaxScanConnections, "cap on connections per target (at most 24)")
	fl.Usage = func() {
		_, _ = fmt.Fprintln(env.Stderr, "usage: cipherhorizon ssh scan [flags] HOST[:PORT]...  (port 22 by default; flags must come before targets)")
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
		err = policyFor(policy, eval.ProtocolSSH)
	}
	if err != nil {
		return fatalf(env, "%v", err)
	}
	if _, ok := eval.SSHBaselineByID(*baseline); !ok {
		return fatalf(env, "--baseline %q: no such baseline; list them with: cipherhorizon ssh baselines", *baseline)
	}
	if *asCBOM && len(policy) > 0 {
		return fatalf(env, "--fail-on judges the evaluation, which a CBOM does not carry; use it with text or --json output")
	}
	targets := make([]sshprobe.Target, 0, fl.NArg())
	for _, a := range fl.Args() {
		t, err := sshprobe.ParseTarget(a)
		if err != nil {
			return fatalf(env, "%s: %v", a, err)
		}
		targets = append(targets, t)
	}
	_, _ = fmt.Fprint(env.Stderr, sshNotice)

	now := time.Now
	if env.Now != nil {
		now = env.Now
	}
	type jsonResult struct {
		Target     string           `json:"target"`
		Report     *sshprobe.Report `json:"report"`
		Evaluation *eval.Evaluation `json:"evaluation"`
	}
	results := []jsonResult{}
	code, failed := ExitOK, false
	for i, t := range targets {
		if ctx.Err() != nil {
			return fatalf(env, "interrupted")
		}
		name := fmt.Sprintf("%s:%d", t.Host, t.Port)
		_, _ = fmt.Fprintf(env.Stderr, "scanning %s (SSH)\n", name)
		rep, err := sshprobe.Scan(ctx, t, sshprobe.Options{Timeout: *timeout, MaxConnections: *maxConns, Now: now,
			Progress: func(msg string) { _, _ = fmt.Fprintf(env.Stderr, "  %s\n", msg) }})
		if err != nil {
			warnf(env, "%s: %v", name, err)
			code = ExitIncomplete
		}
		unscanned := rep == nil || rep.Identification == nil
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
			if err := writeSSHCBOM(env, rep, name, *spec); err != nil {
				return fatalf(env, "%v", err)
			}
			continue
		}
		ev := eval.EvaluateSSH(rep, eval.Input{Now: now(), SSHBaseline: *baseline})
		if !unscanned {
			for _, why := range breaches(policy, ev) {
				failed = true
				_, _ = fmt.Fprintf(env.Stderr, "policy: %s fails: %s\n", name, why)
			}
		}
		if *asJSON {
			results = append(results, jsonResult{Target: name, Report: rep, Evaluation: &ev})
			continue
		}
		if i > 0 {
			_, _ = fmt.Fprintln(env.Stdout)
		}
		if unscanned {
			_, _ = fmt.Fprintf(env.Stdout, "%s\n\n  Could not be scanned: %v\n", name, err)
			continue
		}
		label := name
		if id := rep.Identification; id.Software != "" {
			label += "  (" + id.Software + ")"
		}
		if err := writeVerdict(env.Stdout, label, ev); err != nil {
			return fatalf(env, "writing report: %v", err)
		}
		if *details {
			_, _ = fmt.Fprintln(env.Stdout)
			writeSSHDetails(env.Stdout, rep)
		}
	}
	if *asJSON {
		enc := json.NewEncoder(env.Stdout)
		enc.SetIndent("", "  ")
		enc.SetEscapeHTML(false)
		if err := enc.Encode(results); err != nil {
			return fatalf(env, "writing report: %v", err)
		}
	}
	if failed {
		return ExitPolicy
	}
	return code
}

func writeSSHCBOM(env Env, rep *sshprobe.Report, endpoint, spec string) error {
	bom, warnings := cbom.Build(sshcbom.FromSSHReport(rep), cbom.Options{
		Tool: cbom.Tool{Name: "cipherhorizon", Version: version.Version}, Endpoint: endpoint, Now: env.Now, NewSerial: env.NewSerial,
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

// writeSSHDetails prints the lists and keys a verdict rests on.
func writeSSHDetails(w io.Writer, rep *sshprobe.Report) {
	var b strings.Builder
	if id := rep.Identification; id != nil {
		fmt.Fprintf(&b, "  Identification   %s\n", id.Raw)
	}
	if a := rep.Algorithms; a != nil {
		row := func(name string, l []string) { fmt.Fprintf(&b, "  %-16s %s\n", name, strings.Join(l, ", ")) }
		row("Key exchange", a.Kex)
		row("Host key algs", a.HostKey)
		row("Ciphers", a.CipherC2S)
		row("MACs", a.MACC2S)
		row("Compression", a.CompressionC2S)
		fmt.Fprintf(&b, "  %-16s %v\n", "Strict kex", a.StrictKex)
	}
	if n := rep.Negotiated; n != nil {
		fmt.Fprintf(&b, "  %-16s %s / %s / %s (%s", "Current client", n.Kex, n.HostKey, n.Cipher, n.Evidence)
		if n.Verified {
			b.WriteString(", signature verified")
		}
		b.WriteString(")\n")
	}
	for _, k := range rep.HostKeys {
		v := "verified"
		if !k.Verified {
			v = "not verified: " + k.VerifyNote
		}
		fmt.Fprintf(&b, "  Host key         %s %s (%s), %s\n", k.Type, k.Fingerprint, strings.Join(k.ServedBy, ", "), v)
	}
	_, _ = io.WriteString(w, b.String())
}

// sshBaselinesCmd prints every SSH baseline with its entries and sources (PRD-008 REQ-SHB-6).
func sshBaselinesCmd(env Env) int {
	w := env.Stdout
	kinds := []struct{ kind, title string }{{registry.KindKex, "Key exchange"}, {registry.KindHostKey, "Host keys"},
		{registry.KindCipher, "Ciphers"}, {registry.KindMAC, "MACs"}, {registry.KindCompression, "Compression"}}
	for i, b := range eval.SSHBaselines() {
		if i > 0 {
			_, _ = fmt.Fprintln(w)
		}
		def := ""
		if b.ID == eval.BaselineDefault {
			def = "  (default)"
		}
		_, _ = fmt.Fprintf(w, "%s%s\n  %s, version %s\n", b.ID, def, b.Title, b.Version)
		for _, k := range kinds {
			_, _ = fmt.Fprintf(w, "\n  %s allowed, in preference order\n", k.title)
			for _, e := range b.Allowed[k.kind] {
				since := "OpenSSH " + e.Since
				if e.Since == "—" {
					since = "not in OpenSSH"
				}
				_, _ = fmt.Fprintf(w, "    %-42s %-16s %s\n", e.Name, since, e.Cite.Title)
			}
		}
		_, _ = fmt.Fprintln(w, "\n  Requirements")
		for _, r := range b.Requires {
			_, _ = fmt.Fprintf(w, "    %s. %s\n", r.Text, r.Cite.Title)
		}
		if b.MinRSABits > 0 {
			_, _ = fmt.Fprintf(w, "    RSA host keys of at least %d bits.\n", b.MinRSABits)
		}
	}
	return ExitOK
}
