package mcpserver

import (
	"context"
	"errors"
	"net"
	"strconv"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/offsetsecurity/cipherhorizon/internal/eval"
	"github.com/offsetsecurity/cipherhorizon/internal/sshprobe"
	"github.com/offsetsecurity/cipherhorizon/internal/tlsprobe"
)

// Detail levels for a scan result.
const (
	DetailVerdict  = "verdict"
	DetailFindings = "findings"
	DetailFull     = "full"
)

// TLSScanInput is what tls_scan takes.
type TLSScanInput struct {
	Target string `json:"target" jsonschema:"host, host:port or URL to scan. The port is 443 unless given. A scheme chooses STARTTLS: smtp://mail.example.com, imap://, pop3://, ftp://, xmpp://, ldap://, postgres://"`
	// StartTLS overrides the automatic choice.
	StartTLS string `json:"starttls,omitempty" jsonschema:"STARTTLS protocol: auto (default, by well-known port 25, 587, 143, 110, 21, 5222, 389, 5432), none, smtp, imap, pop3, ftp, xmpp, ldap or postgres"`
	Detail   string `json:"detail,omitempty" jsonschema:"how much to return: verdict (default: readiness, hygiene, standards, what to fix first), findings (every finding with remediation and every standard clause not met), full (the complete evaluation JSON, when it fits)"`
	// HTTPChecks is the only thing beyond a handshake the scan sends.
	HTTPChecks *bool `json:"httpChecks,omitempty" jsonschema:"after the handshake, send one plain HTTP GET / and read the Strict-Transport-Security header (default true). The only request beyond a TLS handshake"`
}

// SSHScanInput is what ssh_scan takes.
type SSHScanInput struct {
	Target   string `json:"target" jsonschema:"host or host:port of an SSH server (ssh:// prefix allowed). The port is 22 unless given"`
	Baseline string `json:"baseline,omitempty" jsonschema:"the SSH baseline to judge against; the default is the current OpenSSH baseline. The cipherhorizon://ssh-baselines resource lists them"`
	Detail   string `json:"detail,omitempty" jsonschema:"how much to return: verdict (default), findings (every finding with remediation, the baseline changes as sshd_config lines) or full (the complete evaluation JSON)"`
}

// ScanResult is the structured half of a scan tool's answer. The text half is the verdict the
// CLI prints. Fields a protocol does not have are omitted: SSH has no hygiene score, TLS no
// baseline.
type ScanResult struct {
	Target   string `json:"target"`
	Protocol string `json:"protocol" jsonschema:"tls or ssh"`
	// Scanned is false when the target answered nothing; Error then says why and there is no verdict.
	Scanned    bool   `json:"scanned"`
	Error      string `json:"error,omitempty"`
	Incomplete bool   `json:"incomplete,omitempty" jsonschema:"a stage did not finish; the verdict judges what was seen"`

	Readiness  *ReadinessView `json:"readiness,omitempty"`
	Hygiene    *HygieneView   `json:"hygiene,omitempty" jsonschema:"TLS only: the TLS hygiene score"`
	Baseline   *BaselineView  `json:"baseline,omitempty" jsonschema:"SSH only: conformance to the chosen SSH baseline"`
	Standards  []StandardView `json:"standards,omitempty" jsonschema:"every published standard this program carries for the protocol, with its verdict"`
	Clients    *ClientsView   `json:"clients,omitempty" jsonschema:"TLS only: how many of the simulated clients connect, fail, or get post-quantum key exchange"`
	Counts     map[string]int `json:"counts,omitempty" jsonschema:"findings by severity"`
	ChecksRun  int            `json:"checksRun,omitempty"`
	FixFirst   []FindingView  `json:"fixFirst,omitempty" jsonschema:"what to fix first, worst first (at most three)"`
	Findings   []FindingView  `json:"findings,omitempty" jsonschema:"with detail findings or full: every finding, worst first"`
	Clauses    []ClauseView   `json:"clausesNotMet,omitempty" jsonschema:"with detail findings or full: every standard clause the endpoint does not meet"`
	Changes    []string       `json:"baselineChanges,omitempty" jsonschema:"SSH, with detail findings or full: each change that would meet the baseline, in words"`
	SSHDConfig string         `json:"sshdConfig,omitempty" jsonschema:"SSH, with detail findings or full: the sshd_config lines that would meet the baseline"`
	Full       any            `json:"evaluation,omitempty" jsonschema:"with detail full: the complete evaluation, as the CLI's --json prints it"`
	Note       string         `json:"note,omitempty" jsonschema:"what was left out and how to get it"`

	text string // the verdict text, for a stored verdict rendered later
}

// ReadinessView is the post-quantum readiness in brief.
type ReadinessView struct {
	Level       int    `json:"level" jsonschema:"0 to 4"`
	Label       string `json:"label" jsonschema:"L0 to L4 with its name"`
	Summary     string `json:"summary"`
	HNDLExposed bool   `json:"hndlExposed" jsonschema:"traffic recorded today could be read by a future quantum computer: the negotiated key exchange is classical"`
}

// HygieneView is the TLS hygiene score in brief.
type HygieneView struct {
	Score int    `json:"score" jsonschema:"0 to 100, or -1 when not rated"`
	Band  string `json:"band" jsonschema:"Excellent, Good, Fair, Poor or Failing"`
}

// BaselineView is SSH baseline conformance in brief.
type BaselineView struct {
	ID      string `json:"id"`
	Title   string `json:"title"`
	Judged  bool   `json:"judged"`
	Meets   bool   `json:"meets"`
	Reason  string `json:"reason,omitempty"`
	Changes int    `json:"changes" jsonschema:"how many sshd_config lines would make it meet the baseline"`
}

// StandardView is one standard's verdict.
type StandardView struct {
	ID             string `json:"id"`
	Title          string `json:"title"`
	Publisher      string `json:"publisher"`
	Verdict        string `json:"verdict" jsonschema:"meets, does-not-meet or not-assessed"`
	MustFailures   int    `json:"mustFailures"`
	ShouldFailures int    `json:"shouldFailures"`
}

// ClientsView counts the simulated clients.
type ClientsView struct {
	Connect int `json:"connect"`
	Fail    int `json:"fail"`
	PQ      int `json:"postQuantum" jsonschema:"clients that get a post-quantum key exchange"`
	NoFS    int `json:"noForwardSecrecy"`
}

// FindingView is one finding, for the model.
type FindingView struct {
	ID          string `json:"id"`
	Severity    string `json:"severity"`
	Title       string `json:"title"`
	Detail      string `json:"detail,omitempty"`
	Remediation string `json:"remediation,omitempty"`
}

// ClauseView is one standard clause not met.
type ClauseView struct {
	Standard string `json:"standard"`
	Clause   string `json:"clause"`
	Level    string `json:"level" jsonschema:"must or should"`
	Text     string `json:"text"`
	Detail   string `json:"detail,omitempty"`
}

func (s *Server) addScanTools() {
	scope := "Link-local, metadata and loopback addresses are refused."
	if s.opts.Scan.Guard.AllowLoopback {
		scope = "Link-local and metadata addresses are refused."
	}
	if s.opts.Scan.Guard.Scope != nil {
		scope = "The operator limited scans to a scope; a target outside it is refused with the reason."
	}
	mcp.AddTool(s.Server, &mcp.Tool{
		Name:  "tls_scan",
		Title: "Scan a TLS endpoint",
		Description: "Scan one TLS/SSL endpoint now and judge it: post-quantum readiness level (L0–L4), TLS hygiene score, " +
			"findings with remediation, conformance to each published standard (NIST SP 800-52, BSI TR-02102, BCP 195, CNSA 2.0, ...), " +
			"and which named clients would connect. Connects to the target and makes a few hundred short handshakes (5–40 s); " +
			"sends nothing beyond handshakes except one HTTP GET / for headers. Nothing is stored. " +
			"Use for a host the user names; for an endpoint the fleet already tracks, prefer endpoint_get. " + scope,
		Annotations: readOnly("Scan a TLS endpoint", true),
	}, s.tlsScan)
	mcp.AddTool(s.Server, &mcp.Tool{
		Name:  "ssh_scan",
		Title: "Scan an SSH server",
		Description: "Scan one SSH server now and judge it: post-quantum readiness level (L0–L4), whether it meets the SSH baseline " +
			"(with the sshd_config lines that would make it), findings with remediation, and conformance to each published SSH standard. " +
			"Reads the server's identification and algorithm lists and fetches every host key in at most 24 connections (under 5 s); " +
			"never logs in. SSH servers have no hygiene score. Nothing is stored. " + scope,
		Annotations: readOnly("Scan an SSH server", true),
	}, s.sshScan)
}

func (s *Server) tlsScan(ctx context.Context, _ *mcp.CallToolRequest, in TLSScanInput) (*mcp.CallToolResult, ScanResult, error) {
	detail, err := detailLevel(in.Detail)
	if err != nil {
		return failf[ScanResult]("%v", err)
	}
	starttls := in.StartTLS
	if starttls == "" {
		starttls = "auto"
	}
	t, err := tlsprobe.ParseTargetStartTLS(strings.TrimSpace(in.Target), starttls)
	if err != nil {
		return failf[ScanResult]("invalid target: %v", err)
	}
	g := s.opts.Scan.Guard
	if err := g.CheckTarget(ctx, t.Host); err != nil {
		return failf[ScanResult]("%s cannot be scanned from here: %v", t.Host, err)
	}
	g = g.ForTarget(t.Host)
	o := tlsprobe.Options{
		Timeout: s.opts.Scan.Timeout, Concurrency: s.opts.Scan.Concurrency, MaxConnections: s.opts.Scan.MaxConnections,
		HTTPChecks: s.opts.Scan.HTTPChecks, Dial: g.Dial, LookupIP: g.LookupIP, Now: s.opts.Now,
	}
	if in.HTTPChecks != nil {
		o.HTTPChecks = *in.HTTPChecks
	}
	name := targetName(t)
	s.opts.Log.Info("tls_scan", "target", name)
	rep, scanErr := tlsprobe.Scan(ctx, t, o)
	if err := ctxErr(ctx); err != nil {
		return failf[ScanResult]("%v", err)
	}
	res := ScanResult{Target: name, Protocol: "tls"}
	if rep == nil || (scanErr != nil && !anySupported(rep)) {
		res.Error = "could not be scanned"
		if scanErr != nil {
			res.Error = scanErr.Error()
		}
		return textResult(name+"\n\n  Could not be scanned: "+res.Error, res)
	}
	res.Scanned = true
	res.Incomplete = rep.Incomplete || scanErr != nil
	ev := eval.Evaluate(rep, s.opts.Now())
	fill(&res, ev, detail)
	res.Hygiene = &HygieneView{Score: ev.Hygiene.Score, Band: ev.Hygiene.Band}
	if cs := eval.SummariseClients(ev.Clients); cs != nil {
		res.Clients = &ClientsView{Connect: cs.Connect, Fail: cs.Fail, PQ: cs.PQ, NoFS: cs.NoFS}
	}
	text := s.verdictText(name, rep, ev, detail)
	if scanErr != nil {
		text = "Warning: " + scanErr.Error() + "\n\n" + text
	}
	return textResult(text, res)
}

func (s *Server) sshScan(ctx context.Context, _ *mcp.CallToolRequest, in SSHScanInput) (*mcp.CallToolResult, ScanResult, error) {
	detail, err := detailLevel(in.Detail)
	if err != nil {
		return failf[ScanResult]("%v", err)
	}
	baseline := in.Baseline
	if baseline == "" {
		baseline = eval.BaselineDefault
	}
	if _, ok := eval.SSHBaselineByID(baseline); !ok {
		ids := make([]string, 0, len(eval.SSHBaselines()))
		for _, b := range eval.SSHBaselines() {
			ids = append(ids, b.ID)
		}
		return failf[ScanResult]("unknown SSH baseline %q; the baselines are %s", baseline, strings.Join(ids, ", "))
	}
	t, err := sshprobe.ParseTarget(in.Target)
	if err != nil {
		return failf[ScanResult]("invalid target: %v", err)
	}
	g := s.opts.Scan.Guard
	if err := g.CheckTarget(ctx, t.Host); err != nil {
		return failf[ScanResult]("%s cannot be scanned from here: %v", t.Host, err)
	}
	g = g.ForTarget(t.Host)
	name := net.JoinHostPort(t.Host, strconv.Itoa(t.Port))
	s.opts.Log.Info("ssh_scan", "target", name)
	rep, scanErr := sshprobe.Scan(ctx, t, sshprobe.Options{
		Timeout: s.opts.Scan.Timeout, MaxConnections: sshprobe.MaxScanConnections, Dial: g.Dial, LookupIP: g.LookupIP, Now: s.opts.Now,
	})
	if err := ctxErr(ctx); err != nil {
		return failf[ScanResult]("%v", err)
	}
	res := ScanResult{Target: name, Protocol: "ssh"}
	if rep == nil || (scanErr != nil && rep.Identification == nil) {
		res.Error = "could not be scanned"
		if scanErr != nil {
			res.Error = scanErr.Error()
		}
		return textResult(name+"\n\n  Could not be scanned: "+res.Error, res)
	}
	res.Scanned = true
	res.Incomplete = rep.Incomplete || scanErr != nil
	ev := eval.EvaluateSSH(rep, eval.Input{Now: s.opts.Now(), SSHBaseline: baseline})
	fill(&res, ev, detail)
	if ev.Baseline != nil {
		res.Baseline = &BaselineView{ID: ev.Baseline.Baseline, Title: ev.Baseline.Title, Judged: ev.Baseline.Judged, Meets: ev.Baseline.Meets,
			Reason: ev.Baseline.Reason, Changes: len(ev.Baseline.Changes)}
		if detail != DetailVerdict {
			for _, c := range ev.Baseline.Changes {
				res.Changes = append(res.Changes, c.Text)
			}
			res.SSHDConfig = ev.Baseline.SSHDConfig
		}
	}
	text := s.verdictText(name, rep, ev, detail)
	if scanErr != nil {
		text = "Warning: " + scanErr.Error() + "\n\n" + text
	}
	return textResult(text, res)
}

// fill sets what TLS and SSH results share.
func fill(res *ScanResult, ev eval.Evaluation, detail string) {
	res.Readiness = &ReadinessView{Level: ev.Readiness.Level, Label: ev.Readiness.Label, Summary: ev.Readiness.Summary, HNDLExposed: ev.Readiness.HNDLExposed}
	res.Counts = map[string]int{}
	for sev, n := range ev.Counts {
		res.Counts[string(sev)] = n
	}
	for _, c := range ev.Checks {
		if c.Result == "found" || c.Result == "not-found" {
			res.ChecksRun++
		}
	}
	for _, st := range ev.Standards {
		res.Standards = append(res.Standards, StandardView{ID: st.ID, Title: st.Title, Publisher: st.Publisher, Verdict: st.Verdict,
			MustFailures: st.MustFailures, ShouldFailures: st.ShouldFailures})
	}
	byID := map[string]eval.Finding{}
	for _, f := range ev.Findings {
		byID[f.ID] = f
	}
	for _, id := range ev.FixFirst {
		if f, ok := byID[id]; ok {
			res.FixFirst = append(res.FixFirst, findingView(f))
		}
	}
	if detail == DetailVerdict {
		return
	}
	for _, f := range ev.Findings {
		res.Findings = append(res.Findings, findingView(f))
	}
	for _, st := range ev.Standards {
		for _, c := range st.Requirements {
			if c.Status != eval.ReqNotMet {
				continue
			}
			res.Clauses = append(res.Clauses, ClauseView{Standard: st.ID, Clause: c.Clause, Level: c.Level, Text: c.Text, Detail: c.Detail})
		}
	}
	if detail == DetailFull {
		if raw, note := compactJSON(ev); raw != nil {
			res.Full = ev
		} else {
			res.Note = note
		}
	}
}

func findingView(f eval.Finding) FindingView {
	return FindingView{ID: f.ID, Severity: string(f.Severity), Title: f.Title, Detail: f.Detail, Remediation: f.Remediation}
}

// verdictText is the text half: the CLI's verdict, and with more detail what --details adds.
func (s *Server) verdictText(name string, rep any, ev eval.Evaluation, detail string) string {
	var b strings.Builder
	if s.opts.Verdict != nil {
		if err := s.opts.Verdict(&b, name, ev); err != nil {
			b.WriteString("verdict: " + err.Error())
		}
	} else {
		b.WriteString(name + ": " + ev.Readiness.Label + "\n")
	}
	if detail != DetailVerdict && s.opts.Details != nil {
		b.WriteString("\n")
		if err := s.opts.Details(&b, rep, ev); err != nil {
			b.WriteString("details: " + err.Error())
		}
	}
	// The verdict was written for the command line; here the flag is a tool argument.
	return strings.ReplaceAll(b.String(), "(--details lists", `(detail "findings" lists`)
}

func detailLevel(d string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(d)) {
	case "", DetailVerdict:
		return DetailVerdict, nil
	case DetailFindings:
		return DetailFindings, nil
	case DetailFull:
		return DetailFull, nil
	}
	return "", errors.New(`detail must be "verdict", "findings" or "full"`)
}

// anySupported says whether a TLS report saw any protocol version accepted.
func anySupported(rep *tlsprobe.Report) bool {
	for _, p := range rep.Protocols {
		if p.Supported {
			return true
		}
	}
	return false
}
