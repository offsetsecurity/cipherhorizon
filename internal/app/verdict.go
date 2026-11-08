package app

import (
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"

	"github.com/offsetsecurity/cipherhorizon/internal/eval"
	"github.com/offsetsecurity/cipherhorizon/internal/tlsprobe"
)

// ExitPolicy is the exit code when a --fail-on condition is met (PRD-007 REQ-CL-3): the scan
// ran, and the result is not acceptable. It is distinct from 1 (nothing could be done) and 2
// (a result, but an incomplete one), so a CI step can tell the three apart.
const ExitPolicy = 3

// policyCond is one --fail-on condition.
type policyCond struct {
	raw   string
	kind  string // level, score, severity, finding
	n     int    // level or score threshold; severity rank
	id    string // finding ID
	label string // for messages
}

// parsePolicy reads --fail-on values; each may hold several conditions separated by commas.
//
//	level<L3        readiness below level 3 (L3 or 3)
//	score<70        hygiene score below 70 (TLS or SSH) (an unrated score fails)
//	severity>=high  any finding of this severity or worse (critical, high, medium, low, info)
//	finding=ID      this finding, e.g. PROTO.TLS10
func parsePolicy(values []string) ([]policyCond, error) {
	var out []policyCond
	for _, v := range values {
		for _, raw := range strings.Split(v, ",") {
			c := strings.TrimSpace(raw)
			if c == "" {
				continue
			}
			pc := policyCond{raw: c}
			switch {
			case strings.HasPrefix(c, "level<"):
				s := strings.TrimPrefix(strings.TrimPrefix(c, "level<"), "L")
				n, err := strconv.Atoi(s)
				if err != nil || n < 1 || n > 4 {
					return nil, fmt.Errorf("--fail-on %q: the level is L1 to L4", c)
				}
				pc.kind, pc.n, pc.label = "level", n, fmt.Sprintf("readiness below L%d", n)
			case strings.HasPrefix(c, "score<"):
				n, err := strconv.Atoi(strings.TrimPrefix(c, "score<"))
				if err != nil || n < 1 || n > 100 {
					return nil, fmt.Errorf("--fail-on %q: the score is 1 to 100", c)
				}
				pc.kind, pc.n, pc.label = "score", n, fmt.Sprintf("hygiene score below %d", n)
			case strings.HasPrefix(c, "severity>="):
				sev := eval.Severity(strings.ToLower(strings.TrimPrefix(c, "severity>=")))
				switch sev {
				case eval.Critical, eval.High, eval.Medium, eval.Low, eval.Info:
				default:
					return nil, fmt.Errorf("--fail-on %q: the severity is critical, high, medium, low or info", c)
				}
				pc.kind, pc.n, pc.label = "severity", sev.Rank(), fmt.Sprintf("a %s finding or worse", sev)
			case c == "baseline":
				pc.kind, pc.label = "baseline", "does not meet the SSH baseline"
			case strings.HasPrefix(c, "standard="):
				id := strings.ToLower(strings.TrimPrefix(c, "standard="))
				std, ok := eval.StandardByID(id)
				if !ok {
					return nil, fmt.Errorf("--fail-on %q: no such standard; list them with: cipherhorizon tls standards (or ssh standards)", c)
				}
				pc.kind, pc.id, pc.label = "standard", id, "does not meet "+std.Title
			case strings.HasPrefix(c, "finding="):
				id := strings.ToUpper(strings.TrimPrefix(c, "finding="))
				if id == "" {
					return nil, fmt.Errorf("--fail-on %q: name a finding, e.g. finding=PROTO.TLS10", c)
				}
				pc.kind, pc.id, pc.label = "finding", id, "finding "+id
			default:
				return nil, fmt.Errorf("--fail-on %q: use level<L3, score<70 (TLS), baseline (SSH), standard=ID, severity>=high or finding=ID", c)
			}
			out = append(out, pc)
		}
	}
	return out, nil
}

// policyFor refuses the conditions that mean nothing for a protocol: an SSH server has no score
// (PRD-008 REQ-SHE-5) and a TLS endpoint no SSH baseline.
func policyFor(conds []policyCond, protocol string) error {
	for _, c := range conds {
		switch {
		case c.kind == "score" && protocol == eval.ProtocolSSH:
			return fmt.Errorf("--fail-on %q: SSH servers have no score; use --fail-on baseline", c.raw)
		case c.kind == "baseline" && protocol != eval.ProtocolSSH:
			return fmt.Errorf("--fail-on %q: the baseline condition is for ssh scan; TLS endpoints are rated by their hygiene score", c.raw)
		case c.kind == "standard":
			if std, ok := eval.StandardByID(c.id); ok && std.Protocol != protocolWord(protocol) {
				return fmt.Errorf("--fail-on %q: %s is a %s standard", c.raw, std.Title, strings.ToUpper(std.Protocol))
			}
		}
	}
	return nil
}

// breaches lists the conditions an evaluation meets, each with what was seen.
func breaches(conds []policyCond, ev eval.Evaluation) []string {
	var out []string
	for _, c := range conds {
		switch c.kind {
		case "level":
			if ev.Readiness.Level < c.n {
				seen := "not determined"
				if ev.Readiness.Level >= 0 {
					seen = fmt.Sprintf("L%d %s", ev.Readiness.Level, ev.Readiness.Label)
				}
				out = append(out, fmt.Sprintf("%s (%s)", c.label, seen))
			}
		case "score":
			if ev.Hygiene.Score < c.n {
				seen := "not rated"
				if ev.Hygiene.Score >= 0 {
					seen = strconv.Itoa(ev.Hygiene.Score)
				}
				out = append(out, fmt.Sprintf("%s (%s)", c.label, seen))
			}
		case "severity":
			var ids []string
			for _, f := range ev.Findings {
				if f.Severity.Rank() <= c.n {
					ids = append(ids, f.ID)
				}
			}
			if len(ids) > 0 {
				out = append(out, fmt.Sprintf("%s (%s)", c.label, strings.Join(ids, ", ")))
			}
		case "baseline":
			if b := ev.Baseline; b != nil && b.Judged && !b.Meets {
				out = append(out, fmt.Sprintf("does not meet %s (%s)", b.Title, changesText(len(b.Changes))))
			}
		case "finding":
			for _, f := range ev.Findings {
				if f.ID == c.id {
					out = append(out, c.label)
					break
				}
			}
		case "standard":
			for _, st := range ev.Standards {
				if st.ID != c.id {
					continue
				}
				switch st.Verdict {
				case eval.StdFails:
					out = append(out, fmt.Sprintf("%s (%s)", c.label, clausesText(st)))
				case eval.StdNotAssessed:
					out = append(out, fmt.Sprintf("%s could not be assessed on this scan", st.Title))
				}
			}
		}
	}
	return out
}

// protocolWord is a standard's protocol word for an evaluation protocol ("" is TLS).
func protocolWord(protocol string) string {
	if protocol == eval.ProtocolSSH {
		return eval.ProtocolSSH
	}
	return "tls"
}

// clausesText names the clauses a standard is not met on: "2 clauses: §3.1, §4.5".
func clausesText(st eval.StandardResult) string {
	var ids []string
	for _, r := range st.Requirements {
		if r.Status == eval.ReqNotMet && r.Level == eval.LevelMust {
			ids = append(ids, r.Clause)
		}
	}
	word := "clauses"
	if len(ids) == 1 {
		word = "clause"
	}
	n := len(ids)
	if len(ids) > 4 {
		ids = append(ids[:4], fmt.Sprintf("and %d more", n-4))
	}
	return fmt.Sprintf("%d %s: %s", n, word, strings.Join(ids, "; "))
}

// writeStandards prints one line per standard: the verdict and how many clauses are not met.
func writeStandards(b *strings.Builder, ev eval.Evaluation) {
	if len(ev.Standards) == 0 {
		return
	}
	b.WriteString("\n  Standards\n")
	for _, st := range ev.Standards {
		var verdict string
		switch st.Verdict {
		case eval.StdMeets:
			verdict = "meets"
			if st.ShouldFailures > 0 {
				verdict += fmt.Sprintf(" (%d recommendation(s) not followed)", st.ShouldFailures)
			}
		case eval.StdFails:
			verdict = "does not meet: " + clausesText(st)
			if st.ShouldFailures > 0 {
				verdict += fmt.Sprintf("; %d recommendation(s) not followed", st.ShouldFailures)
			}
		default:
			verdict = "not assessed: the scan holds no evidence for its clauses"
		}
		fmt.Fprintf(b, "    %-30s %s\n", st.Title, verdict)
	}
	b.WriteString("    (--details lists every clause with its section number)\n")
}

// targetName is host:port, with the STARTTLS protocol when there is one.
func targetName(t tlsprobe.Target) string {
	name := net.JoinHostPort(t.Host, strconv.Itoa(t.Port))
	if t.StartTLS != "" {
		name += " via STARTTLS (" + tlsprobe.StartTLSName(t.StartTLS) + ")"
	}
	return name
}

// writeVerdict prints what the evaluation concluded, before any raw detail (REQ-CL-1): the
// readiness level, the TLS hygiene score, what was checked, then what to do, worst first.
func writeVerdict(w io.Writer, target string, ev eval.Evaluation) error {
	var b strings.Builder
	r, hy := ev.Readiness, ev.Hygiene
	fmt.Fprintf(&b, "%s\n\n", target)
	if r.Level < 0 {
		b.WriteString("  Post-quantum readiness   not determined\n")
	} else {
		fmt.Fprintf(&b, "  Post-quantum readiness   L%d  %s\n", r.Level, r.Label)
	}
	if r.Summary != "" {
		fmt.Fprintf(&b, "                           %s\n", r.Summary)
	}
	if r.HNDLExposed {
		b.WriteString("                           Recorded traffic could be decrypted later (harvest now, decrypt later).\n")
	}
	switch base := ev.Baseline; {
	case ev.Protocol == eval.ProtocolSSH && (base == nil || !base.Judged):
		reason := "the server's lists were not read"
		if base != nil && base.Reason != "" {
			reason = strings.TrimSuffix(base.Reason, ".")
		}
		fmt.Fprintf(&b, "  Baseline                 not judged: %s\n", reason)
	case ev.Protocol == eval.ProtocolSSH && base.Meets:
		fmt.Fprintf(&b, "  Baseline                 meets %s\n", base.Title)
	case ev.Protocol == eval.ProtocolSSH:
		fmt.Fprintf(&b, "  Baseline                 does not meet %s (%s)\n", base.Title, changesText(len(base.Changes)))
	case hy.Score >= 0:
		fmt.Fprintf(&b, "  TLS hygiene score        %d / 100  %s\n", hy.Score, hy.Band)
	default:
		b.WriteString("  TLS hygiene score        not rated\n")
	}
	run, found, notChecked := 0, 0, 0
	for _, c := range ev.Checks {
		switch c.Result {
		case "found":
			run++
			found++
		case "not-found":
			run++
		case "not-applicable": // nothing to check on this kind of service
		default:
			notChecked++
		}
	}
	fmt.Fprintf(&b, "  Checks                   %d run, %d found something", run, found)
	if notChecked > 0 {
		fmt.Fprintf(&b, ", %d not checked", notChecked)
	}
	b.WriteString("\n")

	var act, notes []eval.Finding
	for _, f := range ev.Findings {
		if f.Severity == eval.Info {
			notes = append(notes, f)
		} else {
			act = append(act, f)
		}
	}
	if len(act) == 0 {
		b.WriteString("\n  Nothing to fix.\n")
	} else {
		b.WriteString("\n  What to do, worst first\n")
		for _, f := range act {
			fmt.Fprintf(&b, "    %-8s  %s\n", strings.ToUpper(string(f.Severity)), f.Title)
			if f.Remediation != "" {
				fmt.Fprintf(&b, "              %s\n", f.Remediation)
			}
		}
	}
	if base := ev.Baseline; base != nil && base.SSHDConfig != "" {
		b.WriteString("\n  sshd_config lines that meet the baseline\n")
		for _, line := range strings.Split(strings.TrimRight(base.SSHDConfig, "\n"), "\n") {
			b.WriteString("    " + line + "\n")
		}
	}
	writeStandards(&b, ev)
	writeClients(&b, ev)
	if len(notes) > 0 {
		b.WriteString("\n  Notes\n")
		for _, f := range notes {
			fmt.Fprintf(&b, "    %s\n", f.Title)
		}
	}
	if r, ok := oldRootStores(ev); ok {
		fmt.Fprintf(&b, "\n  The root stores in this version were retrieved %s (%d days before this evaluation): a CA\n"+
			"  removed or blocked since then is not reflected in the trust verdict. Upgrade CipherHorizon.\n", r.Retrieved, r.AgeDays)
	}
	_, err := io.WriteString(w, b.String())
	return err
}

// changesText is "1 change" or "N changes".
func changesText(n int) string {
	if n == 1 {
		return "1 change"
	}
	return strconv.Itoa(n) + " changes"
}

// oldRootStores returns the bundled root store an evaluation flagged as old, if any.
func oldRootStores(ev eval.Evaluation) (eval.RefInfo, bool) {
	for _, r := range ev.ReferenceData {
		if r.Stale && strings.Contains(strings.ToLower(r.Name), "root store") {
			return r, true
		}
	}
	return eval.RefInfo{}, false
}
