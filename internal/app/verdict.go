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
//	score<70        TLS hygiene score below 70 (an unrated score fails)
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
				pc.kind, pc.n, pc.label = "score", n, fmt.Sprintf("TLS hygiene score below %d", n)
			case strings.HasPrefix(c, "severity>="):
				sev := eval.Severity(strings.ToLower(strings.TrimPrefix(c, "severity>=")))
				switch sev {
				case eval.Critical, eval.High, eval.Medium, eval.Low, eval.Info:
				default:
					return nil, fmt.Errorf("--fail-on %q: the severity is critical, high, medium, low or info", c)
				}
				pc.kind, pc.n, pc.label = "severity", sev.Rank(), fmt.Sprintf("a %s finding or worse", sev)
			case strings.HasPrefix(c, "finding="):
				id := strings.ToUpper(strings.TrimPrefix(c, "finding="))
				if id == "" {
					return nil, fmt.Errorf("--fail-on %q: name a finding, e.g. finding=PROTO.TLS10", c)
				}
				pc.kind, pc.id, pc.label = "finding", id, "finding "+id
			default:
				return nil, fmt.Errorf("--fail-on %q: use level<L3, score<70, severity>=high or finding=ID", c)
			}
			out = append(out, pc)
		}
	}
	return out, nil
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
		case "finding":
			for _, f := range ev.Findings {
				if f.ID == c.id {
					out = append(out, c.label)
					break
				}
			}
		}
	}
	return out
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
	if hy.Score >= 0 {
		fmt.Fprintf(&b, "  TLS hygiene score        %d / 100  %s\n", hy.Score, hy.Band)
	} else {
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
	if len(notes) > 0 {
		b.WriteString("\n  Notes\n")
		for _, f := range notes {
			fmt.Fprintf(&b, "    %s\n", f.Title)
		}
	}
	_, err := io.WriteString(w, b.String())
	return err
}
