package app

import (
	"fmt"
	"io"
	"strings"

	"github.com/offsetsecurity/cipherhorizon/internal/eval"
)

// standardsCmd prints every standard of a protocol: what it is, every clause this program judges
// (with the document's own section numbers), and what a network scan cannot assess (PRD-017).
func standardsCmd(env Env, protocol string) int {
	w := env.Stdout
	for i, s := range eval.StandardsFor(protocol) {
		if i > 0 {
			_, _ = fmt.Fprintln(w)
		}
		_, _ = fmt.Fprintf(w, "%s\n  %s, %s, %s\n  %s\n  %s\n", s.ID, s.Title, s.Publisher, s.Edition, s.Scope, s.URL)
		_, _ = fmt.Fprintln(w, "\n  Clauses judged")
		for _, r := range s.Requirements {
			level := "must  "
			if r.Level == eval.LevelShould {
				level = "should"
			}
			_, _ = fmt.Fprintf(w, "    %s  %-26s %s\n", level, r.Clause, r.Text)
		}
		if len(s.NotAssessed) > 0 {
			_, _ = fmt.Fprintln(w, "\n  Not assessed by a network scan")
			for _, n := range s.NotAssessed {
				_, _ = fmt.Fprintf(w, "    %s\n", n)
			}
		}
	}
	_, _ = fmt.Fprintf(w, "\nA scan judges every standard; --fail-on standard=ID exits 3 when the target does not meet one.\n")
	return ExitOK
}

// writeClients prints who connects, in one block: the counts, then the clients that cannot and why.
func writeClients(b *strings.Builder, ev eval.Evaluation) {
	sum := eval.SummariseClients(ev.Clients)
	if sum == nil {
		return
	}
	fmt.Fprintf(b, "\n  Clients                  %d of %d connect", sum.Connect, len(ev.Clients))
	if sum.PQ > 0 {
		fmt.Fprintf(b, "; %d with post-quantum key exchange", sum.PQ)
	}
	if sum.NoFS > 0 {
		fmt.Fprintf(b, "; %d without forward secrecy", sum.NoFS)
	}
	b.WriteString("\n")
	for _, c := range ev.Clients {
		if !c.Connects {
			fmt.Fprintf(b, "    cannot connect  %-28s %s\n", c.Name, c.Why)
		}
	}
	b.WriteString("    (--details lists what every client negotiates)\n")
}

// writeClientsDetail prints every client's simulated outcome.
func writeClientsDetail(w io.Writer, ev eval.Evaluation) {
	if len(ev.Clients) == 0 {
		return
	}
	var b strings.Builder
	b.WriteString("\nClients, simulated from this scan\n")
	for _, c := range ev.Clients {
		if !c.Connects {
			fmt.Fprintf(&b, "  %-34s cannot connect: %s\n", c.Name, c.Why)
			continue
		}
		props := "forward secrecy"
		if !c.ForwardSecrecy {
			props = "no forward secrecy"
		}
		if c.PQ {
			props = "post-quantum, " + props
		}
		group := c.Group
		if group == "" {
			group = "static RSA"
		}
		fmt.Fprintf(&b, "  %-34s %-8s %-46s %-20s %s\n", c.Name, c.Version, c.Suite, group, props)
	}
	_, _ = io.WriteString(w, b.String())
}

// writeStandardsDetail prints, after the raw details, every clause of every standard with its
// status, so the whole checklist is on the terminal.
func writeStandardsDetail(w io.Writer, ev eval.Evaluation) {
	if len(ev.Standards) == 0 {
		return
	}
	var b strings.Builder
	b.WriteString("\nStandards, clause by clause\n")
	for _, st := range ev.Standards {
		fmt.Fprintf(&b, "\n  %s (%s, %s)\n", st.Title, st.Publisher, st.Edition)
		for _, r := range st.Requirements {
			word := map[string]string{eval.ReqMet: "met", eval.ReqNotMet: "NOT MET", eval.ReqNotAssessed: "not assessed", eval.ReqNotApplicable: "n/a"}[r.Status]
			if r.Status == eval.ReqNotMet && r.Level == eval.LevelShould {
				word = "not followed"
			}
			fmt.Fprintf(&b, "    %-13s %-22s %s\n", word, r.Clause, r.Text)
			if r.Detail != "" {
				fmt.Fprintf(&b, "    %-13s %-22s   %s\n", "", "", r.Detail)
			}
		}
	}
	_, _ = io.WriteString(w, b.String())
}
