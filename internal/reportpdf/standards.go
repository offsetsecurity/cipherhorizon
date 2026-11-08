package reportpdf

import (
	"fmt"

	"github.com/offsetsecurity/cipherhorizon/internal/eval"
	"github.com/offsetsecurity/cipherhorizon/internal/pdf"
)

// standards is the standards page (PRD-017): per published standard, the verdict and every
// clause with its section number and what was seen, so an auditor can open the document at
// the clause and check the evidence against the rest of the report.
func (x *endpoint) standards() {
	if len(x.ev.Standards) == 0 {
		return
	}
	x.h2("Standards")
	var rows [][]pdf.Cell
	for _, st := range x.ev.Standards {
		word, t := standardVerdict(st)
		note := fmt.Sprintf("%d met · %d not assessed · %d do not apply", st.Met, st.NotAssessed, st.NotApplicable)
		if st.ShouldFailures > 0 {
			note = fmt.Sprintf("%s not followed · %s", plural(st.ShouldFailures, "recommendation"), note)
		}
		rows = append(rows, []pdf.Cell{txt(st.Title, pdf.Bold, ink), chipCell(word, t), txt(note, pdf.Regular, text2)})
	}
	x.table([]pdf.Col{{Title: "Standard", W: 2.2}, {Title: "Verdict", W: 1.3}, {Title: "Clauses", W: 3.1}}, rows)
	for _, st := range x.ev.Standards {
		x.p(bold(st.Title + " · " + st.Publisher + ", " + st.Edition))
		rows = nil
		for _, r := range st.Requirements {
			word, t := clauseStatus(r)
			rows = append(rows, []pdf.Cell{txt(r.Clause, pdf.Mono, text2), txt(r.Text, pdf.Regular, ink), chipCell(word, t), txt(r.Detail, pdf.Regular, text2)})
		}
		x.table([]pdf.Col{{Title: "Clause", W: 1.1}, {Title: "Requirement", W: 2.8}, {Title: "Status", W: 1}, {Title: "Seen", W: 2.3}}, rows)
		if len(st.Limits) > 0 {
			x.p(span("Not assessed by a network scan: "+joinWith(st.Limits, "; ")+".", pdf.Regular, smallSize, text2))
		}
	}
}

func standardVerdict(st eval.StandardResult) (string, tone) {
	switch st.Verdict {
	case eval.StdMeets:
		return "MEETS", toneGood
	case eval.StdFails:
		return fmt.Sprintf("NOT MET (%d)", st.MustFailures), toneBad
	}
	return "NOT ASSESSED", toneInfo
}

func clauseStatus(r eval.RequirementResult) (string, tone) {
	switch r.Status {
	case eval.ReqMet:
		return "MET", toneGood
	case eval.ReqNotMet:
		if r.Level == eval.LevelShould {
			return "NOT FOLLOWED", toneWarn
		}
		return "NOT MET", toneBad
	case eval.ReqNotApplicable:
		return "N/A", toneInfo
	}
	return "NOT ASSESSED", toneInfo
}

func joinWith(ss []string, sep string) string {
	out := ""
	for i, s := range ss {
		if i > 0 {
			out += sep
		}
		out += s
	}
	return out
}
