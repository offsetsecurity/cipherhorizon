package reportpdf

import (
	"fmt"
	"strings"

	"github.com/example/cipherhorizon/internal/pdf"
	"github.com/example/cipherhorizon/internal/tlsprobe"
)

// The PDF shows what the web report shows (PRD-006): what each TLS version ran, and
// every check that was run, found or not.

var versionOrder = []string{"TLSv1.3", "TLSv1.2", "TLSv1.1", "TLSv1.0", "SSLv3", "SSLv2"}

func versionLabel(v string) string {
	return strings.NewReplacer("TLSv", "TLS ", "SSLv", "SSL ").Replace(v)
}

// suiteStrength matches the web report's four words.
func suiteStrength(s tlsprobe.SuiteResult) string {
	switch {
	case s.Cipher == "NULL" || s.Export || s.Anon || s.Cipher == "RC4":
		return "insecure"
	case s.BlockBits == 64 || (s.Kx != "" && !s.Ephemeral && (s.Kx == "RSA" || s.Kx == "DH" || s.Kx == "ECDH")):
		return "weak"
	case !s.AEAD && s.Version != "TLSv1.3":
		return "acceptable"
	}
	return "strong"
}

// matrix draws one row per protocol version: accepted or not, and what the version ran.
func (x *endpoint) matrix() {
	byVersion := map[string]tlsprobe.ProtocolResult{}
	for _, p := range x.rep.Protocols {
		byVersion[p.Version] = p
	}
	var rows [][]pdf.Cell
	for _, v := range versionOrder {
		p, ok := byVersion[v]
		if !ok {
			continue
		}
		if !p.Supported {
			state := chipCell("OFF: GOOD", toneGood)
			if v == "TLSv1.3" {
				state = chipCell("OFF: TURN ON", toneWarn)
			}
			rows = append(rows, []pdf.Cell{txt(versionLabel(v), pdf.Bold, muted), state, txt("", pdf.Regular, muted), txt("", pdf.Regular, muted), txt("", pdf.Regular, muted)})
			continue
		}
		counts := map[string]int{}
		var n, fs int
		for _, s := range x.rep.Suites {
			if s.Version != v {
				continue
			}
			n++
			counts[suiteStrength(s)]++
			if s.Version == "TLSv1.3" || s.Ephemeral {
				fs++
			}
		}
		var parts []string
		for _, k := range []string{"strong", "acceptable", "weak", "insecure"} {
			if counts[k] > 0 {
				parts = append(parts, fmt.Sprintf("%d %s", counts[k], k))
			}
		}
		suiteCell := txt(fmt.Sprintf("%s: %s", plural(n, "suite"), strings.Join(parts, ", ")), pdf.Regular, ink)
		if counts["insecure"]+counts["weak"] > 0 {
			suiteCell = txt(fmt.Sprintf("%s: %s", plural(n, "suite"), strings.Join(parts, ", ")), pdf.Bold, toneBad.fg)
		}
		var groups, pq []string
		for _, g := range x.rep.Groups {
			if g.Version == v {
				groups = append(groups, g.Name)
				if g.PQ && !g.Obsolete {
					pq = append(pq, g.Name)
				}
			}
		}
		kx := strings.Join(groups, ", ")
		if len(pq) > 0 {
			kx += " (post-quantum: " + strings.Join(pq, ", ") + ")"
		}
		state := chipCell("ON: GOOD", toneGood)
		if legacyVersion(v) {
			state = chipCell("ON: TURN OFF", toneBad)
		}
		fsText := "none"
		switch {
		case n > 0 && fs == n:
			fsText = "all suites"
		case fs > 0:
			fsText = fmt.Sprintf("%d of %d", fs, n)
		}
		rows = append(rows, []pdf.Cell{txt(versionLabel(v), pdf.Bold, ink), state, suiteCell, txt(fsText, pdf.Regular, text2), txt(kx, pdf.Regular, text2)})
	}
	if len(rows) == 0 {
		return
	}
	x.h2("What each TLS version ran")
	x.table([]pdf.Col{{Title: "Version", W: 0.8}, {Title: "Offered", W: 1.3}, {Title: "Cipher suites by strength", W: 2.2}, {Title: "Forward secrecy", W: 1}, {Title: "Key exchange", W: 2}}, rows)
}

// checks lists every check the evaluation ran, area by area.
func (x *endpoint) checks() {
	cs := x.ev.Checks
	if len(cs) == 0 {
		return
	}
	found, clean, skipped := 0, 0, 0
	for _, c := range cs {
		switch c.Result {
		case "found":
			found++
		case "not-found":
			clean++
		default:
			skipped++
		}
	}
	x.h1("Every check run")
	x.p(body(fmt.Sprintf("%d checks: %d found something, %d passed", len(cs), found, clean)),
		body(map[bool]string{true: fmt.Sprintf(", %d could not run", skipped), false: ""}[skipped > 0]+". "),
		soft("A passed check says what was confirmed; a found one names the problem."))
	for _, s := range sections {
		var rows [][]pdf.Cell
		for _, c := range cs {
			if c.Section != s.id {
				continue
			}
			res := chipCell("PASSED", toneGood)
			title := c.Title
			if c.Pass != "" {
				title = c.Pass
			}
			switch c.Result {
			case "found":
				t := sevTone(c.Severity)
				if fs := x.byID[c.ID]; len(fs) > 0 {
					t = sevTone(fs[0].Severity)
				}
				res = chipCell("FOUND", t)
				title = c.Title
			case "not-checked":
				res = chipCell("NOT CHECKED", toneInfo)
			}
			rows = append(rows, []pdf.Cell{txt(title, pdf.Regular, ink), res})
		}
		if len(rows) == 0 {
			continue
		}
		x.h2(s.title)
		x.table([]pdf.Col{{Title: "Check", W: 5}, {Title: "Result", W: 1.2}}, rows)
	}
}
