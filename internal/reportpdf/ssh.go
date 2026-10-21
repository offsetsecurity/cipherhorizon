package reportpdf

import (
	"fmt"
	"strings"
	"time"

	"github.com/offsetsecurity/cipherhorizon/internal/eval"
	"github.com/offsetsecurity/cipherhorizon/internal/pdf"
	"github.com/offsetsecurity/cipherhorizon/internal/sshprobe"
	"github.com/offsetsecurity/cipherhorizon/internal/sshprobe/registry"
)

// The SSH security report (PRD-008 REQ-SHO-3; UX-DESIGN-006 §2.8): the same cover, verdict,
// fix-first and every-check pages as the TLS report, with SSH's own sections.

// SSHInput is one stored SSH scan and its evaluation.
type SSHInput struct {
	Name, Address string
	ScanID        int64
	Report        *sshprobe.Report
	Eval          *eval.Evaluation
	Version       string
	Generated     time.Time
}

// sshSections mirror web/static/js/views/report-ssh.js SSH_SECTIONS.
var sshSections = []section{
	{"ssh-version", "SSH version & software", "Which protocol version the server speaks and what it says it runs."},
	{"key-exchange", "Key exchange & post-quantum", "How session keys are agreed, including post-quantum hybrids."},
	{"host-keys", "Host keys", "The keys the server proves its identity with."},
	{"encryption", "Encryption ciphers", "The ciphers the server offers for the session."},
	{"integrity", "Integrity (MACs) & compression", "How each packet is protected against tampering, and compression."},
	{"vulnerabilities", "Vulnerabilities", "Published attacks the configuration makes possible, inferred, never attempted."},
}

var sshSectionIDs = []string{"ssh-version", "key-exchange", "host-keys", "encryption", "integrity", "vulnerabilities"}

var sshStageTitles = []struct{ id, title string }{
	{sshprobe.StageIdentification, "Identification"}, {sshprobe.StageAlgorithms, "Algorithm lists"},
	{sshprobe.StageNegotiation, "Negotiation"}, {sshprobe.StageHostKeys, "Host keys"},
}

// SSH renders an SSH endpoint's report as a PDF.
func SSH(in SSHInput) ([]byte, error) {
	if in.Report == nil || in.Eval == nil {
		return nil, fmt.Errorf("reportpdf: a report and its evaluation are required")
	}
	if in.Generated.IsZero() {
		in.Generated = time.Now().UTC()
	}
	rep, ev := in.Report, in.Eval
	const title = "SSH security report"
	where := in.Address + "   ·   "
	if in.Name == in.Address {
		where = ""
	}
	sw := ""
	if id := rep.Identification; id != nil && id.Software != "" {
		sw = id.Software + "   ·   "
	}
	lines := []string{
		fmt.Sprintf("%s%sscanned %s", where, sw, stamp(rep.Started)),
		fmt.Sprintf("%s, %s   ·   generated %s", plural(rep.Connections, "connection"), duration(rep.DurationMS), stamp(in.Generated)),
	}
	x := &endpoint{
		doc: newDoc(fmt.Sprintf("%s: %s", title, in.Name), fmt.Sprintf("%s for %s", title, in.Address), in.Generated,
			cover{kicker: strings.ToUpper(title), title: in.Name, lines: lines},
			fmt.Sprintf("%s  ·  %s", title, in.Name),
			fmt.Sprintf("CipherHorizon %s  ·  %s  ·  scan %d  ·  this scan contacted only %s", in.Version, in.Name, in.ScanID, in.Address)),
		in:  EndpointInput{Name: in.Name, Address: in.Address, ScanID: in.ScanID, Eval: ev, Kind: KindFull, Version: in.Version, Generated: in.Generated},
		ssh: rep, ev: ev, byID: map[string][]eval.Finding{}, secOf: map[string]eval.Section{},
	}
	for _, f := range ev.Findings {
		x.byID[f.ID] = append(x.byID[f.ID], f)
	}
	for _, s := range ev.Sections {
		x.secOf[s.ID] = s
	}
	x.sshSummary()
	x.sshBaseline()
	x.fixFirst()
	x.glance()
	for _, id := range sshSectionIDs {
		x.section(id)
	}
	x.checks()
	x.about()
	return x.finish()
}

func (x *endpoint) sshSummary() {
	r := x.ev.Readiness
	lvl := fmt.Sprintf("L%d", r.Level)
	if r.Level < 0 {
		lvl = "?"
	}
	// An SSH server has no score (PRD-008 REQ-SHE-5): its second tile is the baseline verdict.
	baseBig, baseSub, baseT := "Not judged", "lists not read", toneInfo
	if b := x.ev.Baseline; b != nil {
		baseSub = b.Title
		switch {
		case !b.Judged:
			baseSub = b.Reason
		case b.Meets:
			baseBig, baseT = "Meets", toneGood
		case len(b.Changes) == 1:
			baseBig, baseT = "1 change", toneBad
		default:
			baseBig, baseT = fmt.Sprintf("%d changes", len(b.Changes)), toneBad
		}
	}
	keyBig, keySub, keyT := "None", "no host key fetched", toneInfo
	if len(x.ssh.HostKeys) > 0 {
		k := x.ssh.HostKeys[0]
		keyBig, keySub, keyT = hostKeyLabel(k), "classical", toneOK
		if k.PQ {
			keySub, keyT = "post-quantum", toneGood
		}
		if n := len(x.ssh.HostKeys); n > 1 {
			keySub += fmt.Sprintf(", 1 of %d keys", n)
		}
	}
	c := x.ev.Counts
	open := c[eval.Critical] + c[eval.High] + c[eval.Medium] + c[eval.Low]
	var parts []string
	for _, s := range []eval.Severity{eval.Critical, eval.High, eval.Medium, eval.Low} {
		if c[s] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", c[s], s))
		}
	}
	findT := toneGood
	if c[eval.Critical]+c[eval.High] > 0 {
		findT = toneBad
	} else if open > 0 {
		findT = toneWarn
	}
	sub := strings.Join(parts, ", ")
	if sub == "" {
		sub = "nothing above informational"
	}
	x.tiles([]tile{
		{lvl, "PQC readiness", r.Label, levelTone(r.Level)},
		{baseBig, "Baseline", baseSub, baseT},
		{keyBig, "Host key", keySub, keyT},
		{fmt.Sprint(open), "Findings to act on", sub, findT},
	})
	if r.Summary != "" {
		x.f.Add(pdf.Para{Spans: []pdf.Span{bold("Verdict. "), body(r.Summary)}, After: 8})
	}
}

func hostKeyLabel(k sshprobe.HostKey) string {
	switch {
	case k.Algorithm == "RSA" && k.Bits > 0:
		return fmt.Sprintf("RSA %d", k.Bits)
	case k.Curve != "":
		return k.Algorithm + " " + k.Curve
	}
	return k.Algorithm
}

// algoVerdict is the status word for one advertised algorithm against the evaluation's baseline,
// as the web report shows it: allowed (and post-quantum) or should be off.
func (x *endpoint) algoVerdict(kind, name string) (string, tone) {
	for _, a := range x.ev.SSHAlgorithms {
		if a.Kind != kind || a.Name != name {
			continue
		}
		switch {
		case a.Baseline == eval.BaselineOff:
			return "SHOULD BE OFF", toneBad
		case a.Verdict == "post-quantum":
			return "ALLOWED · POST-QUANTUM", toneGood
		}
		return "ALLOWED", toneOK
	}
	return "OFFERED", toneInfo
}

// sshBaseline is the baseline page: the verdict, the requirements, the changes and the sshd_config
// lines that would make the server meet it (PRD-008 REQ-SHB-8).
func (x *endpoint) sshBaseline() {
	b := x.ev.Baseline
	if b == nil {
		return
	}
	x.h2("Baseline: " + b.Title)
	switch {
	case !b.Judged:
		x.callout(toneInfo, bold("Not judged. "), body(b.Reason))
		return
	case b.Meets:
		x.callout(toneGood, bold("Meets the baseline. "), body("Every algorithm offered is on it and every requirement holds."))
	default:
		x.callout(toneBad, bold("Does not meet the baseline. "), body(fmt.Sprintf("%s to make; the sshd_config lines below make them.", plural(len(b.Changes), "change"))))
	}
	var rows [][]pdf.Cell
	for _, r := range b.Requires {
		word, t := "MET", toneGood
		if !r.Met {
			word, t = "NOT MET", toneBad
		}
		rows = append(rows, []pdf.Cell{txt(r.Text, pdf.Bold, ink), chipCell(word, t), txt(r.Detail+" "+r.Cite.Title, pdf.Regular, text2)})
	}
	if len(rows) > 0 {
		x.table([]pdf.Col{{Title: "Requirement", W: 2.2}, {Title: "Status", W: 1}, {Title: "Detail and source", W: 3.4}}, rows)
	}
	rows = nil
	for _, c := range b.Changes {
		rows = append(rows, []pdf.Cell{chipCell(strings.ToUpper(strings.ReplaceAll(c.Action, "-", " ")), toneBad), txt(c.Text, pdf.Regular, ink), txt(c.Cite.Title, pdf.Regular, text2)})
	}
	if len(rows) > 0 {
		x.table([]pdf.Col{{Title: "Change", W: 1.1}, {Title: "What", W: 3.2}, {Title: "Source", W: 2.3}}, rows)
	}
	if b.SSHDConfig != "" {
		var blocks []pdf.Block
		blocks = append(blocks, pdf.Para{Spans: []pdf.Span{bold("sshd_config lines")}, After: 4})
		for _, line := range strings.Split(strings.TrimRight(b.SSHDConfig, "\n"), "\n") {
			sp := mono(line)
			if strings.HasPrefix(line, "#") {
				sp = span(line, pdf.Mono, smallSize, text2)
			}
			blocks = append(blocks, pdf.Para{Spans: []pdf.Span{sp}, After: 1})
		}
		x.f.Box(pdf.BoxStyle{Fill: warmBG, HasFill: true, Accent: warm, AccentWidth: 3.5, Pad: 10, Radius: 4, After: 12}, blocks...)
	}
}

// algoTable lists one category of the server's lists with a verdict per name.
func (x *endpoint) algoTable(kind string, names []string, used string) {
	var rows [][]pdf.Cell
	for _, n := range names {
		word, t := x.algoVerdict(kind, n)
		a, _ := registry.Lookup(kind, n)
		what := a.Display
		if n == used {
			what += "  (used by " + sshprobe.CurrentClient + ")"
		}
		strength := "-"
		for _, ea := range x.ev.SSHAlgorithms {
			if ea.Kind == kind && ea.Name == n && ea.Strength != nil {
				strength = ea.Strength.Words()
			}
		}
		rows = append(rows, []pdf.Cell{monoCell(n), chipCell(word, t), txt(strength, pdf.Regular, ink), txt(what, pdf.Regular, text2)})
	}
	if len(rows) > 0 {
		x.table([]pdf.Col{{Title: "Name", W: 2.3}, {Title: "Status", W: 1.7}, {Title: "Classical strength", W: 1.2}, {Title: "What it is", W: 2.1}}, rows)
	}
}

func merged(a, b []string) []string {
	out := append([]string(nil), a...)
	for _, s := range b {
		if !contains(out, s) {
			out = append(out, s)
		}
	}
	return out
}

func (x *endpoint) sshSectionData(id string) sectionContent {
	rep := x.ssh
	alg := rep.Algorithms
	if alg == nil {
		alg = &sshprobe.Algorithms{}
	}
	n := rep.Negotiated
	if n == nil {
		n = &sshprobe.Negotiated{}
	}
	switch id {
	case "ssh-version":
		idn := rep.Identification
		if idn == nil {
			return sectionContent{facts: []string{"No identification was read."}}
		}
		facts := []string{fmt.Sprintf("The server identifies as %s.", idn.Raw)}
		if idn.SSH1 {
			facts = append(facts, "SSH-1 is accepted.")
		} else {
			facts = append(facts, "SSH-1 is not offered.")
		}
		return sectionContent{facts: facts}
	case "key-exchange":
		r := x.ev.Readiness
		facts := []string{r.KeyEstablishment.Detail}
		if alg.StrictKex {
			facts = append(facts, "Strict key exchange is on (the countermeasure to Terrapin).")
		}
		return sectionContent{facts: facts, detail: func() {
			x.levelScale(r.Level)
			x.algoTable(registry.KindKex, alg.Kex, n.Kex)
		}}
	case "host-keys":
		var facts []string
		for _, k := range rep.HostKeys {
			v := "signature verified"
			if !k.Verified {
				v = "signature " + firstNonEmpty(k.VerifyNote, "not verified")
			}
			facts = append(facts, fmt.Sprintf("%s %s (%s): %s.", hostKeyLabel(k), k.Fingerprint, strings.Join(k.ServedBy, ", "), v))
		}
		if len(facts) == 0 {
			facts = []string{"No host key was fetched."}
		}
		return sectionContent{facts: facts, detail: func() { x.algoTable(registry.KindHostKey, alg.HostKey, n.HostKey) }}
	case "encryption":
		ciphers := merged(alg.CipherC2S, alg.CipherS2C)
		return sectionContent{facts: []string{fmt.Sprintf("%d ciphers offered; a current client uses %s.", len(ciphers), firstNonEmpty(n.Cipher, "none in common"))},
			detail: func() { x.algoTable(registry.KindCipher, ciphers, n.Cipher) }}
	case "integrity":
		macs := merged(alg.MACC2S, alg.MACS2C)
		comp := merged(alg.CompressionC2S, alg.CompressionS2C)
		fact := fmt.Sprintf("%d MACs offered.", len(macs))
		if n.MAC == "" && n.Cipher != "" {
			fact += " The cipher a current client uses carries its own integrity, so no MAC is used."
		}
		return sectionContent{facts: []string{fact, "Compression: " + strings.Join(comp, ", ") + "."},
			detail: func() { x.algoTable(registry.KindMAC, macs, n.MAC) }}
	case "vulnerabilities":
		return x.vulnerabilities()
	}
	return sectionContent{}
}
