package reportpdf

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/offsetsecurity/cipherhorizon/internal/eval"
	"github.com/offsetsecurity/cipherhorizon/internal/pdf"
	"github.com/offsetsecurity/cipherhorizon/internal/pki"
	"github.com/offsetsecurity/cipherhorizon/internal/sshprobe"
	"github.com/offsetsecurity/cipherhorizon/internal/tlsprobe"
)

// The kinds of endpoint report.
const (
	KindFull = "full" // everything: summary, every section, every finding, how it was tested
	KindTLS  = "tls"  // the TLS configuration sections
	KindCert = "cert" // certificates, trust and revocation, with every certificate field
)

// EndpointInput is one stored scan of an endpoint and its evaluation.
type EndpointInput struct {
	Name, Address string
	ScanID        int64
	Report        *tlsprobe.Report
	Eval          *eval.Evaluation
	Kind          string
	Version       string    // the product version, for the footer
	Generated     time.Time // "now" for days-left figures and the document date
}

type section struct{ id, title, purpose string }

// sections mirror web/static/js/views/report.js SECTIONS.
var sections = []section{
	{"certificates", "Certificates & trust", "Who issued the certificate, who trusts it, and how long it lasts."},
	{"revocation", "Revocation & transparency", "The stapled revocation proof and Certificate Transparency proofs."},
	{"protocols", "Protocols", "Which SSL and TLS versions the server accepts."},
	{"suites", "Cipher suites", "Every cipher suite accepted, and who chooses the order."},
	{"key-exchange", "Key exchange & post-quantum", "How session keys are agreed, including post-quantum hybrids."},
	{"features", "Features & sessions", "Renegotiation, compression, downgrade protection and client certificates."},
	{"http", "HTTP security", "Whether browsers are told to use HTTPS only (HSTS)."},
	{"vulnerabilities", "Vulnerabilities", "Published attacks the configuration makes possible, inferred, never attempted."},
}

var kindSections = map[string][]string{
	KindFull: {"certificates", "revocation", "protocols", "suites", "key-exchange", "features", "http", "vulnerabilities"},
	KindTLS:  {"protocols", "suites", "key-exchange", "features", "http", "vulnerabilities"},
	KindCert: {"certificates", "revocation"},
}

var kindTitle = map[string]string{KindFull: "TLS security report", KindTLS: "TLS configuration report", KindCert: "Certificate report"}

// ValidKind says whether k names an endpoint report.
func ValidKind(k string) bool { _, ok := kindSections[k]; return ok }

type endpoint struct {
	*doc
	in    EndpointInput
	rep   *tlsprobe.Report
	ssh   *sshprobe.Report // set for an SSH endpoint (then rep is nil)
	ev    *eval.Evaluation
	byID  map[string][]eval.Finding
	secOf map[string]eval.Section
}

// Endpoint renders the report as a PDF.
func Endpoint(in EndpointInput) ([]byte, error) {
	if in.Report == nil || in.Eval == nil {
		return nil, fmt.Errorf("reportpdf: a report and its evaluation are required")
	}
	if !ValidKind(in.Kind) {
		in.Kind = KindFull
	}
	if in.Generated.IsZero() {
		in.Generated = time.Now().UTC()
	}
	rep, ev := in.Report, in.Eval
	title := kindTitle[in.Kind]
	where := in.Address + "   ·   "
	if in.Name == in.Address {
		where = ""
	}
	lines := []string{
		fmt.Sprintf("%sscanned %s", where, stamp(rep.Started)),
		fmt.Sprintf("%s, %s   ·   generated %s", plural(rep.Connections, "connection"), duration(rep.DurationMS), stamp(in.Generated)),
	}
	x := &endpoint{
		doc: newDoc(fmt.Sprintf("%s: %s", title, in.Name), fmt.Sprintf("%s for %s", title, in.Address), in.Generated,
			cover{kicker: strings.ToUpper(title), title: in.Name, lines: lines},
			fmt.Sprintf("%s  ·  %s", title, in.Name),
			fmt.Sprintf("CipherHorizon %s  ·  %s  ·  scan %d  ·  this scan contacted only %s", in.Version, in.Name, in.ScanID, in.Address)),
		in: in, rep: rep, ev: ev, byID: map[string][]eval.Finding{}, secOf: map[string]eval.Section{},
	}
	for _, f := range ev.Findings {
		x.byID[f.ID] = append(x.byID[f.ID], f)
	}
	for _, s := range ev.Sections {
		x.secOf[s.ID] = s
	}

	x.summary()
	if in.Kind == KindFull {
		x.fixFirst()
	}
	x.glance()
	if in.Kind != KindCert {
		x.matrix()
	}
	for _, id := range kindSections[in.Kind] {
		x.section(id)
	}
	if in.Kind == KindCert {
		x.everyCertificate()
	}
	if in.Kind == KindFull {
		x.checks()
	}
	x.about()
	return x.finish()
}

func duration(ms int64) string {
	if ms < 1000 {
		return fmt.Sprintf("%d ms", ms)
	}
	return fmt.Sprintf("%.1f s", float64(ms)/1000)
}

// ---- tones -------------------------------------------------------------------------------------

func levelTone(l int) tone {
	switch l {
	case 0:
		return toneBad
	case 1:
		return toneHigh
	case 2:
		return toneLow
	case 3:
		return toneGood
	case 4:
		return toneL4
	}
	return toneInfo
}

var levelNames = map[int]string{4: "PQ-authenticated", 3: "Hybrid negotiated", 2: "Hybrid available", 1: "Exposed", 0: "Not ready", -1: "Undetermined"}

func bandTone(b string) tone {
	switch b {
	case "Strong":
		return toneGood
	case "Sound":
		return toneOK
	case "Fair":
		return toneWarn
	case "Weak", "Broken":
		return toneBad
	}
	return toneInfo
}

func sevTone(s eval.Severity) tone {
	switch s {
	case eval.Critical:
		return toneBad
	case eval.High:
		return toneHigh
	case eval.Medium:
		return toneWarn
	case eval.Low:
		return toneLow
	}
	return toneInfo
}

func statusOf(st string) (string, tone) {
	switch st {
	case "problem":
		return "Problem", toneBad
	case "attention":
		return "Needs attention", toneWarn
	case "good":
		return "Good", toneGood
	case "not-checked":
		return "Not checked", toneInfo
	case "not-collected":
		return "Not collected", toneInfo
	case "not-applicable":
		return "Not applicable", toneInfo
	case "inconclusive":
		return "Inconclusive", toneWarn
	}
	return capitalise(st), toneInfo
}

// ---- summary -----------------------------------------------------------------------------------

func (x *endpoint) firstChain() (*eval.ChainView, *tlsprobe.CertResult) {
	var v *eval.ChainView
	for i := range x.ev.PKI {
		if !x.ev.PKI[i].NoSNI {
			v = &x.ev.PKI[i]
			break
		}
	}
	if v == nil && len(x.ev.PKI) > 0 {
		v = &x.ev.PKI[0]
	}
	if v == nil {
		if len(x.rep.Certificates) > 0 {
			return nil, &x.rep.Certificates[0]
		}
		return nil, nil
	}
	for i := range x.rep.Certificates {
		c := &x.rep.Certificates[i]
		if len(c.Chain) > 0 && c.Chain[0].SHA256 == v.Leaf && c.NoSNI == v.NoSNI {
			return v, c
		}
	}
	for i := range x.rep.Certificates {
		c := &x.rep.Certificates[i]
		if len(c.Chain) > 0 && c.Chain[0].SHA256 == v.Leaf {
			return v, c
		}
	}
	return v, nil
}

func (x *endpoint) daysLeft(t time.Time) int {
	return int(t.Sub(x.in.Generated).Hours() / 24)
}

func trustedBy(v *eval.ChainView) []string {
	var out []string
	for _, t := range v.Trust {
		if t.Trusted {
			out = append(out, t.Store)
		}
	}
	if v.Private != nil && v.Private.Trusted {
		out = append(out, "your CA bundle")
	}
	return out
}

func (x *endpoint) summary() {
	r, g := x.ev.Readiness, x.ev.Hygiene
	lvl := fmt.Sprintf("L%d", r.Level)
	if r.Level < 0 {
		lvl = "?"
	}
	label := r.Label
	if label == "" {
		label = levelNames[r.Level]
	}
	score := "-"
	if g.Score >= 0 {
		score = fmt.Sprint(g.Score)
	}
	certBig, certSub, certT := "None", "no certificate received", toneInfo
	if v, cr := x.firstChain(); cr != nil && len(cr.Chain) > 0 {
		left := x.daysLeft(cr.Chain[0].NotAfter)
		if left < 0 {
			certBig = "Expired"
		} else {
			certBig = fmt.Sprintf("%d days left", left)
		}
		certT = toneGood
		if v != nil {
			total := len(v.Trust)
			if v.Private != nil {
				total++
			}
			n := len(trustedBy(v))
			certSub = fmt.Sprintf("trusted by %d of %d root stores", n, total)
			if n == 0 {
				certT = toneBad
			}
		} else {
			certSub = "trust not analysed by this scan version"
		}
		if left < 0 {
			certT = toneBad
		} else if left <= 30 && certT != toneBad {
			certT = toneWarn
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
		{lvl, "PQC readiness", label, levelTone(r.Level)},
		{score, "TLS hygiene", fmt.Sprintf("%s, out of 100", g.Band), bandTone(g.Band)},
		{certBig, "Certificate", certSub, certT},
		{fmt.Sprint(open), "Findings to act on", sub, findT},
	})
	if r.Summary != "" {
		x.f.Add(pdf.Para{Spans: []pdf.Span{bold("Verdict. "), body(r.Summary)}, After: 8})
	}
	if x.ev.LegacyReport {
		x.callout(toneInfo, bold("Scanned by an earlier version. "), body("Some sections were not collected. Scan again to see them."))
	}
}

func (x *endpoint) fixFirst() {
	ids := x.ev.FixFirst
	if len(ids) == 0 {
		x.callout(toneGood, bold("Fix first. "), body("Nothing to fix: every finding on this report is informational."))
		return
	}
	blocks := []pdf.Block{pdf.Para{Spans: []pdf.Span{span("Fix first", pdf.Bold, 12, ink)}, After: 6}}
	for i, id := range ids {
		fs := x.byID[id]
		if len(fs) == 0 {
			continue
		}
		f := fs[0]
		t := sevTone(f.Severity)
		title := []pdf.Span{bold(f.Title)}
		if f.Availability {
			title = append(title, span(". Clients fail to connect", pdf.Bold, 7.5, toneBad.fg))
		}
		blocks = append(blocks,
			chipLine{chip: pdf.Chip{Text: fmt.Sprintf("%d  %s", i+1, strings.ToUpper(string(f.Severity))), FG: t.fg, BG: white, Size: 7}, para: pdf.Para{Spans: title}},
			pdf.Para{Spans: []pdf.Span{soft(f.Remediation)}, Indent: 0, After: 7})
	}
	x.f.Box(pdf.BoxStyle{Fill: warmBG, HasFill: true, Accent: warm, AccentWidth: 3.5, Pad: 12, Radius: 4, After: 12}, blocks...)
}

func (x *endpoint) glance() {
	x.h2("Sections at a glance")
	var rows [][]pdf.Cell
	for _, id := range x.sectionIDs() {
		s := x.sectionByID(id)
		sec := x.sectionData(id)
		word, t := statusOf(x.statusOf(id))
		rows = append(rows, []pdf.Cell{txt(s.title, pdf.Bold, ink), dotCell(word, t), txt(sec.verdict, pdf.Regular, text2)})
	}
	x.table([]pdf.Col{{Title: "Section", W: 1.6}, {Title: "Status", W: 1.05}, {Title: "In one line", W: 3.2}}, rows)
}

// sectionIDs are the sections this report shows, in order.
func (x *endpoint) sectionIDs() []string {
	if x.ssh != nil {
		return sshSectionIDs
	}
	return kindSections[x.in.Kind]
}

func (x *endpoint) sectionByID(id string) section {
	if x.ssh != nil {
		for _, s := range sshSections {
			if s.id == id {
				return s
			}
		}
	}
	return sectionByID(id)
}

func sectionByID(id string) section {
	for _, s := range sections {
		if s.id == id {
			return s
		}
	}
	return section{id: id, title: id}
}

func (x *endpoint) statusOf(id string) string {
	if s, ok := x.secOf[id]; ok {
		return s.Status
	}
	return "not-collected"
}

// ---- sections ----------------------------------------------------------------------------------

// sectionContent is what a section says: a one-line verdict, the facts behind
// it, and the detail drawn after them.
type sectionContent struct {
	verdict string
	facts   []string
	detail  func()
}

func (x *endpoint) sectionData(id string) sectionContent {
	var c sectionContent
	if x.ssh != nil {
		c = x.sshSectionData(id)
		id = ""
	}
	switch id {
	case "certificates":
		c = x.certificates()
	case "revocation":
		c = x.revocation()
	case "protocols":
		c = x.protocols()
	case "suites":
		c = x.suites()
	case "key-exchange":
		c = x.keyExchange()
	case "features":
		c = x.features()
	case "http":
		c = x.http()
	case "vulnerabilities":
		c = x.vulnerabilities()
	}
	var facts []string
	for _, f := range c.facts {
		if f != "" {
			facts = append(facts, f)
		}
	}
	c.facts = facts
	if c.verdict == "" && len(facts) > 0 {
		c.verdict = facts[0]
	}
	if c.verdict == "" {
		c.verdict = x.secOf[id].Reason
	}
	c.verdict = capitalise(c.verdict)
	return c
}

func (x *endpoint) section(id string) {
	s := x.sectionByID(id)
	c := x.sectionData(id)
	sec := x.secOf[id]
	word, t := statusOf(x.statusOf(id))

	x.f.Need(110)
	x.f.Y += 8
	p := x.f.Page
	x.d.Bookmark(s.title, p, x.f.Y)
	top := x.f.Y
	p.Rect(marginX, top, 3.5, 22, t.fg)
	p.Text(marginX+12, top+15, pdf.Bold, 14, ink, s.title)
	chip := pdf.Chip{Text: strings.ToUpper(word), FG: t.fg, BG: t.bg, Size: 7.2}
	pdf.DrawChip(p, right-pdf.ChipWidth(chip), top+4, chip)
	x.f.Y += 28
	x.f.Add(pdf.Para{Spans: []pdf.Span{span(s.purpose, pdf.Italic, 8.8, muted)}, After: 6})
	if st := sec.Status; st == "not-checked" || st == "not-collected" || st == "inconclusive" {
		x.callout(toneInfo, bold(word+". "), body(sec.Reason))
	}
	for _, f := range c.facts {
		if f == c.verdict && len(c.facts) > 1 {
			// The verdict leads the facts in bold.
			x.f.Add(pdf.Para{Spans: []pdf.Span{bold(f)}, Indent: 12, Bullet: "•", After: 2.5})
			continue
		}
		x.f.Add(pdf.Para{Spans: []pdf.Span{body(f)}, Indent: 12, Bullet: "•", After: 2.5})
	}
	x.gap(6)
	if c.detail != nil {
		c.detail()
	}
	var fs []eval.Finding
	for _, fid := range sec.Findings {
		fs = append(fs, x.byID[fid]...)
	}
	if len(fs) == 0 {
		for _, f := range x.ev.Findings {
			if f.Section == id {
				fs = append(fs, f)
			}
		}
	}
	if len(fs) > 0 {
		x.h2(fmt.Sprintf("Findings in %s (%d)", strings.ToLower(s.title), len(fs)))
		for _, f := range fs {
			x.finding(f)
		}
	}
	x.gap(6)
}

func (x *endpoint) finding(f eval.Finding) {
	t := sevTone(f.Severity)
	head := []pdf.Span{span(f.Title, pdf.Bold, 10, ink)}
	if len(f.Labels) > 0 {
		head = append(head, span("   "+strings.Join(f.Labels, ", "), pdf.Bold, 7.5, muted))
	}
	if f.Availability {
		head = append(head, span(" — clients fail to connect", pdf.Bold, 7.5, toneBad.fg))
	}
	blocks := []pdf.Block{
		chipLine{chip: pdf.Chip{Text: strings.ToUpper(string(f.Severity)), FG: t.fg, BG: t.bg, Size: 7}, para: pdf.Para{Spans: head, After: 3}},
	}
	if f.Remediation != "" {
		blocks = append(blocks, pdf.Para{Spans: []pdf.Span{bold("Fix: "), body(f.Remediation)}, After: 3})
	}
	if f.Detail != "" {
		ev := ""
		if f.Evidence != "" {
			ev = fmt.Sprintf("  (%s)", f.Evidence)
		}
		blocks = append(blocks, pdf.Para{Spans: []pdf.Span{span("Seen: ", pdf.Bold, 8.6, text2), span(f.Detail, pdf.Regular, 8.6, text2), small(ev)}, After: 3})
	}
	if len(f.Citations) > 0 {
		sp := []pdf.Span{span("Sources: ", pdf.Bold, smallSize, muted)}
		for i, c := range f.Citations {
			if i > 0 {
				sp = append(sp, small("  ·  "))
			}
			sp = append(sp, linkTo(c.Title, c.URL))
		}
		blocks = append(blocks, pdf.Para{Spans: sp})
	}
	x.f.Box(pdf.BoxStyle{Fill: white, HasFill: true, Border: rule, HasBorder: true, Accent: t.fg, AccentWidth: 3, Pad: 9, Radius: 3, After: 7}, blocks...)
}

// ---- certificates -------------------------------------------------------------------------------

func cn(dn string) string {
	for _, part := range strings.Split(dn, ",") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "CN=") {
			return part[3:]
		}
	}
	if dn == "" {
		return "unknown"
	}
	return dn
}

func keyDesc(k tlsprobe.KeyInfo) string {
	s := k.Algorithm
	if k.Bits > 0 {
		s += fmt.Sprintf(" %d-bit", k.Bits)
	}
	if k.Curve != "" {
		s += fmt.Sprintf(" (%s)", k.Curve)
	}
	return s
}

func chainLabel(v eval.ChainView) string {
	switch {
	case v.NoSNI:
		return "Without SNI"
	case strings.HasPrefix(v.Source, "tls-default"):
		return "Default chain"
	case strings.Contains(v.Source, "ecdsa"):
		return "ECDSA chain"
	case strings.Contains(v.Source, "rsa"):
		return "RSA chain"
	}
	return v.Source
}

func (x *endpoint) certificates() sectionContent {
	certs := x.rep.Certificates
	if len(certs) == 0 {
		return sectionContent{facts: []string{"No certificate was received."}}
	}
	v, cr := x.firstChain()
	if v == nil || cr == nil || len(cr.Chain) == 0 {
		return sectionContent{facts: []string{plural(len(certs), "certificate chain") + " presented."}, detail: func() {
			for _, c := range certs {
				x.servedTable(c, nil)
			}
		}}
	}
	leaf := cr.Chain[0]
	left := x.daysLeft(leaf.NotAfter)
	tb := trustedBy(v)
	validity := fmt.Sprintf("Valid until %s: %d days left of a %d-day lifetime.", day(leaf.NotAfter), left, v.Lifetime.Days)
	if left < 0 {
		validity = fmt.Sprintf("Expired %d days ago (%s).", -left, day(leaf.NotAfter))
	}
	trust := "Not trusted by any root store checked."
	if len(tb) > 0 {
		trust = "Trusted by " + strings.Join(tb, ", ") + "."
	}
	names := fmt.Sprintf("Not valid for %s.", v.Names.Host)
	if v.Names.MatchedBy != "" {
		names = fmt.Sprintf("Valid for %s (matched by %s).", v.Names.Host, v.Names.MatchedBy)
	}
	nosni := ""
	switch x.rep.NoSNI {
	case "same":
		nosni = "Clients that send no server name get the same certificate."
	case "different":
		nosni = "Clients that send no server name get a different certificate (shown below, not scored)."
	}
	verdictTrust := "Not trusted by any store checked"
	if len(tb) > 0 {
		verdictTrust = "Trusted by " + strings.Join(tb, ", ")
	}
	verdict := fmt.Sprintf("%s · %d days left", verdictTrust, left)
	if left < 0 {
		verdict = verdictTrust + " · expired"
	}
	return sectionContent{
		verdict: verdict,
		facts: []string{
			fmt.Sprintf("Issued to %s by %s; %s key, signed with %s.", cn(leaf.Subject), cn(leaf.Issuer), keyDesc(leaf.PublicKey), leaf.SignatureAlg.Name),
			validity, trust, names, nosni,
		},
		detail: func() {
			x.validityBar(leaf, v.Lifetime)
			for i := range x.ev.PKI {
				cv := x.ev.PKI[i]
				var c *tlsprobe.CertResult
				for j := range certs {
					if len(certs[j].Chain) > 0 && certs[j].Chain[0].SHA256 == cv.Leaf && certs[j].NoSNI == cv.NoSNI {
						c = &certs[j]
					}
				}
				if c == nil {
					continue
				}
				if len(x.ev.PKI) > 1 {
					x.h2(chainLabel(cv))
					if cv.NoSNI {
						x.callout(toneInfo, body("Only clients that send no server name see this certificate. Every current client sends one, and many large sites deliberately serve a placeholder here. It is shown for information and is not scored."))
					}
				}
				x.servedTable(*c, &cv)
				x.trustTable(cv)
			}
		},
	}
}

func (x *endpoint) validityBar(leaf tlsprobe.CertInfo, lt eval.LifetimeView) {
	from, to, now := leaf.NotBefore, leaf.NotAfter, x.in.Generated
	var limitEnd time.Time
	if lt.LimitDays > 0 {
		limitEnd = from.Add(time.Duration(lt.LimitDays) * 24 * time.Hour)
	}
	start, end := from, to
	if now.Before(start) {
		start = now
	}
	for _, t := range []time.Time{now, limitEnd} {
		if !t.IsZero() && t.After(end) {
			end = t
		}
	}
	span0 := end.Sub(start).Seconds()
	if span0 <= 0 {
		return
	}
	x.f.Add(pdf.Custom{H: 46, F: func(p *pdf.Page, x0, y, w float64) {
		at := func(t time.Time) float64 { return x0 + w*t.Sub(start).Seconds()/span0 }
		p.RoundRect(x0, y+14, w, 8, 4, headBG, 0, pdf.Color{})
		c := toneGood.fg
		if now.After(to) {
			c = toneBad.fg
		}
		p.RoundRect(at(from), y+14, max(4, at(to)-at(from)), 8, 4, c, 0, pdf.Color{})
		tx := at(now)
		p.Line(tx, y+8, tx, y+28, 1.2, ink)
		p.Text(min(max(x0, tx-10), x0+w-24), y+6, pdf.Bold, 7, ink, "today")
		if !limitEnd.IsZero() && lt.Applies {
			lx := at(limitEnd)
			p.Line(lx, y+10, lx, y+26, 1, toneWarn.fg)
			p.Text(min(max(x0, lx-30), x0+w-70), y+6, pdf.Regular, 7, toneWarn.fg, fmt.Sprintf("%d-day limit", lt.LimitDays))
		}
		p.Text(x0, y+36, pdf.Regular, 7.5, muted, "issued "+day(from))
		p.TextRight(x0+w, y+36, pdf.Regular, 7.5, muted, "expires "+day(to))
	}})
	if lt.LimitDays > 0 {
		note := fmt.Sprintf("Lifetime %d days. The public limit (%d days on its issue date) does not apply: no public root store trusts it.", lt.Days, lt.LimitDays)
		if lt.Applies {
			note = fmt.Sprintf("Lifetime %d days; the limit on its issue date was %d days (%s).", lt.Days, lt.LimitDays, lt.LimitSource)
		}
		x.f.Add(para(6, small(note)))
	}
}

func (x *endpoint) servedTable(c tlsprobe.CertResult, v *eval.ChainView) {
	x.h2("Chain as served")
	issues := map[int][]string{}
	onPath := map[int]bool{}
	if v != nil {
		for _, is := range v.Served.Issues {
			issues[is.Index] = append(issues[is.Index], is.Kind+": "+is.Detail)
		}
		for _, i := range v.Served.Path {
			onPath[i] = true
		}
		for _, i := range v.Served.ExpiresFirst {
			issues[i] = append(issues[i], "expires before the leaf")
		}
	}
	var rows [][]pdf.Cell
	for i, cert := range c.Chain {
		role := "intermediate"
		switch {
		case i == 0:
			role = "leaf"
		case cert.SelfSigned:
			role = "root"
		}
		if v != nil && !onPath[i] && i > 0 {
			role += ", not on the path"
		}
		note := strings.Join(issues[i], "; ")
		noteCell := txt(note, pdf.Regular, toneWarn.fg)
		if note == "" {
			noteCell = txt("", pdf.Regular, muted)
		}
		rows = append(rows, []pdf.Cell{txt(fmt.Sprint(i), pdf.Bold, text2), txt(cn(cert.Subject), pdf.Bold, ink), txt(role, pdf.Regular, text2),
			txt(keyDesc(cert.PublicKey), pdf.Regular, ink), txt(cert.SignatureAlg.Name, pdf.Regular, ink), txt(day(cert.NotAfter), pdf.Regular, ink), noteCell})
	}
	if v != nil && v.Served.Missing != nil {
		m := v.Served.Missing
		what := "Missing"
		why := "Not sent by the server and not in any trusted store."
		if m.Likely == "root" {
			what = "Unknown root"
			why = "Not in any trusted store. If this is your private CA, add it to the system's CA bundle."
		}
		if len(m.AIA) > 0 {
			why += " The certificate says it is available at " + strings.Join(m.AIA, ", ") + " (not fetched)."
		}
		rows = append(rows, []pdf.Cell{txt("?", pdf.Bold, toneBad.fg), txt(what+": "+cn(m.IssuerDN), pdf.Bold, toneBad.fg), txt("not served", pdf.Regular, toneBad.fg),
			txt("", pdf.Regular, ink), txt("", pdf.Regular, ink), txt("", pdf.Regular, ink), txt("", pdf.Regular, ink)})
		defer x.callout(toneBad, bold(what+": "+cn(m.IssuerDN)+". "), body(why))
	}
	x.table([]pdf.Col{{Title: "#", W: 0.3}, {Title: "Certificate", W: 2}, {Title: "Role", W: 1}, {Title: "Key", W: 1.3}, {Title: "Signature", W: 1.3}, {Title: "Valid until", W: 1}, {Title: "Note", W: 2}}, rows)
	if v != nil {
		size := fmt.Sprintf("%s, %d bytes.", plural(len(c.Chain), "certificate"), v.Served.SizeBytes)
		if v.Served.SizeBytes > 4096 {
			size = fmt.Sprintf("%s, %d bytes: more than fits a typical first round trip; trim extra certificates.", plural(len(c.Chain), "certificate"), v.Served.SizeBytes)
		}
		x.f.Add(para(4, small(size)))
		if len(v.Names.Checked) > 0 {
			x.f.Add(para(6, small("Names checked: "+strings.Join(v.Names.Checked, ", ")+". The common name is never used (RFC 9525).")))
		}
	}
}

func (x *endpoint) trustTable(v eval.ChainView) {
	x.h2("Trust")
	var rows [][]pdf.Cell
	results := make([]pki.StoreResult, 0, len(v.Trust)+2)
	results = append(results, v.Trust...)
	if v.Private != nil {
		results = append(results, *v.Private)
	}
	if v.OS != nil {
		results = append(results, *v.OS)
	}
	for _, t := range results {
		res, tt := "NOT TRUSTED", toneBad
		detail := t.Error
		switch {
		case t.Trusted:
			res, tt = "TRUSTED", toneGood
			detail = fmt.Sprintf("path of %d certificates", len(t.Path))
		case t.Distrust != "":
			res, detail = "DISTRUSTED", t.Distrust
		case t.ExpiredOnly:
			res, tt = "EXPIRED", toneWarn
		}
		name := t.Store
		if t.Snapshot != "" {
			name += " (snapshot " + t.Snapshot + ")"
		}
		rows = append(rows, []pdf.Cell{txt(name, pdf.Bold, ink), chipCell(res, tt), txt(detail, pdf.Regular, text2)})
	}
	if len(rows) == 0 {
		x.p(soft("No trust store was available."))
		return
	}
	x.table([]pdf.Col{{Title: "Store", W: 2}, {Title: "Result", W: 1.1}, {Title: "Detail", W: 3}}, rows)
	if v.Private == nil {
		x.f.Add(para(6, small("Private CA? Add it to this endpoint's system as a trust anchor (system page, CA bundle); the result is re-evaluated without a rescan.")))
	}
}

// everyCertificate lists every field of every certificate served (certificate report).
func (x *endpoint) everyCertificate() {
	if len(x.rep.Certificates) == 0 {
		return
	}
	x.h1("Every certificate, field by field")
	for _, c := range x.rep.Certificates {
		for i, cert := range c.Chain {
			role := "Intermediate"
			if i == 0 {
				role = "Leaf"
			} else if cert.SelfSigned {
				role = "Root"
			}
			x.h2(fmt.Sprintf("%s: %s", role, cn(cert.Subject)))
			names := append(append([]string{}, cert.DNSNames...), cert.IPAddresses...)
			bc := ""
			if cert.BasicConstraints != nil {
				bc = fmt.Sprintf("CA: %v", cert.BasicConstraints.CA)
				if cert.BasicConstraints.MaxPathLen >= 0 {
					bc += fmt.Sprintf(", path length %d", cert.BasicConstraints.MaxPathLen)
				}
			}
			yn := func(b bool) string {
				if b {
					return "yes"
				}
				return "no"
			}
			x.kv([][2]string{
				{"Served as", c.Source},
				{"Subject", cert.Subject},
				{"Issuer", cert.Issuer},
				{"Serial", cert.SerialHex},
				{"Valid from", stamp(cert.NotBefore)},
				{"Valid until", stamp(cert.NotAfter)},
				{"Lifetime", lifetimeText(cert.LifetimeDays)},
				{"Public key", keyDesc(cert.PublicKey)},
				{"Signature", cert.SignatureAlg.Name},
				{"Names", strings.Join(names, ", ")},
				{"Key usage", strings.Join(cert.KeyUsage, ", ")},
				{"Extended key usage", strings.Join(cert.ExtKeyUsage, ", ")},
				{"Basic constraints", bc},
				{"Policy class", cert.PolicyClass},
				{"OCSP responders", strings.Join(cert.OCSPServers, ", ")},
				{"Must-Staple", map[bool]string{true: "yes"}[cert.OCSPMustStaple]},
				{"CA issuers", strings.Join(cert.IssuerURLs, ", ")},
				{"CRL", strings.Join(cert.CRLPoints, ", ")},
				{"Embedded SCTs", yn(cert.EmbeddedSCTs)},
				{"Self-signed", yn(cert.SelfSigned)},
				{"SHA-256", cert.SHA256},
				{"SPKI SHA-256", cert.SPKISHA256},
			})
		}
	}
}

func lifetimeText(d int) string {
	if d <= 0 {
		return ""
	}
	return plural(d, "day")
}

// ---- revocation -------------------------------------------------------------------------------

func (x *endpoint) revocation() sectionContent {
	if len(x.ev.PKI) == 0 {
		return sectionContent{}
	}
	v, cr := x.firstChain()
	if v == nil {
		return sectionContent{}
	}
	var leaf tlsprobe.CertInfo
	if cr != nil && len(cr.Chain) > 0 {
		leaf = cr.Chain[0]
	}
	o := v.OCSP
	var ocspLine string
	switch {
	case o == nil && leaf.OCSPMustStaple:
		ocspLine = "No OCSP response was stapled, although the certificate requires one (Must-Staple)."
	case o == nil && len(v.OCSPURLs) > 0:
		ocspLine = "No OCSP response was stapled."
	case o == nil:
		ocspLine = "No OCSP response was stapled, and the certificate names no OCSP responder."
	case o.Error != "":
		ocspLine = "A stapled OCSP response was sent but is not usable: " + o.Error + "."
	case !o.ForThisCert:
		ocspLine = "A stapled OCSP response was sent, but it is for a different certificate."
	default:
		sig := map[string]string{"valid": "signed by the issuer", "invalid": "its signature does NOT verify",
			"unsupported": "its signature algorithm could not be verified", "no-issuer": "its signature could not be checked (issuer not available)"}[o.Signature]
		if o.Signature == "valid" && o.Delegated {
			sig = "signed by a delegated responder the issuer authorised"
		}
		ocspLine = "Stapled OCSP response: " + o.Status
		if o.Status == "revoked" {
			ocspLine += " since " + day(o.RevokedAt)
		}
		if !o.NextUpdate.IsZero() {
			ocspLine += ", valid until " + stamp(o.NextUpdate)
		}
		ocspLine += "; " + sig + "."
	}
	sct := "No Certificate Transparency proof; not required for a privately trusted certificate."
	if len(v.SCTs) > 0 {
		srcs := map[string]bool{}
		var list []string
		for _, s := range v.SCTs {
			if !srcs[s.Source] {
				srcs[s.Source] = true
				list = append(list, s.Source)
			}
		}
		sct = fmt.Sprintf("%s (%s).", plural(len(v.SCTs), "Certificate Transparency proof"), strings.Join(list, ", "))
	} else if v.Public {
		sct = "No Certificate Transparency proof was found in any of the three places it can travel."
	}
	return sectionContent{facts: []string{ocspLine, sct}, detail: func() {
		x.h2("Revocation sources the certificate names")
		var rows [][]pdf.Cell
		for _, u := range v.OCSPURLs {
			rows = append(rows, []pdf.Cell{chipCell("OCSP", toneInfo), monoCell(u), txt("not looked up", pdf.Regular, muted)})
		}
		for _, u := range v.CRLURLs {
			rows = append(rows, []pdf.Cell{chipCell("CRL", toneInfo), monoCell(u), txt("not looked up", pdf.Regular, muted)})
		}
		if len(rows) == 0 {
			x.p(soft("None."))
		}
		x.table([]pdf.Col{{Title: "Kind", W: 0.7}, {Title: "Address", W: 4}, {Title: "", W: 1.1}}, rows)
		x.f.Add(para(6, small("This scan contacts only the endpoint, so the CA's OCSP responder and CRL were not queried.")))
		if len(v.SCTs) > 0 {
			x.h2("Certificate Transparency")
			var sr [][]pdf.Cell
			for _, s := range v.SCTs {
				log := s.LogName
				if log == "" {
					log = "unknown log " + s.LogID
				} else if s.Operator != "" {
					log += " (" + s.Operator + ")"
				}
				sr = append(sr, []pdf.Cell{txt(s.Source, pdf.Regular, ink), txt(log, pdf.Regular, ink), txt(stamp(s.Timestamp), pdf.Regular, text2)})
			}
			x.table([]pdf.Col{{Title: "Source", W: 1}, {Title: "Log", W: 3}, {Title: "Timestamp", W: 1.6}}, sr)
			x.f.Add(para(6, small("SCT signatures are not verified in this version; the log is named from the bundled CT log list.")))
		}
		if o != nil {
			x.h2("Stapled OCSP response")
			x.kv([][2]string{{"Response", o.Response}, {"Status", o.Status}, {"Produced", stamp(o.ProducedAt)}, {"This update", stamp(o.ThisUpdate)},
				{"Next update", stamp(o.NextUpdate)}, {"Responder", o.Responder}, {"Signature", o.Signature}, {"For this certificate", map[bool]string{true: "yes", false: "no"}[o.ForThisCert]}})
		}
	}}
}

// ---- protocols, suites ---------------------------------------------------------------------------

func legacyVersion(v string) bool {
	return v == "SSLv2" || v == "SSLv3" || v == "TLSv1.0" || v == "TLSv1.1"
}

func (x *endpoint) protocols() sectionContent {
	var on, old []string
	for _, p := range x.rep.Protocols {
		if p.Supported {
			on = append(on, p.Version)
			if legacyVersion(p.Version) {
				old = append(old, p.Version)
			}
		}
	}
	facts := []string{"No protocol version was accepted."}
	if len(on) > 0 {
		facts = []string{"Accepts " + strings.Join(on, ", ") + "."}
		if len(old) > 0 {
			verb := "are"
			if len(old) == 1 {
				verb = "is"
			}
			facts = append(facts, strings.Join(old, " and ")+" "+verb+" deprecated.")
		} else {
			facts = append(facts, "No deprecated version is accepted.")
		}
	}
	if n := x.rep.Negotiated; n != nil && n.Version != "" {
		facts = append(facts, "A current client negotiates "+n.Version+".")
	}
	return sectionContent{facts: facts, detail: func() {
		var rows [][]pdf.Cell
		for _, p := range x.rep.Protocols {
			c := chipCell("NO", toneInfo)
			switch {
			case p.Evidence == "inconclusive":
				c = chipCell("UNKNOWN", toneWarn)
			case p.Supported && legacyVersion(p.Version):
				c = chipCell("YES, DEPRECATED", toneBad)
			case p.Supported:
				c = chipCell("YES", toneGood)
			}
			rows = append(rows, []pdf.Cell{txt(p.Version, pdf.Bold, ink), c, txt(string(p.Evidence), pdf.Regular, text2), txt(p.Detail, pdf.Regular, muted)})
		}
		x.table([]pdf.Col{{Title: "Version", W: 1}, {Title: "Accepted", W: 1.4}, {Title: "Evidence", W: 1.1}, {Title: "Detail", W: 2.6}}, rows)
	}}
}

func suiteFlags(s tlsprobe.SuiteResult) (flags []string, bad bool) {
	add := func(f string, serious bool) {
		flags = append(flags, f)
		bad = bad || serious
	}
	if s.Cipher == "NULL" {
		add("no encryption", true)
	}
	if s.Export {
		add("export", true)
	}
	if s.Anon {
		add("anonymous", true)
	}
	if s.Cipher == "RC4" {
		add("RC4", true)
	}
	if s.BlockBits == 64 && !s.Export {
		add("64-bit block", true)
	}
	if s.Kx != "" && !s.Ephemeral && (s.Kx == "RSA" || s.Kx == "DH" || s.Kx == "ECDH") {
		add("no forward secrecy", true)
	}
	if s.Mode == "CBC" && s.Version != "TLSv1.3" {
		add("CBC", false)
	}
	if s.AEAD {
		add("AEAD", false)
	}
	return flags, bad
}

func (x *endpoint) suites() sectionContent {
	suites := x.rep.Suites
	aead, cbc, weak := 0, 0, 0
	for _, s := range suites {
		if s.AEAD {
			aead++
		}
		if s.Mode == "CBC" && s.Version != "TLSv1.3" {
			cbc++
		}
		if _, bad := suiteFlags(s); bad || s.IANARecommended == "D" {
			weak++
		}
	}
	first := fmt.Sprintf("%s accepted: %d AEAD", plural(len(suites), "suite"), aead)
	if cbc > 0 {
		first += fmt.Sprintf(", %d CBC", cbc)
	}
	if weak > 0 {
		first += fmt.Sprintf(", %d with a weakness", weak)
	}
	facts := []string{first + "."}
	var order []string
	words := map[string]string{"server": "server decides", "client": "client decides", "mixed": "depends on the offer", "unknown": "not determined"}
	for _, p := range x.rep.Preference {
		if p.Subject == "suites" {
			order = append(order, p.Version+": "+words[p.Order])
		}
	}
	if len(order) > 0 {
		facts = append(facts, "Order: "+strings.Join(order, "; ")+".")
	}
	return sectionContent{facts: facts, detail: func() {
		var rows [][]pdf.Cell
		for _, s := range suites {
			flags, bad := suiteFlags(s)
			fc := toneInfo.fg
			if bad {
				fc = toneBad.fg
			}
			cipher := fmt.Sprintf("%s-%d %s", s.Cipher, s.KeyBits, s.Mode)
			if s.Cipher == "NULL" {
				cipher = "none"
			}
			kx := s.Kx
			if kx == "" {
				kx = "TLS 1.3"
			}
			iana := map[string]string{"Y": "Recommended", "N": "Not recommended", "D": "Discouraged"}[s.IANARecommended]
			it := toneInfo
			switch s.IANARecommended {
			case "Y":
				it = toneGood
			case "D":
				it = toneBad
			}
			rank := "-"
			if s.Rank > 0 {
				rank = fmt.Sprint(s.Rank)
			}
			rows = append(rows, []pdf.Cell{txt(s.Version, pdf.Regular, text2), txt(rank, pdf.Regular, text2), monoCell(s.Name), txt(cipher, pdf.Regular, ink),
				txt(kx, pdf.Regular, ink), txt(strings.Join(flags, ", "), pdf.Bold, fc), txt(iana, pdf.Bold, it.fg)})
		}
		x.table([]pdf.Col{{Title: "Version", W: 0.85}, {Title: "#", W: 0.3}, {Title: "Suite", W: 3.1}, {Title: "Cipher", W: 1.3}, {Title: "Key exchange", W: 0.9},
			{Title: "Flags", W: 1.3}, {Title: "IANA", W: 1}}, rows)
	}}
}

// ---- key exchange --------------------------------------------------------------------------------

func (x *endpoint) keyExchange() sectionContent {
	r := x.ev.Readiness
	var pq []string
	for _, g := range x.rep.Groups {
		if g.PQ && !g.Obsolete && !contains(pq, g.Name) {
			pq = append(pq, g.Name)
		}
	}
	facts := []string{"No post-quantum key exchange is accepted."}
	if len(pq) > 0 {
		facts = []string{"Post-quantum hybrid groups accepted: " + strings.Join(pq, ", ") + "."}
	}
	if n := x.rep.Negotiated; n != nil && n.Group != "" {
		kind := " (classical)"
		if n.PQ {
			kind = " (post-quantum hybrid)"
		}
		facts = append(facts, "A current client negotiates "+n.Group+kind+".")
	}
	if r.HNDLExposed {
		facts = append(facts, "Traffic recorded today could be decrypted by a future quantum computer (harvest now, decrypt later).")
	}
	if dh := x.rep.DH; dh != nil {
		if x.ev.DHGroup != nil {
			facts = append(facts, fmt.Sprintf("Diffie-Hellman uses %s (%s), %d bits.", x.ev.DHGroup.Name, x.ev.DHGroup.Source, dh.PrimeBits))
		} else {
			facts = append(facts, fmt.Sprintf("Diffie-Hellman uses a %d-bit prime that is not a published group.", dh.PrimeBits))
		}
	}
	if f := signatureFact(x.rep.Signatures); f != "" {
		facts = append(facts, f)
	}
	return sectionContent{facts: facts, detail: func() {
		x.levelScale(r.Level)
		x.h2("Readiness, dimension by dimension")
		var rows [][]pdf.Cell
		for _, d := range []struct {
			name string
			d    eval.Dimension
		}{{"Key establishment", r.KeyEstablishment}, {"Authentication", r.Authentication}, {"Symmetric strength", r.Symmetric}} {
			rows = append(rows, []pdf.Cell{txt(d.name, pdf.Bold, ink), txt(d.d.Status, pdf.Bold, text2), txt(d.d.Detail, pdf.Regular, ink)})
		}
		x.table([]pdf.Col{{Title: "Dimension", W: 1.2}, {Title: "Status", W: 1.1}, {Title: "What was seen", W: 4}}, rows)
		if len(r.NextSteps) > 0 {
			x.h2("What to do next")
			for i, s := range r.NextSteps {
				x.f.Add(pdf.Para{Spans: []pdf.Span{body(s)}, Indent: 16, Bullet: fmt.Sprintf("%d.", i+1), After: 2.5})
			}
			x.gap(4)
		}
		if len(x.rep.Groups) > 0 {
			x.h2("Key-exchange groups accepted")
			var gr [][]pdf.Cell
			for _, g := range x.rep.Groups {
				pqc := txt("classical", pdf.Regular, muted)
				if g.PQ {
					label, t := "POST-QUANTUM", toneGood
					if g.Hybrid {
						label = "HYBRID POST-QUANTUM"
					}
					if g.Obsolete {
						label, t = "OBSOLETE DRAFT", toneWarn
					}
					pqc = chipCell(label, t)
				}
				rank := "-"
				if g.Rank > 0 {
					rank = fmt.Sprint(g.Rank)
				}
				iana := map[string]string{"Y": "Recommended", "N": "Not recommended", "D": "Discouraged"}[g.IANARecommended]
				gr = append(gr, []pdf.Cell{txt(g.Version, pdf.Regular, text2), txt(rank, pdf.Regular, text2), monoCell(g.Name), pqc, txt(iana, pdf.Regular, text2)})
			}
			x.table([]pdf.Col{{Title: "Version", W: 0.9}, {Title: "#", W: 0.35}, {Title: "Group", W: 2.4}, {Title: "Post-quantum", W: 1.9}, {Title: "IANA", W: 1.2}}, gr)
		}
		x.signatureSchemes()
		if len(r.Citations) > 0 {
			sp := []pdf.Span{span("Sources for the readiness assessment: ", pdf.Bold, smallSize, muted)}
			for i, c := range r.Citations {
				if i > 0 {
					sp = append(sp, small("  ·  "))
				}
				sp = append(sp, linkTo(c.Title, c.URL))
			}
			x.f.Add(pdf.Para{Spans: sp, After: 6})
		}
	}}
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// levelScale draws the readiness ladder L0..L4 with the endpoint's level marked.
func (x *endpoint) levelScale(level int) {
	x.f.Add(pdf.Custom{H: 44, F: func(p *pdf.Page, x0, y, w float64) {
		const gapW = 4.0
		bw := (w - 4*gapW) / 5
		for l := 0; l <= 4; l++ {
			bx := x0 + float64(l)*(bw+gapW)
			t := levelTone(l)
			if l == level {
				p.RoundRect(bx, y, bw, 22, 4, t.fg, 0, pdf.Color{})
				p.Text(bx+8, y+14.5, pdf.Bold, 9, white, fmt.Sprintf("L%d", l))
				p.Text(bx+26, y+14.5, pdf.Bold, 7.5, white, levelNames[l])
			} else {
				p.RoundRect(bx, y, bw, 22, 4, t.bg, 0, pdf.Color{})
				p.Text(bx+8, y+14.5, pdf.Bold, 9, t.fg, fmt.Sprintf("L%d", l))
				p.Text(bx+26, y+14.5, pdf.Regular, 7.5, text2, levelNames[l])
			}
		}
		p.Text(x0, y+36, pdf.Regular, 7.2, muted, "The level scale is this product's own; each fact cites its standard.")
	}})
}

// ---- features, HTTP, vulnerabilities ---------------------------------------------------------------

func (x *endpoint) features() sectionContent {
	f := x.rep.Features
	said := func(v *bool, yes, no string) string {
		if v == nil {
			return ""
		}
		if *v {
			return yes
		}
		return no
	}
	facts := []string{
		said(f.SecureRenegotiation, "Secure renegotiation is advertised.", "Secure renegotiation is NOT advertised."),
		said(f.Compression, "TLS compression is accepted (CRIME).", "TLS compression is refused."),
		said(f.FallbackSCSV, "Downgrade protection (TLS_FALLBACK_SCSV) is enforced.", "Downgrade protection (TLS_FALLBACK_SCSV) is not enforced."),
		said(f.SessionTickets, "Session tickets are offered.", "Session tickets are not offered."),
		said(f.ClientCertRequested, "The server asks for a client certificate (mutual TLS).", ""),
	}
	return sectionContent{facts: facts, detail: func() {
		var rows [][]pdf.Cell
		row := func(label string, v *bool, yes string, yt tone, no string, nt tone) {
			if v == nil {
				return
			}
			c := chipCell(no, nt)
			if *v {
				c = chipCell(yes, yt)
			}
			rows = append(rows, []pdf.Cell{txt(label, pdf.Regular, ink), c})
		}
		row("Secure renegotiation (RFC 5746)", f.SecureRenegotiation, "ADVERTISED", toneGood, "NOT ADVERTISED", toneWarn)
		row("Extended master secret (RFC 7627)", f.ExtendedMasterSecret, "SUPPORTED", toneGood, "NOT OFFERED", toneInfo)
		row("Encrypt-then-MAC (RFC 7366)", f.EncryptThenMAC, "SUPPORTED", toneGood, "NOT OFFERED", toneInfo)
		row("Session tickets", f.SessionTickets, "OFFERED", toneInfo, "NOT OFFERED", toneInfo)
		row("OCSP stapling (status_request)", f.OCSPStapling, "SUPPORTED", toneGood, "NOT OFFERED", toneInfo)
		row("TLS compression", f.Compression, "ACCEPTED", toneBad, "REFUSED", toneGood)
		row("TLS_FALLBACK_SCSV (RFC 7507)", f.FallbackSCSV, "ENFORCED", toneGood, "NOT ENFORCED", toneWarn)
		row("Client certificate requested", f.ClientCertRequested, "REQUESTED", toneInfo, "NOT REQUESTED", toneInfo)
		x.table([]pdf.Col{{Title: "Feature", W: 3}, {Title: "Result", W: 1.4}}, rows)
	}}
}

func (x *endpoint) http() sectionContent {
	hd := x.rep.HSTSHeader
	if hd == nil {
		switch {
		case x.rep.HSTS != nil && *x.rep.HSTS:
			return sectionContent{facts: []string{"A Strict-Transport-Security header was sent (details were not collected by the version that ran this scan)."}}
		case x.rep.HSTS != nil:
			return sectionContent{facts: []string{"The HTTP response had no Strict-Transport-Security header."}}
		}
		return sectionContent{}
	}
	if len(hd.Values) == 0 {
		return sectionContent{facts: []string{"The HTTP response had no Strict-Transport-Security header, so browsers may still use plain HTTP."}}
	}
	ma := "max-age could not be read."
	if hd.MaxAge != nil {
		if *hd.MaxAge == 0 {
			ma = "max-age is 0: the header switches HSTS off."
		} else {
			ma = fmt.Sprintf("Browsers remember to use HTTPS for %d seconds (%s).", *hd.MaxAge, humanSeconds(*hd.MaxAge))
		}
	}
	sub := "It does not cover subdomains."
	if hd.IncludeSubDomains {
		sub = "It covers every subdomain (includeSubDomains)."
	}
	pre := ""
	if hd.Preload {
		pre = "It asks to be preloaded into browsers (preload)."
	}
	probs := ""
	if len(hd.Problems) > 0 {
		probs = "Problems: " + strings.Join(hd.Problems, "; ") + "."
	}
	return sectionContent{facts: []string{ma, sub, pre, probs}, detail: func() {
		x.f.Add(para(3, span("Header values as received:", pdf.Bold, smallSize, text2)))
		for _, v := range hd.Values {
			x.f.Add(pdf.Para{Spans: []pdf.Span{mono(v)}, Indent: 12, After: 2})
		}
		x.gap(6)
	}}
}

func humanSeconds(s int64) string {
	const dayS = 86400
	switch {
	case s >= 365*dayS:
		return fmt.Sprintf("%.1f years", float64(s)/(365*dayS))
	case s >= dayS:
		return plural(int(s/dayS), "day")
	case s >= 3600:
		return plural(int(s/3600), "hour")
	case s >= 60:
		return plural(int(s/60), "minute")
	}
	return plural(int(s), "second")
}

func (x *endpoint) vulnerabilities() sectionContent {
	list := x.ev.Vulnerabilities
	if len(list) == 0 {
		return sectionContent{}
	}
	var exposed []string
	for _, a := range list {
		if a.Status == "exposed" {
			exposed = append(exposed, a.Name)
		}
	}
	fact := "Not exposed to any attack this scan can infer."
	if len(exposed) > 0 {
		fact = "Exposed to " + strings.Join(exposed, ", ") + "."
	}
	return sectionContent{facts: []string{fact}, detail: func() {
		sorted := append([]eval.AttackView{}, list...)
		rank := map[string]int{"exposed": 0, "not-exposed": 1, "not-tested": 2}
		sort.SliceStable(sorted, func(i, j int) bool { return rank[sorted[i].Status] < rank[sorted[j].Status] })
		var rows [][]pdf.Cell
		for _, a := range sorted {
			c := chipCell("NOT EXPOSED", toneGood)
			switch a.Status {
			case "exposed":
				c = chipCell("EXPOSED", toneBad)
			case "not-tested":
				c = chipCell("NOT TESTED BY DESIGN", toneInfo)
			}
			rows = append(rows, []pdf.Cell{txt(a.Name, pdf.Bold, ink), c, txt(a.Why, pdf.Regular, text2)})
		}
		x.table([]pdf.Col{{Title: "Attack", W: 1.3}, {Title: "Status", W: 1.6}, {Title: "Why", W: 4}}, rows)
	}}
}

// ---- about -----------------------------------------------------------------------------------

var stageTitles = []struct{ id, title string }{
	{"protocols", "Protocols"}, {"suites", "Cipher suites"}, {"key-exchange", "Key exchange"}, {"signatures", "Signature schemes"}, {"features", "Features"},
	{"certificates", "Certificates"}, {"revocation", "Revocation & transparency"}, {"http", "HTTP"},
}

// scanMeta is what the about page says of either protocol's scan.
type scanMeta struct {
	address    string
	addresses  []string
	started    time.Time
	durationMS int64
	conns      int
	schema     string
	stages     []tlsprobe.Stage
	notes      []string
	titles     []struct{ id, title string }
	hygiene    string
}

func (x *endpoint) meta() scanMeta {
	if r := x.ssh; r != nil {
		return scanMeta{r.Address, r.Addresses, r.Started, r.DurationMS, r.Connections, r.SchemaVersion, r.Stages, r.Notes, sshStageTitles, "SSH hygiene"}
	}
	r := x.rep
	schema := r.SchemaVersion
	if schema == "" {
		schema = "tls-report/1"
	}
	return scanMeta{r.Address, r.Addresses, r.Started, r.DurationMS, r.Connections, schema, r.Stages, r.Notes, stageTitles, "TLS hygiene"}
}

func (x *endpoint) about() {
	m, ev := x.meta(), x.ev
	x.h1("About this report")
	addr := m.address
	if len(m.addresses) > 1 {
		addr += fmt.Sprintf(" (1 of %d: %s)", len(m.addresses), strings.Join(m.addresses, ", "))
	}
	schema := m.schema
	x.kv([][2]string{
		{"Endpoint", x.in.Name + " (" + x.in.Address + ")"},
		{"Scanned", stamp(m.started)},
		{"Duration", fmt.Sprintf("%s, %s", duration(m.durationMS), plural(m.conns, "connection"))},
		{"Address probed", addr},
		{"Report format", schema},
		{"Evaluation", strings.TrimSpace(ev.Version + ", " + stamp(ev.EvaluatedAt))},
		{"Generated", stamp(x.in.Generated) + " by CipherHorizon " + x.in.Version},
	})

	g := ev.Hygiene
	x.h2("How the " + m.hygiene + " score was worked out")
	if g.Score >= 0 {
		x.p(body(fmt.Sprintf("Score %d of 100, band %s. ", g.Score, g.Band)), soft("Each finding takes points off 100; the weights are this product's own choice, not a standard."))
	} else {
		x.p(body("Not rated: "), soft(strings.Join(g.NotMeasured, "; ")))
	}
	if g.Ceiling != nil {
		x.callout(toneWarn, bold(fmt.Sprintf("Capped at %d. ", g.Ceiling.Score)), body(g.Ceiling.Reason))
	}
	if len(g.Deductions) > 0 {
		var rows [][]pdf.Cell
		for _, d := range g.Deductions {
			t := sevTone(d.Severity)
			rows = append(rows, []pdf.Cell{txt(d.Title, pdf.Regular, ink), chipCell(strings.ToUpper(string(d.Severity)), t), txt(fmt.Sprintf("-%d", d.Points), pdf.Bold, t.fg)})
		}
		x.table([]pdf.Col{{Title: "Finding", W: 4}, {Title: "Severity", W: 1}, {Title: "Points", W: 0.6, Align: 1}}, rows)
	}
	if g.Score >= 0 && len(g.NotMeasured) > 0 {
		x.f.Add(para(5, small("Not measured: "+strings.Join(g.NotMeasured, "; ")+".")))
	}
	if g.Methodology != "" {
		x.f.Add(para(6, small(g.Methodology)))
	}

	stages := map[string]tlsprobe.Stage{}
	for _, s := range m.stages {
		stages[s.Name] = s
	}
	if len(stages) > 0 {
		x.h2("How we tested")
		var rows [][]pdf.Cell
		for _, st := range m.titles {
			s, ok := stages[st.id]
			if !ok {
				continue
			}
			what := strings.Join(s.Probes, "; ")
			if s.Outcome == "skipped" {
				what = "not run: " + firstNonEmpty(s.Reason, s.ReasonCode)
			}
			if len(s.Inconclusive) > 0 {
				what += " Inconclusive: " + strings.Join(s.Inconclusive, "; ") + "."
			}
			rows = append(rows, []pdf.Cell{txt(st.title, pdf.Bold, ink), txt(s.Outcome, pdf.Regular, text2), txt(what, pdf.Regular, ink), txt(fmt.Sprint(s.Connections), pdf.Regular, text2)})
		}
		x.table([]pdf.Col{{Title: "Stage", W: 1.3}, {Title: "Outcome", W: 0.8}, {Title: "What was sent", W: 4.2}, {Title: "Conn.", W: 0.55, Align: 1}}, rows)
	}
	if len(ev.ReferenceData) > 0 {
		x.h2("Reference data")
		var items []string
		for _, r := range ev.ReferenceData {
			s := fmt.Sprintf("%s: %d entries, retrieved %s", r.Name, r.Count, r.Retrieved)
			if r.Stale {
				s += fmt.Sprintf(" (%d days old)", r.AgeDays)
			}
			items = append(items, s+".")
		}
		x.bullets(items)
	}
	if len(m.notes) > 0 {
		x.h2("Notes on the scan")
		x.bullets(m.notes)
	}
	x.f.Add(para(0, small("Findings are inferred from what the server accepted; no attack was attempted. Readiness levels and "+m.hygiene+" are this product's own scales; every finding cites the standard it rests on.")))
}

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}

// signatureFact says, in one sentence, which TLS 1.3 signature schemes the server holds keys for
// (PRD-008 REQ-PQS-6); empty when the stage did not run.
func signatureFact(s *tlsprobe.SignatureResult) string {
	if s == nil {
		return ""
	}
	if !s.Conclusive() {
		return "Which signature schemes the server can use could not be told: it answers whatever is offered."
	}
	var pq, classical []string
	for _, a := range s.Accepted() {
		switch {
		case a.PQ:
			pq = append(pq, a.Algorithm)
		case !contains(classical, a.Algorithm):
			classical = append(classical, a.Algorithm)
		}
	}
	switch {
	case len(pq) > 0:
		return "The server can authenticate with " + strings.Join(pq, ", ") + " (post-quantum) as well as " + strings.Join(classical, ", ") + "."
	case len(classical) > 0:
		return "The server authenticates with " + strings.Join(classical, ", ") + "; no post-quantum signature scheme is accepted."
	}
	return ""
}

// signatureSchemes is the per-scheme table of the signature stage.
func (x *endpoint) signatureSchemes() {
	s := x.rep.Signatures
	if s == nil {
		return
	}
	x.h2("Signature schemes the server can authenticate with (TLS 1.3)")
	if !s.Conclusive() {
		x.f.Add(pdf.Para{Spans: []pdf.Span{body(signatureFact(s))}, After: 4})
		return
	}
	var rows [][]pdf.Cell
	for _, sc := range s.Schemes {
		key := sc.Algorithm
		if sc.Detail != "" {
			key += " (" + sc.Detail + ")"
		}
		st := txt("Not accepted", pdf.Regular, muted)
		switch sc.Result {
		case tlsprobe.SigAccepted:
			st = chipCell("ACCEPTED", toneGood)
			if sc.PQ {
				st = chipCell("ACCEPTED · POST-QUANTUM", toneGood)
			}
		case tlsprobe.SigInconclusive:
			st = chipCell("NOT DETERMINED", toneWarn)
		}
		rows = append(rows, []pdf.Cell{monoCell(sc.Name), txt(key, pdf.Regular, text2), st})
	}
	x.table([]pdf.Col{{Title: "Scheme", W: 2.4}, {Title: "Key", W: 2}, {Title: "Status", W: 2.2}}, rows)
	x.f.Add(pdf.Para{Spans: []pdf.Span{small("Tested by offering one scheme per handshake; a server answers only for keys it holds. A control scheme no key can match was refused.")}, After: 4})
}
