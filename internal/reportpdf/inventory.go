package reportpdf

import (
	"fmt"
	"strings"
	"time"

	"github.com/example/cipherhorizon/internal/pdf"
)

// InvItem is one inventory row: an algorithm, key, protocol or software component.
type InvItem struct {
	Name, Kind, Detail, Purpose, Quantum string
	Endpoints, Machines, Imports         int
	Places                               []string // "name (endpoint)" ...
	LastSeen                             time.Time
	Legacy                               bool
}

// InvPurpose counts algorithms of one purpose by post-quantum status.
type InvPurpose struct {
	Purpose                   string
	Vulnerable, Safe, Unknown int
}

// InvCert is one end-entity certificate.
type InvCert struct {
	Name, Issuer, Key, NotAfter string
	DaysLeft                    *int
	Places                      int
}

// InvSource is an endpoint scan, machine inventory or imported CBOM.
type InvSource struct {
	Label, Kind string
	When        time.Time
	Items       int
}

// InventoryInput is everything the inventory report shows.
type InventoryInput struct {
	Version    string
	Generated  time.Time
	Totals     map[string]int // algorithm, key, protocol, software, certificates, endpoints, machines, imports
	Quantum    map[string]int // vulnerable, safe, unknown (algorithms and keys)
	Replace    []InvItem
	ByPurpose  []InvPurpose
	Algorithms []InvItem
	Keys       []InvItem
	Protocols  []InvItem
	Software   []InvItem
	CertCounts struct{ Total, Expired, Within30, Within90, Later int }
	Certs      []InvCert
	Sources    []InvSource
}

func quantumCell(q string) pdf.Cell {
	switch q {
	case "quantum-vulnerable":
		return chipCell("QUANTUM-VULNERABLE", toneBad)
	case "quantum-safe":
		return chipCell("QUANTUM-SAFE", toneGood)
	case "not-applicable":
		return txt("-", pdf.Regular, muted)
	}
	return chipCell("NOT CLASSIFIED", toneInfo)
}

// shownName names a certificate's key by the certificate's common name.
func shownName(name string) string {
	if strings.HasSuffix(name, " public key") {
		return cn(strings.TrimSuffix(name, " public key"))
	}
	return name
}

func seenOn(it InvItem) string {
	var parts []string
	if it.Endpoints > 0 {
		parts = append(parts, plural(it.Endpoints, "endpoint"))
	}
	if it.Machines > 0 {
		parts = append(parts, plural(it.Machines, "machine"))
	}
	if it.Imports > 0 {
		parts = append(parts, plural(it.Imports, "imported CBOM"))
	}
	return strings.Join(parts, ", ")
}

func ago(now, t time.Time) string {
	if t.IsZero() {
		return ""
	}
	d := now.Sub(t)
	switch {
	case d < time.Hour:
		return "within the hour"
	case d < 48*time.Hour:
		return plural(int(d.Hours()), "hour") + " ago"
	}
	return plural(int(d.Hours()/24), "day") + " ago"
}

// Inventory renders the inventory report as a PDF.
func Inventory(in InventoryInput) ([]byte, error) {
	if in.Generated.IsZero() {
		in.Generated = time.Now().UTC()
	}
	t := in.Totals
	lines := []string{
		fmt.Sprintf("%s   ·   %s   ·   %s", plural(t["endpoints"], "endpoint"), plural(t["machines"], "machine"), plural(t["imports"], "imported CBOM")),
		"generated " + stamp(in.Generated),
	}
	x := newDoc("Cryptographic inventory", "Every algorithm, key, certificate and protocol CipherHorizon has seen", in.Generated,
		cover{kicker: "CRYPTOGRAPHIC INVENTORY", title: "Cryptographic inventory", lines: lines},
		"Cryptographic inventory", fmt.Sprintf("CipherHorizon %s  ·  cryptographic inventory  ·  generated %s", in.Version, stamp(in.Generated)))

	q := in.Quantum
	classified := q["vulnerable"] + q["safe"] + q["unknown"]
	cc := in.CertCounts
	certT := toneGood
	if cc.Expired > 0 {
		certT = toneBad
	} else if cc.Within30 > 0 {
		certT = toneWarn
	}
	vulnT := toneGood
	if q["vulnerable"] > 0 {
		vulnT = toneBad
	}
	x.tiles([]tile{
		{fmt.Sprint(t["algorithm"]), "Algorithms", fmt.Sprintf("in use across %s", plural(t["endpoints"]+t["machines"]+t["imports"], "source")), toneL4},
		{fmt.Sprint(q["vulnerable"]), "Quantum-vulnerable", fmt.Sprintf("of %d algorithms and keys", classified), vulnT},
		{fmt.Sprint(cc.Total), "Certificates", fmt.Sprintf("%d expired, %d within 30 days", cc.Expired, cc.Within30), certT},
		{fmt.Sprint(t["protocol"]), "Protocol versions", fmt.Sprintf("%d keys, %d software components", t["key"], t["software"]), toneLow},
	})

	x.h1("Post-quantum status")
	if classified > 0 {
		x.p(body(fmt.Sprintf("%d of %d algorithms and keys are quantum-vulnerable: a large quantum computer could break them. ", q["vulnerable"], classified)),
			soft("Symmetric ciphers and hashes with enough key or output length stay safe; public-key algorithms (RSA, elliptic curves, Diffie-Hellman) do not."))
		x.stackBar([]barPart{{q["vulnerable"], "Quantum-vulnerable", toneBad}, {q["safe"], "Quantum-safe", toneGood}, {q["unknown"], "Not classified", toneInfo}})
	} else {
		x.p(soft("Nothing classified yet. Scan an endpoint or upload a machine inventory."))
	}
	if len(in.ByPurpose) > 0 {
		x.h2("Algorithms by purpose")
		x.purposeBars(in.ByPurpose)
	}
	if len(in.Replace) > 0 {
		x.h2("Replace first")
		x.f.Add(para(5, soft("Quantum-vulnerable algorithms and keys, the most widely used first.")))
		var rows [][]pdf.Cell
		for i, it := range in.Replace {
			what := it.Purpose
			if what == "" {
				what = it.Kind
			}
			if what == "key" {
				what = "certificate key"
			}
			rows = append(rows, []pdf.Cell{txt(fmt.Sprint(i+1), pdf.Bold, text2), txt(shownName(it.Name), pdf.Bold, ink), txt(what, pdf.Regular, text2),
				txt(seenOn(it), pdf.Regular, ink), txt(strings.Join(it.Places, ", "), pdf.Regular, muted)})
		}
		x.table([]pdf.Col{{Title: "#", W: 0.3}, {Title: "Name", W: 2.2}, {Title: "Purpose", W: 1.4}, {Title: "Seen on", W: 1.3}, {Title: "Where", W: 2.4}}, rows)
	}

	if len(in.Protocols) > 0 {
		x.h1("Protocol versions")
		var rows [][]pdf.Cell
		for _, it := range in.Protocols {
			st := chipCell("CURRENT", toneGood)
			if it.Legacy {
				st = chipCell("DEPRECATED", toneBad)
			}
			rows = append(rows, []pdf.Cell{txt(it.Name, pdf.Bold, ink), st, txt(seenOn(it), pdf.Regular, ink), txt(strings.Join(it.Places, ", "), pdf.Regular, muted)})
		}
		x.table([]pdf.Col{{Title: "Version", W: 1}, {Title: "Status", W: 1.1}, {Title: "Seen on", W: 1.4}, {Title: "Where", W: 3.2}}, rows)
	}

	x.h1("Certificates")
	if cc.Total == 0 {
		x.p(soft("No certificates yet."))
	} else {
		x.stackBar([]barPart{{cc.Expired, "Expired", toneBad}, {cc.Within30, "Within 30 days", toneHigh}, {cc.Within90, "Within 90 days", toneWarn}, {cc.Later, "Later", toneGood}})
		var rows [][]pdf.Cell
		for _, c := range in.Certs {
			left := txt("-", pdf.Regular, muted)
			if c.DaysLeft != nil {
				d := *c.DaysLeft
				tt := toneGood
				label := fmt.Sprintf("%d DAYS", d)
				switch {
				case d < 0:
					tt, label = toneBad, "EXPIRED"
				case d <= 30:
					tt = toneHigh
				case d <= 90:
					tt = toneWarn
				}
				left = chipCell(label, tt)
			}
			rows = append(rows, []pdf.Cell{txt(cn(c.Name), pdf.Bold, ink), txt(cn(c.Issuer), pdf.Regular, text2), txt(c.Key, pdf.Regular, ink), txt(dayOf(c.NotAfter), pdf.Regular, ink), left})
		}
		x.table([]pdf.Col{{Title: "Certificate", W: 2.6}, {Title: "Issuer", W: 2}, {Title: "Key", W: 1.3}, {Title: "Expires", W: 1}, {Title: "Left", W: 0.9}}, rows)
	}

	x.itemTable("Algorithms", in.Algorithms, true)
	x.itemTable("Keys", in.Keys, true)
	x.itemTable("Software", in.Software, false)

	x.h1("Sources")
	if len(in.Sources) == 0 {
		x.p(soft("No sources yet."))
	} else {
		var rows [][]pdf.Cell
		for _, s := range in.Sources {
			kind := map[string]string{"endpoint": "Endpoint scan", "machine": "Machine inventory", "import": "Imported CBOM"}[s.Kind]
			rows = append(rows, []pdf.Cell{txt(s.Label, pdf.Bold, ink), txt(kind, pdf.Regular, text2), txt(stamp(s.When)+"  ("+ago(in.Generated, s.When)+")", pdf.Regular, ink), txt(fmt.Sprint(s.Items), pdf.Regular, text2)})
		}
		x.table([]pdf.Col{{Title: "Source", W: 2.2}, {Title: "Kind", W: 1.4}, {Title: "Last reported", W: 2.4}, {Title: "Items", W: 0.6, Align: 1}}, rows)
	}
	x.h2("How this inventory is made")
	x.f.Add(para(4, soft("It is the merge of the latest CycloneDX CBOM of every endpoint (built from its latest completed scan), the latest uploaded CBOM of every machine, and the CBOMs imported from other tools. Items are merged by reference; each lists where it was seen. Post-quantum status uses the cited classification carried in the CBOM. Imported items are leads from other tools, not verified by this product.")))
	x.f.Add(para(0, small("Download the same inventory as a machine-readable CycloneDX CBOM from the Inventory page.")))
	return x.finish()
}

func dayOf(s string) string {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return s
	}
	return day(t)
}

func (x *doc) itemTable(title string, items []InvItem, quantum bool) {
	if len(items) == 0 {
		return
	}
	x.h1(fmt.Sprintf("%s (%d)", title, len(items)))
	var rows [][]pdf.Cell
	for _, it := range items {
		r := []pdf.Cell{txt(shownName(it.Name), pdf.Bold, ink), txt(humanDetail(it.Detail), pdf.Regular, text2)}
		if quantum {
			r = append(r, quantumCell(it.Quantum))
		}
		r = append(r, txt(seenOn(it), pdf.Regular, ink), txt(day(it.LastSeen), pdf.Regular, muted))
		rows = append(rows, r)
	}
	cols := []pdf.Col{{Title: "Name", W: 2.4}, {Title: "Kind", W: 1.6}}
	if quantum {
		cols = append(cols, pdf.Col{Title: "Post-quantum", W: 1.75})
	}
	cols = append(cols, pdf.Col{Title: "Seen on", W: 1.4}, pdf.Col{Title: "Last seen", W: 0.9})
	x.table(cols, rows)
}

var primitiveWords = map[string]string{
	"ae": "authenticated encryption", "block-cipher": "block cipher", "stream-cipher": "stream cipher", "pke": "public-key encryption",
	"signature": "signature", "key-agree": "key agreement", "kem": "key encapsulation", "hash": "hash", "mac": "message authentication",
	"combiner": "hybrid key exchange", "drbg": "random generator", "xof": "extendable output", "kdf": "key derivation",
	"public-key": "public key", "private-key": "private key", "secret-key": "secret key", "tls": "TLS",
}

func humanDetail(d string) string {
	parts := strings.Split(d, " · ")
	for i, p := range parts {
		if w, ok := primitiveWords[p]; ok {
			parts[i] = w
		}
	}
	return strings.Join(parts, " · ")
}

type barPart struct {
	n     int
	label string
	t     tone
}

// stackBar draws one horizontal bar split by share, with a legend under it.
func (x *doc) stackBar(parts []barPart) {
	total := 0
	for _, p := range parts {
		total += p.n
	}
	if total == 0 {
		return
	}
	x.f.Add(pdf.Custom{H: 46, F: func(p *pdf.Page, x0, y, w float64) {
		p.RoundRect(x0, y, w, 14, 4, headBG, 0, pdf.Color{})
		at := x0
		for _, part := range parts {
			if part.n == 0 {
				continue
			}
			pw := w * float64(part.n) / float64(total)
			p.Rect(at, y, pw, 14, part.t.fg)
			if pw > 22 {
				p.Text(at+5, y+10, pdf.Bold, 7.5, white, fmt.Sprint(part.n))
			}
			at += pw
		}
		lx := x0
		for _, part := range parts {
			p.Circle(lx+4, y+28, 3.5, part.t.fg)
			label := fmt.Sprintf("%s  %d (%d%%)", part.label, part.n, part.n*100/total)
			p.Text(lx+11, y+31, pdf.Regular, 8, text2, label)
			lx += pdf.Width(pdf.Regular, 8, label) + 28
		}
	}})
}

// purposeBars draws a stacked bar per purpose, scaled to the largest.
func (x *doc) purposeBars(rows []InvPurpose) {
	most := 1
	for _, r := range rows {
		most = max(most, r.Vulnerable+r.Safe+r.Unknown)
	}
	h := float64(len(rows))*20 + 22
	x.f.Add(pdf.Custom{H: h, F: func(p *pdf.Page, x0, y, w float64) {
		labelW := 130.0
		barW := w - labelW - 40
		for i, r := range rows {
			ry := y + float64(i)*20
			p.Text(x0, ry+10, pdf.Regular, 8.5, ink, r.Purpose)
			at := x0 + labelW
			for _, seg := range []struct {
				n int
				t tone
			}{{r.Vulnerable, toneBad}, {r.Safe, toneGood}, {r.Unknown, toneInfo}} {
				if seg.n == 0 {
					continue
				}
				sw := barW * float64(seg.n) / float64(most)
				p.Rect(at, ry+2, sw, 11, seg.t.fg)
				at += sw
			}
			p.Text(at+6, ry+10.5, pdf.Bold, 8, text2, fmt.Sprint(r.Vulnerable+r.Safe+r.Unknown))
		}
		ly := y + float64(len(rows))*20 + 8
		lx := x0 + labelW
		for _, l := range []barPart{{0, "quantum-vulnerable", toneBad}, {0, "quantum-safe", toneGood}, {0, "not classified", toneInfo}} {
			p.Circle(lx+4, ly+3, 3.2, l.t.fg)
			p.Text(lx+11, ly+6, pdf.Regular, 7.5, muted, l.label)
			lx += pdf.Width(pdf.Regular, 7.5, l.label) + 26
		}
	}})
}
