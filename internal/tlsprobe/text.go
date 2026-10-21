package tlsprobe

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/offsetsecurity/cipherhorizon/internal/tlsprobe/registry"
)

// WriteText renders the report for a person. It states what was observed and the
// registry facts attached to it (IANA's Recommended flag, export/anonymous/NULL
// properties); it passes no verdicts. Evaluation is a separate layer.
func (r *Report) WriteText(w io.Writer) error { return r.WriteTextWith(w, Annotations{}) }

// Annotations add a caller's words to the rows WriteText prints, such as the evaluation's strength
// of each suite and group (PRD-010 REQ-STR-5). This package passes no verdicts itself; a nil
// function adds nothing.
type Annotations struct {
	Suite func(s SuiteResult) string
	Group func(g GroupResult) string
}

// WriteTextWith is WriteText with annotations.
func (r *Report) WriteTextWith(w io.Writer, a Annotations) error {
	o := &out{w: w, ann: a}
	r.writeText(o)
	return o.err
}

// out remembers the first write error so the renderer can be written without
// checking every line, and still report failure.
type out struct {
	w   io.Writer
	err error
	ann Annotations
}

func (o *out) f(format string, args ...any) { o.fTo(o.w, format, args...) }

func (o *out) fTo(w io.Writer, format string, args ...any) {
	if o.err == nil {
		_, o.err = fmt.Fprintf(w, format, args...)
	}
}

func (o *out) ln(s string) { o.f("%s\n", s) }

func (o *out) flush(tw *tabwriter.Writer) {
	if err := tw.Flush(); o.err == nil {
		o.err = err
	}
}

func (r *Report) writeText(o *out) {
	o.f("TLS scan of %s:%d", r.Target.Host, r.Target.Port)
	if r.Address != "" {
		o.f(" (%s)", r.Address)
	}
	if r.Target.StartTLS != "" {
		o.f(" via STARTTLS (%s)", StartTLSName(r.Target.StartTLS))
	}
	o.f("\n  %d connections in %.1fs; IANA registry retrieved %s\n", r.Connections, float64(r.DurationMS)/1000, registryDate())
	if r.Incomplete {
		o.ln("  ! INCOMPLETE: some probes were inconclusive or hit a limit; a missing finding is not proof of absence")
	}

	o.ln("\nProtocols")
	tw := tabwriter.NewWriter(o.w, 0, 4, 2, ' ', 0)
	for _, p := range r.Protocols {
		state := "no"
		if p.Supported {
			state = "YES"
		}
		if p.Evidence == EvidenceInconclusive {
			state = "?"
		}
		o.fTo(tw, "  %s\t%s\t%s\n", p.Version, state, p.detailText())
	}
	o.flush(tw)

	if len(r.Suites) > 0 {
		o.ln("\nCipher suites")
		r.writeSuites(o)
	}
	if len(r.Groups) > 0 {
		o.ln("\nKey-exchange groups")
		r.writeGroups(o)
	}
	if r.DH != nil {
		o.f("\nDiffie-Hellman: %d-bit prime (sha256 %s…) from %s\n", r.DH.PrimeBits, r.DH.PrimeSHA256[:12], r.DH.Suite)
	}

	r.writeFeatures(o)
	r.writeCerts(o)

	if n := r.Negotiated; n != nil {
		o.ln("\nNegotiated by a current client (Go crypto/tls)")
		if n.Version == "" {
			o.f("  handshake failed: %s\n", n.Error)
		} else {
			o.f("  %s  %s", n.Version, n.Suite)
			if n.Group != "" {
				o.f("  group %s", n.Group)
				if n.PQ {
					o.f(" (post-quantum)")
				}
			}
			o.ln("")
		}
	}
	if len(r.Notes) > 0 {
		o.ln("\nNotes")
		for _, n := range r.Notes {
			o.f("  - %s\n", n)
		}
	}
}

func (p ProtocolResult) detailText() string {
	switch {
	case p.Supported && p.Detail != "":
		return p.Detail
	case p.Supported:
		return ""
	case p.Evidence == EvidenceInconclusive:
		return "inconclusive: " + p.Detail
	case p.Evidence == EvidenceAlert:
		return "refused (alert " + p.Detail + ")"
	case p.Detail != "":
		return p.Detail
	}
	return "refused (" + string(p.Evidence) + ")"
}

func (r *Report) writeSuites(o *out) {
	var version string
	tw := tabwriter.NewWriter(o.w, 0, 4, 2, ' ', 0)
	for _, s := range r.Suites {
		if s.Version != version {
			o.flush(tw)
			version = s.Version
			o.f("  %s (%s)\n", version, r.preferenceText(version, "suites"))
		}
		rank := "-"
		if s.Rank > 0 {
			rank = fmt.Sprint(s.Rank)
		}
		note := ""
		if o.ann.Suite != nil {
			note = o.ann.Suite(s)
		}
		o.fTo(tw, "    %s\t%s\t%s\tiana:%s\t%s\n", rank, s.Name, suiteFacts(s), s.IANARecommended, note)
	}
	o.flush(tw)
}

func suiteFacts(s SuiteResult) string {
	var f []string
	if s.Cipher != "NULL" {
		f = append(f, fmt.Sprintf("%s-%d %s", s.Cipher, s.KeyBits, s.Mode))
	} else {
		f = append(f, "NO ENCRYPTION")
	}
	if s.Kx != "" {
		f = append(f, "kx:"+s.Kx)
	}
	if s.Export {
		f = append(f, "EXPORT")
	}
	if s.Anon {
		f = append(f, "ANONYMOUS")
	}
	if s.BlockBits == 64 {
		f = append(f, "64-bit-block")
	}
	return strings.Join(f, " ")
}

func (r *Report) writeGroups(o *out) {
	var version string
	tw := tabwriter.NewWriter(o.w, 0, 4, 2, ' ', 0)
	for _, g := range r.Groups {
		if g.Version != version {
			o.flush(tw)
			version = g.Version
			o.f("  %s (%s)\n", version, r.preferenceText(version, "groups"))
		}
		rank := "-"
		if g.Rank > 0 {
			rank = fmt.Sprint(g.Rank)
		}
		var tags []string
		if g.PQ {
			tag := "POST-QUANTUM"
			if g.Hybrid {
				tag += " HYBRID"
			}
			tags = append(tags, tag)
		}
		if g.Obsolete {
			tags = append(tags, "obsolete draft")
		}
		if o.ann.Group != nil {
			if n := o.ann.Group(g); n != "" {
				tags = append([]string{n}, tags...)
			}
		}
		o.fTo(tw, "    %s\t%s\tiana:%s\t%s\n", rank, g.Name, g.IANARecommended, strings.Join(tags, ", "))
	}
	o.flush(tw)
}

func (r *Report) preferenceText(version, subject string) string {
	for _, p := range r.Preference {
		if p.Version == version && p.Subject == subject {
			switch p.Order {
			case "server":
				return "server's preference order"
			case "client":
				return "server follows the client's order; no ranking"
			case "mixed":
				return "order depends on the client; no ranking"
			}
		}
	}
	return "order unknown"
}

func (r *Report) writeFeatures(o *out) {
	type item struct {
		name string
		v    *bool
		yes  string
		no   string
	}
	f := r.Features
	items := []item{
		{"secure renegotiation (RFC 5746)", f.SecureRenegotiation, "supported", "not offered"},
		{"extended master secret (RFC 7627)", f.ExtendedMasterSecret, "supported", "not offered"},
		{"encrypt-then-MAC (RFC 7366)", f.EncryptThenMAC, "supported", "not offered"},
		{"heartbeat (RFC 6520)", f.Heartbeat, "negotiated", "not negotiated"},
		{"session tickets", f.SessionTickets, "offered", "not offered"},
		{"OCSP stapling", f.OCSPStapling, "supported", "not offered"},
		{"TLS compression", f.Compression, "ACCEPTED", "refused"},
		{"TLS_FALLBACK_SCSV (RFC 7507)", f.FallbackSCSV, "enforced", "NOT enforced"},
		{"client certificate requested (mTLS, RFC 8446 4.3.2)", f.ClientCertRequested, "yes", "no"},
	}
	var any bool
	for _, it := range items {
		if it.v != nil {
			any = true
		}
	}
	if !any {
		return
	}
	o.ln("\nServer features")
	tw := tabwriter.NewWriter(o.w, 0, 4, 2, ' ', 0)
	for _, it := range items {
		if it.v == nil {
			continue
		}
		s := it.no
		if *it.v {
			s = it.yes
		}
		o.fTo(tw, "  %s\t%s\n", it.name, s)
	}
	o.flush(tw)
}

func (r *Report) writeCerts(o *out) {
	if len(r.Certificates) == 0 {
		return
	}
	o.ln("\nCertificates")
	for _, c := range r.Certificates {
		leaf := c.Chain[0]
		o.f("  [%s]\n    subject   %s\n    issuer    %s\n", c.Source, leaf.Subject, leaf.Issuer)
		o.f("    key       %s", leaf.PublicKey.Algorithm)
		if leaf.PublicKey.Bits > 0 {
			o.f(" %d-bit", leaf.PublicKey.Bits)
		}
		if leaf.PublicKey.Curve != "" {
			o.f(" %s", leaf.PublicKey.Curve)
		}
		o.f(" (OID %s)\n    signature %s (OID %s)\n", leaf.PublicKey.OID, leaf.SignatureAlg.Name, leaf.SignatureAlg.OID)
		o.f("    validity  %s to %s\n", leaf.NotBefore.Format("2006-01-02"), leaf.NotAfter.Format("2006-01-02"))
		if c.NoSNI {
			o.ln("    served    to clients that send no server name (differs from the SNI certificate)")
		}
		switch {
		case c.Trusted:
			o.ln("    OS trust  chain builds to a root in this machine's store")
		case c.TrustError != "":
			o.f("    OS trust  NOT trusted by this machine's store: %s\n", c.TrustError)
		default:
			o.ln("    trust     judged in evaluation against the bundled root stores")
		}
		if c.OCSPStaple != "" {
			o.ln("    ocsp      a response was stapled")
		}
		if len(c.TLSSCTs) > 0 {
			o.f("    sct       %d in the TLS extension\n", len(c.TLSSCTs))
		}
		if c.NameMatches {
			o.f("    name      matches %s\n", r.Target.Host)
		} else {
			o.f("    name      does NOT match %s: %s\n", r.Target.Host, c.NameError)
		}
		if len(c.Chain) > 1 {
			o.f("    chain     %d certificates presented\n", len(c.Chain))
		}
		o.f("    sha256    %s\n", leaf.SHA256)
	}
}

func registryDate() string { return registry.SuitesRetrieved }
