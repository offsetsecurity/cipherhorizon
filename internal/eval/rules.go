package eval

import (
	"fmt"
	"strings"
	"time"

	"github.com/example/cbom-scan/internal/tlsprobe"
)

// hit is one place a rule fired.
type hit struct {
	detail   string
	severity Severity // overrides the rule's default when set
	evidence Evidence // overrides the rule's default when set
}

// A rule is one cited judgement. TestEveryRuleIsCited fails a rule with no
// citation or no remediation.
type rule struct {
	id          string
	title       string
	category    string
	severity    Severity
	evidence    Evidence
	citations   []Citation
	remediation string
	check       func(*ctx) []hit
}

// RuleIDs lists the IDs of the built-in rules (PQC readiness findings, which come
// from the readiness assessment, are not included).
func RuleIDs() []string {
	out := make([]string, len(rules))
	for i, r := range rules {
		out[i] = r.id
	}
	return out
}

func one(detail string) []hit { return []hit{{detail: detail}} }

// names lists up to five suite names, then a count.
func names(ss []tlsprobe.SuiteResult) string {
	var out []string
	for i, s := range ss {
		if i == 5 {
			out = append(out, fmt.Sprintf("and %d more", len(ss)-5))
			break
		}
		out = append(out, s.Name)
	}
	return strings.Join(out, ", ")
}

func filter(ss []tlsprobe.SuiteResult, keep func(tlsprobe.SuiteResult) bool) []tlsprobe.SuiteResult {
	var out []tlsprobe.SuiteResult
	for _, s := range ss {
		if keep(s) {
			out = append(out, s)
		}
	}
	return out
}

func suiteRule(id, title string, sev Severity, cites []Citation, remed string, keep func(tlsprobe.SuiteResult) bool) rule {
	return rule{
		id: id, title: title, category: "cipher", severity: sev, evidence: Observed, citations: cites, remediation: remed,
		check: func(c *ctx) []hit {
			if m := filter(c.suites, keep); len(m) > 0 {
				return one(fmt.Sprintf("%d accepted suite(s): %s", len(m), names(m)))
			}
			return nil
		},
	}
}

func protoRule(id, title, version string, sev Severity, cites []Citation, remed string) rule {
	return rule{
		id: id, title: title, category: "protocol", severity: sev, evidence: Observed, citations: cites, remediation: remed,
		check: func(c *ctx) []hit {
			if c.supported[version] {
				return one(version + " is accepted by the server")
			}
			return nil
		},
	}
}

func isCBC(s tlsprobe.SuiteResult) bool { return s.Mode == "CBC" }

func leafOf(cr tlsprobe.CertResult) (tlsprobe.CertInfo, bool) {
	if len(cr.Chain) == 0 {
		return tlsprobe.CertInfo{}, false
	}
	return cr.Chain[0], true
}

func certLabel(cr tlsprobe.CertResult, leaf tlsprobe.CertInfo) string {
	return fmt.Sprintf("%s [%s]", leaf.Subject, cr.Source)
}

func daysLeft(notAfter, now time.Time) int { return int(notAfter.Sub(now).Hours() / 24) }

// certRule runs fn on the leaf of every certificate the server presented.
func certRule(id, title string, sev Severity, cites []Citation, remed string, fn func(c *ctx, cr tlsprobe.CertResult, leaf tlsprobe.CertInfo) (string, Severity, bool)) rule {
	return rule{
		id: id, title: title, category: "certificate", severity: sev, evidence: Observed, citations: cites, remediation: remed,
		check: func(c *ctx) []hit {
			var hits []hit
			for _, cr := range c.rep.Certificates {
				leaf, ok := leafOf(cr)
				if !ok {
					continue
				}
				if detail, s, fire := fn(c, cr, leaf); fire {
					hits = append(hits, hit{detail: detail, severity: s})
				}
			}
			return hits
		},
	}
}

var rules = []rule{
	// ---- protocol versions ----
	protoRule("PROTO.SSL2", "SSLv2 is enabled", "SSLv2", Critical, []Citation{citRFC6176},
		"Disable SSLv2 entirely; it is prohibited and trivially broken."),
	protoRule("PROTO.SSL3", "SSLv3 is enabled", "SSLv3", High, []Citation{citRFC7568},
		"Disable SSLv3."),
	protoRule("PROTO.TLS10", "TLS 1.0 is enabled", "TLSv1.0", Medium, []Citation{citRFC8996, citRFC9325},
		"Disable TLS 1.0. RFC 9325 section 3.1.1: implementations MUST NOT negotiate it."),
	protoRule("PROTO.TLS11", "TLS 1.1 is enabled", "TLSv1.1", Medium, []Citation{citRFC8996, citRFC9325},
		"Disable TLS 1.1. RFC 9325 section 3.1.1: implementations MUST NOT negotiate it."),
	{
		id: "PROTO.NO-TLS12", title: "Neither TLS 1.2 nor TLS 1.3 is supported", category: "protocol", severity: High, evidence: Observed,
		citations:   []Citation{citRFC9325},
		remediation: "Enable TLS 1.2 and TLS 1.3. RFC 9325 section 3.1.1: implementations MUST support TLS 1.2.",
		check: func(c *ctx) []hit {
			if !c.supported["TLSv1.2"] && !c.supported["TLSv1.3"] && !c.inconclusive("TLSv1.2") && !c.inconclusive("TLSv1.3") {
				return one("only older protocol versions were accepted")
			}
			return nil
		},
	},
	{
		id: "PROTO.NO-TLS13", title: "TLS 1.3 is not supported", category: "protocol", severity: Low, evidence: Observed,
		citations:   []Citation{citRFC8446, citRFC9325},
		remediation: "Enable TLS 1.3 (RFC 9325 section 3.1.1: SHOULD support it, and prefer it). It is also the only protocol that can carry post-quantum key exchange.",
		check: func(c *ctx) []hit {
			if !c.supported["TLSv1.3"] && !c.inconclusive("TLSv1.3") {
				return one("the server refused a TLS 1.3 hello")
			}
			return nil
		},
	},

	// ---- cipher suites ----
	suiteRule("CIPHER.NULL", "Cipher suites without encryption are accepted", Critical,
		[]Citation{citRFC9325, citIANASuites}, "Remove all NULL-encryption suites. RFC 9325 section 4.1: MUST NOT negotiate them.",
		func(s tlsprobe.SuiteResult) bool { return s.Cipher == "NULL" }),
	suiteRule("CIPHER.EXPORT", "Export-grade cipher suites are accepted", Critical,
		[]Citation{citFREAK, citLogjam, citRFC9325, citIANASuites}, "Remove export-grade suites (ciphers under 112 bits: RFC 9325 section 4.1).",
		func(s tlsprobe.SuiteResult) bool { return s.Export }),
	suiteRule("CIPHER.ANON", "Anonymous (unauthenticated) key-exchange suites are accepted", Critical,
		[]Citation{citIANASuites}, "Remove anonymous suites: without authentication anyone can impersonate the server.",
		func(s tlsprobe.SuiteResult) bool { return s.Anon }),
	suiteRule("CIPHER.RC4", "RC4 cipher suites are accepted", High,
		[]Citation{citRFC7465, citRFC9325}, "Remove RC4 suites. RFC 7465 prohibits them; RFC 9325 section 4.1: MUST NOT negotiate.",
		func(s tlsprobe.SuiteResult) bool { return s.Cipher == "RC4" && !s.Export }),
	suiteRule("CIPHER.DES", "Single-DES (56-bit) cipher suites are accepted", High,
		[]Citation{citRFC9325, citIANASuites}, "Remove DES suites (under 112 bits of security: RFC 9325 section 4.1).",
		func(s tlsprobe.SuiteResult) bool { return s.Cipher == "DES" && !s.Export }),
	suiteRule("CIPHER.SWEET32", "64-bit block ciphers (3DES, IDEA, ...) are accepted", Medium,
		[]Citation{citSweet32, citIANASuites}, "Remove 64-bit-block suites; prefer AES-GCM or ChaCha20-Poly1305.",
		func(s tlsprobe.SuiteResult) bool {
			return s.BlockBits == 64 && !s.Export && s.Cipher != "DES" && s.Cipher != "NULL"
		}),
	{
		id: "CIPHER.NO-FS", title: "Cipher suites without forward secrecy are accepted", category: "cipher", severity: Medium, evidence: Observed,
		citations:   []Citation{citRFC9325},
		remediation: "Prefer (EC)DHE suites and remove RSA key-transport and static DH suites. RFC 9325 section 4.1: SHOULD NOT negotiate RSA key transport.",
		check: func(c *ctx) []hit {
			m := filter(c.suites, func(s tlsprobe.SuiteResult) bool {
				return s.Kx == "RSA" || s.Kx == "DH" || s.Kx == "ECDH"
			})
			if len(m) > 0 {
				return one(fmt.Sprintf("%d accepted suite(s): %s", len(m), names(m)))
			}
			return nil
		},
	},
	{
		id: "CIPHER.IANA-DISCOURAGED", title: "IANA marks accepted cipher suites as Discouraged", category: "cipher", severity: Low, evidence: Registry,
		citations:   []Citation{citIANASuites},
		remediation: "Remove suites the IANA registry marks Discouraged (D) unless a specific legacy client needs them.",
		check: func(c *ctx) []hit {
			m := filter(c.suites, func(s tlsprobe.SuiteResult) bool {
				// Ones already reported by a more specific rule are not repeated.
				specific := s.Cipher == "NULL" || s.Export || s.Anon || s.Cipher == "RC4" || s.Cipher == "DES" || s.BlockBits == 64
				return s.IANARecommended == "D" && !specific
			})
			if len(m) > 0 {
				return one(fmt.Sprintf("%d accepted suite(s): %s", len(m), names(m)))
			}
			return nil
		},
	},

	// ---- key exchange ----
	{
		id: "KX.DH-SMALL", title: "Finite-field Diffie-Hellman uses a small prime", category: "key-exchange", severity: Medium, evidence: Observed,
		citations:   []Citation{citRFC9325, citLogjam},
		remediation: "Use at least 2048-bit DH groups (RFC 9325 section 4.5: REQUIRED), or drop DHE in favour of ECDHE.",
		check: func(c *ctx) []hit {
			if c.rep.DH == nil || c.rep.DH.PrimeBits >= 2048 {
				return nil
			}
			sev := Medium
			if c.rep.DH.PrimeBits < 1024 {
				sev = High
			}
			return []hit{{detail: fmt.Sprintf("the server's DHE prime is %d bits", c.rep.DH.PrimeBits), severity: sev}}
		},
	},

	// ---- certificates ----
	certRule("CERT.EXPIRED", "Certificate has expired", Critical, []Citation{citRFC5280},
		"Renew and deploy a new certificate.",
		func(c *ctx, cr tlsprobe.CertResult, l tlsprobe.CertInfo) (string, Severity, bool) {
			return fmt.Sprintf("%s expired on %s", certLabel(cr, l), l.NotAfter.Format("2006-01-02")), "", l.NotAfter.Before(c.now)
		}),
	certRule("CERT.NOT-YET-VALID", "Certificate is not yet valid", High, []Citation{citRFC5280},
		"Check the server clock and the certificate's validity period.",
		func(c *ctx, cr tlsprobe.CertResult, l tlsprobe.CertInfo) (string, Severity, bool) {
			return fmt.Sprintf("%s becomes valid on %s", certLabel(cr, l), l.NotBefore.Format("2006-01-02")), "", l.NotBefore.After(c.now)
		}),
	certRule("CERT.EXPIRING", "Certificate expires soon", Medium, []Citation{citRFC5280},
		"Renew before expiry; automate renewal.",
		func(c *ctx, cr tlsprobe.CertResult, l tlsprobe.CertInfo) (string, Severity, bool) {
			d := daysLeft(l.NotAfter, c.now)
			if l.NotAfter.Before(c.now) || d > 30 {
				return "", "", false
			}
			sev := Medium
			if d <= 7 {
				sev = High
			}
			return fmt.Sprintf("%s expires in %d day(s)", certLabel(cr, l), d), sev, true
		}),
	certRule("CERT.UNTRUSTED", "Certificate chain is not trusted", High, []Citation{citRFC5280},
		"Install a certificate from a CA the clients trust, and serve the full chain. (Trust is judged against the scanner host's certificate store.)",
		func(c *ctx, cr tlsprobe.CertResult, l tlsprobe.CertInfo) (string, Severity, bool) {
			if cr.Trusted || l.NotAfter.Before(c.now) || l.NotBefore.After(c.now) {
				return "", "", false // expiry has its own finding
			}
			why := cr.TrustError
			if l.SelfSigned {
				why = "self-signed; " + why
			}
			return fmt.Sprintf("%s: %s", certLabel(cr, l), why), "", true
		}),
	certRule("CERT.NAME-MISMATCH", "Certificate does not match the host name", High, []Citation{citRFC9525},
		"Issue a certificate whose subject alternative names include the name clients use.",
		func(c *ctx, cr tlsprobe.CertResult, l tlsprobe.CertInfo) (string, Severity, bool) {
			return fmt.Sprintf("%s: %s", certLabel(cr, l), cr.NameError), "", !cr.NameMatches
		}),
	certRule("CERT.WEAK-KEY", "Certificate public key is too small", High, []Citation{citCABF, citSP80057},
		"Use RSA of at least 2048 bits or ECDSA P-256 or better.",
		func(c *ctx, cr tlsprobe.CertResult, l tlsprobe.CertInfo) (string, Severity, bool) {
			k := l.PublicKey
			switch {
			case k.Algorithm == "RSA" && k.Bits > 0 && k.Bits < 1024:
				return fmt.Sprintf("%s: RSA %d-bit", certLabel(cr, l), k.Bits), Critical, true
			case k.Algorithm == "RSA" && k.Bits > 0 && k.Bits < 2048:
				return fmt.Sprintf("%s: RSA %d-bit", certLabel(cr, l), k.Bits), "", true
			case k.Algorithm == "ECDSA" && k.Bits > 0 && k.Bits < 224:
				return fmt.Sprintf("%s: ECDSA %d-bit", certLabel(cr, l), k.Bits), "", true
			}
			return "", "", false
		}),
	certRule("CERT.WEAK-SIGNATURE", "Certificate is signed with a broken hash", High, []Citation{citCABF},
		"Reissue the certificate with a SHA-256 (or better) signature.",
		func(c *ctx, cr tlsprobe.CertResult, l tlsprobe.CertInfo) (string, Severity, bool) {
			n := strings.ToUpper(l.SignatureAlg.Name)
			return fmt.Sprintf("%s: signature %s", certLabel(cr, l), l.SignatureAlg.Name),
				"", strings.Contains(n, "SHA1") || strings.Contains(n, "MD5") || strings.Contains(n, "MD2")
		}),

	// ---- server behaviour ----
	{
		id: "FEAT.RENEGOTIATION", title: "Secure renegotiation is not advertised", category: "feature", severity: Medium, evidence: Inferred,
		citations:   []Citation{citRFC5746},
		remediation: "Upgrade the TLS library so it supports the renegotiation_info extension (RFC 5746).",
		check: func(c *ctx) []hit {
			if f := c.rep.Features.SecureRenegotiation; f != nil && !*f {
				return one("the server did not echo renegotiation_info (renegotiation itself was not attempted)")
			}
			return nil
		},
	},
	{
		id: "FEAT.COMPRESSION", title: "TLS compression is accepted", category: "feature", severity: High, evidence: Observed,
		citations:   []Citation{citCRIME, citRFC9325},
		remediation: "Disable TLS-level compression (RFC 9325 section 3.3: SHOULD NOT support it).",
		check: func(c *ctx) []hit {
			if f := c.rep.Features.Compression; f != nil && *f {
				return one("the server selected a compression method")
			}
			return nil
		},
	},
	{
		id: "FEAT.NO-FALLBACK-SCSV", title: "TLS_FALLBACK_SCSV is not enforced", category: "feature", severity: Low, evidence: Observed,
		citations:   []Citation{citRFC7507},
		remediation: "Upgrade the TLS library; better, disable the older protocol versions so downgrade is impossible.",
		check: func(c *ctx) []hit {
			if f := c.rep.Features.FallbackSCSV; f != nil && !*f {
				return one("a downgraded hello carrying the SCSV was answered with a ServerHello, not inappropriate_fallback")
			}
			return nil
		},
	},

	// ---- vulnerabilities inferred from what is enabled ----
	{
		id: "VULN.POODLE", title: "POODLE: SSLv3 with CBC suites", category: "vulnerability", severity: High, evidence: Inferred,
		citations:   []Citation{citPOODLE, citRFC7568},
		remediation: "Disable SSLv3.",
		check: func(c *ctx) []hit {
			if m := filter(c.byVersion["SSLv3"], isCBC); c.supported["SSLv3"] && len(m) > 0 {
				return one("SSLv3 is accepted with CBC suites: " + names(m) + " (inferred; the attack was not attempted)")
			}
			return nil
		},
	},
	{
		id: "VULN.BEAST", title: "BEAST: TLS 1.0 with CBC suites", category: "vulnerability", severity: Low, evidence: Inferred,
		citations:   []Citation{citBEAST, citRFC8996},
		remediation: "Disable TLS 1.0. (Modern clients mitigate this, so the practical risk is low.)",
		check: func(c *ctx) []hit {
			if m := filter(c.byVersion["TLSv1.0"], isCBC); c.supported["TLSv1.0"] && len(m) > 0 {
				return one("TLS 1.0 is accepted with CBC suites: " + names(m) + " (inferred; the attack was not attempted)")
			}
			return nil
		},
	},
}
