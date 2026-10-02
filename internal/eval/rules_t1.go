package eval

import (
	"fmt"
	"strings"

	"github.com/example/cipherhorizon/internal/pki"
	"github.com/example/cipherhorizon/internal/refdata"
	"github.com/example/cipherhorizon/internal/tlsprobe"
)

// The rules added in eval/3 (PRD-004). Those that need the raw certificates,
// the staple or the SCTs run only on tls-report/2 (v2Only).

var (
	citRFC5246  = rfc("5246", "The Transport Layer Security (TLS) Protocol Version 1.2")
	citRFC6960  = rfc("6960", "X.509 Internet Public Key Infrastructure Online Certificate Status Protocol - OCSP")
	citRFC7633  = rfc("7633", "X.509v3 Transport Layer Security (TLS) Feature Extension")
	citRFC6066  = rfc("6066", "Transport Layer Security (TLS) Extensions: Extension Definitions")
	citRFC6962  = rfc("6962", "Certificate Transparency")
	citRFC7919  = rfc("7919", "Negotiated Finite Field Diffie-Hellman Ephemeral Parameters for TLS")
	citSC081    = Citation{Title: "CA/Browser Forum Ballot SC-081v3: schedule of reducing validity periods (BR §6.3.2)", URL: "https://cabforum.org/2025/04/11/ballot-sc081v3-introduce-schedule-of-reducing-validity-and-data-reuse-periods/"}
	citChromeRP = Citation{Title: "Chrome Root Program Policy (dedicated serverAuth hierarchies)", URL: "https://www.chromium.org/Home/chromium-security/root-ca-policy/"}
	citChromeCT = Citation{Title: "Chrome Certificate Transparency Policy", URL: "https://googlechrome.github.io/CertificateTransparency/ct_policy.html"}
	citLEOCSP   = Citation{Title: "Let's Encrypt: ending OCSP support (2025)", URL: "https://letsencrypt.org/2024/12/05/ending-ocsp/"}
	citHSTSPre  = Citation{Title: "HSTS preload list submission requirements", URL: "https://hstspreload.org/"}
	citLucky13  = cve("CVE-2013-0169", "Lucky Thirteen: CBC padding timing")
	citDROWN    = cve("CVE-2016-0800", "DROWN: SSLv2 cross-protocol attack")
)

// chainRule runs fn on every analysed chain of a tls-report/2.
func chainRule(id, title, category string, sev Severity, cites []Citation, remed string, fn func(c *ctx, ch *chain) (string, Severity, bool)) rule {
	return rule{
		id: id, title: title, category: category, severity: sev, evidence: Observed, citations: cites, remediation: remed, v2Only: true,
		check: func(c *ctx) []hit {
			var hits []hit
			for _, ch := range c.chains {
				if ch.served == nil {
					continue
				}
				if d, s, fire := fn(c, ch); fire {
					hits = append(hits, hit{detail: d, severity: s})
				}
			}
			return hits
		},
	}
}

func (c *ctx) negotiatesTLS13() bool {
	return c.rep.Negotiated != nil && c.rep.Negotiated.Version == "TLSv1.3" || c.supported["TLSv1.3"]
}

func issuesOf(ch *chain, kinds ...string) []pki.Issue {
	var out []pki.Issue
	for _, i := range ch.served.Issues {
		for _, k := range kinds {
			if i.Kind == k {
				out = append(out, i)
			}
		}
	}
	return out
}

func describeIssues(is []pki.Issue) string {
	var parts []string
	for _, i := range is {
		parts = append(parts, fmt.Sprintf("position %d: %s (%s)", i.Index, i.Kind, i.Detail))
	}
	return strings.Join(parts, "; ")
}

// expiryWindow is the warning window of REQ-TCRT-4 for a lifetime in days:
// medium at min(30, ⅓ lifetime), high at min(7, ⅒ lifetime).
func expiryWindow(lifetime int) (medium, high int) {
	medium, high = 30, 7
	if lifetime > 0 {
		if l := lifetime / 3; l < medium {
			medium = l
		}
		if l := lifetime / 10; l < high {
			high = l
		}
	}
	return medium, high
}

var t1Rules = []rule{
	// ---- chain as served ----
	chainRule("CERT.CHAIN-INCOMPLETE", "An intermediate certificate is missing from the chain", "certificate", High,
		[]Citation{citRFC8446, citRFC5246},
		"Configure the server to send the intermediate certificate(s) after the leaf. Clients that do not fetch missing intermediates (most non-browser clients) will fail to connect.",
		func(c *ctx, ch *chain) (string, Severity, bool) {
			m := ch.view.Served.Missing
			if m == nil || m.Likely != "intermediate" {
				return "", "", false
			}
			d := fmt.Sprintf("%s: the issuer %q was neither sent nor found in any trusted store (if it is your own private root, add it to the system's CA bundle instead)", ch.label(), m.IssuerDN)
			if len(m.AIA) > 0 {
				d += "; the certificate says it can be downloaded from " + strings.Join(m.AIA, ", ") + " (not fetched: this scan contacts only the target)"
			}
			return d, "", true
		}),
	chainRule("CERT.CHAIN-ORDER", "Certificates are sent in the wrong order", "certificate", Medium,
		[]Citation{citRFC5246, citRFC8446},
		"Send the leaf first, then each certificate followed by the one that issued it. TLS 1.2 requires this order (RFC 5246 §7.4.2); TLS 1.3 tolerates other orders.",
		func(c *ctx, ch *chain) (string, Severity, bool) {
			is := issuesOf(ch, pki.IssueOrder)
			if len(is) == 0 {
				return "", "", false
			}
			sev := Medium
			if c.negotiatesTLS13() {
				sev = Low
			}
			return ch.label() + ": " + describeIssues(is), sev, true
		}),
	chainRule("CERT.CHAIN-EXTRA", "The chain carries certificates clients do not need", "certificate", Info,
		[]Citation{citRFC8446},
		"Remove the root, duplicate or unrelated certificates from the configured chain; they add bytes to every handshake.",
		func(c *ctx, ch *chain) (string, Severity, bool) {
			is := issuesOf(ch, pki.IssueRoot, pki.IssueDuplicate, pki.IssueUnrelated, pki.IssueUnparsed)
			if len(is) == 0 {
				return "", "", false
			}
			return ch.label() + ": " + describeIssues(is), "", true
		}),
	chainRule("CERT.INTERMEDIATE-EXPIRES", "An intermediate certificate expires before the leaf", "certificate", Medium,
		[]Citation{citRFC5280},
		"Obtain the CA's current intermediate and serve it; the chain stops validating when the intermediate expires, whatever the leaf says.",
		func(c *ctx, ch *chain) (string, Severity, bool) {
			leaf := ch.served.Leaf()
			med, _ := expiryWindow(ch.view.Lifetime.Days)
			var parts []string
			for _, i := range ch.served.Path[1:] {
				x := ch.served.Certs[i]
				left := daysLeft(x.NotAfter, c.now)
				if x.NotAfter.Before(leaf.NotAfter) || (left <= med && !x.NotAfter.Before(c.now)) {
					parts = append(parts, fmt.Sprintf("%s expires %s", x.Subject.String(), fmtDate(x.NotAfter)))
				}
			}
			if len(parts) == 0 {
				return "", "", false
			}
			return fmt.Sprintf("%s (leaf expires %s): %s", ch.label(), fmtDate(leaf.NotAfter), strings.Join(parts, "; ")), "", true
		}),
	chainRule("CERT.LIFETIME", "Certificate validity is longer than the limit for public certificates", "certificate", Medium,
		[]Citation{citSC081, citCABF},
		"Reissue with a validity within the limit in force on the issue date, and automate renewal: the limit falls to 200 days (2026-03-15), 100 (2027-03-15) and 47 (2029-03-15).",
		func(c *ctx, ch *chain) (string, Severity, bool) {
			l := ch.view.Lifetime
			if !l.Applies || l.LimitDays == 0 || l.Days <= l.LimitDays {
				return "", "", false
			}
			return fmt.Sprintf("%s: valid for %d days, issued %s when the limit was %d days (%s)", ch.label(), l.Days,
				fmtDate(ch.served.Leaf().NotBefore), l.LimitDays, l.LimitSource), "", true
		}),
	chainRule("CERT.NO-SERVERAUTH", "Certificate is not valid for TLS servers (extended key usage)", "certificate", High,
		[]Citation{citRFC5280},
		"Reissue the certificate with the serverAuth extended key usage.",
		func(c *ctx, ch *chain) (string, Severity, bool) {
			eku := ch.cr.Chain[0].ExtKeyUsage
			if len(eku) == 0 {
				return "", "", false
			}
			for _, u := range eku {
				if u == "serverAuth" || u == "any" {
					return "", "", false
				}
			}
			return fmt.Sprintf("%s: extended key usage is %s, without serverAuth", ch.label(), strings.Join(eku, ", ")), "", true
		}),
	chainRule("CERT.CLIENTAUTH-EKU", "Public certificate also allows client authentication", "certificate", Info,
		[]Citation{citChromeRP},
		"No change needed for a web server. If you use this certificate (or its CA) for client authentication (mTLS), plan a separate private CA: the Chrome Root Program requires serverAuth-only hierarchies (intermediates from 2026-06-15, leaves from 2027-03-15).",
		func(c *ctx, ch *chain) (string, Severity, bool) {
			if !ch.view.Public {
				return "", "", false
			}
			var where []string
			for _, i := range ch.served.Path {
				if i < len(ch.cr.Chain) {
					for _, u := range ch.cr.Chain[i].ExtKeyUsage {
						if u == "clientAuth" {
							where = append(where, ch.cr.Chain[i].Subject)
						}
					}
				}
			}
			if len(where) == 0 {
				return "", "", false
			}
			return ch.label() + ": clientAuth on " + strings.Join(where, "; "), "", true
		}),
	chainRule("CERT.PARTIAL-TRUST", "Only some root stores trust the certificate", "certificate", Medium,
		[]Citation{citRFC5280},
		"Use a CA trusted by every root program your clients rely on; check any distrust constraint named here.",
		func(c *ctx, ch *chain) (string, Severity, bool) {
			if len(ch.trustedBy) == 0 || len(ch.failing) == 0 {
				return "", "", false
			}
			return fmt.Sprintf("%s: trusted by %s, not by %s (%s)", ch.label(), storeList(ch.trustedBy), storeList(ch.failing), ch.trustSummary()), "", true
		}),
	chainRule("CERT.UNTRUSTED", "Certificate chain is not trusted", "certificate", High,
		[]Citation{citRFC5280},
		"Install a certificate from a CA your clients trust and serve the full chain, or add your private CA to this system's CA bundle if the certificate is meant to be private.",
		func(c *ctx, ch *chain) (string, Severity, bool) {
			if len(ch.trustedBy) > 0 || ch.private || ch.expired {
				return "", "", false // trusted somewhere, or expiry has its own finding
			}
			why := ch.trustSummary()
			m := ch.view.Served.Missing
			switch {
			case ch.missing:
				why = "an intermediate is missing (see CERT.CHAIN-INCOMPLETE); " + why
			case m != nil && m.Likely == "root":
				why = fmt.Sprintf("the chain ends at a CA issued by %q, which no trusted store holds (a private or unknown root: add it to the system's CA bundle if it is yours); ", m.IssuerDN) + why
			case pki.SelfSigned(ch.served.Leaf()):
				why = "self-signed; " + why
			}
			if why == "" {
				why = "no root store was available"
			}
			return ch.label() + ": " + why, "", true
		}),
	chainRule("CERT.WEAK-EXPONENT", "RSA public exponent is smaller than 65537", "certificate", Low,
		[]Citation{citCABF},
		"Reissue with a new key whose public exponent is 65537.",
		func(c *ctx, ch *chain) (string, Severity, bool) {
			e := ch.cr.Chain[0].RSAExponent
			return fmt.Sprintf("%s: exponent %d", ch.label(), e), "", e > 0 && e < 65537
		}),

	// ---- revocation and transparency ----
	chainRule("OCSP.REVOKED", "The stapled OCSP response says the certificate is revoked", "revocation", Critical,
		[]Citation{citRFC6960},
		"Replace the certificate now; clients that check the staple will refuse it.",
		func(c *ctx, ch *chain) (string, Severity, bool) {
			o := ch.view.OCSP
			if o == nil || !o.ForThisCert || o.Signature != pki.SigValid || o.Status != "revoked" {
				return "", "", false
			}
			d := fmt.Sprintf("%s: revoked on %s", ch.label(), fmtDate(o.RevokedAt))
			if o.Reason != "" {
				d += " (" + o.Reason + ")"
			}
			return d, "", true
		}),
	chainRule("OCSP.MISMATCH", "The stapled OCSP response does not vouch for this certificate", "revocation", High,
		[]Citation{citRFC6960},
		"Fix the server's stapling configuration so it staples a correctly signed, current response for the certificate it serves (a stale cache after renewal is the usual cause).",
		func(c *ctx, ch *chain) (string, Severity, bool) {
			o := ch.view.OCSP
			switch {
			case o == nil:
				return "", "", false
			case o.Error != "":
				return ch.label() + ": " + o.Error, "", true
			case !o.ForThisCert:
				return ch.label() + ": the stapled response is for a different certificate", "", true
			case o.Signature == pki.SigInvalid:
				return ch.label() + ": the response signature does not verify against the issuer or a delegated responder", "", true
			}
			return "", "", false
		}),
	chainRule("OCSP.STALE", "The stapled OCSP response has expired", "revocation", Medium,
		[]Citation{citRFC6960},
		"Make the server refresh its staple before nextUpdate; check it can reach the CA's responder.",
		func(c *ctx, ch *chain) (string, Severity, bool) {
			o := ch.view.OCSP
			if o == nil || !o.ForThisCert || o.NextUpdate.IsZero() || !o.NextUpdate.Before(c.now) {
				return "", "", false
			}
			return fmt.Sprintf("%s: nextUpdate was %s", ch.label(), o.NextUpdate.UTC().Format("2006-01-02 15:04 MST")), "", true
		}),
	chainRule("OCSP.UNKNOWN", "The stapled OCSP response says the status is unknown", "revocation", Medium,
		[]Citation{citRFC6960},
		"Check that the server staples the response from the certificate's own CA.",
		func(c *ctx, ch *chain) (string, Severity, bool) {
			o := ch.view.OCSP
			return ch.label() + ": the responder does not know this certificate", "", o != nil && o.ForThisCert && o.Status == "unknown"
		}),
	chainRule("OCSP.MUST-STAPLE-MISSING", "A Must-Staple certificate was served without a staple", "revocation", High,
		[]Citation{citRFC7633},
		"Enable OCSP stapling on the server, or reissue without the Must-Staple extension. Clients that honour Must-Staple refuse the connection.",
		func(c *ctx, ch *chain) (string, Severity, bool) {
			return ch.label() + ": the certificate requires a staple (TLS Feature status_request) and none was sent", "",
				ch.cr.Chain[0].OCSPMustStaple && ch.view.OCSP == nil
		}),
	chainRule("OCSP.NO-STAPLE", "OCSP stapling is not used", "revocation", Low,
		[]Citation{citRFC6066, citLEOCSP},
		"Enable OCSP stapling, so clients need not contact the CA. Context: the largest public CA stopped OCSP on 2025-08-06; a certificate without an OCSP URL raises nothing here.",
		func(c *ctx, ch *chain) (string, Severity, bool) {
			l := ch.cr.Chain[0]
			return ch.label() + ": the certificate names an OCSP responder (" + strings.Join(l.OCSPServers, ", ") + ") but no response was stapled", "",
				len(l.OCSPServers) > 0 && ch.view.OCSP == nil && !l.OCSPMustStaple
		}),
	chainRule("CT.NO-SCTS", "Public certificate carries no Certificate Transparency proof", "revocation", Medium,
		[]Citation{citRFC6962, citChromeCT},
		"Use a certificate from a CA that embeds SCTs (all major public CAs do), or deliver SCTs in the TLS extension.",
		func(c *ctx, ch *chain) (string, Severity, bool) {
			return ch.label() + ": no SCT embedded, in the TLS extension or in a stapled OCSP response", "",
				ch.view.Public && len(ch.view.SCTs) == 0
		}),

	// ---- key exchange ----
	{
		id: "KX.DH-COMMON-PRIME", title: "DHE uses a small, widely shared published prime", category: "key-exchange", severity: Medium, evidence: Observed,
		citations:   []Citation{citLogjam, citRFC7919},
		remediation: "Use an RFC 7919 group of at least 2048 bits (ffdhe2048 or larger), or drop DHE in favour of ECDHE.",
		check: func(c *ctx) []hit {
			if c.rep.DH == nil {
				return nil
			}
			p, ok := refdata.LookupDHPrime(c.rep.DH.PrimeSHA256)
			if !ok || p.Bits > 1024 {
				return nil
			}
			return one(fmt.Sprintf("the DHE prime is %s (%s), %d bits: one precomputation breaks every server that uses it", p.Name, p.Source, p.Bits))
		},
	},

	// ---- HTTP ----
	{
		id: "HTTP.HSTS-DISABLED", title: "HSTS is switched off (max-age=0)", category: "http", severity: Medium, evidence: Observed,
		citations: []Citation{citRFC6797}, remediation: "Send max-age of at least one year (31536000). max-age=0 tells browsers to forget the HSTS policy.",
		check: func(c *ctx) []hit {
			h := c.rep.HSTSHeader
			if h.Valid() && *h.MaxAge == 0 {
				return one("Strict-Transport-Security: " + h.Values[0])
			}
			return nil
		},
	},
	{
		id: "HTTP.HSTS-SHORT", title: "HSTS max-age is shorter than one year", category: "http", severity: Low, evidence: Observed,
		citations: []Citation{citRFC6797, citHSTSPre}, remediation: "Raise max-age to at least 31536000 seconds (one year), the HSTS preload list's minimum.",
		check: func(c *ctx) []hit {
			h := c.rep.HSTSHeader
			if h.Valid() && *h.MaxAge > 0 && *h.MaxAge < 31536000 {
				if *h.MaxAge < 86400 {
					return one(fmt.Sprintf("max-age is %d seconds (under a day)", *h.MaxAge))
				}
				return one(fmt.Sprintf("max-age is %d seconds (%d days)", *h.MaxAge, *h.MaxAge/86400))
			}
			return nil
		},
	},
	{
		id: "HTTP.HSTS-INVALID", title: "The HSTS header is invalid", category: "http", severity: Medium, evidence: Observed,
		citations: []Citation{citRFC6797}, remediation: "Send exactly one Strict-Transport-Security header with one max-age directive; browsers ignore an invalid header entirely.",
		check: func(c *ctx) []hit {
			h := c.rep.HSTSHeader
			if h != nil && len(h.Values) > 0 && len(h.Problems) > 0 {
				return one(strings.Join(h.Problems, "; "))
			}
			return nil
		},
	},
	{
		id: "HTTP.HSTS-NO-SUBDOMAINS", title: "HSTS does not cover subdomains", category: "http", severity: Info, evidence: Observed,
		citations: []Citation{citRFC6797}, remediation: "Add includeSubDomains once every subdomain serves HTTPS.",
		check: func(c *ctx) []hit {
			h := c.rep.HSTSHeader
			if h.Valid() && *h.MaxAge > 0 && !h.IncludeSubDomains {
				return one("includeSubDomains is not set")
			}
			return nil
		},
	},

	// ---- suites and vulnerabilities ----
	{
		id: "CIPHER.CBC", title: "CBC-mode cipher suites are accepted", category: "cipher", severity: Info, evidence: Observed,
		citations: []Citation{citRFC9325, citLucky13}, remediation: "Prefer AEAD suites (AES-GCM, ChaCha20-Poly1305); remove CBC suites once no client needs them.",
		check: func(c *ctx) []hit {
			m := filter(c.suites, func(s tlsprobe.SuiteResult) bool { return isCBC(s) && s.Version != "TLSv1.3" })
			if len(m) > 0 {
				return one(fmt.Sprintf("%d accepted suite(s): %s", len(m), names(m)))
			}
			return nil
		},
	},
	{
		id: "VULN.DROWN-SHARED-KEY", title: "DROWN: this key is also served on an SSLv2 endpoint", category: "vulnerability", severity: High, evidence: Inferred,
		citations: []Citation{citDROWN}, remediation: "Disable SSLv2 on the endpoints named, or stop using this key there; an attacker can use them to decrypt this endpoint's traffic.",
		v2Only: true,
		check: func(c *ctx) []hit {
			var hits []hit
			seen := map[string]bool{}
			for _, ch := range c.chains {
				if ch.served == nil {
					continue
				}
				k := ch.cr.Chain[0].SPKISHA256
				if eps := c.in.SSLv2Keys[k]; len(eps) > 0 && !seen[k] {
					seen[k] = true
					hits = append(hits, hit{detail: fmt.Sprintf("%s: the same public key is served with SSLv2 enabled on %s (inferred; the attack was not attempted)",
						ch.label(), strings.Join(eps, ", "))})
				}
			}
			return hits
		},
	},
}
