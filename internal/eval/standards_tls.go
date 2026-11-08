package eval

import (
	"crypto/rsa"
	"fmt"
	"strings"
	"time"

	"github.com/offsetsecurity/cipherhorizon/internal/tlsprobe"
)

// The TLS standards. Every clause below was read from the document named in the standard's
// Edition, on the date of the transcription (2026-11-08); the clause column is the document's own
// numbering. Where a document gives a "use up to" year (BSI), the year is applied at evaluation
// time, so a verdict changes when the document says it should, not when this program is rebuilt.

var tlsStandards = []*Standard{&bcp195, &nistSP80052, &bsiTR021022, &anssiTLS, &mozillaModern, &mozillaIntermediate, &pciDSS4, &cnsa2TLS}

const (
	v13  = "TLSv1.3"
	v12  = "TLSv1.2"
	v11  = "TLSv1.1"
	v10  = "TLSv1.0"
	ssl3 = "SSLv3"
	ssl2 = "SSLv2"
)

// req is a TLS requirement.
func req(id, clause, level, text string, check func(*tlsCheck) Verdict) Requirement {
	return Requirement{ID: id, Clause: clause, Level: level, Text: text, check: check}
}

// ---- RFC 9325 (BCP 195) -----------------------------------------------------------------------------

var bcp195 = Standard{
	ID: "bcp195", Title: "RFC 9325 (BCP 195)", Publisher: "IETF", Edition: "November 2022", Protocol: "tls",
	URL:   "https://www.rfc-editor.org/rfc/rfc9325",
	Scope: "The IETF's best current practice for deploying TLS; the baseline most other guidance builds on.",
	Requirements: []Requirement{
		req("versions", "§3.1.1", LevelMust, "SSL 2.0, SSL 3.0, TLS 1.0 and TLS 1.1 are not negotiated (MUST NOT)",
			func(t *tlsCheck) Verdict { return t.versionsNotAllowed(ssl2, ssl3, v10, v11) }),
		req("tls12", "§3.1.1", LevelMust, "TLS 1.2 is supported (MUST)", func(t *tlsCheck) Verdict { return t.versionRequired(v12) }),
		req("tls13", "§3.1.1", LevelShould, "TLS 1.3 is supported (SHOULD)", func(t *tlsCheck) Verdict { return t.versionRequired(v13) }),
		req("compression", "§3.3", LevelShould, "TLS-level compression is not supported (SHOULD NOT)", func(t *tlsCheck) Verdict {
			return t.feature(t.rep.Features.Compression, false, "DEFLATE compression is refused", "the server accepted DEFLATE compression", "compression was not probed")
		}),
		req("reneg", "§3.5", LevelMust, "TLS 1.2 servers implement renegotiation_info (MUST)", func(t *tlsCheck) Verdict {
			if !t.pre13() {
				return notApplicable("only TLS 1.3 is supported")
			}
			return t.feature(t.rep.Features.SecureRenegotiation, true, "renegotiation_info is echoed", "renegotiation_info is not echoed", "the extension was not observed")
		}),
		req("ems", "§3.5", LevelMust, "TLS 1.2 servers support extended_master_secret (MUST)", func(t *tlsCheck) Verdict {
			if !t.pre13() {
				return notApplicable("only TLS 1.3 is supported")
			}
			return t.feature(t.rep.Features.ExtendedMasterSecret, true, "extended_master_secret is echoed", "extended_master_secret is not echoed", "the extension was not observed")
		}),
		req("no-null-rc4-export", "§4.1", LevelMust, "No NULL, RC4 or export suite, nor any under 112 bits (MUST NOT)", func(t *tlsCheck) Verdict {
			return t.noSuite(func(s tlsprobe.SuiteResult) bool {
				return s.Cipher == "NULL" || s.Cipher == "RC4" || s.Export || s.Cipher == "DES" || s.Cipher == "IDEA" && s.KeyBits < 112 || s.KeyBits > 0 && s.KeyBits < 112 && s.Cipher != "3DES"
			}, "forbidden suites accepted", "no NULL, RC4, export or sub-112-bit suite")
		}),
		req("no-under-128", "§4.1", LevelShould, "No suite under 128 bits of security, such as 3DES (SHOULD NOT)", func(t *tlsCheck) Verdict {
			return t.noSuite(func(s tlsprobe.SuiteResult) bool { return s.Cipher == "3DES" || s.Cipher == "RC2" }, "suites under 128 bits accepted", "every suite's cipher is 128 bits or more")
		}),
		req("no-static-rsa", "§4.1", LevelShould, "No RSA key transport (static RSA) suite (SHOULD NOT)", func(t *tlsCheck) Verdict {
			return t.noSuite(func(s tlsprobe.SuiteResult) bool { return s.Kx == "RSA" }, "RSA key-transport suites accepted", "no static RSA suite")
		}),
		req("no-static-dh", "§4.1", LevelShould, "No static (non-ephemeral) finite-field or elliptic-curve DH suite (SHOULD NOT)", func(t *tlsCheck) Verdict {
			return t.noSuite(func(s tlsprobe.SuiteResult) bool { return s.Kx == "DH" || s.Kx == "ECDH" }, "static DH suites accepted", "no static DH suite")
		}),
		req("fs-preferred", "§4.1", LevelMust, "Forward-secrecy suites are supported and preferred (MUST)", func(t *tlsCheck) Verdict {
			if !t.stageRan(tlsprobe.StageSuites) {
				return notAssessed("the cipher-suite stage did not run")
			}
			fs := func(s tlsprobe.SuiteResult) bool { return s.Version == v13 || s.Ephemeral }
			any := false
			for _, v := range t.supportedVersions() {
				var firstFS, firstNon int
				for _, s := range t.byVersion[v] {
					if fs(s) {
						any = true
						if firstFS == 0 && s.Rank > 0 {
							firstFS = s.Rank
						}
					} else if firstNon == 0 && s.Rank > 0 {
						firstNon = s.Rank
					}
				}
				if firstNon > 0 && (firstFS == 0 || firstNon < firstFS) {
					return notMet("on " + v + " the server ranks a non-forward-secrecy suite above every forward-secrecy suite")
				}
			}
			if !any {
				if len(t.suites) == 0 {
					return notAssessed("no cipher suite was enumerated")
				}
				return notMet("no forward-secrecy suite is accepted")
			}
			return met("forward-secrecy suites are accepted and ranked first where the server decides")
		}),
		req("no-dhe", "§4.1", LevelShould, "TLS 1.2 does not negotiate finite-field DHE suites (SHOULD NOT)", func(t *tlsCheck) Verdict {
			return t.noSuite(func(s tlsprobe.SuiteResult) bool { return s.Kx == "DHE" }, "TLS_DHE_* suites accepted", "no finite-field DHE suite")
		}),
		req("cbc-etm", "§4.2", LevelShould, "CBC suites only with encrypt_then_mac (SHOULD NOT otherwise)", func(t *tlsCheck) Verdict { return t.etmWhenCBC() }),
		req("recommended", "§4.2", LevelShould, "A RECOMMENDED TLS 1.2 suite is accepted (ECDHE with AES-GCM)", func(t *tlsCheck) Verdict {
			if !t.supported[v12] {
				return notApplicable("TLS 1.2 is not supported")
			}
			for _, s := range t.byVersion[v12] {
				switch s.Name {
				case "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
					"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384":
					return met(s.Name + " is accepted")
				}
			}
			if len(t.byVersion[v12]) == 0 {
				return notAssessed("no TLS 1.2 suite was enumerated")
			}
			return notMet("none of the four recommended suites is accepted")
		}),
		req("dh-2048", "§4.5", LevelMust, "DHE groups are at least 2048 bits (REQUIRED)", func(t *tlsCheck) Verdict { return t.minDH(2048) }),
		req("curve-224", "§4.5", LevelMust, "No elliptic curve under 224 bits (MUST NOT)", func(t *tlsCheck) Verdict { return t.minCurve(224) }),
		req("rsa-2048", "§4.5", LevelMust, "The certificate's public key is at least RSA 2048 (MUST)", func(t *tlsCheck) Verdict { return t.certKeyAtLeast(2048, 224) }),
		req("sig-hash", "§4.5", LevelMust, "The certificate is not signed with SHA-1 or MD5 (MUST NOT)", func(t *tlsCheck) Verdict { return t.certSignedSHA2() }),
		req("hsts", "§3.2", LevelShould, "Web servers use HTTP Strict Transport Security (SHOULD)", func(t *tlsCheck) Verdict { return t.hstsAtLeast(1) }),
		req("stapling", "§7.5", LevelShould, "The server supports OCSP stapling (SHOULD)", func(t *tlsCheck) Verdict { return t.ocspStapled() }),
	},
	NotAssessed: []string{
		"§3.7 SNI and §3.8 ALPN support (the scan always sends both, so a refusal is not observable)",
		"§3.4 session-ticket key rotation and lifetime", "§3.10 0-RTT data", "§4.6 the truncated HMAC extension (never offered by the scan)",
		"§7.4 reuse of ephemeral DH values across connections",
	},
}

// ---- NIST SP 800-52 Rev. 2 --------------------------------------------------------------------------

// nistApproved are the cipher suites SP 800-52 Rev. 2 §3.3.1 lists for TLS 1.2 and earlier (by
// certificate type), Appendix C (pre-shared keys) and Appendix D (RSA key transport, transitional).
// "Cipher suites that do not appear in this section, Appendix C, or Appendix D shall not be used."
var nistApproved12 = []string{
	// §3.3.1.1.1 ECDSA certificates
	"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", "TLS_ECDHE_ECDSA_WITH_AES_128_CCM", "TLS_ECDHE_ECDSA_WITH_AES_256_CCM",
	"TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8", "TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8", "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256", "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
	"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA", "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
	// §3.3.1.1.2 RSA certificates
	"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
	"TLS_DHE_RSA_WITH_AES_128_CCM", "TLS_DHE_RSA_WITH_AES_256_CCM", "TLS_DHE_RSA_WITH_AES_128_CCM_8", "TLS_DHE_RSA_WITH_AES_256_CCM_8",
	"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256", "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384", "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256", "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
	"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA", "TLS_DHE_RSA_WITH_AES_128_CBC_SHA", "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
	// §3.3.1.1.3 DSA certificates
	"TLS_DHE_DSS_WITH_AES_128_GCM_SHA256", "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384", "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256", "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256",
	"TLS_DHE_DSS_WITH_AES_128_CBC_SHA", "TLS_DHE_DSS_WITH_AES_256_CBC_SHA",
	// §3.3.1.1.4 DH certificates
	"TLS_DH_DSS_WITH_AES_128_GCM_SHA256", "TLS_DH_DSS_WITH_AES_256_GCM_SHA384", "TLS_DH_DSS_WITH_AES_128_CBC_SHA256", "TLS_DH_DSS_WITH_AES_256_CBC_SHA256",
	"TLS_DH_DSS_WITH_AES_128_CBC_SHA", "TLS_DH_DSS_WITH_AES_256_CBC_SHA",
	"TLS_DH_RSA_WITH_AES_128_GCM_SHA256", "TLS_DH_RSA_WITH_AES_256_GCM_SHA384", "TLS_DH_RSA_WITH_AES_128_CBC_SHA256", "TLS_DH_RSA_WITH_AES_256_CBC_SHA256",
	"TLS_DH_RSA_WITH_AES_128_CBC_SHA", "TLS_DH_RSA_WITH_AES_256_CBC_SHA",
	// §3.3.1.1.5 ECDH certificates
	"TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256", "TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384", "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256", "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384",
	"TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA", "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA",
	"TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256", "TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384", "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256", "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384",
	"TLS_ECDH_RSA_WITH_AES_128_CBC_SHA", "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA",
	// Appendix C: pre-shared keys
	"TLS_DHE_PSK_WITH_AES_128_GCM_SHA256", "TLS_DHE_PSK_WITH_AES_256_GCM_SHA384", "TLS_DHE_PSK_WITH_AES_128_CCM", "TLS_DHE_PSK_WITH_AES_256_CCM",
	"TLS_PSK_DHE_WITH_AES_128_CCM_8", "TLS_PSK_DHE_WITH_AES_256_CCM_8", "TLS_DHE_PSK_WITH_AES_128_CBC_SHA256", "TLS_DHE_PSK_WITH_AES_256_CBC_SHA384",
	"TLS_DHE_PSK_WITH_AES_128_CBC_SHA", "TLS_DHE_PSK_WITH_AES_256_CBC_SHA", "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256", "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384",
	"TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA", "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA", "TLS_PSK_WITH_AES_128_GCM_SHA256", "TLS_PSK_WITH_AES_256_GCM_SHA384",
	"TLS_PSK_WITH_AES_128_CCM", "TLS_PSK_WITH_AES_256_CCM", "TLS_PSK_WITH_AES_128_CCM_8", "TLS_PSK_WITH_AES_256_CCM_8",
	"TLS_PSK_WITH_AES_128_CBC_SHA256", "TLS_PSK_WITH_AES_256_CBC_SHA384", "TLS_PSK_WITH_AES_128_CBC_SHA", "TLS_PSK_WITH_AES_256_CBC_SHA",
	// Appendix D: RSA key transport, during a transition only
	"TLS_RSA_WITH_AES_128_GCM_SHA256", "TLS_RSA_WITH_AES_256_GCM_SHA384", "TLS_RSA_WITH_AES_128_CCM", "TLS_RSA_WITH_AES_256_CCM",
	"TLS_RSA_WITH_AES_128_CCM_8", "TLS_RSA_WITH_AES_256_CCM_8", "TLS_RSA_WITH_AES_128_CBC_SHA256", "TLS_RSA_WITH_AES_256_CBC_SHA256",
	"TLS_RSA_WITH_AES_128_CBC_SHA", "TLS_RSA_WITH_AES_256_CBC_SHA",
}

var nistApproved13 = []string{"TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384", "TLS_AES_128_CCM_SHA256", "TLS_AES_128_CCM_8_SHA256"}

var nistSP80052 = Standard{
	ID: "nist-sp800-52r2", Title: "NIST SP 800-52 Rev. 2", Publisher: "NIST", Edition: "August 2019", Protocol: "tls",
	URL:   "https://csrc.nist.gov/pubs/sp/800/52/r2/final",
	Scope: "Guidelines for the selection, configuration and use of TLS by US federal agencies; the reference most FIPS-bound deployments follow.",
	Requirements: []Requirement{
		req("tls12", "§3.1", LevelMust, "Servers shall be configured to use TLS 1.2", func(t *tlsCheck) Verdict { return t.versionRequired(v12) }),
		req("tls13", "§3.1", LevelMust, "Servers shall support TLS 1.3 (by 1 January 2024)", func(t *tlsCheck) Verdict { return t.versionRequired(v13) }),
		req("no-ssl", "§3.1", LevelMust, "SSL 2.0 and SSL 3.0 shall not be used", func(t *tlsCheck) Verdict { return t.versionsNotAllowed(ssl2, ssl3) }),
		req("no-tls10", "§3.1", LevelShould, "TLS 1.0 is not used (shall not on government-only servers; discouraged for citizen-facing ones)",
			func(t *tlsCheck) Verdict { return t.versionsNotAllowed(v10) }),
		req("no-tls11", "§3.1", LevelShould, "TLS 1.1 is not used (should not on government-only servers; discouraged for citizen-facing ones)",
			func(t *tlsCheck) Verdict { return t.versionsNotAllowed(v11) }),
		req("suites", "§3.3.1", LevelMust, "Only cipher suites from §3.3.1, Appendix C or Appendix D are used (NIST-approved algorithms; 3DES no longer allowed)",
			func(t *tlsCheck) Verdict {
				return t.suitesOnly(map[string][]string{v13: nistApproved13, v12: nistApproved12, v11: nistApproved12, v10: nistApproved12}, "SP 800-52 Rev. 2 §3.3.1")
			}),
		req("rsa-transport", "§3.3.1, App. D", LevelShould, "RSA key transport is not used (deprecated; Appendix D allows it only during a transition)",
			func(t *tlsCheck) Verdict {
				return t.noSuite(func(s tlsprobe.SuiteResult) bool { return s.Kx == "RSA" }, "RSA key-transport suites accepted", "no RSA key-transport suite")
			}),
		req("ephemeral-112", "§3.3.1", LevelMust, "Ephemeral keys provide at least 112 bits of security (DH 2048, curves 224 and above)", func(t *tlsCheck) Verdict {
			dh := t.minDH(2048)
			if dh.Status == ReqNotMet {
				return dh
			}
			cv := t.minCurve(224)
			if cv.Status == ReqNotMet || dh.Status == ReqNotAssessed {
				return cv
			}
			return met(strings.TrimSuffix(dh.Detail+"; "+cv.Detail, "; "))
		}),
		req("cert-type", "§3.2", LevelMust, "The server is configured with an RSA or ECDSA signature certificate", func(t *tlsCheck) Verdict {
			return t.certs(func(_ *chain, leaf tlsprobe.CertInfo) Verdict {
				switch leaf.PublicKey.Algorithm {
				case "RSA", "ECDSA":
					return met(keyWords(leaf.PublicKey))
				case "DSA":
					return met("a DSA certificate (listed, though uncommon)")
				}
				return notMet(leaf.PublicKey.Algorithm + " is not an RSA or ECDSA signature certificate")
			})
		}),
		req("cert-curve", "§3.2", LevelShould, "An ECDSA certificate uses P-256 or P-384", func(t *tlsCheck) Verdict {
			return t.certs(func(_ *chain, leaf tlsprobe.CertInfo) Verdict {
				if leaf.PublicKey.Algorithm != "ECDSA" {
					return notApplicable("not an ECDSA certificate")
				}
				if curveNamed(leaf.PublicKey.Curve, "P-256", "P-384") {
					return met(keyWords(leaf.PublicKey))
				}
				return notMet(keyWords(leaf.PublicKey))
			})
		}),
		req("cert-112", "§3.2.1", LevelMust, "The certificate's key and signature each provide at least 112 bits of security", func(t *tlsCheck) Verdict {
			k := t.certKeyAtLeast(2048, 224)
			if k.Status != ReqMet {
				return k
			}
			s := t.certSignedSHA2()
			if s.Status != ReqMet {
				return s
			}
			return met(k.Detail + "; " + s.Detail)
		}),
		req("cert-ocsp", "§3.2", LevelMust, "The certificate is issued by a CA that publishes OCSP, and names the source", func(t *tlsCheck) Verdict { return t.certRevocationSource(true) }),
		req("cert-eku", "§3.2.1", LevelShould, "The certificate's extended key usage allows server authentication", func(t *tlsCheck) Verdict { return t.certEKUServerAuth() }),
		req("cert-san", "§3.2.1, Table 3-1", LevelShould, "The server's DNS name is in the subjectAltName", func(t *tlsCheck) Verdict { return t.certHasSAN() }),
		req("reneg", "§3.4.1.1", LevelMust, "Renegotiation indication (RFC 5746) is supported", func(t *tlsCheck) Verdict {
			if !t.pre13() {
				return notApplicable("only TLS 1.3 is supported")
			}
			return t.feature(t.rep.Features.SecureRenegotiation, true, "renegotiation_info is echoed", "renegotiation_info is not echoed", "the extension was not observed")
		}),
		req("ems", "§3.4.1.3", LevelMust, "Extended master secret (RFC 7627) is supported", func(t *tlsCheck) Verdict {
			if !t.pre13() {
				return notApplicable("only TLS 1.3 is supported")
			}
			return t.feature(t.rep.Features.ExtendedMasterSecret, true, "extended_master_secret is echoed", "extended_master_secret is not echoed", "the extension was not observed")
		}),
		req("stapling", "§3.4.1.5", LevelMust, "A server whose CA supports OCSP staples the certificate status", func(t *tlsCheck) Verdict {
			src := t.certRevocationSource(true)
			if src.Status == ReqNotMet {
				return notApplicable("the certificate names no OCSP responder")
			}
			if src.Status != ReqMet {
				return src
			}
			return t.ocspStapled()
		}),
		req("scsv", "§3.4.2.1", LevelMust, "TLS_FALLBACK_SCSV is supported when more than one version is enabled", func(t *tlsCheck) Verdict {
			if len(t.supportedVersions()) < 2 {
				return notApplicable("one protocol version only")
			}
			return t.feature(t.rep.Features.FallbackSCSV, true, "a downgraded hello with the SCSV is refused", "a downgraded hello with the SCSV is answered", "the SCSV was not probed")
		}),
		req("groups", "§3.4.2.2", LevelMust, "P-256 or P-384 is supported when elliptic-curve suites or TLS 1.3 are configured", func(t *tlsCheck) Verdict {
			if !t.stageRan(tlsprobe.StageKeyExchange) {
				return notAssessed("the key-exchange stage did not run")
			}
			if len(t.rep.Groups) == 0 {
				return notAssessed("no key-exchange group was enumerated")
			}
			if g, ok := t.hasGroup("secp256r1", "secp384r1"); ok {
				return met(g + " is supported")
			}
			return notMet("neither secp256r1 nor secp384r1 is accepted: " + groupNameList(t.rep.Groups))
		}),
		req("etm", "§3.4.2.7", LevelMust, "Encrypt-then-MAC is supported when CBC suites are configured", func(t *tlsCheck) Verdict { return t.etmWhenCBC() }),
		req("compression", "§3.7", LevelMust, "Only the null compression method is enabled", func(t *tlsCheck) Verdict {
			return t.feature(t.rep.Features.Compression, false, "DEFLATE compression is refused", "the server accepted DEFLATE compression", "compression was not probed")
		}),
	},
	NotAssessed: []string{
		"§3.3.3 FIPS 140 validation of the cryptographic module", "§3.4.1.2 SNI handling (the scan always sends SNI)",
		"§3.4.1.4 processing of the signature_algorithms extension", "§3.4.2.8 the truncated HMAC extension (never offered)",
		"§3.5 client authentication", "§3.6 session resumption lifetimes and 0-RTT", "§3.8 operational controls",
	},
}

// ---- BSI TR-02102-2 (2026-01) ------------------------------------------------------------------------

// bsiUntil maps a name to the last year BSI recommends it (TR-02102-2 Tables 3 to 6, 10 and 13).
type bsiUntil map[string]int

func (u bsiUntil) allowedIn(year int) []string {
	var out []string
	for n, y := range u {
		if year <= y {
			out = append(out, n)
		}
	}
	return out
}

var bsiSuites12 = bsiUntil{
	// Table 3: with forward secrecy
	"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256": 2031, "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384": 2031, "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256": 2031,
	"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384": 2031, "TLS_ECDHE_ECDSA_WITH_AES_128_CCM": 2031, "TLS_ECDHE_ECDSA_WITH_AES_256_CCM": 2031,
	"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256": 2031, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384": 2031, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256": 2031,
	"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384": 2031,
	"TLS_DHE_DSS_WITH_AES_128_CBC_SHA256":   2029, "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256": 2029, "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256": 2029,
	"TLS_DHE_DSS_WITH_AES_256_GCM_SHA384": 2029, "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256": 2029, "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256": 2029,
	"TLS_DHE_RSA_WITH_AES_128_GCM_SHA256": 2029, "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384": 2029, "TLS_DHE_RSA_WITH_AES_128_CCM": 2029, "TLS_DHE_RSA_WITH_AES_256_CCM": 2029,
	// Table 4: without forward secrecy
	"TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256": 2026, "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384": 2026, "TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256": 2026,
	"TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384": 2026, "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256": 2026, "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384": 2026,
	"TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256": 2026, "TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384": 2026, "TLS_DH_DSS_WITH_AES_128_CBC_SHA256": 2026,
	"TLS_DH_DSS_WITH_AES_256_CBC_SHA256": 2026, "TLS_DH_DSS_WITH_AES_128_GCM_SHA256": 2026, "TLS_DH_DSS_WITH_AES_256_GCM_SHA384": 2026,
	"TLS_DH_RSA_WITH_AES_128_CBC_SHA256": 2026, "TLS_DH_RSA_WITH_AES_256_CBC_SHA256": 2026, "TLS_DH_RSA_WITH_AES_128_GCM_SHA256": 2026,
	"TLS_DH_RSA_WITH_AES_256_GCM_SHA384": 2026,
	// Table 5: pre-shared keys
	"TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256": 2031, "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384": 2031, "TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256": 2031,
	"TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384": 2031, "TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256": 2031,
	"TLS_DHE_PSK_WITH_AES_128_CBC_SHA256": 2029, "TLS_DHE_PSK_WITH_AES_256_CBC_SHA384": 2029, "TLS_DHE_PSK_WITH_AES_128_GCM_SHA256": 2029,
	"TLS_DHE_PSK_WITH_AES_256_GCM_SHA384": 2029, "TLS_DHE_PSK_WITH_AES_128_CCM": 2029, "TLS_DHE_PSK_WITH_AES_256_CCM": 2029,
	"TLS_RSA_PSK_WITH_AES_128_CBC_SHA256": 2026, "TLS_RSA_PSK_WITH_AES_256_CBC_SHA384": 2026, "TLS_RSA_PSK_WITH_AES_128_GCM_SHA256": 2026,
	"TLS_RSA_PSK_WITH_AES_256_GCM_SHA384": 2026,
}

var bsiSuites13 = bsiUntil{"TLS_AES_128_GCM_SHA256": 2099, "TLS_AES_256_GCM_SHA384": 2099, "TLS_AES_128_CCM_SHA256": 2099}

var bsiGroups12 = bsiUntil{"secp256r1": 2031, "secp384r1": 2031, "secp521r1": 2031, "brainpoolP256r1": 2031, "brainpoolP384r1": 2031, "brainpoolP512r1": 2031,
	"ffdhe3072": 2029, "ffdhe4096": 2029}

// Table 10, plus the hybrid groups BSI's TR-02102 page (2026) says may now be used TR-compliant in
// TLS 1.3: SecP256r1MLKEM768, SecP384r1MLKEM1024 and, in addition, X25519MLKEM768.
var bsiGroups13 = bsiUntil{"secp256r1": 2031, "secp384r1": 2031, "secp521r1": 2031, "brainpoolP256r1tls13": 2031, "brainpoolP384r1tls13": 2031,
	"brainpoolP512r1tls13": 2031, "ffdhe3072": 2031, "ffdhe4096": 2031, "SecP256r1MLKEM768": 2099, "SecP384r1MLKEM1024": 2099, "X25519MLKEM768": 2099}

// Table 11: the signature_algorithms values recommended for TLS 1.3.
var bsiSchemes13 = []string{"rsa_pss_rsae_sha256", "rsa_pss_rsae_sha384", "rsa_pss_rsae_sha512", "rsa_pss_pss_sha256", "rsa_pss_pss_sha384", "rsa_pss_pss_sha512",
	"ecdsa_secp256r1_sha256", "ecdsa_secp384r1_sha384", "ecdsa_secp521r1_sha512", "ecdsa_brainpoolP256r1tls13_sha256", "ecdsa_brainpoolP384r1tls13_sha384",
	"ecdsa_brainpoolP512r1tls13_sha512"}

func (t *tlsCheck) bsiGroupsOnly() Verdict {
	if !t.stageRan(tlsprobe.StageKeyExchange) {
		return notAssessed("the key-exchange stage did not run")
	}
	y := t.now.Year()
	ok12, ok13 := map[string]bool{}, map[string]bool{}
	for _, n := range bsiGroups12.allowedIn(y) {
		ok12[strings.ToLower(n)] = true
	}
	for _, n := range bsiGroups13.allowedIn(y) {
		ok13[strings.ToLower(n)] = true
	}
	var bad []tlsprobe.GroupResult
	for _, g := range t.rep.Groups {
		ok := ok12
		if g.Version == v13 {
			ok = ok13
		}
		if !ok[strings.ToLower(g.Name)] {
			bad = append(bad, g)
		}
	}
	if len(bad) > 0 {
		return notMet("accepted but not recommended (Tables 6 and 10): " + groupNameList(bad))
	}
	if len(t.rep.Groups) == 0 {
		return notAssessed("no key-exchange group was enumerated")
	}
	return met("every accepted group is recommended: " + groupNameList(t.rep.Groups))
}

var bsiTR021022 = Standard{
	ID: "bsi-tr-02102-2", Title: "BSI TR-02102-2", Publisher: "BSI (Germany)", Edition: "Version 2026-01", Protocol: "tls",
	URL:   "https://www.bsi.bund.de/EN/Themen/Unternehmen-und-Organisationen/Standards-und-Zertifizierung/Technische-Richtlinien/TR-nach-Thema-sortiert/tr02102/tr02102_node.html",
	Scope: "The German Federal Office for Information Security's recommendations for TLS, at a 120-bit security level, with a year each mechanism may be used until.",
	Requirements: []Requirement{
		req("versions", "§3.2, Table 2", LevelMust, "Only TLS 1.2 (until 2031) and TLS 1.3 are used; TLS 1.0, 1.1, SSL v2 and v3 are not recommended",
			func(t *tlsCheck) Verdict {
				if t.now.Year() > 2031 && t.supported[v12] {
					return notMet("TLS 1.2 is recommended only until the end of 2031")
				}
				return t.versionsNotAllowed(ssl2, ssl3, v10, v11)
			}),
		req("tls13", "§3.2", LevelShould, "TLS 1.3 should be used in preference", func(t *tlsCheck) Verdict { return t.versionRequired(v13) }),
		req("suites12", "§3.3.1, Tables 3 to 5", LevelMust, "TLS 1.2 accepts only recommended cipher suites, within their period of use", func(t *tlsCheck) Verdict {
			if !t.supported[v12] && !t.supported[v11] && !t.supported[v10] {
				return notApplicable("TLS 1.2 is not supported")
			}
			ok := bsiSuites12.allowedIn(t.now.Year())
			return t.suitesOnly(map[string][]string{v12: ok, v11: ok, v10: ok}, "TR-02102-2 Tables 3 to 5 for "+fmt.Sprint(t.now.Year()))
		}),
		req("suites13", "§3.4.4, Table 13", LevelMust, "TLS 1.3 accepts only TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384 and TLS_AES_128_CCM_SHA256", func(t *tlsCheck) Verdict {
			if !t.supported[v13] {
				return notApplicable("TLS 1.3 is not supported")
			}
			return t.suitesOnly(map[string][]string{v13: bsiSuites13.allowedIn(t.now.Year())}, "TR-02102-2 Table 13")
		}),
		req("cbc-etm", "§3.3.1, §3.3.4.5", LevelMust, "CBC suites only together with the Encrypt-then-MAC extension", func(t *tlsCheck) Verdict { return t.etmWhenCBC() }),
		req("groups", "§3.3.2 Table 6, §3.4.2 Table 10", LevelMust, "Only recommended Diffie-Hellman groups are accepted (NIST and Brainpool curves, ffdhe3072, ffdhe4096; the ML-KEM hybrids BSI now allows)",
			func(t *tlsCheck) Verdict { return t.bsiGroupsOnly() }),
		req("pq-hybrid", "§3.1.3, §3.4.2", LevelShould, "A quantum-safe hybrid key agreement is offered (classical key agreement alone is recommended only until the end of 2031)",
			func(t *tlsCheck) Verdict {
				return t.hybridPQ("SecP256r1MLKEM768", "SecP384r1MLKEM1024", "X25519MLKEM768")
			}),
		req("schemes13", "§3.4.3, Table 11", LevelMust, "TLS 1.3 accepts only recommended signature algorithms (RSA-PSS, ECDSA on recommended curves)", func(t *tlsCheck) Verdict {
			if !t.supported[v13] {
				return notApplicable("TLS 1.3 is not supported")
			}
			acc, ok := t.schemesAccepted()
			if !ok {
				return notAssessed("the signature stage was inconclusive or did not run")
			}
			var bad []string
			for _, s := range acc {
				if !contains(bsiSchemes13, s) {
					bad = append(bad, s)
				}
			}
			if len(bad) > 0 {
				return notMet("accepted but not in Table 11: " + strings.Join(bad, ", "))
			}
			if len(acc) == 0 {
				return notAssessed("no signature scheme was proved accepted")
			}
			return met("accepted schemes: " + strings.Join(acc, ", "))
		}),
		req("cert-sig", "§3.4.3, Table 12; §3.3.3, Table 7", LevelMust, "The certificate is signed with RSA-PSS or ECDSA using SHA-256 or longer (PKCS #1 v1.5 recommended only until 2025)",
			func(t *tlsCheck) Verdict {
				return t.certs(func(_ *chain, leaf tlsprobe.CertInfo) Verdict {
					n := strings.ToLower(leaf.SignatureAlg.Name)
					switch {
					case sigHash(n) == "weak":
						return notMet("signed with " + leaf.SignatureAlg.Name)
					case strings.Contains(n, "pss"), strings.Contains(n, "ecdsa"):
						if sigHash(n) == "sha2" {
							return met("signed with " + leaf.SignatureAlg.Name)
						}
					case strings.Contains(n, "rsa") && sigHash(n) == "sha2":
						if t.now.Year() > 2025 {
							return notMet("signed with " + leaf.SignatureAlg.Name + " (PKCS #1 v1.5, recommended only until the end of 2025)")
						}
						return met("signed with " + leaf.SignatureAlg.Name + " (PKCS #1 v1.5, recommended until the end of 2025)")
					case sigHash(n) == "pq":
						return met("signed with " + leaf.SignatureAlg.Name + " (quantum-safe)")
					}
					return notMet("signed with " + leaf.SignatureAlg.Name + ", which Tables 7 and 12 do not list")
				})
			}),
		req("keys", "§3.6.1, Table 14", LevelMust, "RSA keys are at least 3000 bits and elliptic-curve keys at least 250 bits", func(t *tlsCheck) Verdict { return t.certKeyAtLeast(3000, 250) }),
		req("dh", "§3.6.1, Table 14", LevelMust, "Finite-field Diffie-Hellman groups are at least 3000 bits", func(t *tlsCheck) Verdict { return t.minDH(3000) }),
		req("reneg", "§3.3.4.1", LevelShould, "Renegotiation only on the basis of RFC 5746", func(t *tlsCheck) Verdict {
			if !t.pre13() {
				return notApplicable("only TLS 1.3 is supported")
			}
			return t.feature(t.rep.Features.SecureRenegotiation, true, "renegotiation_info is echoed", "renegotiation_info is not echoed", "the extension was not observed")
		}),
		req("compression", "§3.3.4.3", LevelShould, "TLS data compression is not used", func(t *tlsCheck) Verdict {
			return t.feature(t.rep.Features.Compression, false, "DEFLATE compression is refused", "the server accepted DEFLATE compression", "compression was not probed")
		}),
		req("etm", "§3.3.4.5", LevelShould, "The Encrypt-then-MAC extension is used", func(t *tlsCheck) Verdict {
			if !t.pre13() {
				return notApplicable("only TLS 1.3 is supported")
			}
			return t.feature(t.rep.Features.EncryptThenMAC, true, "encrypt_then_mac is echoed", "encrypt_then_mac is not echoed", "the extension was not observed")
		}),
		req("heartbeat", "§3.3.4.6, §3.4.5.1", LevelShould, "The Heartbeat extension is not used", func(t *tlsCheck) Verdict {
			return t.feature(t.rep.Features.Heartbeat, false, "the heartbeat extension is not echoed", "the server echoed the heartbeat extension", "the extension was not observed")
		}),
		req("ems", "§3.3.4.7", LevelShould, "The Extended Master Secret extension is used", func(t *tlsCheck) Verdict {
			if !t.pre13() {
				return notApplicable("only TLS 1.3 is supported")
			}
			return t.feature(t.rep.Features.ExtendedMasterSecret, true, "extended_master_secret is echoed", "extended_master_secret is not echoed", "the extension was not observed")
		}),
	},
	NotAssessed: []string{
		"§3.3.3 the TLS 1.2 signature_algorithms values accepted (the scan enumerates signature schemes for TLS 1.3 only)",
		"§3.3.4.2 truncated HMAC (never offered)", "§3.4.1 PSK modes and 0-RTT", "§3.5 certification-path requirements of TR-03116-4",
		"§4 key storage, ephemeral-key deletion and random numbers",
	},
}

// ---- ANSSI TLS guide v1.2 ---------------------------------------------------------------------------

var anssiTLS = Standard{
	ID: "anssi-tls-v1.2", Title: "ANSSI TLS recommendations", Publisher: "ANSSI (France)", Edition: "Version 1.2, 26 March 2020", Protocol: "tls",
	URL:   "https://cyber.gouv.fr/publications/recommandations-de-securite-relatives-tls",
	Scope: "The French national cybersecurity agency's numbered recommendations for TLS servers; R-numbers are the guide's own.",
	Requirements: []Requirement{
		req("r3", "R3", LevelMust, "TLS 1.3 is supported and preferred; TLS 1.2 is accepted under the guide's conditions", func(t *tlsCheck) Verdict { return t.versionRequired(v13) }),
		req("r4", "R4", LevelMust, "SSLv2, SSLv3, TLS 1.0 and TLS 1.1 are not used", func(t *tlsCheck) Verdict { return t.versionsNotAllowed(ssl2, ssl3, v10, v11) }),
		req("r6", "R6", LevelMust, "Every key exchange provides forward secrecy (ECDHE, or DHE); no RSA key transport or static DH", func(t *tlsCheck) Verdict {
			return t.noSuite(func(s tlsprobe.SuiteResult) bool { return s.Version != v13 && !s.Ephemeral }, "suites without forward secrecy accepted", "every suite uses an ephemeral key exchange")
		}),
		req("r7", "R7", LevelMust, "ECDHE uses secp256r1, secp384r1 or secp521r1; x25519, x448 and the Brainpool curves are acceptable", func(t *tlsCheck) Verdict {
			allowed := []string{"secp256r1", "secp384r1", "secp521r1", "x25519", "x448", "brainpoolP256r1", "brainpoolP384r1", "brainpoolP512r1",
				"brainpoolP256r1tls13", "brainpoolP384r1tls13", "brainpoolP512r1tls13", "ffdhe2048", "ffdhe3072", "ffdhe4096", "ffdhe6144", "ffdhe8192",
				"X25519MLKEM768", "SecP256r1MLKEM768", "SecP384r1MLKEM1024"}
			return t.groupsOnly(allowed, "R7 (finite-field groups are judged by R7-)")
		}),
		req("r7-dhe", "R7-", LevelMust, "DHE groups are at least 2048 bits (tolerated until 2030; 3072 recommended)", func(t *tlsCheck) Verdict { return t.minDH(2048) }),
		req("r7-dhe-3072", "R7-", LevelShould, "DHE groups are at least 3072 bits", func(t *tlsCheck) Verdict { return t.minDH(3072) }),
		req("r9", "R9, R9-", LevelMust, "Suites use AES or ChaCha20 (Camellia and ARIA tolerated)", func(t *tlsCheck) Verdict {
			return t.noSuite(func(s tlsprobe.SuiteResult) bool {
				switch s.Cipher {
				case "AES", "CHACHA20", "CAMELLIA", "ARIA":
					return false
				}
				return true
			}, "other ciphers accepted", "every suite uses AES, ChaCha20, Camellia or ARIA")
		}),
		req("r10", "R10, R10-", LevelMust, "Suites use an authenticated-encryption mode (GCM, CCM, ChaCha20-Poly1305); CBC only with encrypt_then_mac; no CCM_8", func(t *tlsCheck) Verdict {
			ccm8 := t.noSuite(func(s tlsprobe.SuiteResult) bool { return s.Mode == "CCM8" }, "CCM_8 suites accepted", "")
			if ccm8.Status == ReqNotMet {
				return ccm8
			}
			other := t.noSuite(func(s tlsprobe.SuiteResult) bool { return !s.AEAD && s.Mode != "CBC" }, "suites that are neither AEAD nor CBC accepted", "")
			if other.Status == ReqNotMet {
				return other
			}
			if v := t.etmWhenCBC(); v.Status != ReqNotApplicable {
				return v
			}
			if len(t.suites) == 0 {
				return notAssessed("no cipher suite was enumerated")
			}
			return met("every suite is an AEAD suite")
		}),
		req("r11", "R11", LevelMust, "Hash functions are from the SHA-2 family (no SHA-1 or MD5 MAC)", func(t *tlsCheck) Verdict {
			return t.noSuite(func(s tlsprobe.SuiteResult) bool { return s.MAC == "SHA1" || s.MAC == "MD5" }, "suites with SHA-1 or MD5 integrity accepted", "every suite uses SHA-2")
		}),
		req("r13", "R13", LevelMust, "The server's cipher-suite order prevails over the client's", func(t *tlsCheck) Verdict { return t.serverOrder() }),
		req("r19", "R19", LevelMust, "TLS compression is not used", func(t *tlsCheck) Verdict {
			return t.feature(t.rep.Features.Compression, false, "DEFLATE compression is refused", "the server accepted DEFLATE compression", "compression was not probed")
		}),
		req("r22", "R22", LevelShould, "The secure-renegotiation extension is enabled", func(t *tlsCheck) Verdict {
			if !t.pre13() {
				return notApplicable("only TLS 1.3 is supported: no renegotiation")
			}
			return t.feature(t.rep.Features.SecureRenegotiation, true, "renegotiation_info is echoed", "renegotiation_info is not echoed", "the extension was not observed")
		}),
		req("r24", "R24", LevelMust, "The certificate is signed with a SHA-2 hash", func(t *tlsCheck) Verdict { return t.certSignedSHA2() }),
		req("r25", "R25", LevelMust, "The certificate is valid for at most 825 days (issued after 1 March 2018)", func(t *tlsCheck) Verdict {
			return t.certValidityAtMost(825, time.Date(2018, 3, 1, 0, 0, 0, 0, time.UTC))
		}),
		req("r26", "R26", LevelMust, "RSA keys are at least 2048 bits with a public exponent of at least 65537; ECDSA keys at least 256 bits on an approved curve", func(t *tlsCheck) Verdict {
			return t.certs(func(ch *chain, leaf tlsprobe.CertInfo) Verdict {
				k := leaf.PublicKey
				switch k.Algorithm {
				case "RSA":
					if k.Bits < 2048 {
						return notMet(keyWords(k))
					}
					if ch.served != nil && len(ch.served.Certs) > 0 && ch.served.Certs[0] != nil {
						if pub, ok := ch.served.Certs[0].PublicKey.(*rsa.PublicKey); ok && pub.E < 65537 {
							return notMet(fmt.Sprintf("RSA public exponent %d", pub.E))
						}
					}
					return met(keyWords(k))
				case "ECDSA":
					if curveNamed(k.Curve, "P-256", "P-384", "P-521", "brainpoolP256r1", "brainpoolP384r1", "brainpoolP512r1") {
						return met(keyWords(k))
					}
					return notMet(keyWords(k) + " is not an approved curve")
				case "Ed25519", "Ed448":
					return notMet(k.Algorithm + " is not among the curves R26 lists")
				}
				if strings.HasPrefix(k.Algorithm, "ML-DSA") {
					return notAssessed(k.Algorithm + " postdates the guide")
				}
				return notAssessed(keyWords(k) + " not classified")
			})
		}),
		req("r28", "R28", LevelShould, "The certificate's ExtendedKeyUsage is appropriate (serverAuth)", func(t *tlsCheck) Verdict { return t.certEKUServerAuth() }),
		req("r29", "R29", LevelMust, "The certificate carries an appropriate SubjectAlternativeName", func(t *tlsCheck) Verdict { return t.certHasSAN() }),
		req("r33", "R33", LevelMust, "The certificate names a revocation source (OCSP responder or CRL)", func(t *tlsCheck) Verdict { return t.certRevocationSource(false) }),
		req("r34", "R34", LevelMust, "The certificate chain is sent ordered and complete", func(t *tlsCheck) Verdict { return t.chainComplete() }),
		req("r35", "R35", LevelShould, "OCSP stapling is preferred", func(t *tlsCheck) Verdict { return t.ocspStapled() }),
		req("r38", "R38", LevelShould, "The certificate is registered in Certificate Transparency", func(t *tlsCheck) Verdict { return t.ctProof() }),
	},
	NotAssessed: []string{
		"R1, R2 client profiling and up-to-date software", "R12 several cipher suites per client profile", "R14 to R16 the full extension tables",
		"R17, R18 random-number generation", "R20, R21 session-ticket lifetime and resumption with key exchange", "R23 0-RTT data",
		"R27 KeyUsage against the key type", "R30 to R32, R36, R37 PKI operations", "R39 rejecting certificates CT invalidates (a client duty)",
	},
}

// ---- Mozilla Server Side TLS 6.0 ------------------------------------------------------------------

var mozilla13Suites = []string{"TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256"}
var mozillaIntermediate12Suites = []string{"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
	"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256", "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"}
var mozillaCurves = []string{"X25519MLKEM768", "x25519", "secp256r1", "secp384r1"}

func mozillaCert(modern bool) func(*tlsCheck) Verdict {
	return func(t *tlsCheck) Verdict {
		return t.certs(func(_ *chain, leaf tlsprobe.CertInfo) Verdict {
			k := leaf.PublicKey
			sig := strings.ToLower(leaf.SignatureAlg.Name)
			switch k.Algorithm {
			case "ECDSA":
				if !curveNamed(k.Curve, "P-256", "P-384") {
					return notMet(keyWords(k) + " (the profile allows prime256v1 and secp384r1)")
				}
				if !strings.Contains(sig, "ecdsa") || sigHash(sig) != "sha2" {
					return notMet("signed with " + leaf.SignatureAlg.Name)
				}
				return met(keyWords(k) + ", " + leaf.SignatureAlg.Name)
			case "RSA":
				if modern {
					return notMet("an RSA certificate; the Modern profile is ECDSA only")
				}
				if k.Bits < 2048 {
					return notMet(keyWords(k))
				}
				if !strings.Contains(sig, "sha256") || strings.Contains(sig, "pss") {
					return notMet("signed with " + leaf.SignatureAlg.Name + " (the profile lists sha256WithRSAEncryption)")
				}
				return met(keyWords(k) + ", " + leaf.SignatureAlg.Name)
			}
			return notMet(keyWords(k) + " is not a certificate type of the profile")
		})
	}
}

var mozillaModern = Standard{
	ID: "mozilla-modern-6.0", Title: "Mozilla Modern", Publisher: "Mozilla Server Side TLS", Edition: "Guideline 6.0", Protocol: "tls",
	URL:   "https://ssl-config.mozilla.org/guidelines/6.0.json",
	Scope: "Mozilla's configuration for services with modern clients only: TLS 1.3, ECDSA certificates, 90-day lifetimes.",
	Requirements: []Requirement{
		req("versions", "tls_versions", LevelMust, "Only TLS 1.3 is enabled", func(t *tlsCheck) Verdict {
			if v := t.versionsNotAllowed(v12, v11, v10, ssl3, ssl2); v.Status != ReqMet {
				return v
			}
			return t.versionRequired(v13)
		}),
		req("suites", "ciphersuites", LevelMust, "Only TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384 and TLS_CHACHA20_POLY1305_SHA256", func(t *tlsCheck) Verdict {
			return t.suitesOnly(map[string][]string{v13: mozilla13Suites}, "the Modern profile")
		}),
		req("curves", "tls_curves", LevelMust, "Only X25519MLKEM768, X25519, prime256v1 and secp384r1 key-exchange groups", func(t *tlsCheck) Verdict {
			return t.groupsOnly(mozillaCurves, "the Modern profile")
		}),
		req("pq", "tls_curves", LevelShould, "X25519MLKEM768 is offered (first in the profile's list)", func(t *tlsCheck) Verdict { return t.hybridPQ("X25519MLKEM768") }),
		req("cert", "certificate_types, certificate_curves, certificate_signatures", LevelMust, "An ECDSA certificate on prime256v1 or secp384r1, signed ecdsa-with-SHA256/384/512",
			mozillaCert(true)),
		req("lifespan", "maximum_certificate_lifespan", LevelMust, "The certificate is valid for at most 90 days", func(t *tlsCheck) Verdict { return t.certValidityAtMost(90, time.Time{}) }),
		req("stapling", "ocsp_staple", LevelShould, "OCSP stapling is on", func(t *tlsCheck) Verdict { return t.ocspStapled() }),
		req("hsts", "hsts_min_age", LevelShould, "HSTS max-age is at least 63072000 seconds (two years)", func(t *tlsCheck) Verdict { return t.hstsAtLeast(63072000) }),
	},
	NotAssessed: []string{"server_preferred_order is false for this profile, so suite order is not judged", "recommended_certificate_lifespan (90 days) equals the maximum here"},
}

var mozillaIntermediate = Standard{
	ID: "mozilla-intermediate-6.0", Title: "Mozilla Intermediate", Publisher: "Mozilla Server Side TLS", Edition: "Guideline 6.0", Protocol: "tls",
	URL:   "https://ssl-config.mozilla.org/guidelines/6.0.json",
	Scope: "Mozilla's general-purpose configuration: TLS 1.2 and 1.3, ECDHE with AES-GCM or ChaCha20, ECDSA or RSA certificates.",
	Requirements: []Requirement{
		req("versions", "tls_versions", LevelMust, "Only TLS 1.2 and TLS 1.3 are enabled", func(t *tlsCheck) Verdict { return t.versionsNotAllowed(v11, v10, ssl3, ssl2) }),
		req("tls13", "tls_versions", LevelMust, "TLS 1.3 is enabled", func(t *tlsCheck) Verdict { return t.versionRequired(v13) }),
		req("suites", "ciphersuites, ciphers", LevelMust, "Only the profile's TLS 1.3 suites and its six ECDHE AES-GCM and ChaCha20 suites for TLS 1.2", func(t *tlsCheck) Verdict {
			return t.suitesOnly(map[string][]string{v13: mozilla13Suites, v12: mozillaIntermediate12Suites}, "the Intermediate profile")
		}),
		req("curves", "tls_curves", LevelMust, "Only X25519MLKEM768, X25519, prime256v1 and secp384r1 key-exchange groups", func(t *tlsCheck) Verdict {
			return t.groupsOnly(mozillaCurves, "the Intermediate profile")
		}),
		req("pq", "tls_curves", LevelShould, "X25519MLKEM768 is offered (first in the profile's list)", func(t *tlsCheck) Verdict { return t.hybridPQ("X25519MLKEM768") }),
		req("dh", "dh_param_size", LevelMust, "DH parameters, where used, are 2048 bits", func(t *tlsCheck) Verdict { return t.minDH(2048) }),
		req("cert", "certificate_types, rsa_key_size, certificate_signatures", LevelMust, "An ECDSA (prime256v1, secp384r1) or RSA 2048+ certificate, signed ecdsa-with-SHA* or sha256WithRSAEncryption",
			mozillaCert(false)),
		req("lifespan", "maximum_certificate_lifespan", LevelMust, "The certificate is valid for at most 366 days", func(t *tlsCheck) Verdict { return t.certValidityAtMost(366, time.Time{}) }),
		req("lifespan-90", "recommended_certificate_lifespan", LevelShould, "The certificate is valid for at most 90 days (recommended)", func(t *tlsCheck) Verdict { return t.certValidityAtMost(90, time.Time{}) }),
		req("stapling", "ocsp_staple", LevelShould, "OCSP stapling is on", func(t *tlsCheck) Verdict { return t.ocspStapled() }),
		req("hsts", "hsts_min_age", LevelShould, "HSTS max-age is at least 63072000 seconds (two years)", func(t *tlsCheck) Verdict { return t.hstsAtLeast(63072000) }),
	},
	NotAssessed: []string{"server_preferred_order is false for this profile, so suite order is not judged"},
}

// ---- PCI DSS v4.0.1 ---------------------------------------------------------------------------------

var pciDSS4 = Standard{
	ID: "pci-dss-4", Title: "PCI DSS v4.0.1, Requirement 4.2.1", Publisher: "PCI Security Standards Council", Edition: "v4.0.1, June 2024", Protocol: "tls",
	URL:   "https://www.pcisecuritystandards.org/document_library/",
	Scope: "Strong cryptography and security protocols for cardholder data in transit over open, public networks: trusted certificates, secure protocol versions only, no fallback, strength per the PCI glossary (112 bits minimum, 128 recommended).",
	Requirements: []Requirement{
		req("no-ssl-early-tls", "4.2.1 (secure versions only); PCI SSC: SSL and early TLS", LevelMust, "SSL and early TLS (SSLv2, SSLv3, TLS 1.0) are not supported",
			func(t *tlsCheck) Verdict { return t.versionsNotAllowed(ssl2, ssl3, v10) }),
		req("no-tls11", "4.2.1; PCI SSC: migrate to TLS 1.2 or higher", LevelShould, "TLS 1.1 is not supported (PCI SSC strongly encourages TLS 1.2 or higher)",
			func(t *tlsCheck) Verdict { return t.versionsNotAllowed(v11) }),
		req("strong-112", "4.2.1; Glossary: Strong Cryptography", LevelMust, "Every accepted suite provides at least 112 bits of effective key strength (no NULL, export, RC4, DES, anonymous)", func(t *tlsCheck) Verdict {
			return t.noSuite(func(s tlsprobe.SuiteResult) bool {
				return s.Cipher == "NULL" || s.Export || s.Anon || s.Cipher == "RC4" || s.Cipher == "DES" || s.Cipher == "RC2" || s.KeyBits > 0 && s.KeyBits < 112 && s.Cipher != "3DES" || s.MAC == "MD5"
			}, "suites under 112 bits accepted", "every suite's cipher provides at least 112 bits")
		}),
		req("keys-112", "Glossary: Strong Cryptography", LevelMust, "Public keys provide at least 112 bits: RSA 2048, ECC 224, DH 2048 and above", func(t *tlsCheck) Verdict {
			if v := t.minDH(2048); v.Status == ReqNotMet {
				return v
			}
			if v := t.minCurve(224); v.Status == ReqNotMet {
				return v
			}
			return t.certKeyAtLeast(2048, 224)
		}),
		req("strong-128", "Glossary: Strong Cryptography (recommendation)", LevelShould, "New implementations use at least 128 bits of effective key strength (no 3DES; RSA 3072, ECC 256 and above)", func(t *tlsCheck) Verdict {
			if v := t.noSuite(func(s tlsprobe.SuiteResult) bool { return s.Cipher == "3DES" }, "3DES suites accepted", ""); v.Status == ReqNotMet {
				return v
			}
			if v := t.minDH(3072); v.Status == ReqNotMet {
				return v
			}
			if v := t.minCurve(255); v.Status == ReqNotMet {
				return v
			}
			return t.certKeyAtLeast(3072, 255)
		}),
		req("trusted", "4.2.1 (only trusted keys and certificates; valid and not expired)", LevelMust, "The certificate chain is trusted and within its validity", func(t *tlsCheck) Verdict { return t.certTrusted() }),
		req("not-revoked", "4.2.1 (certificates confirmed as not revoked)", LevelShould, "The certificate is confirmed as not revoked", func(t *tlsCheck) Verdict {
			if !t.stageRan(tlsprobe.StageCerts) || len(t.leaves()) == 0 {
				return notAssessed("no certificate was read")
			}
			for _, ch := range t.leaves() {
				if o := ch.view.OCSP; o != nil && o.Status == "revoked" {
					return notMet("the stapled OCSP response says revoked")
				}
				for _, r := range ch.view.CRL {
					if r.Status == "revoked" {
						return notMet("the issuer's CRL lists the certificate")
					}
				}
			}
			if t.revocationVouched() {
				return met("a verified OCSP staple or CRL says the certificate is not revoked")
			}
			return notAssessed("revocation status is unknown to this scan (no verified staple; CRL lookups " + map[bool]string{true: "found nothing conclusive", false: "were off"}[t.rep.CRLLookups] + ")")
		}),
		req("no-fallback", "4.2.1 (no fallback to insecure versions)", LevelShould, "Downgrade to an older version is refused (TLS_FALLBACK_SCSV) where several versions are enabled", func(t *tlsCheck) Verdict {
			if len(t.supportedVersions()) < 2 {
				return notApplicable("one protocol version only")
			}
			return t.feature(t.rep.Features.FallbackSCSV, true, "a downgraded hello with the SCSV is refused", "a downgraded hello with the SCSV is answered", "the SCSV was not probed")
		}),
	},
	NotAssessed: []string{
		"4.2.1.1 the inventory of trusted keys and certificates (this product's Inventory and certificate pages are that inventory)",
		"Whether this endpoint carries cardholder data at all: scope is the assessor's call", "Key-management practices (generation, storage, rotation)",
	},
}

// ---- CNSA 2.0 (TLS) ------------------------------------------------------------------------------------

var cnsa2TLS = Standard{
	ID: "cnsa-2.0-tls", Title: "CNSA 2.0 for TLS", Publisher: "NSA (via IETF profiles)", Edition: "draft-becker-cnsa2-tls-profile-06 (October 2026); RFC 9151 for the CNSA 1.0 transition", Protocol: "tls",
	URL:   "https://datatracker.ietf.org/doc/draft-becker-cnsa2-tls-profile/",
	Scope: "The Commercial National Security Algorithm Suite for US national security systems: TLS 1.3, AES-256-GCM-SHA384, ML-KEM-1024 and ML-DSA-87, with P-384 and RSA 3072/4096 allowed during the transition (RFC 9151).",
	Requirements: []Requirement{
		req("tls13-only", "draft §6", LevelShould, "Only TLS 1.3 is negotiated (a TLS 1.2 connection cannot be CNSA 2.0 compliant; RFC 9151 governs it meanwhile)",
			func(t *tlsCheck) Verdict {
				if v := t.versionsNotAllowed(v12); v.Status != ReqMet {
					return v
				}
				return t.versionRequired(v13)
			}),
		req("versions", "RFC 9151 §4; draft §6", LevelMust, "Nothing below TLS 1.2 is negotiated, and TLS 1.3 is supported", func(t *tlsCheck) Verdict {
			if v := t.versionsNotAllowed(v11, v10, ssl3, ssl2); v.Status != ReqMet {
				return v
			}
			return t.versionRequired(v13)
		}),
		req("suite13", "draft §4, §7.1", LevelMust, "TLS 1.3 uses TLS_AES_256_GCM_SHA384 and nothing else", func(t *tlsCheck) Verdict {
			if !t.supported[v13] {
				return notApplicable("TLS 1.3 is not supported")
			}
			return t.suitesOnly(map[string][]string{v13: {"TLS_AES_256_GCM_SHA384"}}, "the CNSA profile")
		}),
		req("suite12", "RFC 9151 §6", LevelMust, "TLS 1.2, where still enabled, uses only the AES-256-GCM-SHA384 suites RFC 9151 lists", func(t *tlsCheck) Verdict {
			if !t.supported[v12] {
				return notApplicable("TLS 1.2 is not supported")
			}
			return t.suitesOnly(map[string][]string{v12: {"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
				"TLS_DHE_RSA_WITH_AES_256_GCM_SHA384", "TLS_RSA_WITH_AES_256_GCM_SHA384"}}, "RFC 9151 §6")
		}),
		req("groups", "draft §7.2.1; RFC 9151 §5", LevelMust, "Key exchange uses ML-KEM-1024, or during the transition secp384r1, ffdhe3072 or ffdhe4096, and nothing else",
			func(t *tlsCheck) Verdict {
				return t.groupsOnly([]string{"MLKEM1024", "secp384r1", "ffdhe3072", "ffdhe4096"}, "the CNSA profiles")
			}),
		req("mlkem", "draft §4, §7.2.1", LevelShould, "ML-KEM-1024 is offered (the CNSA 2.0 key establishment)", func(t *tlsCheck) Verdict {
			if _, ok := t.hasGroup("MLKEM1024"); ok {
				return met("MLKEM1024 is accepted")
			}
			if !t.stageRan(tlsprobe.StageKeyExchange) {
				return notAssessed("the key-exchange stage did not run")
			}
			return notMet("MLKEM1024 is not accepted")
		}),
		req("cert-key", "draft §8.4; RFC 9151 §5.1, §5.2", LevelMust, "The certificate key is ML-DSA-87, or during the transition ECDSA P-384 or RSA 3072/4096", func(t *tlsCheck) Verdict {
			return t.certs(func(_ *chain, leaf tlsprobe.CertInfo) Verdict {
				k := leaf.PublicKey
				switch {
				case k.Algorithm == "ML-DSA-87":
					return met("ML-DSA-87 (CNSA 2.0)")
				case k.Algorithm == "ECDSA" && curveNamed(k.Curve, "P-384"):
					return met(keyWords(k) + " (CNSA 1.0, transitional)")
				case k.Algorithm == "RSA" && (k.Bits == 3072 || k.Bits == 4096):
					return met(keyWords(k) + " (CNSA 1.0, transitional)")
				}
				return notMet(keyWords(k))
			})
		}),
		req("cert-sig", "RFC 9151 §4, §7.1; draft §8.4", LevelMust, "The certificate is signed with ML-DSA-87, or with ECDSA or RSA-PSS over SHA-384 during the transition", func(t *tlsCheck) Verdict {
			return t.certs(func(_ *chain, leaf tlsprobe.CertInfo) Verdict {
				n := strings.ToLower(leaf.SignatureAlg.Name)
				switch {
				case strings.Contains(n, "mldsa87") || strings.Contains(n, "ml-dsa-87"):
					return met("signed with ML-DSA-87")
				case strings.Contains(n, "sha384"):
					return met("signed with " + leaf.SignatureAlg.Name)
				}
				return notMet("signed with " + leaf.SignatureAlg.Name + " (SHA-384 is required)")
			})
		}),
		req("mldsa", "draft §3, §8.1", LevelShould, "ML-DSA-87 authentication is available (the CNSA 2.0 signature)", func(t *tlsCheck) Verdict {
			if hasPQCertificate(t.rep) {
				return met("an ML-DSA certificate is presented")
			}
			acc, ok := t.schemesAccepted()
			if !ok {
				return notAssessed("the signature stage was inconclusive or did not run")
			}
			for _, s := range acc {
				if strings.Contains(strings.ToLower(s), "mldsa87") {
					return met(s + " is accepted")
				}
			}
			return notMet("no ML-DSA-87 signature is offered")
		}),
	},
	NotAssessed: []string{
		"The CNSA 2.0 timeline (NSA: prefer CNSA 2.0 for web servers and browsers by 2025, exclusively by 2033) is a policy date, not a server property",
		"draft §8.1: that non-CNSA signature algorithms are refused (the scan proves acceptance, not refusal of every other scheme)",
		"Whether the system is a national security system at all",
	},
}
