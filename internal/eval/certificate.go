package eval

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/offsetsecurity/cipherhorizon/internal/pki"
	"github.com/offsetsecurity/cipherhorizon/internal/refdata"
)

// CertificateFacts is what a certificate says about itself: enough to judge it, wherever it
// was found (presented by a server, held in a store, described in an imported CBOM). It
// carries no key material and no path.
type CertificateFacts struct {
	Subject      string
	NotBefore    time.Time
	NotAfter     time.Time
	KeyAlgorithm string // RSA, ECDSA, Ed25519, ... as certinfo names it
	KeyBits      int    // 0 when unknown
	SigName      string // the signature algorithm's name, e.g. SHA256-RSA
	IsCA         bool
	SelfSigned   bool
	// SHA256 and SPKISHA256 identify the certificate and its key (lower-case hex; either may be
	// empty), for the distrust list.
	SHA256     string
	SPKISHA256 string
}

// quantumVulnerableKeys are the public-key algorithms NIST IR 8547 lists as vulnerable to a
// cryptographically relevant quantum computer: RSA, ECDSA, EdDSA, DH and ECDH.
var quantumVulnerableKeys = map[string]bool{
	"RSA": true, "RSASSA-PSS": true, "ECDSA": true, "Ed25519": true, "Ed448": true, "DSA": true, "X25519": true, "X448": true,
}

// The dates NIST IR 8547 (initial public draft) gives for the transition: quantum-vulnerable
// public-key algorithms to be deprecated by 2030 and disallowed by 2035.
var (
	pqcDeprecatedAfter = time.Date(2030, 12, 31, 23, 59, 59, 0, time.UTC)
	pqcDisallowedAfter = time.Date(2035, 1, 1, 0, 0, 0, 0, time.UTC)
)

// EvaluateCertificate judges one certificate. It applies the same certificate rules as the
// TLS evaluation (expired, not yet valid, expiring soon, weak key, broken signature hash;
// TestCertificateRulesAgreeWithTheTLSRules keeps the two in step) plus one that only makes
// sense per certificate: a quantum-vulnerable key whose certificate outlives the dates NIST
// sets for retiring such keys. Every finding is cited. It never says a certificate is
// trusted or in use: that needs facts this function does not have.
func EvaluateCertificate(f CertificateFacts, now time.Time) []Finding {
	label := f.Subject
	if label == "" {
		label = "the certificate"
	}
	var out []Finding
	add := func(id, title string, sev Severity, cites []Citation, remed, detail string) {
		out = append(out, Finding{ID: id, Title: title, Severity: sev, Category: "certificate", Detail: detail,
			Evidence: Observed, Citations: cites, Remediation: remed})
	}

	if l, ok := refdata.Distrust().LookupHashes(strings.ToLower(f.SHA256), strings.ToLower(f.SPKISHA256)); ok {
		sev := Critical
		if l.Kind == pki.KindCADistrust {
			sev = High
		}
		detail := fmt.Sprintf("%s is %q %s", label, l.Name, l.Phrase())
		if f.IsCA {
			detail += "; a machine that trusts it, or a CA bundle that carries it, accepts certificates anyone can issue under it"
		}
		if len(l.Sources) > 0 {
			detail += "; see " + l.Sources[0]
		}
		add("CERT.DISTRUSTED-KEY", "Certificate uses a distrusted CA key", sev, []Citation{citCAKeyCompromise, citRFC5280},
			"Remove this certificate from every trust store and CA bundle that holds it, replace anything issued under it, and update the software on this machine so it blocks the key.",
			detail)
	}

	if !f.NotAfter.IsZero() {
		switch {
		case f.NotAfter.Before(now):
			add("CERT.EXPIRED", "Certificate has expired", Critical, []Citation{citRFC5280}, "Renew and deploy a new certificate.",
				fmt.Sprintf("%s expired on %s", label, f.NotAfter.Format("2006-01-02")))
		default:
			if detail, sev, fire := expiringCheck(now, label, f.NotBefore, f.NotAfter, 0); fire {
				add("CERT.EXPIRING", "Certificate expires soon", sev, []Citation{citRFC5280}, "Renew before expiry; automate renewal.", detail)
			}
		}
	}
	if !f.NotBefore.IsZero() && f.NotBefore.After(now) {
		add("CERT.NOT-YET-VALID", "Certificate is not yet valid", High, []Citation{citRFC5280}, "Check the clock and the certificate's validity period.",
			fmt.Sprintf("%s becomes valid on %s", label, f.NotBefore.Format("2006-01-02")))
	}

	weakKey := func(sev Severity, detail string) {
		add("CERT.WEAK-KEY", "Certificate public key is too small", sev, []Citation{citCABF, citSP80057},
			"Use RSA of at least 2048 bits or ECDSA P-256 or better.", detail)
	}
	switch {
	case f.KeyAlgorithm == "RSA" && f.KeyBits > 0 && f.KeyBits < 1024:
		weakKey(Critical, fmt.Sprintf("%s: RSA %d-bit", label, f.KeyBits))
	case f.KeyAlgorithm == "RSA" && f.KeyBits > 0 && f.KeyBits < 2048:
		weakKey(High, fmt.Sprintf("%s: RSA %d-bit", label, f.KeyBits))
	case f.KeyAlgorithm == "ECDSA" && f.KeyBits > 0 && f.KeyBits < 224:
		weakKey(High, fmt.Sprintf("%s: ECDSA %d-bit", label, f.KeyBits))
	}

	if n := strings.ToUpper(f.SigName); strings.Contains(n, "SHA1") || strings.Contains(n, "MD5") || strings.Contains(n, "MD2") {
		add("CERT.WEAK-SIGNATURE", "Certificate is signed with a broken hash", High, []Citation{citCABF},
			"Reissue the certificate with a SHA-256 (or better) signature.", fmt.Sprintf("%s: signature %s", label, f.SigName))
	}

	if quantumVulnerableKeys[f.KeyAlgorithm] && !f.NotAfter.IsZero() && f.NotAfter.After(pqcDeprecatedAfter) {
		sev, when := Medium, "2030"
		detail := fmt.Sprintf("%s uses a %s key and is valid until %s, beyond the 2030 date by which NIST IR 8547 says such keys are to be deprecated",
			label, f.KeyAlgorithm, f.NotAfter.Format("2006-01-02"))
		if f.NotAfter.After(pqcDisallowedAfter) {
			sev, when = High, "2035"
			detail = fmt.Sprintf("%s uses a %s key and is valid until %s, beyond the 2035 date after which NIST IR 8547 says such keys are to be disallowed",
				label, f.KeyAlgorithm, f.NotAfter.Format("2006-01-02"))
		}
		add("CERT.PQ-OUTLIVES-DEPRECATION", "Certificate outlives the date its key type is to be retired", sev, []Citation{citIR8547},
			"Plan to reissue before "+when+" with a post-quantum or hybrid certificate once your PKI supports it, and shorten the validity period so this certificate does not depend on a retired algorithm.",
			detail)
	}

	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Severity.Rank() != out[j].Severity.Rank() {
			return out[i].Severity.Rank() < out[j].Severity.Rank()
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// CertificateRuleIDs lists the rule IDs EvaluateCertificate can produce.
func CertificateRuleIDs() []string {
	return []string{"CERT.DISTRUSTED-KEY", "CERT.EXPIRED", "CERT.EXPIRING", "CERT.NOT-YET-VALID", "CERT.WEAK-KEY", "CERT.WEAK-SIGNATURE", "CERT.PQ-OUTLIVES-DEPRECATION"}
}
