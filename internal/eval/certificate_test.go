package eval

import (
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/offsetsecurity/cipherhorizon/internal/tlsprobe"
)

var certNow = time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)

func ids(fs []Finding) []string {
	var out []string
	for _, f := range fs {
		out = append(out, f.ID)
	}
	sort.Strings(out)
	return out
}

func days(n int) time.Time { return certNow.Add(time.Duration(n) * 24 * time.Hour) }

// REQ-CERT-7: each rule fires on the certificates it should and stays quiet on the ones it
// should not.
func TestCertificateRules(t *testing.T) {
	good := CertificateFacts{Subject: "CN=ok", NotBefore: days(-365), NotAfter: days(300), KeyAlgorithm: "ECDSA", KeyBits: 256, SigName: "ECDSA-SHA256"}
	mut := func(f func(*CertificateFacts)) CertificateFacts { c := good; f(&c); return c }
	cases := []struct {
		name string
		c    CertificateFacts
		want []string
		sev  map[string]Severity
	}{
		{"healthy", good, nil, nil},
		{"expired", mut(func(c *CertificateFacts) { c.NotAfter = days(-1) }), []string{"CERT.EXPIRED"}, map[string]Severity{"CERT.EXPIRED": Critical}},
		{"expires in 5 days", mut(func(c *CertificateFacts) { c.NotAfter = days(5) }), []string{"CERT.EXPIRING"}, map[string]Severity{"CERT.EXPIRING": High}},
		{"expires in 20 days", mut(func(c *CertificateFacts) { c.NotAfter = days(20) }), []string{"CERT.EXPIRING"}, map[string]Severity{"CERT.EXPIRING": Medium}},
		{"expires in 31 days", mut(func(c *CertificateFacts) { c.NotAfter = days(31) }), nil, nil},
		// REQ-TCRT-4: the window scales with the lifetime.
		{"47-day certificate with 20 days left", mut(func(c *CertificateFacts) { c.NotBefore, c.NotAfter = days(-27), days(20) }), nil, nil},
		{"47-day certificate with 15 days left", mut(func(c *CertificateFacts) { c.NotBefore, c.NotAfter = days(-32), days(15) }),
			[]string{"CERT.EXPIRING"}, map[string]Severity{"CERT.EXPIRING": Medium}},
		{"47-day certificate with 4 days left", mut(func(c *CertificateFacts) { c.NotBefore, c.NotAfter = days(-43), days(4) }),
			[]string{"CERT.EXPIRING"}, map[string]Severity{"CERT.EXPIRING": High}},
		{"not yet valid", mut(func(c *CertificateFacts) { c.NotBefore = days(3) }), []string{"CERT.NOT-YET-VALID"}, nil},
		{"RSA 512", mut(func(c *CertificateFacts) { c.KeyAlgorithm, c.KeyBits = "RSA", 512 }), []string{"CERT.WEAK-KEY"}, map[string]Severity{"CERT.WEAK-KEY": Critical}},
		{"RSA 1536", mut(func(c *CertificateFacts) { c.KeyAlgorithm, c.KeyBits = "RSA", 1536 }), []string{"CERT.WEAK-KEY"}, map[string]Severity{"CERT.WEAK-KEY": High}},
		{"RSA 2048", mut(func(c *CertificateFacts) { c.KeyAlgorithm, c.KeyBits = "RSA", 2048 }), nil, nil},
		{"RSA of unknown size", mut(func(c *CertificateFacts) { c.KeyAlgorithm, c.KeyBits = "RSA", 0 }), nil, nil},
		{"ECDSA 192", mut(func(c *CertificateFacts) { c.KeyBits = 192 }), []string{"CERT.WEAK-KEY"}, nil},
		{"SHA-1 signature", mut(func(c *CertificateFacts) { c.SigName = "SHA1-RSA" }), []string{"CERT.WEAK-SIGNATURE"}, nil},
		{"MD5 signature", mut(func(c *CertificateFacts) { c.SigName = "MD5-RSA" }), []string{"CERT.WEAK-SIGNATURE"}, nil},
		{"valid past 2030", mut(func(c *CertificateFacts) { c.NotAfter = time.Date(2032, 1, 1, 0, 0, 0, 0, time.UTC) }),
			[]string{"CERT.PQ-OUTLIVES-DEPRECATION"}, map[string]Severity{"CERT.PQ-OUTLIVES-DEPRECATION": Medium}},
		{"valid past 2035", mut(func(c *CertificateFacts) { c.NotAfter = time.Date(2040, 1, 1, 0, 0, 0, 0, time.UTC) }),
			[]string{"CERT.PQ-OUTLIVES-DEPRECATION"}, map[string]Severity{"CERT.PQ-OUTLIVES-DEPRECATION": High}},
		{"valid until the very end of 2030", mut(func(c *CertificateFacts) { c.NotAfter = time.Date(2030, 12, 31, 23, 59, 59, 0, time.UTC) }), nil, nil},
		{"a post-quantum key valid past 2035 is not flagged", mut(func(c *CertificateFacts) {
			c.KeyAlgorithm, c.NotAfter = "ML-DSA-65", time.Date(2040, 1, 1, 0, 0, 0, 0, time.UTC)
		}), nil, nil},
		{"an unknown key type is not flagged", mut(func(c *CertificateFacts) {
			c.KeyAlgorithm, c.NotAfter = "unknown", time.Date(2040, 1, 1, 0, 0, 0, 0, time.UTC)
		}), nil, nil},
		{"several at once", mut(func(c *CertificateFacts) {
			c.NotAfter, c.KeyAlgorithm, c.KeyBits, c.SigName = days(-5), "RSA", 1024, "SHA1-RSA"
		}), []string{"CERT.EXPIRED", "CERT.WEAK-KEY", "CERT.WEAK-SIGNATURE"}, nil},
		{"no dates at all", CertificateFacts{Subject: "x", KeyAlgorithm: "ECDSA", KeyBits: 256}, nil, nil},
	}
	for _, c := range cases {
		got := EvaluateCertificate(c.c, certNow)
		if strings.Join(ids(got), ",") != strings.Join(c.want, ",") {
			t.Errorf("%s: findings %v, want %v", c.name, ids(got), c.want)
		}
		for _, f := range got {
			if want, ok := c.sev[f.ID]; ok && f.Severity != want {
				t.Errorf("%s: %s severity %s, want %s", c.name, f.ID, f.Severity, want)
			}
		}
	}
}

// The same rule that fires on a certificate a server presented fires on the same
// certificate wherever else it is found: the five shared rules agree with the TLS
// evaluation on a table of certificates.
func TestCertificateRulesAgreeWithTheTLSRules(t *testing.T) {
	shared := map[string]bool{"CERT.EXPIRED": true, "CERT.NOT-YET-VALID": true, "CERT.EXPIRING": true, "CERT.WEAK-KEY": true, "CERT.WEAK-SIGNATURE": true}
	tab := []CertificateFacts{
		{NotBefore: days(-365), NotAfter: days(300), KeyAlgorithm: "ECDSA", KeyBits: 256, SigName: "ECDSA-SHA256"},
		{NotBefore: days(-365), NotAfter: days(-1), KeyAlgorithm: "RSA", KeyBits: 2048, SigName: "SHA256-RSA"},
		{NotBefore: days(-365), NotAfter: days(3), KeyAlgorithm: "RSA", KeyBits: 2048, SigName: "SHA256-RSA"},
		{NotBefore: days(-365), NotAfter: days(20), KeyAlgorithm: "RSA", KeyBits: 2048, SigName: "SHA256-RSA"},
		{NotBefore: days(-365), NotAfter: days(30), KeyAlgorithm: "RSA", KeyBits: 2048, SigName: "SHA256-RSA"},
		{NotBefore: days(-365), NotAfter: days(31), KeyAlgorithm: "RSA", KeyBits: 2048, SigName: "SHA256-RSA"},
		{NotBefore: days(2), NotAfter: days(300), KeyAlgorithm: "RSA", KeyBits: 2048, SigName: "SHA256-RSA"},
		{NotBefore: days(-365), NotAfter: days(300), KeyAlgorithm: "RSA", KeyBits: 512, SigName: "SHA256-RSA"},
		{NotBefore: days(-365), NotAfter: days(300), KeyAlgorithm: "RSA", KeyBits: 1023, SigName: "SHA256-RSA"},
		{NotBefore: days(-365), NotAfter: days(300), KeyAlgorithm: "RSA", KeyBits: 1024, SigName: "SHA256-RSA"},
		{NotBefore: days(-365), NotAfter: days(300), KeyAlgorithm: "RSA", KeyBits: 2047, SigName: "SHA256-RSA"},
		{NotBefore: days(-365), NotAfter: days(300), KeyAlgorithm: "ECDSA", KeyBits: 223, SigName: "ECDSA-SHA256"},
		{NotBefore: days(-365), NotAfter: days(300), KeyAlgorithm: "ECDSA", KeyBits: 224, SigName: "ECDSA-SHA256"},
		{NotBefore: days(-365), NotAfter: days(300), KeyAlgorithm: "RSA", KeyBits: 2048, SigName: "SHA1-RSA"},
		{NotBefore: days(-365), NotAfter: days(300), KeyAlgorithm: "RSA", KeyBits: 2048, SigName: "MD5-RSA"},
		{NotBefore: days(-365), NotAfter: days(300), KeyAlgorithm: "RSA", KeyBits: 2048, SigName: "ECDSA-SHA1"},
		{NotBefore: days(-365), NotAfter: days(-10), KeyAlgorithm: "RSA", KeyBits: 512, SigName: "MD5-RSA"},
	}
	for i, f := range tab {
		f.Subject = "CN=x"
		rep := &tlsprobe.Report{
			Protocols: []tlsprobe.ProtocolResult{{Version: "TLSv1.3", Supported: true}},
			Certificates: []tlsprobe.CertResult{{Source: "tls-default", Trusted: true, NameMatches: true, Chain: []tlsprobe.CertInfo{{
				Subject: "CN=x", SHA256: "aa", NotBefore: f.NotBefore, NotAfter: f.NotAfter,
				PublicKey: tlsprobe.KeyInfo{Algorithm: f.KeyAlgorithm, Bits: f.KeyBits}, SignatureAlg: tlsprobe.AlgInfo{Name: f.SigName},
			}}}},
		}
		var viaTLS []string
		for _, fd := range Evaluate(rep, certNow).Findings {
			if shared[fd.ID] {
				viaTLS = append(viaTLS, fd.ID)
			}
		}
		sort.Strings(viaTLS)
		var viaCert []string
		for _, id := range ids(EvaluateCertificate(f, certNow)) {
			if shared[id] {
				viaCert = append(viaCert, id)
			}
		}
		if strings.Join(viaTLS, ",") != strings.Join(viaCert, ",") {
			t.Errorf("certificate %d (%+v): TLS rules say %v, certificate rules say %v", i, f, viaTLS, viaCert)
		}
	}
}

// Every certificate finding is cited, has a remediation and says what it saw.
func TestEveryCertificateFindingIsCited(t *testing.T) {
	f := CertificateFacts{Subject: "CN=x", NotBefore: days(2), NotAfter: time.Date(2040, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyAlgorithm: "RSA", KeyBits: 512, SigName: "SHA1-RSA"}
	seen := map[string]bool{}
	collect := func(f CertificateFacts) {
		for _, fd := range EvaluateCertificate(f, certNow) {
			seen[fd.ID] = true
			if len(fd.Citations) == 0 || fd.Remediation == "" || fd.Detail == "" || fd.Title == "" || fd.Category != "certificate" {
				t.Errorf("%s: incomplete finding %+v", fd.ID, fd)
			}
			for _, c := range fd.Citations {
				if c.Title == "" || !strings.HasPrefix(c.URL, "https://") {
					t.Errorf("%s: bad citation %+v", fd.ID, c)
				}
			}
		}
	}
	collect(f)
	f.NotBefore, f.NotAfter = days(-30), days(-1)
	collect(f)
	f.NotAfter = days(4)
	collect(f)
	for _, id := range CertificateRuleIDs() {
		if !seen[id] {
			t.Errorf("rule %s never fired in the citation check", id)
		}
	}
}
