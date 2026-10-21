package eval

import (
	"fmt"
	"sort"
	"strings"

	"github.com/offsetsecurity/cipherhorizon/internal/algo"
	"github.com/offsetsecurity/cipherhorizon/internal/sshprobe"
	"github.com/offsetsecurity/cipherhorizon/internal/sshprobe/registry"
	"github.com/offsetsecurity/cipherhorizon/internal/tlsprobe"
)

// SSH evaluation (PRD-008 WP-C). An SSH scan report is judged into the same Evaluation shape as a
// TLS one, so every fleet view, count and ranking works unchanged; only the rules, the sections
// and the readiness rules are SSH's own. The post-quantum finding IDs are the shared ones, so the
// fleet groups harvest-now-decrypt-later exposure across protocols.

// ProtocolSSH is Evaluation.Protocol for an SSH endpoint (empty means TLS).
const ProtocolSSH = "ssh"

// SSH section identifiers, in page order.
const (
	SecSSHVersion = "ssh-version"
	SecHostKeys   = "host-keys"
	SecEncryption = "encryption"
	SecIntegrity  = "integrity"
)

// SSHSectionOrder is the order an SSH report's sections appear in.
var SSHSectionOrder = []string{SecSSHVersion, SecKeyExchange, SecHostKeys, SecEncryption, SecIntegrity, SecVulnerabilities}

var (
	citRFC4253 = rfc("4253", "The Secure Shell (SSH) Transport Layer Protocol")
	citRFC9142 = rfc("9142", "Key Exchange (KEX) Method Updates and Recommendations for Secure Shell (SSH)")
	citRFC8332 = rfc("8332", "Use of RSA Keys with SHA-256 and SHA-512 in the Secure Shell (SSH) Protocol")
	citRFC8758 = rfc("8758", "Deprecating RC4 in Secure Shell (SSH)")
	citRFC6151 = rfc("6151", "Updated Security Considerations for the MD5 Message-Digest and the HMAC-MD5 Algorithms")
	citRFC6668 = rfc("6668", "SHA-2 Data Integrity Verification for the Secure Shell (SSH) Transport Layer Protocol")

	citTerrapin   = cve("CVE-2023-48795", "Terrapin: prefix truncation of the SSH handshake")
	citSSHCBC     = cve("CVE-2008-5161", "plaintext recovery from SSH in CBC mode")
	citSSH1       = cve("CVE-2001-0144", "SSH-1 CRC-32 compensation attack detector")
	citFIPS1865   = Citation{Title: "NIST FIPS 186-5: Digital Signature Standard (DSA no longer approved for signature generation)", URL: "https://doi.org/10.6028/NIST.FIPS.186-5"}
	citSP800131A  = Citation{Title: "NIST SP 800-131A Rev. 2: Transitioning the Use of Cryptographic Algorithms and Key Lengths", URL: "https://csrc.nist.gov/pubs/sp/800/131/a/r2/final"}
	citOpenSSH74  = Citation{Title: "OpenSSH 7.4 release notes (SSH-1 server support and pre-authentication compression removed)", URL: "https://www.openssh.org/txt/release-7.4"}
	citOpenSSH88  = Citation{Title: "OpenSSH 8.8 release notes (ssh-rsa SHA-1 signatures disabled by default)", URL: "https://www.openssh.org/txt/release-8.8"}
	citOpenSSH100 = Citation{Title: "OpenSSH 10.0 release notes (mlkem768x25519-sha256 the default key exchange; DSA removed)", URL: "https://www.openssh.org/txt/release-10.0"}
	citOpenSSH106 = Citation{Title: "OpenSSH 10.6 release notes (ssh-mldsa44-ed25519 host keys enabled)", URL: "https://www.openssh.org/releasenotes.html"}
	citSSHMLKEM   = rfc("10042", "Hybrid Post-Quantum Key Exchange with ML-KEM in the Secure Shell (SSH) Protocol")
	citSSHSntrup  = rfc("9941", "Secure Shell (SSH) Key Exchange Method Using Hybrid Streamlined NTRU Prime sntrup761 and X25519 with SHA-512")
	citSSHComp    = Citation{Title: "IETF draft-miller-sshm-composite-sigs: ML-DSA composite signatures in SSH", URL: "https://datatracker.ietf.org/doc/draft-miller-sshm-composite-sigs/"}
)

// sshCtx is the report plus the views the SSH rules use.
type sshCtx struct {
	rep     *sshprobe.Report
	alg     *sshprobe.Algorithms
	ciphers []string // client-to-server and server-to-client, once each
	macs    []string
	comp    []string
}

func mergeOrdered(a, b []string) []string {
	out := append([]string(nil), a...)
	for _, x := range b {
		if !contains(out, x) {
			out = append(out, x)
		}
	}
	return out
}

func newSSHCtx(rep *sshprobe.Report) *sshCtx {
	c := &sshCtx{rep: rep, alg: rep.Algorithms}
	if c.alg == nil {
		c.alg = &sshprobe.Algorithms{}
	}
	c.ciphers = mergeOrdered(c.alg.CipherC2S, c.alg.CipherS2C)
	c.macs = mergeOrdered(c.alg.MACC2S, c.alg.MACS2C)
	c.comp = mergeOrdered(c.alg.CompressionC2S, c.alg.CompressionS2C)
	return c
}

// pick lists the names of a kind that satisfy keep.
func pick(names []string, kind string, keep func(registry.Algorithm) bool) []string {
	var out []string
	for _, n := range names {
		if a, ok := registry.Lookup(kind, n); ok && keep(a) {
			out = append(out, n)
		}
	}
	return out
}

// sshRule is one cited judgement about an SSH endpoint.
type sshRule struct {
	id, title, category string
	severity            Severity
	evidence            Evidence
	citations           []Citation
	remediation         string
	check               func(*sshCtx) []hit
}

// offered is one hit listing the offending names, or none.
func offered(names []string) []hit {
	if len(names) == 0 {
		return nil
	}
	return one("Offered: " + strings.Join(names, ", ") + ".")
}

var sshRules = []sshRule{
	{id: "SSH.PROTOCOL-1", title: "SSH protocol version 1 is accepted", category: "protocol", severity: Critical, evidence: Observed,
		citations:   []Citation{citRFC4253, citSSH1, citOpenSSH74},
		remediation: "Upgrade the server: SSH-1 has been broken for two decades and OpenSSH removed it in 7.4. Only SSH-2 should answer.",
		check: func(c *sshCtx) []hit {
			if id := c.rep.Identification; id != nil && id.SSH1 {
				return one("The server identifies as " + id.Raw + ".")
			}
			return nil
		}},
	{id: "SSH.KEX-WEAK-GROUP", title: "A key exchange with a group or key under 2048 bits is offered", category: "key-exchange", severity: High, evidence: Observed,
		citations:   []Citation{citRFC9142, citLogjam},
		remediation: "Remove diffie-hellman-group1-sha1 and rsa1024-sha1 from KexAlgorithms in sshd_config.",
		check: func(c *sshCtx) []hit {
			return offered(pick(c.alg.Kex, registry.KindKex, func(a registry.Algorithm) bool { return a.GroupBits > 0 && a.GroupBits < 2048 }))
		}},
	{id: "SSH.KEX-SHA1", title: "A key exchange hashed with SHA-1 is offered", category: "key-exchange", severity: Low, evidence: Observed,
		citations:   []Citation{citRFC9142, citSP800131A},
		remediation: "Remove the -sha1 methods from KexAlgorithms in sshd_config; every current client supports curve25519-sha256 and the SHA-2 groups.",
		check: func(c *sshCtx) []hit {
			sha1 := pick(c.alg.Kex, registry.KindKex, func(a registry.Algorithm) bool { return a.Hash == "SHA-1" })
			if len(sha1) == 0 {
				return nil
			}
			h := hit{detail: "Offered: " + strings.Join(sha1, ", ") + "."}
			// RFC 9142: group1-sha1 and group-exchange-sha1 SHOULD NOT be implemented; group14-sha1 MAY.
			for _, n := range sha1 {
				if n != "diffie-hellman-group14-sha1" {
					h.severity = Medium
				}
			}
			return []hit{h}
		}},
	{id: "SSH.HOSTKEY-DSA", title: "A DSA host key is offered", category: "host-key", severity: High, evidence: Observed,
		citations:   []Citation{citFIPS1865, citOpenSSH100},
		remediation: "In sshd_config, remove the HostKey line for ssh_host_dsa_key and ssh-dss from HostKeyAlgorithms; use Ed25519 or ECDSA keys.",
		check: func(c *sshCtx) []hit {
			return offered(pick(c.alg.HostKey, registry.KindHostKey, func(a registry.Algorithm) bool { return a.Key == "DSA" }))
		}},
	{id: "SSH.HOSTKEY-RSA-SHA1", title: "RSA host key signatures with SHA-1 (ssh-rsa) are offered", category: "host-key", severity: Medium, evidence: Observed,
		citations:   []Citation{citRFC8332, citOpenSSH88, citSP800131A},
		remediation: "Remove ssh-rsa from HostKeyAlgorithms in sshd_config; keep rsa-sha2-512 and rsa-sha2-256, which use the same key.",
		check: func(c *sshCtx) []hit {
			if contains(c.alg.HostKey, "ssh-rsa") || contains(c.alg.HostKey, "ssh-rsa-cert-v01@openssh.com") {
				return one("ssh-rsa is advertised: a client that asks for it gets a SHA-1 signature.")
			}
			return nil
		}},
	{id: "SSH.HOSTKEY-RSA-SMALL", title: "An RSA host key is shorter than 2048 bits", category: "host-key", severity: High, evidence: Observed,
		citations:   []Citation{citSP800131A, citSP80057},
		remediation: "Generate a new host key of at least 3072 bits (ssh-keygen -t rsa -b 3072), or switch to Ed25519.",
		check: func(c *sshCtx) []hit {
			var out []hit
			for _, k := range c.rep.HostKeys {
				if k.Algorithm == "RSA" && k.Bits > 0 && k.Bits < 2048 {
					out = append(out, hit{detail: fmt.Sprintf("RSA %d-bit host key %s.", k.Bits, k.Fingerprint)})
				}
			}
			return out
		}},
	{id: "SSH.HOSTKEY-BAD-SIGNATURE", title: "A host key signature did not verify", category: "host-key", severity: Medium, evidence: Observed,
		citations:   []Citation{citRFC4253},
		remediation: "Check the HostKey files named in sshd_config and the server software: a server must sign the exchange hash with the key it presents. A mismatch can also mean something between the scanner and the server altered the exchange.",
		check: func(c *sshCtx) []hit {
			var out []hit
			for _, k := range c.rep.HostKeys {
				if !k.Verified && strings.Contains(k.VerifyNote, "did not verify") {
					out = append(out, hit{detail: k.Type + " " + k.Fingerprint + ": " + k.VerifyNote + "."})
				}
			}
			return out
		}},
	{id: "SSH.CIPHER-NONE", title: "No encryption (the none cipher) is offered", category: "cipher", severity: Critical, evidence: Observed,
		citations: []Citation{citRFC4253}, remediation: "Remove none from Ciphers in sshd_config.",
		check: func(c *sshCtx) []hit {
			if contains(c.ciphers, "none") {
				return one("The none cipher is advertised.")
			}
			return nil
		}},
	{id: "SSH.CIPHER-RC4", title: "RC4 (arcfour) ciphers are offered", category: "cipher", severity: High, evidence: Observed,
		citations: []Citation{citRFC8758}, remediation: "Remove arcfour, arcfour128 and arcfour256 from Ciphers in sshd_config.",
		check: func(c *sshCtx) []hit {
			return offered(pick(c.ciphers, registry.KindCipher, func(a registry.Algorithm) bool { return a.Cipher == "RC4" }))
		}},
	{id: "SSH.CIPHER-DES", title: "Single DES is offered", category: "cipher", severity: High, evidence: Observed,
		citations: []Citation{citSP800131A}, remediation: "Remove des-cbc from Ciphers in sshd_config.",
		check: func(c *sshCtx) []hit {
			return offered(pick(c.ciphers, registry.KindCipher, func(a registry.Algorithm) bool { return a.Cipher == "DES" }))
		}},
	{id: "SSH.CIPHER-64BIT-BLOCK", title: "Ciphers with a 64-bit block are offered", category: "cipher", severity: Medium, evidence: Observed,
		citations:   []Citation{citSweet32, citSP800131A},
		remediation: "Remove 3des-cbc, blowfish-cbc, cast128-cbc and idea-cbc from Ciphers in sshd_config; AES-GCM, AES-CTR and ChaCha20-Poly1305 are available in every current client.",
		check: func(c *sshCtx) []hit {
			return offered(pick(c.ciphers, registry.KindCipher, func(a registry.Algorithm) bool { return a.BlockBits == 64 }))
		}},
	{id: "SSH.CIPHER-CBC", title: "CBC-mode ciphers are offered", category: "cipher", severity: Low, evidence: Observed,
		citations:   []Citation{citSSHCBC},
		remediation: "Remove the -cbc ciphers from Ciphers in sshd_config; keep chacha20-poly1305@openssh.com, aes*-gcm@openssh.com and aes*-ctr.",
		check: func(c *sshCtx) []hit {
			return offered(pick(c.ciphers, registry.KindCipher, func(a registry.Algorithm) bool { return a.Mode == "CBC" }))
		}},
	{id: "SSH.MAC-NONE", title: "No integrity protection (the none MAC) is offered", category: "mac", severity: Critical, evidence: Observed,
		citations: []Citation{citRFC4253}, remediation: "Remove none from MACs in sshd_config.",
		check: func(c *sshCtx) []hit {
			if contains(c.macs, "none") {
				return one("The none MAC is advertised.")
			}
			return nil
		}},
	{id: "SSH.MAC-WEAK", title: "Weak MACs (MD5, truncated or 64-bit tags) are offered", category: "mac", severity: Medium, evidence: Observed,
		citations:   []Citation{citRFC6151, citRFC6668},
		remediation: "Remove hmac-md5*, hmac-sha1-96* and umac-64* from MACs in sshd_config; keep hmac-sha2-256-etm@openssh.com and hmac-sha2-512-etm@openssh.com.",
		check: func(c *sshCtx) []hit {
			weak := pick(c.macs, registry.KindMAC, func(a registry.Algorithm) bool { return a.Hash == "MD5" || a.TagBits > 0 && a.TagBits < 128 })
			hits := offered(weak)
			// A 64-bit UMAC tag alone (in OpenSSH's own default list) is a smaller margin, not a break: Low.
			if len(hits) > 0 && len(pick(weak, registry.KindMAC, func(a registry.Algorithm) bool { return a.Hash != "UMAC" })) == 0 {
				hits[0].severity = Low
			}
			return hits
		}},
	{id: "SSH.MAC-SHA1", title: "HMAC-SHA-1 is offered", category: "mac", severity: Info, evidence: Observed,
		citations:   []Citation{citRFC6668, citSP800131A},
		remediation: "HMAC-SHA-1 is not broken, but SHA-2 MACs are available in every current client: prefer hmac-sha2-256-etm@openssh.com and drop hmac-sha1 when old clients no longer need it.",
		check: func(c *sshCtx) []hit {
			return offered(pick(c.macs, registry.KindMAC, func(a registry.Algorithm) bool { return a.Hash == "SHA-1" && a.TagBits >= 128 }))
		}},
	{id: "SSH.MAC-NOT-ETM", title: "MACs that authenticate before encrypting are offered", category: "mac", severity: Info, evidence: Observed,
		citations:   []Citation{citSSHCBC, citRFC4253},
		remediation: "Prefer the -etm@openssh.com MACs (encrypt-then-MAC); the original SSH MACs authenticate the plaintext, which is what made the CBC attacks possible.",
		check: func(c *sshCtx) []hit {
			if len(pick(c.ciphers, registry.KindCipher, func(a registry.Algorithm) bool { return !a.AEAD && a.Cipher != "none" })) == 0 {
				return nil // with AEAD ciphers only, no MAC is ever used
			}
			return offered(pick(c.macs, registry.KindMAC, func(a registry.Algorithm) bool { return !a.ETM && a.Hash != "none" }))
		}},
	{id: "SSH.COMPRESSION-PREAUTH", title: "Compression before authentication (zlib) is offered", category: "feature", severity: Info, evidence: Observed,
		citations:   []Citation{citOpenSSH74},
		remediation: "Use Compression delayed (zlib@openssh.com) or no, so unauthenticated clients cannot reach the decompressor.",
		check: func(c *sshCtx) []hit {
			if contains(c.comp, "zlib") {
				return one("zlib is advertised: compression starts before the client has authenticated.")
			}
			return nil
		}},
	{id: "SSH.TERRAPIN", title: "Vulnerable to the Terrapin prefix truncation attack", category: "vulnerability", severity: Medium, evidence: Inferred,
		citations:   []Citation{citTerrapin},
		remediation: "Upgrade to a server that supports strict key exchange (OpenSSH 9.6 or later), or remove chacha20-poly1305@openssh.com and the -etm MACs combined with CBC ciphers.",
		check: func(c *sshCtx) []hit {
			if c.alg.StrictKex {
				return nil
			}
			var why []string
			if contains(c.ciphers, "chacha20-poly1305@openssh.com") {
				why = append(why, "chacha20-poly1305@openssh.com")
			}
			cbc := pick(c.ciphers, registry.KindCipher, func(a registry.Algorithm) bool { return a.Mode == "CBC" })
			etm := pick(c.macs, registry.KindMAC, func(a registry.Algorithm) bool { return a.ETM })
			if len(cbc) > 0 && len(etm) > 0 {
				why = append(why, "CBC ciphers with encrypt-then-MAC MACs")
			}
			if len(why) == 0 {
				return nil
			}
			return one("The server offers " + strings.Join(why, " and ") + " without strict key exchange (kex-strict-s-v00@openssh.com).")
		}},
}

// sshAttackLabels name the attacks an SSH finding enables.
var sshAttackLabels = map[string][]string{
	"SSH.TERRAPIN": {"Terrapin"}, "SSH.CIPHER-64BIT-BLOCK": {"SWEET32"}, "SSH.KEX-WEAK-GROUP": {"Logjam"},
	"SSH.CIPHER-CBC": {"CBC plaintext recovery"}, "SSH.CIPHER-RC4": {"RC4 biases"},
}

var sshInferableAttacks = []struct{ name, needs string }{
	{"Terrapin", "chacha20-poly1305@openssh.com, or CBC with encrypt-then-MAC, without strict key exchange"},
	{"SWEET32", "64-bit block ciphers"},
	{"Logjam", "a Diffie-Hellman group or RSA key exchange under 2048 bits"},
	{"CBC plaintext recovery", "CBC-mode ciphers"},
	{"RC4 biases", "RC4 ciphers"},
}

var sshActiveOnlyAttacks = []struct{ name, why string }{
	{"Server software flaws (regreSSHion and others)", "Not tested: they depend on the server's software and version, not its configuration. Check the vendor's advisories for the version shown."},
	{"Authentication weaknesses", "Not tested: this product never attempts a login, so password policy, user enumeration and key handling are out of its view."},
}

func sshSectionOf(f Finding) string {
	switch f.Category {
	case "protocol":
		return SecSSHVersion
	case "key-exchange", "pqc":
		if f.ID == "PQC.CLASSICAL-AUTH" {
			return SecHostKeys
		}
		return SecKeyExchange
	case "host-key":
		return SecHostKeys
	case "cipher":
		return SecEncryption
	case "mac", "feature":
		return SecIntegrity
	}
	return SecVulnerabilities
}

// sshStageFor names the scan stage each SSH section depends on.
var sshStageFor = map[string]string{
	SecSSHVersion: sshprobe.StageIdentification, SecKeyExchange: sshprobe.StageAlgorithms, SecHostKeys: sshprobe.StageHostKeys,
	SecEncryption: sshprobe.StageAlgorithms, SecIntegrity: sshprobe.StageAlgorithms, SecVulnerabilities: sshprobe.StageAlgorithms,
}

// SSHRuleIDs lists the SSH rules (for tests and the methodology page).
func SSHRuleIDs() []string {
	out := make([]string, 0, len(sshRules))
	for _, r := range sshRules {
		out = append(out, r.id)
	}
	return out
}

// EvaluateSSH judges an SSH scan report.
func EvaluateSSH(rep *sshprobe.Report, in Input) Evaluation {
	c := newSSHCtx(rep)
	var findings []Finding
	var checks []Check
	for _, r := range sshRules {
		ch := Check{ID: r.id, Title: r.title, Severity: r.severity, Result: "not-found", Pass: passText[r.id],
			Section: sshSectionOf(Finding{ID: r.id, Category: r.category})}
		hits := r.check(c)
		if len(hits) > 0 {
			ch.Result = "found"
		}
		checks = append(checks, ch)
		for _, h := range hits {
			sev, ev := r.severity, r.evidence
			if h.severity != "" {
				sev = h.severity
			}
			if h.evidence != "" {
				ev = h.evidence
			}
			findings = append(findings, Finding{ID: r.id, Title: r.title, Severity: sev, Category: r.category,
				Detail: h.detail, Evidence: ev, Citations: r.citations, Remediation: r.remediation})
		}
	}

	ready := sshReadiness(c)
	pf := sshPQCFindings(c, ready)
	findings = append(findings, pf...)
	for _, f := range pf {
		checks = append(checks, Check{ID: f.ID, Title: f.Title, Severity: f.Severity, Result: "found", Section: sshSectionOf(f)})
	}
	if !containsCheck(checks, "PQC.HNDL-EXPOSED") && !containsCheck(checks, "PQC.NO-PQ-POSSIBLE") {
		checks = append(checks, Check{ID: "PQC.HNDL-EXPOSED", Title: "Traffic is exposed to harvest-now-decrypt-later", Severity: Medium,
			Result: "not-found", Section: SecKeyExchange, Pass: passText["PQC.HNDL-EXPOSED"]})
	}

	sort.SliceStable(findings, func(i, j int) bool {
		if findings[i].Severity.Rank() != findings[j].Severity.Rank() {
			return findings[i].Severity.Rank() < findings[j].Severity.Rank()
		}
		return findings[i].ID < findings[j].ID
	})
	for i := range findings {
		f := &findings[i]
		f.Section = sshSectionOf(*f)
		f.Labels = append([]string(nil), sshAttackLabels[f.ID]...)
	}
	counts := map[Severity]int{}
	for _, f := range findings {
		counts[f.Severity]++
	}
	ev := Evaluation{Version: Version, Protocol: ProtocolSSH, Findings: findings, Readiness: ready, Counts: counts,
		EvaluatedAt: in.Now.UTC(), PKI: []ChainView{}, ReferenceData: []RefInfo{}}
	ev.Hygiene = Hygiene{Score: -1, Deductions: []Deduction{}, NotMeasured: []string{}, Methodology: sshNoScore}
	b, ok := SSHBaselineByID(in.SSHBaseline)
	if !ok {
		b, _ = SSHBaselineByID(BaselineDefault)
	}
	ev.Baseline = sshConformance(c, b)
	ev.Sections = sshSections(c, findings, ev.Baseline)
	skipped := map[string]string{}
	for _, s := range ev.Sections {
		switch s.Status {
		case StatusNotChecked, StatusNotCollected:
			skipped[s.ID] = "not-checked"
		case StatusNotApplicable:
			skipped[s.ID] = "not-applicable"
		}
	}
	for i := range checks {
		if r := skipped[checks[i].Section]; checks[i].Result == "not-found" && r != "" {
			checks[i].Result = r
		}
	}
	ev.Checks = checks
	ev.FixFirst = fixFirst(findings)
	ev.Vulnerabilities = sshAttacks(findings)
	ev.SSHAlgorithms = sshAlgorithmViews(c, b)
	return ev
}

// sshNoScore is the Hygiene.Methodology of an SSH evaluation: SSH servers get no 0 to 100 score
// (PRD-008 REQ-SHE-5); they are judged against a baseline, which Evaluation.Baseline holds.
const sshNoScore = "SSH servers are not scored. They are judged against an SSH baseline: see the baseline verdict."

// sshBaselineSection is the report section a baseline change belongs to.
func sshBaselineSection(ch BaselineChange) string {
	switch {
	case ch.Kind == registry.KindKex || ch.Action == ChangeUpgrade && ch.Kind == "":
		return SecKeyExchange
	case ch.Kind == registry.KindHostKey:
		return SecHostKeys
	case ch.Kind == registry.KindCipher:
		return SecEncryption
	}
	return SecIntegrity
}

// sshSections rates each area from its findings; an area the baseline wants changed is at least
// "needs attention" (PRD-008 WP-G), so a section never reads good beside a change to make.
func sshSections(c *sshCtx, findings []Finding, conf *Conformance) []Section {
	needsChange := map[string]bool{}
	if conf != nil && conf.Judged && c.rep.Algorithms != nil {
		for _, ch := range conf.Changes {
			needsChange[sshBaselineSection(ch)] = true
		}
	}
	stages := map[string]tlsprobe.Stage{}
	for _, s := range c.rep.Stages {
		stages[s.Name] = s
	}
	var out []Section
	for _, id := range SSHSectionOrder {
		s := Section{ID: id, Findings: []string{}}
		worst := Info
		for _, f := range findings {
			if f.Section != id && (id != SecVulnerabilities || len(f.Labels) == 0) {
				continue
			}
			if !contains(s.Findings, f.ID) {
				s.Findings = append(s.Findings, f.ID)
			}
			if f.Severity.Rank() < worst.Rank() {
				worst = f.Severity
			}
		}
		switch {
		case worst.Rank() <= High.Rank():
			s.Status = StatusProblem
		case worst.Rank() <= Low.Rank():
			s.Status = StatusAttention
		default:
			s.Status = StatusGood
		}
		if id == SecVulnerabilities && len(s.Findings) > 0 && s.Status == StatusGood {
			s.Status = StatusAttention
		}
		if needsChange[id] && s.Status == StatusGood {
			s.Status = StatusAttention
		}
		if st, ok := stages[sshStageFor[id]]; ok {
			s.Inconclusive = st.Inconclusive
			switch st.Outcome {
			case tlsprobe.OutcomeSkipped:
				s.Status, s.Reason, s.ReasonCode = StatusNotChecked, st.Reason, st.ReasonCode
				if st.ReasonCode == tlsprobe.ReasonNotApplicable {
					s.Status = StatusNotApplicable
				}
			case tlsprobe.OutcomeInconclusive:
				s.Status, s.Reason, s.ReasonCode = StatusInconclusive, st.Reason, st.ReasonCode
			}
		}
		// SSH-1 is a protocol finding whatever the other stages did.
		if id == SecSSHVersion && contains(s.Findings, "SSH.PROTOCOL-1") {
			s.Status = StatusProblem
		}
		out = append(out, s)
	}
	return out
}

func sshAttacks(findings []Finding) []AttackView {
	by := map[string][]string{}
	for _, f := range findings {
		for _, l := range f.Labels {
			if !contains(by[l], f.ID) {
				by[l] = append(by[l], f.ID)
			}
		}
	}
	out := []AttackView{}
	for _, a := range sshInferableAttacks {
		v := AttackView{Name: a.name, Status: "not-exposed", Needs: a.needs, Why: "Needs " + a.needs + "; not seen on this server."}
		if ids := by[a.name]; len(ids) > 0 {
			v.Status, v.Findings, v.Why = "exposed", ids, "Possible: the server offers "+a.needs+"."
		}
		out = append(out, v)
	}
	for _, a := range sshActiveOnlyAttacks {
		out = append(out, AttackView{Name: a.name, Status: "not-tested", Why: a.why})
	}
	return out
}

// ---- readiness ----------------------------------------------------------------------------------

func sshReadiness(c *sshCtx) Readiness {
	rep := c.rep
	r := Readiness{PQGroups: []string{}, ObsoletePQGroups: []string{}}
	pq := c.alg.PQKex()
	r.PQGroups = append(r.PQGroups, pq...)
	n := rep.Negotiated
	keyEv := Observed
	switch {
	case rep.Identification != nil && rep.Identification.SSH1Only:
		r.Level = LevelNotReady
	case rep.Algorithms == nil:
		r.Level = LevelUndetermined
	case len(pq) == 0:
		r.Level = LevelExposed
	case n != nil && n.Kex != "" && contains(pq, n.Kex) && (n.Completed || n.Evidence == sshprobe.EvidenceComputed):
		r.Level = LevelHybridNeg
		if !n.Completed {
			keyEv = Inferred
		}
	default:
		r.Level = LevelHybridAvail
	}
	pqKeys := sshPQHostKeys(rep)
	if r.Level == LevelHybridNeg && len(pqKeys) > 0 {
		r.Level = LevelPQAuth
	}
	r.Label = LevelLabel(r.Level)
	r.HNDLExposed = r.Level >= LevelNotReady && r.Level < LevelHybridNeg

	ke := Dimension{Evidence: keyEv, Citations: []Citation{citSSHMLKEM, citFIPS203, citHNDL, citOpenSSH100}}
	switch r.Level {
	case LevelUndetermined:
		ke.Status, ke.Evidence = "undetermined", NotMeasured
		ke.Detail = "The server's algorithm lists could not be read; re-scan."
	case LevelNotReady:
		ke.Status = "unavailable"
		ke.Detail = "The server speaks only SSH-1, which has no post-quantum key exchange."
	case LevelExposed:
		ke.Status = "classical"
		ke.Detail = "Key exchanges offered: " + orNone(c.alg.Kex) + ". None is post-quantum."
	case LevelHybridAvail:
		ke.Status = "hybrid-available"
		ke.Detail = "Offers " + strings.Join(pq, ", ") + ", but negotiating as " + sshprobe.CurrentClient + " did not end on it"
		if n != nil && n.Error != "" {
			ke.Detail += " (" + n.Error + ")"
		}
		ke.Detail += "."
	default:
		ke.Status = "hybrid-negotiated"
		ke.Detail = "A current client (" + sshprobe.CurrentClient + ") negotiates " + n.Kex
		if n.Completed {
			ke.Detail += "; the exchange was carried out and the server's signature verified."
			if !n.Verified {
				ke.Detail = "A current client (" + sshprobe.CurrentClient + ") negotiates " + n.Kex + "; the exchange was carried out."
			}
		} else {
			ke.Detail += " (chosen by the two lists, RFC 4253 section 7.1; this scanner does not carry that method out)."
		}
	}
	r.KeyEstablishment = ke
	r.Authentication = sshAuthDimension(rep, pqKeys)
	r.Symmetric = sshSymmetric(c)
	r.Summary, r.NextSteps = sshNarrative(r.Level)
	r.Citations = []Citation{citHNDL, citSSHMLKEM, citFIPS203, citFIPS204, citIR8547, citOpenSSH100, citOpenSSH106}
	return r
}

func sshPQHostKeys(rep *sshprobe.Report) []string {
	var out []string
	for _, k := range rep.HostKeys {
		if k.PQ && !contains(out, k.Type) {
			out = append(out, k.Type)
		}
	}
	return out
}

func sshAuthDimension(rep *sshprobe.Report, pqKeys []string) Dimension {
	d := Dimension{Citations: []Citation{citIR8547, citFIPS204, citSSHComp}}
	if len(rep.HostKeys) == 0 {
		d.Status, d.Evidence = "unknown", NotMeasured
		d.Detail = "No host key was fetched, so the authentication algorithms are unknown."
		return d
	}
	var algs []string
	for _, k := range rep.HostKeys {
		label := k.Algorithm
		switch {
		case k.Bits > 0 && k.Algorithm == "RSA":
			label = fmt.Sprintf("RSA %d-bit", k.Bits)
		case k.Curve != "":
			label += " " + k.Curve
		}
		if !contains(algs, label) {
			algs = append(algs, label)
		}
	}
	sort.Strings(algs)
	d.Evidence = Observed
	if len(pqKeys) > 0 {
		d.Status = "post-quantum"
		d.Detail = "Host keys: " + strings.Join(algs, ", ") + ". The server holds a post-quantum host key (" + strings.Join(pqKeys, ", ") + ")."
		return d
	}
	d.Status = "classical"
	d.Detail = "Host keys: " + strings.Join(algs, ", ") + ". All are quantum-vulnerable signatures; this matters for future impersonation, not for recorded sessions."
	return d
}

func sshSymmetric(c *sshCtx) Dimension {
	d := Dimension{Evidence: Observed, Citations: []Citation{citNISTCategories}}
	if len(c.ciphers) == 0 {
		d.Status, d.Evidence = "unknown", NotMeasured
		d.Detail = "No ciphers were read."
		return d
	}
	minBits, none := 0, false
	for _, n := range c.ciphers {
		a, ok := registry.Lookup(registry.KindCipher, n)
		if !ok {
			continue
		}
		if a.Cipher == "none" {
			none = true
			continue
		}
		if minBits == 0 || a.KeyBits < minBits {
			minBits = a.KeyBits
		}
	}
	switch {
	case none:
		d.Status, d.Detail = "inadequate", "The server offers the none cipher: no encryption at all."
	case minBits > 0 && minBits < 128:
		d.Status, d.Detail = "inadequate", fmt.Sprintf("The weakest offered cipher has a %d-bit key; NIST's post-quantum categories start at AES-128.", minBits)
	case minBits == 0:
		d.Status, d.Evidence, d.Detail = "unknown", NotMeasured, "No offered cipher is in this program's registry."
	default:
		d.Status, d.Detail = "adequate", fmt.Sprintf("Every offered cipher has a key of at least %d bits (AES-128 is NIST category 1).", minBits)
	}
	return d
}

func sshNarrative(level int) (string, []string) {
	switch level {
	case LevelUndetermined:
		return "The scan could not read the server's algorithm lists, so readiness is unknown.",
			[]string{"Re-run the scan; check the port is the SSH service and reachable."}
	case LevelNotReady:
		return "The server speaks only SSH-1: no post-quantum key exchange is possible.",
			[]string{"Replace the server software with a current SSH-2 implementation (OpenSSH 10 or later)."}
	case LevelExposed:
		return "Only classical key exchange: recorded sessions could be decrypted by a future quantum computer.",
			[]string{"Upgrade to OpenSSH 9.9 or later and put mlkem768x25519-sha256 first in KexAlgorithms (the default from OpenSSH 10.0).",
				"Keep curve25519-sha256 for clients that are not ready."}
	case LevelHybridAvail:
		return "A post-quantum hybrid key exchange is offered, but a current client does not end up using it.",
			[]string{"Check that the hybrid method completes: a current client fell back to a classical one."}
	case LevelHybridNeg:
		return "A current client gets a post-quantum hybrid key exchange: recorded sessions are protected.",
			[]string{"Keep the hybrid method first; remove classical-only methods as clients allow.",
				"Plan post-quantum host keys (ssh-mldsa44-ed25519, enabled in OpenSSH 10.6)."}
	}
	return "Post-quantum key exchange and a post-quantum host key.",
		[]string{"Maintain; keep classical host keys only while clients need them."}
}

func sshPQCFindings(c *sshCtx, r Readiness) []Finding {
	var out []Finding
	// Every SSH post-quantum finding rests on the server's own lists or keys: observed.
	add := func(id, title string, sev Severity, detail, remed string, cites ...Citation) {
		out = append(out, Finding{ID: id, Title: title, Severity: sev, Category: "pqc", Detail: detail, Evidence: Observed, Citations: cites, Remediation: remed})
	}
	switch r.Level {
	case LevelNotReady:
		add("PQC.NO-PQ-POSSIBLE", "No post-quantum key exchange is possible (SSH-1 only)", Medium, r.KeyEstablishment.Detail, r.NextSteps[0], citHNDL)
	case LevelExposed:
		add("PQC.HNDL-EXPOSED", "Traffic is exposed to harvest-now-decrypt-later", Medium, r.KeyEstablishment.Detail, r.NextSteps[0],
			citHNDL, citSSHMLKEM, citFIPS203, citOpenSSH100)
	case LevelHybridAvail:
		add("PQC.HYBRID-NOT-NEGOTIATED", "A hybrid key exchange is offered but not negotiated by default", Low, r.KeyEstablishment.Detail, r.NextSteps[0], citSSHMLKEM)
	}
	// PD-3: sntrup761 protects against harvest-now-decrypt-later, but it is not a NIST standard.
	if r.Level >= LevelHybridNeg {
		fips := pick(c.alg.Kex, registry.KindKex, func(a registry.Algorithm) bool { return a.FIPS })
		sntrup := pick(c.alg.Kex, registry.KindKex, func(a registry.Algorithm) bool { return a.PQ && !a.FIPS })
		if len(fips) == 0 && len(sntrup) > 0 {
			add("SSH.PQ-NOT-FIPS", "The post-quantum key exchange is not a NIST-standardised one", Low,
				"Offered post-quantum methods: "+strings.Join(sntrup, ", ")+". Streamlined NTRU Prime is not a NIST standard; ML-KEM (FIPS 203) is.",
				"Upgrade to OpenSSH 9.9 or later and offer mlkem768x25519-sha256 first; programmes bound to FIPS 203 need ML-KEM.",
				citSSHSntrup, citFIPS203, citSSHMLKEM)
		}
	}
	if r.Authentication.Status == "classical" {
		add("PQC.CLASSICAL-AUTH", "Host keys use classical (quantum-vulnerable) signatures", Info, r.Authentication.Detail,
			"No action needed yet. Plan ssh-mldsa44-ed25519 host keys (OpenSSH 10.6) once your clients support them.", citIR8547, citFIPS204, citOpenSSH106)
	}
	if r.Symmetric.Status == "inadequate" {
		add("PQC.SYMMETRIC-INADEQUATE", "Symmetric ciphers below the post-quantum baseline are offered", Medium, r.Symmetric.Detail,
			"Remove ciphers with keys under 128 bits.", citNISTCategories)
	}
	return out
}

// SSHAlgorithm is one advertised SSH algorithm with its verdict, so the report can show, for each
// name, what it is and whether that is right (UX-DESIGN-006 §2.4) without judging in the browser.
type SSHAlgorithm struct {
	Kind    string `json:"kind"` // kex | host-key | cipher | mac | compression
	Name    string `json:"name"`
	Display string `json:"display"`
	// Verdict is post-quantum, fine, should-be-off or unknown (not in this program's registry).
	Verdict string `json:"verdict"`
	// Used: a current client (OpenSSH 10.6 defaults) uses it.
	Used bool `json:"used,omitempty"`
	// Baseline is allowed or off against the evaluation's baseline (PRD-008 REQ-SHB-3).
	Baseline string `json:"baseline"`
	// Strength is its classical strength (PRD-010 REQ-STR-7); nil for compression.
	Strength *algo.Strength `json:"strength,omitempty"`
}

// sshAlgorithmViews lists every advertised algorithm, kind by kind, in the server's order.
func sshAlgorithmViews(c *sshCtx, b *SSHBaseline) []SSHAlgorithm {
	n := c.rep.Negotiated
	if n == nil {
		n = &sshprobe.Negotiated{}
	}
	used := map[string]string{registry.KindKex: n.Kex, registry.KindHostKey: n.HostKey, registry.KindCipher: n.Cipher, registry.KindMAC: n.MAC, registry.KindCompression: n.Compression}
	out := []SSHAlgorithm{}
	for _, l := range []struct {
		kind  string
		names []string
	}{{registry.KindKex, c.alg.Kex}, {registry.KindHostKey, c.alg.HostKey}, {registry.KindCipher, c.ciphers}, {registry.KindMAC, c.macs}, {registry.KindCompression, c.comp}} {
		for _, name := range l.names {
			a, ok := registry.Lookup(l.kind, name)
			v := SSHAlgorithm{Kind: l.kind, Name: name, Display: a.Display, Used: used[l.kind] == name, Baseline: BaselineOff,
				Strength: sshStrength(l.kind, name, a, ok, c.rep.HostKeys)}
			if registry.IsPseudo(name) {
				v.Baseline = ""
			} else if b.allows(l.kind, name) {
				v.Baseline = BaselineAllowed
			}
			switch {
			case !ok:
				v.Verdict = "unknown"
			case a.PQ:
				v.Verdict = "post-quantum"
			case sshWeak(l.kind, name) || l.kind == registry.KindCompression && name == "zlib":
				v.Verdict = "should-be-off"
			default:
				v.Verdict = "fine"
			}
			out = append(out, v)
		}
	}
	return out
}
