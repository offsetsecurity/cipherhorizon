package eval

import (
	"strings"

	"github.com/offsetsecurity/cipherhorizon/internal/sshprobe/registry"
)

// The SSH standards. Clauses read from the documents on 2026-11-08; see standards_tls.go.

var sshStandards = []*Standard{&bsiTR021024, &cnsa2SSH}

// sreq is an SSH requirement.
func sreq(id, clause, level, text string, check func(*sshCheck) Verdict) Requirement {
	return Requirement{ID: id, Clause: clause, Level: level, Text: text, sshChk: check}
}

// ---- BSI TR-02102-4 (2026-01) ------------------------------------------------------------------------

// Table 2. RFC 5647's AEAD_AES_*_GCM are the GCM ciphers; OpenSSH names the same algorithms
// aes128-gcm@openssh.com and aes256-gcm@openssh.com, which are accepted as the same mechanism.
// Table 4's hmac-sha2-256 and -512 are accepted in OpenSSH's encrypt-then-MAC spelling too:
// the MAC algorithm is the one the table names, computed over the ciphertext.
var (
	bsiSSHKex = []string{"diffie-hellman-group-exchange-sha256", "diffie-hellman-group15-sha512", "diffie-hellman-group16-sha512",
		"ecdh-sha2-nistp256", "ecdh-sha2-nistp384", "ecdh-sha2-nistp521",
		// §3.3 note: the hybrids BSI intends to recommend once the RFC is adopted (RFC 10042 now is).
		"mlkem768nistp256-sha256", "mlkem1024nistp384-sha384"}
	bsiSSHCiphers = []string{"AEAD_AES_128_GCM", "AEAD_AES_256_GCM", "aes128-gcm@openssh.com", "aes256-gcm@openssh.com", "aes128-ctr", "aes192-ctr", "aes256-ctr"}
	bsiSSHMACs    = []string{"hmac-sha2-256", "hmac-sha2-512", "hmac-sha2-256-etm@openssh.com", "hmac-sha2-512-etm@openssh.com"}
	bsiSSHHostKey = []string{"ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521",
		"ecdsa-sha2-nistp256-cert-v01@openssh.com", "ecdsa-sha2-nistp384-cert-v01@openssh.com", "ecdsa-sha2-nistp521-cert-v01@openssh.com",
		"x509v3-ecdsa-sha2-nistp256", "x509v3-ecdsa-sha2-nistp384", "x509v3-ecdsa-sha2-nistp521", "pgp-sign-dss"}
)

var bsiTR021024 = Standard{
	ID: "bsi-tr-02102-4", Title: "BSI TR-02102-4", Publisher: "BSI (Germany)", Edition: "Version 2026-01", Protocol: "ssh",
	URL:   "https://www.bsi.bund.de/EN/Themen/Unternehmen-und-Organisationen/Standards-und-Zertifizierung/Technische-Richtlinien/TR-nach-Thema-sortiert/tr02102/tr02102_node.html",
	Scope: "The German Federal Office for Information Security's recommendations for SSH: the key exchange methods, ciphers, MACs and host-key signatures it recommends, at a 120-bit security level.",
	Requirements: []Requirement{
		sreq("ssh2", "§3.2", LevelMust, "SSH-2 is used; SSH-1 is not", func(s *sshCheck) Verdict {
			id := s.rep.Identification
			if id == nil {
				return notAssessed("the identification line was not read")
			}
			if id.SSH1 {
				return notMet("the server accepts SSH-1 (" + id.Raw + ")")
			}
			return met("SSH-2 only")
		}),
		sreq("kex", "§3.3, Table 2", LevelMust, "Only recommended key exchange methods are offered (group exchange SHA-256, group 15 and 16 SHA-512, ECDH on nistp256/384/521; the ML-KEM hybrids on NIST curves)",
			func(s *sshCheck) Verdict { return s.onlyFrom(registry.KindKex, bsiSSHKex, "TR-02102-4 Table 2") }),
		sreq("pq-kex", "§3.1.3, §3.3", LevelShould, "A quantum-safe hybrid key exchange is offered (classical key agreement alone is recommended only until the end of 2031)",
			func(s *sshCheck) Verdict {
				if !s.listed() {
					return notAssessed("the server's algorithm lists were not read")
				}
				if pq := s.alg.PQKex(); len(pq) > 0 {
					return met(strings.Join(pq, ", ") + " offered")
				}
				return notMet("no post-quantum hybrid key exchange is offered")
			}),
		sreq("ciphers", "§3.4, Table 3", LevelMust, "Only recommended encryption algorithms are offered (AES-GCM, AES-CTR)",
			func(s *sshCheck) Verdict { return s.onlyFrom(registry.KindCipher, bsiSSHCiphers, "TR-02102-4 Table 3") }),
		sreq("macs", "§3.5, Table 4", LevelMust, "Only recommended MAC algorithms are offered (hmac-sha2-256, hmac-sha2-512)",
			func(s *sshCheck) Verdict { return s.onlyFrom(registry.KindMAC, bsiSSHMACs, "TR-02102-4 Table 4") }),
		sreq("hostkeys", "§3.6, Table 5", LevelMust, "Only recommended host-key signature algorithms are offered (ECDSA on nistp256/384/521, their X.509 forms; pgp-sign-dss until 2029)",
			func(s *sshCheck) Verdict {
				return s.onlyFrom(registry.KindHostKey, bsiSSHHostKey, "TR-02102-4 Table 5")
			}),
	},
	NotAssessed: []string{
		"§3.3 remark 1: the group-exchange prime's size and safe-prime property (the scan does not complete a group exchange)",
		"§3.3.1 key re-exchange after one hour or one gigabyte", "§3.7 client authentication method", "§4 key storage and random numbers",
	},
}

// ---- CNSA 2.0 (SSH) ----------------------------------------------------------------------------------

var cnsa2SSH = Standard{
	ID: "cnsa-2.0-ssh", Title: "CNSA 2.0 for SSH", Publisher: "NSA (via IETF profiles)", Edition: "draft-becker-cnsa2-ssh-profile-07 (October 2026); RFC 9212 for the CNSA 1.0 transition", Protocol: "ssh",
	URL:   "https://datatracker.ietf.org/doc/draft-becker-cnsa2-ssh-profile/",
	Scope: "The Commercial National Security Algorithm Suite for SSH on US national security systems: mlkem1024-sha384, ML-DSA-87 host keys and AES-256-GCM, with ECDH/ECDSA P-384 and RSA 3072+ allowed during the transition.",
	Requirements: []Requirement{
		sreq("kex", "draft §4.1, §5.2; RFC 9212 §4", LevelMust, "Only CNSA key exchange methods are offered: mlkem1024-sha384, or during the transition ecdh-sha2-nistp384, group15 and group16 SHA-512",
			func(s *sshCheck) Verdict {
				return s.onlyFrom(registry.KindKex, []string{"mlkem1024-sha384", "ecdh-sha2-nistp384", "diffie-hellman-group15-sha512", "diffie-hellman-group16-sha512"}, "the CNSA profiles")
			}),
		sreq("kex-first", "draft §4.1", LevelShould, "mlkem1024-sha384 is listed first", func(s *sshCheck) Verdict { return s.firstIs(registry.KindKex, []string{"mlkem1024-sha384"}) }),
		sreq("hostkey", "draft §4.1, §5.3; RFC 9212 §5", LevelMust, "Only CNSA host-key algorithms are offered: ssh-mldsa-87, or during the transition ECDSA nistp384 or RSA with SHA-2 (3072 bits and above)",
			func(s *sshCheck) Verdict {
				return s.onlyFrom(registry.KindHostKey, []string{"ssh-mldsa-87", "ssh-mldsa87", "ecdsa-sha2-nistp384", "x509v3-ecdsa-sha2-nistp384",
					"rsa-sha2-512", "rsa-sha2-256", "x509v3-rsa2048-sha256"}, "the CNSA profiles")
			}),
		sreq("hostkey-first", "draft §5.3", LevelShould, "ML-DSA-87 is the most preferred host-key algorithm", func(s *sshCheck) Verdict {
			return s.firstIs(registry.KindHostKey, []string{"ssh-mldsa-87", "ssh-mldsa87"})
		}),
		sreq("rsa-3072", "RFC 9212 §5", LevelMust, "RSA host keys are 3072 bits or more", func(s *sshCheck) Verdict { return s.rsaKeysAtLeast(3072) }),
		sreq("cipher", "draft §4.1; RFC 9212 §6", LevelMust, "Only AES-256-GCM is offered for encryption",
			func(s *sshCheck) Verdict {
				return s.onlyFrom(registry.KindCipher, []string{"AEAD_AES_256_GCM", "aes256-gcm@openssh.com"}, "the CNSA profiles")
			}),
		sreq("mac", "draft §4.1; RFC 9212 §6", LevelMust, "Integrity comes from AES-256-GCM (or hmac-sha2-512 beside it during the transition)",
			func(s *sshCheck) Verdict {
				return s.onlyFrom(registry.KindMAC, []string{"AEAD_AES_256_GCM", "hmac-sha2-512", "hmac-sha2-512-etm@openssh.com"}, "the CNSA profiles")
			}),
	},
	NotAssessed: []string{
		"draft §5.3: that trust-on-first-use is not used (a client policy)", "draft §8: that re-keying keeps the cipher suite",
		"The CNSA 2.0 timeline is a policy date, not a server property", "Whether the system is a national security system at all",
	},
}
