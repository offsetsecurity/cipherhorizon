package eval

import (
	"fmt"
	"strings"

	"github.com/offsetsecurity/cipherhorizon/internal/sshprobe/registry"
)

// SSH baseline conformance (PRD-008 WP-G, ENG-HANDOFF-005 §9). SSH practice judges a server
// against a policy, not a score: a baseline is a named, versioned, cited list of what a server may
// offer and must offer, and the answer an administrator wants is whether the server meets it and
// which sshd_config lines would make it.

// SSHBaseline is one named, versioned baseline.
type SSHBaseline struct {
	ID      string `json:"id"`
	Title   string `json:"title"`
	Version string `json:"version"`
	// Allowed is, per registry kind, the allow-list in preference order (the order the generated
	// sshd_config lines use). A name not on its kind's list should be off.
	Allowed    map[string][]BaselineEntry `json:"allowed"`
	Requires   []BaselineRequirement      `json:"requires"`
	MinRSABits int                        `json:"minRsaBits"`
}

// BaselineEntry is one allowed name, why it is allowed, and the OpenSSH version that first offers
// it ("—" when OpenSSH does not implement it).
type BaselineEntry struct {
	Name  string   `json:"name"`
	Since string   `json:"since"`
	Cite  Citation `json:"cite"`
}

// BaselineRequirement is something a server must do, beyond offering only allowed names.
type BaselineRequirement struct {
	ID    string   `json:"id"`
	Text  string   `json:"text"`
	Cite  Citation `json:"cite"`
	Kind  string   `json:"kind,omitempty"`  // the registry kind AnyOf is about
	AnyOf []string `json:"anyOf,omitempty"` // at least one offered; empty for the special checks
	Since string   `json:"since,omitempty"` // OpenSSH version that brings it, for the fix text
}

// Requirement ids with their own checks.
const (
	ReqPQKex     = "pq-kex"
	ReqStrictKex = "strict-kex"
	ReqRSASize   = "rsa-size"
)

// BaselineDefault is the baseline an SSH evaluation uses unless told otherwise.
const BaselineDefault = "cipherhorizon-ssh-2026"

const (
	osshEarly = "all versions"
	notOSSH   = "—"
)

var (
	citRFC8731      = rfc("8731", "Secure Shell (SSH) Key Exchange Method Using Curve25519 and Curve448")
	citRFC5656      = rfc("5656", "Elliptic Curve Algorithm Integration in the Secure Shell Transport Layer")
	citRFC8268      = rfc("8268", "More Modular Exponentiation (MODP) Diffie-Hellman (DH) Key Exchange (KEX) Groups for Secure Shell (SSH)")
	citRFC4419      = rfc("4419", "Diffie-Hellman Group Exchange for the Secure Shell (SSH) Transport Layer Protocol")
	citRFC8709      = rfc("8709", "Ed25519 and Ed448 Public Key Algorithms for the Secure Shell (SSH) Protocol")
	citRFC5647      = rfc("5647", "AES Galois Counter Mode for the Secure Shell Transport Layer Protocol")
	citRFC4344      = rfc("4344", "The Secure Shell (SSH) Transport Layer Encryption Modes")
	citRFC4418      = rfc("4418", "UMAC: Message Authentication Code using Universal Hashing")
	citChaChaPoly   = Citation{Title: "OpenSSH PROTOCOL.chacha20poly1305: the chacha20-poly1305@openssh.com cipher", URL: "https://cvsweb.openbsd.org/src/usr.bin/ssh/PROTOCOL.chacha20poly1305?annotate=HEAD"}
	citOpenSSHETM   = Citation{Title: "OpenSSH PROTOCOL §1.7: encrypt-then-MAC MAC algorithms", URL: "https://cvsweb.openbsd.org/src/usr.bin/ssh/PROTOCOL?annotate=HEAD"}
	citCertKeys     = Citation{Title: "OpenSSH PROTOCOL.certkeys: OpenSSH certificate host keys", URL: "https://cvsweb.openbsd.org/src/usr.bin/ssh/PROTOCOL.certkeys?annotate=HEAD"}
	citDelayedZlib  = Citation{Title: "OpenSSH PROTOCOL §2.2: zlib@openssh.com, compression only after authentication", URL: "https://cvsweb.openbsd.org/src/usr.bin/ssh/PROTOCOL?annotate=HEAD"}
	citSSHMLDSA     = Citation{Title: "IETF draft-sfluhrer-ssh-mldsa: ML-DSA public keys and signatures in SSH", URL: "https://datatracker.ietf.org/doc/draft-sfluhrer-ssh-mldsa/"}
	citOpenSSH96    = Citation{Title: "OpenSSH 9.6 release notes (strict key exchange against Terrapin)", URL: "https://www.openssh.org/txt/release-9.6"}
	citNoneCompress = rfc("4253", "The Secure Shell (SSH) Transport Layer Protocol: compression \"none\"")
)

func entries(cite Citation, since string, names ...string) []BaselineEntry {
	out := make([]BaselineEntry, len(names))
	for i, n := range names {
		out[i] = BaselineEntry{Name: n, Since: since, Cite: cite}
	}
	return out
}

func joinEntries(lists ...[]BaselineEntry) []BaselineEntry {
	var out []BaselineEntry
	for _, l := range lists {
		out = append(out, l...)
	}
	return out
}

// cipherHorizon2026 is this program's own baseline. Its preference order follows OpenSSH's own
// defaults, so the generated lines change as little as possible.
var cipherHorizon2026 = SSHBaseline{
	ID: BaselineDefault, Title: "CipherHorizon SSH baseline 2026", Version: "2026-10-13",
	Allowed: map[string][]BaselineEntry{
		registry.KindKex: joinEntries(
			entries(citSSHMLKEM, "9.9", "mlkem768x25519-sha256"),
			entries(citSSHSntrup, "9.9", "sntrup761x25519-sha512"),
			entries(citSSHSntrup, "8.5", "sntrup761x25519-sha512@openssh.com"),
			entries(citRFC8731, "7.4", "curve25519-sha256"),
			entries(citRFC8731, "6.5", "curve25519-sha256@libssh.org"),
			entries(citRFC8731, notOSSH, "curve448-sha512"),
			entries(citRFC5656, "5.7", "ecdh-sha2-nistp256", "ecdh-sha2-nistp384", "ecdh-sha2-nistp521"),
			entries(citRFC4419, "4.4", "diffie-hellman-group-exchange-sha256"),
			entries(citRFC8268, "7.3", "diffie-hellman-group16-sha512", "diffie-hellman-group18-sha512", "diffie-hellman-group14-sha256"),
			entries(citRFC8268, notOSSH, "diffie-hellman-group15-sha512", "diffie-hellman-group17-sha512"),
			entries(citSSHMLKEM, notOSSH, "mlkem768nistp256-sha256", "mlkem1024nistp384-sha384"),
		),
		registry.KindHostKey: joinEntries(
			entries(citSSHComp, "10.6", "ssh-mldsa44-ed25519"),
			entries(citCertKeys, "10.6", "ssh-mldsa44-ed25519-cert"),
			entries(citSSHComp, notOSSH, "ssh-mldsa87-p384"),
			entries(citSSHMLDSA, notOSSH, "ssh-mldsa-44", "ssh-mldsa-65", "ssh-mldsa-87"),
			entries(citRFC8709, "6.5", "ssh-ed25519"),
			entries(citCertKeys, "6.5", "ssh-ed25519-cert-v01@openssh.com"),
			entries(citRFC8709, notOSSH, "ssh-ed448"),
			entries(citRFC5656, "5.7", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521"),
			entries(citCertKeys, "5.7", "ecdsa-sha2-nistp256-cert-v01@openssh.com", "ecdsa-sha2-nistp384-cert-v01@openssh.com", "ecdsa-sha2-nistp521-cert-v01@openssh.com"),
			entries(citRFC8332, "7.2", "rsa-sha2-512", "rsa-sha2-256"),
			entries(citCertKeys, "7.8", "rsa-sha2-512-cert-v01@openssh.com", "rsa-sha2-256-cert-v01@openssh.com"),
		),
		registry.KindCipher: joinEntries(
			entries(citChaChaPoly, "6.5", "chacha20-poly1305@openssh.com"),
			entries(citRFC5647, "6.2", "aes128-gcm@openssh.com", "aes256-gcm@openssh.com"),
			entries(citRFC4344, "3.7", "aes128-ctr", "aes192-ctr", "aes256-ctr"),
			entries(citRFC5647, notOSSH, "AEAD_AES_128_GCM", "AEAD_AES_256_GCM"),
		),
		registry.KindMAC: joinEntries(
			entries(citOpenSSHETM, "6.2", "hmac-sha2-256-etm@openssh.com", "hmac-sha2-512-etm@openssh.com"),
			entries(citRFC4418, "6.2", "umac-128-etm@openssh.com"),
		),
		registry.KindCompression: joinEntries(
			entries(citNoneCompress, osshEarly, "none"),
			entries(citDelayedZlib, "4.2", "zlib@openssh.com"),
		),
	},
	Requires: []BaselineRequirement{
		{ID: ReqPQKex, Text: "A post-quantum hybrid key exchange is offered", Cite: citSSHMLKEM, Kind: registry.KindKex,
			AnyOf: []string{"mlkem768x25519-sha256", "sntrup761x25519-sha512", "sntrup761x25519-sha512@openssh.com", "mlkem768nistp256-sha256", "mlkem1024nistp384-sha384"}, Since: "9.9"},
		{ID: ReqStrictKex, Text: "Strict key exchange is offered (Terrapin, CVE-2023-48795)", Cite: citOpenSSH96, Since: "9.6"},
		{ID: ReqRSASize, Text: "RSA host keys are at least 3072 bits", Cite: citSP80057},
	},
	MinRSABits: 3072,
}

var sshBaselines = []*SSHBaseline{&cipherHorizon2026}

// SSHBaselines lists the baselines this program carries.
func SSHBaselines() []*SSHBaseline { return sshBaselines }

// SSHBaselineByID finds a baseline.
func SSHBaselineByID(id string) (*SSHBaseline, bool) {
	for _, b := range sshBaselines {
		if b.ID == id {
			return b, true
		}
	}
	return nil, false
}

// Conformance is how one SSH server measures against one baseline.
type Conformance struct {
	Baseline string `json:"baseline"`
	Title    string `json:"title"`
	// Judged is false when the server's lists were not read; Meets then means nothing.
	Judged     bool             `json:"judged"`
	Reason     string           `json:"reason,omitempty"`
	Meets      bool             `json:"meets"`
	Changes    []BaselineChange `json:"changes"`
	Requires   []RequireView    `json:"requires"`
	SSHDConfig string           `json:"sshdConfig"`
}

// BaselineChange is one thing to do to meet the baseline.
type BaselineChange struct {
	Kind   string   `json:"kind,omitempty"`
	Name   string   `json:"name,omitempty"`
	Action string   `json:"action"` // remove | add | upgrade | replace-key
	Text   string   `json:"text"`
	Cite   Citation `json:"cite"`
}

// Baseline verdicts of one algorithm (SSHAlgorithm.Baseline).
const (
	BaselineAllowed = "allowed"
	BaselineOff     = "off"
)

// Change actions.
const (
	ChangeRemove     = "remove"
	ChangeAdd        = "add"
	ChangeUpgrade    = "upgrade"
	ChangeReplaceKey = "replace-key"
)

// RequireView is one requirement and whether the server meets it.
type RequireView struct {
	ID   string `json:"id"`
	Text string `json:"text"`
	Met  bool   `json:"met"`
	// NotApplicable: there was nothing to judge (no RSA host key for an RSA size rule). Met stays
	// true, so the verdict is unchanged; the page says "does not apply" instead of "met".
	NotApplicable bool     `json:"notApplicable,omitempty"`
	Detail        string   `json:"detail,omitempty"`
	Cite          Citation `json:"cite"`
}

// baselineKinds are the kinds a baseline judges, in sshd_config order.
var baselineKinds = []struct{ kind, directive string }{
	{registry.KindKex, "KexAlgorithms"}, {registry.KindHostKey, "HostKeyAlgorithms"},
	{registry.KindCipher, "Ciphers"}, {registry.KindMAC, "MACs"}, {registry.KindCompression, ""},
}

func (b *SSHBaseline) allows(kind, name string) bool {
	for _, e := range b.Allowed[kind] {
		if e.Name == name {
			return true
		}
	}
	return false
}

func (b *SSHBaseline) entry(kind, name string) BaselineEntry {
	for _, e := range b.Allowed[kind] {
		if e.Name == name {
			return e
		}
	}
	return BaselineEntry{Name: name}
}

// offeredOf is what the server offers of a kind, signals left out of the key exchange list.
func (c *sshCtx) offeredOf(kind string) []string {
	switch kind {
	case registry.KindKex:
		var out []string
		for _, n := range c.alg.Kex {
			if !registry.IsPseudo(n) {
				out = append(out, n)
			}
		}
		return out
	case registry.KindHostKey:
		return c.alg.HostKey
	case registry.KindCipher:
		return c.ciphers
	case registry.KindMAC:
		return c.macs
	default:
		return c.comp
	}
}

// offReason says, citing, why a name is not on the baseline. It reuses the facts the rules judge
// by, so the two never disagree about why something is wrong.
func offReason(kind, name string) (string, Citation) {
	a, known := registry.Lookup(kind, name)
	switch {
	case !known:
		return "not a name this program knows, so the baseline cannot allow it", Citation{}
	case kind == registry.KindKex && a.Hash == "SHA-1":
		return "a SHA-1 key exchange", citRFC9142
	case kind == registry.KindKex && a.GroupBits > 0 && a.GroupBits < 2048:
		return "a group under 2048 bits", citRFC9142
	case kind == registry.KindKex && a.Exchange == "RSA":
		return "RSA key exchange, which RFC 9142 deprecates", citRFC9142
	case kind == registry.KindHostKey && (name == "ssh-rsa" || strings.HasPrefix(name, "ssh-rsa-cert")):
		return "RSA signatures with SHA-1", citRFC8332
	case kind == registry.KindHostKey && a.Key == "DSA":
		return "DSA, which FIPS 186-5 no longer approves for signing", citFIPS1865
	case kind == registry.KindCipher && a.Mode == "CBC":
		return "a CBC mode cipher", citSSHCBC
	case kind == registry.KindCipher && (a.Cipher == "RC4" || strings.HasPrefix(name, "arcfour")):
		return "RC4", citRFC8758
	case kind == registry.KindCipher && name == "none":
		return "no encryption", citRFC4253
	case kind == registry.KindCipher:
		return "a cipher outside the baseline (" + a.Display + ")", citRFC4253
	case kind == registry.KindMAC && name == "none":
		return "no integrity protection", citRFC4253
	case kind == registry.KindMAC && a.TagBits > 0 && a.TagBits < 128:
		return fmt.Sprintf("a %d-bit tag", a.TagBits), citRFC4418
	case kind == registry.KindMAC && (a.Hash == "SHA-1" || a.Hash == "MD5"):
		return a.Hash + " integrity", citRFC6668
	case kind == registry.KindMAC && !a.ETM:
		return "encrypt-and-MAC: the MAC is computed over the plaintext", citOpenSSHETM
	case kind == registry.KindCompression && name == "zlib":
		return "compression before authentication", citOpenSSH74
	default:
		return "not on the baseline's list", Citation{}
	}
}

// sshConformance judges the report against baseline b.
func sshConformance(c *sshCtx, b *SSHBaseline) *Conformance {
	out := &Conformance{Baseline: b.ID, Title: b.Title, Changes: []BaselineChange{}, Requires: []RequireView{}}
	rep := c.rep
	if rep.Identification != nil && rep.Identification.SSH1Only {
		out.Judged = true
		out.Changes = append(out.Changes, BaselineChange{Action: ChangeUpgrade, Text: "The server speaks only SSH-1: replace it with a current SSH-2 server.", Cite: citSSH1})
		return out
	}
	if rep.Algorithms == nil {
		out.Reason = "The server's algorithm lists were not read."
		return out
	}
	out.Judged = true

	for _, k := range baselineKinds {
		for _, n := range c.offeredOf(k.kind) {
			if b.allows(k.kind, n) {
				continue
			}
			why, cite := offReason(k.kind, n)
			out.Changes = append(out.Changes, BaselineChange{Kind: k.kind, Name: n, Action: ChangeRemove, Text: "Stop offering " + n + ": " + why + ".", Cite: cite})
		}
	}

	for _, r := range b.Requires {
		v := RequireView{ID: r.ID, Text: r.Text, Cite: r.Cite, Met: true}
		switch r.ID {
		case ReqStrictKex:
			v.Met = c.alg.StrictKex
			if !v.Met {
				v.Detail = "kex-strict-s-v00@openssh.com is not offered."
				out.Changes = append(out.Changes, BaselineChange{Action: ChangeUpgrade, Text: pick2(isOpenSSH(rep), "Upgrade to OpenSSH "+r.Since+" or later for strict key exchange.",
					"Offer strict key exchange (kex-strict-s-v00@openssh.com; OpenSSH has it from "+r.Since+")."), Cite: r.Cite})
			}
		case ReqRSASize:
			rsa := 0
			for _, hk := range rep.HostKeys {
				if hk.Algorithm == "RSA" {
					rsa++
				}
			}
			if rsa == 0 {
				v.NotApplicable, v.Detail = true, "The server has no RSA host key."
			}
			for _, hk := range rep.HostKeys {
				if hk.Algorithm == "RSA" && hk.Bits > 0 && hk.Bits < b.MinRSABits {
					v.Met = false
					v.Detail = fmt.Sprintf("The RSA host key is %d bits.", hk.Bits)
					out.Changes = append(out.Changes, BaselineChange{Kind: registry.KindHostKey, Name: hk.Fingerprint, Action: ChangeReplaceKey,
						Text: fmt.Sprintf("Replace the %d-bit RSA host key with one of at least %d bits.", hk.Bits, b.MinRSABits), Cite: r.Cite})
				}
			}
		default:
			v.Met = false
			for _, n := range c.offeredOf(r.Kind) {
				if contains(r.AnyOf, n) {
					v.Met = true
					break
				}
			}
			if !v.Met {
				first := r.AnyOf[0]
				v.Detail = "None is offered."
				out.Changes = append(out.Changes, BaselineChange{Kind: r.Kind, Name: first, Action: ChangeAdd,
					Text: "Offer " + first + " (OpenSSH " + b.entry(r.Kind, first).Since + " or later).", Cite: r.Cite})
			}
		}
		out.Requires = append(out.Requires, v)
	}
	out.Meets = len(out.Changes) == 0
	if !out.Meets {
		out.SSHDConfig = sshdConfigBlock(c, b, out)
	}
	return out
}

// sshdConfigBlock writes the sshd_config lines that would make the server meet b (REQ-SHB-4).
// sshd uses the first value it reads for each keyword and has no trailing comments, so every
// comment is a line of its own and the header says where the lines go.
func sshdConfigBlock(c *sshCtx, b *SSHBaseline, conf *Conformance) string {
	var w strings.Builder
	fmt.Fprintf(&w, "# %s (%s). Put these lines before any other setting of the same keyword:\n", b.Title, b.ID)
	w.WriteString("# sshd uses the first value it reads. Check with sshd -t, then reload sshd.\n")
	for _, k := range baselineKinds {
		if k.directive == "" {
			continue
		}
		offered := c.offeredOf(k.kind)
		if len(offered) == 0 {
			continue
		}
		var keep, notes []string
		for _, e := range b.Allowed[k.kind] {
			if contains(offered, e.Name) {
				keep = append(keep, e.Name)
			}
		}
		for _, r := range b.Requires {
			if r.Kind != k.kind || len(r.AnyOf) == 0 || anyIn(r.AnyOf, keep) {
				continue
			}
			first := b.entry(k.kind, r.AnyOf[0])
			keep = append([]string{first.Name}, keep...)
			notes = append(notes, fmt.Sprintf("# %s needs OpenSSH %s or later", first.Name, first.Since))
		}
		if len(keep) == 0 {
			first := b.Allowed[k.kind][0]
			if k.kind == registry.KindHostKey {
				first = hostKeyFallback(c, b)
				if first.Name == "ssh-ed25519" {
					notes = append(notes, "# generate the key first: ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key")
				}
			}
			keep = []string{first.Name}
			notes = append(notes, fmt.Sprintf("# %s needs OpenSSH %s or later", first.Name, first.Since))
		}
		if sameSet(keep, offered) {
			continue
		}
		for _, n := range notes {
			w.WriteString(n + "\n")
		}
		fmt.Fprintf(&w, "%s %s\n", k.directive, strings.Join(keep, ","))
	}
	if contains(c.comp, "zlib") {
		w.WriteString("Compression no\n")
	}
	for _, ch := range conf.Changes {
		switch ch.Action {
		case ChangeUpgrade:
			w.WriteString("# " + ch.Text + "\n")
		case ChangeReplaceKey:
			fmt.Fprintf(&w, "# %s Then restart sshd:\n#   ssh-keygen -t rsa -b %d -f /etc/ssh/ssh_host_rsa_key\n", ch.Text, b.MinRSABits)
		}
	}
	return w.String()
}

// hostKeyFallback is the host key algorithm to name when the server offers no allowed one: the
// SHA-2 RSA signatures when it holds an RSA key, otherwise Ed25519 (a key to generate).
func hostKeyFallback(c *sshCtx, b *SSHBaseline) BaselineEntry {
	for _, hk := range c.rep.HostKeys {
		if hk.Algorithm == "RSA" {
			return b.entry(registry.KindHostKey, "rsa-sha2-512")
		}
	}
	return b.entry(registry.KindHostKey, "ssh-ed25519")
}

func anyIn(want, have []string) bool {
	for _, w := range want {
		if contains(have, w) {
			return true
		}
	}
	return false
}

// sameSet: the same names, in any order (a reordered list is not a change worth a line).
func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for _, x := range a {
		if !contains(b, x) {
			return false
		}
	}
	return true
}

// SSHBaselineSummary is the stored, listable part of a conformance (REQ-SHB-5).
func SSHBaselineSummary(ev Evaluation) (id string, meets *bool, changes int) {
	if ev.Baseline == nil || !ev.Baseline.Judged {
		return "", nil, 0
	}
	m := ev.Baseline.Meets
	return ev.Baseline.Baseline, &m, len(ev.Baseline.Changes)
}
