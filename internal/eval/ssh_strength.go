package eval

import (
	"fmt"
	"strings"

	"github.com/offsetsecurity/cipherhorizon/internal/algo"
	"github.com/offsetsecurity/cipherhorizon/internal/sshprobe"
	"github.com/offsetsecurity/cipherhorizon/internal/sshprobe/registry"
)

// sshStrength is the classical strength of one advertised SSH algorithm (PRD-010 REQ-STR-7), from
// what the SSH registry records about it and, for RSA and DSA host keys, the size of the key the
// server presented. The numbers come from internal/algo (NIST's methods).
func sshStrength(kind, name string, a registry.Algorithm, ok bool, keys []sshprobe.HostKey) *algo.Strength {
	if !ok || kind == registry.KindCompression || registry.IsPseudo(name) {
		return nil
	}
	var st algo.Strength
	switch kind {
	case registry.KindKex:
		st = sshKexStrength(name, a)
	case registry.KindHostKey:
		st = sshHostKeyStrength(name, a, keys)
	case registry.KindCipher:
		st = sshNamed(a.Catalogue, a.KeyBits, a.Cipher)
	case registry.KindMAC:
		st = sshNamed(a.Catalogue, 0, "")
		// A truncated tag bounds forgery: an attacker guesses it with probability 2^-tag (SP 800-107
		// Rev. 1 section 5.3.5), so hmac-sha1-96 is 96 bits, not HMAC-SHA-1's 128.
		if a.TagBits > 0 && st.Known() && a.TagBits < st.Bits {
			st = algo.Strength{Bits: a.TagBits, Status: st.Status, Basis: fmt.Sprintf("%s; truncated to a %d-bit tag, which bounds forgery (NIST SP 800-107 Rev. 1, section 5.3.5)", st.Basis, a.TagBits)}
		}
	default:
		return nil
	}
	return &st
}

// sshNamed rates a cipher or MAC by its catalogue name, falling back, for a cipher NIST does not
// rate, to the bound an exhaustive search of its key sets.
func sshNamed(catalogue string, keyBits int, cipher string) algo.Strength {
	if catalogue != "" {
		if st := algo.StrengthOf(catalogue); st.Status != algo.StrengthNotRated || keyBits == 0 {
			return st
		}
	}
	if keyBits > 0 {
		return algo.Strength{Bits: keyBits, Status: algo.StrengthRated,
			Basis: fmt.Sprintf("%d-bit key; NIST assigns %s no strength, so this is the bound an exhaustive key search sets", keyBits, cipher)}
	}
	return algo.Strength{Status: algo.StrengthNotRated, Basis: "no strength is recorded for this algorithm"}
}

// sshCurve is the SECG curve an SSH method names (ecdh-sha2-nistp256, ecdsa-sha2-nistp384).
func sshCurve(name string) string {
	for _, c := range []string{"nistp256", "nistp384", "nistp521"} {
		if strings.Contains(name, c) {
			return "secp" + strings.TrimPrefix(c, "nistp") + "r1"
		}
	}
	return ""
}

func sshKexStrength(name string, a registry.Algorithm) algo.Strength {
	switch a.Exchange {
	case "MODP":
		if a.GroupBits > 0 {
			return algo.KeyStrength("DH", a.GroupBits, "")
		}
	case "ECDH":
		if c := sshCurve(name); c != "" {
			return algo.GroupStrength(c)
		}
	case "X25519":
		return algo.GroupStrength("x25519")
	case "X448":
		return algo.GroupStrength("x448")
	case "Hybrid":
		return algo.StrengthOf(a.Catalogue)
	case "GEX":
		return algo.Strength{Status: algo.StrengthNotRated, Basis: "group exchange: the group's size is chosen per connection and was not measured"}
	}
	return algo.Strength{Status: algo.StrengthNotRated, Basis: "no strength is recorded for this key exchange"}
}

func sshHostKeyStrength(name string, a registry.Algorithm, keys []sshprobe.HostKey) algo.Strength {
	// A SHA-1 signature (ssh-rsa, ssh-dss) is below 80 bits where collisions matter (SP 800-57
	// Part 1 Table 3, footnote 74), whatever the key.
	if a.Hash == "SHA-1" {
		return algo.Strength{Status: algo.StrengthBroken, Basis: "SHA-1 signatures: NIST SP 800-57 Part 1 Rev. 5, Table 3, footnote 74"}
	}
	switch {
	case a.Key == "Ed25519":
		return algo.KeyStrength("Ed25519", 0, "")
	case a.Key == "Ed448":
		return algo.KeyStrength("Ed448", 0, "")
	case a.Key == "ECDSA":
		if c := sshCurve(name); c != "" {
			return algo.GroupStrength(c)
		}
	case a.Key == "RSA" || a.Key == "DSA":
		// The size is the presented key's: the method name does not fix it.
		weakest := algo.Strength{Status: algo.StrengthNotRated, Basis: "the host key was not fetched, so its size is not known"}
		for _, k := range keys {
			if !strings.EqualFold(k.Algorithm, a.Key) || k.Bits == 0 {
				continue
			}
			if st := algo.KeyStrength(a.Key, k.Bits, ""); weakest.Status == algo.StrengthNotRated || st.Bits < weakest.Bits {
				weakest = st
			}
		}
		return weakest
	case strings.Contains(a.Key, "+"):
		// A composite signature (ML-DSA-44+Ed25519) stands while either part does: its stronger part.
		var best algo.Strength
		for _, part := range strings.Split(a.Key, "+") {
			if st := algo.KeyStrength(part, 0, ""); st.Known() && st.Bits > best.Bits {
				best = st
			}
		}
		if best.Known() {
			best.Basis = "a composite signature stands while either part does: its stronger part (" + best.Basis + ")"
			return best
		}
	case a.Key != "":
		return algo.KeyStrength(a.Key, 0, "") // ML-DSA-65 and the other parameter sets
	}
	return algo.Strength{Status: algo.StrengthNotRated, Basis: "no strength is recorded for this host key type"}
}
