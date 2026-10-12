// Package sshcbom builds the CycloneDX components an SSH scan observed (PRD-008 REQ-SHO-1): one
// protocol component of type ssh, an algorithm component for every advertised key exchange,
// host key algorithm, cipher and MAC the catalogue knows, and every host key as a public key.
// The same rules as internal/tlscbom: closed vocabularies, nothing guessed, every component
// carries the evidence of how it was seen, and the choices a current client makes are marked.
package sshcbom

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"sort"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/offsetsecurity/cipherhorizon/internal/algo"
	"github.com/offsetsecurity/cipherhorizon/internal/cbom"
	"github.com/offsetsecurity/cipherhorizon/internal/collector"
	"github.com/offsetsecurity/cipherhorizon/internal/sshprobe"
	"github.com/offsetsecurity/cipherhorizon/internal/sshprobe/registry"
)

// ProtocolRef is the bom-ref of the SSH protocol component.
const ProtocolRef = "protocol/ssh/2.0"

func evidence(method string) *cdx.Evidence {
	one := float32(1.0)
	return &cdx.Evidence{Identity: &cdx.EvidenceIdentityChoice{Identities: &[]cdx.EvidenceIdentity{{
		Field: cdx.EvidenceIdentityFieldTypeName, Confidence: &one,
		Methods: &[]cdx.EvidenceIdentityMethod{{Technique: cdx.EvidenceIdentityTechniqueOther, Confidence: &one, Value: method}},
	}}}}
}

const (
	evAdvertised = "SSH KEXINIT: the server's own algorithm lists"
	evHostKey    = "SSH key exchange reply: the host key the server presented"
)

// FromSSHReport returns the components of one SSH scan. nil for a nil report or one whose
// algorithm lists were not read (an SSH-1-only server has none).
func FromSSHReport(rep *sshprobe.Report) []collector.CryptoAsset {
	if rep == nil || rep.Algorithms == nil {
		return nil
	}
	var assets []collector.CryptoAsset
	index := map[string]int{}
	emitAsset := func(a collector.CryptoAsset, method string) string {
		ref := a.Component.BOMRef
		if _, ok := index[ref]; !ok {
			if a.Component.Evidence == nil {
				a.Component.Evidence = evidence(method)
			}
			index[ref] = len(assets)
			assets = append(assets, a)
		}
		return ref
	}
	emit := func(method string) func(string) (string, bool) {
		return func(id string) (string, bool) {
			a, ok := algo.Lookup(id)
			if !ok {
				return "", false
			}
			return emitAsset(a.Asset(), method), true
		}
	}

	a := rep.Algorithms
	var deps, unknown []string
	seen := map[string]bool{}
	add := func(kind string, names []string) {
		for _, n := range names {
			r, ok := registry.Lookup(kind, n)
			if !ok || r.Catalogue == "" {
				if !contains(unknown, n) && n != "none" {
					unknown = append(unknown, n)
				}
				continue
			}
			if ref, ok := emit(evAdvertised)(r.Catalogue); ok && !seen[ref] {
				seen[ref] = true
				deps = append(deps, ref)
			}
		}
	}
	add(registry.KindKex, a.Kex)
	add(registry.KindHostKey, a.HostKey)
	add(registry.KindCipher, merge(a.CipherC2S, a.CipherS2C))
	add(registry.KindMAC, merge(a.MACC2S, a.MACS2C))

	for _, k := range rep.HostKeys {
		alg := k.Algorithm
		if r, ok := registry.Lookup(registry.KindHostKey, k.Type); ok && strings.Contains(alg, "+") {
			alg = r.Catalogue // a composite key is named by its post-quantum half; the type says the rest
		}
		key, ok := cbom.PublicKeyAsset(keyRef(k), "SSH host key "+k.Fingerprint, alg, k.Bits, curveName(k.Curve),
			emit(evHostKey), func(c collector.CryptoAsset) string { return emitAsset(c, evHostKey) })
		if !ok {
			continue
		}
		key.Component.Evidence = evidence(evHostKey)
		props := []cdx.Property{cbom.Property("ssh-host-key-type", k.Type), cbom.Property("fingerprint", k.Fingerprint),
			cbom.Property("signature-verified", boolText(k.Verified))}
		if k.Certificate != nil {
			props = append(props, cbom.Property("openssh-certificate-ca", k.Certificate.CAFingerprint))
		}
		key.Component.Properties = &props
		deps = append(deps, emitAsset(key, evHostKey))
	}

	props := []cdx.Property{cbom.Property("strict-kex", boolText(a.StrictKex))}
	if id := rep.Identification; id != nil && id.Software != "" {
		props = append(props, cbom.Property("ssh-software", id.Software))
	}
	if n := rep.Negotiated; n != nil && n.Kex != "" {
		for _, kv := range [][2]string{{"negotiated-kex", n.Kex}, {"negotiated-host-key", n.HostKey}, {"negotiated-cipher", n.Cipher}, {"negotiated-mac", n.MAC}} {
			if kv[1] != "" {
				props = append(props, cbom.Property(kv[0], kv[1]))
			}
		}
		props = append(props, cbom.Property("negotiated-by", n.Client), cbom.Property("negotiation-evidence", n.Evidence))
		markNegotiated(n, assets, index)
	}
	if len(unknown) > 0 {
		sort.Strings(unknown)
		props = append(props, cbom.Property("ssh-algorithms-not-catalogued", strings.Join(unknown, ",")))
	}
	sort.Strings(deps)
	assets = append(assets, collector.CryptoAsset{
		Component: cdx.Component{
			BOMRef: ProtocolRef, Type: cdx.ComponentTypeCryptographicAsset, Name: "SSH-2.0",
			CryptoProperties: &cdx.CryptoProperties{AssetType: cdx.CryptoAssetTypeProtocol,
				ProtocolProperties: &cdx.CryptoProtocolProperties{Type: cdx.CryptoProtocolTypeSSH, Version: "2.0"}},
			Evidence:   evidence("SSH identification line and KEXINIT"),
			Properties: &props,
		},
		DependsOn: deps,
	})
	sort.SliceStable(assets, func(i, j int) bool { return assets[i].Component.BOMRef < assets[j].Component.BOMRef })
	return assets
}

// markNegotiated flags the algorithm components a current client uses: the key exchange, the
// cipher and the MAC, each named exactly (a family component shared with other names is not
// flagged, so the flag cannot overclaim).
func markNegotiated(n *sshprobe.Negotiated, assets []collector.CryptoAsset, index map[string]int) {
	for _, pair := range [][2]string{{registry.KindKex, n.Kex}, {registry.KindCipher, n.Cipher}, {registry.KindMAC, n.MAC}} {
		r, ok := registry.Lookup(pair[0], pair[1])
		if !ok || r.Catalogue == "" {
			continue
		}
		c, ok := algo.Lookup(r.Catalogue)
		if !ok {
			continue
		}
		i, ok := index[c.BOMRef()]
		if !ok || sharedFamily(r.Catalogue) {
			continue
		}
		comp := &assets[i].Component
		p := cbom.Property("negotiated", "true")
		if comp.Properties == nil {
			comp.Properties = &[]cdx.Property{p}
		} else {
			*comp.Properties = append(*comp.Properties, p)
		}
	}
}

// sharedFamily: catalogue entries that stand for more than one SSH name (X25519 for both
// curve25519 names is fine; ECDH, DH, RSA and the generic families are not exact).
func sharedFamily(id string) bool {
	switch id {
	case "ECDH", "DH", "RSA", "ECDSA", "AES", "HMAC-SHA-1", "HMAC-MD5", "UMAC", "Blowfish", "CAST-128", "3DES", "RC4":
		return true
	}
	return false
}

func keyRef(k sshprobe.HostKey) string {
	blob, err := base64.StdEncoding.DecodeString(k.Blob)
	if err != nil || len(blob) == 0 {
		blob = []byte(k.Fingerprint)
	}
	sum := sha256.Sum256(blob)
	return "crypto/key/public/ssh-" + hex.EncodeToString(sum[:])
}

func curveName(c string) string { return c } // "P-256": the form keyAlgorithm expects

func boolText(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func merge(a, b []string) []string {
	out := append([]string(nil), a...)
	for _, x := range b {
		if !contains(out, x) {
			out = append(out, x)
		}
	}
	return out
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}
