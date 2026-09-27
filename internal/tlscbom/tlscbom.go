// Package tlscbom turns an active TLS scan's observations into CBOM assets. It lives apart
// from internal/cbom so that a program that only needs the host inventory (the collector) does
// not link the TLS scanner.
package tlscbom

import (
	"fmt"
	"sort"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/example/cipherhorizon/internal/algo"
	"github.com/example/cipherhorizon/internal/cbom"
	"github.com/example/cipherhorizon/internal/collector"
	"github.com/example/cipherhorizon/internal/tlsprobe"
)

// FromTLSReport turns an active TLS scan's observations into CBOM assets: one
// protocol component per supported version, with the cipher suites it accepts
// and, for TLS 1.3, the key-exchange groups it accepts; and one certificate
// component per certificate the scan retrieved (every position in every chain,
// deduplicated by fingerprint). Every algorithm the suites, groups and
// certificates reference is emitted once as its own component, so that no
// DependsOn edge points at something absent from the document.
//
// This states only what was observed on the wire: no readiness level, no TLS
// hygiene score, no finding. Those live in the evaluation, which is not a CBOM's
// business (principle 4: closed vocabularies, nothing guessed). An algorithm
// with no catalogue entry — a legacy cipher such as RC4, a named curve this
// program does not carry an OID for — is still named in the suite or
// certificate text; it simply gets no algorithm reference.
//
// The caller decides whether to run pqc.Analyze/Annotate over the result, the
// same as it would for a host inventory; this package cannot do so itself
// without an import cycle (pqc imports cbom for its property namespace).
func FromTLSReport(rep *tlsprobe.Report) []collector.CryptoAsset {
	if rep == nil {
		return nil
	}

	// index maps a bom-ref to its position in assets, so a later pass (the
	// negotiated-vs-capability marking below) can amend a component already
	// emitted instead of emitting a second, conflicting copy of it.
	var assets []collector.CryptoAsset
	index := map[string]int{}
	emitted := func(ref string) (*collector.CryptoAsset, bool) {
		i, ok := index[ref]
		if !ok {
			return nil, false
		}
		return &assets[i], true
	}
	// emit resolves a catalogue algorithm ID to its bom-ref, appending the
	// component — Observed, since everything this scanner emits was seen on the
	// wire (feature 1) — the first time each one is used.
	emit := func(id string) (string, bool) {
		a, ok := algo.Lookup(id)
		if !ok {
			return "", false
		}
		ref := a.BOMRef()
		if _, ok := index[ref]; !ok {
			c := a.Asset()
			c.Component.Evidence = observedEvidence("TLS handshake (cipher suite or key-exchange group enumeration)")
			index[ref] = len(assets)
			assets = append(assets, c)
		}
		return ref, true
	}
	// emitHybrid is emit's counterpart for TLS-specific hybrid groups, which have
	// no static catalogue entry (see hybridComponent).
	emitHybrid := func(g tlsprobe.GroupResult) (string, bool) {
		a, ok := hybridComponent(g)
		if !ok {
			return "", false
		}
		ref := a.Component.BOMRef
		if _, ok := index[ref]; !ok {
			a.Component.Evidence = observedEvidence("TLS 1.3 HelloRetryRequest naming this group for an empty key_share")
			index[ref] = len(assets)
			assets = append(assets, a)
		}
		return ref, true
	}

	for _, p := range rep.Protocols {
		if !p.Supported {
			continue
		}
		assets = append(assets, protocolAsset(rep, p.Version, emit, emitHybrid))
		index[assets[len(assets)-1].Component.BOMRef] = len(assets) - 1
	}
	// emitAsset adds a component this scan derived itself (a key-size variant such
	// as RSA-2048 that no static catalogue could enumerate) the first time it is
	// used, and returns its bom-ref.
	emitAsset := func(a collector.CryptoAsset) string {
		ref := a.Component.BOMRef
		if _, ok := index[ref]; !ok {
			a.Component.Evidence = observedEvidence("certificate chain presented during the TLS handshake")
			index[ref] = len(assets)
			assets = append(assets, a)
		}
		return ref
	}
	for _, c := range certificateAssets(rep, emit, emitAsset) {
		assets = append(assets, c)
		index[c.Component.BOMRef] = len(assets) - 1
	}

	markNegotiated(rep, emitted)

	sort.SliceStable(assets, func(i, j int) bool { return assets[i].Component.BOMRef < assets[j].Component.BOMRef })
	return assets
}

// observedEvidence is feature 1: every fact this builder emits was directly
// observed on the wire (a ServerHello, a HelloRetryRequest, a certificate) —
// never inferred, and never a fact the scan could not have seen (that fact
// simply has no component at all: "omit, don't guess" already covers it). The
// confidence and technique values are this project's own choice, not a
// standard: CycloneDX's identity-evidence vocabulary (checked against the
// vendored 1.6 schema, not just the Go SDK's struct) has no TLS-specific
// technique, so "other" plus a human-readable value is the honest fit.
func observedEvidence(method string) *cdx.Evidence {
	one := float32(1.0)
	return &cdx.Evidence{Identity: &cdx.EvidenceIdentityChoice{Identities: &[]cdx.EvidenceIdentity{{
		Field: cdx.EvidenceIdentityFieldTypeName, Confidence: &one,
		Methods: &[]cdx.EvidenceIdentityMethod{{Technique: cdx.EvidenceIdentityTechniqueOther, Confidence: &one, Value: method}},
	}}}}
}

// markNegotiated is feature 2: capability (everything enumerateLegacy/
// enumerateTLS13 found acceptable) and negotiation (what one specific,
// standard client actually got) are different facts, and the research this
// project's PRD-002 is built on names conflating them as the most common
// reason other scanners under-report post-quantum support. Nothing here
// changes what enumeration already found; it only marks, on the protocol
// component, exactly which one suite and group a real handshake chose — and,
// separately, the algorithm components the negotiated handshake used: the
// group, and the negotiated suite's cipher, key exchange and authentication.
// A component is flagged only when it names exactly what was used, so the
// flag cannot overclaim: that is why the cipher is a key-size-and-mode
// variant (AES-128-GCM) and never the whole AES family, which every AES
// suite shares. Everything else the server merely accepts stays unflagged.
//
// The negotiated group is looked up by bom-ref, computed the same way the
// enumeration loop above computed it (groupCatalogueID, falling back to the
// hybrid bom-ref) — not by comparing Component.Name against Negotiated.Group,
// which do not always match: a catalogue-backed group's component is named
// after the catalogue ID ("ML-KEM-768"), not the raw registry group name
// ("MLKEM768") the negotiated result carries.
func markNegotiated(rep *tlsprobe.Report, emitted func(string) (*collector.CryptoAsset, bool)) {
	n := rep.Negotiated
	if n == nil || n.Error != "" {
		return
	}
	proto, ok := emitted(protocolBOMRef(n.Version))
	if !ok {
		return
	}
	addProperty(&proto.Component, "negotiated-suite", n.Suite)
	if n.Group != "" {
		addProperty(&proto.Component, "negotiated-group", n.Group)
	}
	// The algorithms of the negotiated suite: the bulk cipher (a specific
	// variant, e.g. AES-128-GCM, so the claim is exact) and, up to TLS 1.2, the
	// key exchange and authentication the suite names.
	for _, s := range rep.Suites {
		if s.ID != n.SuiteID || s.Version != n.Version {
			continue
		}
		for _, pick := range []func() (string, bool){
			func() (string, bool) { return cipherCatalogueID(s) },
			func() (string, bool) { return kxCatalogueID(s.Kx) },
			func() (string, bool) { return authCatalogueID(s.Auth) },
		} {
			id, ok := pick()
			if !ok {
				continue
			}
			if a, found := algo.Lookup(id); found {
				markNegotiatedOnce(emitted, a.BOMRef())
			}
		}
		break
	}
	if n.GroupID == 0 {
		return
	}
	for _, g := range rep.Groups {
		if g.ID != n.GroupID {
			continue
		}
		// The same resolution the enumeration loop above used to decide whether
		// (and under what bom-ref) this group got a component at all.
		var ref string
		switch id, ok := groupCatalogueID(g); {
		case ok:
			a, found := algo.Lookup(id) // groupCatalogueID returns a catalogue ID, not a bom-ref
			if !found {
				return
			}
			ref = a.BOMRef()
		case g.PQ && g.Hybrid:
			ref = hybridBOMRef(g.Name)
		default:
			return // no component exists for this group (e.g. an uncatalogued classical curve)
		}
		markNegotiatedOnce(emitted, ref)
		return
	}
}

// markNegotiatedOnce flags the component with ref as used by the negotiated
// handshake, once, however many parts of the negotiated suite it plays (RSA is
// both key exchange and authentication in a static-RSA suite).
func markNegotiatedOnce(emitted func(string) (*collector.CryptoAsset, bool), ref string) {
	a, found := emitted(ref)
	if !found {
		return
	}
	if a.Component.Properties != nil {
		for _, p := range *a.Component.Properties {
			if p.Name == cbom.PropertyNamespace+":negotiated" {
				return
			}
		}
	}
	addProperty(&a.Component, "negotiated", "true")
}

// addProperty appends one namespaced custom property to c, preserving any it
// already has.
func addProperty(c *cdx.Component, name, value string) {
	p := cbom.Property(name, value)
	if c.Properties == nil {
		c.Properties = &[]cdx.Property{p}
		return
	}
	*c.Properties = append(*c.Properties, p)
}

// ---- protocols and cipher suites -----------------------------------------------------------

// protocolVersionNumbers maps this program's version labels to the bare
// dotted-number form CycloneDX's protocolProperties.version documents
// (examples "1.0", "1.2", "1.99").
var protocolVersionNumbers = map[string]string{
	"SSLv2": "2.0", "SSLv3": "3.0",
	"TLSv1.0": "1.0", "TLSv1.1": "1.1", "TLSv1.2": "1.2", "TLSv1.3": "1.3",
}

func protocolBOMRef(version string) string {
	if n, ok := protocolVersionNumbers[version]; ok {
		return "protocol/tls/" + n
	}
	return "protocol/tls/" + strings.ToLower(version) // defensive: every real version is in the map above
}

// resolver looks an algorithm ID up and returns its bom-ref, emitting the
// component on first use.
type resolver func(id string) (ref string, ok bool)

// hybridResolver is resolver's counterpart for hybrid groups.
type hybridResolver func(g tlsprobe.GroupResult) (ref string, ok bool)

func protocolAsset(rep *tlsprobe.Report, version string, emit resolver, emitHybrid hybridResolver) collector.CryptoAsset {
	var suites []cdx.CipherSuite
	var deps []string
	seen := map[string]bool{}
	dep := func(ref string, ok bool) {
		if ok && !seen[ref] {
			seen[ref] = true
			deps = append(deps, ref)
		}
	}

	for _, s := range rep.Suites {
		if s.Version != version {
			continue
		}
		var algos []cdx.BOMReference
		add := func(id string, ok bool) {
			if !ok {
				return
			}
			if ref, found := emit(id); found {
				algos = append(algos, cdx.BOMReference(ref))
				dep(ref, true)
			}
		}
		add(cipherCatalogueID(s))
		add(kxCatalogueID(s.Kx))
		add(authCatalogueID(s.Auth))
		suites = append(suites, cdx.CipherSuite{
			Name:        s.Name,
			Identifiers: ptrOrNil([]string{hexID(s.ID)}),
			Algorithms:  ptrOrNil(algos),
		})
	}

	for _, g := range rep.Groups {
		if g.Version != version {
			continue
		}
		if id, ok := groupCatalogueID(g); ok {
			dep(emit(id))
		} else if g.PQ && g.Hybrid {
			dep(emitHybrid(g))
		}
	}

	sort.Strings(deps)
	c := collector.CryptoAsset{
		Component: cdx.Component{
			BOMRef: protocolBOMRef(version), Type: cdx.ComponentTypeCryptographicAsset, Name: version,
			CryptoProperties: &cdx.CryptoProperties{
				AssetType: cdx.CryptoAssetTypeProtocol,
				ProtocolProperties: &cdx.CryptoProtocolProperties{
					Type: cdx.CryptoProtocolTypeTLS, Version: protocolVersionNumbers[version],
				},
			},
			Evidence: observedEvidence("TLS ServerHello (protocol version negotiation)"),
		},
		DependsOn: deps,
	}
	if len(suites) > 0 {
		c.Component.CryptoProperties.ProtocolProperties.CipherSuites = &suites
	}
	return c
}

func hexID(id uint16) string {
	const hexDigits = "0123456789ABCDEF"
	return "0x" + string([]byte{hexDigits[id>>12&0xF], hexDigits[id>>8&0xF], hexDigits[id>>4&0xF], hexDigits[id&0xF]})
}

// cipherCatalogueID identifies a suite's bulk cipher, when the catalogue has an
// entry for it. Legacy ciphers (RC4, 3DES, DES, SEED, IDEA, NULL, ...) have none
// and are named in the suite text without a reference.
func cipherCatalogueID(s tlsprobe.SuiteResult) (string, bool) {
	switch {
	case s.Cipher == "AES":
		// The key size and mode are part of what the suite names, and a CBOM
		// should carry them (AES-128-GCM and AES-256-CBC are not the same asset).
		// A combination the catalogue has no variant for (CCM8, say) is still AES.
		if id := fmt.Sprintf("AES-%d-%s", s.KeyBits, s.Mode); catalogued(id) {
			return id, true
		}
		return "AES", true
	case s.Cipher == "CHACHA20" && s.Mode == "POLY1305":
		return "ChaCha20-Poly1305", true
	}
	return "", false
}

func catalogued(id string) bool {
	_, ok := algo.Lookup(id)
	return ok
}

// kxCatalogueID normalises a suite's key-exchange label (TLS 1.2 and earlier
// name the ephemeral forms DHE/ECDHE; the catalogue carries the generic DH/ECDH
// entry, since it is the same algorithm family whether ephemeral or static).
func kxCatalogueID(kx string) (string, bool) {
	switch kx {
	case "DH", "DHE":
		return "DH", true
	case "ECDH", "ECDHE":
		return "ECDH", true
	case "RSA":
		return "RSA", true
	}
	return "", false
}

// authCatalogueID normalises a suite's authentication label. DSS is TLS's name
// for DSA (RFC 5246 section 7.4.2).
func authCatalogueID(auth string) (string, bool) {
	switch auth {
	case "RSA":
		return "RSA", true
	case "ECDSA":
		return "ECDSA", true
	case "DSS":
		return "DSA", true
	}
	return "", false
}

// groupCatalogueID identifies a key-exchange group against the static algorithm
// catalogue: the three RFC 10024 hybrids and pure ML-KEM groups (the registry
// names the latter "MLKEM768" etc.) map to the same catalogue entries a host
// inventory would use; x25519 and the RFC 7919 ffdheNNNN groups map to the
// existing X25519/DH entries. Other hybrid names (draft-only, or IANA-obsolete
// pre-standard Kyber) are not in the static catalogue (see hybridComponent);
// other classical curves (the NIST P-curves) have no catalogue entry yet either.
func groupCatalogueID(g tlsprobe.GroupResult) (string, bool) {
	switch {
	case g.Hybrid:
		if _, ok := algo.Lookup(g.Name); ok {
			return g.Name, true
		}
	case g.PQ:
		if id, ok := pureMLKEMCatalogueID(g.Name); ok {
			return id, true
		}
	case strings.EqualFold(g.Name, "x25519"):
		return "X25519", true
	case strings.HasPrefix(strings.ToLower(g.Name), "ffdhe"):
		return "DH", true
	}
	return "", false
}

func pureMLKEMCatalogueID(name string) (string, bool) {
	if !strings.HasPrefix(name, "MLKEM") {
		return "", false
	}
	switch strings.TrimPrefix(name, "MLKEM") {
	case "512":
		return "ML-KEM-512", true
	case "768":
		return "ML-KEM-768", true
	case "1024":
		return "ML-KEM-1024", true
	}
	return "", false
}

// hybridComponent builds a Combiner-primitive algorithm component for a hybrid
// post-quantum group (e.g. X25519MLKEM768) directly from what the scan and the
// generated IANA registry already know, rather than a static catalogue entry:
// these names are TLS-specific constructions with no independent identity (and
// no OID of their own) outside this context, unlike RSA or ML-KEM-768, which a
// host inventory also needs to name on their own. A pre-standard draft group
// (IANA-obsolete) still gets a component, marked as such, since it is a real
// thing a server can be observed offering, not a guess.
// hybridBOMRef is the bom-ref a hybrid group's algorithm component gets. It is
// computed the same way in markNegotiated so a negotiated hybrid group can be
// found without re-deriving the component.
func hybridBOMRef(name string) string { return "crypto/algorithm/" + strings.ToLower(name) }

func hybridComponent(g tlsprobe.GroupResult) (collector.CryptoAsset, bool) {
	if !g.PQ || !g.Hybrid {
		return collector.CryptoAsset{}, false
	}
	c := cdx.Component{
		BOMRef: hybridBOMRef(g.Name), Type: cdx.ComponentTypeCryptographicAsset, Name: g.Name,
		CryptoProperties: &cdx.CryptoProperties{
			AssetType:           cdx.CryptoAssetTypeAlgorithm,
			AlgorithmProperties: &cdx.CryptoAlgorithmProperties{Primitive: cdx.CryptoPrimitiveCombiner},
		},
	}
	if g.Obsolete {
		c.Properties = &[]cdx.Property{cbom.Property("iana-obsolete", "true")}
	}
	return collector.CryptoAsset{Component: c}, true
}

// ---- certificates ----------------------------------------------------------------------------

// chainRole names a certificate's place in the chain the server presented: the
// first is the server's own (leaf) certificate; anything after it is a CA, a
// root when it signed itself. The scan reports what was presented, so a root the
// server did not send has no component.
func chainRole(pos int, ci tlsprobe.CertInfo) string {
	switch {
	case pos == 0:
		return "leaf"
	case ci.SelfSigned:
		return "root"
	}
	return "intermediate"
}

// certificateAssets emits one certificate component per distinct certificate the
// server presented, plus, for each, the public key it certifies as its own
// related-crypto-material component (see cbom.CertificateAsset, which the host
// inventory shares). emit resolves a catalogue algorithm; emitAsset adds a derived one.
func certificateAssets(rep *tlsprobe.Report, emit resolver, emitAsset func(collector.CryptoAsset) string) []collector.CryptoAsset {
	seen := map[string]bool{}
	var out []collector.CryptoAsset
	for _, cr := range rep.Certificates {
		for pos, ci := range cr.Chain {
			if ci.SHA256 == "" || seen[ci.SHA256] {
				continue
			}
			seen[ci.SHA256] = true
			cert, key := certificateAsset(ci, chainRole(pos, ci), emit, emitAsset)
			out = append(out, cert)
			if key != nil {
				out = append(out, *key)
			}
		}
	}
	return out
}

// certificateAsset builds the components for one certificate the server presented. The
// shape (certificate, its public key with size, algorithm references) is shared with the host
// inventory; what is TLS-specific is where it was seen and its place in the chain.
func certificateAsset(ci tlsprobe.CertInfo, role string, emit resolver, emitAsset func(collector.CryptoAsset) string) (collector.CryptoAsset, *collector.CryptoAsset) {
	cert, key := cbom.CertificateAsset(cbom.CertFacts{
		Subject: ci.Subject, Issuer: ci.Issuer, SerialHex: ci.SerialHex, SHA256: ci.SHA256,
		NotBefore: ci.NotBefore, NotAfter: ci.NotAfter,
		KeyAlgorithm: ci.PublicKey.Algorithm, KeyBits: ci.PublicKey.Bits, Curve: ci.PublicKey.Curve, SigName: ci.SignatureAlg.Name,
	}, emit, emitAsset)
	ev := observedEvidence("certificate chain presented during the TLS handshake")
	cert.Component.Evidence = ev
	props := []cdx.Property{cbom.Property("chain-role", role)}
	if ci.SerialHex != "" {
		props = append(props, cbom.Property("cert-serial", ci.SerialHex))
	}
	cert.Component.Properties = &props
	if key != nil {
		key.Component.Evidence = ev
	}
	return cert, key
}

// ptrOrNil returns a pointer to s, or nil when it is empty (an empty list is omitted).
func ptrOrNil[T any](s []T) *[]T {
	if len(s) == 0 {
		return nil
	}
	return &s
}
