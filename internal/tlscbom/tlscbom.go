// Package tlscbom turns an active TLS scan's observations into CBOM assets. It lives apart
// from internal/cbom so that a program that only needs the host inventory (the collector) does
// not link the TLS scanner.
package tlscbom

import (
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/offsetsecurity/cipherhorizon/internal/algo"
	"github.com/offsetsecurity/cipherhorizon/internal/cbom"
	"github.com/offsetsecurity/cipherhorizon/internal/collector"
	"github.com/offsetsecurity/cipherhorizon/internal/tlsprobe"
	"github.com/offsetsecurity/cipherhorizon/internal/tlsprobe/registry"
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
// program does not carry (SEED, Camellia, a binary curve) — is still named in
// the suite or certificate text; it simply gets no algorithm reference.
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

	// How each component was learned (AUDIT-TLS-CBOM-001 A-5). One component can be reached more
	// than one way (X25519 is an accepted group; ECDH is derived from an accepted suite's name).
	states := map[string]map[string]bool{}
	record := func(ref, state string) {
		if states[ref] == nil {
			states[ref] = map[string]bool{}
		}
		states[ref][state] = true
	}
	as := func(state string, r resolver) resolver {
		return func(id string) (string, bool) {
			ref, ok := r(id)
			if ok {
				record(ref, state)
			}
			return ref, ok
		}
	}
	hybridAccepted := func(g tlsprobe.GroupResult) (string, bool) {
		ref, ok := emitHybrid(g)
		if ok {
			record(ref, EvidenceAccepted)
		}
		return ref, ok
	}

	for _, p := range rep.Protocols {
		if !p.Supported {
			continue
		}
		pa := protocolAsset(rep, p.Version, as(EvidenceDerived, emit), as(EvidenceAccepted, emit), hybridAccepted)
		record(pa.Component.BOMRef, EvidenceObserved)
		assets = append(assets, pa)
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
		record(ref, EvidenceObserved)
		return ref
	}
	for _, c := range certificateAssets(rep, as(EvidenceObserved, emit), emitAsset) {
		record(c.Component.BOMRef, EvidenceObserved)
		assets = append(assets, c)
		index[c.Component.BOMRef] = len(assets) - 1
	}
	signatureAlgorithms(rep, as(EvidenceAccepted, emit), emitted)

	for _, ref := range markNegotiated(rep, emitted) {
		record(ref, EvidenceNegotiated)
	}
	for i := range assets {
		if st := states[assets[i].Component.BOMRef]; len(st) > 0 {
			var list []string
			for _, s := range []string{EvidenceObserved, EvidenceAccepted, EvidenceDerived, EvidenceNegotiated} {
				if st[s] {
					list = append(list, s)
				}
			}
			addProperty(&assets[i].Component, "evidence", strings.Join(list, ", "))
		}
	}

	sort.SliceStable(assets, func(i, j int) bool { return assets[i].Component.BOMRef < assets[j].Component.BOMRef })
	return assets
}

// The evidence states (AUDIT-TLS-CBOM-001 A-5), written as cipherhorizon:evidence on every
// component. They say how a fact was learned, and they are never a probability:
//
//   - observed: seen directly: a ServerHello for a protocol version, a certificate and what it
//     states (its key, its signature algorithm), decoded from the bytes the server sent;
//   - accepted: a probe offering only that one thing was answered (a key-exchange group named by a
//     HelloRetryRequest, a TLS 1.3 signature scheme answered with a ServerHello);
//   - derived: implied by an accepted thing through a fixed, cited mapping: the bulk cipher, key
//     exchange and authentication an accepted suite's IANA registry entry names;
//   - negotiated: used by the one handshake a current client completed (see markNegotiated).
//
// What was not tested, or proved nothing, is stated per stage in the document's metadata (Coverage).
const (
	EvidenceObserved   = "observed"
	EvidenceAccepted   = "accepted"
	EvidenceDerived    = "derived"
	EvidenceNegotiated = "negotiated"
)

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
// It returns the bom-refs it marked (the protocol among them), for the evidence states.
func markNegotiated(rep *tlsprobe.Report, emitted func(string) (*collector.CryptoAsset, bool)) (marked []string) {
	n := rep.Negotiated
	if n == nil || n.Error != "" {
		return
	}
	proto, ok := emitted(protocolBOMRef(n.Version))
	if !ok {
		return
	}
	marked = append(marked, proto.Component.BOMRef)
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
				if markNegotiatedOnce(emitted, a.BOMRef(), n.Version) {
					marked = append(marked, a.BOMRef())
				}
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
		if markNegotiatedOnce(emitted, ref, n.Version) {
			marked = append(marked, ref)
		}
		return
	}
	return
}

// sigCatalogueID maps the key a TLS 1.3 signature scheme needs to its catalogue algorithm. A key
// the catalogue does not carry gets no component: it stays named in the property below.
func sigCatalogueID(algorithm string) (string, bool) {
	switch algorithm {
	case "ML-DSA-44", "ML-DSA-65", "ML-DSA-87", "ECDSA", "Ed25519", "Ed448", "RSA":
		return algorithm, true
	case "RSASSA-PSS":
		return "RSA", true
	}
	return "", false
}

// signatureAlgorithms records the TLS 1.3 signature schemes the signature stage proved the server
// can sign with (PRD-008 REQ-PQS-6): the scheme names on the TLS 1.3 protocol component, and an
// edge to each scheme's algorithm. Only a conclusive stage counts; nothing is marked negotiated,
// because offering one scheme at a time shows what the server holds, not what a client uses.
func signatureAlgorithms(rep *tlsprobe.Report, emit resolver, emitted func(string) (*collector.CryptoAsset, bool)) {
	acc := rep.Signatures.Accepted()
	if len(acc) == 0 {
		return
	}
	if _, ok := emitted(protocolBOMRef("TLSv1.3")); !ok {
		return
	}
	names := make([]string, 0, len(acc))
	coded := make([]string, 0, len(acc))
	var refs []string
	for _, s := range acc {
		names = append(names, s.Name)
		coded = append(coded, ianaName(s.Name, s.ID))
		id, ok := sigCatalogueID(s.Algorithm)
		if !ok {
			continue
		}
		if ref, ok := emit(id); ok {
			refs = append(refs, ref)
		}
	}
	// Looked up only now: emit may have grown the slice the component lives in.
	proto, _ := emitted(protocolBOMRef("TLSv1.3"))
	addProperty(&proto.Component, "accepted-signature-schemes", strings.Join(names, ","))
	// The same schemes with their IANA code points (AUDIT-TLS-CBOM-001 A-13). These are what the
	// server can sign a TLS 1.3 handshake with, not its certificates' signature algorithms.
	addProperty(&proto.Component, "accepted-signature-schemes-iana", strings.Join(coded, ", "))
	have := map[string]bool{}
	for _, d := range proto.DependsOn {
		have[d] = true
	}
	for _, r := range refs {
		if !have[r] {
			have[r] = true
			proto.DependsOn = append(proto.DependsOn, r)
		}
	}
	sort.Strings(proto.DependsOn)
}

// markNegotiatedOnce flags the component with ref as used by the negotiated
// handshake, once, however many parts of the negotiated suite it plays (RSA is
// both key exchange and authentication in a static-RSA suite).
//
// negotiated-in names the version of that handshake (AUDIT-TLS-CBOM-001 A-14): one algorithm
// component (AES-128-GCM) serves suites of several versions, and the flag alone does not say which
// one was used. It reports whether the component exists.
func markNegotiatedOnce(emitted func(string) (*collector.CryptoAsset, bool), ref, version string) bool {
	a, found := emitted(ref)
	if !found {
		return false
	}
	if a.Component.Properties != nil {
		for _, p := range *a.Component.Properties {
			if p.Name == cbom.PropertyNamespace+":negotiated" {
				return true
			}
		}
	}
	addProperty(&a.Component, "negotiated", "true")
	addProperty(&a.Component, "negotiated-in", version)
	return true
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

// emitSuite resolves what a suite's IANA name implies (derived); emitGroup resolves an accepted
// group (accepted). They are the same catalogue lookup, kept apart for the evidence states.
func protocolAsset(rep *tlsprobe.Report, version string, emitSuite, emitGroup resolver, emitHybrid hybridResolver) collector.CryptoAsset {
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
			ref, found := emitSuite(id)
			if !found {
				return
			}
			// RSA is both the key exchange and the authentication of a static-RSA suite:
			// list it once (CBOM-REVIEW-002 C-6).
			for _, have := range algos {
				if have == cdx.BOMReference(ref) {
					return
				}
			}
			algos = append(algos, cdx.BOMReference(ref))
			dep(ref, true)
		}
		add(cipherCatalogueID(s))
		add(kxCatalogueID(s.Kx))
		add(authCatalogueID(s.Auth))
		add(macCatalogueID(s))
		suites = append(suites, cdx.CipherSuite{
			Name:        s.Name,
			Identifiers: ptrOrNil([]string{hexID(s.ID)}),
			Algorithms:  ptrOrNil(algos),
		})
	}

	// Every accepted group is listed with its IANA code point, whether or not the catalogue has an
	// algorithm for it, so a group the program cannot model (brainpool, a binary curve, GOST) is
	// still in the document (AUDIT-TLS-CBOM-001 A-4).
	var groupIDs []string
	for _, g := range rep.Groups {
		if g.Version != version {
			continue
		}
		groupIDs = append(groupIDs, ianaName(g.Name, g.ID))
		if id, ok := groupCatalogueID(g); ok {
			dep(emitGroup(id))
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
	if len(groupIDs) > 0 {
		addProperty(&c.Component, "accepted-groups", strings.Join(groupIDs, ", "))
	}
	return c
}

// ianaName is a registry name with its code point, as IANA lists it: "x25519 (0x001D)".
func ianaName(name string, id uint16) string { return name + " (" + hexID(id) + ")" }

func hexID(id uint16) string {
	const hexDigits = "0123456789ABCDEF"
	return "0x" + string([]byte{hexDigits[id>>12&0xF], hexDigits[id>>8&0xF], hexDigits[id>>4&0xF], hexDigits[id&0xF]})
}

// cipherCatalogueID identifies a suite's bulk cipher, when the catalogue has an
// entry for it. The legacy ciphers the catalogue carries (3DES, RC4, DES, RC2) are
// referenced with their cited classical status (CBOM-REVIEW-002 C-1); the others
// (SEED, IDEA, Camellia, ARIA, ...) and NULL, which is no cipher, are named in the
// suite text without a reference.
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
	case s.Cipher == "3DES", s.Cipher == "RC4", s.Cipher == "DES", s.Cipher == "RC2":
		// A whole-family entry: the catalogue has no key-size variants for these, and
		// an export (40-bit) RC4 or DES is still RC4 or DES.
		return s.Cipher, true
	}
	return "", false
}

// macCatalogueID names what protects the records of a suite besides its cipher (AUDIT-TLS-CBOM-001
// A-11), as the IANA registry entry for the suite states it: the HMAC of a TLS 1.2 CBC or stream
// suite (..._SHA, _SHA256, _SHA384, _MD5), or, for an AEAD suite, the hash its name carries (the
// TLS 1.2 PRF hash, or the TLS 1.3 HKDF hash). Derived from the registry, like the cipher.
func macCatalogueID(s tlsprobe.SuiteResult) (string, bool) {
	switch s.MAC {
	case "SHA1":
		return "HMAC-SHA-1", true
	case "SHA256":
		return "HMAC-SHA-256", true
	case "SHA384":
		return "HMAC-SHA-384", true
	case "MD5":
		return "HMAC-MD5", true
	case "AEAD":
		if r, ok := registry.SuiteByID(s.ID); ok {
			switch r.Hash {
			case "SHA256":
				return "SHA-256", true
			case "SHA384":
				return "SHA-384", true
			}
		}
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
// existing X25519/DH entries; x448 and the NIST curves secp256r1/384r1/521r1 map to
// X448 and ECDH-P256/P384/P521 (CBOM-REVIEW-002 C-2). Other hybrid names (draft-only, or IANA-obsolete
// pre-standard Kyber) are not in the static catalogue (see hybridComponent);
// other classical curves (brainpool, binary, GOST) have no catalogue entry yet either.
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
	case strings.EqualFold(g.Name, "x448"):
		return "X448", true
	case g.Name == "secp256r1":
		return "ECDH-P256", true
	case g.Name == "secp384r1":
		return "ECDH-P384", true
	case g.Name == "secp521r1":
		return "ECDH-P521", true
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
//
// Each certificate says which handshakes returned it (AUDIT-TLS-CBOM-001 A-9) and, within a chain
// as served, which certificate after it issued it (A-10). A chain is never rebuilt from a trust
// store here: an issued-by link exists only when the server sent the issuer next.
func certificateAssets(rep *tlsprobe.Report, emit resolver, emitAsset func(collector.CryptoAsset) string) []collector.CryptoAsset {
	sources := map[string][]string{}
	noSNIOnly := map[string]bool{}
	issuedBy := map[string]string{}
	for _, cr := range rep.Certificates {
		for pos, ci := range cr.Chain {
			if ci.SHA256 == "" {
				continue
			}
			src := cr.Source
			if cr.NoSNI {
				src += " (no SNI)"
			}
			if !slices.Contains(sources[ci.SHA256], src) {
				sources[ci.SHA256] = append(sources[ci.SHA256], src)
			}
			if _, seen := noSNIOnly[ci.SHA256]; !seen {
				noSNIOnly[ci.SHA256] = cr.NoSNI
			} else if !cr.NoSNI {
				noSNIOnly[ci.SHA256] = false
			}
			if pos+1 < len(cr.Chain) && cr.Chain[pos+1].SHA256 != "" && ci.Issuer != "" && ci.Issuer == cr.Chain[pos+1].Subject && issuedBy[ci.SHA256] == "" {
				issuedBy[ci.SHA256] = "crypto/certificate/" + strings.ToLower(cr.Chain[pos+1].SHA256)
			}
		}
	}
	seen := map[string]bool{}
	var out []collector.CryptoAsset
	for _, cr := range rep.Certificates {
		for pos, ci := range cr.Chain {
			if ci.SHA256 == "" || seen[ci.SHA256] {
				continue
			}
			seen[ci.SHA256] = true
			cert, key := certificateAsset(ci, chainRole(pos, ci), emit, emitAsset)
			addProperty(&cert.Component, "seen-in", strings.Join(sources[ci.SHA256], ", "))
			if noSNIOnly[ci.SHA256] {
				// Only a client that sends no server name gets this certificate.
				addProperty(&cert.Component, "no-sni", "true")
			}
			if by := issuedBy[ci.SHA256]; by != "" {
				addProperty(&cert.Component, "issued-by", by)
			}
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
		SigOID: ci.SignatureAlg.OID, KeyOID: ci.PublicKey.OID,
		Extensions: certExtensions(ci),
	}, emit, emitAsset)
	ev := observedEvidence("certificate chain presented during the TLS handshake")
	cert.Component.Evidence = ev
	props := []cdx.Property{cbom.Property("chain-role", role)}
	if ci.SerialHex != "" {
		props = append(props, cbom.Property("cert-serial", ci.SerialHex))
	}
	if ci.SignatureParams != "" {
		// RSASSA-PSS hash, mask generation, salt and trailer (RFC 8017 A.2.3): CycloneDX has no
		// field for a signature's parameters (AUDIT-TLS-CBOM-001 A-3).
		props = append(props, cbom.Property("signature-parameters", ci.SignatureParams))
	}
	cert.Component.Properties = &props
	if key != nil {
		key.Component.Evidence = ev
		// The key's own identity and the RSA exponent (A-12). In 1.7 the fingerprint moves into
		// relatedCryptoMaterialProperties.fingerprint; 1.6 has no such field.
		if ci.SPKISHA256 != "" {
			addProperty(&key.Component, "key-fingerprint-sha256", ci.SPKISHA256)
		}
		if ci.RSAExponent > 0 {
			addProperty(&key.Component, "rsa-exponent", strconv.Itoa(ci.RSAExponent))
		}
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

// certExtensions names the extensions a tls-report/2 recorded, by the CycloneDX 1.7 common
// names (PRD-004 REQ-TNFR-7), and lists every other extension by its OID as a 1.7 custom
// extension, decoded where this program decodes it and marked "not decoded" where it does not
// (AUDIT-TLS-CBOM-001 A-7, A-8). A tls-report/1 certificate yields what it recorded: nothing is
// invented.
func certExtensions(ci tlsprobe.CertInfo) []cbom.CertExtension {
	var out []cbom.CertExtension
	if bc := ci.BasicConstraints; bc != nil {
		v := "CA:FALSE"
		if bc.CA {
			v = "CA:TRUE"
			if bc.MaxPathLen >= 0 {
				v += ", pathlen:" + strconv.Itoa(bc.MaxPathLen)
			}
		}
		out = append(out, cbom.CertExtension{Name: "basicConstraints", Value: v})
	}
	if len(ci.KeyUsage) > 0 {
		out = append(out, cbom.CertExtension{Name: "keyUsage", Value: strings.Join(ci.KeyUsage, ", ")})
	}
	if len(ci.ExtKeyUsage) > 0 {
		out = append(out, cbom.CertExtension{Name: "extendedKeyUsage", Value: strings.Join(ci.ExtKeyUsage, ", ")})
	}
	if len(ci.Policies) > 0 {
		out = append(out, cbom.CertExtension{Name: "certificatePolicies", Value: strings.Join(ci.Policies, ", ")})
	}
	var san []string
	for _, d := range ci.DNSNames {
		san = append(san, "DNS:"+d)
	}
	for _, ip := range ci.IPAddresses {
		san = append(san, "IP:"+ip)
	}
	if len(san) > 0 {
		out = append(out, cbom.CertExtension{Name: "subjectAlternativeName", Value: strings.Join(san, ", ")})
	}
	var aia []string
	for _, u := range ci.OCSPServers {
		aia = append(aia, "OCSP - URI:"+u)
	}
	for _, u := range ci.IssuerURLs {
		aia = append(aia, "CA Issuers - URI:"+u)
	}
	if len(aia) > 0 {
		out = append(out, cbom.CertExtension{Name: "authorityInformationAccess", Value: strings.Join(aia, ", ")})
	}
	if len(ci.CRLPoints) > 0 {
		out = append(out, cbom.CertExtension{Name: "crlDistributionPoints", Value: "URI:" + strings.Join(ci.CRLPoints, ", URI:")})
	}
	if ci.AuthorityKeyID != "" {
		out = append(out, cbom.CertExtension{Name: "authorityKeyIdentifier", Value: ci.AuthorityKeyID})
	}
	if ci.SubjectKeyID != "" {
		out = append(out, cbom.CertExtension{Name: "subjectKeyIdentifier", Value: ci.SubjectKeyID})
	}
	if ci.EmbeddedSCTs {
		out = append(out, cbom.CertExtension{Name: "signedCertificateTimestamp", Value: "present (not decoded into the CBOM)"})
	}
	// Every extension 1.7 has no common name for: name constraints and the TLS Feature are decoded;
	// anything else is listed by OID as not decoded.
	for _, e := range ci.Extensions {
		if commonExtensionNames[e.Name] {
			continue
		}
		v := "not decoded"
		switch e.Name {
		case "nameConstraints":
			v = nameConstraintsWords(ci.NameConstraints)
		case "tlsFeature":
			v = "present"
			if ci.OCSPMustStaple {
				v = "status_request (OCSP must-staple)"
			}
		}
		if e.Critical {
			v += "; critical"
		}
		name := e.OID
		if e.Name != "" {
			name = e.Name + " (" + e.OID + ")"
		}
		out = append(out, cbom.CertExtension{Name: name, Value: v, Custom: true})
	}
	return out
}

// commonExtensionNames are the extensions written under their 1.7 common name above.
var commonExtensionNames = map[string]bool{
	"basicConstraints": true, "keyUsage": true, "extendedKeyUsage": true, "certificatePolicies": true,
	"subjectAlternativeName": true, "authorityInformationAccess": true, "crlDistributionPoints": true,
	"authorityKeyIdentifier": true, "subjectKeyIdentifier": true, "signedCertificateTimestamp": true,
}

func nameConstraintsWords(nc *tlsprobe.NameConstraints) string {
	if nc == nil {
		return "present"
	}
	var parts []string
	if len(nc.Permitted) > 0 {
		parts = append(parts, "permitted: "+strings.Join(nc.Permitted, ", "))
	}
	if len(nc.Excluded) > 0 {
		parts = append(parts, "excluded: "+strings.Join(nc.Excluded, ", "))
	}
	if len(parts) == 0 {
		return "present, no names"
	}
	return strings.Join(parts, "; ")
}

// Coverage states, in the document's metadata, what the scan covered (AUDIT-TLS-CBOM-001 A-6): one
// property per stage (done; done with inconclusive parts; not tested and why; inconclusive), whether
// the scan was complete, and the registry the derived facts were mapped with. Without it an absent
// component cannot be told apart from an untested one.
func Coverage(rep *tlsprobe.Report) []cdx.Property {
	if rep == nil {
		return nil
	}
	props := []cdx.Property{cbom.Property("scan-complete", strconv.FormatBool(!rep.Incomplete))}
	for _, st := range rep.Stages {
		var v string
		switch st.Outcome {
		case tlsprobe.OutcomeDone:
			v = "done"
			if len(st.Inconclusive) > 0 {
				v += "; inconclusive: " + strings.Join(st.Inconclusive, "; ")
			}
		case tlsprobe.OutcomeSkipped:
			// Why it did not run decides what its absence means: a test switched off, one that
			// does not apply to this service, one an earlier failure prevented, or one the budget cut.
			v = map[string]string{
				tlsprobe.ReasonOptionOff:     "not tested",
				tlsprobe.ReasonNotApplicable: "not applicable",
				tlsprobe.ReasonNotReached:    "not reached",
				tlsprobe.ReasonBudget:        "not tested (budget)",
				tlsprobe.ReasonLegacy:        "not recorded (older report)",
			}[st.ReasonCode]
			if v == "" {
				v = "not tested"
			}
			if st.Reason != "" {
				v += ": " + st.Reason
			}
		case tlsprobe.OutcomeInconclusive:
			v = "inconclusive"
			if why := firstNonEmpty(st.Reason, st.ReasonCode); why != "" {
				v += ": " + why
			}
		default:
			continue
		}
		props = append(props, cbom.Property("coverage:"+st.Name, v))
	}
	props = append(props, cbom.Property("mapping",
		"IANA TLS cipher suites retrieved "+registry.SuitesRetrieved+", supported groups retrieved "+registry.GroupsRetrieved+
			"; algorithm catalogue with cited OIDs (docs/cbom-model.md)"))
	return props
}

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}

// CipherID and GroupID are the catalogue IDs this package gives a suite's cipher and a group,
// for the evaluation's list of algorithms in use (PRD-011 REQ-CLS-4), so both name them alike.
func CipherID(s tlsprobe.SuiteResult) (string, bool) { return cipherCatalogueID(s) }

// GroupID is the catalogue ID this package gives a key-exchange group; see CipherID.
func GroupID(g tlsprobe.GroupResult) (string, bool) { return groupCatalogueID(g) }
