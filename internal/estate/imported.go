package estate

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strings"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/offsetsecurity/cipherhorizon/internal/algo"
	"github.com/offsetsecurity/cipherhorizon/internal/evidence"
)

// ImportKind says what kind of evidence a third-party document is, which decides the
// strongest thing its content may be read as (ENG-HANDOFF-002 DN-3, PRD-003 REQ-ING-5).
type ImportKind string

// The import kinds.
const (
	// ImportSource: made by reading source code or a repository (CBOMkit's scanners, cdxgen). It
	// says what code REFERENCES, not what is deployed: read as "capable, from source", never as present.
	ImportSource ImportKind = "static-source"
	// ImportHost: made by looking at a machine's files or network ports (CBOM-Lens, Theia,
	// this product's own collector). Read as "present"; a certificate as held.
	ImportHost ImportKind = "host"
	// ImportGeneric: a producer we do not recognise. Read at the weakest honest level.
	ImportGeneric ImportKind = "generic"
)

// Methods for observations made from an imported document.
const (
	MethodImportSource = "cbom.import.source@1"
	MethodImportHost   = "cbom.import.host@1"
)

const maxOccurrencesPerComponent = 8

var (
	sha256Hint = regexp.MustCompile(`sha256:([0-9a-fA-F]{64})`)
)

// FromImportedCBOM projects a third-party CBOM into observations on the imported stream. It
// can only ever say things an import may say: nothing it produces is bound, loaded or
// exercised (Validate refuses those for the imported stream), and what the document claims
// about its own subject, producer or trust plays no part. Whatever it cannot model is counted
// in Uninterpreted, never dropped silently.
func FromImportedCBOM(bom *cdx.BOM, kind ImportKind) Result {
	res := Result{Uninterpreted: Uninterpreted{}}
	if bom == nil || bom.Components == nil {
		return res
	}
	rung, relAlg, relProto, method, quality := evidence.RungPresent, RelCapable, RelOffers, MethodCBOMImport, QualitySampled
	certRung := evidence.RungProvisioned
	switch kind {
	case ImportSource:
		rung, relProto, method, quality = evidence.RungCapable, RelCapable, MethodImportSource, QualityHeuristic
		certRung = evidence.RungPresent
	case ImportHost:
		method = MethodImportHost
	}

	byRef := map[string]cdx.Component{}
	var all []cdx.Component
	var walk func(cs []cdx.Component)
	walk = func(cs []cdx.Component) {
		for _, c := range cs {
			all = append(all, c)
			if c.BOMRef != "" {
				byRef[c.BOMRef] = c
			}
			if c.Components != nil {
				walk(*c.Components)
			}
		}
	}
	walk(*bom.Components)

	add := func(e Entity, relation string, r evidence.Rung, attrs map[string]string) {
		res.Observations = append(res.Observations, Observation{
			Entity: e, Relation: relation, Rung: r, Class: evidence.ClassOf(evidence.Claim{Rung: r}),
			Method: method, Quality: quality, Attrs: dropEmpty(attrs),
		})
	}

	res.Components = len(all)
	// project turns one component into observations and reports whether it was interpreted:
	// whether it produced observations or contributed to one (a public key gives a certificate its
	// size). Everything else is counted by reason.
	project := func(c cdx.Component) bool {
		switch {
		case c.Type == cdx.ComponentTypeCryptographicAsset && c.CryptoProperties != nil:
			switch c.CryptoProperties.AssetType {
			case cdx.CryptoAssetTypeAlgorithm:
				e, ok := importedAlgorithm(c)
				if !ok {
					res.Uninterpreted.add("algorithm without a name")
					return false
				}
				add(e, relAlg, rung, nil)
			case cdx.CryptoAssetTypeCertificate:
				fp := importedFingerprint(c)
				if fp == "" {
					res.Uninterpreted.add("certificate without a SHA-256 hash")
					return false
				}
				ent := importedCertificate(c, fp, byRef)
				occ := occurrences(c)
				if len(occ) == 0 {
					add(ent, RelContains, certRung, nil)
					return true
				}
				for _, loc := range occ {
					add(ent, RelContains, certRung, map[string]string{"location": loc})
				}
			case cdx.CryptoAssetTypeProtocol:
				name, ok := importedProtocol(c)
				if !ok {
					res.Uninterpreted.add("protocol of an unrecognised type")
					return false
				}
				add(Entity{Kind: KindProtocol, Key: ProtocolKey(name), Name: name, Attrs: map[string]string{"version": name}}, relProto, rung, nil)
				if pp := c.CryptoProperties.ProtocolProperties; pp != nil && pp.CipherSuites != nil {
					for _, cs := range *pp.CipherSuites {
						if id, ok := suiteID(cs); ok {
							add(Entity{Kind: KindSuite, Key: SuiteKey(id), Name: clean(cs.Name, MaxNameLen)}, relProto, rung, nil)
						} else {
							res.Uninterpreted.add("cipher suite without a code point")
						}
					}
				}
			case cdx.CryptoAssetTypeRelatedCryptoMaterial:
				// Public keys give a certificate its key size (read through the certificate's
				// reference); every other kind of key or secret is counted and not modelled: the
				// graph carries no key material of any kind, imported or not.
				t := "related crypto material"
				if rp := c.CryptoProperties.RelatedCryptoMaterialProperties; rp != nil && rp.Type != "" {
					if rp.Type == cdx.RelatedCryptoMaterialTypePublicKey {
						return true
					}
					t += ": " + clean(string(rp.Type), 40)
				}
				res.Uninterpreted.add(t + " (not modelled)")
				return false
			default:
				res.Uninterpreted.add("cryptographic asset of type " + clean(string(c.CryptoProperties.AssetType), 40))
				return false
			}
		case c.Type == cdx.ComponentTypeCryptographicAsset:
			res.Uninterpreted.add("cryptographic asset without cryptoProperties")
			return false
		case c.Name == "":
			res.Uninterpreted.add("component without a name")
			return false
		default:
			attrs := map[string]string{"version": clean(c.Version, 128), "purl": clean(c.PackageURL, MaxAttrLen), "kind": string(c.Type)}
			add(Entity{Kind: KindSoftware, Key: SoftwareKey(c.PackageURL, c.Name, c.Version), Name: clean(c.Name, MaxNameLen), Attrs: dropEmpty(attrs)}, RelContains, evidence.RungPresent, nil)
		}
		return true
	}
	for _, c := range all {
		if project(c) {
			res.Interpreted++
		} else {
			res.NotInterpreted++
		}
	}
	return res
}

// importedAlgorithm maps an algorithm component to an entity. A component whose OID is in
// the catalogue shares the catalogue's key, so the same algorithm from a host scan and from an
// import is one entity; anything else is keyed by its name (and parameter set) under a
// separate prefix that cannot collide with a catalogue key.
func importedAlgorithm(c cdx.Component) (Entity, bool) {
	name := strings.TrimSpace(c.Name)
	if name == "" {
		return Entity{}, false
	}
	oid := ""
	if c.CryptoProperties != nil {
		oid = strings.TrimSpace(c.CryptoProperties.OID)
	}
	if oid != "" {
		for _, a := range algo.All() {
			if a.OID == oid {
				return Entity{Kind: KindAlgorithm, Key: evidence.AlgorithmKey(a.ID), Name: clean(name, MaxNameLen), Attrs: dropEmpty(map[string]string{"oid": clean(oid, 128)})}, true
			}
		}
	}
	key := "algo:x:" + strings.ToLower(strings.ReplaceAll(name, " ", "-"))
	if ap := c.CryptoProperties.AlgorithmProperties; ap != nil && ap.ParameterSetIdentifier != "" {
		key += "/" + strings.ToLower(clean(ap.ParameterSetIdentifier, 32))
	}
	return Entity{Kind: KindAlgorithm, Key: clean(key, MaxKeyLen), Name: clean(name, MaxNameLen), Attrs: dropEmpty(map[string]string{"oid": clean(oid, 128)})}, true
}

// importedFingerprint finds a certificate's SHA-256 fingerprint: its SHA-256 hash, or a
// sha256 fingerprint some producers put in the bom-ref. A document that gives neither has no
// identity we can key a certificate on, and the certificate is counted, not guessed.
func importedFingerprint(c cdx.Component) string {
	if fp := sha256Of(c); fp != "" {
		return fp
	}
	if m := sha256Hint.FindStringSubmatch(c.BOMRef); m != nil {
		return strings.ToLower(m[1])
	}
	return ""
}

func importedCertificate(c cdx.Component, fp string, byRef map[string]cdx.Component) Entity {
	attrs := map[string]string{"fingerprint": fp}
	if cp := c.CryptoProperties; cp != nil && cp.CertificateProperties != nil {
		p := cp.CertificateProperties
		attrs["subject"] = clean(p.SubjectName, MaxAttrLen)
		attrs["issuer"] = clean(p.IssuerName, MaxAttrLen)
		if t, ok := parseTime(p.NotValidBefore); ok {
			attrs["notBefore"] = t
		}
		if t, ok := parseTime(p.NotValidAfter); ok {
			attrs["notAfter"] = t
		}
		// Key size and algorithm through the standard's references: the certificate points at a
		// public-key component, which states its size and points at its algorithm.
		// CycloneDX 1.7 moved these references into relatedCryptographicAssets; both forms are read.
		keyRef, sigRef := string(p.SubjectPublicKeyRef), string(p.SignatureAlgorithmRef)
		if p.RelatedCryptographicAssets != nil {
			for _, ra := range *p.RelatedCryptographicAssets {
				switch strings.ToLower(ra.Type) {
				case "publickey":
					if keyRef == "" {
						keyRef = ra.Ref
					}
				case "algorithm", "signaturealgorithm":
					if sigRef == "" {
						sigRef = ra.Ref
					}
				}
			}
		}
		if key, ok := byRef[keyRef]; ok && key.CryptoProperties != nil && key.CryptoProperties.RelatedCryptoMaterialProperties != nil {
			rp := key.CryptoProperties.RelatedCryptoMaterialProperties
			if rp.Size != nil && *rp.Size > 0 && *rp.Size < 100000 {
				attrs["keyBits"] = itoa(*rp.Size)
			}
			algRef := string(rp.AlgorithmRef)
			if algRef == "" && rp.RelatedCryptographicAssets != nil {
				for _, ra := range *rp.RelatedCryptographicAssets {
					if strings.ToLower(ra.Type) == "algorithm" {
						algRef = ra.Ref
						break
					}
				}
			}
			if a, ok := byRef[algRef]; ok {
				attrs["keyAlg"], attrs["curve"] = importedKeyAlgorithm(a)
			}
		}
		if a, ok := byRef[sigRef]; ok {
			attrs["sigAlg"] = clean(a.Name, 64)
		}
	}
	name := clean(attrs["subject"], MaxNameLen)
	if name == "" {
		name = clean(c.Name, MaxNameLen)
	}
	if name == "" {
		name = fp
	}
	return Entity{Kind: KindCertificate, Key: CertificateKey(fp), Name: name, Attrs: dropEmpty(attrs)}
}

// importedKeyAlgorithm names a key algorithm from its algorithm component, by OID first and
// otherwise by the family the document states (1.7) or the leading word of its name.
func importedKeyAlgorithm(a cdx.Component) (alg, curve string) {
	oid, family := "", ""
	if a.CryptoProperties != nil {
		oid = a.CryptoProperties.OID
		if ap := a.CryptoProperties.AlgorithmProperties; ap != nil {
			family = ap.AlgorithmFamily
			curve = ap.EllipticCurve
			if curve == "" {
				curve = ap.Curve
			}
		}
	}
	switch oid {
	case "1.2.840.113549.1.1.1":
		alg = "RSA"
	case "1.2.840.10045.2.1":
		alg = "ECDSA"
	case "1.3.101.112":
		alg = "Ed25519"
	case "1.2.840.10040.4.1":
		alg = "DSA"
	}
	if alg == "" && family != "" {
		alg = family
	}
	if alg == "" {
		if f := strings.FieldsFunc(a.Name, func(r rune) bool { return r == '-' || r == ' ' || r == '_' }); len(f) > 0 {
			alg = f[0]
		}
	}
	return clean(alg, 64), clean(curve, 64)
}

func importedProtocol(c cdx.Component) (string, bool) {
	pp := c.CryptoProperties.ProtocolProperties
	if pp == nil || strings.ToLower(string(pp.Type)) != "tls" {
		return "", false
	}
	v := strings.TrimSpace(pp.Version)
	switch v {
	case "1.0", "1.1", "1.2", "1.3":
		return "TLSv" + v, true
	case "3.0":
		return "SSLv3", true
	case "2.0":
		return "SSLv2", true
	}
	return "", false
}

// suiteID reads a cipher suite's IANA code point from the two identifier bytes ("0x13", "0x01").
func suiteID(cs cdx.CipherSuite) (uint16, bool) {
	if cs.Identifiers == nil || len(*cs.Identifiers) != 2 {
		return 0, false
	}
	var v uint16
	for _, s := range *cs.Identifiers {
		s = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(s)), "0x")
		if len(s) == 0 || len(s) > 2 {
			return 0, false
		}
		b, err := hex.DecodeString(strings.Repeat("0", 2-len(s)) + s)
		if err != nil {
			return 0, false
		}
		v = v<<8 | uint16(b[0])
	}
	return v, true
}

func occurrences(c cdx.Component) []string {
	if c.Evidence == nil || c.Evidence.Occurrences == nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, o := range *c.Evidence.Occurrences {
		if len(out) >= maxOccurrencesPerComponent {
			break
		}
		if o.Location == "" || !evidence.SafeText(o.Location, MaxAttrLen) || seen[o.Location] {
			continue
		}
		seen[o.Location] = true
		out = append(out, o.Location)
	}
	return out
}

// parseTime accepts an RFC 3339 time and returns it in the one format the graph stores.
func parseTime(s string) (string, bool) {
	t, err := time.Parse(time.RFC3339, strings.TrimSpace(s))
	if err != nil {
		return "", false
	}
	return t.UTC().Format("2006-01-02T15:04:05Z"), true
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [12]byte
	i := len(b)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

// SHA256Hex is the hex SHA-256 of b, exported for callers that record document identity.
func SHA256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
