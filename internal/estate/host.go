package estate

import (
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/offsetsecurity/cipherhorizon/internal/evidence"
)

const propPrefix = "cipherhorizon:"

// Uninterpreted counts what a document held that the projection could not turn into
// an observation, by reason. It is what lets a report say "we did not understand N
// components" instead of silently dropping them (REQ-ING-7).
type Uninterpreted map[string]int

// Result is a projection of a CBOM: what was understood and what was not.
type Result struct {
	Observations  []Observation
	Uninterpreted Uninterpreted
	// Accounting for imports: every component of the document is either interpreted (it produced
	// observations or contributed to one, like a public key giving a certificate its size) or
	// counted as not interpreted, so Components == Interpreted + NotInterpreted always holds and
	// nothing is dropped unaccounted (PRD-003 REQ-ING-7, AC-ING-1).
	Components     int
	Interpreted    int
	NotInterpreted int
}

func (u Uninterpreted) add(reason string) { u[reason]++ }

// FromHostCBOM projects a host inventory CBOM into observations on the host
// stream. A CBOM this product made carries the evidence rung, method and method
// quality of every component in `cipherhorizon:*` properties, and those are read
// back exactly. A component without them (an older or third-party document) is
// projected at the weakest honest reading: present, method quality "sampled".
//
// Nothing here can establish more than the document says: a rung the host stream may
// not hold ("exercised") is refused by Validate, and the document's own claims about
// trust play no part.
func FromHostCBOM(bom *cdx.BOM) Result {
	res := Result{Uninterpreted: Uninterpreted{}}
	if bom == nil || bom.Components == nil {
		return res
	}

	// Software keys by bom-ref, so a provides edge can name its provider.
	swKey := map[string]string{}
	var walk func(cs []cdx.Component, fn func(cdx.Component))
	walk = func(cs []cdx.Component, fn func(cdx.Component)) {
		for _, c := range cs {
			fn(c)
			if c.Components != nil {
				walk(*c.Components, fn)
			}
		}
	}

	walk(*bom.Components, func(c cdx.Component) {
		if c.Type == cdx.ComponentTypeCryptographicAsset {
			return
		}
		if c.Name == "" {
			return
		}
		swKey[c.BOMRef] = SoftwareKey(c.PackageURL, c.Name, c.Version)
	})

	// providedBy maps an algorithm bom-ref to the software that provides it.
	providedBy := map[string][]string{}
	if bom.Dependencies != nil {
		for _, d := range *bom.Dependencies {
			if d.Provides == nil {
				continue
			}
			for _, algRef := range *d.Provides {
				if k, ok := swKey[d.Ref]; ok {
					providedBy[algRef] = append(providedBy[algRef], k)
				}
			}
		}
	}

	walk(*bom.Components, func(c cdx.Component) {
		claim, method, quality := readEvidence(c)
		switch {
		case c.Type == cdx.ComponentTypeCryptographicAsset && c.CryptoProperties != nil:
			switch c.CryptoProperties.AssetType {
			case cdx.CryptoAssetTypeAlgorithm:
				key := algorithmKey(c)
				if key == "" {
					res.Uninterpreted.add("algorithm without a name")
					return
				}
				e := Entity{Kind: KindAlgorithm, Key: key, Name: clean(c.Name, MaxNameLen), Attrs: dropEmpty(map[string]string{"oid": clean(c.CryptoProperties.OID, 128)})}
				via := providedBy[c.BOMRef]
				if len(via) == 0 {
					res.add(e, RelCapable, "", evidence.RungCapable, method, quality)
					return
				}
				for _, v := range via {
					res.add(e, RelCapable, v, evidence.RungCapable, method, quality)
				}
			case cdx.CryptoAssetTypeCertificate:
				fp := sha256Of(c)
				if fp == "" {
					res.Uninterpreted.add("certificate without a SHA-256 hash")
					return
				}
				// One observation per place the certificate was found: the same certificate in two
				// files is two sightings, and each says for itself whether a key sits beside it.
				ent := certificateFromComponent(c, fp)
				class := evidence.ClassOf(evidence.Claim{Rung: evidence.RungProvisioned})
				var occ []cdx.EvidenceOccurrence
				if c.Evidence != nil && c.Evidence.Occurrences != nil {
					occ = *c.Evidence.Occurrences
				}
				if len(occ) == 0 {
					res.Observations = append(res.Observations, Observation{Entity: ent, Relation: RelContains, Rung: evidence.RungProvisioned,
						Class: class, Method: method, Quality: quality})
					return
				}
				for _, o := range occ {
					oa := map[string]string{}
					if evidence.SafeText(o.Location, MaxAttrLen) {
						oa["location"] = o.Location
					}
					if v, ok := strings.CutPrefix(o.AdditionalContext, "privateKey="); ok && (v == "yes" || v == "no" || v == "unknown") {
						oa["privateKey"] = v
					}
					res.Observations = append(res.Observations, Observation{Entity: ent, Relation: RelContains, Rung: evidence.RungProvisioned,
						Class: class, Method: method, Quality: quality, Attrs: dropEmpty(oa)})
				}
			default:
				res.Uninterpreted.add("cryptographic asset of type " + string(c.CryptoProperties.AssetType))
			}
		case c.Type == cdx.ComponentTypeCryptographicAsset:
			res.Uninterpreted.add("cryptographic asset without cryptoProperties")
		case c.Name == "":
			res.Uninterpreted.add("component without a name")
		case isProvider(c):
			res.add(Entity{Kind: KindProvider, Key: providerKey(c), Name: clean(c.Name, MaxNameLen), Attrs: dropEmpty(map[string]string{"providerKind": clean(prop(c, "provider-kind"), 64)})},
				RelContains, "", claim, method, quality)
		default:
			attrs := map[string]string{"version": clean(c.Version, 128), "purl": clean(c.PackageURL, MaxAttrLen), "family": clean(prop(c, "package-family"), 64), "kind": string(c.Type), "arch": clean(prop(c, "file-arch"), 32)}
			res.add(Entity{Kind: KindSoftware, Key: SoftwareKey(c.PackageURL, c.Name, c.Version), Name: clean(c.Name, MaxNameLen), Attrs: dropEmpty(attrs)},
				RelContains, "", claim, method, quality)
		}
	})
	return res
}

func (r *Result) add(e Entity, relation, via string, rung evidence.Rung, method, quality string) {
	r.Observations = append(r.Observations, Observation{
		Entity: e, Relation: relation, Via: via, Rung: rung, Class: evidence.ClassOf(evidence.Claim{Rung: rung}),
		Method: method, Quality: quality,
	})
}

// readEvidence reads the rung, method and method quality a CBOM made by this product
// records on each component. Missing or unreadable values fall back to the weakest
// honest reading rather than an assumed strong one.
func readEvidence(c cdx.Component) (rung evidence.Rung, method, quality string) {
	rung, method, quality = evidence.RungPresent, MethodCBOMImport, QualitySampled
	if v := prop(c, "claim"); v != "" {
		switch evidence.Rung(v) {
		case evidence.RungPresent, evidence.RungProvisioned, evidence.RungCapable, evidence.RungPolicy, evidence.RungBound, evidence.RungLoaded:
			rung = evidence.Rung(v)
		}
	}
	if v := prop(c, "method"); v != "" && evidence.SafeText(v, 128) {
		method = v
	}
	switch q := prop(c, "method-quality"); q {
	case QualityAuthoritative, QualityParsed, QualityHeuristic, QualitySampled:
		quality = q
	}
	return rung, method, quality
}

func prop(c cdx.Component, name string) string {
	if c.Properties == nil {
		return ""
	}
	for _, p := range *c.Properties {
		if p.Name == propPrefix+name {
			return strings.TrimSpace(p.Value)
		}
	}
	return ""
}

func isProvider(c cdx.Component) bool {
	return prop(c, "provider-kind") != ""
}

func providerKey(c cdx.Component) string {
	if strings.HasPrefix(c.BOMRef, "provider:") {
		return strings.ToLower(c.BOMRef)
	}
	return evidence.ProviderKey("other", c.Name)
}

func algorithmKey(c cdx.Component) string {
	if strings.HasPrefix(c.BOMRef, "algo:") {
		return c.BOMRef
	}
	if c.Name == "" {
		return ""
	}
	return "algo:" + strings.ToLower(strings.ReplaceAll(strings.TrimSpace(c.Name), " ", "-"))
}

func sha256Of(c cdx.Component) string {
	if c.Hashes == nil {
		return ""
	}
	for _, h := range *c.Hashes {
		if h.Algorithm == cdx.HashAlgoSHA256 && len(h.Value) == 64 && isHex(h.Value) {
			return strings.ToLower(h.Value)
		}
	}
	return ""
}

func isHex(s string) bool {
	for _, r := range s {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') && (r < 'A' || r > 'F') {
			return false
		}
	}
	return true
}

// certificateFromComponent reads a certificate component. Only what the standard
// carries is read: names, validity, key and signature algorithm references. Key size
// is not a field of a CycloneDX 1.6 certificate, so it is left unset here (not
// guessed); the certificate sensor supplies it through its own attributes.
func certificateFromComponent(c cdx.Component, fingerprint string) Entity {
	attrs := map[string]string{"fingerprint": fingerprint}
	if cp := c.CryptoProperties; cp != nil && cp.CertificateProperties != nil {
		p := cp.CertificateProperties
		attrs["subject"] = clean(p.SubjectName, MaxAttrLen)
		attrs["issuer"] = clean(p.IssuerName, MaxAttrLen)
		attrs["notBefore"] = clean(p.NotValidBefore, 40)
		attrs["notAfter"] = clean(p.NotValidAfter, 40)
	}
	for _, p := range []struct {
		prop, attr string
		max        int
	}{{"key-algorithm", "keyAlg", 64}, {"key-bits", "keyBits", 8}, {"curve", "curve", 64}, {"signature-algorithm", "sigAlg", 64},
		{"is-ca", "isCA", 5}, {"self-signed", "selfSigned", 5}, {"serial", "serial", 128}, {"san", "dnsNames", MaxAttrLen}, {"key-usage", "keyUsage", 200}} {
		if v := prop2(c, p.prop); v != "" {
			attrs[p.attr] = clean(v, p.max)
		}
	}
	name := clean(attrs["subject"], MaxNameLen)
	if name == "" {
		name = fingerprint
	}
	return Entity{Kind: KindCertificate, Key: CertificateKey(fingerprint), Name: name, Attrs: dropEmpty(attrs)}
}

// prop2 is prop under the certificate-attribute name space used by the certificate
// sensors: `cipherhorizon:cert:<name>`.
func prop2(c cdx.Component, name string) string { return prop(c, "cert:"+name) }
