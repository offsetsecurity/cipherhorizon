package estate

import (
	"strconv"
	"strings"

	"github.com/example/cipherhorizon/internal/evidence"
	"github.com/example/cipherhorizon/internal/tlsprobe"
)

// FromScanReport projects one TLS scan report into observations. Every fact in a
// report was read from a server's own reply, so each is network-stream evidence at
// the "exercised" rung (E3): the server did this in front of us. Anything the
// report marks unsupported, refused or inconclusive produces no observation, and an
// incomplete report says so through its source, not by inventing absences.
//
// Nothing is dropped that the report carries: protocols, suites, groups, and
// every presented certificate are all here, so the graph can answer what the report
// could (REQ-MOD-3).
func FromScanReport(rep *tlsprobe.Report) []Observation {
	if rep == nil {
		return nil
	}
	var out []Observation

	for _, p := range rep.Protocols {
		if !p.Supported {
			continue
		}
		out = append(out, Observation{
			Entity:   Entity{Kind: KindProtocol, Key: ProtocolKey(p.Version), Name: clean(p.Version, MaxNameLen), Attrs: map[string]string{"version": clean(p.Version, 32)}},
			Relation: RelOffers,
			Rung:     evidence.RungExercised, Class: evidence.E3Exercised,
			Method: MethodTLSServerHello, Quality: QualityAuthoritative,
		})
	}

	for _, s := range rep.Suites {
		attrs := map[string]string{
			"version": clean(s.Version, 32), "kx": clean(s.Kx, 64), "auth": clean(s.Auth, 64),
			"cipher": clean(s.Cipher, 64), "mac": clean(s.MAC, 64), "aead": strconv.FormatBool(s.AEAD),
			"ianaRecommended": clean(s.IANARecommended, 16),
		}
		out = append(out, Observation{
			Entity:   Entity{Kind: KindSuite, Key: SuiteKey(s.ID), Name: clean(s.Name, MaxNameLen), Attrs: dropEmpty(attrs)},
			Relation: RelOffers,
			Rung:     evidence.RungExercised, Class: evidence.E3Exercised,
			Method: MethodTLSServerHello, Quality: QualityAuthoritative,
			Attrs: dropEmpty(map[string]string{"version": clean(s.Version, 32), "rank": rankText(s.Rank)}),
		})
	}

	for _, g := range rep.Groups {
		attrs := map[string]string{
			"version": clean(g.Version, 32), "pq": strconv.FormatBool(g.PQ), "hybrid": strconv.FormatBool(g.Hybrid),
			"obsolete": strconv.FormatBool(g.Obsolete), "ianaRecommended": clean(g.IANARecommended, 16),
		}
		method := MethodTLSServerHello
		if g.Version == "TLSv1.3" {
			method = MethodTLSRetry
		}
		out = append(out, Observation{
			Entity:   Entity{Kind: KindGroup, Key: GroupKey(g.ID), Name: clean(g.Name, MaxNameLen), Attrs: dropEmpty(attrs)},
			Relation: RelOffers,
			Rung:     evidence.RungExercised, Class: evidence.E3Exercised,
			Method: method, Quality: QualityAuthoritative,
			Attrs: dropEmpty(map[string]string{"version": clean(g.Version, 32), "rank": rankText(g.Rank)}),
		})
	}

	if n := rep.Negotiated; n != nil && n.Error == "" {
		if n.Suite != "" {
			out = append(out, Observation{
				Entity:   Entity{Kind: KindSuite, Key: SuiteKey(n.SuiteID), Name: clean(n.Suite, MaxNameLen)},
				Relation: RelNegotiates,
				Rung:     evidence.RungExercised, Class: evidence.E3Exercised,
				Method: MethodTLSServerHello, Quality: QualityAuthoritative,
				Attrs: dropEmpty(map[string]string{"version": clean(n.Version, 32)}),
			})
		}
		if n.Group != "" {
			out = append(out, Observation{
				Entity:   Entity{Kind: KindGroup, Key: GroupKey(n.GroupID), Name: clean(n.Group, MaxNameLen), Attrs: map[string]string{"pq": strconv.FormatBool(n.PQ)}},
				Relation: RelNegotiates,
				Rung:     evidence.RungExercised, Class: evidence.E3Exercised,
				Method: MethodTLSServerHello, Quality: QualityAuthoritative,
				Attrs: dropEmpty(map[string]string{"version": clean(n.Version, 32)}),
			})
		}
	}

	seen := map[string]bool{}
	for _, cr := range rep.Certificates {
		for i, c := range cr.Chain {
			if c.SHA256 == "" {
				continue // a certificate that could not be parsed has no identity to key on
			}
			position := "chain"
			if i == 0 {
				position = "leaf"
			}
			// The same certificate is presented on several probe paths (default, RSA-only,
			// ECDSA-only): one observation each would be noise, so one per certificate and
			// position, with the leaf position winning.
			id := c.SHA256 + "/" + position
			if seen[id] {
				continue
			}
			seen[id] = true
			out = append(out, Observation{
				Entity:   CertificateEntity(c),
				Relation: RelPresents,
				Rung:     evidence.RungExercised, Class: evidence.E3Exercised,
				Method: MethodTLSCertificate, Quality: QualityAuthoritative,
				Attrs: map[string]string{"position": position},
			})
		}
	}
	return out
}

// CertificateEntity builds the certificate entity for a parsed certificate. Subject,
// issuer and names are display strings from the certificate and are attacker
// controlled: they are cleaned and length-capped here and escaped again on render.
func CertificateEntity(c tlsprobe.CertInfo) Entity {
	attrs := map[string]string{
		"fingerprint": strings.ToLower(c.SHA256),
		"serial":      clean(c.SerialHex, 128),
		"subject":     clean(c.Subject, MaxAttrLen),
		"issuer":      clean(c.Issuer, MaxAttrLen),
		"notBefore":   c.NotBefore.UTC().Format("2006-01-02T15:04:05Z"),
		"notAfter":    c.NotAfter.UTC().Format("2006-01-02T15:04:05Z"),
		"keyAlg":      clean(c.PublicKey.Algorithm, 64),
		"curve":       clean(c.PublicKey.Curve, 64),
		"sigAlg":      clean(c.SignatureAlg.Name, 64),
		"isCA":        strconv.FormatBool(c.IsCA),
		"selfSigned":  strconv.FormatBool(c.SelfSigned),
	}
	if c.PublicKey.Bits > 0 {
		attrs["keyBits"] = strconv.Itoa(c.PublicKey.Bits)
	}
	if names := append(append([]string{}, c.DNSNames...), c.IPAddresses...); len(names) > 0 {
		attrs["dnsNames"] = clean(strings.Join(names, ","), MaxAttrLen)
	}
	name := clean(c.Subject, MaxNameLen)
	if name == "" {
		name = c.SHA256
	}
	return Entity{Kind: KindCertificate, Key: CertificateKey(c.SHA256), Name: name, Attrs: dropEmpty(attrs)}
}

func rankText(r int) string {
	if r <= 0 {
		return ""
	}
	return strconv.Itoa(r)
}

func dropEmpty(m map[string]string) map[string]string {
	for k, v := range m {
		if v == "" {
			delete(m, k)
		}
	}
	if len(m) == 0 {
		return nil
	}
	return m
}
