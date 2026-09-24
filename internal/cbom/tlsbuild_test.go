package cbom_test

import (
	"strings"
	"testing"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/example/cipherhorizon/internal/cbom"
	"github.com/example/cipherhorizon/internal/collector"
	"github.com/example/cipherhorizon/internal/schematest"
	"github.com/example/cipherhorizon/internal/tlsprobe"
)

// A report with one TLS 1.3 hybrid suite/group and one classical TLS 1.2 suite,
// plus a self-signed RSA certificate: enough to exercise every code path.
func sampleReport() *tlsprobe.Report {
	return &tlsprobe.Report{
		SchemaVersion: tlsprobe.SchemaVersion,
		Target:        tlsprobe.Target{Host: "endpoint.example", Port: 443},
		Protocols: []tlsprobe.ProtocolResult{
			{Version: "TLSv1.2", Supported: true, Evidence: tlsprobe.EvidenceServerHello},
			{Version: "TLSv1.3", Supported: true, Evidence: tlsprobe.EvidenceServerHello},
			{Version: "SSLv3", Supported: false, Evidence: tlsprobe.EvidenceAlert},
		},
		Suites: []tlsprobe.SuiteResult{
			{
				Version: "TLSv1.2", ID: 0xC02F, Name: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
				Kx: "ECDHE", Auth: "RSA", Cipher: "AES", KeyBits: 128, Mode: "GCM", MAC: "AEAD", AEAD: true, Ephemeral: true,
				IANARecommended: "Y",
			},
			{
				Version: "TLSv1.3", ID: 0x1301, Name: "TLS_AES_128_GCM_SHA256",
				Cipher: "AES", KeyBits: 128, Mode: "GCM", MAC: "AEAD", AEAD: true, IANARecommended: "Y",
			},
			{
				Version: "TLSv1.3", ID: 0x1303, Name: "TLS_CHACHA20_POLY1305_SHA256",
				Cipher: "CHACHA20", KeyBits: 256, Mode: "POLY1305", MAC: "AEAD", AEAD: true, IANARecommended: "Y",
			},
		},
		Groups: []tlsprobe.GroupResult{
			{Version: "TLSv1.3", ID: 0x11EC, Name: "X25519MLKEM768", PQ: true, Hybrid: true, IANARecommended: "Y"},
			{Version: "TLSv1.3", ID: 513, Name: "MLKEM768", PQ: true, IANARecommended: "N"},
			{Version: "TLSv1.3", ID: 29, Name: "x25519", IANARecommended: "Y"},
			{Version: "TLSv1.2", ID: 23, Name: "secp256r1", IANARecommended: "Y"}, // no catalogue entry: expect no ref
		},
		Certificates: []tlsprobe.CertResult{{
			Source: "tls-default",
			Chain: []tlsprobe.CertInfo{{
				Subject: "CN=endpoint.example", Issuer: "CN=endpoint.example",
				SerialHex: "01A2B3", NotBefore: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
				NotAfter:     time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
				SHA256:       "deadbeef00112233445566778899aabbccddeeff00112233445566778899aa",
				PublicKey:    tlsprobe.KeyInfo{Algorithm: "RSA", Bits: 2048},
				SignatureAlg: tlsprobe.AlgInfo{Name: "SHA256-RSA"},
			}},
			Trusted: true, NameMatches: true,
		}},
	}
}

func findComponent(assets []collector.CryptoAsset, ref string) *collector.CryptoAsset {
	for i := range assets {
		if assets[i].Component.BOMRef == ref {
			return &assets[i]
		}
	}
	return nil
}

// property returns a component's property value, and whether it has one at all.
func property(c *collector.CryptoAsset, name string) (string, bool) {
	if c == nil || c.Component.Properties == nil {
		return "", false
	}
	for _, p := range *c.Component.Properties {
		if p.Name == cbom.PropertyNamespace+":"+name {
			return p.Value, true
		}
	}
	return "", false
}

// anyComponentHasProperty reports whether any component in assets carries the
// named property, and which bom-ref if so — used to assert a property landed
// on exactly the expected component and nowhere else.
func componentsWithProperty(assets []collector.CryptoAsset, name string) []string {
	var refs []string
	for _, a := range assets {
		if _, ok := property(&a, name); ok {
			refs = append(refs, a.Component.BOMRef)
		}
	}
	return refs
}

func TestFromTLSReportBuildsProtocolsSuitesAndGroups(t *testing.T) {
	assets := cbom.FromTLSReport(sampleReport())

	tls13 := findComponent(assets, "protocol/tls/1.3")
	if tls13 == nil {
		t.Fatal("no TLSv1.3 protocol component")
	}
	pp := tls13.Component.CryptoProperties.ProtocolProperties
	if pp.Type != cdx.CryptoProtocolTypeTLS || pp.Version != "1.3" {
		t.Errorf("protocol properties = %+v", pp)
	}
	if pp.CipherSuites == nil || len(*pp.CipherSuites) != 2 {
		t.Fatalf("cipher suites = %+v", pp.CipherSuites)
	}
	for _, cs := range *pp.CipherSuites {
		if cs.Algorithms == nil || len(*cs.Algorithms) == 0 {
			t.Errorf("suite %s has no algorithm references", cs.Name)
		}
	}

	// Protocol not offered at all (SSLv3) gets no component.
	if findComponent(assets, "protocol/tls/3.0") != nil {
		t.Error("an unsupported protocol got a component")
	}

	// The hybrid group is its own Combiner-primitive component and is a dependency
	// of the TLS 1.3 protocol.
	hybrid := findComponent(assets, "crypto/algorithm/x25519mlkem768")
	if hybrid == nil {
		t.Fatal("no component for the hybrid group")
	}
	if hybrid.Component.CryptoProperties.AlgorithmProperties.Primitive != cdx.CryptoPrimitiveCombiner {
		t.Errorf("hybrid primitive = %q, want combiner", hybrid.Component.CryptoProperties.AlgorithmProperties.Primitive)
	}
	if !containsRef(tls13.DependsOn, "crypto/algorithm/x25519mlkem768") {
		t.Errorf("TLSv1.3 protocol does not depend on the hybrid group: %v", tls13.DependsOn)
	}
	if !containsRef(tls13.DependsOn, "crypto/algorithm/ml-kem-768@2.16.840.1.101.3.4.4.2") {
		t.Errorf("TLSv1.3 protocol does not depend on the pure ML-KEM group: %v", tls13.DependsOn)
	}
	if !containsRef(tls13.DependsOn, "crypto/algorithm/x25519@1.3.101.110") {
		t.Errorf("TLSv1.3 protocol does not depend on x25519: %v", tls13.DependsOn)
	}

	// secp256r1 has no catalogue entry: it must not silently invent one.
	if findComponent(assets, "crypto/algorithm/secp256r1") != nil {
		t.Error("secp256r1 got a component from nowhere")
	}
}

func TestFromTLSReportBuildsCertificates(t *testing.T) {
	assets := cbom.FromTLSReport(sampleReport())
	cert := findComponent(assets, "crypto/certificate/deadbeef00112233445566778899aabbccddeeff00112233445566778899aa")
	if cert == nil {
		t.Fatal("no certificate component")
	}
	cp := cert.Component.CryptoProperties.CertificateProperties
	if cp.SubjectName != "CN=endpoint.example" || cp.CertificateFormat != "X.509" {
		t.Errorf("certificate properties = %+v", cp)
	}
	// The certificate points at its public key (an asset of its own), not at an
	// algorithm; the key states its size and points at RSA-2048, not "RSA".
	const keyRef = "crypto/key/public/deadbeef00112233445566778899aabbccddeeff00112233445566778899aa"
	if string(cp.SubjectPublicKeyRef) != keyRef {
		t.Errorf("subjectPublicKeyRef = %q, want the public-key component", cp.SubjectPublicKeyRef)
	}
	key := findComponent(assets, keyRef)
	if key == nil {
		t.Fatal("no public-key component")
	}
	kp := key.Component.CryptoProperties
	if kp.AssetType != cdx.CryptoAssetTypeRelatedCryptoMaterial || kp.RelatedCryptoMaterialProperties.Type != cdx.RelatedCryptoMaterialTypePublicKey {
		t.Errorf("key properties = %+v", kp)
	}
	if sz := kp.RelatedCryptoMaterialProperties.Size; sz == nil || *sz != 2048 {
		t.Errorf("key size = %v, want 2048", sz)
	}
	const rsa2048 = "crypto/algorithm/rsa-2048@1.2.840.113549.1.1.1"
	if string(kp.RelatedCryptoMaterialProperties.AlgorithmRef) != rsa2048 {
		t.Errorf("key algorithmRef = %q, want %q", kp.RelatedCryptoMaterialProperties.AlgorithmRef, rsa2048)
	}
	alg := findComponent(assets, rsa2048)
	if alg == nil || alg.Component.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier != "2048" {
		t.Errorf("no RSA-2048 algorithm component with its parameter set: %+v", alg)
	}
	if v, _ := property(cert, "chain-role"); v != "leaf" {
		t.Errorf("chain-role = %q, want leaf", v)
	}
	if cp.SignatureAlgorithmRef != "crypto/algorithm/rsa@1.2.840.113549.1.1.1" {
		t.Errorf("signatureAlgorithmRef = %q", cp.SignatureAlgorithmRef)
	}
	if cp.NotValidBefore == "" || cp.NotValidAfter == "" {
		t.Error("validity dates missing")
	}
	var serial string
	if cert.Component.Properties != nil {
		for _, p := range *cert.Component.Properties {
			if p.Name == cbom.PropertyNamespace+":cert-serial" {
				serial = p.Value
			}
		}
	}
	if serial != "01A2B3" {
		t.Errorf("serial property = %q", serial)
	}
}

// Two scans that presented the same certificate (e.g. via the default and the
// RSA-only probe) must not duplicate it.
func TestFromTLSReportDeduplicatesCertificatesBySHA256(t *testing.T) {
	rep := sampleReport()
	rep.Certificates = append(rep.Certificates, rep.Certificates[0])
	assets := cbom.FromTLSReport(rep)
	n := 0
	for _, a := range assets {
		if a.Component.CryptoProperties.AssetType == cdx.CryptoAssetTypeCertificate {
			n++
		}
	}
	if n != 1 {
		t.Errorf("%d certificate components, want 1", n)
	}
}

func TestFromTLSReportOutputIsSchemaValid(t *testing.T) {
	bom, warnings := cbom.Build(cbom.FromTLSReport(sampleReport()), cbom.Options{
		Tool: cbom.Tool{Name: "cipherhorizon", Version: "test"}, Endpoint: "endpoint.example:443",
		Now:       func() time.Time { return time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC) },
		NewSerial: func() string { return "urn:uuid:00000000-0000-4000-8000-000000000000" },
	})
	if len(warnings) != 0 {
		t.Errorf("unexpected warnings: %v", warnings)
	}
	if bom.Metadata == nil || bom.Metadata.Component == nil || bom.Metadata.Component.Name != "endpoint.example:443" {
		t.Errorf("metadata.component = %+v", bom.Metadata)
	}
	schematest.Validate(t, encode(t, bom))
}

func TestFromTLSReportNilReport(t *testing.T) {
	if got := cbom.FromTLSReport(nil); got != nil {
		t.Errorf("FromTLSReport(nil) = %v, want nil", got)
	}
}

func containsRef(refs []string, want string) bool {
	for _, r := range refs {
		if r == want {
			return true
		}
	}
	return false
}

// ---- feature 1: evidence-aware CBOM ------------------------------------------------------------

// PRD-002 AC-1.1 / AC-1.3: every component this builder emits states, at full
// confidence, how it was observed — and nothing is emitted with any other
// confidence, since this builder never emits an inferred or unobserved fact.
func TestFromTLSReportEveryComponentCarriesObservedEvidence(t *testing.T) {
	for _, a := range cbom.FromTLSReport(sampleReport()) {
		ev := a.Component.Evidence
		if ev == nil || ev.Identity == nil || ev.Identity.Identities == nil || len(*ev.Identity.Identities) != 1 {
			t.Errorf("%s: no single identity-evidence entry: %+v", a.Component.BOMRef, ev)
			continue
		}
		id := (*ev.Identity.Identities)[0]
		if id.Field != cdx.EvidenceIdentityFieldTypeName {
			t.Errorf("%s: evidence field = %q, want name", a.Component.BOMRef, id.Field)
		}
		if id.Confidence == nil || *id.Confidence != 1.0 {
			t.Errorf("%s: confidence = %v, want 1.0 (this builder only ever states what it observed)", a.Component.BOMRef, id.Confidence)
		}
		if id.Methods == nil || len(*id.Methods) != 1 || (*id.Methods)[0].Value == "" {
			t.Errorf("%s: no method describing how this was observed: %+v", a.Component.BOMRef, id.Methods)
		}
	}
}

// AC-1.2: the evidence block, like everything else this builder produces, must
// be valid CycloneDX 1.6 (already exercised end to end by
// TestFromTLSReportOutputIsSchemaValid; this asserts the field specifically
// survives Encode/round-trip so a regression there is caught close to the cause).
func TestFromTLSReportEvidenceSurvivesEncoding(t *testing.T) {
	bom, warnings := cbom.Build(cbom.FromTLSReport(sampleReport()), cbom.Options{Tool: cbom.Tool{Name: "cipherhorizon"}})
	if len(warnings) != 0 {
		t.Fatalf("unexpected warnings: %v", warnings)
	}
	raw := encode(t, bom)
	schematest.Validate(t, raw)
	if !strings.Contains(string(raw), `"confidence": 1`) {
		t.Error("no confidence field made it into the encoded document")
	}
}

// ---- feature 2: capability vs. negotiation -------------------------------------------------

func negotiatedHybridReport() *tlsprobe.Report {
	rep := sampleReport()
	rep.Negotiated = &tlsprobe.Negotiated{
		Version: "TLSv1.3", Suite: "TLS_AES_128_GCM_SHA256", SuiteID: 0x1301,
		Group: "X25519MLKEM768", GroupID: 0x11EC, PQ: true,
	}
	return rep
}

// AC-2.1, AC-2.2: the protocol component states exactly what was negotiated,
// and the negotiated group's own algorithm component is marked.
func TestFromTLSReportMarksNegotiatedSuiteAndGroup(t *testing.T) {
	assets := cbom.FromTLSReport(negotiatedHybridReport())

	proto := findComponent(assets, "protocol/tls/1.3")
	if proto == nil {
		t.Fatal("no TLSv1.3 protocol component")
	}
	if v, ok := property(proto, "negotiated-suite"); !ok || v != "TLS_AES_128_GCM_SHA256" {
		t.Errorf("negotiated-suite = %q, ok=%v", v, ok)
	}
	if v, ok := property(proto, "negotiated-group"); !ok || v != "X25519MLKEM768" {
		t.Errorf("negotiated-group = %q, ok=%v", v, ok)
	}

	hybrid := findComponent(assets, "crypto/algorithm/x25519mlkem768")
	if hybrid == nil {
		t.Fatal("no hybrid group component")
	}
	if v, ok := property(hybrid, "negotiated"); !ok || v != "true" {
		t.Errorf("hybrid group negotiated property = %q, ok=%v", v, ok)
	}
}

// AC-2.4: capability (everything else the enumeration found) must stay
// unmarked. What is flagged negotiated is exactly what the handshake used: the
// group and the specific cipher variant of the negotiated suite. Since the
// cipher is a key-size-and-mode variant (AES-128-GCM), flagging it cannot
// overclaim the way flagging the whole AES family (shared by every AES suite)
// would have; the other variants and groups the server merely accepts stay unflagged.
func TestFromTLSReportDoesNotOverclaimNegotiation(t *testing.T) {
	assets := cbom.FromTLSReport(negotiatedHybridReport())

	got := componentsWithProperty(assets, "negotiated")
	want := []string{"crypto/algorithm/aes-128-gcm@2.16.840.1.101.3.4.1.6", "crypto/algorithm/x25519mlkem768"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("negotiated components = %v, want exactly %v", got, want)
	}
	// Accepted (capability) but not negotiated: must stay unmarked.
	for _, ref := range []string{
		"crypto/algorithm/ml-kem-768@2.16.840.1.101.3.4.4.2", "crypto/algorithm/x25519@1.3.101.110",
		"crypto/algorithm/chacha20-poly1305", "crypto/algorithm/ecdh@1.3.132.1.12",
	} {
		if c := findComponent(assets, ref); c != nil {
			if _, ok := property(c, "negotiated"); ok {
				t.Errorf("%s: capability, not negotiation, must not be marked negotiated", ref)
			}
		}
	}
}

// A TLS 1.2 negotiation also flags the suite's key exchange and authentication
// (TLS 1.3 suites name neither), and only those.
func TestFromTLSReportMarksNegotiatedTLS12Suite(t *testing.T) {
	rep := sampleReport()
	rep.Negotiated = &tlsprobe.Negotiated{Version: "TLSv1.2", Suite: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", SuiteID: 0xC02F}
	assets := cbom.FromTLSReport(rep)
	got := componentsWithProperty(assets, "negotiated")
	want := map[string]bool{
		"crypto/algorithm/aes-128-gcm@2.16.840.1.101.3.4.1.6": true,
		"crypto/algorithm/ecdh@1.3.132.1.12":                  true,
		"crypto/algorithm/rsa@1.2.840.113549.1.1.1":           true,
	}
	if len(got) != len(want) {
		t.Fatalf("negotiated components = %v, want %v", got, want)
	}
	for _, ref := range got {
		if !want[ref] {
			t.Errorf("unexpected negotiated component %s", ref)
		}
	}
}

// AES is never emitted as one undifferentiated "AES": a suite names its key size
// and mode and each variant is its own asset with its own OID.
func TestFromTLSReportDistinguishesAESVariants(t *testing.T) {
	rep := sampleReport()
	rep.Suites = append(rep.Suites,
		tlsprobe.SuiteResult{Version: "TLSv1.3", ID: 0x1302, Name: "TLS_AES_256_GCM_SHA384", Cipher: "AES", KeyBits: 256, Mode: "GCM", AEAD: true},
		tlsprobe.SuiteResult{Version: "TLSv1.2", ID: 0xC014, Name: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA", Kx: "ECDHE", Auth: "RSA", Cipher: "AES", KeyBits: 256, Mode: "CBC"},
	)
	assets := cbom.FromTLSReport(rep)
	for ref, wantParams := range map[string][2]string{
		"crypto/algorithm/aes-128-gcm@2.16.840.1.101.3.4.1.6":  {"128", "gcm"},
		"crypto/algorithm/aes-256-gcm@2.16.840.1.101.3.4.1.46": {"256", "gcm"},
		"crypto/algorithm/aes-256-cbc@2.16.840.1.101.3.4.1.42": {"256", "cbc"},
	} {
		c := findComponent(assets, ref)
		if c == nil {
			t.Errorf("no component %s", ref)
			continue
		}
		ap := c.Component.CryptoProperties.AlgorithmProperties
		if ap.ParameterSetIdentifier != wantParams[0] || string(ap.Mode) != wantParams[1] {
			t.Errorf("%s: parameter set %q mode %q, want %v", ref, ap.ParameterSetIdentifier, ap.Mode, wantParams)
		}
	}
	if findComponent(assets, "crypto/algorithm/aes") != nil {
		t.Error("generic AES emitted although every suite names its key size and mode")
	}
}

// An elliptic-curve key states its curve, and the document still validates.
func TestFromTLSReportECDSAKeyNamesItsCurve(t *testing.T) {
	rep := sampleReport()
	rep.Certificates[0].Chain[0].PublicKey = tlsprobe.KeyInfo{Algorithm: "ECDSA", Curve: "P-256", Bits: 256}
	rep.Certificates[0].Chain[0].SignatureAlg = tlsprobe.AlgInfo{Name: "ECDSA-SHA256"}
	assets := cbom.FromTLSReport(rep)
	alg := findComponent(assets, "crypto/algorithm/ecdsa-p256@1.2.840.10045.2.1")
	if alg == nil {
		t.Fatal("no ECDSA-P256 key algorithm component")
	}
	if c := alg.Component.CryptoProperties.AlgorithmProperties.Curve; c != "secp256r1" {
		t.Errorf("curve = %q, want secp256r1", c)
	}
	bom, warnings := cbom.Build(assets, cbom.Options{Tool: cbom.Tool{Name: "cipherhorizon"}, Endpoint: "endpoint.example:443"})
	if len(warnings) != 0 {
		t.Errorf("warnings: %v", warnings)
	}
	schematest.Validate(t, encode(t, bom))
}

// Where the cryptography is used: the endpoint depends on its protocols and its
// certificates, a certificate on its public key, the key on its algorithm.
func TestBuildLinksEndpointToProtocolsAndCertificates(t *testing.T) {
	bom, _ := cbom.Build(cbom.FromTLSReport(sampleReport()), cbom.Options{Tool: cbom.Tool{Name: "cipherhorizon"}, Endpoint: "endpoint.example:443"})
	edges := map[string][]string{}
	for _, d := range *bom.Dependencies {
		if d.Dependencies != nil {
			edges[d.Ref] = *d.Dependencies
		}
	}
	const cert = "crypto/certificate/deadbeef00112233445566778899aabbccddeeff00112233445566778899aa"
	keyRef := "crypto/key/public/" + strings.TrimPrefix(cert, "crypto/certificate/")
	root := edges["endpoint:endpoint.example:443"]
	if len(root) != 3 || !containsRef(root, "protocol/tls/1.2") || !containsRef(root, "protocol/tls/1.3") || !containsRef(root, cert) {
		t.Errorf("endpoint dependsOn = %v, want both protocols and the certificate only", root)
	}
	if !containsRef(edges[cert], keyRef) {
		t.Errorf("certificate does not depend on its public key: %v", edges[cert])
	}
	if !containsRef(edges[keyRef], "crypto/algorithm/rsa-2048@1.2.840.113549.1.1.1") {
		t.Error("public key does not depend on RSA-2048")
	}
	// The document says what its edges mean.
	if bom.Metadata.Properties == nil || !strings.Contains((*bom.Metadata.Properties)[0].Value, "accepts") {
		t.Errorf("metadata carries no statement of the graph's semantics: %+v", bom.Metadata.Properties)
	}
}

// The catalogue-lookup path (a negotiated group that resolves through the
// static algo catalogue, not hybridComponent) is a separate code path from the
// hybrid one above and had its own bug during development (matching by the
// catalogue ID string instead of resolving it to a bom-ref) — covered directly.
func TestFromTLSReportMarksNegotiatedCatalogueGroup(t *testing.T) {
	rep := sampleReport()
	rep.Negotiated = &tlsprobe.Negotiated{
		Version: "TLSv1.3", Suite: "TLS_AES_128_GCM_SHA256", SuiteID: 0x1301,
		Group: "MLKEM768", GroupID: 513, PQ: true,
	}
	assets := cbom.FromTLSReport(rep)
	mlkem := findComponent(assets, "crypto/algorithm/ml-kem-768@2.16.840.1.101.3.4.4.2")
	if mlkem == nil {
		t.Fatal("no ML-KEM-768 component")
	}
	if v, ok := property(mlkem, "negotiated"); !ok || v != "true" {
		t.Errorf("ML-KEM-768 negotiated property = %q, ok=%v", v, ok)
	}
	// the group, plus the negotiated suite's cipher variant
	if refs := componentsWithProperty(assets, "negotiated"); len(refs) != 2 {
		t.Errorf("want the group and the cipher flagged negotiated, got %v", refs)
	}
}

// AC-2.3: no negotiation result, or a failed one, marks nothing anywhere —
// absence of a negotiation is not an error and must not be asserted as one.
func TestFromTLSReportNoMarkerWhenNegotiationAbsentOrFailed(t *testing.T) {
	for name, mutate := range map[string]func(*tlsprobe.Report){
		"nil":     func(r *tlsprobe.Report) { r.Negotiated = nil },
		"errored": func(r *tlsprobe.Report) { r.Negotiated = &tlsprobe.Negotiated{Error: "connection reset"} },
	} {
		t.Run(name, func(t *testing.T) {
			rep := sampleReport()
			mutate(rep)
			assets := cbom.FromTLSReport(rep)
			for _, prop := range []string{"negotiated", "negotiated-suite", "negotiated-group"} {
				if refs := componentsWithProperty(assets, prop); len(refs) != 0 {
					t.Errorf("%s: %v carry %q, want none", name, refs, prop)
				}
			}
		})
	}
}
