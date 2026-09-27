package cbom_test

import (
	"bytes"
	"strings"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/example/cipherhorizon/internal/algo"
	"github.com/example/cipherhorizon/internal/cbom"
	"github.com/example/cipherhorizon/internal/cdxschema"
	"github.com/example/cipherhorizon/internal/collector"
)

func has(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// REQ-EXP-2: every catalogue entry has a registry family or a stated reason it has none, every
// family and curve the tables name exists in the registry, and every gap is listed.
func TestRegistryMappingIsCompleteAndValid(t *testing.T) {
	families, curves := cdxschema.Families(), cdxschema.Curves()
	if len(families) < 90 || len(curves) < 240 {
		t.Fatalf("registry read as %d families and %d curves; want 93 and 246", len(families), len(curves))
	}
	mapped, gaps := 0, 0
	for _, a := range algo.All() {
		fam, ok := cbom.FamilyFor(a.ID)
		gap, isGap := cbom.Registry17Gaps()[a.ID]
		switch {
		case ok:
			mapped++
			if !has(families, fam) {
				t.Errorf("%s maps to family %q, which is not in the registry", a.ID, fam)
			}
			if isGap {
				t.Errorf("%s is both mapped and listed as a gap", a.ID)
			}
		case isGap:
			gaps++
			if len(gap) < 20 {
				t.Errorf("%s: the reason for having no family is missing", a.ID)
			}
		default:
			t.Errorf("catalogue entry %s is neither mapped to a registry family nor listed as a gap", a.ID)
		}
	}
	if mapped == 0 || gaps == 0 {
		t.Errorf("%d mapped and %d gaps: the check proves nothing", mapped, gaps)
	}
	// The derived, size- and curve-qualified names.
	for _, n := range []string{"RSA-2048", "ECDSA-P256", "DSA-2048", "SLH-DSA-SHA2-128s"} {
		fam, ok := cbom.FamilyFor(n)
		if n == "RSA-2048" && ok {
			t.Errorf("RSA-2048 was given family %q; the registry has no plain RSA", fam)
		}
		if ok && !has(families, fam) {
			t.Errorf("%s -> %q not in the registry", n, fam)
		}
	}
	if _, ok := cbom.FamilyFor("NOT-AN-ALGORITHM"); ok {
		t.Error("an unknown algorithm was given a family")
	}
}

// A minimal 1.6-shaped BOM with every construct 1.7 changes.
func oldStyleBOM() *cdx.BOM {
	comps := []cdx.Component{
		{BOMRef: "alg-ecdsa", Type: cdx.ComponentTypeCryptographicAsset, Name: "ECDSA-P256", CryptoProperties: &cdx.CryptoProperties{
			AssetType: cdx.CryptoAssetTypeAlgorithm, AlgorithmProperties: &cdx.CryptoAlgorithmProperties{Primitive: cdx.CryptoPrimitiveSignature, Curve: "secp256r1"}}},
		{BOMRef: "alg-aes", Type: cdx.ComponentTypeCryptographicAsset, Name: "AES-128-GCM", CryptoProperties: &cdx.CryptoProperties{
			AssetType: cdx.CryptoAssetTypeAlgorithm, AlgorithmProperties: &cdx.CryptoAlgorithmProperties{Primitive: cdx.CryptoPrimitiveAE, ParameterSetIdentifier: "128"}}},
		{BOMRef: "alg-rsa", Type: cdx.ComponentTypeCryptographicAsset, Name: "RSA-2048", CryptoProperties: &cdx.CryptoProperties{
			AssetType: cdx.CryptoAssetTypeAlgorithm, AlgorithmProperties: &cdx.CryptoAlgorithmProperties{Primitive: cdx.CryptoPrimitivePKE}}},
		{BOMRef: "alg-odd", Type: cdx.ComponentTypeCryptographicAsset, Name: "ECDSA-odd", CryptoProperties: &cdx.CryptoProperties{
			AssetType: cdx.CryptoAssetTypeAlgorithm, AlgorithmProperties: &cdx.CryptoAlgorithmProperties{Primitive: cdx.CryptoPrimitiveSignature, Curve: "some-curve-the-registry-lacks"}}},
		{BOMRef: "key", Type: cdx.ComponentTypeCryptographicAsset, Name: "k", CryptoProperties: &cdx.CryptoProperties{
			AssetType: cdx.CryptoAssetTypeRelatedCryptoMaterial, RelatedCryptoMaterialProperties: &cdx.RelatedCryptoMaterialProperties{
				Type: cdx.RelatedCryptoMaterialTypePublicKey, AlgorithmRef: "alg-rsa", Size: intp(2048)}}},
		{BOMRef: "cert", Type: cdx.ComponentTypeCryptographicAsset, Name: "c", CryptoProperties: &cdx.CryptoProperties{
			AssetType: cdx.CryptoAssetTypeCertificate, CertificateProperties: &cdx.CertificateProperties{
				SubjectName: "CN=x", SignatureAlgorithmRef: "alg-ecdsa", SubjectPublicKeyRef: "key"}}},
	}
	return &cdx.BOM{BOMFormat: "CycloneDX", Version: 1, Components: &comps}
}

func intp(n int) *int { return &n }

func TestOneDotSevenReplacesDeprecatedConstructsAndDoesNotEmitBoth(t *testing.T) {
	old := oldStyleBOM()
	got := cbom.To17(old)
	byRef := map[string]cdx.Component{}
	for _, c := range *got.Components {
		byRef[c.BOMRef] = c
	}
	ecdsa := byRef["alg-ecdsa"].CryptoProperties.AlgorithmProperties
	if ecdsa.EllipticCurve != "secg/secp256r1" || ecdsa.Curve != "" || ecdsa.AlgorithmFamily != "ECDSA" {
		t.Errorf("ECDSA = %+v: curve should move to the registry name and the family be set", ecdsa)
	}
	if aes := byRef["alg-aes"].CryptoProperties.AlgorithmProperties; aes.AlgorithmFamily != "AES" {
		t.Errorf("AES family = %q", aes.AlgorithmFamily)
	}
	if rsa := byRef["alg-rsa"].CryptoProperties.AlgorithmProperties; rsa.AlgorithmFamily != "" {
		t.Errorf("RSA-2048 got family %q: the registry has none, and none is invented", rsa.AlgorithmFamily)
	}
	odd := byRef["alg-odd"].CryptoProperties.AlgorithmProperties
	if odd.Curve != "some-curve-the-registry-lacks" || odd.EllipticCurve != "" {
		t.Errorf("a curve the registry lacks must keep the older field and invent nothing: %+v", odd)
	}
	cert := byRef["cert"].CryptoProperties.CertificateProperties
	if cert.SubjectPublicKeyRef != "" || cert.SignatureAlgorithmRef != "" || cert.RelatedCryptographicAssets == nil || len(*cert.RelatedCryptographicAssets) != 2 {
		t.Errorf("certificate = %+v", cert)
	}
	rel := *cert.RelatedCryptographicAssets
	if rel[0].Type != "publicKey" || rel[0].Ref != "key" || rel[1].Type != "algorithm" || rel[1].Ref != "alg-ecdsa" {
		t.Errorf("related assets = %+v", rel)
	}
	key := byRef["key"].CryptoProperties.RelatedCryptoMaterialProperties
	if key.AlgorithmRef != "" || key.RelatedCryptographicAssets == nil || (*key.RelatedCryptographicAssets)[0].Ref != "alg-rsa" || *key.Size != 2048 {
		t.Errorf("key = %+v", key)
	}
	// The input is untouched.
	if old.Components == nil || (*old.Components)[0].CryptoProperties.AlgorithmProperties.Curve != "secp256r1" {
		t.Error("To17 changed its input")
	}
}

func TestEncodedOneDotSevenValidatesAgainstTheOneDotSevenSchemaAndOneDotSixStillAgainstOneDotSix(t *testing.T) {
	var b17, b16 bytes.Buffer
	if err := cbom.EncodeSpec(&b17, oldStyleBOM(), cbom.Spec17, true); err != nil {
		t.Fatal(err)
	}
	if err := cbom.EncodeSpec(&b16, oldStyleBOM(), cbom.Spec16, true); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b17.String(), `"specVersion": "1.7"`) || !strings.Contains(b17.String(), "bom-1.7.schema.json") || strings.Contains(b17.String(), `"subjectPublicKeyRef"`) {
		t.Errorf("1.7 output:\n%s", b17.String())
	}
	if p, err := cdxschema.Validate(b17.Bytes(), "1.7", 5); err != nil || len(p) != 0 {
		t.Errorf("1.7 output is not valid 1.7: %v %v", p, err)
	}
	if p, err := cdxschema.Validate(b16.Bytes(), "1.6", 5); err != nil || len(p) != 0 {
		t.Errorf("1.6 output is not valid 1.6: %v %v", p, err)
	}
	// Negative control: a 1.7-only field is rejected by the 1.6 schema, and a bad family by the 1.7 one.
	if p, _ := cdxschema.Validate(b17.Bytes(), "1.6", 5); len(p) == 0 {
		t.Error("a 1.7 document validated as 1.6")
	}
	bad := strings.Replace(b17.String(), `"algorithmFamily": "AES"`, `"algorithmFamily": "NOT-A-FAMILY"`, 1)
	if p, _ := cdxschema.Validate([]byte(bad), "1.7", 5); len(p) == 0 {
		t.Error("an invented algorithm family was accepted by the 1.7 schema")
	}
	// The crypto components survive (the SDK downgrade pass that rewrites them is not used).
	if !strings.Contains(b17.String(), `"type": "cryptographic-asset"`) {
		t.Error("cryptographic assets were lost")
	}
	if err := cbom.EncodeSpec(&bytes.Buffer{}, oldStyleBOM(), "1.5", false); err == nil || !strings.Contains(err.Error(), "1.6 or 1.7") {
		t.Errorf("an unsupported version: %v", err)
	}
	if err := cbom.EncodeSpec(&bytes.Buffer{}, oldStyleBOM(), "1.7\x00\x1b", false); err == nil || strings.ContainsAny(err.Error(), "\x00\x1b") {
		t.Errorf("hostile version text was echoed: %v", err)
	}
	_ = collector.CryptoAsset{}
}
