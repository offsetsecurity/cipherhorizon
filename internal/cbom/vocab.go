package cbom

import (
	"fmt"
	"regexp"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

// The closed CycloneDX 1.6 vocabularies for algorithm assets.
//
// CycloneDX enumerations are closed: one out-of-vocabulary value makes the
// whole document schema-invalid. These sets are the last line of defence for
// values a plugin sets by hand. vocab_test.go pins every one of them to the
// enumerations in the vendored bom-1.6.schema.json, so they cannot drift.
var (
	assetTypes = setOf(cdx.CryptoAssetTypeAlgorithm)

	primitives = setOf(
		cdx.CryptoPrimitiveDRBG, cdx.CryptoPrimitiveMAC, cdx.CryptoPrimitiveBlockCipher,
		cdx.CryptoPrimitiveStreamCipher, cdx.CryptoPrimitiveSignature, cdx.CryptoPrimitiveHash,
		cdx.CryptoPrimitivePKE, cdx.CryptoPrimitiveXOF, cdx.CryptoPrimitiveKDF,
		cdx.CryptoPrimitiveKeyAgree, cdx.CryptoPrimitiveKEM, cdx.CryptoPrimitiveAE,
		cdx.CryptoPrimitiveCombiner, cdx.CryptoPrimitiveOther, cdx.CryptoPrimitiveUnknown,
	) // note: "key-wrap" is 1.7-only

	functions = setOf(
		cdx.CryptoFunctionGenerate, cdx.CryptoFunctionKeygen, cdx.CryptoFunctionEncrypt,
		cdx.CryptoFunctionDecrypt, cdx.CryptoFunctionDigest, cdx.CryptoFunctionTag,
		cdx.CryptoFunctionKeyderive, cdx.CryptoFunctionSign, cdx.CryptoFunctionVerify,
		cdx.CryptoFunctionEncapsulate, cdx.CryptoFunctionDecapsulate, cdx.CryptoFunctionOther,
		cdx.CryptoFunctionUnknown,
	)

	modes = setOf(
		cdx.CryptoAlgorithmMode("cbc"), "ecb", "ccm", "gcm", "cfb", "ofb", "ctr", "other", "unknown",
	)

	paddings = setOf(
		cdx.CryptoPadding("pkcs5"), "pkcs7", "pkcs1v15", "oaep", "raw", "other", "unknown",
	)

	execEnvironments = setOf(
		cdx.CryptoExecutionEnvironment("software-plain-ram"), "software-encrypted-ram",
		"software-tee", "hardware", "other", "unknown",
	)

	platforms = setOf(
		cdx.ImplementationPlatform("generic"), "x86_32", "x86_64", "armv7-a", "armv7-m", "armv8-a",
		"armv8-m", "armv9-a", "armv9-m", "s390x", "ppc64", "ppc64le", "other", "unknown",
	)

	certLevels = setOf(
		cdx.CryptoCertificationLevel("none"),
		"fips140-1-l1", "fips140-1-l2", "fips140-1-l3", "fips140-1-l4",
		"fips140-2-l1", "fips140-2-l2", "fips140-2-l3", "fips140-2-l4",
		"fips140-3-l1", "fips140-3-l2", "fips140-3-l3", "fips140-3-l4",
		"cc-eal1", "cc-eal1+", "cc-eal2", "cc-eal2+", "cc-eal3", "cc-eal3+", "cc-eal4", "cc-eal4+",
		"cc-eal5", "cc-eal5+", "cc-eal6", "cc-eal6+", "cc-eal7", "cc-eal7+", "other", "unknown",
	)
)

func setOf[T comparable](vs ...T) map[T]struct{} {
	m := make(map[T]struct{}, len(vs))
	for _, v := range vs {
		m[v] = struct{}{}
	}
	return m
}

func has[T comparable](set map[T]struct{}, v T) bool {
	_, ok := set[v]
	return ok
}

var oidRE = regexp.MustCompile(`^[0-2](\.(0|[1-9][0-9]*))+$`)

// sanitize enforces the vocabularies on c in place. Anything out of vocabulary
// is OMITTED, never passed through or "corrected"; each omission is reported.
// It returns human-readable warnings.
func sanitize(c *cdx.Component) []string {
	cp := c.CryptoProperties
	if cp == nil {
		return nil
	}
	warn := func(format string, args ...any) string {
		return fmt.Sprintf("%s: %s", c.BOMRef, fmt.Sprintf(format, args...))
	}

	// Only algorithm assets have vocabulary tables so far. Fail closed rather than
	// let unchecked certificate/protocol/key-material values through.
	if !has(assetTypes, cp.AssetType) {
		c.CryptoProperties = nil
		return []string{warn("crypto assetType %q is not supported yet; cryptoProperties omitted", cp.AssetType)}
	}

	var w []string
	if cp.OID != "" && !oidRE.MatchString(cp.OID) {
		w = append(w, warn("malformed OID %q omitted", cp.OID))
		cp.OID = ""
	}
	ap := cp.AlgorithmProperties
	if ap == nil {
		return w
	}
	if ap.Primitive != "" && !has(primitives, ap.Primitive) {
		w = append(w, warn("primitive %q is not in CycloneDX 1.6; omitted", ap.Primitive))
		ap.Primitive = ""
	}
	if ap.Mode != "" && !has(modes, ap.Mode) {
		w = append(w, warn("mode %q is not in CycloneDX 1.6; omitted", ap.Mode))
		ap.Mode = ""
	}
	if ap.Padding != "" && !has(paddings, ap.Padding) {
		w = append(w, warn("padding %q is not in CycloneDX 1.6; omitted", ap.Padding))
		ap.Padding = ""
	}
	if ap.ExecutionEnvironment != "" && !has(execEnvironments, ap.ExecutionEnvironment) {
		w = append(w, warn("executionEnvironment %q is not in CycloneDX 1.6; omitted", ap.ExecutionEnvironment))
		ap.ExecutionEnvironment = ""
	}
	if ap.ImplementationPlatform != "" && !has(platforms, ap.ImplementationPlatform) {
		w = append(w, warn("implementationPlatform %q is not in CycloneDX 1.6; omitted", ap.ImplementationPlatform))
		ap.ImplementationPlatform = ""
	}
	if ap.CertificationLevel != nil {
		var keep []cdx.CryptoCertificationLevel
		for _, l := range *ap.CertificationLevel {
			if has(certLevels, l) {
				keep = append(keep, l)
			} else {
				w = append(w, warn("certificationLevel %q is not in CycloneDX 1.6; omitted", l))
			}
		}
		ap.CertificationLevel = ptrOrNil(keep)
	}
	if ap.CryptoFunctions != nil {
		var keep []cdx.CryptoFunction
		for _, f := range *ap.CryptoFunctions {
			if has(functions, f) {
				keep = append(keep, f)
			} else {
				w = append(w, warn("cryptoFunction %q is not in CycloneDX 1.6; omitted", f))
			}
		}
		ap.CryptoFunctions = ptrOrNil(keep)
	}
	if ap.NistQuantumSecurityLevel != nil && (*ap.NistQuantumSecurityLevel < 0 || *ap.NistQuantumSecurityLevel > 6) {
		w = append(w, warn("nistQuantumSecurityLevel %d outside 0..6; omitted", *ap.NistQuantumSecurityLevel))
		ap.NistQuantumSecurityLevel = nil
	}

	// algorithmFamily and ellipticCurve are 1.7 registry fields with closed
	// vocabularies. No authoritative lookup table backs them yet, so they are
	// never emitted, whatever a plugin set.
	if ap.AlgorithmFamily != "" {
		w = append(w, warn("algorithmFamily %q omitted: 1.7 registry field with no lookup table yet", ap.AlgorithmFamily))
		ap.AlgorithmFamily = ""
	}
	if ap.EllipticCurve != "" {
		w = append(w, warn("ellipticCurve %q omitted: 1.7 registry field with no lookup table yet", ap.EllipticCurve))
		ap.EllipticCurve = ""
	}
	return w
}

func ptrOrNil[T any](s []T) *[]T {
	if len(s) == 0 {
		return nil
	}
	return &s
}
