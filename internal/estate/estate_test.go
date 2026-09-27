package estate_test

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/example/cipherhorizon/internal/cbom"
	"github.com/example/cipherhorizon/internal/discover"
	"github.com/example/cipherhorizon/internal/estate"
	"github.com/example/cipherhorizon/internal/evidence"
	"github.com/example/cipherhorizon/internal/pqc"
	"github.com/example/cipherhorizon/internal/sense"
	_ "github.com/example/cipherhorizon/internal/sense/all"
	"github.com/example/cipherhorizon/internal/sense/pefiles/pefilestest"
	"github.com/example/cipherhorizon/internal/tlsprobe"
)

func sampleReport() *tlsprobe.Report {
	leaf := tlsprobe.CertInfo{
		Subject: "CN=example.test", Issuer: "CN=Test CA", SerialHex: "01",
		DNSNames: []string{"example.test", "www.example.test"}, SHA256: strings.Repeat("ab", 32),
		NotBefore: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
		PublicKey: tlsprobe.KeyInfo{Algorithm: "RSA", Bits: 2048}, SignatureAlg: tlsprobe.AlgInfo{Name: "SHA256-RSA"},
	}
	ca := tlsprobe.CertInfo{Subject: "CN=Test CA", Issuer: "CN=Test CA", SHA256: strings.Repeat("cd", 32), IsCA: true, SelfSigned: true, PublicKey: tlsprobe.KeyInfo{Algorithm: "RSA", Bits: 4096}}
	return &tlsprobe.Report{
		SchemaVersion: tlsprobe.SchemaVersion,
		Protocols: []tlsprobe.ProtocolResult{
			{Version: "TLSv1.2", Supported: true}, {Version: "TLSv1.3", Supported: true}, {Version: "SSLv3", Supported: false},
		},
		Suites: []tlsprobe.SuiteResult{
			{Version: "TLSv1.3", ID: 0x1301, Name: "TLS_AES_128_GCM_SHA256", Rank: 1, AEAD: true, Cipher: "AES_128_GCM"},
			{Version: "TLSv1.2", ID: 0xc02f, Name: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", AEAD: true},
		},
		Groups:     []tlsprobe.GroupResult{{Version: "TLSv1.3", ID: 0x11ec, Name: "X25519MLKEM768", PQ: true, Hybrid: true, Rank: 1}},
		Negotiated: &tlsprobe.Negotiated{Version: "TLSv1.3", Suite: "TLS_AES_128_GCM_SHA256", SuiteID: 0x1301, Group: "X25519MLKEM768", GroupID: 0x11ec, PQ: true},
		Certificates: []tlsprobe.CertResult{
			{Source: "tls-default", Chain: []tlsprobe.CertInfo{leaf, ca}},
			{Source: "tls1.2-rsa", Chain: []tlsprobe.CertInfo{leaf, ca}}, // the same chain, seen on a second probe path
		},
	}
}

func count(obs []estate.Observation, kind, relation string) int {
	n := 0
	for _, o := range obs {
		if o.Entity.Kind == kind && o.Relation == relation {
			n++
		}
	}
	return n
}

// REQ-MOD-3: a scan report projects completely, as network evidence at the exercised rung.
func TestScanReportProjectsEveryFactAsNetworkEvidence(t *testing.T) {
	obs := estate.FromScanReport(sampleReport())

	want := map[[2]string]int{
		{estate.KindProtocol, estate.RelOffers}:      2, // SSLv3 is unsupported and produces nothing
		{estate.KindSuite, estate.RelOffers}:         2,
		{estate.KindGroup, estate.RelOffers}:         1,
		{estate.KindSuite, estate.RelNegotiates}:     1,
		{estate.KindGroup, estate.RelNegotiates}:     1,
		{estate.KindCertificate, estate.RelPresents}: 2, // leaf and CA, once each despite two probe paths
	}
	for k, n := range want {
		if got := count(obs, k[0], k[1]); got != n {
			t.Errorf("%s/%s = %d observations, want %d", k[0], k[1], got, n)
		}
	}
	for _, o := range obs {
		if err := estate.Validate(estate.StreamNetwork, o); err != nil {
			t.Errorf("%s %s: %v", o.Entity.Kind, o.Entity.Key, err)
		}
		if o.Rung != evidence.RungExercised || o.Class != evidence.E3Exercised {
			t.Errorf("%s: rung %s class %v, want exercised/E3", o.Entity.Key, o.Rung, o.Class)
		}
	}
	// The certificate entity is keyed by fingerprint and carries the key size.
	for _, o := range obs {
		if o.Entity.Kind == estate.KindCertificate && o.Attrs["position"] == "leaf" {
			if o.Entity.Key != "cert:"+strings.Repeat("ab", 32) || o.Entity.Attrs["keyBits"] != "2048" || o.Entity.Attrs["keyAlg"] != "RSA" {
				t.Errorf("leaf certificate entity = %+v", o.Entity)
			}
		}
	}
}

func TestScanProjectionIsDeterministic(t *testing.T) {
	a, b := estate.FromScanReport(sampleReport()), estate.FromScanReport(sampleReport())
	if len(a) != len(b) {
		t.Fatalf("lengths %d and %d", len(a), len(b))
	}
	for i := range a {
		if a[i].Entity.Key != b[i].Entity.Key || a[i].Relation != b[i].Relation {
			t.Fatalf("observation %d differs: %+v vs %+v", i, a[i], b[i])
		}
	}
}

// SECARCH-001 T-02: strings from a certificate are attacker-controlled. They are
// cleaned on the way in, and Validate is the second line of defence.
func TestHostileCertificateStringsAreCleaned(t *testing.T) {
	rep := sampleReport()
	rep.Certificates[0].Chain[0].Subject = "CN=<img src=x onerror=alert(1)>\x00\x1b[31m\u202e" + strings.Repeat("A", 5000)
	rep.Certificates[0].Chain[0].DNSNames = []string{"a\nb.test"}
	for _, o := range estate.FromScanReport(rep) {
		if err := estate.Validate(estate.StreamNetwork, o); err != nil {
			t.Fatalf("hostile input escaped cleaning: %v", err)
		}
		if o.Entity.Kind == estate.KindCertificate {
			for _, v := range o.Entity.Attrs {
				if len(v) > estate.MaxAttrLen || strings.ContainsAny(v, "\x00\x1b\n") {
					t.Errorf("uncleaned value %q", v)
				}
			}
		}
	}
}

func TestValidateRefusals(t *testing.T) {
	good := estate.Observation{
		Entity:   estate.Entity{Kind: estate.KindSoftware, Key: "sw:x@1", Name: "x"},
		Relation: estate.RelContains, Rung: evidence.RungPresent, Class: evidence.E0Existence,
		Method: "m@1", Quality: estate.QualityParsed,
	}
	if err := estate.Validate(estate.StreamHost, good); err != nil {
		t.Fatalf("good observation refused: %v", err)
	}
	cases := []struct {
		name   string
		stream estate.Stream
		mut    func(*estate.Observation)
	}{
		{"host claims exercised (ADR-0006)", estate.StreamHost, func(o *estate.Observation) { o.Rung = evidence.RungExercised }},
		{"import claims bound (SR-18)", estate.StreamImported, func(o *estate.Observation) { o.Rung = evidence.RungBound }},
		{"import claims loaded (SR-18)", estate.StreamImported, func(o *estate.Observation) { o.Rung = evidence.RungLoaded }},
		{"import claims exercised (SR-18)", estate.StreamImported, func(o *estate.Observation) { o.Rung = evidence.RungExercised }},
		{"unknown stream", estate.Stream("x"), func(*estate.Observation) {}},
		{"unknown kind", estate.StreamHost, func(o *estate.Observation) { o.Entity.Kind = "thing" }},
		{"empty key", estate.StreamHost, func(o *estate.Observation) { o.Entity.Key = "" }},
		{"attribute not allowed", estate.StreamHost, func(o *estate.Observation) { o.Entity.Attrs = map[string]string{"password": "x"} }},
		{"control character in a value", estate.StreamHost, func(o *estate.Observation) { o.Entity.Attrs = map[string]string{"version": "1\x00"} }},
		{"oversized value", estate.StreamHost, func(o *estate.Observation) {
			o.Entity.Attrs = map[string]string{"version": strings.Repeat("v", estate.MaxAttrLen+1)}
		}},
		{"observation attribute not allowed", estate.StreamHost, func(o *estate.Observation) { o.Attrs = map[string]string{"secret": "x"} }},
		{"unknown relation", estate.StreamHost, func(o *estate.Observation) { o.Relation = "owns" }},
		{"no method", estate.StreamHost, func(o *estate.Observation) { o.Method = "" }},
		{"unknown quality", estate.StreamHost, func(o *estate.Observation) { o.Quality = "great" }},
		{"unknown rung", estate.StreamHost, func(o *estate.Observation) { o.Rung = "believed" }},
	}
	for _, c := range cases {
		o := good
		c.mut(&o)
		if err := estate.Validate(c.stream, o); err == nil {
			t.Errorf("%s: accepted", c.name)
		}
	}
}

// ---- host CBOM projection, from a real collector run ---------------------------------------

func hostBOM(t *testing.T) *cdx.BOM {
	t.Helper()
	pe := func(v, product string, ms, ls uint32) *fstest.MapFile {
		return &fstest.MapFile{Data: pefilestest.Build(pefilestest.Opts{}, ms, ls, v, product)}
	}
	fsys := fstest.MapFS{
		"Program Files/Git/mingw64/bin/libcrypto-3-x64.dll": pe("3.5.7", "The OpenSSL Toolkit", 3<<16|5, 7<<16),
		"Program Files/Evil/libcrypto-3-x64.dll":            {Data: []byte("MZ this is not really a PE")},
		"Program Files/App/server.key":                      {Data: []byte("-----BEGIN PRIVATE KEY-----")},
	}
	res, err := discover.Run(context.Background(), sense.Default, discover.Options{FS: fsys, OS: "windows", Tier: "user", HostName: "test-host"})
	if err != nil {
		t.Fatal(err)
	}
	assets, props, err := cbom.FromHostGraph(res.Graph, cbom.HostOptions{PrivilegeNote: res.PrivilegeNote})
	if err != nil {
		t.Fatal(err)
	}
	bom, _ := cbom.Build(assets, cbom.Options{Tool: cbom.Tool{Name: "cipherhorizon", Version: "test"}, HostName: "test-host", MetadataProperties: props})
	pqc.Annotate(bom, pqc.Analyze(bom))
	// Round-trip through JSON, as the server does with a stored snapshot.
	var buf bytes.Buffer
	if err := cbom.Encode(&buf, bom, true); err != nil {
		t.Fatal(err)
	}
	out := new(cdx.BOM)
	if err := cdx.NewBOMDecoder(&buf, cdx.BOMFileFormatJSON).Decode(out); err != nil {
		t.Fatal(err)
	}
	return out
}

// REQ-MOD-4: the host stream keeps the rung, method and method quality the collector
// recorded, and the algorithm capability names the software that provides it.
func TestHostCBOMProjectionKeepsTheCollectorsEvidence(t *testing.T) {
	res := estate.FromHostCBOM(hostBOM(t))
	if len(res.Observations) == 0 {
		t.Fatal("nothing projected")
	}
	var openssl, decoy *estate.Observation
	algs, withVia := 0, 0
	for i, o := range res.Observations {
		if err := estate.Validate(estate.StreamHost, o); err != nil {
			t.Errorf("%s: %v", o.Entity.Key, err)
		}
		switch {
		case o.Entity.Kind == estate.KindSoftware && o.Entity.Attrs["version"] == "3.5.7.0":
			openssl = &res.Observations[i]
		case o.Entity.Kind == estate.KindSoftware && o.Entity.Name == "libcrypto-3-x64.dll" && o.Entity.Attrs["version"] == "":
			decoy = &res.Observations[i]
		case o.Entity.Kind == estate.KindAlgorithm:
			algs++
			if o.Relation != estate.RelCapable || o.Rung != evidence.RungCapable {
				t.Errorf("algorithm %s: %s/%s, want capable/capable", o.Entity.Key, o.Relation, o.Rung)
			}
			if o.Via != "" {
				withVia++
			}
		}
	}
	if openssl == nil {
		t.Fatal("bundled OpenSSL not projected")
	}
	if openssl.Rung != evidence.RungPresent || openssl.Quality != estate.QualityParsed || openssl.Method != evidence.MethodPEVersion {
		t.Errorf("openssl evidence = %s / %s / %s", openssl.Rung, openssl.Quality, openssl.Method)
	}
	if algs == 0 || withVia != algs {
		t.Errorf("%d algorithm observations, %d name their provider", algs, withVia)
	}
	if decoy == nil || decoy.Quality != estate.QualityHeuristic {
		t.Errorf("decoy = %+v, want present at heuristic quality", decoy)
	}
	for _, o := range res.Observations {
		if strings.Contains(strings.ToLower(o.Entity.Key+o.Entity.Name), "server.key") {
			t.Errorf("a private-key file entered the graph: %+v", o.Entity)
		}
	}
}

// A component without this product's evidence properties (older or third-party) is
// read at the weakest honest reading, and a certificate with no hash is counted, not
// invented.
func TestForeignComponentsAreReadAtTheWeakestReading(t *testing.T) {
	bom := &cdx.BOM{Components: &[]cdx.Component{
		{BOMRef: "a", Type: cdx.ComponentTypeLibrary, Name: "libfoo", Version: "1.2"},
		{BOMRef: "b", Type: cdx.ComponentTypeCryptographicAsset, Name: "AES-256-GCM", CryptoProperties: &cdx.CryptoProperties{AssetType: cdx.CryptoAssetTypeAlgorithm}},
		{BOMRef: "c", Type: cdx.ComponentTypeCryptographicAsset, Name: "a certificate", CryptoProperties: &cdx.CryptoProperties{AssetType: cdx.CryptoAssetTypeCertificate}},
		{BOMRef: "d", Type: cdx.ComponentTypeCryptographicAsset, Name: "a key", CryptoProperties: &cdx.CryptoProperties{AssetType: cdx.CryptoAssetTypeRelatedCryptoMaterial}},
		{BOMRef: "e", Type: cdx.ComponentTypeLibrary},
	}}
	res := estate.FromHostCBOM(bom)
	if len(res.Observations) != 2 {
		t.Fatalf("%d observations, want 2 (library and algorithm)", len(res.Observations))
	}
	for _, o := range res.Observations {
		if o.Quality != estate.QualitySampled || o.Method != estate.MethodCBOMImport {
			t.Errorf("%s: %s / %s, want the weakest reading", o.Entity.Key, o.Quality, o.Method)
		}
	}
	if res.Uninterpreted["certificate without a SHA-256 hash"] != 1 || res.Uninterpreted["component without a name"] != 1 {
		t.Errorf("uninterpreted = %v", res.Uninterpreted)
	}
	if res.Uninterpreted["cryptographic asset of type related-crypto-material"] != 1 {
		t.Errorf("uninterpreted = %v", res.Uninterpreted)
	}
}

// A certificate component with a SHA-256 hash becomes a certificate entity on the same
// key a TLS scan uses: the same certificate is one entity (REQ-CERT-6).
func TestCertificateComponentSharesTheScanKey(t *testing.T) {
	fp := strings.Repeat("ab", 32)
	bom := &cdx.BOM{Components: &[]cdx.Component{{
		BOMRef: "c", Type: cdx.ComponentTypeCryptographicAsset, Name: "example.test",
		Hashes: &[]cdx.Hash{{Algorithm: cdx.HashAlgoSHA256, Value: strings.ToUpper(fp)}},
		CryptoProperties: &cdx.CryptoProperties{AssetType: cdx.CryptoAssetTypeCertificate,
			CertificateProperties: &cdx.CertificateProperties{SubjectName: "CN=example.test"}},
	}}}
	res := estate.FromHostCBOM(bom)
	if len(res.Observations) != 1 {
		t.Fatalf("got %d observations", len(res.Observations))
	}
	o := res.Observations[0]
	scan := estate.FromScanReport(sampleReport())
	var scanKey string
	for _, s := range scan {
		if s.Entity.Kind == estate.KindCertificate && s.Attrs["position"] == "leaf" {
			scanKey = s.Entity.Key
		}
	}
	if o.Entity.Key != scanKey || o.Rung != evidence.RungProvisioned {
		t.Errorf("key %q / rung %s, want %q / provisioned", o.Entity.Key, o.Rung, scanKey)
	}
	if err := estate.Validate(estate.StreamHost, o); err != nil {
		t.Error(err)
	}
}

// One observation per place a certificate was found, each carrying its own private-key
// answer from the occurrence's additionalContext; unknown values are ignored, not stored.
func TestEachOccurrenceOfACertificateIsItsOwnObservation(t *testing.T) {
	fp := strings.Repeat("cd", 32)
	bom := &cdx.BOM{Components: &[]cdx.Component{{
		BOMRef: "c", Type: cdx.ComponentTypeCryptographicAsset, Name: "x",
		Hashes: &[]cdx.Hash{{Algorithm: cdx.HashAlgoSHA256, Value: fp}},
		Evidence: &cdx.Evidence{Occurrences: &[]cdx.EvidenceOccurrence{
			{Location: "/etc/a.pem", AdditionalContext: "privateKey=yes"},
			{Location: "/etc/b.crt", AdditionalContext: "privateKey=unknown"},
			{Location: "/etc/c.crt", AdditionalContext: "privateKey=absolutely"},
			{Location: "/etc/d.crt", AdditionalContext: "something else"},
			{Location: "/etc/\x00bad"},
		}},
		CryptoProperties: &cdx.CryptoProperties{AssetType: cdx.CryptoAssetTypeCertificate},
		Properties:       &[]cdx.Property{{Name: "cipherhorizon:cert:key-algorithm", Value: "RSA"}, {Name: "cipherhorizon:cert:key-bits", Value: "2048"}},
	}}}
	res := estate.FromHostCBOM(bom)
	if len(res.Observations) != 5 {
		t.Fatalf("%d observations, want 5 (one per occurrence)", len(res.Observations))
	}
	want := map[string]string{"/etc/a.pem": "yes", "/etc/b.crt": "unknown", "/etc/c.crt": "", "/etc/d.crt": ""}
	for _, o := range res.Observations {
		if o.Entity.Attrs["keyBits"] != "2048" || o.Entity.Attrs["keyAlg"] != "RSA" {
			t.Errorf("entity attrs = %v", o.Entity.Attrs)
		}
		if w, ok := want[o.Attrs["location"]]; ok && o.Attrs["privateKey"] != w {
			t.Errorf("%s privateKey = %q, want %q", o.Attrs["location"], o.Attrs["privateKey"], w)
		}
		if err := estate.Validate(estate.StreamHost, o); err != nil {
			t.Errorf("%v", err)
		}
	}
}
