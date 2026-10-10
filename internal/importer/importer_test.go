package importer_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/offsetsecurity/cipherhorizon/internal/estate"
	"github.com/offsetsecurity/cipherhorizon/internal/evidence"
	"github.com/offsetsecurity/cipherhorizon/internal/importer"
)

func fixture(t testing.TB, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "testdata", "interop", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func parse(t *testing.T, name string) *importer.Doc {
	t.Helper()
	d, err := importer.Parse(fixture(t, name), importer.DefaultLimits)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return d
}

func count(obs []estate.Observation, kind string) int {
	n := 0
	for _, o := range obs {
		if o.Entity.Kind == kind {
			n++
		}
	}
	return n
}

// REQ-ING-6: each producer is recognised by what it records about itself, and an unrecognised
// one still imports, generically.
func TestProfilesAreDetected(t *testing.T) {
	for file, want := range map[string]importer.Profile{
		"cbomkit-like-1.6.json":     importer.ProfileCBOMkit,
		"cbomlens-like-1.7.json":    importer.ProfileLens,
		"unknown-producer-1.6.json": importer.ProfileGeneric,
	} {
		d := parse(t, file)
		if d.Profile.ID != want.ID || d.Profile.Kind != want.Kind {
			t.Errorf("%s: profile %+v, want %+v", file, d.Profile, want)
		}
	}
	// Theia's sample records no tool, only an application name: it imports generically, which is
	// the weakest reading and never an overclaim.
	if d := parse(t, "theia-like-1.6.json"); d.Profile.ID != "generic" {
		t.Errorf("theia-like: %+v", d.Profile)
	}
	if d := parse(t, "cbomlens-like-1.7.json"); d.SpecVersion != "1.7" || d.ToolName != "CBOM-Lens" {
		t.Errorf("lens: spec %s tool %q", d.SpecVersion, d.ToolName)
	}
}

// REQ-ING-3, SR-04: what the document says about its subject is a claim to display; it never
// decides anything, and nothing here even has a way to name a system.
func TestTheDocumentsOwnSubjectIsAClaimOnly(t *testing.T) {
	d := parse(t, "theia-like-1.6.json")
	if d.SubjectClaim != "my application" {
		t.Errorf("subject claim = %q", d.SubjectClaim)
	}
	if d := parse(t, "cbomkit-like-1.6.json"); d.SubjectClaim != "" {
		t.Errorf("a document with no subject claims %q", d.SubjectClaim)
	}
}

// REQ-ING-5: evidence follows the kind of producer, and nothing ever exceeds what an import may say.
func TestEvidenceMappingByProducerKind(t *testing.T) {
	src := parse(t, "cbomkit-like-1.6.json").Project()
	for _, o := range src.Observations {
		if o.Entity.Kind == estate.KindAlgorithm && (o.Rung != evidence.RungCapable || o.Quality != estate.QualityHeuristic || o.Method != estate.MethodImportSource) {
			t.Errorf("source-scan algorithm %s: %s/%s/%s, want capable/heuristic/source", o.Entity.Key, o.Rung, o.Quality, o.Method)
		}
	}
	host := parse(t, "cbomlens-like-1.7.json").Project()
	for _, o := range host.Observations {
		if o.Entity.Kind == estate.KindCertificate && (o.Rung != evidence.RungProvisioned || o.Method != estate.MethodImportHost) {
			t.Errorf("host-scan certificate: %s/%s", o.Rung, o.Method)
		}
		if o.Entity.Kind == estate.KindAlgorithm && o.Rung != evidence.RungPresent {
			t.Errorf("host-scan algorithm rung %s, want present", o.Rung)
		}
	}
	gen := parse(t, "unknown-producer-1.6.json").Project()
	for _, o := range gen.Observations {
		if o.Quality != estate.QualitySampled || o.Method != estate.MethodCBOMImport {
			t.Errorf("unknown producer: %s/%s", o.Quality, o.Method)
		}
	}
	// Whatever the kind, the imported stream refuses a claim of use.
	for name, r := range map[string]estate.Result{"source": src, "host": host, "generic": gen} {
		for _, o := range r.Observations {
			if err := estate.Validate(estate.StreamImported, o); err != nil {
				t.Errorf("%s: %v", name, err)
			}
			switch o.Rung {
			case evidence.RungBound, evidence.RungLoaded, evidence.RungExercised:
				t.Errorf("%s: an import produced a %s observation", name, o.Rung)
			}
		}
	}
}

// REQ-ING-1/7: what is understood is projected; what is not is counted by reason.
func TestLensDocumentIsProjectedAndTheRestIsCounted(t *testing.T) {
	r := parse(t, "cbomlens-like-1.7.json").Project()
	// certificate: one observation per occurrence (a file and a network location)
	if got := count(r.Observations, estate.KindCertificate); got != 2 {
		t.Errorf("%d certificate observations, want 2 (one per occurrence)", got)
	}
	var cert estate.Observation
	for _, o := range r.Observations {
		if o.Entity.Kind == estate.KindCertificate {
			cert = o
		}
	}
	a := cert.Entity.Attrs
	if cert.Entity.Key != "cert:"+strings.Repeat("ab", 32) || a["keyBits"] != "2048" || a["keyAlg"] != "RSA" || a["sigAlg"] != "SHA256withRSA" ||
		a["notAfter"] != "2027-01-01T00:00:00Z" || a["subject"] != "CN=leaf.example.test" {
		t.Errorf("certificate entity = %+v", cert.Entity)
	}
	// protocol and its suites: the two-byte identifier becomes the IANA code point; one bad suite is counted
	if count(r.Observations, estate.KindProtocol) != 1 || count(r.Observations, estate.KindSuite) != 1 {
		t.Errorf("protocol/suite observations = %d/%d", count(r.Observations, estate.KindProtocol), count(r.Observations, estate.KindSuite))
	}
	for _, o := range r.Observations {
		if o.Entity.Kind == estate.KindSuite && o.Entity.Key != "suite:0x1301" {
			t.Errorf("suite key %q, want the IANA code point of TLS_AES_128_GCM_SHA256", o.Entity.Key)
		}
	}
	// the algorithm with a catalogue OID shares the catalogue's key
	found := false
	for _, o := range r.Observations {
		found = found || (o.Entity.Kind == estate.KindAlgorithm && o.Entity.Key == "algo:RSA")
	}
	if !found {
		t.Errorf("RSA (OID 1.2.840.113549.1.1.1) did not map to the catalogue key: %+v", r.Observations)
	}
	for _, reason := range []string{"certificate without a SHA-256 hash", "cipher suite without a code point", "related crypto material: password (not modelled)"} {
		if r.Uninterpreted[reason] != 1 {
			t.Errorf("uninterpreted %q = %d, want 1 (all: %v)", reason, r.Uninterpreted[reason], r.Uninterpreted)
		}
	}
	// No key material of any kind is modelled.
	for _, o := range r.Observations {
		if strings.Contains(strings.ToLower(o.Entity.Name), "password") {
			t.Errorf("a password asset became an entity: %+v", o.Entity)
		}
	}
}

func TestCertificateIdentityFromABomRefHintAndSizeFromTheKeyReference(t *testing.T) {
	r := parse(t, "theia-like-1.6.json").Project()
	if len(r.Observations) != 1 {
		t.Fatalf("%d observations", len(r.Observations))
	}
	e := r.Observations[0].Entity
	if e.Key != "cert:"+strings.Repeat("ab", 32) || e.Attrs["keyBits"] != "4096" {
		t.Errorf("entity = %+v", e)
	}
}

func TestSourceScanFixtureIsProjectedAsCapabilityFromSource(t *testing.T) {
	r := parse(t, "cbomkit-like-1.6.json").Project()
	if count(r.Observations, estate.KindAlgorithm) != 2 || count(r.Observations, estate.KindSoftware) != 1 || count(r.Observations, estate.KindProtocol) != 0 {
		t.Errorf("observations by kind: algorithms %d software %d protocols %d",
			count(r.Observations, estate.KindAlgorithm), count(r.Observations, estate.KindSoftware), count(r.Observations, estate.KindProtocol))
	}
	// AES-256-GCM's OID is in the catalogue; RSA has none, so it is keyed by name under a separate prefix.
	keys := map[string]bool{}
	for _, o := range r.Observations {
		keys[o.Entity.Key] = true
	}
	if !keys["algo:x:rsa"] {
		t.Errorf("keys = %v", keys)
	}
	if r.Uninterpreted["related crypto material: secret-key (not modelled)"] != 1 || r.Uninterpreted["protocol of an unrecognised type"] != 1 {
		t.Errorf("uninterpreted = %v", r.Uninterpreted)
	}
}

// ---- hostile documents (REQ-ING-2, SR-01) -------------------------------------------------

func TestRefusals(t *testing.T) {
	lim := importer.DefaultLimits
	lim.MaxBytes, lim.MaxDepth, lim.MaxNodes, lim.MaxString, lim.MaxComponents = 1<<20, 20, 10_000, 1000, 50

	nested := strings.Repeat(`{"a":`, 30) + `1` + strings.Repeat(`}`, 30)
	manyNodes := `{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"x":[` + strings.TrimSuffix(strings.Repeat("1,", 20_000), ",") + `]}`
	longString := `{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"x":"` + strings.Repeat("a", 2000) + `"}`
	comps := func(n int) string {
		var sb strings.Builder
		sb.WriteString(`{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":[`)
		for i := 0; i < n; i++ {
			if i > 0 {
				sb.WriteString(",")
			}
			fmt.Fprintf(&sb, `{"type":"library","name":"c%d"}`, i)
		}
		sb.WriteString("]}")
		return sb.String()
	}
	valid := `{"bomFormat":"CycloneDX","specVersion":"1.6","version":1}`

	cases := []struct {
		name  string
		doc   string
		stage string
		text  string
	}{
		{"oversized", strings.Repeat(" ", 1<<20+1), "limits", "limit is"},
		{"nested too deep", nested, "limits", "nested more than"},
		{"too many values", manyNodes, "limits", "more than"},
		{"a huge string", longString, "limits", "longer than"},
		{"too many components", comps(51), "limits", "components"},
		{"not JSON", `{"bomFormat":`, "format", "not valid JSON"},
		{"truncated", `{"bomFormat":"CycloneDX","components":[`, "format", "not valid JSON"},
		{"an array", `[1,2,3]`, "format", "not a JSON object"},
		{"an SBOM standard that is not CycloneDX", `{"bomFormat":"SPDX","specVersion":"1.6"}`, "format", "not a CycloneDX"},
		{"version 1.5", `{"bomFormat":"CycloneDX","specVersion":"1.5","version":1}`, "format", "no cryptographic assets"},
		{"version 2.0", `{"bomFormat":"CycloneDX","specVersion":"2.0","version":1}`, "format", "not supported"},
		{"no version at all", `{"bomFormat":"CycloneDX"}`, "format", "not supported"},
		{"a schema violation", `{"bomFormat":"CycloneDX","specVersion":"1.6","version":"one"}`, "schema", "not valid CycloneDX 1.6"},
		{"an asset of an unknown type", `{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":[{"type":"cryptographic-asset","name":"x","cryptoProperties":{"assetType":"widget"}}]}`, "schema", "not valid"},
	}
	for _, c := range cases {
		_, err := importer.Parse([]byte(c.doc), lim)
		var ie *importer.Error
		if !errors.As(err, &ie) {
			t.Errorf("%s: err = %v, want an *importer.Error", c.name, err)
			continue
		}
		if ie.Stage != c.stage || !strings.Contains(ie.Message, c.text) {
			t.Errorf("%s: %s: %s (want stage %s containing %q)", c.name, ie.Stage, ie.Message, c.stage, c.text)
		}
		if len(ie.Message) > 400 || len(ie.Problems) > 5 {
			t.Errorf("%s: the refusal itself is large: %d bytes, %d problems", c.name, len(ie.Message), len(ie.Problems))
		}
	}
	if _, err := importer.Parse([]byte(valid), lim); err != nil {
		t.Errorf("a minimal valid document was refused: %v", err)
	}
}

// SR-02: attacker-chosen strings anywhere in a document project into inert, bounded, valid data.
func TestHostileStringsProjectIntoValidObservations(t *testing.T) {
	evil := "<img src=x onerror=alert(1)>\x1b[31m\u202e" + strings.Repeat("A", 5000)
	q := func(s string) string { b, _ := json.Marshal(s); return string(b) }
	doc := fmt.Sprintf(`{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":[
	  {"type":"cryptographic-asset","bom-ref":"a","name":%s,"cryptoProperties":{"assetType":"algorithm","oid":%s}},
	  {"type":"library","bom-ref":"l","name":%s,"version":%s,"purl":%s},
	  {"type":"cryptographic-asset","bom-ref":"c","name":%s,"hashes":[{"alg":"SHA-256","content":%s}],
	   "evidence":{"occurrences":[{"location":%s}]},
	   "cryptoProperties":{"assetType":"certificate","certificateProperties":{"subjectName":%s,"issuerName":%s}}}]}`,
		q(evil), q("1.2.3"), q(evil), q("1.0\x1b[0m"), q("pkg:generic/x"), q(evil), q(strings.Repeat("cd", 32)), q(evil), q(evil), q(evil))
	d, err := importer.Parse([]byte(doc), importer.DefaultLimits)
	if err != nil {
		var ie *importer.Error
		if errors.As(err, &ie) {
			t.Fatalf("%v %+v", err, ie.Problems)
		}
		t.Fatal(err)
	}
	r := d.Project()
	if len(r.Observations) == 0 {
		t.Fatal("nothing projected")
	}
	for _, o := range r.Observations {
		if err := estate.Validate(estate.StreamImported, o); err != nil {
			t.Errorf("%s %.40q: %v", o.Entity.Kind, o.Entity.Key, err)
		}
	}
}

// AC-ING-1 on real documents, when the developer has them.
func TestRealDocumentsProjectWithoutLoss(t *testing.T) {
	dir := os.Getenv("CIPHERHORIZON_INTEROP_DIR")
	if dir == "" {
		t.Skip("CIPHERHORIZON_INTEROP_DIR is not set")
	}
	files, _ := filepath.Glob(filepath.Join(dir, "*.json"))
	parsed := 0
	for _, f := range files {
		if strings.HasPrefix(filepath.Base(f), "tree_") || strings.HasPrefix(filepath.Base(f), "cbom-repo") {
			continue
		}
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		d, err := importer.Parse(raw, importer.DefaultLimits)
		if err != nil {
			t.Errorf("%s: %v", filepath.Base(f), err)
			continue
		}
		parsed++
		r := d.Project()
		refused := r.Uninterpreted["refused by validation"]
		for _, o := range r.Observations {
			if err := estate.Validate(estate.StreamImported, o); err != nil {
				refused++
			}
		}
		t.Logf("%s: profile %s, spec %s, %d components -> %d observations, uninterpreted %v, invalid %d", filepath.Base(f), d.Profile.ID, d.SpecVersion, d.Components, len(r.Observations), r.Uninterpreted, refused)
		if refused > 0 {
			t.Errorf("%s: %d observations failed validation", filepath.Base(f), refused)
		}
	}
	if parsed == 0 {
		t.Error("no real document was parsed")
	}
}

// FuzzParse: whatever the bytes, Parse neither panics nor hangs, and returns either an
// *importer.Error or a document whose projection validates.
func FuzzParse(f *testing.F) {
	for _, n := range []string{"cbomkit-like-1.6.json", "cbomlens-like-1.7.json", "theia-like-1.6.json", "unknown-producer-1.6.json"} {
		f.Add(fixture(f, n))
	}
	f.Add([]byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":[{"type":"cryptographic-asset","name":"x","cryptoProperties":{"assetType":"certificate"}}]}`))
	f.Add([]byte(`{"bomFormat":"CycloneDX","specVersion":"1.7","version":1,"components":[{"type":"library","name":"a","components":[{"type":"library","name":"b"}]}]}`))
	lim := importer.DefaultLimits
	lim.MaxBytes = 1 << 20
	f.Fuzz(func(t *testing.T, data []byte) {
		d, err := importer.Parse(data, lim)
		if err != nil {
			var ie *importer.Error
			if !errors.As(err, &ie) {
				t.Fatalf("a refusal that is not an *importer.Error: %v", err)
			}
			if len(ie.Message) > 600 {
				t.Fatalf("refusal of %d bytes", len(ie.Message))
			}
			return
		}
		for _, o := range d.Project().Observations {
			if err := estate.Validate(estate.StreamImported, o); err != nil {
				t.Fatalf("an observation from a valid document is invalid: %v", err)
			}
		}
	})
}

// AC-ING-1 / REQ-ING-7: nothing is dropped unaccounted. Every component of a document is either
// interpreted or counted as not interpreted, whatever the producer.
func TestEveryComponentIsAccountedFor(t *testing.T) {
	check := func(name string, d *importer.Doc) {
		r := d.Project()
		if r.Components != d.Components || r.Interpreted+r.NotInterpreted != r.Components {
			t.Errorf("%s: %d components, %d interpreted + %d not interpreted", name, r.Components, r.Interpreted, r.NotInterpreted)
		}
		reasons := 0
		for reason, n := range r.Uninterpreted {
			if !strings.HasPrefix(reason, "cipher suite") {
				reasons += n
			}
		}
		if reasons != r.NotInterpreted {
			t.Errorf("%s: %d components not interpreted but the reasons add up to %d: %v", name, r.NotInterpreted, reasons, r.Uninterpreted)
		}
	}
	for _, f := range []string{"cbomkit-like-1.6.json", "cbomlens-like-1.7.json", "theia-like-1.6.json", "unknown-producer-1.6.json"} {
		check(f, parse(t, f))
	}
	if dir := os.Getenv("CIPHERHORIZON_INTEROP_DIR"); dir != "" {
		files, _ := filepath.Glob(filepath.Join(dir, "*.json"))
		for _, f := range files {
			if strings.HasPrefix(filepath.Base(f), "tree_") || strings.HasPrefix(filepath.Base(f), "cbom-repo") {
				continue
			}
			raw, _ := os.ReadFile(f)
			d, err := importer.Parse(raw, importer.DefaultLimits)
			if err != nil {
				t.Errorf("%s: %v", f, err)
				continue
			}
			check(filepath.Base(f), d)
		}
	}
}

// A native 1.7 document that uses relatedCryptographicAssets (the replacement for the deprecated
// references) yields the same certificate facts as the 1.6-style references: this product's own 1.7
// output can be imported elsewhere, and other producers' 1.7 output here.
func TestOneDotSevenRelatedAssetsAreReadLikeTheDeprecatedReferences(t *testing.T) {
	doc := strings.Replace(string(fixture(t, "cbomlens-like-1.7.json")),
		`"signatureAlgorithmRef": "crypto/algorithm/sig", "subjectPublicKeyRef": "crypto/key/leaf"`,
		`"relatedCryptographicAssets": [{"type": "publicKey", "ref": "crypto/key/leaf"}, {"type": "algorithm", "ref": "crypto/algorithm/sig"}]`, 1)
	doc = strings.Replace(doc, `"size": 2048, "algorithmRef": "crypto/algorithm/rsa"`, `"size": 2048, "relatedCryptographicAssets": [{"type": "algorithm", "ref": "crypto/algorithm/rsa"}]`, 1)
	if !strings.Contains(doc, "relatedCryptographicAssets") || strings.Contains(doc, "subjectPublicKeyRef") {
		t.Fatal("the fixture was not rewritten")
	}
	d, err := importer.Parse([]byte(doc), importer.DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range d.Project().Observations {
		if o.Entity.Kind == estate.KindCertificate {
			a := o.Entity.Attrs
			if a["keyBits"] != "2048" || a["keyAlg"] != "RSA" || a["sigAlg"] != "SHA256withRSA" {
				t.Errorf("attrs = %v", a)
			}
			return
		}
	}
	t.Error("no certificate observation")
}
