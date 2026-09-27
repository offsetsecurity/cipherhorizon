package discover_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"testing/fstest"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/example/cipherhorizon/internal/cbom"
	"github.com/example/cipherhorizon/internal/discover"
	"github.com/example/cipherhorizon/internal/evidence"
	"github.com/example/cipherhorizon/internal/pqc"
	"github.com/example/cipherhorizon/internal/schematest"
	"github.com/example/cipherhorizon/internal/sense"
	_ "github.com/example/cipherhorizon/internal/sense/all"
	"github.com/example/cipherhorizon/internal/sense/pefiles/pefilestest"
	"github.com/example/cipherhorizon/internal/sense/sensetest"
	"github.com/example/cipherhorizon/internal/sense/wincng"
	"github.com/example/cipherhorizon/internal/winapi"
)

func pe(fileVersion, product string, ms, ls uint32) *fstest.MapFile {
	return &fstest.MapFile{Data: pefilestest.Build(pefilestest.Opts{}, ms, ls, fileVersion, product)}
}

// A Windows-shaped host: a real-looking bundled OpenSSL 3.5.7, an NSS library, and a
// decoy that has an OpenSSL name but is not a PE image.
func windowsHost() fstest.MapFS {
	return fstest.MapFS{
		"Program Files/Git/mingw64/bin/libcrypto-3-x64.dll":     pe("3.5.7", "The OpenSSL Toolkit", 3<<16|5, 7<<16),
		"Program Files/Mozilla Firefox/nss3.dll":                pe("3.100", "Network Security Services", 3<<16|100, 0),
		"Program Files/Evil/libcrypto-3-x64.dll":                {Data: []byte("MZ this is not really a PE")},
		"Program Files/App/server.key":                          {Data: []byte("-----BEGIN PRIVATE KEY-----")},
		"Users/alice/AppData/Local/Programs/Tool/libsodium.dll": pe("1.0.20", "libsodium", 1<<16, 20<<16),
	}
}

func run(t *testing.T, fsys fstest.MapFS, os, tier string, mutate ...func(*discover.Options)) *discover.Result {
	t.Helper()
	o := discover.Options{FS: fsys, OS: os, Tier: tier, HostName: "test-host"}
	for _, m := range mutate {
		m(&o)
	}
	res, err := discover.Run(context.Background(), sense.Default, o)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func project(t *testing.T, res *discover.Result) *cdx.BOM {
	t.Helper()
	assets, props, err := cbom.FromHostGraph(res.Graph, cbom.HostOptions{PrivilegeNote: res.PrivilegeNote})
	if err != nil {
		t.Fatal(err)
	}
	bom, warnings := cbom.Build(assets, cbom.Options{
		Tool: cbom.Tool{Name: "cipherhorizon", Version: "test"}, HostName: res.Graph.Host.Name, MetadataProperties: props,
	})
	if len(warnings) != 0 {
		t.Errorf("warnings: %v", warnings)
	}
	pqc.Annotate(bom, pqc.Analyze(bom))
	var buf bytes.Buffer
	if err := cbom.Encode(&buf, bom, true); err != nil {
		t.Fatal(err)
	}
	schematest.Validate(t, buf.Bytes())
	return bom
}

func component(bom *cdx.BOM, name string) *cdx.Component {
	if bom.Components == nil {
		return nil // a host on which nothing was found
	}
	for i, c := range *bom.Components {
		if c.Name == name && c.Type != cdx.ComponentTypeCryptographicAsset {
			return &(*bom.Components)[i]
		}
	}
	return nil
}

func prop(c *cdx.Component, name string) string {
	if c == nil || c.Properties == nil {
		return ""
	}
	for _, p := range *c.Properties {
		if p.Name == cbom.PropertyNamespace+":"+name {
			return p.Value
		}
	}
	return ""
}

func provided(bom *cdx.BOM, ref string) []string {
	if bom.Dependencies == nil {
		return nil
	}
	for _, d := range *bom.Dependencies {
		if d.Ref == ref && d.Provides != nil {
			return *d.Provides
		}
	}
	return nil
}

func TestWindowsHostEndToEnd(t *testing.T) {
	res := run(t, windowsHost(), "windows", "user")
	bom := project(t, res)

	// The bundled OpenSSL is found, its version read from the file, and it is credited
	// with what OpenSSL 3.5 can do: 9 classical + 18 post-quantum (mapped, cited).
	ossl := component(bom, "libcrypto-3-x64.dll")
	var opensslRef string
	for _, c := range *bom.Components {
		if c.Version == "3.5.7.0" {
			opensslRef, ossl = c.BOMRef, &c
		}
	}
	if ossl == nil {
		t.Fatal("the bundled OpenSSL was not inventoried")
	}
	if n := len(provided(bom, opensslRef)); n != 27 {
		t.Errorf("OpenSSL 3.5.7 provides %d algorithms, want 27", n)
	}
	if prop(ossl, "claim") != "present" || prop(ossl, "provides-claim") != "capable-mapped" || prop(ossl, "method-quality") != "parsed" {
		t.Errorf("claims = %q / %q / %q", prop(ossl, "claim"), prop(ossl, "provides-claim"), prop(ossl, "method-quality"))
	}
	if prop(ossl, "collector") != "pe-files" || prop(ossl, "pe-valid") != "true" || prop(ossl, "product-name") != "The OpenSSL Toolkit" {
		t.Errorf("properties = %v", *ossl.Properties)
	}

	// NSS is inventoried and, having no curated mapping, credited with nothing.
	if nss := component(bom, "nss3.dll"); nss == nil || nss.Version != "3.100.0.0" {
		t.Errorf("nss = %+v", nss)
	} else if len(provided(bom, nss.BOMRef)) != 0 {
		t.Error("an uncurated family was credited with capabilities")
	}
}

// The decoy control: a file that only *looks* like OpenSSL (right name, not a PE) is
// listed as present at heuristic quality and credited with nothing.
func TestDecoyIsInventoriedButNeverCapable(t *testing.T) {
	bom := project(t, run(t, windowsHost(), "windows", "user"))
	var decoys int
	for _, c := range *bom.Components {
		if c.Type == cdx.ComponentTypeCryptographicAsset {
			continue
		}
		if prop(&c, "pe-valid") == "false" {
			decoys++
			if prop(&c, "method-quality") != "heuristic" {
				t.Errorf("decoy quality = %q, want heuristic", prop(&c, "method-quality"))
			}
			if len(provided(bom, c.BOMRef)) != 0 || prop(&c, "provides-claim") != "" {
				t.Errorf("a name match was credited with capabilities: %s", c.BOMRef)
			}
		}
	}
	if decoys != 1 {
		t.Errorf("decoys = %d, want 1", decoys)
	}
}

func TestNothingSecretEntersTheOutputAndUserNamesAreRedacted(t *testing.T) {
	res := run(t, windowsHost(), "windows", "user")
	bom := project(t, res)
	var buf bytes.Buffer
	if err := cbom.Encode(&buf, bom, true); err != nil {
		t.Fatal(err)
	}
	out := strings.ToLower(buf.String())
	for _, banned := range []string{"private key", "server.key", "alice"} {
		if strings.Contains(out, banned) {
			t.Errorf("%q leaked into the CBOM", banned)
		}
	}
	if !strings.Contains(out, "users/%user%/appdata/local/programs") {
		t.Error("the per-user library was not reported with a tokenised path")
	}
}

func TestPrivilegeNote(t *testing.T) {
	if got := discover.PrivilegeNote("admin", 3); got != "" {
		t.Errorf("admin note = %q, want none", got)
	}
	plain := discover.PrivilegeNote("user", 0)
	if !strings.Contains(plain, "elevated privileges") || !strings.Contains(plain, "Administrator") || !strings.Contains(plain, "root") {
		t.Errorf("note = %q", plain)
	}
	withDenied := discover.PrivilegeNote("user", 4)
	if !strings.Contains(withDenied, "4 location(s)") || !strings.Contains(withDenied, "Administrator") {
		t.Errorf("note = %q", withDenied)
	}
}

func TestPrivilegeIsRecordedInTheDocument(t *testing.T) {
	for tier, wantNote := range map[string]bool{"user": true, "admin": false} {
		res := run(t, windowsHost(), "windows", tier)
		bom := project(t, res)
		var gotTier string
		var gotNote bool
		for _, p := range *bom.Metadata.Properties {
			switch p.Name {
			case cbom.PropertyNamespace + ":privilege-tier":
				gotTier = p.Value
			case cbom.PropertyNamespace + ":coverage-note":
				gotNote = true
			}
		}
		if gotTier != tier || gotNote != wantNote {
			t.Errorf("tier %s: recorded tier %q, note present %v (want %v)", tier, gotTier, gotNote, wantNote)
		}
	}
}

func TestRedactHost(t *testing.T) {
	fsys := fstest.MapFS{
		"var/lib/dpkg/status": {Data: []byte("Package: libssl3\nStatus: install ok installed\nVersion: 3.0.13-1\nArchitecture: amd64\n\n")},
		"etc/machine-id":      {Data: []byte("0123456789abcdef0123456789abcdef\n")},
	}
	res := run(t, fsys, "linux", "user", func(o *discover.Options) { o.RedactHost = true })
	if res.Graph.Host.ID != res.Graph.Host.Name {
		t.Errorf("when redacting, the label is both the name and the id: %q vs %q", res.Graph.Host.Name, res.Graph.Host.ID)
	}
	if !strings.HasPrefix(res.Graph.Host.Name, "host-") || res.Graph.Host.Name == "test-host" {
		t.Errorf("host name = %q, want a redacted label", res.Graph.Host.Name)
	}
	if strings.Contains(res.Graph.Host.Name, "0123456789") {
		t.Error("the label contains part of the machine id")
	}
	// Redaction with no machine id must refuse, not emit an unstable label.
	_, err := discover.Run(context.Background(), sense.Default, discover.Options{
		FS: fstest.MapFS{"var/lib/dpkg/status": {Data: []byte("")}}, OS: "linux", Tier: "user", HostName: "x", RedactHost: true,
	})
	if err == nil || !strings.Contains(err.Error(), "machine id") {
		t.Errorf("err = %v", err)
	}
}

// A sensor that breaks the evidence contract is a bug and must surface, never be
// papered over into a partial result.
func TestAContractViolationIsAnError(t *testing.T) {
	reg := sense.NewRegistry()
	_ = reg.Register("liar", sensetest.Factory(&sensetest.Fake{SensorInfo: sensetest.Info("liar"),
		CollectFn: func(context.Context) (evidence.Batch, error) {
			o := sensetest.Observation("x")
			o.Subject.Attrs = map[string]string{"password": "hunter2"} // not on the allow-list
			evidence.Finish(&o)
			return evidence.Batch{Observations: []evidence.Observation{o}}, nil
		}}))
	_, err := discover.Run(context.Background(), reg, discover.Options{FS: fstest.MapFS{}, OS: "linux", Tier: "user", HostName: "h"})
	if err == nil || !strings.Contains(err.Error(), "evidence contract") {
		t.Errorf("err = %v", err)
	}
}

func TestDeterministic(t *testing.T) {
	encode := func() string {
		bom := project(t, run(t, windowsHost(), "windows", "user"))
		bom.SerialNumber = "urn:uuid:00000000-0000-4000-8000-000000000000"
		if bom.Metadata != nil {
			bom.Metadata.Timestamp = "2026-01-01T00:00:00Z"
		}
		var buf bytes.Buffer
		if err := cbom.Encode(&buf, bom, true); err != nil {
			t.Fatal(err)
		}
		return buf.String()
	}
	if a, b := encode(), encode(); a != b {
		t.Error("two runs on the same host produced different CBOMs")
	}
}

// windows-cng asks the running operating system, so it is registered but runs only for a live host.
func TestDebianAndWindowsSensorsAreBothRegistered(t *testing.T) {
	names := sense.Default.Names()
	if len(names) != 5 || names[0] != "apt" || names[1] != "cert-files" || names[2] != "pe-files" || names[3] != "windows-certs" || names[4] != "windows-cng" {
		t.Errorf("registered sensors = %v", names)
	}
}

// A persistent device identifier leaves the machine only when the operator asked for the
// redacted label. By default the host name is the subject and nothing more identifying is emitted.
func TestHostIDIsNotEmittedUnlessRedacting(t *testing.T) {
	fsys := fstest.MapFS{
		"var/lib/dpkg/status": {Data: []byte("")},
		"etc/machine-id":      {Data: []byte("0123456789abcdef0123456789abcdef\n")},
	}
	res := run(t, fsys, "linux", "user")
	if res.Graph.Host.ID != "" {
		t.Errorf("host id %q emitted without --redact-host", res.Graph.Host.ID)
	}
	bom := project(t, res)
	for _, p := range *bom.Metadata.Properties {
		if p.Name == cbom.PropertyNamespace+":host-id" {
			t.Errorf("the document carries a host-id without redaction: %q", p.Value)
		}
	}
}

func peImporting(fileVersion, product string, ms, ls uint32, imports ...string) *fstest.MapFile {
	return &fstest.MapFile{Data: pefilestest.Build(pefilestest.Opts{Imports: imports}, ms, ls, fileVersion, product)}
}

func dependsOn(bom *cdx.BOM, ref string) []string {
	if bom.Dependencies == nil {
		return nil
	}
	for _, d := range *bom.Dependencies {
		if d.Ref == ref && d.Dependencies != nil {
			return *d.Dependencies
		}
	}
	return nil
}

// OpenSSL on Windows is three files with three roles. Only libcrypto implements the
// algorithms; libssl and the openssl command use it, and the document says so with
// dependency edges proven from their import tables, not with duplicated capability.
func TestOpenSSLRolesAreSeparatedAndLinkedByImports(t *testing.T) {
	dir := "Program Files/Git/mingw64/bin/"
	host := fstest.MapFS{
		dir + "libcrypto-3-x64.dll": peImporting("3.5.7", "The OpenSSL Toolkit", 3<<16|5, 7<<16, "kernel32.dll"),
		dir + "libssl-3-x64.dll":    peImporting("3.5.7", "The OpenSSL Toolkit", 3<<16|5, 7<<16, "libcrypto-3-x64.dll", "ws2_32.dll"),
		dir + "openssl.exe":         peImporting("3.5.7", "The OpenSSL Toolkit", 3<<16|5, 7<<16, "libssl-3-x64.dll", "libcrypto-3-x64.dll"),
	}
	bom := project(t, run(t, host, "windows", "user"))
	crypto, ssl, cli := component(bom, "libcrypto-3-x64.dll"), component(bom, "libssl-3-x64.dll"), component(bom, "openssl.exe")
	if crypto == nil || ssl == nil || cli == nil {
		t.Fatal("a file of the bundle was not inventoried")
	}

	if n := len(provided(bom, crypto.BOMRef)); n != 27 {
		t.Errorf("libcrypto provides %d algorithms, want 27", n)
	}
	for _, c := range []*cdx.Component{ssl, cli} {
		if n := len(provided(bom, c.BOMRef)); n != 0 {
			t.Errorf("%s (a consumer) provides %d algorithms, want 0", c.Name, n)
		}
		if prop(c, "role") != "consumer" || prop(c, "role-basis") == "" || prop(c, "provides-claim") != "" {
			t.Errorf("%s: role %q, basis %q, provides-claim %q", c.Name, prop(c, "role"), prop(c, "role-basis"), prop(c, "provides-claim"))
		}
	}
	if prop(crypto, "role") != "provider" {
		t.Errorf("libcrypto role = %q", prop(crypto, "role"))
	}

	if got := dependsOn(bom, ssl.BOMRef); len(got) != 1 || got[0] != crypto.BOMRef {
		t.Errorf("libssl depends on %v, want libcrypto", got)
	}
	if got := dependsOn(bom, cli.BOMRef); len(got) != 2 {
		t.Errorf("openssl.exe depends on %v, want libcrypto and libssl", got)
	}
	if len(dependsOn(bom, crypto.BOMRef)) != 0 {
		t.Error("the provider must not depend on its consumers")
	}
	if b := prop(ssl, "dependency-basis"); !strings.Contains(b, "could use") || !strings.Contains(b, "same directory") {
		t.Errorf("the edge must say what it rests on and that it is not use: %q", b)
	}
	if prop(ssl, "static-imports") != "libcrypto-3-x64.dll" {
		t.Errorf("static-imports = %q: only recognised crypto libraries are recorded", prop(ssl, "static-imports"))
	}
}

func TestAConsumerNextToNoProviderIsNotLinked(t *testing.T) {
	host := fstest.MapFS{
		"Program Files/App/libssl-3-x64.dll":          peImporting("3.5.7", "The OpenSSL Toolkit", 3<<16|5, 7<<16, "libcrypto-3-x64.dll"),
		"Program Files/Elsewhere/libcrypto-3-x64.dll": pe("3.5.7", "The OpenSSL Toolkit", 3<<16|5, 7<<16),
	}
	bom := project(t, run(t, host, "windows", "user"))
	ssl := component(bom, "libssl-3-x64.dll")
	if got := dependsOn(bom, ssl.BOMRef); len(got) != 0 {
		t.Errorf("linked across directories: %v", got)
	}
	if prop(ssl, "static-imports") != "libcrypto-3-x64.dll" || prop(ssl, "dependency-basis") != "" {
		t.Errorf("the name should be reported without an edge: imports %q, basis %q", prop(ssl, "static-imports"), prop(ssl, "dependency-basis"))
	}
}

// A file is identified by its SHA-256 and a generic package URL that says it is a
// file identity. A decoy that is not a PE has neither.
func TestFilesCarryAHashAndAFileIdentity(t *testing.T) {
	img := pefilestest.Build(pefilestest.Opts{}, 3<<16|5, 7<<16, "3.5.7", "The OpenSSL Toolkit")
	sum := sha256.Sum256(img)
	host := fstest.MapFS{
		"Program Files/Git/bin/libcrypto-3-x64.dll": {Data: img},
		"Program Files/Evil/libcrypto-3-x64.dll":    {Data: []byte("MZ this is not really a PE")},
	}
	bom := project(t, run(t, host, "windows", "user"))
	var real, decoy *cdx.Component
	for i, c := range *bom.Components {
		if c.Type == cdx.ComponentTypeCryptographicAsset {
			continue
		}
		if c.Version != "" {
			real = &(*bom.Components)[i]
		} else {
			decoy = &(*bom.Components)[i]
		}
	}
	if real == nil || decoy == nil {
		t.Fatal("expected one genuine file and one decoy")
	}
	if real.Hashes == nil || len(*real.Hashes) != 1 || (*real.Hashes)[0].Algorithm != cdx.HashAlgoSHA256 || (*real.Hashes)[0].Value != hex.EncodeToString(sum[:]) {
		t.Errorf("hashes = %+v", real.Hashes)
	}
	want := "pkg:generic/libcrypto-3-x64.dll@3.5.7.0?checksum=sha256:" + hex.EncodeToString(sum[:])
	if real.PackageURL != want {
		t.Errorf("purl = %q, want %q", real.PackageURL, want)
	}
	if !strings.Contains(prop(real, "identifier-basis"), "not an upstream product identifier") {
		t.Errorf("identifier-basis = %q", prop(real, "identifier-basis"))
	}
	if decoy.Hashes != nil || decoy.PackageURL != "" || prop(decoy, "identifier-basis") != "" {
		t.Errorf("a decoy was given an identity: hashes %v, purl %q", decoy.Hashes, decoy.PackageURL)
	}
}

// ---- native Windows cryptography (sensor windows-cng), through the whole pipeline ----

// fakeWindows is a Windows that reports a small, realistic crypto footprint.
type fakeWindows struct{ native bool }

const primitiveProvider = "Microsoft Primitive Provider"

func (f fakeWindows) Native() bool { return f.native }
func (fakeWindows) Algorithms(op uint32) ([]winapi.Algorithm, int, error) {
	all := map[uint32][]winapi.Algorithm{
		winapi.OpCipher:    {{Name: "AES", Ops: winapi.OpCipher}, {Name: "RC4", Ops: winapi.OpCipher}},
		winapi.OpHash:      {{Name: "SHA256", Ops: winapi.OpHash}, {Name: "MD5", Ops: winapi.OpHash}},
		winapi.OpSignature: {{Name: "ECDSA_P256", Ops: winapi.OpSignature}, {Name: "ML-DSA", Ops: winapi.OpSignature}},
	}
	return all[op], 0, nil
}
func (fakeWindows) AlgorithmProviders(string) ([]string, int, error) {
	return []string{primitiveProvider}, 0, nil
}
func (fakeWindows) RegisteredProviders() ([]string, int, error) {
	return []string{primitiveProvider, "Microsoft Platform Crypto Provider"}, 0, nil
}
func (fakeWindows) StorageProviders() ([]winapi.StorageProvider, int, error) {
	return []winapi.StorageProvider{{Name: "Microsoft Platform Crypto Provider"}}, 0, nil
}
func (fakeWindows) StorageProviderAlgorithms(string, uint32) ([]winapi.Algorithm, int, error) {
	return nil, 0, nil
}
func (fakeWindows) CSPs() ([]winapi.CSP, int, error) {
	return []winapi.CSP{{Name: "Microsoft Base Cryptographic Provider v1.0", Type: 1}}, 0, nil
}
func (fakeWindows) Probe(alg, set string) (bool, error) {
	return alg == "ML-KEM" && (set == "" || set == "768"), nil
}

func liveWindows(t *testing.T, native bool, live bool) *cdx.BOM {
	t.Helper()
	reg := sense.NewRegistry()
	if err := wincng.Register(reg, fakeWindows{native: native}); err != nil {
		t.Fatal(err)
	}
	res, err := discover.Run(context.Background(), reg, discover.Options{FS: fstest.MapFS{}, OS: "windows", Tier: "user", HostName: "live-host", Live: live})
	if err != nil {
		t.Fatal(err)
	}
	return project(t, res)
}

func TestNativeCryptographyProjectsToProvidersAndCatalogueAlgorithms(t *testing.T) {
	bom := liveWindows(t, true, true) // project() validates the document against the CycloneDX 1.6 schema

	prim := component(bom, primitiveProvider)
	if prim == nil || prim.Type != cdx.ComponentTypeLibrary {
		t.Fatalf("the provider was not inventoried as a library: %+v", prim)
	}
	if prop(prim, "provider-kind") != "cng" || prop(prim, "evidence") != "os-enumeration" || prop(prim, "provides-claim") != "capable-probed" || prop(prim, "method-quality") != "authoritative" {
		t.Errorf("provider properties: kind %q evidence %q provides-claim %q quality %q", prop(prim, "provider-kind"), prop(prim, "evidence"), prop(prim, "provides-claim"), prop(prim, "method-quality"))
	}
	got := map[string]bool{}
	for _, ref := range provided(bom, prim.BOMRef) {
		got[ref] = true
	}
	for _, id := range []string{"aes", "sha-256", "md5", "rc4", "ecdsa", "ml-kem-768"} {
		found := false
		for ref := range got {
			if strings.HasPrefix(ref, "crypto/algorithm/"+id) {
				found = true
			}
		}
		if !found {
			t.Errorf("the provider does not provide %s: %v", id, provided(bom, prim.BOMRef))
		}
	}
	for ref := range got {
		if strings.HasPrefix(ref, "crypto/algorithm/ml-kem-512") || strings.HasPrefix(ref, "crypto/algorithm/ml-kem-1024") {
			t.Errorf("an unconfirmed parameter set was reported: %s", ref)
		}
	}
	if prop(component(bom, "Microsoft Platform Crypto Provider"), "opened") != "false" {
		t.Error("a hardware key storage provider must be listed and not opened")
	}
	if csp := component(bom, "Microsoft Base Cryptographic Provider v1.0"); prop(csp, "provider-kind") != "csp" || prop(csp, "csp-type-name") != "PROV_RSA_FULL" {
		t.Errorf("legacy provider: %v", csp)
	}
}

// Legacy algorithms are inventoried with their citation, and get no invented quantum verdict.
func TestLegacyAlgorithmsCarryACitationAndNoQuantumVerdict(t *testing.T) {
	bom := liveWindows(t, true, true)
	var md5 *cdx.Component
	for i, c := range *bom.Components {
		if c.Type == cdx.ComponentTypeCryptographicAsset && c.Name == "MD5" {
			md5 = &(*bom.Components)[i]
		}
	}
	if md5 == nil {
		t.Fatal("MD5 was not inventoried")
	}
	if prop(md5, "classical-status") == "" || !strings.Contains(prop(md5, "classical-basis"), "rfc6151") {
		t.Errorf("MD5 legacy statement: %q / %q", prop(md5, "classical-status"), prop(md5, "classical-basis"))
	}
	if prop(md5, "pqc:status") != "" {
		t.Errorf("MD5 was given a post-quantum verdict %q", prop(md5, "pqc:status"))
	}
	if prop(md5, "pqc:unclassified-reason") == "" {
		t.Error("the reason for having no verdict must be recorded")
	}
}

// The sensor asks the running OS, so it must not run for anything but a live Windows host.
func TestNativeSensorDoesNotRunForAFixtureOrAStub(t *testing.T) {
	for name, tc := range map[string]struct{ native, live bool }{"fixture root": {true, false}, "stub API": {false, true}} {
		bom := liveWindows(t, tc.native, tc.live)
		if component(bom, primitiveProvider) != nil {
			t.Errorf("%s: providers were inventoried for a host that cannot be asked", name)
		}
	}
}
