package discover_test

import (
	"bytes"
	"context"
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

func TestDebianAndWindowsSensorsAreBothRegistered(t *testing.T) {
	names := sense.Default.Names()
	if len(names) != 2 || names[0] != "apt" || names[1] != "pe-files" {
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
