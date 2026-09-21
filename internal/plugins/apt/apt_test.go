package apt

import (
	"context"
	"errors"
	"io/fs"
	"sort"
	"strings"
	"testing"
	"testing/fstest"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/example/cbom-scan/internal/algo"
	"github.com/example/cbom-scan/internal/collector"
)

func stanza(name, version, status string) string {
	return "Package: " + name + "\nStatus: " + status + "\nPriority: optional\nArchitecture: amd64\nVersion: " + version +
		"\nDescription: a multi-line\n description that must be skipped\n  with: colons in continuation lines\n\n"
}

func host(status string, osRelease string) fs.FS {
	m := fstest.MapFS{"var/lib/dpkg/status": {Data: []byte(status)}}
	if osRelease != "" {
		m["etc/os-release"] = &fstest.MapFile{Data: []byte(osRelease)}
	}
	return m
}

const ubuntuRelease = "NAME=\"Ubuntu\"\nVERSION_ID=\"24.04\"\nID=ubuntu\nID_LIKE=debian\n"

func collect(t *testing.T, fsys fs.FS) map[string]collector.CryptoAsset {
	t.Helper()
	assets, err := New(fsys).Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]collector.CryptoAsset{}
	for _, a := range assets {
		byName[a.Component.Name] = a
	}
	return byName
}

func TestUpstreamVersion(t *testing.T) {
	for in, want := range map[string]version{
		"3.0.13-0ubuntu3.4":    {3, 0, 13},
		"1:2.4.4-2ubuntu17":    {2, 4, 4},
		"3.5.1-1":              {3, 5, 1},
		"1.1.1w-0+deb11u1":     {1, 1, 1},
		"3.5.0~rc1-1":          {3, 5, 0},
		"2.4":                  {2, 4, 0},
		"3":                    {3, 0, 0},
		"1.10.3-2build1":       {1, 10, 3},
		"3.0.2-0ubuntu1.18":    {3, 0, 2},
		"0~20240101+git-1":     {0, 0, 0},
		"2:1.4.5-1+b1":         {1, 4, 5},
		"1.0.1e-2+deb7u20":     {1, 0, 1},
		"3.5.4-1~deb13u1":      {3, 5, 4},
		"1:3.5.0-0ubuntu2:bad": {3, 5, 0},
	} {
		got, ok := upstream(in)
		if !ok || got != want {
			t.Errorf("upstream(%q) = %v,%v want %v", in, got, ok, want)
		}
	}
	for _, bad := range []string{"", "abc", "-1", "v3.5"} {
		if _, ok := upstream(bad); ok {
			t.Errorf("upstream(%q) parsed; want !ok", bad)
		}
	}
}

func TestAtLeast(t *testing.T) {
	min := version{3, 5, 0}
	for v, want := range map[version]bool{
		{3, 5, 0}: true, {3, 5, 1}: true, {3, 6, 0}: true, {4, 0, 0}: true,
		{3, 4, 9}: false, {3, 0, 13}: false, {2, 9, 9}: false, {1, 1, 1}: false,
	} {
		if got := v.atLeast(min); got != want {
			t.Errorf("%v.atLeast(%v) = %v, want %v", v, min, got, want)
		}
	}
}

func TestParseStatus(t *testing.T) {
	// No trailing blank line after the last stanza; CRLF-free; continuation lines contain colons.
	in := stanza("a", "1", "install ok installed") + "Package: b\nStatus: install ok installed\nVersion: 2"
	var got []pkg
	if err := parseStatus(context.Background(), strings.NewReader(in), func(p pkg) { got = append(got, p) }); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Name != "a" || got[0].Arch != "amd64" || got[1].Name != "b" || got[1].Version != "2" {
		t.Errorf("parsed %+v", got)
	}
}

func TestInstalled(t *testing.T) {
	for status, want := range map[string]bool{
		"install ok installed":      true,
		"deinstall ok installed":    true, // marked for removal, files still present
		"deinstall ok config-files": false,
		"install ok half-installed": false,
		"install ok unpacked":       false,
		"":                          false,
	} {
		if got := (pkg{Status: status}).installed(); got != want {
			t.Errorf("installed(%q) = %v, want %v", status, got, want)
		}
	}
}

func TestCollectClassicalOpenSSL(t *testing.T) {
	got := collect(t, host(
		stanza("libssl3t64", "3.0.13-0ubuntu3.4", "install ok installed")+
			stanza("bash", "5.2.21-2ubuntu4", "install ok installed"),
		ubuntuRelease))

	lib, ok := got["libssl3t64"]
	if !ok {
		t.Fatal("libssl3t64 not inventoried")
	}
	if _, found := got["bash"]; found {
		t.Error("non-crypto package inventoried")
	}
	if want := "pkg:deb/ubuntu/libssl3t64@3.0.13-0ubuntu3.4?arch=amd64&distro=ubuntu-24.04"; lib.Component.PackageURL != want || lib.Component.BOMRef != want {
		t.Errorf("purl/bom-ref = %q / %q, want %q", lib.Component.PackageURL, lib.Component.BOMRef, want)
	}
	if lib.Component.Type != cdx.ComponentTypeLibrary || lib.Component.Version != "3.0.13-0ubuntu3.4" {
		t.Errorf("component = %+v", lib.Component)
	}

	provided := providedNames(t, lib)
	for _, want := range []string{"RSA", "ECDSA", "AES", "SHA-256"} {
		if !provided[want] {
			t.Errorf("3.0.13 should provide %s", want)
		}
	}
	for name := range provided {
		if strings.HasPrefix(name, "ML-") || strings.HasPrefix(name, "SLH-") {
			t.Errorf("OpenSSL 3.0.13 must not be credited with %s (added in 3.5)", name)
		}
	}
	// Every provides target must be emitted as an asset in the same collection.
	for _, ref := range lib.Provides {
		var found bool
		for _, a := range got {
			found = found || a.Component.BOMRef == ref
		}
		if !found {
			t.Errorf("provides %q but no such asset emitted", ref)
		}
	}
}

func TestCollectOpenSSL35IsPQCCapable(t *testing.T) {
	got := collect(t, host(stanza("libssl3t64", "3.5.1-1", "install ok installed"), "ID=debian\nVERSION_ID=13\n"))
	provided := providedNames(t, got["libssl3t64"])
	for _, want := range []string{"ML-KEM-768", "ML-DSA-65", "SLH-DSA-SHAKE-256f", "RSA"} {
		if !provided[want] {
			t.Errorf("3.5.1 should provide %s", want)
		}
	}
	if n := len(got["libssl3t64"].Provides); n != 9+18 {
		t.Errorf("provides %d algorithms, want 27 (9 classical + 18 PQC)", n)
	}
}

// If the version cannot be read, gated claims are omitted, not assumed.
func TestCollectUnparseableVersionOmitsGatedCapabilities(t *testing.T) {
	got := collect(t, host(stanza("libssl3", "unknown", "install ok installed"), ubuntuRelease))
	provided := providedNames(t, got["libssl3"])
	if !provided["RSA"] {
		t.Error("ungated capability lost")
	}
	if provided["ML-KEM-768"] {
		t.Error("gated capability assumed for an unparseable version")
	}
}

func TestCollectGnuPG(t *testing.T) {
	old := providedNames(t, collect(t, host(stanza("gpg", "1.4.23-1", "install ok installed"), ubuntuRelease))["gpg"])
	if !old["RSA"] || old["ECDSA"] {
		t.Errorf("gpg 1.4 provides %v; want RSA without ECC", old)
	}
	cur := collect(t, host(stanza("gpg", "2.4.4-2ubuntu17", "install ok installed"), ubuntuRelease))["gpg"]
	got := providedNames(t, cur)
	for _, want := range []string{"RSA", "DSA", "ECDSA", "ECDH", "Ed25519"} {
		if !got[want] {
			t.Errorf("gpg 2.4 should provide %s", want)
		}
	}
	if cur.Component.Type != cdx.ComponentTypeApplication {
		t.Errorf("gpg type = %q", cur.Component.Type)
	}
}

func TestCollectInventoryOnlyFamilyHasNoCapabilities(t *testing.T) {
	got := collect(t, host(stanza("libgcrypt20", "1.10.3-2build1", "install ok installed"), ubuntuRelease))
	a, ok := got["libgcrypt20"]
	if !ok {
		t.Fatal("libgcrypt20 not inventoried")
	}
	if len(a.Provides) != 0 {
		t.Errorf("uncurated family credited with capabilities: %v", a.Provides)
	}
	if len(got) != 1 {
		t.Errorf("emitted %d assets, want just the library (no algorithm assets)", len(got))
	}
	for _, p := range *a.Component.Properties {
		if strings.HasSuffix(p.Name, ":capability-basis") || strings.HasSuffix(p.Name, ":evidence") {
			t.Errorf("inventory-only component carries capability property %v", p)
		}
	}
}

func TestCollectSkipsRemovedAndDevPackages(t *testing.T) {
	got := collect(t, host(
		stanza("openssl", "3.0.13-0ubuntu3.4", "deinstall ok config-files")+
			stanza("libssl-dev", "3.0.13-0ubuntu3.4", "install ok installed")+
			stanza("libssl-doc", "3.0.13-0ubuntu3.4", "install ok installed"),
		ubuntuRelease))
	if len(got) != 0 {
		t.Errorf("collected %v; want nothing", got)
	}
}

func TestCollectWithoutOSReleaseOmitsPurl(t *testing.T) {
	a := collect(t, host(stanza("libssl3", "3.0.2-0ubuntu1", "install ok installed"), ""))["libssl3"]
	if a.Component.PackageURL != "" {
		t.Errorf("purl %q built without a known vendor", a.Component.PackageURL)
	}
	if a.Component.BOMRef != "apt/libssl3@3.0.2-0ubuntu1/amd64" {
		t.Errorf("fallback bom-ref = %q", a.Component.BOMRef)
	}
}

func TestPurlOmitsDistroWhenVersionIDMissing(t *testing.T) {
	got := purlFor(pkg{Name: "openssl", Version: "3.5.1-1", Arch: "amd64"}, osRelease{ID: "debian"})
	if want := "pkg:deb/debian/openssl@3.5.1-1?arch=amd64"; got != want {
		t.Errorf("purl = %q, want %q", got, want)
	}
}

func TestMultiArchPackagesGetDistinctRefs(t *testing.T) {
	status := stanza("libssl3", "3.0.13-1", "install ok installed") +
		strings.Replace(stanza("libssl3", "3.0.13-1", "install ok installed"), "amd64", "i386", 1)
	assets, err := New(host(status, ubuntuRelease)).Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	refs := map[string]bool{}
	for _, a := range assets {
		if a.Component.Type == cdx.ComponentTypeLibrary {
			refs[a.Component.BOMRef] = true
		}
	}
	if len(refs) != 2 {
		t.Errorf("bom-refs = %v, want two distinct", refs)
	}
}

func TestDetect(t *testing.T) {
	ctx := context.Background()
	if ok, err := New(host("", "")).Detect(ctx); !ok || err != nil {
		t.Errorf("Detect on a dpkg host = %v, %v", ok, err)
	}
	if ok, err := New(fstest.MapFS{}).Detect(ctx); ok || err != nil {
		t.Errorf("Detect on a non-dpkg host = %v, %v; want false, nil", ok, err)
	}
}

func TestCollectHonoursCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := New(host(stanza("libssl3", "3.0.13-1", "install ok installed"), ubuntuRelease)).Collect(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", err)
	}
}

func TestRegisteredWithDefaultRegistry(t *testing.T) {
	c, err := collector.Default.New(Name, collector.Host{FS: fstest.MapFS{}})
	if err != nil {
		t.Fatal(err)
	}
	if info := c.Metadata(); info.Name != "apt" || info.SourceType != collector.SourceOSPackage {
		t.Errorf("metadata = %+v", info)
	}
	if _, err := collector.Default.New(Name, collector.Host{}); err == nil {
		t.Error("nil host FS accepted")
	}
}

// Invariants over the rules table itself.
func TestRulesAreSound(t *testing.T) {
	seen := map[string]bool{}
	for _, r := range rules {
		if seen[r.family] {
			t.Errorf("duplicate family %q", r.family)
		}
		seen[r.family] = true

		if len(r.caps) > 0 && len(r.basis) == 0 {
			t.Errorf("%s: capabilities without a cited basis", r.family)
		}
		for _, c := range r.caps {
			for _, id := range c.algos {
				if _, ok := algo.Lookup(id); !ok {
					t.Errorf("%s: algorithm %q is not in the catalogue", r.family, id)
				}
			}
		}
	}

	for _, name := range []string{"bash", "coreutils", "libc6", "libssl-dev", "libssl-doc", "openssl-provider-legacy", "gnupg-l10n", "libgpg-error0", "libcurl4"} {
		if r := match(name); r != nil {
			t.Errorf("%q wrongly matched crypto family %q", name, r.family)
		}
	}
	for name, family := range map[string]string{
		"openssl": "openssl", "libssl3": "openssl", "libssl3t64": "openssl", "libssl1.1": "openssl", "libssl1.0.0": "openssl",
		"gnupg": "gnupg", "gpg": "gnupg", "gnupg2": "gnupg", "gpgv": "gnupg",
		"libgnutls30t64": "gnutls", "libnettle8t64": "nettle", "libhogweed6": "nettle", "libssh-4": "libssh", "libssh2-1": "libssh",
		"openssh-server": "openssh", "libcrypt1": "libxcrypt", "python3-cryptography": "python-cryptography",
	} {
		if r := match(name); r == nil || r.family != family {
			t.Errorf("match(%q) = %v, want family %q", name, r, family)
		}
	}
}

func providedNames(t *testing.T, a collector.CryptoAsset) map[string]bool {
	t.Helper()
	byRef := map[string]string{}
	for _, alg := range algo.All() {
		byRef[alg.BOMRef()] = alg.ID
	}
	out := map[string]bool{}
	var unknown []string
	for _, ref := range a.Provides {
		if id, ok := byRef[ref]; ok {
			out[id] = true
		} else {
			unknown = append(unknown, ref)
		}
	}
	sort.Strings(unknown)
	if len(unknown) > 0 {
		t.Errorf("provides refs outside the catalogue: %v", unknown)
	}
	return out
}

// The openssl CLI is an application; its libssl* siblings are libraries.
func TestComponentTypeSplitsExecutablesFromLibraries(t *testing.T) {
	got := collect(t, host(
		stanza("openssl", "3.0.13-0ubuntu3.4", "install ok installed")+
			stanza("libssl3t64", "3.0.13-0ubuntu3.4", "install ok installed")+
			stanza("openssh-server", "1:9.6p1-3ubuntu13.5", "install ok installed"),
		ubuntuRelease))
	for name, want := range map[string]cdx.ComponentType{
		"openssl": cdx.ComponentTypeApplication, "libssl3t64": cdx.ComponentTypeLibrary, "openssh-server": cdx.ComponentTypeApplication,
	} {
		if got[name].Component.Type != want {
			t.Errorf("%s typed %q, want %q", name, got[name].Component.Type, want)
		}
	}
}
