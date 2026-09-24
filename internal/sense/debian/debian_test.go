package debian

import (
	"context"
	"errors"
	"io/fs"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/example/cipherhorizon/internal/evidence"
	"github.com/example/cipherhorizon/internal/hostinfo"
	"github.com/example/cipherhorizon/internal/sense"
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

func collect(t *testing.T, fsys fs.FS) map[string]evidence.Observation {
	t.Helper()
	batch, err := New(sense.Env{FS: fsys, OS: "linux", Tier: "user"}).Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]evidence.Observation{}
	for _, o := range batch.Observations {
		if err := evidence.Validate(o); err != nil {
			t.Errorf("sensor emitted an invalid observation: %v", err)
		}
		byName[o.Subject.Name] = o
	}
	return byName
}

func TestParseStatus(t *testing.T) {
	// No trailing blank line after the last stanza; continuation lines contain colons.
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

func TestPackagesArePresentObservationsAtAuthoritativeQuality(t *testing.T) {
	got := collect(t, host(
		stanza("libssl3t64", "3.0.13-0ubuntu3.4", "install ok installed")+
			stanza("bash", "5.2.21-2ubuntu4", "install ok installed"),
		ubuntuRelease))

	o, ok := got["libssl3t64"]
	if !ok {
		t.Fatal("libssl3t64 not inventoried")
	}
	if _, found := got["bash"]; found {
		t.Error("non-crypto package inventoried")
	}
	const purl = "pkg:deb/ubuntu/libssl3t64@3.0.13-0ubuntu3.4?arch=amd64&distro=ubuntu-24.04"
	if o.Subject.Key != purl || o.Subject.Kind != evidence.KindPackage {
		t.Errorf("subject = %+v", o.Subject)
	}
	if o.Claim.Rung != evidence.RungPresent || o.Origin != evidence.OriginObserved || o.Method != evidence.MethodDpkgStatus {
		t.Errorf("claim/origin/method = %+v %s %s", o.Claim, o.Origin, o.Method)
	}
	if q, _ := evidence.QualityOf(o); q != evidence.QualityAuthoritative {
		t.Errorf("quality = %s", q)
	}
	for k, want := range map[string]string{"name": "libssl3t64", "version": "3.0.13-0ubuntu3.4", "arch": "amd64", "family": "openssl", "kind": "library", "distro": "ubuntu-24.04"} {
		if o.Subject.Attrs[k] != want {
			t.Errorf("attr %s = %q, want %q", k, o.Subject.Attrs[k], want)
		}
	}
	if o.Source.Location != "var/lib/dpkg/status" || o.Privilege != "user" {
		t.Errorf("source/privilege = %+v %q", o.Source, o.Privilege)
	}
}

// The sensor reports presence only. It must never assert capability: that is
// knowledge applied by derive.
func TestSensorNeverAssertsCapability(t *testing.T) {
	batch, err := New(sense.Env{FS: host(stanza("libssl3t64", "3.5.1-1", "install ok installed"), ubuntuRelease), Tier: "user"}).Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range batch.Observations {
		if o.Claim.Rung != evidence.RungPresent || len(o.Relations) != 0 {
			t.Errorf("sensor asserted more than presence: %+v", o)
		}
	}
}

func TestComponentKindSplitsExecutablesFromLibraries(t *testing.T) {
	got := collect(t, host(
		stanza("openssl", "3.0.13-0ubuntu3.4", "install ok installed")+
			stanza("libssl3t64", "3.0.13-0ubuntu3.4", "install ok installed")+
			stanza("openssh-server", "1:9.6p1-3ubuntu13.5", "install ok installed"),
		ubuntuRelease))
	for name, want := range map[string]string{"openssl": "application", "libssl3t64": "library", "openssh-server": "application"} {
		if got[name].Subject.Attrs["kind"] != want {
			t.Errorf("%s kind = %q, want %q", name, got[name].Subject.Attrs["kind"], want)
		}
	}
}

func TestSkipsRemovedAndDevPackages(t *testing.T) {
	got := collect(t, host(
		stanza("openssl", "3.0.13-0ubuntu3.4", "deinstall ok config-files")+
			stanza("libssl-dev", "3.0.13-0ubuntu3.4", "install ok installed")+
			stanza("libssl-doc", "3.0.13-0ubuntu3.4", "install ok installed"),
		ubuntuRelease))
	if len(got) != 0 {
		t.Errorf("collected %v; want nothing", got)
	}
}

func TestWithoutOSReleaseOmitsPurl(t *testing.T) {
	o := collect(t, host(stanza("libssl3", "3.0.2-0ubuntu1", "install ok installed"), ""))["libssl3"]
	if o.Subject.Key != "apt/libssl3@3.0.2-0ubuntu1/amd64" {
		t.Errorf("fallback key = %q", o.Subject.Key)
	}
}

func TestPurlOmitsDistroWhenVersionIDMissing(t *testing.T) {
	got := purlFor(pkg{Name: "openssl", Version: "3.5.1-1", Arch: "amd64"}, hostinfo.OSRelease{ID: "debian"})
	if want := "pkg:deb/debian/openssl@3.5.1-1?arch=amd64"; got != want {
		t.Errorf("purl = %q, want %q", got, want)
	}
}

func TestMultiArchPackagesGetDistinctKeys(t *testing.T) {
	status := stanza("libssl3", "3.0.13-1", "install ok installed") +
		strings.Replace(stanza("libssl3", "3.0.13-1", "install ok installed"), "amd64", "i386", 1)
	batch, err := New(sense.Env{FS: host(status, ubuntuRelease), Tier: "user"}).Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	keys := map[string]bool{}
	for _, o := range batch.Observations {
		keys[o.Subject.Key] = true
	}
	if len(keys) != 2 {
		t.Errorf("keys = %v, want two distinct", keys)
	}
}

func TestCoverageStatesWhatIsNotSeen(t *testing.T) {
	batch, err := New(sense.Env{FS: host(stanza("libssl3", "3.0.13-1", "install ok installed"), ubuntuRelease), Tier: "user"}).Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(batch.Coverage) != 1 {
		t.Fatalf("coverage = %+v", batch.Coverage)
	}
	c := batch.Coverage[0]
	if c.Status != evidence.CoverageComplete || c.Sensor != Name || c.Method != evidence.MethodDpkgStatus || len(c.Unseen) == 0 {
		t.Errorf("coverage = %+v", c)
	}
	joined := strings.Join(c.Unseen, " | ")
	for _, want := range []string{"statically linked", "bundled", "certificates", "actually does"} {
		if !strings.Contains(joined, want) {
			t.Errorf("unseen list does not mention %q: %s", want, joined)
		}
	}
}

func TestDetect(t *testing.T) {
	ctx := context.Background()
	if ok, err := New(sense.Env{FS: host("", "")}).Detect(ctx); !ok || err != nil {
		t.Errorf("Detect on a dpkg host = %v, %v", ok, err)
	}
	if ok, err := New(sense.Env{FS: fstest.MapFS{}}).Detect(ctx); ok || err != nil {
		t.Errorf("Detect on a non-dpkg host = %v, %v; want false, nil", ok, err)
	}
}

func TestCollectHonoursCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	batch, err := New(sense.Env{FS: host(stanza("libssl3", "3.0.13-1", "install ok installed"), ubuntuRelease)}).Collect(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", err)
	}
	if len(batch.Coverage) != 1 || batch.Coverage[0].Status != evidence.CoveragePartial {
		t.Errorf("a cancelled read must be reported as partial coverage: %+v", batch.Coverage)
	}
}

func TestRegisteredWithDefaultRegistry(t *testing.T) {
	s, err := sense.Default.New(Name, sense.Env{FS: fstest.MapFS{}})
	if err != nil {
		t.Fatal(err)
	}
	if info := s.Info(); info.Name != "apt" || len(info.Methods) != 1 {
		t.Errorf("info = %+v", info)
	}
	if _, err := sense.Default.New(Name, sense.Env{}); err == nil {
		t.Error("nil host FS accepted")
	}
}

func TestOnlyDeclaredMethodsAreUsed(t *testing.T) {
	if err := (&Sensor{}).Info().Validate(); err != nil {
		t.Error(err)
	}
}

// Everything in the status file is host-supplied. A stanza with control characters or
// invalid UTF-8 in a value must still yield a valid observation, not break the run.
func TestHostileStanzaValuesAreCleaned(t *testing.T) {
	status := "Package: libssl3\nStatus: install ok installed\nArchitecture: am\x1bd64\nVersion: 3.0.\xff13\x07-1\n\n"
	got := collect(t, host(status, "ID=ubu\x00ntu\nVERSION_ID=\"24.\xff04\"\n")) // collect validates every observation
	o, ok := got["libssl3"]
	if !ok {
		t.Fatal("the package was dropped")
	}
	for k, v := range o.Subject.Attrs {
		if !evidence.SafeText(v, 1024) {
			t.Errorf("attribute %s = %q is not safe text", k, v)
		}
	}
	if !evidence.SafeText(o.Subject.Key, 2048) {
		t.Errorf("key %q is not safe text", o.Subject.Key)
	}
}
