package machinefacts

import (
	"context"
	"fmt"
	"strings"
	"testing/fstest"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/package-url/packageurl-go"

	"github.com/example/cipherhorizon/internal/cbom"
	"github.com/example/cipherhorizon/internal/discover"
	"github.com/example/cipherhorizon/internal/evidence"
	"github.com/example/cipherhorizon/internal/hostinfo"
	"github.com/example/cipherhorizon/internal/knowledge"
	"github.com/example/cipherhorizon/internal/pqc"
	"github.com/example/cipherhorizon/internal/sense"
	"github.com/example/cipherhorizon/internal/sense/certfiles"
	"github.com/example/cipherhorizon/internal/sense/debian"
	"github.com/example/cipherhorizon/internal/sense/wincerts"
	"github.com/example/cipherhorizon/internal/signatures"
	"github.com/example/cipherhorizon/internal/winapi"
)

// Options describe the conversion.
type Options struct {
	ToolVersion string
	Now         func() time.Time
}

// ToCBOM converts facts into a CycloneDX CBOM with post-quantum annotations, using
// the collector's sensors on an in-memory copy of what the script gathered. Only
// sensors fed from the facts are registered: nothing on the server's own machine is
// ever read.
func ToCBOM(ctx context.Context, f *Facts, o Options) (*cdx.BOM, error) {
	if o.Now == nil {
		o.Now = time.Now
	}
	tier := hostinfo.TierUser
	if f.Privilege == "admin" {
		tier = hostinfo.TierAdmin
	}
	fsys := fstest.MapFS{}
	if len(f.OSRelease) > 0 {
		fsys["etc/os-release"] = &fstest.MapFile{Data: f.OSRelease}
	}
	var dpkg strings.Builder
	var others []Package
	for _, p := range f.Packages {
		if p.Manager == "dpkg" {
			fmt.Fprintf(&dpkg, "Package: %s\nStatus: install ok installed\nVersion: %s\nArchitecture: %s\n\n", oneLine(p.Name), oneLine(p.Version), oneLine(p.Arch))
		} else {
			others = append(others, p)
		}
	}
	if dpkg.Len() > 0 || f.hasManager("dpkg") {
		fsys["var/lib/dpkg/status"] = &fstest.MapFile{Data: []byte(dpkg.String())}
	}
	for _, c := range f.CertFiles {
		fsys[c.Path] = &fstest.MapFile{Data: c.Data}
	}

	reg := sense.NewRegistry()
	must := func(err error) {
		if err != nil {
			panic(err) // registering fixed names into a new registry cannot fail
		}
	}
	if f.OS == "linux" {
		must(reg.Register(debian.Name, func(env sense.Env) (sense.Sensor, error) { return debian.New(env), nil }))
		must(reg.Register(certfiles.Name, func(env sense.Env) (sense.Sensor, error) { return certfiles.New(env), nil }))
		must(reg.Register(packagesName, func(env sense.Env) (sense.Sensor, error) {
			return &packageSensor{facts: f, others: others, tier: env.Tier}, nil
		}))
	}
	if f.OS == "windows" {
		must(reg.Register(wincerts.Name, func(env sense.Env) (sense.Sensor, error) { return wincerts.New(env, storeFacts(f.StoreCerts)), nil }))
	}
	db := signatures.MustLoad()
	var libs []Item
	for _, it := range f.Items {
		if it.Kind == "file" && interpretOf(db, it.Sig) == "library-file" {
			libs = append(libs, it)
		}
	}
	if len(libs) > 0 {
		must(reg.Register(libraryFilesName, func(env sense.Env) (sense.Sensor, error) { return &libraryFileSensor{items: libs, tier: env.Tier}, nil }))
	}

	res, err := discover.Run(ctx, reg, discover.Options{
		FS: fsys, OS: f.OS, Tier: tier, HostName: f.Name,
		// Live only lets the fact-backed Windows certificate sensor answer; no sensor that
		// reads this server is registered.
		Live:    true,
		Timeout: 30 * time.Second,
	})
	if err != nil {
		return nil, err
	}
	// The host description must come from the facts, not from the server's own system.
	res.Graph.Host.Arch = ""
	if f.OS == "windows" {
		res.Graph.Host.OSVersion = f.OSVersion
		res.Graph.Host.ID = ""
	}

	assets, props, err := cbom.FromHostGraph(res.Graph, cbom.HostOptions{PrivilegeNote: res.PrivilegeNote})
	if err != nil {
		return nil, err
	}
	// Configuration the signatures collected becomes components and properties of its own.
	cb := &configBuilder{db: db, refs: map[string]bool{}}
	for _, a := range assets {
		cb.refs[a.Component.BOMRef] = true
	}
	cb.build(f.Items)
	assets = append(assets, cb.assets...)
	props = append(props, cb.props...)
	props = append(props, coverage(db, f)...)
	if f.SignatureDB != "" {
		props = append(props, cbom.Property("signature-db", f.SignatureDB))
	}
	script := strings.TrimSpace(f.Script + " " + f.ScriptVersion)
	if script != "" {
		props = append(props, cbom.Property("collected-by", "inventory script "+script))
	}
	if f.Dropped > 0 {
		props = append(props, cbom.Property("coverage-note", fmt.Sprintf("%d entries in the facts file were refused (unreadable, too large, or holding private key material) and are not in this inventory.", f.Dropped)))
	}
	for _, n := range f.Notes {
		props = append(props, cbom.Property("script-note", n))
	}
	if f.OS == "windows" {
		props = append(props, cbom.Property("not-seen", "Windows CNG algorithms and providers, and the import tables of program files: the script does not collect them (the Go collector can, built from source)"))
	}
	bom, _ := cbom.Build(assets, cbom.Options{
		Tool:               cbom.Tool{Name: "cipherhorizon", Version: o.ToolVersion},
		HostName:           res.Graph.Host.Name,
		MetadataProperties: props,
		Now:                o.Now,
	})
	pqc.Annotate(bom, pqc.Analyze(bom))
	return bom, nil
}

func oneLine(s string) string { return strings.NewReplacer("\n", " ", "\r", " ").Replace(s) }

func (f *Facts) hasManager(m string) bool {
	for _, n := range f.Managers {
		if n == m {
			return true
		}
	}
	return false
}

// ---- RPM and Alpine packages ----------------------------------------------------------------

const packagesName = "packages"

// packageSensor reports crypto-relevant RPM and Alpine packages from the script's list,
// the way the dpkg sensor reports Debian ones.
type packageSensor struct {
	facts  *Facts
	others []Package
	tier   string
}

// Info implements sense.Sensor.
func (s *packageSensor) Info() sense.Info {
	return sense.Info{Name: packagesName, Version: "1.0.0", Methods: []string{evidence.MethodRPMQuery, evidence.MethodAPKInstalled}}
}

// Detect implements sense.Sensor: the script listed rpm or apk packages.
func (s *packageSensor) Detect(context.Context) (bool, error) {
	return len(s.others) > 0 || s.facts.hasManager("rpm") || s.facts.hasManager("apk"), nil
}

// Collect implements sense.Sensor.
func (s *packageSensor) Collect(context.Context) (evidence.Batch, error) {
	var batch evidence.Batch
	osr := hostinfo.ReadOSRelease(fstest.MapFS{"etc/os-release": &fstest.MapFile{Data: s.facts.OSRelease}})
	managers := map[string]bool{}
	for _, p := range s.others {
		managers[p.Manager] = true
		fam := knowledge.RecognizePackage(p.Name)
		if fam == nil {
			continue
		}
		method, purlType, where := evidence.MethodRPMQuery, packageurl.TypeRPM, "rpm database (rpm -qa)"
		if p.Manager == "apk" {
			method, purlType, where = evidence.MethodAPKInstalled, packageurl.TypeApk, "apk database (apk info)"
		}
		name, version, arch := evidence.Clean(p.Name, 128), evidence.Clean(p.Version, 128), evidence.Clean(p.Arch, 32)
		q := map[string]string{}
		if arch != "" {
			q["arch"] = arch
		}
		if osr.ID != "" && osr.VersionID != "" {
			q["distro"] = osr.ID + "-" + osr.VersionID
		}
		ns := osr.ID
		if ns == "" {
			ns = p.Manager
		}
		key := packageurl.NewPackageURL(purlType, ns, name, version, packageurl.QualifiersFromMap(q), "").ToString()
		o := evidence.Observation{
			Stream: evidence.StreamHost, Origin: evidence.OriginObserved,
			Subject: evidence.Subject{Kind: evidence.KindPackage, Key: key, Name: name,
				Attrs: map[string]string{"name": name, "version": version, "arch": arch, "family": fam.ID, "kind": fam.KindFor(name)}},
			Claim: evidence.Claim{Rung: evidence.RungPresent}, Outcome: evidence.OutcomeObserved,
			Method: method, Source: evidence.Source{Kind: "database", Location: where}, Privilege: s.tier,
		}
		evidence.Finish(&o)
		batch.Observations = append(batch.Observations, o)
	}
	for m := range managers {
		method, scope := evidence.MethodRPMQuery, "installed packages (rpm database, listed by the inventory script)"
		if m == "apk" {
			method, scope = evidence.MethodAPKInstalled, "installed packages (apk database, listed by the inventory script)"
		}
		batch.Coverage = append(batch.Coverage, evidence.Coverage{Sensor: packagesName, Method: method, Scope: scope, Status: evidence.CoverageComplete,
			Unseen: []string{"software not installed through the package manager", "cryptography statically linked into applications or bundled inside them",
				"what any installed software actually does: a package being installed says nothing about use"}})
	}
	return batch, nil
}

// ---- Windows certificate stores --------------------------------------------------------------

// storeFacts answers the Windows certificate sensor from the facts file.
type storeFacts []StoreCert

// Native implements winapi.CertStoreAPI: the facts stand in for this machine's stores.
func (storeFacts) Native() bool { return true }

// CertStore implements winapi.CertStoreAPI from the uploaded store certificates.
func (s storeFacts) CertStore(loc winapi.StoreLocation, name string) ([]winapi.StoreCert, int, error) {
	var out []winapi.StoreCert
	for _, c := range s {
		if strings.EqualFold(c.Location, string(loc)) && strings.EqualFold(c.Store, name) {
			out = append(out, winapi.StoreCert{DER: c.DER, PrivateKey: c.PrivateKey})
		}
	}
	return out, 0, nil
}
