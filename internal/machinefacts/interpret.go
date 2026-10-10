package machinefacts

import (
	"context"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/offsetsecurity/cipherhorizon/internal/cbom"
	"github.com/offsetsecurity/cipherhorizon/internal/collector"
	"github.com/offsetsecurity/cipherhorizon/internal/evidence"
	"github.com/offsetsecurity/cipherhorizon/internal/knowledge"
	"github.com/offsetsecurity/cipherhorizon/internal/sense"
	"github.com/offsetsecurity/cipherhorizon/internal/signatures"
)

// Interpretation of version 2 facts (PRD-006 REQ-SG-5). The signature database says how
// each signature's facts are read: library files go through the collector's knowledge
// base as evidence; configuration becomes CBOM components; anything without its own
// interpreter is recorded as observed configuration, so a new signature needs no code.

// interpretOf returns the signature's interpretation, or "config" for one the database no
// longer (or not yet) has.
func interpretOf(db *signatures.DB, sig string) string {
	if s, ok := db.ByID(sig); ok {
		return s.Interpret
	}
	return "config"
}

func titleOf(db *signatures.DB, sig string) string {
	if s, ok := db.ByID(sig); ok {
		return s.Title
	}
	return sig
}

// ---- library files, through the knowledge base -------------------------------------------

const libraryFilesName = "script-files"

var sha256Hex = regexp.MustCompile(`^[0-9a-f]{64}$`)

// libraryFileSensor turns the files a script found into the same evidence the Windows file
// sensor produces: the file by name, and its version resource as the script read it.
type libraryFileSensor struct {
	items []Item
	tier  string
}

// Info implements sense.Sensor.
func (s *libraryFileSensor) Info() sense.Info {
	return sense.Info{Name: libraryFilesName, Version: "1.0.0", Methods: []string{evidence.MethodFSWalkName, evidence.MethodPEVersion}}
}

// Detect implements sense.Sensor.
func (s *libraryFileSensor) Detect(context.Context) (bool, error) { return len(s.items) > 0, nil }

// Collect implements sense.Sensor.
func (s *libraryFileSensor) Collect(context.Context) (evidence.Batch, error) {
	var batch evidence.Batch
	seen := map[string]bool{}
	for _, it := range s.items {
		if len(it.Fields) < 3 {
			continue
		}
		full := strings.ReplaceAll(it.Fields[0], "\\", "/")
		if i := strings.Index(full, ":/"); i == 1 {
			full = full[3:] // a drive letter: paths are host-relative, as the file sensor records them
		}
		name := path.Base(full)
		fam := knowledge.RecognizeFile(strings.ToLower(name))
		if fam == nil || !evidence.SafeText(full, 1024) {
			continue
		}
		redacted := evidence.RedactPath(full)
		key := evidence.ArtefactKey(redacted)
		if seen[key] {
			continue
		}
		seen[key] = true
		kind := fam.KindForFile(strings.ToLower(name))
		attrs := map[string]string{"path": redacted, "family": fam.ID, "kind": kind, "size": it.Fields[1]}
		if sha256Hex.MatchString(it.Fields[2]) { // anything else from the machine is dropped, not trusted
			attrs["sha256"] = it.Fields[2]
		}
		batch.Observations = append(batch.Observations, s.observe(evidence.MethodFSWalkName, key, name, attrs, redacted))
		if len(it.Fields) >= 4 && it.Fields[3] != "" {
			pa := map[string]string{"path": redacted, "family": fam.ID, "kind": kind, "peValid": "true", "fileVersion": it.Fields[3]}
			if len(it.Fields) >= 5 && it.Fields[4] != "" {
				pa["productName"] = it.Fields[4]
			}
			batch.Observations = append(batch.Observations, s.observe(evidence.MethodPEVersion, key, name, pa, redacted))
		}
	}
	batch.Coverage = []evidence.Coverage{{Sensor: libraryFilesName, Method: evidence.MethodFSWalkName, Status: evidence.CoverageComplete,
		Scope:  "cryptographic library files the inventory script found by name",
		Unseen: []string{"libraries under names the signature database does not list", "cryptography linked statically into programs"}}}
	return batch, nil
}

func (s *libraryFileSensor) observe(method, key, name string, attrs map[string]string, location string) evidence.Observation {
	o := evidence.Observation{
		Stream: evidence.StreamHost, Origin: evidence.OriginObserved,
		Subject: evidence.Subject{Kind: evidence.KindArtefact, Key: key, Name: name, Attrs: attrs},
		Claim:   evidence.Claim{Rung: evidence.RungPresent}, Outcome: evidence.OutcomeObserved,
		Method: method, Source: evidence.Source{Kind: "file", Location: location},
		Privilege: s.tier,
	}
	evidence.Finish(&o)
	return o
}

// ---- configuration, as CBOM components ----------------------------------------------------

type configBuilder struct {
	db     *signatures.DB
	assets []collector.CryptoAsset
	refs   map[string]bool
	props  []cdx.Property
}

func (b *configBuilder) add(a collector.CryptoAsset) {
	if b.refs[a.Component.BOMRef] {
		return
	}
	b.refs[a.Component.BOMRef] = true
	b.assets = append(b.assets, a)
}

func prop(name, value string) cdx.Property { return cbom.Property(name, value) }

func refSafe(s string) string {
	return strings.Trim(regexp.MustCompile(`[^a-z0-9.+-]+`).ReplaceAllString(strings.ToLower(s), "-"), "-")
}

// algorithm adds (once) an algorithm component a configuration names.
func (b *configBuilder) algorithm(name string, prim cdx.CryptoPrimitive, configuredAs, source string) string {
	ref := "config/algorithm/" + refSafe(name)
	if !b.refs[ref] {
		b.add(collector.CryptoAsset{Component: cdx.Component{
			BOMRef: ref, Type: cdx.ComponentTypeCryptographicAsset, Name: name,
			CryptoProperties: &cdx.CryptoProperties{AssetType: cdx.CryptoAssetTypeAlgorithm, AlgorithmProperties: &cdx.CryptoAlgorithmProperties{Primitive: prim}},
			Properties:       &[]cdx.Property{prop("configured-as", configuredAs), prop("config-source", source)},
		}})
	}
	return ref
}

func protocolComponent(ref, name string, typ cdx.CryptoProtocolType, props []cdx.Property, suites []cdx.CipherSuite) collector.CryptoAsset {
	pp := &cdx.CryptoProtocolProperties{Type: typ}
	if len(suites) > 0 {
		pp.CipherSuites = &suites
	}
	return collector.CryptoAsset{Component: cdx.Component{
		BOMRef: ref, Type: cdx.ComponentTypeCryptographicAsset, Name: name,
		CryptoProperties: &cdx.CryptoProperties{AssetType: cdx.CryptoAssetTypeProtocol, ProtocolProperties: pp},
		Properties:       &props,
	}}
}

var schannelPath = regexp.MustCompile(`(?i)\\SCHANNEL\\(Protocols|Ciphers|Hashes|KeyExchangeAlgorithms)\\([^\\]+)(?:\\(Server|Client))?$`)

// build interprets the configuration items into components and metadata properties.
func (b *configBuilder) build(items []Item) {
	byInterp := map[string][]Item{}
	for _, it := range items {
		byInterp[interpretOf(b.db, it.Sig)] = append(byInterp[interpretOf(b.db, it.Sig)], it)
	}

	// Windows Schannel: one protocol component with what is set explicitly.
	var sch []cdx.Property
	var suites []cdx.CipherSuite
	for _, it := range append(append(byInterp["schannel-protocols"], byInterp["schannel-ciphers"]...), byInterp["schannel-suite-order"]...) {
		if it.Kind != "registry" || len(it.Fields) < 3 {
			continue
		}
		key, name, value := it.Fields[0], it.Fields[1], it.Fields[2]
		if strings.EqualFold(name, "Functions") {
			for _, s := range strings.Split(value, ",") {
				if s = strings.TrimSpace(s); s != "" {
					suites = append(suites, cdx.CipherSuite{Name: s})
				}
			}
			continue
		}
		if strings.EqualFold(name, "EccCurves") {
			sch = append(sch, prop("schannel:curves", value))
			continue
		}
		m := schannelPath.FindStringSubmatch(key)
		if m == nil {
			continue
		}
		what := m[2]
		if m[3] != "" {
			what += " (" + strings.ToLower(m[3]) + ")"
		}
		state := value
		switch {
		case strings.EqualFold(name, "Enabled") && value == "0":
			state = "disabled"
		case strings.EqualFold(name, "Enabled"):
			state = "enabled"
		case strings.EqualFold(name, "DisabledByDefault") && value != "0":
			state = "disabled by default"
		case strings.EqualFold(name, "DisabledByDefault"):
			state = "enabled by default"
		}
		sch = append(sch, prop("schannel:"+strings.ToLower(m[1]), what+": "+state))
	}
	if len(sch) > 0 || len(suites) > 0 {
		props := append([]cdx.Property{prop("config-source", "Windows registry (Schannel)")}, sch...)
		if len(suites) > 0 {
			props = append(props, prop("schannel:suite-order", "set on this machine (otherwise the Windows default applies)"))
		} else {
			props = append(props, prop("schannel:suite-order", "Windows default"))
		}
		b.add(protocolComponent("config/protocol/windows-schannel", "Windows Schannel (TLS)", cdx.CryptoProtocolTypeTLS, props, suites))
	}

	// SSH servers: the configured algorithms, and the host key types.
	sshMap := b.db.Maps["ssh"]
	mapped := func(n string) string {
		if m, ok := sshMap[n]; ok {
			return m
		}
		return n
	}
	sshBySource := map[string][]Item{}
	for _, it := range append(byInterp["ssh-config"], byInterp["ssh-host-key"]...) {
		if it.Kind == "line" && len(it.Fields) >= 2 {
			sshBySource[it.Fields[0]] = append(sshBySource[it.Fields[0]], it)
		}
	}
	sources := make([]string, 0, len(sshBySource))
	for s := range sshBySource {
		sources = append(sources, s)
	}
	sort.Strings(sources)
	var sshRefs []string
	var sshProps []cdx.Property
	for _, src := range sources {
		for _, it := range sshBySource[src] {
			f := strings.Fields(it.Fields[1])
			if len(f) < 2 {
				continue
			}
			if interpretOf(b.db, it.Sig) == "ssh-host-key" {
				alg := mapped(f[0])
				ar := b.algorithm(alg, cdx.CryptoPrimitiveSignature, f[0], src)
				sshRefs = append(sshRefs, ar)
				kr := "config/ssh/host-key/" + refSafe(f[0])
				b.add(collector.CryptoAsset{Component: cdx.Component{
					BOMRef: kr, Type: cdx.ComponentTypeCryptographicAsset, Name: "SSH host key (" + f[0] + ")",
					CryptoProperties: &cdx.CryptoProperties{AssetType: cdx.CryptoAssetTypeRelatedCryptoMaterial,
						RelatedCryptoMaterialProperties: &cdx.RelatedCryptoMaterialProperties{Type: cdx.RelatedCryptoMaterialTypePublicKey, AlgorithmRef: cdx.BOMReference(ar)}},
					Properties: &[]cdx.Property{prop("config-source", src)},
				}})
				sshRefs = append(sshRefs, kr)
				continue
			}
			directive := f[0]
			prim := map[string]cdx.CryptoPrimitive{"kexalgorithms": cdx.CryptoPrimitiveKeyAgree, "ciphers": cdx.CryptoPrimitiveAE, "macs": cdx.CryptoPrimitiveMAC,
				"hostkeyalgorithms": cdx.CryptoPrimitiveSignature, "pubkeyacceptedalgorithms": cdx.CryptoPrimitiveSignature}[strings.ToLower(directive)]
			sshProps = append(sshProps, prop("ssh:"+strings.ToLower(directive), strings.Join(f[1:], " ")))
			for _, n := range strings.Split(strings.TrimLeft(f[1], "+-^"), ",") {
				if n == "" {
					continue
				}
				p := prim
				if strings.Contains(n, "mlkem") || strings.Contains(n, "sntrup") {
					p = cdx.CryptoPrimitiveCombiner
				}
				sshRefs = append(sshRefs, b.algorithm(mapped(n), p, n, src))
			}
		}
	}
	if len(sources) > 0 {
		props := append([]cdx.Property{prop("config-source", strings.Join(sources, ", "))}, sshProps...)
		a := protocolComponent("config/protocol/ssh-server", "SSH server (OpenSSH)", cdx.CryptoProtocolTypeSSH, props, nil)
		a.Provides = dedupe(sshRefs)
		b.add(a)
	}

	// OpenSSL system defaults.
	var osl []cdx.Property
	var oslSrc []string
	for _, it := range byInterp["openssl-config"] {
		if it.Kind == "line" && len(it.Fields) >= 2 {
			k, v, ok := strings.Cut(it.Fields[1], "=")
			if ok {
				osl = append(osl, prop("openssl:"+strings.ToLower(strings.TrimSpace(k)), strings.TrimSpace(v)))
				oslSrc = append(oslSrc, it.Fields[0])
			}
		}
	}
	if len(osl) > 0 {
		props := append([]cdx.Property{prop("config-source", strings.Join(dedupe(oslSrc), ", "))}, osl...)
		b.add(protocolComponent("config/protocol/openssl-defaults", "OpenSSL system defaults (TLS)", cdx.CryptoProtocolTypeTLS, props, nil))
	}

	// System crypto policy.
	for _, it := range byInterp["crypto-policy"] {
		if it.Kind == "line" && len(it.Fields) >= 2 {
			b.props = append(b.props, prop("crypto-policy", strings.TrimSpace(it.Fields[1])))
		}
	}

	// Installed programs that bring their own cryptography.
	for _, it := range byInterp["software"] {
		if it.Kind != "program" || len(it.Fields) < 1 || it.Fields[0] == "" {
			continue
		}
		c := cdx.Component{BOMRef: "software/" + refSafe(it.Fields[0]), Type: cdx.ComponentTypeApplication, Name: it.Fields[0]}
		if len(it.Fields) >= 2 {
			c.Version = it.Fields[1]
		}
		ps := []cdx.Property{prop("collected-by", it.Sig)}
		if len(it.Fields) >= 3 && it.Fields[2] != "" {
			ps = append(ps, prop("publisher", it.Fields[2]))
		}
		c.Properties = &ps
		b.add(collector.CryptoAsset{Component: c})
	}

	// Everything else is recorded as observed configuration (REQ-SG-5): a new signature
	// reaches the CBOM without code.
	for interp, list := range byInterp {
		switch interp {
		case "schannel-protocols", "schannel-ciphers", "schannel-suite-order", "ssh-config", "ssh-host-key", "openssl-config", "crypto-policy", "software", "library-file":
			continue
		}
		for _, it := range list {
			b.props = append(b.props, prop("observed-config", fmt.Sprintf("%s: %s", titleOf(b.db, it.Sig), strings.Join(it.Fields, " = "))))
		}
	}
}

// coverage records, per signature, what it returned or why it could not (REQ-SG-6).
func coverage(db *signatures.DB, f *Facts) []cdx.Property {
	ids := map[string]bool{}
	for id := range f.Ran {
		ids[id] = true
	}
	for id := range f.Skipped {
		ids[id] = true
	}
	sorted := make([]string, 0, len(ids))
	for id := range ids {
		sorted = append(sorted, id)
	}
	sort.Strings(sorted)
	var out []cdx.Property
	for _, id := range sorted {
		n := f.Ran[id]
		if reason, ok := f.Skipped[id]; ok && n == 0 {
			out = append(out, prop("coverage", fmt.Sprintf("sensor=%s status=complete scope=%s: %s", id, titleOf(db, id), reason)))
			continue
		}
		out = append(out, prop("coverage", fmt.Sprintf("sensor=%s status=complete scope=%s: %s", id, titleOf(db, id), plural(n, "item"))))
	}
	return out
}

func plural(n int, one string) string {
	if n == 1 {
		return "1 " + one
	}
	return strconv.Itoa(n) + " " + one + "s"
}

func dedupe(ss []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range ss {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
