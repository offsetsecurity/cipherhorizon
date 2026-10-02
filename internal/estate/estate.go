// Package estate is the platform-neutral model of a whole cryptographic estate:
// the things found (certificates, algorithms, software, protocol configuration)
// and the observations that say who saw them, how, and how strongly.
//
// It is a projection. The documents the product stores (TLS scan reports, host
// CBOMs, imported CBOMs) remain the source of truth and are never rewritten;
// everything here can be dropped and rebuilt from them (PRD-003 REQ-MOD-1,
// ENG-HANDOFF-002 D1). The package does no I/O and imports no store, operating
// system or network package, so a projection is a pure function that golden
// tests can pin.
//
// Host and network evidence stay separate (ADR-0006): every observation carries
// the stream it came from, and a join between streams is a labelled link, never a
// rewritten claim. Strength reuses the evidence package's classes, so no
// observation here claims more than the rung it rests on.
package estate

import (
	"fmt"
	"strings"

	"github.com/example/cipherhorizon/internal/evidence"
)

// SourceClass says who produced a document and therefore how far it is trusted
// (SECARCH-001 section 2). Trust attaches to the channel, never to what a
// document says about itself.
type SourceClass string

// The source classes.
const (
	ClassScanner   SourceClass = "scanner"   // this server's own TLS prober
	ClassCollector SourceClass = "collector" // this product's collector, over an authenticated channel
	ClassImported  SourceClass = "imported"  // any other document: untrusted, provenance recorded
	ClassOperator  SourceClass = "operator"  // a person, audited
)

// FirstParty reports whether the class is produced by this product's own
// authenticated components. Only first-party data may auto-confirm a link.
func (c SourceClass) FirstParty() bool { return c == ClassScanner || c == ClassCollector }

// Valid reports whether c is a known class.
func (c SourceClass) Valid() bool {
	switch c {
	case ClassScanner, ClassCollector, ClassImported, ClassOperator:
		return true
	}
	return false
}

// Stream says what kind of observation a record is. host and network are the two
// streams of ADR-0006; imported is the third, for third-party documents.
type Stream string

// The streams.
const (
	StreamHost     Stream = "host"
	StreamNetwork  Stream = "network"
	StreamImported Stream = "imported"
)

// Valid reports whether s is a known stream.
func (s Stream) Valid() bool {
	return s == StreamHost || s == StreamNetwork || s == StreamImported
}

// Entity kinds. An entity is a thing with a stable identity that several
// observations, from several sources, can be about.
const (
	KindCertificate = "certificate" // key: SHA-256 fingerprint
	KindAlgorithm   = "algorithm"   // key: evidence.AlgorithmKey
	KindSoftware    = "software"    // key: package URL, else name@version
	KindProvider    = "provider"    // key: evidence.ProviderKey
	KindProtocol    = "protocol"    // a protocol version: SSLv3, TLSv1.2 ...
	KindSuite       = "suite"       // a TLS cipher suite, by IANA code point
	KindGroup       = "group"       // a TLS key-exchange group, by IANA code point
)

// Relations say how a system, through a source, stands to an entity.
const (
	RelPresents   = "presents"   // a service showed this in a handshake (certificate)
	RelOffers     = "offers"     // a service accepts this (protocol, suite, group)
	RelNegotiates = "negotiates" // what a current client actually gets
	RelContains   = "contains"   // a host holds this (software, certificate, provider)
	RelCapable    = "capable"    // something present can perform this algorithm
)

// Method names for observations that are not made by a host sensor. Host sensors
// keep the method IDs declared in the evidence package.
const (
	MethodTLSServerHello = "tls.server-hello@1"
	MethodTLSCertificate = "tls.certificate@1"
	MethodTLSRetry       = "tls.hello-retry@1"
	MethodCBOMImport     = "cbom.document@1"
)

// Method qualities, reused from the evidence package.
const (
	QualityAuthoritative = string(evidence.QualityAuthoritative)
	QualityParsed        = string(evidence.QualityParsed)
	QualityHeuristic     = string(evidence.QualityHeuristic)
	QualitySampled       = string(evidence.QualitySampled)
)

// Entity is a thing found. Key is canonical: the same thing seen by two methods,
// in two documents, has the same Key, which is what lets the graph say "this
// certificate was seen at this endpoint and in that store".
type Entity struct {
	Kind  string
	Key   string
	Name  string
	Attrs map[string]string
}

// Observation is one statement about an entity, made through a source.
type Observation struct {
	Entity   Entity
	Relation string
	// Via is the key of a related entity that explains the observation: for an
	// algorithm "capable" of, the software that provides it.
	Via     string
	Rung    evidence.Rung
	Class   evidence.Class
	Method  string
	Quality string
	// Attrs are attributes of the observation itself, not of the entity.
	Attrs map[string]string
}

// Limits on strings that came from a certificate, a document or a host. They are
// attacker-controlled and are carried as data, never interpreted.
const (
	MaxKeyLen  = 2048
	MaxNameLen = 512
	MaxAttrLen = 1024
)

// entityAttrs and observationAttrs allow-list what may be attached (ADR-0005):
// nothing free-form travels through the graph.
var entityAttrs = map[string]map[string]bool{
	KindCertificate: set("fingerprint", "serial", "subject", "issuer", "notBefore", "notAfter", "keyAlg", "keyBits", "curve", "sigAlg", "isCA", "selfSigned", "dnsNames", "keyUsage",
		"extKeyUsage", "policyClass", "lifetimeDays", "spkiSha256", "cnOnly", "wildcards"),
	KindAlgorithm: set("oid"),
	KindSoftware:  set("version", "purl", "family", "kind", "arch"),
	KindProvider:  set("providerKind"),
	KindProtocol:  set("version"),
	KindSuite:     set("version", "kx", "auth", "cipher", "mac", "aead", "ianaRecommended"),
	KindGroup:     set("version", "pq", "hybrid", "obsolete", "ianaRecommended"),
}

var observationAttrs = set("rank", "position", "location", "version", "origin", "privateKey")

func set(ss ...string) map[string]bool {
	m := make(map[string]bool, len(ss))
	for _, s := range ss {
		m[s] = true
	}
	return m
}

var relations = set(RelPresents, RelOffers, RelNegotiates, RelContains, RelCapable)

// Validate rejects an observation that could carry something it should not. It
// is the second line of defence after the projections' own cleaning: a hostile
// string that got through would be refused here rather than stored.
func Validate(stream Stream, o Observation) error {
	if !stream.Valid() {
		return fmt.Errorf("estate: unknown stream %q", stream)
	}
	allowed, ok := entityAttrs[o.Entity.Kind]
	if !ok {
		return fmt.Errorf("estate: unknown entity kind %q", o.Entity.Kind)
	}
	if o.Entity.Key == "" || len(o.Entity.Key) > MaxKeyLen || !safe(o.Entity.Key, MaxKeyLen) {
		return fmt.Errorf("estate: bad %s key", o.Entity.Kind)
	}
	if !safe(o.Entity.Name, MaxNameLen) {
		return fmt.Errorf("estate: bad %s name", o.Entity.Kind)
	}
	if o.Via != "" && !safe(o.Via, MaxKeyLen) {
		return fmt.Errorf("estate: bad via key")
	}
	for k, v := range o.Entity.Attrs {
		if !allowed[k] {
			return fmt.Errorf("estate: attribute %q is not allowed on a %s", k, o.Entity.Kind)
		}
		if !safe(v, MaxAttrLen) {
			return fmt.Errorf("estate: attribute %q is over %d bytes or not safe text", k, MaxAttrLen)
		}
	}
	for k, v := range o.Attrs {
		if !observationAttrs[k] {
			return fmt.Errorf("estate: observation attribute %q is not allowed", k)
		}
		if !safe(v, MaxAttrLen) {
			return fmt.Errorf("estate: observation attribute %q is over %d bytes or not safe text", k, MaxAttrLen)
		}
	}
	if !relations[o.Relation] {
		return fmt.Errorf("estate: unknown relation %q", o.Relation)
	}
	if o.Method == "" {
		return fmt.Errorf("estate: an observation needs a method")
	}
	switch o.Quality {
	case QualityAuthoritative, QualityParsed, QualityHeuristic, QualitySampled:
	default:
		return fmt.Errorf("estate: unknown method quality %q", o.Quality)
	}
	switch o.Rung {
	case evidence.RungPresent, evidence.RungProvisioned, evidence.RungCapable, evidence.RungPolicy, evidence.RungBound, evidence.RungLoaded, evidence.RungExercised:
	default:
		return fmt.Errorf("estate: unknown rung %q", o.Rung)
	}
	if stream == StreamHost && o.Rung == evidence.RungExercised {
		return fmt.Errorf("estate: a host observation is never %q: observed use is network evidence (ADR-0006)", evidence.RungExercised)
	}
	if stream == StreamImported && (o.Rung == evidence.RungExercised || o.Rung == evidence.RungLoaded || o.Rung == evidence.RungBound) {
		return fmt.Errorf("estate: an imported document cannot establish %q: nothing here observed it (SECARCH-001 SR-18)", o.Rung)
	}
	return nil
}

// safe reports whether s is valid UTF-8 within max bytes with no control characters.
func safe(s string, max int) bool { return evidence.SafeText(s, max) }

// clean makes an untrusted string safe to carry, truncating to max bytes.
func clean(s string, max int) string { return evidence.Clean(strings.TrimSpace(s), max) }

// CertificateKey is the canonical key of a certificate: its SHA-256 fingerprint
// over the DER encoding, lower-case hex.
func CertificateKey(sha256hex string) string { return evidence.CertificateKey(sha256hex) }

// SoftwareKey is the canonical key of a piece of software: its package URL when
// it has one, otherwise its name and version.
func SoftwareKey(purl, name, version string) string {
	if purl != "" {
		return "sw:" + strings.ToLower(purl)
	}
	return "sw:" + strings.ToLower(name) + "@" + version
}

// SuiteKey and GroupKey key TLS registry entries by IANA code point.
func SuiteKey(id uint16) string { return fmt.Sprintf("suite:0x%04x", id) }

// GroupKey is the key of a TLS group by IANA code point.
func GroupKey(id uint16) string { return fmt.Sprintf("group:0x%04x", id) }

// ProtocolKey is the key of a protocol version.
func ProtocolKey(version string) string { return "protocol:" + strings.ToLower(version) }
