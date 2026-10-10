package pki

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"time"
)

// MaxOCSPBytes bounds a stapled response.
const MaxOCSPBytes = 64 << 10

// OCSP is a decoded OCSP response (RFC 6960 §4.2.1). Only the fields the
// evaluation reads are kept.
type OCSP struct {
	// Status is the outer responseStatus by its RFC name ("successful",
	// "tryLater", ...). The remaining fields are empty unless it is "successful".
	Status     string
	ProducedAt time.Time
	// ResponderName is the byName responder (an RFC 4514 string); ResponderKeyHash
	// the byKey one. Exactly one is set.
	ResponderName    string
	ResponderKeyHash []byte
	Responses        []SingleResponse
	// Certs are the certificates carried in the response (a delegated responder).
	Certs []*x509.Certificate

	tbs    []byte
	sigAlg asn1.ObjectIdentifier
	sig    []byte
}

// SingleResponse is the status of one certificate.
type SingleResponse struct {
	HashAlg    string // "SHA-1", "SHA-256", ... or the OID
	NameHash   []byte
	KeyHash    []byte
	Serial     *big.Int
	Status     string // "good", "revoked" or "unknown"
	RevokedAt  time.Time
	Reason     int // RFC 5280 CRLReason, -1 when absent
	ThisUpdate time.Time
	NextUpdate time.Time // zero when absent
	SCTs       []SCT
	SCTError   string

	hash crypto.Hash
}

var (
	oidOCSPBasic = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 1}
	oidSHA1      = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	oidSHA256    = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidSHA384    = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	oidSHA512    = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}
)

var responseStatusNames = map[int]string{
	0: "successful", 1: "malformedRequest", 2: "internalError", 3: "tryLater", 5: "sigRequired", 6: "unauthorized",
}

// The ASN.1 shapes of RFC 6960 §4.2.1. The OCSP module uses EXPLICIT tags.
type ocspResponseASN1 struct {
	Status   asn1.Enumerated
	Response responseBytesASN1 `asn1:"explicit,tag:0,optional"`
}

type responseBytesASN1 struct {
	Type     asn1.ObjectIdentifier
	Response []byte
}

type basicResponseASN1 struct {
	TBS       asn1.RawValue
	SigAlg    pkix.AlgorithmIdentifier
	Signature asn1.BitString
	Certs     []asn1.RawValue `asn1:"explicit,tag:0,optional"`
}

type responseDataASN1 struct {
	Version     int `asn1:"optional,explicit,tag:0,default:0"`
	ResponderID asn1.RawValue
	ProducedAt  time.Time `asn1:"generalized"`
	Responses   []singleResponseASN1
	Extensions  []pkix.Extension `asn1:"explicit,tag:1,optional"`
}

type certIDASN1 struct {
	HashAlg  pkix.AlgorithmIdentifier
	NameHash []byte
	KeyHash  []byte
	Serial   *big.Int
}

type revokedInfoASN1 struct {
	Time   time.Time       `asn1:"generalized"`
	Reason asn1.Enumerated `asn1:"explicit,tag:0,optional,default:-1"`
}

type singleResponseASN1 struct {
	CertID     certIDASN1
	Good       asn1.Flag        `asn1:"tag:0,optional"`
	Revoked    revokedInfoASN1  `asn1:"tag:1,optional"`
	Unknown    asn1.Flag        `asn1:"tag:2,optional"`
	ThisUpdate time.Time        `asn1:"generalized"`
	NextUpdate time.Time        `asn1:"generalized,explicit,tag:0,optional"`
	Extensions []pkix.Extension `asn1:"explicit,tag:1,optional"`
}

const maxSingleResponses = 32

func unmarshalAll(b []byte, v any, what string) error {
	rest, err := asn1.Unmarshal(b, v)
	if err != nil {
		return fmt.Errorf("ocsp: %s: %w", what, err)
	}
	if len(rest) != 0 {
		return fmt.Errorf("ocsp: %s: trailing data", what)
	}
	return nil
}

// ParseOCSP decodes a DER OCSP response. It verifies nothing; see Match and
// VerifySignature.
func ParseOCSP(der []byte) (*OCSP, error) {
	if len(der) > MaxOCSPBytes {
		return nil, errors.New("ocsp: response too long")
	}
	var outer ocspResponseASN1
	if err := unmarshalAll(der, &outer, "response"); err != nil {
		return nil, err
	}
	o := &OCSP{Status: responseStatusNames[int(outer.Status)]}
	if o.Status == "" {
		return nil, fmt.Errorf("ocsp: unknown response status %d", outer.Status)
	}
	if o.Status != "successful" {
		return o, nil
	}
	if !outer.Response.Type.Equal(oidOCSPBasic) {
		return nil, fmt.Errorf("ocsp: unsupported response type %v", outer.Response.Type)
	}
	var basic basicResponseASN1
	if err := unmarshalAll(outer.Response.Response, &basic, "basic response"); err != nil {
		return nil, err
	}
	var data responseDataASN1
	if err := unmarshalAll(basic.TBS.FullBytes, &data, "response data"); err != nil {
		return nil, err
	}
	if data.Version != 0 {
		return nil, fmt.Errorf("ocsp: unsupported version %d", data.Version)
	}
	o.tbs, o.sigAlg, o.sig = basic.TBS.FullBytes, basic.SigAlg.Algorithm, basic.Signature.RightAlign()
	o.ProducedAt = data.ProducedAt

	rid := data.ResponderID
	switch {
	case rid.Class == asn1.ClassContextSpecific && rid.Tag == 1 && rid.IsCompound:
		var name pkix.RDNSequence
		if err := unmarshalAll(rid.Bytes, &name, "responder name"); err != nil {
			return nil, err
		}
		var n pkix.Name
		n.FillFromRDNSequence(&name)
		o.ResponderName = n.String()
	case rid.Class == asn1.ClassContextSpecific && rid.Tag == 2 && rid.IsCompound:
		var kh []byte
		if err := unmarshalAll(rid.Bytes, &kh, "responder key hash"); err != nil {
			return nil, err
		}
		o.ResponderKeyHash = kh
	default:
		return nil, errors.New("ocsp: unreadable responder ID")
	}

	if len(data.Responses) == 0 || len(data.Responses) > maxSingleResponses {
		return nil, fmt.Errorf("ocsp: %d single responses", len(data.Responses))
	}
	for _, r := range data.Responses {
		sr := SingleResponse{NameHash: r.CertID.NameHash, KeyHash: r.CertID.KeyHash, Serial: r.CertID.Serial,
			ThisUpdate: r.ThisUpdate, NextUpdate: r.NextUpdate, Reason: -1}
		if sr.Serial == nil {
			return nil, errors.New("ocsp: single response without a serial")
		}
		sr.HashAlg, sr.hash = hashName(r.CertID.HashAlg.Algorithm)
		good, unknown := bool(r.Good), bool(r.Unknown)
		switch {
		case good && !unknown && r.Revoked.Time.IsZero():
			sr.Status = "good"
		case unknown && !good && r.Revoked.Time.IsZero():
			sr.Status = "unknown"
		case !good && !unknown && !r.Revoked.Time.IsZero():
			sr.Status, sr.RevokedAt, sr.Reason = "revoked", r.Revoked.Time, int(r.Revoked.Reason)
		default:
			return nil, errors.New("ocsp: single response has no single status")
		}
		for _, e := range r.Extensions {
			if e.Id.Equal(oidOCSPSCTs) {
				scts, err := parseWrappedList(e.Value)
				if err != nil {
					sr.SCTError = err.Error()
				}
				sr.SCTs = scts
			}
		}
		o.Responses = append(o.Responses, sr)
	}
	if len(basic.Certs) > 4 {
		return nil, fmt.Errorf("ocsp: %d embedded certificates", len(basic.Certs))
	}
	for _, raw := range basic.Certs {
		c, err := x509.ParseCertificate(raw.FullBytes)
		if err != nil {
			return nil, fmt.Errorf("ocsp: embedded certificate: %w", err)
		}
		o.Certs = append(o.Certs, c)
	}
	return o, nil
}

func hashName(oid asn1.ObjectIdentifier) (string, crypto.Hash) {
	switch {
	case oid.Equal(oidSHA1):
		return "SHA-1", crypto.SHA1
	case oid.Equal(oidSHA256):
		return "SHA-256", crypto.SHA256
	case oid.Equal(oidSHA384):
		return "SHA-384", crypto.SHA384
	case oid.Equal(oidSHA512):
		return "SHA-512", crypto.SHA512
	}
	return oid.String(), 0
}

// Match returns the single response for leaf as issued by issuer: the serial is
// equal and the issuer name and key hashes match, computed with the response's
// own hash algorithm. A response naming a hash we cannot compute never matches.
func (o *OCSP) Match(leaf, issuer *x509.Certificate) (*SingleResponse, bool) {
	if o == nil || leaf == nil || issuer == nil {
		return nil, false
	}
	key, err := subjectPublicKeyBits(issuer)
	if err != nil {
		return nil, false
	}
	for i := range o.Responses {
		r := &o.Responses[i]
		if r.hash == 0 || !r.hash.Available() || r.Serial.Cmp(leaf.SerialNumber) != 0 {
			continue
		}
		h := r.hash.New()
		h.Write(issuer.RawSubject)
		nameHash := h.Sum(nil)
		h = r.hash.New()
		h.Write(key)
		if bytes.Equal(nameHash, r.NameHash) && bytes.Equal(h.Sum(nil), r.KeyHash) {
			return r, true
		}
	}
	return nil, false
}

func subjectPublicKeyBits(c *x509.Certificate) ([]byte, error) {
	var spki struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	if err := unmarshalAll(c.RawSubjectPublicKeyInfo, &spki, "issuer key"); err != nil {
		return nil, err
	}
	return spki.PublicKey.RightAlign(), nil
}

// Signature outcomes.
const (
	SigValid       = "valid"
	SigInvalid     = "invalid"
	SigUnsupported = "unsupported"
	SigNoIssuer    = "no-issuer"
)

// sigAlgs maps the signature OIDs we verify to crypto/x509's names. Anything
// else is reported as unsupported, never as valid.
var sigAlgs = map[string]x509.SignatureAlgorithm{
	"1.2.840.113549.1.1.5":  x509.SHA1WithRSA,
	"1.2.840.113549.1.1.11": x509.SHA256WithRSA,
	"1.2.840.113549.1.1.12": x509.SHA384WithRSA,
	"1.2.840.113549.1.1.13": x509.SHA512WithRSA,
	"1.2.840.10045.4.1":     x509.ECDSAWithSHA1,
	"1.2.840.10045.4.3.2":   x509.ECDSAWithSHA256,
	"1.2.840.10045.4.3.3":   x509.ECDSAWithSHA384,
	"1.2.840.10045.4.3.4":   x509.ECDSAWithSHA512,
	"1.3.101.112":           x509.PureEd25519,
}

// VerifySignature checks the response signature: by the issuer itself, or by a
// delegated responder certificate carried in the response that the issuer
// signed and that has the OCSPSigning extended key usage (RFC 6960 §4.2.2.2).
// It returns the outcome and, when delegated, the responder certificate.
func (o *OCSP) VerifySignature(issuer *x509.Certificate) (string, *x509.Certificate) {
	if o == nil || o.tbs == nil {
		return SigInvalid, nil
	}
	if issuer == nil {
		return SigNoIssuer, nil
	}
	alg, ok := sigAlgs[o.sigAlg.String()]
	if !ok {
		return SigUnsupported, nil
	}
	if issuer.CheckSignature(alg, o.tbs, o.sig) == nil {
		return SigValid, nil
	}
	for _, c := range o.Certs {
		if !hasEKU(c, x509.ExtKeyUsageOCSPSigning) || c.CheckSignatureFrom(issuer) != nil {
			continue
		}
		if c.CheckSignature(alg, o.tbs, o.sig) == nil {
			return SigValid, c
		}
	}
	return SigInvalid, nil
}

func hasEKU(c *x509.Certificate, want x509.ExtKeyUsage) bool {
	for _, u := range c.ExtKeyUsage {
		if u == want {
			return true
		}
	}
	return false
}
