package pki

import (
	"bytes"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"strings"
	"time"
)

// CRL status values. Unknown is never a pass: it says the CRL could not answer.
const (
	CRLGood    = "good"
	CRLRevoked = "revoked"
	CRLUnknown = "unknown"
)

// CRL signature results.
const (
	CRLSigValid    = "valid"
	CRLSigInvalid  = "invalid"
	CRLSigNoIssuer = "no-issuer"
)

// CRLResult is what one CRL says about one certificate on a served path. It is
// a status beside the trust verdict, never a gate on it.
type CRLResult struct {
	Position int    `json:"position"` // served index of the certificate checked
	SHA256   string `json:"sha256"`   // the certificate checked
	URL      string `json:"url,omitempty"`

	Status    string    `json:"status"`              // good | revoked | unknown
	Reason    string    `json:"reason,omitempty"`    // the CRL's reason code, when revoked
	RevokedAt time.Time `json:"revokedAt,omitempty"` // when revoked
	// Signature is valid (the certificate's issuer signed the CRL), invalid, or
	// no-issuer (the issuer was not available to check it); empty when the CRL
	// was never read.
	Signature  string    `json:"signature,omitempty"`
	ThisUpdate time.Time `json:"thisUpdate,omitempty"`
	NextUpdate time.Time `json:"nextUpdate,omitempty"`
	Number     string    `json:"crlNumber,omitempty"`
	// Issuer is the SHA-256 of the certificate whose key verified the CRL.
	Issuer string `json:"issuer,omitempty"`

	FetchedAt time.Time `json:"fetchedAt,omitempty"`
	Size      int       `json:"size,omitempty"`
	CRLSHA256 string    `json:"crlSha256,omitempty"`
	// Problem says why the status is unknown (or what else was wrong).
	Problem string `json:"problem,omitempty"`
}

// CRLReasons names RFC 5280 §5.3.1 reason codes.
var CRLReasons = map[int]string{0: "unspecified", 1: "keyCompromise", 2: "cACompromise", 3: "affiliationChanged",
	4: "superseded", 5: "cessationOfOperation", 6: "certificateHold", 8: "removeFromCRL", 9: "privilegeWithdrawn", 10: "aACompromise"}

var (
	oidDeltaCRLIndicator    = asn1.ObjectIdentifier{2, 5, 29, 27}
	oidIssuingDistribution  = asn1.ObjectIdentifier{2, 5, 29, 28}
	oidCRLNumber            = asn1.ObjectIdentifier{2, 5, 29, 20}
	oidAuthorityKeyID       = asn1.ObjectIdentifier{2, 5, 29, 35}
	oidFreshestCRL          = asn1.ObjectIdentifier{2, 5, 29, 46}
	oidExpiredCertsOnCRL    = asn1.ObjectIdentifier{2, 5, 29, 60}
	understoodCRLExtensions = []asn1.ObjectIdentifier{oidDeltaCRLIndicator, oidIssuingDistribution, oidCRLNumber, oidAuthorityKeyID, oidFreshestCRL, oidExpiredCertsOnCRL}
)

// clockSkew is how far in the future a CRL's thisUpdate may be before it is
// treated as not yet issued.
const clockSkew = 5 * time.Minute

// JudgeCRL says what the CRL rl, fetched from url, says about subject, whose
// issuer is issuer (nil when the evaluation does not have it). It checks, in
// order: that the CRL is issued under the subject's issuer name, that the
// issuer's key signed it, that it is not dated in the future, that it is a
// complete CRL whose scope (issuing distribution point) covers the subject,
// and then whether the subject's serial is listed. Anything that stops the CRL
// from answering gives CRLUnknown with the reason in Problem. Staleness
// (nextUpdate passed) is left to evaluation, which knows its own clock.
//
// The caller fills Position, SHA256, FetchedAt, Size and CRLSHA256.
func JudgeCRL(rl *x509.RevocationList, url string, subject, issuer *x509.Certificate, now time.Time) CRLResult {
	r := CRLResult{URL: url, Status: CRLUnknown, ThisUpdate: rl.ThisUpdate, NextUpdate: rl.NextUpdate}
	if rl.Number != nil {
		r.Number = rl.Number.String()
	}
	if !bytes.Equal(rl.RawIssuer, subject.RawIssuer) {
		r.Problem = fmt.Sprintf("the CRL is issued by %q, not by the certificate's issuer; indirect CRLs are not supported", rl.Issuer.String())
		return r
	}
	if issuer == nil {
		r.Signature = CRLSigNoIssuer
		r.Problem = "the certificate's issuer is not available to this scan, so the CRL's signature cannot be checked"
		return r
	}
	if err := rl.CheckSignatureFrom(issuer); err != nil {
		r.Signature = CRLSigInvalid
		r.Problem = "the CRL's signature does not verify under the issuer's key: " + err.Error()
		return r
	}
	r.Signature, r.Issuer = CRLSigValid, Fingerprint(issuer)
	if rl.ThisUpdate.After(now.Add(clockSkew)) {
		r.Problem = fmt.Sprintf("the CRL is dated %s, in the future", rl.ThisUpdate.UTC().Format(time.RFC3339))
		return r
	}
	for _, e := range rl.Extensions {
		switch {
		case e.Id.Equal(oidDeltaCRLIndicator):
			r.Problem = "this is a delta CRL; the complete CRL it updates was not found"
			return r
		case e.Id.Equal(oidIssuingDistribution):
			if why := idpScope(e.Value, url, subject); why != "" {
				r.Problem = why
				return r
			}
		case e.Critical && !understood(e.Id):
			r.Problem = fmt.Sprintf("the CRL has a critical extension %s this scan does not understand", e.Id)
			return r
		}
	}
	for _, e := range rl.RevokedCertificateEntries {
		if e.SerialNumber != nil && subject.SerialNumber != nil && e.SerialNumber.Cmp(subject.SerialNumber) == 0 {
			if e.ReasonCode == 8 { // removeFromCRL: only meaningful in a delta CRL, which is refused above
				continue
			}
			r.Status, r.RevokedAt = CRLRevoked, e.RevocationTime
			if e.ReasonCode != 0 {
				r.Reason = CRLReasons[e.ReasonCode]
				if r.Reason == "" {
					r.Reason = fmt.Sprintf("reason %d", e.ReasonCode)
				}
			}
			return r
		}
	}
	r.Status = CRLGood
	return r
}

func understood(id asn1.ObjectIdentifier) bool {
	for _, u := range understoodCRLExtensions {
		if id.Equal(u) {
			return true
		}
	}
	return false
}

// issuingDistributionPoint is RFC 5280 §5.2.5. distributionPoint is a tagged
// CHOICE (so its [0] wraps the choice element); the booleans are implicitly tagged.
type issuingDistributionPoint struct {
	DistributionPoint asn1.RawValue  `asn1:"optional,tag:0"` // the [0] wrapper; Bytes is the CHOICE
	OnlyUser          bool           `asn1:"optional,tag:1"`
	OnlyCA            bool           `asn1:"optional,tag:2"`
	OnlySomeReasons   asn1.BitString `asn1:"optional,tag:3"`
	Indirect          bool           `asn1:"optional,tag:4"`
	OnlyAttribute     bool           `asn1:"optional,tag:5"`
}

// idpScope returns why a CRL with this issuing distribution point does not
// answer for subject fetched from url, or "" when it does.
func idpScope(der []byte, url string, subject *x509.Certificate) string {
	var idp issuingDistributionPoint
	if rest, err := asn1.Unmarshal(der, &idp); err != nil || len(rest) > 0 {
		return "the CRL's issuing distribution point extension cannot be read"
	}
	switch {
	case idp.Indirect:
		return "the CRL is an indirect CRL; indirect CRLs are not supported"
	case idp.OnlyAttribute:
		return "the CRL covers only attribute certificates"
	case idp.OnlyUser && subject.IsCA:
		return "the CRL covers only end-entity certificates, and this is a CA certificate"
	case idp.OnlyCA && !subject.IsCA:
		return "the CRL covers only CA certificates, and this is an end-entity certificate"
	case idp.OnlySomeReasons.BitLength > 0:
		return "the CRL covers only some revocation reasons, so it cannot say the certificate is not revoked"
	}
	if len(idp.DistributionPoint.Bytes) > 0 {
		uris, ok := fullNameURIs(idp.DistributionPoint.Bytes)
		if !ok {
			return "" // a relative name or other form: the scope is the issuer's, which already matched
		}
		if len(uris) > 0 && !containsFold(uris, url) {
			return fmt.Sprintf("the CRL is the partition for %s, not for %s", strings.Join(uris, ", "), url)
		}
	}
	return ""
}

// fullNameURIs reads the URIs of a DistributionPointName's fullName ([0]
// IMPLICIT GeneralNames). ok is false for nameRelativeToCRLIssuer.
func fullNameURIs(choice []byte) (uris []string, ok bool) {
	var dpn asn1.RawValue
	if _, err := asn1.Unmarshal(choice, &dpn); err != nil || dpn.Class != asn1.ClassContextSpecific || dpn.Tag != 0 {
		return nil, false
	}
	rest := dpn.Bytes
	for len(rest) > 0 {
		var gn asn1.RawValue
		var err error
		if rest, err = asn1.Unmarshal(rest, &gn); err != nil {
			return uris, true
		}
		if gn.Class == asn1.ClassContextSpecific && gn.Tag == 6 { // uniformResourceIdentifier
			uris = append(uris, string(gn.Bytes))
		}
	}
	return uris, true
}

func containsFold(list []string, s string) bool {
	for _, x := range list {
		if strings.EqualFold(x, s) {
			return true
		}
	}
	return false
}
