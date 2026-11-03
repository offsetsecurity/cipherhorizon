package refdata

import "github.com/offsetsecurity/cipherhorizon/internal/pki"

// onecrlKey is a key Mozilla blocks through OneCRL (generated into onecrl_gen.go).
type onecrlKey struct {
	SPKI  string // lower-case hex SHA-256 of the SubjectPublicKeyInfo
	Name  string // the subject's common name
	Since string // YYYY-MM-DD the record last changed
	Bug   string // the Bugzilla bug that asked for it
}

// onecrlCert is a CA certificate Mozilla revokes through OneCRL, named by issuer and serial.
type onecrlCert struct {
	Issuer     string // lower-case hex SHA-256 of the issuer Name's DER
	IssuerName string // the issuer's common name, for display
	Serial     string // lower-case hex of the serial number's magnitude
	Since      string
	Bug        string
}

const licenceOneCRL = "Published by Mozilla for Firefox through Remote Settings (public); factual identifiers"

const onecrlIncident = "mozilla-onecrl"

// addOneCRL puts the OneCRL entries on d as root-program blocks. A key already on the
// hand-curated list keeps its own entry, which says why (a compromise, its incident and sources).
func addOneCRL(d *pki.Distrust) {
	for _, k := range onecrlKeys {
		if d.Has(k.SPKI) {
			continue
		}
		d.Add(k.SPKI, nil, onecrlListed(k.Name, k.Since, k.Bug,
			"Mozilla blocks this CA key in Firefox through OneCRL, its list of revoked and distrusted CA certificates."))
	}
	for _, c := range onecrlCerts {
		d.AddIssuerSerial(c.Issuer, c.Serial, onecrlListed("serial "+c.Serial+" issued by "+c.IssuerName, c.Since, c.Bug,
			"Mozilla revokes this CA certificate in Firefox through OneCRL, its list of revoked and distrusted CA certificates."))
	}
}

func onecrlListed(name, since, bug, summary string) pki.Listed {
	l := pki.Listed{Name: name, Kind: pki.KindCADistrust, Incident: onecrlIncident, Title: "Mozilla OneCRL", Since: since,
		Summary: summary}
	if bug != "" {
		l.Sources = []string{bug}
	}
	return l
}

// OneCRLCounts returns how many keys and CA certificates the bundled OneCRL snapshot blocks.
func OneCRLCounts() (keys, certs int) { return len(onecrlKeys), len(onecrlCerts) }
