package tlscbom_test

import (
	"bytes"
	"crypto/x509"
	"strings"
	"testing"
	"time"

	"github.com/example/cipherhorizon/internal/cbom"
	"github.com/example/cipherhorizon/internal/pki/pkitest"
	"github.com/example/cipherhorizon/internal/schematest"
	"github.com/example/cipherhorizon/internal/tlscbom"
	"github.com/example/cipherhorizon/internal/tlsprobe"
)

// TestCertificateExtensionsOnlyIn17 is PRD-004 REQ-TNFR-7: the certificate facts a
// tls-report/2 records reach the CBOM only where CycloneDX 1.7 has a field for them
// (certificateExtensions), and a 1.6 document, which has none, stays valid without them.
func TestCertificateExtensionsOnlyIn17(t *testing.T) {
	root := pkitest.NewRoot(t, "Root", pkitest.CAOpts{})
	leaf := root.Leaf(t, pkitest.LeafOpts{EKU: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, Policies: []string{"2.23.140.1.2.1"}})
	rep := sampleReport()
	rep.SchemaVersion = tlsprobe.SchemaVersion
	rep.Certificates = []tlsprobe.CertResult{{Source: "tls-default", NameMatches: true,
		Chain: []tlsprobe.CertInfo{tlsprobe.DescribeCertificate(leaf), tlsprobe.DescribeCertificate(root.Cert)}}}
	bom, _ := cbom.Build(tlscbom.FromTLSReport(rep), cbom.Options{
		Tool: cbom.Tool{Name: "cipherhorizon", Version: "test"}, Endpoint: "endpoint.example:443",
		Now:       func() time.Time { return time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC) },
		NewSerial: func() string { return "urn:uuid:00000000-0000-4000-8000-000000000000" },
	})
	for _, spec := range []string{cbom.Spec16, cbom.Spec17} {
		var buf bytes.Buffer
		if err := cbom.EncodeSpec(&buf, bom, spec, true); err != nil {
			t.Fatal(err)
		}
		doc := buf.String()
		schematest.Validate(t, buf.Bytes())
		has := strings.Contains(doc, `"certificateExtensions"`)
		if spec == cbom.Spec17 {
			for _, want := range []string{`"commonExtensionName": "extendedKeyUsage"`, `"commonExtensionValue": "serverAuth"`,
				`"commonExtensionName": "basicConstraints"`, `"commonExtensionValue": "CA:TRUE"`, `"2.23.140.1.2.1"`} {
				if !strings.Contains(doc, want) {
					t.Errorf("1.7 document lacks %s", want)
				}
			}
		} else if has {
			t.Error("1.6 document carries certificateExtensions, which 1.6 does not define")
		}
	}
}
