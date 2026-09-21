package eval_test

import (
	"strings"
	"testing"

	"github.com/example/cbom-scan/internal/eval"
	"github.com/example/cbom-scan/internal/tlsprobe"
)

func compare(a, b *tlsprobe.Report) eval.Diff {
	return eval.Compare(a, b, eval.Evaluate(a, now), eval.Evaluate(b, now))
}

func find(d eval.Diff, area, kind, subject string) *eval.Change {
	for i := range d.Changes {
		c := &d.Changes[i]
		if c.Area == area && c.Kind == kind && strings.Contains(c.Subject, subject) {
			return c
		}
	}
	return nil
}

func TestIdenticalScansHaveNoChanges(t *testing.T) {
	d := compare(modern(), modern())
	if len(d.Changes) != 0 || d.Summary != "No changes between these scans." || d.Better+d.Worse+d.Neutral != 0 {
		t.Errorf("diff = %+v", d)
	}
	if d.Changes == nil {
		t.Error("Changes must be an empty list, not null, for the API")
	}
}

// AC-07.3: the story a user needs: someone enabled the hybrid group.
func TestEnablingPostQuantumIsBetter(t *testing.T) {
	before := modern()
	before.Groups = []tlsprobe.GroupResult{x25519, p256}
	before.Negotiated = negotiated(x25519)
	after := modern()

	d := compare(before, after)
	if c := find(d, "readiness", "changed", "readiness"); c == nil || c.Impact != eval.Better || !strings.Contains(c.Before, "L1") || !strings.Contains(c.After, "L3") {
		t.Errorf("readiness change = %+v", c)
	}
	if c := find(d, "group", "added", "X25519MLKEM768"); c == nil || c.Impact != eval.Better {
		t.Errorf("group change = %+v", c)
	}
	if c := find(d, "finding", "removed", "PQC.HNDL-EXPOSED"); c == nil || c.Impact != eval.Better {
		t.Errorf("the HNDL finding must be reported as resolved: %+v", d.Changes)
	}
	if d.Worse != 0 || d.Better < 3 {
		t.Errorf("counts better=%d worse=%d", d.Better, d.Worse)
	}
	if !strings.Contains(d.Summary, "better") {
		t.Errorf("summary = %q", d.Summary)
	}
}

func TestRegressionsAreWorse(t *testing.T) {
	before := modern()
	after := modern()
	after.Protocols = protocols("TLSv1.3", "TLSv1.2", "TLSv1.0")
	after.Suites = append(append([]tlsprobe.SuiteResult(nil), after.Suites...),
		suite("TLSv1.0", "TLS_RSA_WITH_3DES_EDE_CBC_SHA", "RSA", "RSA", "3DES", "CBC", 168, 64, false, false))
	after.Groups = []tlsprobe.GroupResult{x25519} // hybrid removed
	after.Negotiated = negotiated(x25519)

	d := compare(before, after)
	for _, want := range []struct{ area, kind, subject string }{
		{"protocol", "added", "TLSv1.0"}, {"suite", "added", "3DES"}, {"group", "removed", "X25519MLKEM768"},
		{"readiness", "changed", "readiness"}, {"hygiene", "changed", "TLS hygiene"},
	} {
		c := find(d, want.area, want.kind, want.subject)
		if c == nil || c.Impact != eval.Worse {
			t.Errorf("%v: %+v", want, c)
		}
	}
	if d.Better != 0 {
		t.Errorf("a pure regression reported %d improvements: %+v", d.Better, d.Changes)
	}
}

func TestProtocolAndSuiteImpactDependOnWhatChanged(t *testing.T) {
	before := &tlsprobe.Report{Protocols: protocols("TLSv1.2", "TLSv1.1"), Suites: []tlsprobe.SuiteResult{gcm128}}
	after := &tlsprobe.Report{Protocols: protocols("TLSv1.3", "TLSv1.2"), Suites: []tlsprobe.SuiteResult{gcm128, gcm256}}
	d := compare(before, after)
	if c := find(d, "protocol", "removed", "TLSv1.1"); c == nil || c.Impact != eval.Better {
		t.Errorf("dropping TLS 1.1 = %+v", c)
	}
	if c := find(d, "protocol", "added", "TLSv1.3"); c == nil || c.Impact != eval.Better {
		t.Errorf("adding TLS 1.3 = %+v", c)
	}
	if c := find(d, "suite", "added", "AES_256_GCM"); c == nil || c.Impact != eval.Neutral {
		t.Errorf("adding a strong suite must be neutral: %+v", c)
	}
}

func TestCertificateRenewalIsNeutralAndVisible(t *testing.T) {
	before, after := modern(), modern()
	after.Certificates = []tlsprobe.CertResult{cert("RSA", 2048, func(c *tlsprobe.CertResult) {
		c.Chain[0].SHA256 = "renewed"
	})}
	d := compare(before, after)
	if c := find(d, "certificate", "changed", "replaced"); c == nil || c.Impact != eval.Neutral || !strings.Contains(c.After, "valid until") {
		t.Errorf("renewal = %+v", d.Changes)
	}
}

func TestIncompleteScansAreFlaggedInTheSummary(t *testing.T) {
	a, b := modern(), modern()
	b.Incomplete = true
	if d := compare(a, b); !strings.Contains(d.Summary, "incomplete") {
		t.Errorf("summary = %q", d.Summary)
	}
}

func TestChangesAreOrderedByImportance(t *testing.T) {
	before := modern()
	after := modern()
	after.Protocols = protocols("TLSv1.3", "TLSv1.2", "TLSv1.0")
	after.Groups = []tlsprobe.GroupResult{x25519}
	after.Negotiated = negotiated(x25519)
	d := compare(before, after)
	order := map[string]int{"readiness": 0, "hygiene": 1, "protocol": 2, "group": 3, "suite": 4, "certificate": 5, "finding": 6}
	for i := 1; i < len(d.Changes); i++ {
		if order[d.Changes[i-1].Area] > order[d.Changes[i].Area] {
			t.Fatalf("changes not ordered: %+v", d.Changes)
		}
	}
	if d.Changes[0].Area != "readiness" {
		t.Errorf("headline change first: %+v", d.Changes[0])
	}
}
