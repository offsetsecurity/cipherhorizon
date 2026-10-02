package eval_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/example/cipherhorizon/internal/eval"
	"github.com/example/cipherhorizon/internal/tlsprobe"
)

// TestLegacyReportsEvaluate is PRD-004 T1-M7 at the evaluation level: every stored
// tls-report/1 sample from the 0.2.0 runs evaluates under eval/3, says it is a
// legacy report, and marks the sections it cannot fill "not collected".
func TestLegacyReportsEvaluate(t *testing.T) {
	files, _ := filepath.Glob(filepath.Join("..", "..", "artifacts", "samples", "*.report.json"))
	if len(files) == 0 {
		t.Skip("no stored samples")
	}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var rep tlsprobe.Report
		if err := json.Unmarshal(b, &rep); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		if rep.SchemaVersion != tlsprobe.SchemaVersion1 {
			continue
		}
		ev := eval.Evaluate(&rep, time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC))
		if !ev.LegacyReport || len(ev.Sections) != len(eval.SectionOrder) || len(ev.PKI) != 0 {
			t.Errorf("%s: legacy=%v sections=%d pki=%d", f, ev.LegacyReport, len(ev.Sections), len(ev.PKI))
		}
		for _, s := range ev.Sections {
			if s.ID == eval.SecRevocation && s.Status != eval.StatusNotCollected {
				t.Errorf("%s: revocation %s", f, s.Status)
			}
		}
	}
}
