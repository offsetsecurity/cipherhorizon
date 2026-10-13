package archtest

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The requirements traceability matrix (docs/program/RTM.md) is the only place a
// requirement is declared done. These tests keep it honest: it cannot drift from
// the product requirements document, and "done" cannot be claimed without tests
// that exist.

// prdPaths are the product requirements documents whose requirements the matrix traces.
var prdPaths = []string{
	"../../docs/product/PRD-003-cryptographic-estate-model.md",
	"../../docs/product/PRD-004-tls-scanner-t1-pki-depth.md",
	"../../docs/product/PRD-005-product-focus-and-flows.md",
	"../../docs/product/PRD-006-self-evident-results-and-signatures.md",
	"../../docs/product/PRD-007-launch-1-0.md",
	"../../docs/product/PRD-008-pq-signatures-and-ssh.md",
}

const (
	secarchDoc = "../../docs/product/SECARCH-001-threat-model-and-security-requirements.md"
	rtmPath    = "../../docs/program/RTM.md"
	repoRoot   = "../.."
)

var (
	reqDeclared = regexp.MustCompile(`(?m)^\| \*\*(REQ-[A-Z]+-\d+)\*\* \|`)
	srDeclared  = regexp.MustCompile(`\*\*(SR-\d+)\*\*`)
	testName    = regexp.MustCompile(`\b(Test|Fuzz)[A-Za-z0-9_]+\b`)
)

type rtmRow struct {
	id, status, evidence, notes string
}

func readFile(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// rtmRows parses the requirement table of the matrix.
func rtmRows(t *testing.T) []rtmRow {
	t.Helper()
	var rows []rtmRow
	for _, line := range strings.Split(readFile(t, rtmPath), "\n") {
		if !strings.HasPrefix(line, "| REQ-") {
			continue
		}
		cells := strings.Split(strings.Trim(strings.TrimSpace(line), "|"), "|")
		if len(cells) != 8 {
			t.Fatalf("RTM row has %d columns, want 8: %q", len(cells), line)
		}
		for i := range cells {
			cells[i] = strings.TrimSpace(cells[i])
		}
		rows = append(rows, rtmRow{id: cells[0], evidence: cells[5], status: cells[6], notes: cells[7]})
	}
	return rows
}

// goTestNames returns every Test*/Fuzz* function declared in a _test.go file.
func goTestNames(t *testing.T) map[string]bool {
	t.Helper()
	decl := regexp.MustCompile(`(?m)^func ((?:Test|Fuzz)[A-Za-z0-9_]+)\(`)
	names := map[string]bool{}
	err := filepath.WalkDir(repoRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", "dist", "artifacts":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, "_test.go") {
			return nil
		}
		b, rerr := os.ReadFile(path)
		if rerr != nil {
			return rerr
		}
		for _, m := range decl.FindAllStringSubmatch(string(b), -1) {
			names[m[1]] = true
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return names
}

func TestRequirementsTraceability(t *testing.T) {
	declared := map[string]bool{}
	for _, p := range prdPaths {
		n := 0
		for _, m := range reqDeclared.FindAllStringSubmatch(readFile(t, p), -1) {
			if declared[m[1]] {
				t.Errorf("%s is declared by more than one PRD", m[1])
			}
			declared[m[1]] = true
			n++
		}
		if n == 0 {
			t.Fatalf("no requirement ids found in %s: has its table format changed?", p)
		}
	}

	rows := rtmRows(t)
	seen := map[string]bool{}
	tests := goTestNames(t)
	statuses := map[string]bool{"todo": true, "in-progress": true, "done": true, "deferred": true}

	for _, r := range rows {
		if seen[r.id] {
			t.Errorf("%s appears twice in the RTM", r.id)
		}
		seen[r.id] = true
		if !declared[r.id] {
			t.Errorf("%s is in the RTM but not declared in the PRD", r.id)
		}
		if !statuses[r.status] {
			t.Errorf("%s has status %q; want todo, in-progress, done or deferred", r.id, r.status)
		}
		if r.status == "deferred" && r.notes == "" {
			t.Errorf("%s is deferred without a reason in Notes", r.id)
		}
		names := testName.FindAllString(r.evidence, -1)
		for _, n := range names {
			if !tests[n] {
				t.Errorf("%s cites %s, which is not a test in this repository", r.id, n)
			}
		}
		if r.status == "done" && r.evidence == "" {
			t.Errorf("%s is done but lists no evidence", r.id)
		}
		if r.status == "done" && len(names) == 0 && !strings.Contains(r.evidence, "script:") && !strings.Contains(r.evidence, "oracle:") && !strings.Contains(r.evidence, "report:") {
			t.Errorf("%s is done but its evidence names no test, script, oracle or report", r.id)
		}
		checkEvidenceFiles(t, r)
	}
	for id := range declared {
		if !seen[id] {
			t.Errorf("%s is declared in the PRD but has no RTM row", id)
		}
	}
}

// checkEvidenceFiles resolves the file part of script:, oracle: and report: items.
func checkEvidenceFiles(t *testing.T, r rtmRow) {
	t.Helper()
	for _, item := range strings.Split(r.evidence, ",") {
		item = strings.TrimSpace(item)
		for _, prefix := range []string{"script:", "oracle:", "report:"} {
			if !strings.HasPrefix(item, prefix) {
				continue
			}
			file := strings.TrimPrefix(item, prefix)
			if i := strings.Index(file, "#"); i >= 0 {
				file = file[:i]
			}
			if _, err := os.Stat(filepath.Join(repoRoot, filepath.FromSlash(file))); err != nil {
				t.Errorf("%s cites %s but %s does not exist", r.id, item, file)
			}
		}
	}
}

// Every security requirement in SECARCH-001 must be assigned to at least one
// requirement in the matrix's coverage table, so a threat cannot be written down
// and then forgotten.
func TestSecurityRequirementsAreCovered(t *testing.T) {
	declared := map[string]bool{}
	for _, m := range srDeclared.FindAllStringSubmatch(readFile(t, secarchDoc), -1) {
		declared[m[1]] = true
	}
	if len(declared) == 0 {
		t.Fatal("no security requirement ids found in SECARCH-001")
	}
	covered := map[string]bool{}
	for _, line := range strings.Split(readFile(t, rtmPath), "\n") {
		if !strings.HasPrefix(line, "| SR-") {
			continue
		}
		cells := strings.Split(strings.Trim(strings.TrimSpace(line), "|"), "|")
		if len(cells) >= 3 && strings.Contains(cells[1], "REQ-") && strings.TrimSpace(cells[2]) != "" {
			covered[strings.TrimSpace(cells[0])] = true
		}
	}
	for id := range declared {
		if !covered[id] {
			t.Errorf("%s is declared in SECARCH-001 but the RTM coverage table names no requirement and no mutation check for it", id)
		}
	}
	for id := range covered {
		if !declared[id] {
			t.Errorf("%s is in the RTM coverage table but not declared in SECARCH-001", id)
		}
	}
}
