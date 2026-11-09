package archtest

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The requirements traceability matrix (docs/engineering/RTM.md) is the only place a
// requirement is declared done. This test keeps it honest: "done" cannot be claimed without
// evidence, and every test it names must exist, so a test cannot be deleted silently.
//
// The product requirements documents the ids come from are internal (they live in the
// product-docs repository), so the matrix is no longer cross-checked against them here.

const (
	rtmPath  = "../../docs/engineering/RTM.md"
	repoRoot = "../.."
)

var testName = regexp.MustCompile(`\b(Test|Fuzz)[A-Za-z0-9_]+\b`)

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
	rows := rtmRows(t)
	if len(rows) < 100 {
		t.Fatalf("only %d requirement rows found in the RTM: has its table format changed?", len(rows))
	}
	seen := map[string]bool{}
	tests := goTestNames(t)
	statuses := map[string]bool{"todo": true, "in-progress": true, "done": true, "deferred": true}

	for _, r := range rows {
		if seen[r.id] {
			t.Errorf("%s appears twice in the RTM", r.id)
		}
		seen[r.id] = true
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
}

// checkEvidenceFiles resolves the file part of script: and oracle: items, which are in this
// repository. A report: item names an internal document and is not resolved here.
func checkEvidenceFiles(t *testing.T, r rtmRow) {
	t.Helper()
	for _, item := range strings.Split(r.evidence, ",") {
		item = strings.TrimSpace(item)
		for _, prefix := range []string{"script:", "oracle:"} {
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

// Every security requirement in the matrix's coverage table names at least one requirement
// that exists in the matrix, so a threat cannot be written down and then left unassigned.
func TestSecurityRequirementsAreCovered(t *testing.T) {
	reqs := map[string]bool{}
	for _, r := range rtmRows(t) {
		reqs[r.id] = true
	}
	reqID := regexp.MustCompile(`REQ-[A-Z]+-\d+`)
	n := 0
	for _, line := range strings.Split(readFile(t, rtmPath), "\n") {
		if !strings.HasPrefix(line, "| SR-") {
			continue
		}
		n++
		cells := strings.Split(strings.Trim(strings.TrimSpace(line), "|"), "|")
		if len(cells) < 3 || strings.TrimSpace(cells[2]) == "" {
			t.Errorf("%s names no requirement or no mutation check", strings.TrimSpace(cells[0]))
			continue
		}
		ids := reqID.FindAllString(cells[1], -1)
		if len(ids) == 0 {
			t.Errorf("%s names no requirement", strings.TrimSpace(cells[0]))
		}
		for _, id := range ids {
			if !reqs[id] {
				t.Errorf("%s is assigned to %s, which is not in the matrix", strings.TrimSpace(cells[0]), id)
			}
		}
	}
	if n == 0 {
		t.Fatal("no security requirement rows found in the RTM coverage table")
	}
}
