package server

import (
	"strings"
	"testing"

	"github.com/example/cipherhorizon/internal/store"
)

// FuzzImportSystemsCSV (PRD-007 REQ-TR-6, audit L-15): a systems CSV is a spreadsheet a person
// uploads. Whatever it holds, parsing never panics; every patch it accepts passes the same
// validation the API applies; every problem names its line; and the list of problems is bounded.
func FuzzImportSystemsCSV(f *testing.F) {
	for _, s := range []string{
		"",
		"id\n",
		"name,id\n1,2\n",
		"id,owner,environment,dataLifetimeYears\n1,Payments team,production,10\n2,,,\n",
		"\xef\xbb\xbfid,owner\n1,\"quoted, with comma\"\n",
		"id,owner\n1,'=cmd\n1,again\n",
		"id,owner,owner\n1,a,b\n",
		"id,unknown\n1,x\n",
		"id,dataLifetimeYears\n3,ten\n-1,\n0,\nx,\n",
		"id,owner\n\"1\n",
		"id\r\n1\r\n\r\n2\r\n",
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		patches, problems, refusal := parseSystemsCSV(raw)
		if refusal != "" {
			if len(patches) > 0 || len(problems) > 0 {
				t.Fatalf("a refused file also returned %d patches and %d problems", len(patches), len(problems))
			}
			return
		}
		if len(problems) > 51 {
			t.Fatalf("%d problems: the list must stop at 50", len(problems))
		}
		for _, p := range problems {
			if !strings.HasPrefix(p, "line ") && p != "too many problems; stopping" {
				t.Fatalf("a problem that names no line: %q", p)
			}
		}
		seen := map[int64]bool{}
		for _, p := range patches {
			if p.ID <= 0 || seen[p.ID] {
				t.Fatalf("patch for id %d (seen before: %v)", p.ID, seen[p.ID])
			}
			seen[p.ID] = true
			if err := store.ValidateSystemPatch(p.Patch); err != nil {
				t.Fatalf("an accepted patch fails validation: %v", err)
			}
		}
	})
}
