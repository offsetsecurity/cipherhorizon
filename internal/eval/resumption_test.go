package eval_test

import (
	"strings"
	"testing"

	"github.com/offsetsecurity/cipherhorizon/internal/eval"
	"github.com/offsetsecurity/cipherhorizon/internal/tlsprobe"
)

func resumeCheck(ev eval.Evaluation, id string) string {
	for _, c := range ev.Checks {
		if c.ID == id {
			return c.Result
		}
	}
	return ""
}

func clause(t *testing.T, ev eval.Evaluation, std, id string) eval.RequirementResult {
	t.Helper()
	for _, s := range ev.Standards {
		if s.ID != std {
			continue
		}
		for _, r := range s.Requirements {
			if r.ID == id {
				return r
			}
		}
	}
	t.Fatalf("no clause %s in %s", id, std)
	return eval.RequirementResult{}
}

// The resumption checks and the RFC 9325 clauses follow what the probe recorded, and say "not
// checked" when it did not run.
func TestResumptionChecksAndClauses(t *testing.T) {
	base := func(r *tlsprobe.Resumption) eval.Evaluation {
		rep := terrible()
		rep.Resumption = r
		return eval.Evaluate(rep, now)
	}
	u := func(v uint32) *uint32 { return &v }
	yes := true

	none := base(nil)
	for _, id := range []string{"FEAT.EARLY-DATA", "FEAT.TICKET-LIFETIME"} {
		if got := resumeCheck(none, id); got != "not-checked" {
			t.Errorf("%s without the probe: %q", id, got)
		}
	}
	for _, id := range []string{"ticket-lifetime", "resume-dhe", "early-data"} {
		if got := clause(t, none, "bcp195", id); got.Status != eval.ReqNotAssessed {
			t.Errorf("clause %s without the probe: %+v", id, got)
		}
	}

	good := base(&tlsprobe.Resumption{
		TLS13: &tlsprobe.ResumeResult{Tickets: 2, LifetimeSeconds: u(7200), MaxEarlyData: u(0), Resumed: &yes},
		TLS12: &tlsprobe.ResumeResult{Tickets: 1, LifetimeSeconds: u(0), Resumed: &yes},
	})
	for _, id := range []string{"FEAT.EARLY-DATA", "FEAT.TICKET-LIFETIME"} {
		if got := resumeCheck(good, id); got != "not-found" {
			t.Errorf("%s on a sound server: %q", id, got)
		}
	}
	if got := clause(t, good, "bcp195", "ticket-lifetime"); got.Status != eval.ReqMet || !strings.Contains(got.Detail, "2 hours") {
		t.Errorf("ticket lifetime: %+v", got)
	}
	if got := clause(t, good, "bcp195", "resume-dhe"); got.Status != eval.ReqMet {
		t.Errorf("resumption with a key exchange: %+v", got)
	}
	if got := clause(t, good, "bcp195", "early-data"); got.Status != eval.ReqMet {
		t.Errorf("no early data: %+v", got)
	}

	bad := base(&tlsprobe.Resumption{
		TLS13: &tlsprobe.ResumeResult{Tickets: 2, LifetimeSeconds: u(7200), MaxEarlyData: u(16384), Resumed: &yes},
		TLS12: &tlsprobe.ResumeResult{Tickets: 1, LifetimeSeconds: u(30 * 24 * 3600), Resumed: &yes},
	})
	for _, id := range []string{"FEAT.EARLY-DATA", "FEAT.TICKET-LIFETIME"} {
		if got := resumeCheck(bad, id); got != "found" {
			t.Errorf("%s: %q", id, got)
		}
	}
	if got := clause(t, bad, "bcp195", "ticket-lifetime"); got.Status != eval.ReqNotMet || !strings.Contains(got.Detail, "30 days") {
		t.Errorf("a 30-day ticket: %+v", got)
	}
	// Early data on is not a failure of the RFC by itself: HTTP has a profile for it.
	if got := clause(t, bad, "bcp195", "early-data"); got.Status != eval.ReqNotAssessed || !strings.Contains(got.Detail, "16384") {
		t.Errorf("early data on: %+v", got)
	}

	// Tickets the scan could not read decide nothing.
	unread := base(&tlsprobe.Resumption{TLS13: &tlsprobe.ResumeResult{Tickets: 2, Resumed: &yes, Note: "the tickets' contents could not be read"}})
	if got := resumeCheck(unread, "FEAT.EARLY-DATA"); got != "not-checked" {
		t.Errorf("unread tickets: %q", got)
	}
}
