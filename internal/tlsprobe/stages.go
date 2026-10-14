package tlsprobe

import "fmt"

// What each stage sends, in words, for the "How we tested" panel.
var (
	probesProtocols = []string{
		"one ClientHello per version (SSLv2, SSLv3, TLS 1.0, 1.1, 1.2, 1.3); a refusal of a large offer is retried with a short conventional one",
	}
	probesSuites = []string{
		"per supported version: offer every candidate suite, note the server's pick, remove it, repeat until refused",
		"TLS 1.3 suites and groups: read from HelloRetryRequests, one at a time",
		"preference: offer adjacent pairs in reverse order to see who decides",
	}
	probesKeyExchange = []string{
		"TLS 1.2 and earlier: offer one ECDHE suite with the remaining curves until refused",
		"one DHE handshake to read the prime's size and fingerprint",
	}
	probesKeyExchange13 = []string{
		"TLS 1.3 groups: an empty key_share for each candidate group, answered by HelloRetryRequest",
	}
	probesSignatures = []string{
		"TLS 1.3: one hello per signature scheme, each offering only that scheme and carrying real key shares; a ServerHello means the server holds a key it can sign with for that scheme",
		"one control hello offering only a private-use scheme no certificate can match: a server that answers it does not choose by scheme, and the stage says so",
	}
	probesFeatures = []string{
		"hello extensions echoed by the server (renegotiation_info, extended_master_secret, session tickets, encrypt_then_mac, status_request)",
		"one hello offering DEFLATE compression",
		"one hello at a lower version with TLS_FALLBACK_SCSV",
	}
	probesCerts = []string{
		"full handshakes with Go's TLS client: the default, then TLS 1.2 limited to ECDSA and to RSA suites to find every certificate",
	}
	probesRevocation = []string{
		"reads the stapled OCSP response and the SCTs the certificate handshakes returned; no CA, OCSP responder or CT log is contacted",
	}
	probesHTTP = []string{
		"one GET / over a fresh TLS connection; reads response headers only and follows no redirect",
	}
)

// stageClock attributes connections to the stage that made them.
type stageClock struct {
	p     *prober
	start int64
}

func (c *stageClock) begin() {
	c.start = c.p.conns.Load()
	c.p.notesMu.Lock()
	c.p.stageIncon = nil
	c.p.notesMu.Unlock()
}

func (c *stageClock) end(name, outcome, reason, code string, probes []string) Stage {
	c.p.notesMu.Lock()
	incon := c.p.stageIncon
	c.p.stageIncon = nil
	c.p.notesMu.Unlock()
	st := Stage{Name: name, Outcome: outcome, Reason: reason, ReasonCode: code,
		Connections: int(c.p.conns.Load() - c.start), Probes: probes, Inconclusive: incon}
	if c.p.budgetHit.Load() && outcome == OutcomeDone {
		st.Inconclusive = append(st.Inconclusive, "the connection budget ran out; some probes were not sent")
		if st.ReasonCode == "" {
			st.ReasonCode = ReasonBudget
		}
	}
	return st
}

func (c *stageClock) skip(name, reason, code string) Stage {
	return Stage{Name: name, Outcome: OutcomeSkipped, Reason: reason, ReasonCode: code}
}

// StageNames lists the stages in page order.
var StageNames = []string{StageProtocols, StageSuites, StageKeyExchange, StageSignatures, StageFeatures, StageCerts, StageRevocation, StageHTTP}

// notReached adds a skipped record for every stage not yet recorded.
func notReached(have []Stage, why string) []Stage {
	done := map[string]bool{}
	for _, s := range have {
		done[s.Name] = true
	}
	for _, n := range StageNames {
		if !done[n] {
			have = append(have, Stage{Name: n, Outcome: OutcomeSkipped, Reason: why, ReasonCode: ReasonNotReached})
		}
	}
	return have
}

// inconclusive records that part of the running stage proved nothing.
func (p *prober) inconclusive(format string, args ...any) {
	p.incomplete.Store(true)
	msg := fmt.Sprintf(format, args...)
	p.notesMu.Lock()
	p.notes = append(p.notes, msg)
	p.stageIncon = append(p.stageIncon, msg)
	p.notesMu.Unlock()
}
