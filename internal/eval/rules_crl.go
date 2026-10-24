package eval

import (
	"fmt"
	"strings"

	"github.com/offsetsecurity/cipherhorizon/internal/pki"
)

// The CRL rules (CRYPTO-REVIEW-004 P1b) read what the scan's opt-in CRL lookups recorded
// (CertResult.CRL). Revocation is a status beside the trust verdict, never a gate on it: a revoked
// certificate stays on the path, and every other rule still runs. When the scan did not look CRLs
// up, these checks are "not checked", never "passed".

var citBRCRL = Citation{Title: "CA/Browser Forum Baseline Requirements §4.9 (revocation) and §7.2 (CRL profile)",
	URL: "https://cabforum.org/working-groups/server/baseline-requirements/requirements/"}

var crlRules = []rule{
	chainRule("REV.REVOKED", "A certificate on the chain is revoked", "revocation", Critical, []Citation{citRFC5280, citBRCRL},
		"Replace the revoked certificate now: issue a new one (under a CA that is not revoked, when an intermediate is the one revoked) and deploy it with its current chain. Clients that check revocation refuse this chain; those that do not are trusting a certificate its CA has withdrawn.",
		func(c *ctx, ch *chain) (string, Severity, bool) {
			var parts []string
			for _, r := range ch.view.CRL {
				if r.Status != pki.CRLRevoked {
					continue
				}
				s := fmt.Sprintf("%s is revoked", ch.certAt(r.Position))
				if r.Reason != "" {
					s += " (" + r.Reason + ")"
				}
				if !r.RevokedAt.IsZero() {
					s += " since " + fmtDate(r.RevokedAt)
				}
				s += " by the CRL at " + r.URL + ", signed by its issuer"
				if r.Reason == "keyCompromise" || r.Reason == "cACompromise" {
					s += "; its private key is reported compromised, so anyone holding it can sign in its name"
				}
				if r.Position > 0 {
					s += "; everything below it on the chain, the leaf included, is issued under a revoked CA"
				}
				parts = append(parts, s)
			}
			return ch.label() + ": " + strings.Join(parts, "; "), "", len(parts) > 0
		}),
	chainRule("REV.CRL-BAD-SIGNATURE", "A CRL the chain names is not signed by the certificate's issuer", "revocation", High, []Citation{citRFC5280, citBRCRL},
		"Ask the CA: the CRL its certificate points to does not verify under the CA's key, so no client can use it to check revocation. If the address is yours (a private CA), publish there the CRL the CA signs.",
		func(c *ctx, ch *chain) (string, Severity, bool) {
			var parts []string
			for _, r := range ch.view.CRL {
				if r.Signature == pki.CRLSigInvalid {
					parts = append(parts, fmt.Sprintf("the CRL at %s for %s does not verify under its issuer's key", r.URL, ch.certAt(r.Position)))
				}
			}
			return ch.label() + ": " + strings.Join(parts, "; "), "", len(parts) > 0
		}),
	chainRule("REV.CRL-STALE", "A CRL the chain relies on is out of date", "revocation", Medium, []Citation{citRFC5280, citBRCRL},
		"Ask the CA (or, for a private CA, publish a new CRL): the CRL is past the date by which its issuer promised a newer one, so clients that require a current CRL cannot use it.",
		func(c *ctx, ch *chain) (string, Severity, bool) {
			var parts []string
			for _, r := range ch.view.CRL {
				if r.Status == pki.CRLGood && !r.NextUpdate.IsZero() && r.NextUpdate.Before(c.now) {
					parts = append(parts, fmt.Sprintf("the CRL at %s for %s was due to be replaced on %s (nextUpdate)", r.URL, ch.certAt(r.Position), fmtDate(r.NextUpdate)))
				}
			}
			return ch.label() + ": " + strings.Join(parts, "; "), "", len(parts) > 0
		}),
	chainRule("REV.UNKNOWN", "Revocation status could not be determined from a CRL", "revocation", Low, []Citation{citRFC5280, citBRCRL},
		"Check that the CRL address the certificate names is reachable over plain HTTP from where clients run, and that it serves a current CRL its issuer signed. For a private CA on an internal address, allow private CRL addresses (--revocation-private).",
		func(c *ctx, ch *chain) (string, Severity, bool) {
			var parts []string
			for _, pos := range ch.crlPositions() {
				answered, why := false, ""
				for _, r := range ch.view.CRL {
					if r.Position != pos {
						continue
					}
					if r.Status != pki.CRLUnknown {
						answered = true
					}
					if r.Problem != "" {
						why = r.Problem
						if r.URL != "" {
							why = r.URL + ": " + why
						}
					}
				}
				if !answered {
					parts = append(parts, fmt.Sprintf("%s: %s", ch.certAt(pos), why))
				}
			}
			return ch.label() + ": " + strings.Join(parts, "; "), "", len(parts) > 0
		}),
}

// certAt names the served certificate at index pos for a sentence.
func (ch *chain) certAt(pos int) string {
	if pos == 0 {
		return "the leaf"
	}
	if pos < len(ch.cr.Chain) {
		if cn := commonName(ch.cr.Chain[pos].Subject); cn != "" {
			return fmt.Sprintf("intermediate %q", cn)
		}
		return fmt.Sprintf("intermediate %q", ch.cr.Chain[pos].Subject)
	}
	return fmt.Sprintf("served certificate %d", pos)
}

// crlPositions lists, in order, the served positions the CRL lookups recorded anything for.
func (ch *chain) crlPositions() []int {
	var out []int
	seen := map[int]bool{}
	for _, r := range ch.view.CRL {
		if !seen[r.Position] {
			seen[r.Position] = true
			out = append(out, r.Position)
		}
	}
	return out
}

// crlVouches reports whether a CRL lookup says the leaf is not revoked: a CRL signed by its
// issuer, in scope, current at the evaluation time, that does not list it.
func (ch *chain) crlVouches(c *ctx) bool {
	for _, r := range ch.view.CRL {
		if r.Position == 0 && r.Status == pki.CRLGood && r.Signature == pki.CRLSigValid && (r.NextUpdate.IsZero() || !r.NextUpdate.Before(c.now)) {
			return true
		}
	}
	return false
}
