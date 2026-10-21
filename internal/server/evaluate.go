package server

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"runtime/debug"

	"github.com/offsetsecurity/cipherhorizon/internal/eval"
	"github.com/offsetsecurity/cipherhorizon/internal/pki"
	"github.com/offsetsecurity/cipherhorizon/internal/sense/certfiles"
	"github.com/offsetsecurity/cipherhorizon/internal/store"
	"github.com/offsetsecurity/cipherhorizon/internal/tlsprobe"
)

// Evaluation inputs beyond the report (ENG-HANDOFF-003 D-6, D-10, D-11): the
// operator's private anchors (server-wide bundle plus the endpoint's system) and
// the estate-wide index of keys served on SSLv2 endpoints.

// AnchorCert is a parsed CA certificate accepted as a private anchor.
type AnchorCert struct {
	Cert *x509.Certificate
	SHA  string
}

// ParseAnchors reads PEM text under the certificate-only rules: any private-key
// block refuses the whole upload (it is counted, never decoded), and every
// certificate must be a CA. It returns the certificates or a reason.
func ParseAnchors(pemText []byte, max int) ([]AnchorCert, error) {
	r := certfiles.ReadPEMCertificates(pemText)
	switch {
	case r.KeyBlocks > 0:
		return nil, errors.New("the upload contains a private key block; nothing was read. Upload CA certificates only")
	case r.Malformed > 0:
		return nil, errors.New("the upload contains a malformed PEM block")
	case len(r.Certs) == 0:
		return nil, errors.New("no CERTIFICATE block was found")
	case len(r.Certs) > max || r.Truncated:
		return nil, fmt.Errorf("at most %d certificates per upload", max)
	}
	var out []AnchorCert
	for i, der := range r.Certs {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("certificate %d does not parse: %w", i+1, err)
		}
		if !c.BasicConstraintsValid || !c.IsCA {
			return nil, fmt.Errorf("certificate %d (%s) is not a CA certificate; add the CA that issued it instead", i+1, clip(c.Subject.String(), 200))
		}
		sum := sha256.Sum256(c.Raw)
		out = append(out, AnchorCert{Cert: c, SHA: hex.EncodeToString(sum[:])})
	}
	return out, nil
}

// anchorsFor builds the private anchor store for an asset: the server-wide
// bundle plus the anchors of the asset's system. nil when there are none.
func (r *Runner) anchorsFor(assetID int64) *pki.Store {
	var roots []pki.Root
	for _, a := range r.opts.CABundle {
		roots = append(roots, pki.Root{DER: a.Cert.Raw})
	}
	if a, err := r.st.GetAsset(assetID); err == nil && a.SystemID > 0 {
		if ders, err := r.st.TrustAnchorDER(a.SystemID); err == nil {
			for _, d := range ders {
				roots = append(roots, pki.Root{DER: d})
			}
		}
	}
	if len(roots) == 0 {
		return nil
	}
	s, err := pki.NewStore("private", "", false, roots)
	if err != nil {
		return nil
	}
	return s
}

// sslv2Index maps each public key served by an endpoint whose latest scan
// accepted SSLv2 to those endpoints, leaving out the asset being evaluated.
func (r *Runner) sslv2Index(except int64) map[string][]string {
	keys, err := r.st.SSLv2LeafKeys()
	if err != nil {
		r.log.Warn("reading the SSLv2 key index failed; the DROWN shared-key check is skipped", "err", err)
		return nil
	}
	out := map[string][]string{}
	for _, k := range keys {
		if k.AssetID != except {
			out[k.SPKI] = append(out[k.SPKI], k.Address)
		}
	}
	return out
}

// Evaluate judges a report for an asset with every input the server has.
func (r *Runner) Evaluate(rep *tlsprobe.Report, assetID int64) eval.Evaluation {
	return eval.EvaluateWith(rep, eval.Input{Now: r.opts.Now(), Anchors: r.anchorsFor(assetID), SSLv2Keys: r.sslv2Index(assetID)})
}

func resultOf(rep *tlsprobe.Report, ev eval.Evaluation) (store.Result, error) {
	repJSON, err1 := json.Marshal(rep)
	evJSON, err2 := json.Marshal(ev)
	if err1 != nil || err2 != nil {
		return store.Result{}, errors.New("could not encode the result")
	}
	return store.Result{
		Report: repJSON, Evaluation: evJSON, Band: ev.Hygiene.Band, Score: ev.Hygiene.Score, ReadinessLevel: ev.Readiness.Level,
		HNDLExposed: ev.Readiness.HNDLExposed, Critical: ev.Counts[eval.Critical], High: ev.Counts[eval.High],
		Medium: ev.Counts[eval.Medium], Low: ev.Counts[eval.Low], Info: ev.Counts[eval.Info], Incomplete: rep.Incomplete,
		CertNotAfter: leafNotAfter(rep),
	}, nil
}

// Reevaluate recomputes a completed scan's evaluation from its stored report
// with the current anchors, reference data and time. The report is untouched.
//
// A panic while evaluating is returned as an error: this runs at startup over every stored
// report, and one report the rules choke on must not keep the server from starting.
func (r *Runner) Reevaluate(scanID int64, why string) (ev eval.Evaluation, err error) {
	defer func() {
		if v := recover(); v != nil {
			r.log.Error("re-evaluation panicked", "scan", scanID, "panic", v, "stack", string(debug.Stack()))
			ev, err = eval.Evaluation{}, fmt.Errorf("internal error while re-evaluating scan %d", scanID)
		}
	}()
	sc, err := r.st.GetScan(scanID)
	if err != nil {
		return eval.Evaluation{}, err
	}
	if sc.Status != store.StatusDone {
		return eval.Evaluation{}, store.ErrNotFound
	}
	raw, err := r.st.Report(scanID)
	if err != nil {
		return eval.Evaluation{}, err
	}
	dec, err := decodeReport(raw)
	if err != nil {
		return eval.Evaluation{}, fmt.Errorf("stored report unreadable: %w", err)
	}
	old := "unknown"
	if b, err := r.st.Evaluation(scanID); err == nil {
		var v struct {
			Version string `json:"version"`
		}
		if json.Unmarshal(b, &v) == nil && v.Version != "" {
			old = v.Version
		}
	}
	var res store.Result
	label := "TLS"
	if dec.ssh != nil {
		ev, label = r.EvaluateSSH(dec.ssh), "SSH"
		res, err = resultOfSSH(dec.ssh, ev)
	} else {
		ev = r.Evaluate(dec.tls, sc.AssetID)
		res, err = resultOf(dec.tls, ev)
	}
	if err != nil {
		return ev, err
	}
	event := fmt.Sprintf("re-evaluated (%s): %s → %s; %s hygiene %s (%d)", why, old, ev.Version, label, ev.Hygiene.Band, ev.Hygiene.Score)
	if dec.ssh != nil {
		event = fmt.Sprintf("re-evaluated (%s): %s → %s; baseline %s", why, old, ev.Version, baselineWords(ev.Baseline))
	}
	return ev, r.st.ReplaceEvaluation(scanID, res, event)
}

// ReevaluateSystem re-evaluates the latest completed scan of every endpoint of a
// system (after its anchors change). It returns how many were re-evaluated.
func (r *Runner) ReevaluateSystem(systemID int64, why string) int {
	latest, err := r.st.LatestDoneScans(systemID)
	if err != nil {
		r.log.Error("listing scans to re-evaluate failed", "system", systemID, "err", err)
		return 0
	}
	n := 0
	for _, scanID := range latest {
		if _, err := r.Reevaluate(scanID, why); err != nil {
			r.log.Warn("re-evaluating a scan failed", "scan", scanID, "err", err)
		} else {
			n++
		}
	}
	return n
}

// ReevaluateOutdated re-evaluates the latest completed scan of every endpoint whose
// stored evaluation was made by an earlier rule set, so the current view never shows a
// conclusion the current rules would not draw. Older scans keep the evaluation they
// were given (history shows what was concluded then). It returns how many changed.
func (r *Runner) ReevaluateOutdated() int {
	latest, err := r.st.LatestDoneScans(0)
	if err != nil {
		r.log.Error("listing scans to re-evaluate failed", "err", err)
		return 0
	}
	n := 0
	for _, scanID := range latest {
		b, err := r.st.Evaluation(scanID)
		if err != nil {
			continue
		}
		var v struct {
			Version string `json:"version"`
		}
		if json.Unmarshal(b, &v) != nil || v.Version == eval.Version {
			continue
		}
		if _, err := r.Reevaluate(scanID, "rules updated"); err != nil {
			r.log.Warn("re-evaluating a scan failed", "scan", scanID, "err", err)
		} else {
			n++
		}
	}
	return n
}
