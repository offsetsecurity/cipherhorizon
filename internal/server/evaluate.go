package server

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/example/cipherhorizon/internal/eval"
	"github.com/example/cipherhorizon/internal/pki"
	"github.com/example/cipherhorizon/internal/sense/certfiles"
	"github.com/example/cipherhorizon/internal/store"
	"github.com/example/cipherhorizon/internal/tlsprobe"
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
	latest, err := r.st.LatestDoneScans(0)
	if err != nil {
		return nil
	}
	out := map[string][]string{}
	for assetID, scanID := range latest {
		if assetID == except {
			continue
		}
		raw, err := r.st.Report(scanID)
		if err != nil {
			continue
		}
		var rep struct {
			Protocols []struct {
				Version   string `json:"version"`
				Supported bool   `json:"supported"`
			} `json:"protocols"`
			Certificates []struct {
				Chain []struct {
					SPKI string `json:"spkiSha256"`
				} `json:"chain"`
			} `json:"certificates"`
		}
		if json.Unmarshal(raw, &rep) != nil {
			continue
		}
		v2 := false
		for _, p := range rep.Protocols {
			v2 = v2 || p.Version == "SSLv2" && p.Supported
		}
		if !v2 {
			continue
		}
		name := fmt.Sprintf("asset %d", assetID)
		if a, err := r.st.GetAsset(assetID); err == nil {
			name = a.Address()
		}
		for _, c := range rep.Certificates {
			if len(c.Chain) > 0 && c.Chain[0].SPKI != "" {
				out[c.Chain[0].SPKI] = append(out[c.Chain[0].SPKI], name)
			}
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
		Medium: ev.Counts[eval.Medium], Incomplete: rep.Incomplete,
	}, nil
}

// Reevaluate recomputes a completed scan's evaluation from its stored report
// with the current anchors, reference data and time. The report is untouched.
func (r *Runner) Reevaluate(scanID int64, why string) (eval.Evaluation, error) {
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
	var rep tlsprobe.Report
	if err := json.Unmarshal(raw, &rep); err != nil {
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
	ev := r.Evaluate(&rep, sc.AssetID)
	res, err := resultOf(&rep, ev)
	if err != nil {
		return ev, err
	}
	event := fmt.Sprintf("re-evaluated (%s): %s → %s; TLS hygiene %s (%d)", why, old, ev.Version, ev.Hygiene.Band, ev.Hygiene.Score)
	return ev, r.st.ReplaceEvaluation(scanID, res, event)
}

// ReevaluateSystem re-evaluates the latest completed scan of every endpoint of a
// system (after its anchors change). It returns how many were re-evaluated.
func (r *Runner) ReevaluateSystem(systemID int64, why string) int {
	latest, err := r.st.LatestDoneScans(systemID)
	if err != nil {
		return 0
	}
	n := 0
	for _, scanID := range latest {
		if _, err := r.Reevaluate(scanID, why); err == nil {
			n++
		}
	}
	return n
}
