package store

import (
	"encoding/json"
	"strconv"
	"time"

	"github.com/offsetsecurity/cipherhorizon/internal/eval"
)

// Facts describes the certificate for the certificate rules.
func (c CertificateRow) Facts() eval.CertificateFacts { return certFacts(c.Attrs) }

func certFacts(a map[string]string) eval.CertificateFacts {
	f := eval.CertificateFacts{Subject: a["subject"], KeyAlgorithm: a["keyAlg"], SigName: a["sigAlg"], IsCA: a["isCA"] == "true", SelfSigned: a["selfSigned"] == "true"}
	if t, err := time.Parse("2006-01-02T15:04:05Z", a["notBefore"]); err == nil {
		f.NotBefore = t
	}
	if t, err := time.Parse("2006-01-02T15:04:05Z", a["notAfter"]); err == nil {
		f.NotAfter = t
	}
	if n, err := strconv.Atoi(a["keyBits"]); err == nil {
		f.KeyBits = n
	}
	return f
}

// PriorityInputs gathers, for every system, what ranking reads: the metadata a person entered, the
// latest completed scan of each of its endpoints, its current end-entity certificates, and how it
// is known. It is a handful of queries, not one per system.
func (s *Store) PriorityInputs() ([]eval.PriorityInput, error) {
	systems, err := s.ListSystems()
	if err != nil {
		return nil, err
	}
	assets, err := s.ListAssets("")
	if err != nil {
		return nil, err
	}
	byID := map[int64]*eval.PriorityInput{}
	out := make([]eval.PriorityInput, len(systems))
	for i, sys := range systems {
		out[i] = eval.PriorityInput{SystemID: sys.ID, Name: sys.Name,
			Meta: eval.PriorityMeta{Criticality: sys.Criticality, Exposure: sys.Exposure, DataLifetimeYears: sys.DataLifetimeYears}}
		byID[sys.ID] = &out[i]
	}
	for _, a := range assets {
		in := byID[a.SystemID]
		if in == nil || a.Kind != KindTLS || a.LastDone == nil {
			continue
		}
		d := a.LastDone
		in.Services = append(in.Services, eval.ServiceFacts{Name: a.Address(), HNDLExposed: d.HNDLExposed, ReadinessLevel: d.ReadinessLevel, Critical: d.Critical, High: d.High})
	}

	rows, err := s.db.Query(`SELECT DISTINCT COALESCE(a.system_id, src.system_id), e.key, e.attrs_json
		FROM observations o JOIN entities e ON e.id = o.entity_id AND e.kind = 'certificate'
		JOIN sources src ON src.id = o.source_id AND src.is_current = 1 AND src.status = 'active'
		LEFT JOIN assets a ON a.id = src.asset_id`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var sid int64
		var key, attrs string
		if err := rows.Scan(&sid, &key, &attrs); err != nil {
			_ = rows.Close()
			return nil, err
		}
		var a map[string]string
		_ = json.Unmarshal([]byte(attrs), &a)
		if in := byID[sid]; in != nil && a["isCA"] != "true" {
			in.Certs = append(in.Certs, certFacts(a))
		}
	}
	_ = rows.Close()

	src, err := s.db.Query(`SELECT COALESCE(a.system_id, s.system_id), s.class, COUNT(*) FROM sources s LEFT JOIN assets a ON a.id = s.asset_id
		WHERE s.is_current = 1 AND s.status = 'active' GROUP BY 1, 2`)
	if err != nil {
		return nil, err
	}
	defer src.Close() //nolint:errcheck // read-only
	for src.Next() {
		var sid int64
		var class string
		var n int
		if err := src.Scan(&sid, &class, &n); err != nil {
			return nil, err
		}
		if in := byID[sid]; in != nil {
			in.EvidenceSources += n
			if class == "scanner" || class == "collector" {
				in.EvidenceFirstParty = true
			}
		}
	}
	return out, src.Err()
}
