package store

import (
	"database/sql"
	"encoding/json"
	"sort"
	"strings"
	"time"
)

// CertificateRow is one certificate in the estate graph: its public attributes and where and
// when it was seen. Nothing here is key material; the graph has no field that could hold it.
type CertificateRow struct {
	Fingerprint string            `json:"fingerprint"`
	Name        string            `json:"name"`
	Attrs       map[string]string `json:"attrs"`
	FirstSeen   time.Time         `json:"firstSeen"`
	LastSeen    time.Time         `json:"lastSeen"`
	// Current is true while a current source still observes it.
	Current bool `json:"current"`
	// Places is how many current observations there are; Systems how many systems they span.
	Places  int `json:"places"`
	Systems int `json:"systems"`
	// Origins lists the source classes (scanner, collector, imported) that currently observe it.
	Origins []string `json:"origins"`
}

// Role is what the certificate is in a chain: a root (a CA that signed itself), an
// intermediate (any other CA) or an end-entity certificate.
func (c CertificateRow) Role() string {
	switch {
	case c.Attrs["isCA"] == "true" && c.Attrs["selfSigned"] == "true":
		return "root"
	case c.Attrs["isCA"] == "true":
		return "intermediate"
	}
	return "end-entity"
}

// Certificates lists every certificate entity.
func (s *Store) Certificates() ([]CertificateRow, error) {
	rows, err := s.db.Query(`SELECT e.key, e.name, e.attrs_json, MIN(o.observed_at), MAX(o.observed_at),
		MAX(CASE WHEN src.is_current = 1 AND src.status = 'active' THEN 1 ELSE 0 END),
		SUM(CASE WHEN src.is_current = 1 AND src.status = 'active' THEN 1 ELSE 0 END),
		COUNT(DISTINCT CASE WHEN src.is_current = 1 AND src.status = 'active' THEN COALESCE(a.system_id, src.system_id) END),
		COALESCE(GROUP_CONCAT(DISTINCT CASE WHEN src.is_current = 1 AND src.status = 'active' THEN src.class END), '')
		FROM entities e JOIN observations o ON o.entity_id = e.id JOIN sources src ON src.id = o.source_id
		LEFT JOIN assets a ON a.id = src.asset_id
		WHERE e.kind = 'certificate' GROUP BY e.id ORDER BY e.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck // read-only
	out := []CertificateRow{}
	for rows.Next() {
		var c CertificateRow
		var attrs, first, last, origins string
		var cur int
		if err := rows.Scan(&c.Fingerprint, &c.Name, &attrs, &first, &last, &cur, &c.Places, &c.Systems, &origins); err != nil {
			return nil, err
		}
		c.Origins = []string{}
		if origins != "" {
			c.Origins = strings.Split(origins, ",")
			sort.Strings(c.Origins)
		}
		c.Fingerprint = strings.TrimPrefix(c.Fingerprint, "cert:")
		_ = json.Unmarshal([]byte(attrs), &c.Attrs)
		if c.Attrs == nil {
			c.Attrs = map[string]string{}
		}
		if t := parseTS(sql.NullString{String: first, Valid: true}); t != nil {
			c.FirstSeen = *t
		}
		if t := parseTS(sql.NullString{String: last, Valid: true}); t != nil {
			c.LastSeen = *t
		}
		c.Current = cur == 1
		out = append(out, c)
	}
	return out, rows.Err()
}

// CertificatePlace is one sighting of a certificate.
type CertificatePlace struct {
	SystemID    int64     `json:"systemId"`
	SystemName  string    `json:"systemName"`
	AssetID     int64     `json:"assetId,omitempty"`
	AssetKind   string    `json:"assetKind,omitempty"`
	SourceClass string    `json:"sourceClass"`
	Stream      string    `json:"stream"`
	Relation    string    `json:"relation"`
	Rung        string    `json:"rung"`
	Method      string    `json:"method"`
	Quality     string    `json:"methodQuality"`
	Position    string    `json:"position,omitempty"`   // leaf or chain, for a presented certificate
	Location    string    `json:"location,omitempty"`   // where a host holds it
	PrivateKey  string    `json:"privateKey,omitempty"` // yes, no or unknown
	ObservedAt  time.Time `json:"observedAt"`
	Current     bool      `json:"current"`
}

// CertificatePlaces lists every sighting of one certificate, newest first. found is false
// when no such certificate is in the graph.
func (s *Store) CertificatePlaces(fingerprint string) (places []CertificatePlace, found bool, err error) {
	key := "cert:" + strings.ToLower(fingerprint)
	rows, err := s.db.Query(`SELECT COALESCE(a.system_id, src.system_id, 0), COALESCE(sy.name, ''), COALESCE(src.asset_id, 0), COALESCE(a.kind, ''),
		src.class, src.stream, o.relation, o.rung, o.method, o.quality, o.attrs_json, o.observed_at, src.is_current, src.status
		FROM entities e JOIN observations o ON o.entity_id = e.id JOIN sources src ON src.id = o.source_id
		LEFT JOIN assets a ON a.id = src.asset_id LEFT JOIN systems sy ON sy.id = COALESCE(a.system_id, src.system_id)
		WHERE e.kind = 'certificate' AND e.key = ? ORDER BY o.observed_at DESC, o.id DESC`, key)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close() //nolint:errcheck // read-only
	places = []CertificatePlace{}
	for rows.Next() {
		var p CertificatePlace
		var attrs, at, status string
		var cur int
		if err := rows.Scan(&p.SystemID, &p.SystemName, &p.AssetID, &p.AssetKind, &p.SourceClass, &p.Stream, &p.Relation, &p.Rung, &p.Method,
			&p.Quality, &attrs, &at, &cur, &status); err != nil {
			return nil, false, err
		}
		var oa map[string]string
		_ = json.Unmarshal([]byte(attrs), &oa)
		p.Position, p.Location, p.PrivateKey = oa["position"], oa["location"], oa["privateKey"]
		if t := parseTS(sql.NullString{String: at, Valid: true}); t != nil {
			p.ObservedAt = *t
		}
		p.Current = cur == 1 && status == "active"
		places = append(places, p)
	}
	return places, len(places) > 0, rows.Err()
}

// RootSetChange says which trust anchors a host gained or lost between its two most recent
// uploads. A change to the set of roots a machine trusts is worth a person's attention even
// though no individual root is a finding (PRD-003 REQ-CERT-5).
type RootSetChange struct {
	AssetID      int64     `json:"assetId"`
	AssetName    string    `json:"assetName"`
	SystemID     int64     `json:"systemId"`
	Previous     time.Time `json:"previous"`
	Latest       time.Time `json:"latest"`
	Added        []string  `json:"added"`   // fingerprints
	Removed      []string  `json:"removed"` // fingerprints
	AddedName    []string  `json:"addedNames"`
	RemovedNames []string  `json:"removedNames"`
}

// RootSetChanges compares, for each host with at least two uploads that recorded
// certificates, the roots of the latest against the one before.
func (s *Store) RootSetChanges() ([]RootSetChange, error) {
	assets, err := s.db.Query(`SELECT a.id, a.name, COALESCE(a.system_id, 0) FROM assets a WHERE a.kind = ? ORDER BY a.id`, KindHost)
	if err != nil {
		return nil, err
	}
	type hostRow struct {
		id, system int64
		name       string
	}
	var hosts []hostRow
	for assets.Next() {
		var h hostRow
		if err := assets.Scan(&h.id, &h.name, &h.system); err != nil {
			_ = assets.Close()
			return nil, err
		}
		hosts = append(hosts, h)
	}
	_ = assets.Close()

	out := []RootSetChange{}
	for _, h := range hosts {
		srcs, err := s.db.Query(`SELECT id, observed_at FROM sources WHERE asset_id = ? AND ref_kind = 'host_snapshot' AND status = 'active'
			AND id IN (SELECT o.source_id FROM observations o JOIN entities e ON e.id = o.entity_id WHERE e.kind = 'certificate')
			ORDER BY ref_id DESC LIMIT 2`, h.id)
		if err != nil {
			return nil, err
		}
		var ids []int64
		var when []time.Time
		for srcs.Next() {
			var id int64
			var at string
			if err := srcs.Scan(&id, &at); err != nil {
				_ = srcs.Close()
				return nil, err
			}
			ids = append(ids, id)
			t := time.Time{}
			if p := parseTS(sql.NullString{String: at, Valid: true}); p != nil {
				t = *p
			}
			when = append(when, t)
		}
		_ = srcs.Close()
		if len(ids) < 2 {
			continue
		}
		latest, err := s.rootsOf(ids[0])
		if err != nil {
			return nil, err
		}
		prev, err := s.rootsOf(ids[1])
		if err != nil {
			return nil, err
		}
		ch := RootSetChange{AssetID: h.id, AssetName: h.name, SystemID: h.system, Previous: when[1], Latest: when[0],
			Added: []string{}, Removed: []string{}, AddedName: []string{}, RemovedNames: []string{}}
		for fp, name := range latest {
			if _, ok := prev[fp]; !ok {
				ch.Added, ch.AddedName = append(ch.Added, fp), append(ch.AddedName, name)
			}
		}
		for fp, name := range prev {
			if _, ok := latest[fp]; !ok {
				ch.Removed, ch.RemovedNames = append(ch.Removed, fp), append(ch.RemovedNames, name)
			}
		}
		if len(ch.Added) == 0 && len(ch.Removed) == 0 {
			continue
		}
		sortTogether(ch.Added, ch.AddedName)
		sortTogether(ch.Removed, ch.RemovedNames)
		out = append(out, ch)
	}
	return out, nil
}

// rootsOf returns fingerprint -> name for the root certificates one source observed.
func (s *Store) rootsOf(sourceID int64) (map[string]string, error) {
	rows, err := s.db.Query(`SELECT DISTINCT e.key, e.name, e.attrs_json FROM observations o JOIN entities e ON e.id = o.entity_id
		WHERE o.source_id = ? AND e.kind = 'certificate'`, sourceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck // read-only
	out := map[string]string{}
	for rows.Next() {
		var key, name, attrs string
		if err := rows.Scan(&key, &name, &attrs); err != nil {
			return nil, err
		}
		var a map[string]string
		_ = json.Unmarshal([]byte(attrs), &a)
		if a["isCA"] == "true" && a["selfSigned"] == "true" {
			out[strings.TrimPrefix(key, "cert:")] = name
		}
	}
	return out, rows.Err()
}

// sortTogether sorts keys and keeps names in step.
func sortTogether(keys, names []string) {
	idx := make([]int, len(keys))
	for i := range idx {
		idx[i] = i
	}
	sort.Slice(idx, func(a, b int) bool { return keys[idx[a]] < keys[idx[b]] })
	k2, n2 := make([]string, len(keys)), make([]string, len(names))
	for i, j := range idx {
		k2[i], n2[i] = keys[j], names[j]
	}
	copy(keys, k2)
	copy(names, n2)
}
