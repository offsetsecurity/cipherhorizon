package store

import (
	"database/sql"
	"sort"
	"time"
)

// Fleet is everything the dashboard shows, computed from each asset's latest
// completed scan.
type Fleet struct {
	Assets      int `json:"assets"`
	Scanned     int `json:"scanned"`
	HNDLExposed int `json:"hndlExposed"`
	Critical    int `json:"critical"` // critical findings across the fleet
	High        int `json:"high"`
	// CertsExpiring counts assets whose certificate expires within 30 days (or already has).
	CertsExpiring int `json:"certsExpiring"`

	// Readiness counts assets per level; -1 is undetermined. Bands counts per TLS hygiene band.
	Readiness map[int]int    `json:"readiness"`
	Bands     map[string]int `json:"bands"`

	NeedsAttention []AttentionRow  `json:"needsAttention"`
	Recent         []ScanWithAsset `json:"recent"`
	Trend          []TrendPoint    `json:"trend"`

	// Protocols breaks the fleet down by protocol ("tls", "ssh") for the Overview's protocol
	// cards (PRD-008 REQ-SHW-4). Each protocol keeps its own measure: hygiene bands for TLS,
	// the baseline verdict for SSH. Nothing adds the two together.
	Protocols map[string]*ProtocolSummary `json:"protocols"`
}

// ProtocolSummary is one protocol's share of the fleet.
type ProtocolSummary struct {
	Assets      int         `json:"assets"`
	Scanned     int         `json:"scanned"`
	HNDLExposed int         `json:"hndlExposed"`
	Critical    int         `json:"critical"`
	High        int         `json:"high"`
	Readiness   map[int]int `json:"readiness"`
	// TLS only.
	Bands         map[string]int `json:"bands,omitempty"`
	CertsExpiring int            `json:"certsExpiring"`
	// SSH only: servers judged against their baseline, and those that speak only SSH-1 (L0).
	BaselineMeets int `json:"baselineMeets"`
	BaselineFails int `json:"baselineFails"`
	SSH1          int `json:"ssh1"`
}

// Protocol names of the fleet breakdown.
const (
	ProtocolTLS = "tls"
	ProtocolSSH = "ssh"
)

// ProtocolOf is an endpoint kind's protocol.
func ProtocolOf(kind string) string {
	if kind == KindSSH {
		return ProtocolSSH
	}
	return ProtocolTLS
}

// AttentionRow is an asset that needs looking at, worst first.
type AttentionRow struct {
	AssetID        int64  `json:"assetId"`
	Name           string `json:"name"`
	Address        string `json:"address"`
	Protocol       string `json:"protocol"`
	Band           string `json:"band"` // TLS only; empty for SSH, which has no score
	Score          int    `json:"score"`
	ReadinessLevel *int   `json:"readinessLevel"`
	HNDLExposed    bool   `json:"hndlExposed"`
	Critical       int    `json:"critical"`
	High           int    `json:"high"`
	Why            string `json:"why"`
}

// TrendPoint is the fleet's readiness distribution at the end of a day.
type TrendPoint struct {
	Date   string      `json:"date"`
	Levels map[int]int `json:"levels"`
}

// FleetSummary computes the dashboard data. trendDays is how many days of trend to return.
func (s *Store) FleetSummary(trendDays int) (Fleet, error) {
	if trendDays <= 0 {
		trendDays = 14
	}
	f := Fleet{Readiness: map[int]int{}, Bands: map[string]int{}, Protocols: map[string]*ProtocolSummary{
		ProtocolTLS: {Readiness: map[int]int{}, Bands: map[string]int{}},
		ProtocolSSH: {Readiness: map[int]int{}},
	}}

	assets, err := s.ListAssets(KindEndpoint)
	if err != nil {
		return f, err
	}
	f.Assets = len(assets)
	now := s.now()

	var attention []AttentionRow
	for _, a := range assets {
		proto := ProtocolOf(a.Kind)
		ps := f.Protocols[proto]
		ps.Assets++
		d := a.LastDone
		if d == nil {
			continue
		}
		f.Scanned++
		ps.Scanned++
		ps.Critical += d.Critical
		ps.High += d.High
		if d.HNDLExposed {
			ps.HNDLExposed++
		}
		if d.ReadinessLevel != nil {
			ps.Readiness[*d.ReadinessLevel]++
		}
		switch proto {
		case ProtocolTLS:
			if d.Band != "" {
				ps.Bands[d.Band]++
			}
			if d.CertNotAfter != nil && d.CertNotAfter.Before(now.AddDate(0, 0, 30)) {
				ps.CertsExpiring++
			}
		case ProtocolSSH:
			if d.BaselineMeets != nil && *d.BaselineMeets {
				ps.BaselineMeets++
			} else if d.BaselineMeets != nil {
				ps.BaselineFails++
			}
			if d.ReadinessLevel != nil && *d.ReadinessLevel == 0 {
				ps.SSH1++
			}
		}
		f.Critical += d.Critical
		f.High += d.High
		if d.HNDLExposed {
			f.HNDLExposed++
		}
		if d.ReadinessLevel != nil {
			f.Readiness[*d.ReadinessLevel]++
		}
		if d.Band != "" {
			f.Bands[d.Band]++
		}
		if d.CertNotAfter != nil && d.CertNotAfter.Before(now.AddDate(0, 0, 30)) {
			f.CertsExpiring++
		}
		if why := attentionReason(d, now); why != "" {
			attention = append(attention, AttentionRow{AssetID: a.ID, Name: a.Name, Address: a.Address(), Protocol: proto, Band: d.Band, Score: d.Score,
				ReadinessLevel: d.ReadinessLevel, HNDLExposed: d.HNDLExposed, Critical: d.Critical, High: d.High, Why: why})
		}
	}
	sort.SliceStable(attention, func(i, j int) bool {
		a, b := attention[i], attention[j]
		if a.Critical != b.Critical {
			return a.Critical > b.Critical
		}
		if a.High != b.High {
			return a.High > b.High
		}
		la, lb := 9, 9
		if a.ReadinessLevel != nil {
			la = *a.ReadinessLevel
		}
		if b.ReadinessLevel != nil {
			lb = *b.ReadinessLevel
		}
		return la < lb
	})
	if len(attention) > 10 {
		attention = attention[:10]
	}
	if attention == nil {
		attention = []AttentionRow{}
	}
	f.NeedsAttention = attention

	if f.Recent, err = s.ListScans(ScanFilter{Limit: 10}); err != nil {
		return f, err
	}
	if f.Trend, err = s.trend(trendDays, now); err != nil {
		return f, err
	}
	return f, nil
}

func attentionReason(d *ScanSummary, now time.Time) string {
	switch {
	case d.Critical > 0:
		return "critical findings"
	case d.CertNotAfter != nil && d.CertNotAfter.Before(now):
		return "certificate expired"
	case d.High > 0:
		return "high-severity findings"
	case d.CertNotAfter != nil && d.CertNotAfter.Before(now.AddDate(0, 0, 30)):
		return "certificate expires within 30 days"
	case d.HNDLExposed:
		return "exposed to harvest-now-decrypt-later"
	}
	return ""
}

// trend reconstructs, for each of the last days, each asset's readiness as of
// the end of that day (its latest completed scan on or before it).
func (s *Store) trend(days int, now time.Time) ([]TrendPoint, error) {
	end := now.UTC()
	startDay := time.Date(end.Year(), end.Month(), end.Day(), 0, 0, 0, 0, time.UTC).AddDate(0, 0, -(days - 1))

	rows, err := s.db.Query(`SELECT asset_id, finished_at, readiness_level FROM scans
		WHERE status = 'done' AND readiness_level IS NOT NULL AND finished_at IS NOT NULL ORDER BY finished_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck // read-only

	type obs struct {
		at    time.Time
		level int
	}
	byAsset := map[int64][]obs{}
	for rows.Next() {
		var id int64
		var at string
		var level int
		if err := rows.Scan(&id, &at, &level); err != nil {
			return nil, err
		}
		if t := parseTS(sql.NullString{String: at, Valid: true}); t != nil {
			byAsset[id] = append(byAsset[id], obs{*t, level})
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	out := make([]TrendPoint, 0, days)
	for d := 0; d < days; d++ {
		dayEnd := startDay.AddDate(0, 0, d+1)
		pt := TrendPoint{Date: startDay.AddDate(0, 0, d).Format("2006-01-02"), Levels: map[int]int{}}
		for _, list := range byAsset {
			level, ok := 0, false
			for _, o := range list {
				if o.at.Before(dayEnd) {
					level, ok = o.level, true
				}
			}
			if ok {
				pt.Levels[level]++
			}
		}
		out = append(out, pt)
	}
	return out, nil
}
