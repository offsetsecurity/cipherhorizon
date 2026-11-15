package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// A discovery is one run of finding the host names under a domain (PRD-022, internal). Its names
// are a review list: none is an endpoint until a person accepts it.

// Discovery statuses.
const (
	DiscoveryRunning  = "running"
	DiscoveryDone     = "done"
	DiscoveryFailed   = "failed"
	DiscoveryCanceled = "canceled"
)

// SettingDiscoveryCT is "on" when discovery may search Certificate Transparency, which tells an
// outside service the domain being asked about. Absent means off.
const SettingDiscoveryCT = "discovery.ct"

// Discovery is a run as listed.
type Discovery struct {
	ID      int64    `json:"id"`
	Domain  string   `json:"domain"`
	Sources []string `json:"sources"`
	Status  string   `json:"status"`
	// Stage is what a running discovery is doing, in words.
	Stage string `json:"stage"`
	Error string `json:"error,omitempty"`
	// Report is the outcome besides the names, as JSON: what each source did and the limits.
	Report     json.RawMessage `json:"report,omitempty"`
	Names      int             `json:"names"`
	Accepted   int             `json:"accepted"`
	StartedBy  string          `json:"startedBy"`
	CreatedAt  time.Time       `json:"createdAt"`
	FinishedAt *time.Time      `json:"finishedAt,omitempty"`
}

// DiscoveryName is one found name.
type DiscoveryName struct {
	Name      string   `json:"name"`
	Sources   []string `json:"sources"`
	Addresses []string `json:"addresses"`
	CNAME     string   `json:"cname,omitempty"`
	External  bool     `json:"external"`
	Ports     []int    `json:"ports"`
	Refused   string   `json:"refused,omitempty"`
	Mail      bool     `json:"mail,omitempty"`
	// Accepted says the name was added as endpoints from this run.
	Accepted bool `json:"accepted"`
	// New says the previous finished run of the same domain did not list the name.
	New bool `json:"new"`
	// Tracked says an endpoint with this host already exists, whichever way it was added.
	Tracked bool `json:"tracked"`
}

const discoveryCols = `d.id, d.domain, d.sources, d.status, d.stage, d.error, d.report, d.started_by, d.created_at, d.finished_at,
	(SELECT COUNT(*) FROM discovery_names n WHERE n.discovery_id = d.id),
	(SELECT COUNT(*) FROM discovery_names n WHERE n.discovery_id = d.id AND n.accepted_at IS NOT NULL)`

func scanDiscovery(row interface{ Scan(...any) error }) (Discovery, error) {
	var d Discovery
	var sources, report, created string
	var finished sql.NullString
	if err := row.Scan(&d.ID, &d.Domain, &sources, &d.Status, &d.Stage, &d.Error, &report, &d.StartedBy, &created, &finished, &d.Names, &d.Accepted); err != nil {
		return Discovery{}, err
	}
	d.Sources = []string{}
	_ = json.Unmarshal([]byte(sources), &d.Sources)
	if report != "" {
		d.Report = json.RawMessage(report)
	}
	if t := parseTS(sql.NullString{String: created, Valid: true}); t != nil {
		d.CreatedAt = *t
	}
	d.FinishedAt = parseTS(finished)
	return d, nil
}

// CreateDiscovery records a run as started.
func (s *Store) CreateDiscovery(domain string, sources []string, startedBy string) (Discovery, error) {
	if sources == nil {
		sources = []string{}
	}
	b, _ := json.Marshal(sources)
	res, err := s.db.Exec(`INSERT INTO discoveries (domain, sources, status, stage, started_by, created_at) VALUES (?, ?, ?, 'starting', ?, ?)`,
		domain, string(b), DiscoveryRunning, startedBy, ts(s.now()))
	if err != nil {
		return Discovery{}, err
	}
	id, _ := res.LastInsertId()
	return s.GetDiscovery(id)
}

// GetDiscovery returns one run.
func (s *Store) GetDiscovery(id int64) (Discovery, error) {
	d, err := scanDiscovery(s.db.QueryRow(`SELECT `+discoveryCols+` FROM discoveries d WHERE d.id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return Discovery{}, ErrNotFound
	}
	return d, err
}

// ListDiscoveries returns every run, newest first.
func (s *Store) ListDiscoveries() ([]Discovery, error) {
	rows, err := s.db.Query(`SELECT ` + discoveryCols + ` FROM discoveries d ORDER BY d.id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck // read-only
	out := []Discovery{}
	for rows.Next() {
		d, err := scanDiscovery(rows)
		if err != nil {
			return nil, err
		}
		d.Report = nil // the list is short; the report comes with one run
		out = append(out, d)
	}
	return out, rows.Err()
}

// SetDiscoveryStage says what a running discovery is doing.
func (s *Store) SetDiscoveryStage(id int64, stage string) error {
	_, err := s.db.Exec(`UPDATE discoveries SET stage = ? WHERE id = ? AND status = ?`, stage, id, DiscoveryRunning)
	return err
}

// FinishDiscovery stores the outcome of a run: its names and report when it is done, or why it
// stopped. A run that was canceled meanwhile stays canceled.
func (s *Store) FinishDiscovery(id int64, status, errText string, report any, names []DiscoveryName) error {
	rep := ""
	if report != nil {
		b, err := json.Marshal(report)
		if err != nil {
			return err
		}
		rep = string(b)
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	res, err := tx.Exec(`UPDATE discoveries SET status = ?, stage = ?, error = ?, report = ?, finished_at = ? WHERE id = ? AND status = ?`,
		status, status, errText, rep, ts(s.now()), id, DiscoveryRunning)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return nil
	}
	stmt, err := tx.Prepare(`INSERT INTO discovery_names (discovery_id, name, sources, addresses, cname, external, ports, refused, mail)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer stmt.Close() //nolint:errcheck // the transaction ends it
	for _, n := range names {
		src, _ := json.Marshal(orEmpty(n.Sources))
		addrs, _ := json.Marshal(orEmpty(n.Addresses))
		ports := n.Ports
		if ports == nil {
			ports = []int{}
		}
		pj, _ := json.Marshal(ports)
		if _, err := stmt.Exec(id, n.Name, string(src), string(addrs), n.CNAME, n.External, string(pj), n.Refused, n.Mail); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func orEmpty(v []string) []string {
	if v == nil {
		return []string{}
	}
	return v
}

// CancelDiscovery marks a running discovery canceled. It reports whether it was running.
func (s *Store) CancelDiscovery(id int64) (bool, error) {
	res, err := s.db.Exec(`UPDATE discoveries SET status = ?, stage = ?, finished_at = ? WHERE id = ? AND status = ?`,
		DiscoveryCanceled, DiscoveryCanceled, ts(s.now()), id, DiscoveryRunning)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// FailInterruptedDiscoveries marks discoveries left running by a previous process as failed.
func (s *Store) FailInterruptedDiscoveries() (int, error) {
	res, err := s.db.Exec(`UPDATE discoveries SET status = ?, stage = ?, error = 'interrupted by a restart of the server', finished_at = ? WHERE status = ?`,
		DiscoveryFailed, DiscoveryFailed, ts(s.now()), DiscoveryRunning)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// DeleteDiscovery removes a run and its names. Endpoints added from it stay.
func (s *Store) DeleteDiscovery(id int64) error {
	res, err := s.db.Exec(`DELETE FROM discoveries WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// DiscoveryNames lists the names of a run, in name order. Each says whether the previous finished
// run of the same domain already listed it; in a domain's first run nothing is marked new.
func (s *Store) DiscoveryNames(id int64) ([]DiscoveryName, error) {
	var prev sql.NullInt64
	if err := s.db.QueryRow(`SELECT MAX(p.id) FROM discoveries p JOIN discoveries d ON d.id = ? AND p.domain = d.domain
		WHERE p.id < d.id AND p.status = ?`, id, DiscoveryDone).Scan(&prev); err != nil {
		return nil, err
	}
	rows, err := s.db.Query(`SELECT n.name, n.sources, n.addresses, n.cname, n.external, n.ports, n.refused, n.mail, n.accepted_at IS NOT NULL,
		? AND NOT EXISTS (SELECT 1 FROM discovery_names o WHERE o.discovery_id = ? AND o.name = n.name),
		EXISTS (SELECT 1 FROM assets a WHERE a.host = n.name)
		FROM discovery_names n WHERE n.discovery_id = ? ORDER BY n.name`, prev.Valid, prev.Int64, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck // read-only
	out := []DiscoveryName{}
	for rows.Next() {
		var n DiscoveryName
		var src, addrs, ports string
		if err := rows.Scan(&n.Name, &src, &addrs, &n.CNAME, &n.External, &ports, &n.Refused, &n.Mail, &n.Accepted, &n.New, &n.Tracked); err != nil {
			return nil, err
		}
		n.Sources, n.Addresses, n.Ports = []string{}, []string{}, []int{}
		_ = json.Unmarshal([]byte(src), &n.Sources)
		_ = json.Unmarshal([]byte(addrs), &n.Addresses)
		_ = json.Unmarshal([]byte(ports), &n.Ports)
		out = append(out, n)
	}
	return out, rows.Err()
}

// MarkDiscoveryAccepted records that names of a run were added as endpoints.
func (s *Store) MarkDiscoveryAccepted(id int64, names []string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	now := ts(s.now())
	for _, n := range names {
		if _, err := tx.Exec(`UPDATE discovery_names SET accepted_at = ? WHERE discovery_id = ? AND name = ? AND accepted_at IS NULL`, now, id, n); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// KnownNamesUnder returns the host names this store already holds that are the domain or under
// it: the names in certificates it has seen, and the hosts of its endpoints.
func (s *Store) KnownNamesUnder(domain string) ([]string, error) {
	domain = strings.ToLower(strings.Trim(domain, "."))
	seen := map[string]bool{}
	var out []string
	add := func(n string) {
		n = strings.ToLower(strings.TrimSpace(n))
		bare := strings.TrimPrefix(n, "*.")
		if n == "" || seen[n] || (bare != domain && !strings.HasSuffix(bare, "."+domain)) {
			return
		}
		seen[n] = true
		out = append(out, n)
	}
	rows, err := s.db.Query(`SELECT attrs_json FROM entities WHERE kind = 'certificate' AND instr(lower(attrs_json), ?) > 0`, domain)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck // read-only
	for rows.Next() {
		var attrs string
		if err := rows.Scan(&attrs); err != nil {
			return nil, err
		}
		var a map[string]string
		_ = json.Unmarshal([]byte(attrs), &a)
		for _, n := range strings.Split(a["dnsNames"], ",") {
			add(n)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	hosts, err := s.db.Query(`SELECT DISTINCT host FROM assets WHERE host = ? OR host LIKE ?`, domain, "%."+domain)
	if err != nil {
		return nil, err
	}
	defer hosts.Close() //nolint:errcheck // read-only
	for hosts.Next() {
		var h string
		if err := hosts.Scan(&h); err != nil {
			return nil, err
		}
		add(h)
	}
	return out, hosts.Err()
}
