package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/example/cipherhorizon/internal/estate"
)

// Link states.
const (
	LinkProposed  = "proposed"
	LinkConfirmed = "confirmed"
	LinkRejected  = "rejected"
)

// Link is a reviewable statement that an asset (typically a TLS endpoint) belongs to a system
// (typically the machine's): the rules that produced it with the values that matched, a strength
// from a fixed table, a state, and who decided. It is never a silent merge (PRD-003 REQ-COR-2).
type Link struct {
	ID         int64            `json:"id"`
	AssetID    int64            `json:"assetId"`
	AssetName  string           `json:"assetName"`
	AssetKind  string           `json:"assetKind"`
	AssetAddr  string           `json:"assetAddress"`
	SystemID   int64            `json:"systemId"`
	SystemName string           `json:"systemName"`
	State      string           `json:"state"`
	Strength   string           `json:"strength"`
	Rules      []estate.RuleHit `json:"rules"`
	Ambiguous  bool             `json:"ambiguous"`
	Note       string           `json:"note,omitempty"`
	Stale      bool             `json:"stale"`
	DecidedBy  string           `json:"decidedBy,omitempty"`
	DecidedAt  *time.Time       `json:"decidedAt,omitempty"`
	CreatedAt  time.Time        `json:"createdAt"`
	UpdatedAt  time.Time        `json:"updatedAt"`
	Reason     string           `json:"reason,omitempty"`
	Competes   int              `json:"competingProposals"`
}

type linkEvidence struct {
	Ambiguous bool   `json:"ambiguous"`
	Note      string `json:"note,omitempty"`
	Reason    string `json:"reason,omitempty"`
}

const linkCols = `l.id, l.asset_id, a.name, a.kind, a.host, a.port, l.system_id, sy.name, l.state, l.strength, l.rules_json, l.evidence_json,
	l.stale, l.decided_by, l.decided_at, l.created_at, l.updated_at,
	(SELECT COUNT(*) FROM links o WHERE o.asset_id = l.asset_id AND o.id <> l.id AND o.state = 'proposed')`

const linkFrom = ` FROM links l JOIN assets a ON a.id = l.asset_id JOIN systems sy ON sy.id = l.system_id`

func scanLink(r scanner) (Link, error) {
	var l Link
	var host string
	var port int
	var rules, ev, created, updated string
	var decided sql.NullString
	var stale int
	if err := r.Scan(&l.ID, &l.AssetID, &l.AssetName, &l.AssetKind, &host, &port, &l.SystemID, &l.SystemName, &l.State, &l.Strength,
		&rules, &ev, &stale, &l.DecidedBy, &decided, &created, &updated, &l.Competes); err != nil {
		return Link{}, err
	}
	l.AssetAddr = Asset{Host: host, Port: port}.Address()
	l.Stale = stale != 0
	_ = json.Unmarshal([]byte(rules), &l.Rules)
	if l.Rules == nil {
		l.Rules = []estate.RuleHit{}
	}
	var e linkEvidence
	_ = json.Unmarshal([]byte(ev), &e)
	l.Ambiguous, l.Note, l.Reason = e.Ambiguous, e.Note, e.Reason
	l.DecidedAt = parseTS(decided)
	if t := parseTS(sql.NullString{String: created, Valid: true}); t != nil {
		l.CreatedAt = *t
	}
	if t := parseTS(sql.NullString{String: updated, Valid: true}); t != nil {
		l.UpdatedAt = *t
	}
	return l, nil
}

// Links lists links of one state (all states when empty), newest first.
func (s *Store) Links(state string) ([]Link, error) {
	q := `SELECT ` + linkCols + linkFrom
	var args []any
	if state != "" {
		q += ` WHERE l.state = ?`
		args = append(args, state)
	}
	q += ` ORDER BY l.updated_at DESC, l.id DESC LIMIT 2000`
	return s.queryLinks(q, args...)
}

// SystemLinks lists the links that touch one system, either as target or through an asset it holds.
func (s *Store) SystemLinks(systemID int64) ([]Link, error) {
	return s.queryLinks(`SELECT `+linkCols+linkFrom+` WHERE l.system_id = ? OR a.system_id = ? ORDER BY l.updated_at DESC, l.id DESC`, systemID, systemID)
}

// GetLink returns one link.
func (s *Store) GetLink(id int64) (Link, error) {
	l, err := scanLink(s.db.QueryRow(`SELECT `+linkCols+linkFrom+` WHERE l.id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return Link{}, ErrNotFound
	}
	return l, err
}

func (s *Store) queryLinks(q string, args ...any) ([]Link, error) {
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck // read-only
	out := []Link{}
	for rows.Next() {
		l, err := scanLink(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

// ---- deciding ------------------------------------------------------------------------------

// ConfirmLink accepts a proposed link: the asset's system is merged into the target. If the two
// systems hold different operator-set values the confirmation is refused with a ConflictError
// naming them and nothing changes (REQ-COR-7, DN-1).
func (s *Store) ConfirmLink(id int64, actor, reason string) (Link, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return Link{}, err
	}
	defer func() { _ = tx.Rollback() }()
	if err := s.confirmLinkTx(tx, id, actor, reason); err != nil {
		return Link{}, err
	}
	if err := tx.Commit(); err != nil {
		return Link{}, err
	}
	return s.GetLink(id)
}

func (s *Store) confirmLinkTx(tx *sql.Tx, id int64, actor, reason string) error {
	var assetID, systemID, assetSystem int64
	var state string
	err := tx.QueryRow(`SELECT l.asset_id, l.system_id, l.state, COALESCE(a.system_id, 0) FROM links l JOIN assets a ON a.id = l.asset_id WHERE l.id = ?`, id).
		Scan(&assetID, &systemID, &state, &assetSystem)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if state == LinkConfirmed {
		return nil
	}
	if assetSystem != 0 && assetSystem != systemID {
		if err := s.mergeSystemsTx(tx, assetSystem, systemID, actor, fmt.Sprintf("link %d confirmed: %s", id, reason)); err != nil {
			return err
		}
	}
	now := ts(s.now())
	if _, err := tx.Exec(`UPDATE links SET state = 'confirmed', stale = 0, decided_by = ?, decided_at = ?, updated_at = ? WHERE id = ?`, actor, now, now, id); err != nil {
		return err
	}
	// Merging can leave the same pair proposed twice under the merged system's old id; those rows are gone with it (cascade).
	return audit(tx, now, actor, systemID, "link-confirm", map[string]any{"linkId": id, "state": state},
		map[string]any{"assetId": assetID, "state": LinkConfirmed}, reason)
}

// RejectLink refuses a link. A rejected link is never proposed again (REQ-COR-5). Rejecting a
// link that had been confirmed also takes the asset back out into a system of its own.
func (s *Store) RejectLink(id int64, actor, reason string) (Link, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return Link{}, err
	}
	defer func() { _ = tx.Rollback() }()
	var assetID, systemID, assetSystem int64
	var state, assetName string
	err = tx.QueryRow(`SELECT l.asset_id, l.system_id, l.state, COALESCE(a.system_id, 0), a.name FROM links l JOIN assets a ON a.id = l.asset_id WHERE l.id = ?`, id).
		Scan(&assetID, &systemID, &state, &assetSystem, &assetName)
	if errors.Is(err, sql.ErrNoRows) {
		return Link{}, ErrNotFound
	}
	if err != nil {
		return Link{}, err
	}
	if state == LinkRejected {
		return s.GetLink(id)
	}
	if state == LinkConfirmed && assetSystem == systemID {
		// Undo the join: the asset leaves the system it was merged into. Only the asset moves; the
		// system keeps its metadata and its other assets.
		if err := s.splitAssetTx(tx, []int64{assetID}, assetName, actor, fmt.Sprintf("link %d rejected: %s", id, reason), systemID); err != nil {
			return Link{}, err
		}
	}
	now := ts(s.now())
	if _, err := tx.Exec(`UPDATE links SET state = 'rejected', stale = 0, decided_by = ?, decided_at = ?, updated_at = ? WHERE id = ?`, actor, now, now, id); err != nil {
		return Link{}, err
	}
	if err := audit(tx, now, actor, systemID, "link-reject", map[string]any{"linkId": id, "state": state}, map[string]any{"assetId": assetID, "state": LinkRejected}, reason); err != nil {
		return Link{}, err
	}
	if err := tx.Commit(); err != nil {
		return Link{}, err
	}
	return s.GetLink(id)
}

// recordManualLinkTx records a link a person made by hand (LinkAssets) as a confirmed link, and a
// link a person removed (UnlinkAssets) as a rejected one, so correlation neither loses the first
// nor re-proposes the second.
func recordManualLinkTx(tx *sql.Tx, now, actor string, assetID, systemID int64, state string) error {
	rules, _ := json.Marshal([]estate.RuleHit{{ID: estate.RuleManual, Detail: "linked by a person (" + actor + ")"}})
	ev, _ := json.Marshal(linkEvidence{})
	_, err := tx.Exec(`INSERT INTO links (asset_id, system_id, state, strength, rules_json, evidence_json, stale, decided_by, decided_at, created_at, updated_at)
		VALUES (?, ?, ?, 'strong', ?, ?, 0, ?, ?, ?, ?)
		ON CONFLICT(asset_id, system_id) DO UPDATE SET state = excluded.state, stale = 0, decided_by = excluded.decided_by, decided_at = excluded.decided_at, updated_at = excluded.updated_at`,
		assetID, systemID, state, string(rules), string(ev), actor, now, now, now)
	return err
}

// backfillLinks turns the manual links of 0.1.0 (asset_links) into confirmed links (migration 6).
func backfillLinks(tx *sql.Tx, now time.Time) error {
	rows, err := tx.Query(`SELECT asset_id, linked_asset_id, created_at FROM asset_links`)
	if err != nil {
		return err
	}
	type pair struct {
		a, b int64
		at   string
	}
	var pairs []pair
	for rows.Next() {
		var p pair
		if err := rows.Scan(&p.a, &p.b, &p.at); err != nil {
			_ = rows.Close()
			return err
		}
		pairs = append(pairs, p)
	}
	_ = rows.Close()
	for _, p := range pairs {
		var sys sql.NullInt64
		if err := tx.QueryRow(`SELECT system_id FROM assets WHERE id = ?`, p.a).Scan(&sys); err != nil || !sys.Valid {
			continue
		}
		if err := recordManualLinkTx(tx, p.at, "operator", p.a, sys.Int64, LinkConfirmed); err != nil {
			return err
		}
	}
	_ = now
	return nil
}

// ---- correlating ------------------------------------------------------------------------------

// correlateQuietly recomputes links after evidence changes, and returns once a correlation that
// started after the caller's change has finished. Correlation reads the whole estate, so calls
// are coalesced: while one runs, everyone who asks meanwhile waits for one more run that covers
// them all, instead of each running their own. Correlation is derived: a failure never fails the
// operation that changed the evidence; it is logged, and Maintain rebuilds.
func (s *Store) correlateQuietly() {
	s.corrMu.Lock()
	defer s.corrMu.Unlock()
	s.corrWanted++
	mine := s.corrWanted
	for s.corrDone < mine {
		if s.corrRunning {
			s.corrCond.Wait()
			continue
		}
		s.corrRunning = true
		covers := s.corrWanted // every request made before this run starts reading
		s.corrMu.Unlock()
		err := func() (err error) {
			// A panic must not leave corrRunning set: every later caller would wait for ever.
			defer func() {
				if v := recover(); v != nil {
					err = fmt.Errorf("panic: %v", v)
				}
			}()
			return s.Correlate()
		}()
		if err != nil {
			s.markStale("correlating the estate", err)
		}
		s.corrMu.Lock()
		s.corrRunning = false
		s.corrDone = covers
		s.corrCond.Broadcast()
	}
}

// Correlate recomputes links from the current graph.
func (s *Store) Correlate() error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if err := s.correlateTx(tx); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) correlateTx(tx *sql.Tx) error {
	sn, err := snapshotTx(tx)
	if err != nil {
		return err
	}
	sn.KeepSameSystem = true
	cands := estate.Correlate(sn)

	assetSystem := map[int64]int64{}
	for _, a := range sn.Assets {
		assetSystem[a.ID] = a.SystemID
	}
	type key struct{ asset, system int64 }
	supported := map[key]estate.Candidate{}
	for _, c := range cands {
		supported[key{c.AssetID, c.SystemID}] = c
	}

	// existing links
	type row struct {
		id     int64
		state  string
		manual bool
	}
	existing := map[key]row{}
	rows, err := tx.Query(`SELECT id, asset_id, system_id, state, rules_json FROM links`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var r row
		var k key
		var rules string
		if err := rows.Scan(&r.id, &k.asset, &k.system, &r.state, &rules); err != nil {
			_ = rows.Close()
			return err
		}
		r.manual = strings.Contains(rules, estate.RuleManual)
		existing[k] = r
	}
	_ = rows.Close()

	now := ts(s.now())
	// Candidates in a fixed order: create, refresh, or (for a strong first-party join) confirm.
	for _, c := range cands {
		k := key{c.AssetID, c.SystemID}
		rules, _ := json.Marshal(c.Rules)
		ev, _ := json.Marshal(linkEvidence{Ambiguous: c.Ambiguous, Note: c.Note})
		if r, ok := existing[k]; ok {
			switch r.state {
			case LinkRejected:
				continue // a rejected link is never proposed again
			case LinkConfirmed:
				if !r.manual {
					if _, err := tx.Exec(`UPDATE links SET strength = ?, rules_json = ?, evidence_json = ?, stale = 0 WHERE id = ?`, string(c.Strength), string(rules), string(ev), r.id); err != nil {
						return err
					}
				}
				continue
			}
			// proposed: refresh, and confirm if it has become an unambiguous first-party join
			if _, err := tx.Exec(`UPDATE links SET strength = ?, rules_json = ?, evidence_json = ?, updated_at = ? WHERE id = ?`, string(c.Strength), string(rules), string(ev), now, r.id); err != nil {
				return err
			}
			if c.AutoConfirm {
				s.tryAutoConfirmTx(tx, r.id, k.asset, k.system, assetSystem[k.asset], now)
			}
			continue
		}
		if assetSystem[c.AssetID] == c.SystemID {
			continue // already together: nothing to propose
		}
		res, err := tx.Exec(`INSERT INTO links (asset_id, system_id, state, strength, rules_json, evidence_json, stale, decided_by, created_at, updated_at)
			VALUES (?, ?, 'proposed', ?, ?, ?, 0, '', ?, ?)`, c.AssetID, c.SystemID, string(c.Strength), string(rules), string(ev), now, now)
		if err != nil {
			return err
		}
		id, _ := res.LastInsertId()
		if c.AutoConfirm {
			s.tryAutoConfirmTx(tx, id, c.AssetID, c.SystemID, assetSystem[c.AssetID], now)
		}
	}

	// Links the evidence no longer supports: a proposal disappears; a confirmed join is flagged for review, never removed.
	ids := make([]key, 0, len(existing))
	for k := range existing {
		ids = append(ids, k)
	}
	sort.Slice(ids, func(i, j int) bool {
		if ids[i].asset != ids[j].asset {
			return ids[i].asset < ids[j].asset
		}
		return ids[i].system < ids[j].system
	})
	for _, k := range ids {
		r := existing[k]
		if _, ok := supported[k]; ok || r.manual {
			continue
		}
		switch r.state {
		case LinkProposed:
			if _, err := tx.Exec(`DELETE FROM links WHERE id = ?`, r.id); err != nil {
				return err
			}
		case LinkConfirmed:
			if _, err := tx.Exec(`UPDATE links SET stale = 1 WHERE id = ? AND stale = 0`, r.id); err != nil {
				return err
			}
		}
	}
	return nil
}

// tryAutoConfirmTx confirms a strong, unambiguous, first-party link and merges the systems. If the
// merge would overwrite operator-set values it does nothing but say why on the link, which stays a
// proposal for a person to decide.
func (s *Store) tryAutoConfirmTx(tx *sql.Tx, linkID, assetID, systemID, assetSystem int64, now string) {
	// A savepoint so a refused merge leaves no half-done state.
	if _, err := tx.Exec(`SAVEPOINT autoconfirm`); err != nil {
		return
	}
	err := s.confirmLinkTx(tx, linkID, "auto", "a strong, unambiguous first-party match")
	if err == nil {
		_, _ = tx.Exec(`RELEASE autoconfirm`)
		return
	}
	_, _ = tx.Exec(`ROLLBACK TO autoconfirm`)
	_, _ = tx.Exec(`RELEASE autoconfirm`)
	note := "automatic confirmation was refused: " + err.Error()
	var ce *ConflictError
	if !errors.As(err, &ce) {
		note = "automatic confirmation failed"
	}
	ev, _ := json.Marshal(linkEvidence{Note: note})
	_, _ = tx.Exec(`UPDATE links SET evidence_json = ?, updated_at = ? WHERE id = ? AND state = 'proposed'`, string(ev), now, linkID)
	_ = assetID
	_ = systemID
	_ = assetSystem
}

// snapshotTx gathers what correlation reads: the assets, and every current sighting of an
// end-entity certificate.
func snapshotTx(tx *sql.Tx) (estate.Snapshot, error) {
	var sn estate.Snapshot
	rows, err := tx.Query(`SELECT a.id, COALESCE(a.system_id, 0), a.kind, a.name, a.host,
		EXISTS (SELECT 1 FROM sources s WHERE s.asset_id = a.id AND s.is_current = 1 AND s.status = 'active' AND s.class IN ('scanner', 'collector'))
		FROM assets a ORDER BY a.id`)
	if err != nil {
		return sn, err
	}
	for rows.Next() {
		var a estate.AssetInfo
		var fpFlag int
		if err := rows.Scan(&a.ID, &a.SystemID, &a.Kind, &a.Name, &a.Host, &fpFlag); err != nil {
			_ = rows.Close()
			return sn, err
		}
		a.FirstParty = fpFlag != 0
		sn.Assets = append(sn.Assets, a)
	}
	_ = rows.Close()

	srows, err := tx.Query(`SELECT e.key, e.attrs_json, COALESCE(a.system_id, src.system_id, 0), COALESCE(src.asset_id, 0), src.stream, src.class,
		o.relation, o.attrs_json, COALESCE(a.name, ''), src.ref_kind, src.ref_id
		FROM observations o JOIN entities e ON e.id = o.entity_id AND e.kind = 'certificate'
		JOIN sources src ON src.id = o.source_id AND src.is_current = 1 AND src.status = 'active'
		LEFT JOIN assets a ON a.id = src.asset_id
		ORDER BY o.id`)
	if err != nil {
		return sn, err
	}
	defer srows.Close() //nolint:errcheck // read-only
	for srows.Next() {
		var key, eattrs, stream, class, relation, oattrs, aname, refKind string
		var systemID, assetID, refID int64
		if err := srows.Scan(&key, &eattrs, &systemID, &assetID, &stream, &class, &relation, &oattrs, &aname, &refKind, &refID); err != nil {
			return sn, err
		}
		if systemID == 0 || !strings.HasPrefix(key, "cert:") {
			continue
		}
		var ea, oa map[string]string
		_ = json.Unmarshal([]byte(eattrs), &ea)
		_ = json.Unmarshal([]byte(oattrs), &oa)
		if ea["isCA"] == "true" {
			continue // a CA certificate is shared by every site it signed; it identifies no machine
		}
		sg := estate.CertSighting{Fingerprint: strings.TrimPrefix(key, "cert:"), SystemID: systemID, AssetID: assetID,
			Stream: estate.Stream(stream), Class: estate.SourceClass(class)}
		switch {
		case stream == string(estate.StreamNetwork) && relation == estate.RelPresents:
			sg.Leaf = oa["position"] == "leaf"
			for _, n := range strings.Split(strings.ToLower(ea["dnsNames"]), ",") {
				if n = strings.TrimSpace(n); n != "" {
					sg.DNSNames = append(sg.DNSNames, n)
				}
			}
			sg.Where = "presented by a scan"
		case stream == string(estate.StreamHost) && relation == estate.RelContains:
			loc := clipLoc(oa["location"])
			if loc == "" {
				loc = "in a host snapshot"
			}
			sg.Where = fmt.Sprintf("by host %s at %s (%s)", clipLoc(aname), loc, class)
		case stream == string(estate.StreamImported) && relation == estate.RelContains:
			sg.Where = fmt.Sprintf("in imported document %d", refID)
		default:
			continue
		}
		sn.Sightings = append(sn.Sightings, sg)
	}
	return sn, srows.Err()
}

func clipLoc(s string) string {
	var b strings.Builder
	for _, r := range s {
		if b.Len() >= 80 {
			b.WriteString("...")
			break
		}
		if r < 0x20 || r == 0x7f {
			r = '?'
		}
		b.WriteRune(r)
	}
	return b.String()
}
