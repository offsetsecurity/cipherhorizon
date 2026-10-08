package store

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/example/cipherhorizon/internal/estate"
	"github.com/example/cipherhorizon/internal/tlsprobe"
)

// ProjectionVersion identifies the projection code. When it changes the graph is
// rebuilt from the stored documents on the next start (ENG-HANDOFF-002 D1), so a fix
// to a projection reaches old data without a data migration.
const ProjectionVersion = 1

// ObservationCap is the most observations one document contributes to the graph. It is a
// variable so tests can lower it.
var ObservationCap = 50000

// sourceInput describes a document being projected.
type sourceInput struct {
	Class        estate.SourceClass
	Stream       estate.Stream
	RefKind      string
	RefID        int64
	AssetID      int64 // 0 when the source belongs to a system directly (an import)
	SystemID     int64
	ToolName     string
	ToolVersion  string
	SHA256       string
	Size         int
	ObservedAt   time.Time
	SubmittedBy  string
	SubjectClaim string
	Uninterp     map[string]int
}

// writeSourceTx records one source and its observations, replacing any earlier
// projection of the same document, so projecting twice is the same as projecting once.
// An observation that fails validation is counted and skipped, never stored: one
// hostile value must not lose the rest of a document.
func (s *Store) writeSourceTx(tx *sql.Tx, in sourceInput, obs []estate.Observation) error {
	if !in.Class.Valid() || !in.Stream.Valid() {
		return fmt.Errorf("store: bad source class %q or stream %q", in.Class, in.Stream)
	}
	if _, err := tx.Exec(`DELETE FROM sources WHERE ref_kind = ? AND ref_id = ?`, in.RefKind, in.RefID); err != nil {
		return err
	}
	now := ts(s.now())
	res, err := tx.Exec(`INSERT INTO sources (class, stream, ref_kind, ref_id, asset_id, system_id, tool_name, tool_version, sha256, size,
		received_at, observed_at, submitted_by, subject_claim, is_current, not_interpreted_json)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, '{}')`,
		string(in.Class), string(in.Stream), in.RefKind, in.RefID, nullID(in.AssetID), nullID(in.SystemID), in.ToolName, in.ToolVersion,
		in.SHA256, in.Size, now, ts(in.ObservedAt), in.SubmittedBy, in.SubjectClaim)
	if err != nil {
		return err
	}
	sourceID, _ := res.LastInsertId()
	if err := s.insertObservations(tx, sourceID, in.Class, in.Stream, in.ObservedAt, in.Uninterp, obs); err != nil {
		return err
	}
	if in.AssetID == 0 {
		// A source that belongs to a system directly (an import) is its own current picture until withdrawn.
		if _, err := tx.Exec(`UPDATE sources SET is_current = 1 WHERE id = ?`, sourceID); err != nil {
			return err
		}
	}
	if in.AssetID != 0 {
		// The newest source of each kind for an asset is the current picture of it.
		if _, err := tx.Exec(`UPDATE sources SET is_current = (id = (SELECT id FROM sources WHERE asset_id = ? AND ref_kind = ? ORDER BY ref_id DESC LIMIT 1))
			WHERE asset_id = ? AND ref_kind = ?`, in.AssetID, in.RefKind, in.AssetID, in.RefKind); err != nil {
			return err
		}
	}
	return nil
}

// maxConflictNotes bounds how many attribute conflicts one import records by name.
const maxConflictNotes = 50

// insertObservations validates and stores the observations of an existing source, and records
// on the source what was not interpreted, refused, or in conflict with earlier evidence. Rebuilding
// an import's projection calls it on the source it already has.
//
// Precedence (SECARCH-001 SR-18): an untrusted source can add entities and attributes, but it
// never replaces a value that is already there, so an imported document cannot overwrite what a
// scan or a collector observed. Where it disagrees, the disagreement is recorded on the source
// and shown next to the first-party value, not resolved.
func (s *Store) insertObservations(tx *sql.Tx, sourceID int64, class estate.SourceClass, stream estate.Stream, observedAt time.Time, uninterpIn map[string]int, obs []estate.Observation) error {
	uninterp := map[string]int{}
	for k, v := range uninterpIn {
		uninterp[k] = v
	}
	var accepted []estate.Observation
	for _, o := range obs {
		if err := estate.Validate(stream, o); err != nil {
			uninterp["refused by validation"]++
			continue
		}
		if len(accepted) >= ObservationCap {
			// A document can be made to hold millions of components; the graph keeps a bounded
			// number and says how many it did not (SECARCH-001 SR-01).
			uninterp["over the per-document limit"]++
			continue
		}
		accepted = append(accepted, o)
	}
	cache := entityCache{tx: tx, ids: map[string]int64{}, attrs: map[string]map[string]string{}, firstParty: class.FirstParty()}
	at := ts(observedAt)
	for _, o := range accepted {
		eid, err := cache.upsert(o.Entity)
		if err != nil {
			return err
		}
		oa, _ := json.Marshal(nonNil(o.Attrs))
		if _, err := tx.Exec(`INSERT INTO observations (source_id, entity_id, relation, via, rung, class, method, quality, observed_at, attrs_json)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, sourceID, eid, o.Relation, o.Via, string(o.Rung), int(o.Class), o.Method, o.Quality, at, string(oa)); err != nil {
			return err
		}
	}
	for i, c := range cache.conflicts {
		if i >= maxConflictNotes {
			uninterp["further conflicts with first-party evidence"] = len(cache.conflicts) - maxConflictNotes
			break
		}
		uninterp[c]++
	}
	ui, _ := json.Marshal(uninterp)
	_, err := tx.Exec(`UPDATE sources SET not_interpreted_json = ? WHERE id = ?`, string(ui), sourceID)
	return err
}

func nullID(id int64) any {
	if id == 0 {
		return nil
	}
	return id
}

func nonNil(m map[string]string) map[string]string {
	if m == nil {
		return map[string]string{}
	}
	return m
}

// entityCache upserts entities, merging attributes: a value seen later replaces an
// earlier one, but an attribute only one source knew (a key size the host document
// lacks) is kept.
type entityCache struct {
	tx    *sql.Tx
	ids   map[string]int64
	attrs map[string]map[string]string
	// firstParty is true for the product's own scanner and collector. Anything else may add
	// but never replace (see insertObservations).
	firstParty bool
	conflicts  []string
}

func (c *entityCache) upsert(e estate.Entity) (int64, error) {
	k := e.Kind + "\x00" + e.Key
	if id, ok := c.ids[k]; ok {
		merged := c.merge(c.attrs[k], e)
		c.attrs[k] = merged
		return id, c.write(id, e.Name, merged)
	}
	var id int64
	var raw string
	err := c.tx.QueryRow(`SELECT id, attrs_json FROM entities WHERE kind = ? AND key = ?`, e.Kind, e.Key).Scan(&id, &raw)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		merged := mergeAttrs(nil, e.Attrs)
		ja, _ := json.Marshal(merged)
		res, err := c.tx.Exec(`INSERT INTO entities (kind, key, name, attrs_json) VALUES (?, ?, ?, ?)`, e.Kind, e.Key, e.Name, string(ja))
		if err != nil {
			return 0, err
		}
		id, _ = res.LastInsertId()
		c.ids[k], c.attrs[k] = id, merged
		return id, nil
	case err != nil:
		return 0, err
	}
	var old map[string]string
	_ = json.Unmarshal([]byte(raw), &old)
	merged := c.merge(old, e)
	c.ids[k], c.attrs[k] = id, merged
	return id, c.write(id, e.Name, merged)
}

// merge combines an entity's stored attributes with a new sighting's. First-party sightings
// replace; others only fill what is missing and note any disagreement.
func (c *entityCache) merge(old map[string]string, e estate.Entity) map[string]string {
	if c.firstParty {
		return mergeAttrs(old, e.Attrs)
	}
	out := map[string]string{}
	for k, v := range old {
		out[k] = v
	}
	for k, v := range e.Attrs {
		if have, ok := out[k]; !ok {
			out[k] = v
		} else if have != v {
			c.conflicts = append(c.conflicts, fmt.Sprintf("conflict with first-party evidence: %s %s (this document says %q, the graph has %q)", shortKey(e.Key), k, clipText(v, 40), clipText(have, 40)))
		}
	}
	return out
}

func shortKey(k string) string {
	if len(k) > 24 {
		return k[:24] + "..."
	}
	return k
}

func clipText(s string, n int) string {
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}

func (c *entityCache) write(id int64, name string, attrs map[string]string) error {
	ja, _ := json.Marshal(attrs)
	if !c.firstParty {
		// An untrusted source names a new entity but never renames an existing one.
		_, err := c.tx.Exec(`UPDATE entities SET name = CASE WHEN name = '' THEN ? ELSE name END, attrs_json = ? WHERE id = ?`, name, string(ja), id)
		return err
	}
	_, err := c.tx.Exec(`UPDATE entities SET name = CASE WHEN ? <> '' THEN ? ELSE name END, attrs_json = ? WHERE id = ?`, name, name, string(ja), id)
	return err
}

func mergeAttrs(old, add map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range old {
		out[k] = v
	}
	for k, v := range add {
		out[k] = v
	}
	return out
}

// ---- projecting documents -------------------------------------------------------------------

// projectScanTx projects one finished scan. Scans that did not finish, or whose report
// cannot be read, project nothing.
func (s *Store) projectScanTx(tx *sql.Tx, scanID int64) error {
	var assetID int64
	var status string
	var report []byte
	var finished sql.NullString
	err := tx.QueryRow(`SELECT asset_id, status, report_json, finished_at FROM scans WHERE id = ?`, scanID).Scan(&assetID, &status, &report, &finished)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if status != StatusDone || len(report) == 0 {
		return nil
	}
	var rep tlsprobe.Report
	if err := json.Unmarshal(report, &rep); err != nil {
		return nil // an unreadable report is not a projection error; the raw document is still there
	}
	at := s.now()
	if t := parseTS(finished); t != nil {
		at = *t
	}
	sum := sha256.Sum256(report)
	err = s.writeSourceTx(tx, sourceInput{
		Class: estate.ClassScanner, Stream: estate.StreamNetwork, RefKind: "scan", RefID: scanID, AssetID: assetID,
		ToolName: "cipherhorizon-tls", ToolVersion: rep.SchemaVersion, SHA256: hex.EncodeToString(sum[:]), Size: len(report), ObservedAt: at,
	}, estate.FromScanReport(&rep))
	return err
}

// projectSnapshotTx projects one stored host upload.
func (s *Store) projectSnapshotTx(tx *sql.Tx, snapshotID int64) error {
	var assetID int64
	var at, class, by string
	var raw []byte
	err := tx.QueryRow(`SELECT asset_id, at, cbom_json, source_class, submitted_by FROM host_snapshots WHERE id = ?`, snapshotID).Scan(&assetID, &at, &raw, &class, &by)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	var bom cdx.BOM
	if err := cdx.NewBOMDecoder(bytes.NewReader(raw), cdx.BOMFileFormatJSON).Decode(&bom); err != nil {
		return nil
	}
	observed := s.now()
	if t := parseTS(sql.NullString{String: at, Valid: true}); t != nil {
		observed = *t
	}
	sc := estate.SourceClass(class)
	if !sc.Valid() {
		sc = estate.ClassImported
	}
	res := estate.FromHostCBOM(&bom)
	tool, ver := producer(&bom)
	sum := sha256.Sum256(raw)
	err = s.writeSourceTx(tx, sourceInput{
		Class: sc, Stream: estate.StreamHost, RefKind: "host_snapshot", RefID: snapshotID, AssetID: assetID,
		ToolName: tool, ToolVersion: ver, SHA256: hex.EncodeToString(sum[:]), Size: len(raw), ObservedAt: observed, SubmittedBy: by, Uninterp: res.Uninterpreted,
	}, res.Observations)
	return err
}

// producer is the tool a document says made it. It is a claim, recorded and shown,
// never a trust input.
func producer(bom *cdx.BOM) (name, version string) {
	if bom.Metadata == nil || bom.Metadata.Tools == nil || bom.Metadata.Tools.Components == nil || len(*bom.Metadata.Tools.Components) == 0 {
		return "", ""
	}
	t := (*bom.Metadata.Tools.Components)[0]
	return capText(t.Name, 100), capText(t.Version, 50)
}

func capText(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// projectQuietly projects a document after it is stored. A failure never fails the
// operation that stored the document: the graph is derived, the document is the truth.
// The failure is logged and remembered, and Maintain (or the next start) rebuilds.
func (s *Store) projectQuietly(fn func(tx *sql.Tx) error) {
	tx, err := s.db.Begin()
	if err == nil {
		err = fn(tx)
		if err == nil {
			err = tx.Commit()
		} else {
			_ = tx.Rollback()
		}
	}
	if err != nil {
		s.markStale("projecting a stored document", err)
	}
}

// markStale records that derived data (the graph or its links) could not be updated, so it is
// rebuilt from the stored documents by the next Maintain or start.
func (s *Store) markStale(what string, cause error) {
	s.log.Warn(what+" failed; the graph will be rebuilt", "err", cause)
	if _, err := s.db.Exec(`UPDATE projection_state SET stale = 1`); err != nil {
		s.log.Error("marking the graph for a rebuild failed; it is rebuilt at the next start", "err", err)
	}
}

// deriveTx runs derived-data work inside tx under a savepoint. If it fails, its writes are undone and
// false is returned; the surrounding transaction is unaffected.
func (s *Store) deriveTx(tx *sql.Tx, fn func() error) bool {
	if _, err := tx.Exec(`SAVEPOINT derive`); err != nil {
		return false
	}
	if err := fn(); err != nil {
		_, _ = tx.Exec(`ROLLBACK TO derive`)
		_, _ = tx.Exec(`RELEASE derive`)
		return false
	}
	_, err := tx.Exec(`RELEASE derive`)
	return err == nil
}

// pruneOrphans removes projections whose document was deleted (an asset deleted with its
// documents) and entities nothing observes any more. It sweeps whole tables, so it runs from
// Maintain, not after every write: retention removes its own projections as it goes
// (deleteSourcesTx).
func (s *Store) pruneOrphans() error {
	for _, q := range []string{
		`DELETE FROM sources WHERE ref_kind = 'scan' AND NOT EXISTS (SELECT 1 FROM scans sc WHERE sc.id = sources.ref_id)`,
		`DELETE FROM sources WHERE ref_kind = 'host_snapshot' AND NOT EXISTS (SELECT 1 FROM host_snapshots h WHERE h.id = sources.ref_id)`,
		`DELETE FROM entities WHERE NOT EXISTS (SELECT 1 FROM observations o WHERE o.entity_id = entities.id)`,
	} {
		if _, err := s.db.Exec(q); err != nil {
			return err
		}
	}
	return nil
}

// deleteSourcesTx removes the projections of the given documents (their observations go by
// cascade) and then the entities that only they observed. It is the scoped, per-write form of
// pruneOrphans: it touches the rows of those documents, not the whole graph.
func deleteSourcesTx(tx *sql.Tx, refKind string, refIDs []int64) error {
	for len(refIDs) > 500 { // well under SQLite's cap on parameters per statement
		if err := deleteSourcesTx(tx, refKind, refIDs[:500]); err != nil {
			return err
		}
		refIDs = refIDs[500:]
	}
	if len(refIDs) == 0 {
		return nil
	}
	ph := strings.TrimSuffix(strings.Repeat("?,", len(refIDs)), ",")
	args := make([]any, 0, len(refIDs)+1)
	args = append(args, refKind)
	for _, id := range refIDs {
		args = append(args, id)
	}
	entityIDs, err := ids(tx, `SELECT DISTINCT o.entity_id FROM observations o JOIN sources src ON src.id = o.source_id
		WHERE src.ref_kind = ? AND src.ref_id IN (`+ph+`)`, args...)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM sources WHERE ref_kind = ? AND ref_id IN (`+ph+`)`, args...); err != nil { //nolint:gosec // ph is only "?" placeholders
		return err
	}
	for start := 0; start < len(entityIDs); start += 500 {
		batch := entityIDs[start:min(start+500, len(entityIDs))]
		eargs := make([]any, len(batch))
		for i, id := range batch {
			eargs[i] = id
		}
		eph := strings.TrimSuffix(strings.Repeat("?,", len(batch)), ",")
		q := `DELETE FROM entities WHERE id IN (` + eph + `) AND NOT EXISTS (SELECT 1 FROM observations o WHERE o.entity_id = entities.id)` //nolint:gosec // eph is only "?" placeholders
		if _, err := tx.Exec(q, eargs...); err != nil {
			return err
		}
	}
	return nil
}

// Maintain repairs derived data in the background: it rebuilds the graph if a projection or a
// correlation failed since the last build, and sweeps orphans left by deleted assets. The
// server calls it periodically, so a failure is repaired without waiting for a restart.
func (s *Store) Maintain() error {
	if err := s.ensureProjection(); err != nil {
		return fmt.Errorf("rebuilding the graph: %w", err)
	}
	if err := s.pruneOrphans(); err != nil {
		return fmt.Errorf("removing orphaned graph rows: %w", err)
	}
	return nil
}

// ---- rebuild --------------------------------------------------------------------------------

// ensureProjection rebuilds the graph when it was built by other projection code, or
// when a projection failed since the last build.
func (s *Store) ensureProjection() error {
	var version, stale int
	if err := s.db.QueryRow(`SELECT version, stale FROM projection_state WHERE id = 1`).Scan(&version, &stale); err != nil {
		return err
	}
	if version == ProjectionVersion && stale == 0 {
		return nil
	}
	_, err := s.RebuildGraph()
	return err
}

// GraphCounts says what a rebuild produced.
type GraphCounts struct {
	Sources      int `json:"sources"`
	Entities     int `json:"entities"`
	Observations int `json:"observations"`
}

// RebuildGraph drops the projection and rebuilds it from the stored documents, in
// one transaction: it is complete or it does not happen. Imported documents are the one
// thing kept as sources rather than re-derived from another table, so they are
// re-projected by their own rebuild step when that exists.
func (s *Store) RebuildGraph() (GraphCounts, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return GraphCounts{}, err
	}
	defer func() { _ = tx.Rollback() }()

	for _, q := range []string{
		`DELETE FROM observations`,
		`DELETE FROM sources WHERE ref_kind IN ('scan', 'host_snapshot')`,
		`DELETE FROM entities`,
	} {
		if _, err := tx.Exec(q); err != nil {
			return GraphCounts{}, err
		}
	}
	scanIDs, err := ids(tx, `SELECT id FROM scans WHERE status = 'done' AND report_json IS NOT NULL ORDER BY id`)
	if err != nil {
		return GraphCounts{}, err
	}
	for _, id := range scanIDs {
		if err := s.projectScanTx(tx, id); err != nil {
			return GraphCounts{}, err
		}
	}
	snapIDs, err := ids(tx, `SELECT id FROM host_snapshots ORDER BY id`)
	if err != nil {
		return GraphCounts{}, err
	}
	for _, id := range snapIDs {
		if err := s.projectSnapshotTx(tx, id); err != nil {
			return GraphCounts{}, err
		}
	}
	if err := s.reprojectImportsTx(tx); err != nil {
		return GraphCounts{}, err
	}
	if _, err := tx.Exec(`UPDATE projection_state SET version = ?, built_at = ?, stale = 0 WHERE id = 1`, ProjectionVersion, ts(s.now())); err != nil {
		return GraphCounts{}, err
	}
	if err := s.correlateTx(tx); err != nil {
		return GraphCounts{}, err
	}
	var c GraphCounts
	if err := tx.QueryRow(`SELECT (SELECT COUNT(*) FROM sources), (SELECT COUNT(*) FROM entities), (SELECT COUNT(*) FROM observations)`).Scan(&c.Sources, &c.Entities, &c.Observations); err != nil {
		return GraphCounts{}, err
	}
	return c, tx.Commit()
}

func ids(tx *sql.Tx, q string, args ...any) ([]int64, error) {
	rows, err := tx.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck // read-only
	var out []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// ---- reading the graph ----------------------------------------------------------------------

// Entity is a thing in the graph with when it was first and last observed.
type Entity struct {
	ID        int64             `json:"id"`
	Kind      string            `json:"kind"`
	Key       string            `json:"key"`
	Name      string            `json:"name"`
	Attrs     map[string]string `json:"attrs"`
	FirstSeen time.Time         `json:"firstSeen"`
	LastSeen  time.Time         `json:"lastSeen"`
	// Current is true when a current source (the latest picture of an asset, or an
	// active import) still observes it. False means "no longer observed", not deleted.
	Current bool `json:"current"`
	Seen    int  `json:"observations"`
}

// Entities lists entities of a kind (all kinds when empty), most recently seen first.
func (s *Store) Entities(kind string, limit int) ([]Entity, error) {
	if limit <= 0 || limit > 5000 {
		limit = 1000
	}
	q := `SELECT e.id, e.kind, e.key, e.name, e.attrs_json, MIN(o.observed_at), MAX(o.observed_at), COUNT(*),
		MAX(CASE WHEN src.is_current = 1 AND src.status = 'active' THEN 1 ELSE 0 END)
		FROM entities e JOIN observations o ON o.entity_id = e.id JOIN sources src ON src.id = o.source_id`
	var args []any
	if kind != "" {
		q += ` WHERE e.kind = ?`
		args = append(args, kind)
	}
	q += ` GROUP BY e.id ORDER BY MAX(o.observed_at) DESC, e.id LIMIT ?`
	args = append(args, limit)
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck // read-only
	out := []Entity{}
	for rows.Next() {
		var e Entity
		var attrs, first, last string
		var cur int
		if err := rows.Scan(&e.ID, &e.Kind, &e.Key, &e.Name, &attrs, &first, &last, &e.Seen, &cur); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(attrs), &e.Attrs)
		if t := parseTS(sql.NullString{String: first, Valid: true}); t != nil {
			e.FirstSeen = *t
		}
		if t := parseTS(sql.NullString{String: last, Valid: true}); t != nil {
			e.LastSeen = *t
		}
		e.Current = cur == 1
		out = append(out, e)
	}
	return out, rows.Err()
}

// ObservationRow is one observation with where it came from.
type ObservationRow struct {
	ID         int64             `json:"id"`
	SourceID   int64             `json:"sourceId"`
	SourceKind string            `json:"sourceKind"`
	Class      string            `json:"sourceClass"`
	Stream     string            `json:"stream"`
	AssetID    int64             `json:"assetId,omitempty"`
	SystemID   int64             `json:"systemId"`
	Entity     Entity            `json:"entity"`
	Relation   string            `json:"relation"`
	Via        string            `json:"via,omitempty"`
	Rung       string            `json:"rung"`
	EvClass    int               `json:"evidenceClass"`
	Method     string            `json:"method"`
	Quality    string            `json:"methodQuality"`
	ObservedAt time.Time         `json:"observedAt"`
	Attrs      map[string]string `json:"attrs,omitempty"`
	Current    bool              `json:"current"`
}

// SystemObservations returns the observations of a system: those made through its
// assets and those from sources assigned to it. Current-only limits it to the latest
// picture of each source.
func (s *Store) SystemObservations(systemID int64, currentOnly bool) ([]ObservationRow, error) {
	q := `SELECT o.id, o.source_id, src.ref_kind, src.class, src.stream, COALESCE(src.asset_id, 0), ?, e.id, e.kind, e.key, e.name, e.attrs_json,
		o.relation, o.via, o.rung, o.class, o.method, o.quality, o.observed_at, o.attrs_json, src.is_current
		FROM observations o JOIN sources src ON src.id = o.source_id JOIN entities e ON e.id = o.entity_id
		LEFT JOIN assets a ON a.id = src.asset_id
		WHERE COALESCE(a.system_id, src.system_id) = ? AND src.status = 'active'`
	if currentOnly {
		q += ` AND src.is_current = 1`
	}
	q += ` ORDER BY o.id`
	rows, err := s.db.Query(q, systemID, systemID)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck // read-only
	out := []ObservationRow{}
	for rows.Next() {
		var r ObservationRow
		var eattrs, oattrs, at string
		var cur int
		if err := rows.Scan(&r.ID, &r.SourceID, &r.SourceKind, &r.Class, &r.Stream, &r.AssetID, &r.SystemID, &r.Entity.ID, &r.Entity.Kind, &r.Entity.Key,
			&r.Entity.Name, &eattrs, &r.Relation, &r.Via, &r.Rung, &r.EvClass, &r.Method, &r.Quality, &at, &oattrs, &cur); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(eattrs), &r.Entity.Attrs)
		_ = json.Unmarshal([]byte(oattrs), &r.Attrs)
		if t := parseTS(sql.NullString{String: at, Valid: true}); t != nil {
			r.ObservedAt = *t
		}
		r.Current = cur == 1
		out = append(out, r)
	}
	return out, rows.Err()
}

// GraphStats counts the graph by kind and by source class, for the API and for QA.
type GraphStats struct {
	Entities     map[string]int `json:"entities"`
	Observations map[string]int `json:"observationsBySourceClass"`
	Sources      int            `json:"sources"`
	BuiltAt      string         `json:"builtAt"`
	Version      int            `json:"projectionVersion"`
	Stale        bool           `json:"stale"`
}

// Stats summarises the graph.
func (s *Store) Stats() (GraphStats, error) {
	st := GraphStats{Entities: map[string]int{}, Observations: map[string]int{}}
	rows, err := s.db.Query(`SELECT kind, COUNT(*) FROM entities GROUP BY kind`)
	if err != nil {
		return st, err
	}
	for rows.Next() {
		var k string
		var n int
		if err := rows.Scan(&k, &n); err != nil {
			_ = rows.Close()
			return st, err
		}
		st.Entities[k] = n
	}
	_ = rows.Close()
	rows, err = s.db.Query(`SELECT src.class, COUNT(*) FROM observations o JOIN sources src ON src.id = o.source_id GROUP BY src.class`)
	if err != nil {
		return st, err
	}
	for rows.Next() {
		var k string
		var n int
		if err := rows.Scan(&k, &n); err != nil {
			_ = rows.Close()
			return st, err
		}
		st.Observations[k] = n
	}
	_ = rows.Close()
	var stale int
	if err := s.db.QueryRow(`SELECT (SELECT COUNT(*) FROM sources), built_at, version, stale FROM projection_state WHERE id = 1`).Scan(&st.Sources, &st.BuiltAt, &st.Version, &stale); err != nil {
		return st, err
	}
	st.Stale = stale != 0
	return st, nil
}
