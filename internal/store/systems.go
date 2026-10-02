package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// System is the unit an owner answers for: one or more assets (a host, the endpoints
// it serves) plus what a person knows about it that no scanner can observe. Every
// field a person may set is optional; an empty one means "not provided", never a
// default (PRD-003 REQ-SYS-1). The M-23-02 items 1, 2, 3, 7 and 8 live here because
// CISA says no tool can collect them.
type System struct {
	ID                int64     `json:"id"`
	Name              string    `json:"name"`
	Owner             string    `json:"owner"`
	Environment       string    `json:"environment"`
	Criticality       string    `json:"criticality"`
	Exposure          string    `json:"exposure"`
	DataLifetimeYears *int      `json:"dataLifetimeYears"`
	FISMAID           string    `json:"fismaId"`
	FIPS199           string    `json:"fips199"`
	HVAID             string    `json:"hvaId"`
	Hosting           string    `json:"hosting"`
	HostingProvider   string    `json:"hostingProvider"`
	Notes             string    `json:"notes"`
	CreatedAt         time.Time `json:"createdAt"`
	UpdatedAt         time.Time `json:"updatedAt"`

	Assets []SystemAsset `json:"assets"`
}

// SystemAsset is an asset as listed under its system.
type SystemAsset struct {
	ID      int64  `json:"id"`
	Kind    string `json:"kind"`
	Name    string `json:"name"`
	Address string `json:"address"`
}

// The allowed values of the enumerated fields. An empty value is always allowed.
var (
	Environments  = []string{"production", "staging", "development", "other"}
	Criticalities = []string{"low", "moderate", "high"} // the FIPS 199 impact vocabulary
	Exposures     = []string{"internet", "internal", "restricted"}
	FIPS199Levels = []string{"low", "moderate", "high"}
	HostingKinds  = []string{"on-premises", "commercial-cloud", "government-cloud", "hybrid"}
)

// SystemFields lists the editable fields, in display order. They are also the CSV columns.
var SystemFields = []string{"name", "owner", "environment", "criticality", "exposure", "dataLifetimeYears",
	"fismaId", "fips199", "hvaId", "hosting", "hostingProvider", "notes"}

// Limits on what a person may enter. They are also what a hostile CSV is held to.
const (
	maxNameLen  = 200
	maxShortLen = 200
	maxIDLen    = 100
	maxNotesLen = 4000
	maxLifetime = 200
)

// ErrInvalid marks input the store refuses. The wrapped message names the field.
var ErrInvalid = errors.New("invalid")

// ErrConflict marks a merge that would overwrite different operator-set values.
var ErrConflict = errors.New("conflict")

// ConflictError lists the fields on which two systems disagree.
type ConflictError struct{ Fields []string }

func (e *ConflictError) Error() string {
	return "the systems have different values for: " + strings.Join(e.Fields, ", ")
}

// Is makes errors.Is(err, ErrConflict) true.
func (e *ConflictError) Is(target error) bool { return target == ErrConflict }

// SystemPatch changes some fields of a system. A key that is absent is left alone; a
// nil value clears the field; a string (or, for dataLifetimeYears, a number) sets it.
type SystemPatch map[string]any

func inSet(v string, allowed []string) bool {
	if v == "" {
		return true
	}
	for _, a := range allowed {
		if v == a {
			return true
		}
	}
	return false
}

// text checks a free-text value: valid UTF-8, within max bytes, and no control
// characters (newlines are allowed only where multi is set).
func text(field, v string, max int, multi bool) error {
	if len(v) > max || !utf8.ValidString(v) {
		return fmt.Errorf("%w: %s is over %d bytes or not valid UTF-8", ErrInvalid, field, max)
	}
	for _, r := range v {
		if r == '\n' && multi {
			continue
		}
		if unicode.IsControl(r) {
			return fmt.Errorf("%w: %s contains a control character", ErrInvalid, field)
		}
	}
	return nil
}

// normalizeField validates one field and returns its stored form: a string, or an
// *int for the lifetime (nil clears it).
func normalizeField(field string, v any) (any, error) {
	if field == "dataLifetimeYears" {
		switch n := v.(type) {
		case nil:
			return (*int)(nil), nil
		case float64:
			if n != float64(int(n)) || n < 0 || n > maxLifetime {
				return nil, fmt.Errorf("%w: dataLifetimeYears must be a whole number from 0 to %d", ErrInvalid, maxLifetime)
			}
			i := int(n)
			return &i, nil
		case int:
			if n < 0 || n > maxLifetime {
				return nil, fmt.Errorf("%w: dataLifetimeYears must be a whole number from 0 to %d", ErrInvalid, maxLifetime)
			}
			return &n, nil
		}
		return nil, fmt.Errorf("%w: dataLifetimeYears must be a number", ErrInvalid)
	}
	var str string
	switch t := v.(type) {
	case nil:
		str = ""
	case string:
		str = strings.TrimSpace(t)
	default:
		return nil, fmt.Errorf("%w: %s must be text", ErrInvalid, field)
	}
	enum := map[string][]string{"environment": Environments, "criticality": Criticalities, "exposure": Exposures, "fips199": FIPS199Levels, "hosting": HostingKinds}
	if allowed, ok := enum[field]; ok {
		if !inSet(str, allowed) {
			return nil, fmt.Errorf("%w: %s must be one of %s", ErrInvalid, field, strings.Join(allowed, ", "))
		}
		return str, nil
	}
	switch field {
	case "name":
		if v == nil || str == "" {
			return nil, fmt.Errorf("%w: a system needs a name", ErrInvalid)
		}
		return str, text(field, str, maxNameLen, false)
	case "owner", "hostingProvider":
		return str, text(field, str, maxShortLen, false)
	case "fismaId", "hvaId":
		return str, text(field, str, maxIDLen, false)
	case "notes":
		return str, text(field, str, maxNotesLen, true)
	}
	return nil, fmt.Errorf("%w: unknown field %q", ErrInvalid, field)
}

// ValidateSystemPatch checks a patch without applying it, so a bulk import can report
// every problem before changing anything.
func ValidateSystemPatch(p SystemPatch) error {
	for f, v := range p {
		if _, err := normalizeField(f, v); err != nil {
			return err
		}
	}
	return nil
}

// IsSystemField reports whether name is an editable system field.
func IsSystemField(name string) bool {
	_, ok := systemColumns[name]
	return ok
}

// systemColumns maps a field to its column.
var systemColumns = map[string]string{
	"name": "name", "owner": "owner", "environment": "environment", "criticality": "criticality",
	"exposure": "exposure", "dataLifetimeYears": "data_lifetime_years", "fismaId": "fisma_id", "fips199": "fips199",
	"hvaId": "hva_id", "hosting": "hosting", "hostingProvider": "hosting_provider", "notes": "notes",
}

const systemCols = `id, name, owner, environment, criticality, exposure, data_lifetime_years, fisma_id, fips199, hva_id, hosting, hosting_provider, notes, created_at, updated_at`

func scanSystem(r scanner) (System, error) {
	var sys System
	var life sql.NullInt64
	var created, updated string
	if err := r.Scan(&sys.ID, &sys.Name, &sys.Owner, &sys.Environment, &sys.Criticality, &sys.Exposure, &life, &sys.FISMAID,
		&sys.FIPS199, &sys.HVAID, &sys.Hosting, &sys.HostingProvider, &sys.Notes, &created, &updated); err != nil {
		return System{}, err
	}
	if life.Valid {
		n := int(life.Int64)
		sys.DataLifetimeYears = &n
	}
	if t := parseTS(sql.NullString{String: created, Valid: true}); t != nil {
		sys.CreatedAt = *t
	}
	if t := parseTS(sql.NullString{String: updated, Valid: true}); t != nil {
		sys.UpdatedAt = *t
	}
	sys.Assets = []SystemAsset{}
	return sys, nil
}

// fieldMap is a system's editable fields as they are recorded in the audit log.
func (sys System) fieldMap() map[string]any {
	m := map[string]any{
		"name": sys.Name, "owner": sys.Owner, "environment": sys.Environment, "criticality": sys.Criticality,
		"exposure": sys.Exposure, "fismaId": sys.FISMAID, "fips199": sys.FIPS199, "hvaId": sys.HVAID,
		"hosting": sys.Hosting, "hostingProvider": sys.HostingProvider, "notes": sys.Notes,
	}
	if sys.DataLifetimeYears != nil {
		m["dataLifetimeYears"] = *sys.DataLifetimeYears
	} else {
		m["dataLifetimeYears"] = nil
	}
	return m
}

// Provided reports which optional fields a person has filled in.
func (sys System) Provided() []string {
	var out []string
	for _, f := range SystemFields[1:] { // the name is always there
		if v := sys.fieldMap()[f]; v != nil && v != "" {
			out = append(out, f)
		}
	}
	return out
}

// ListSystems returns every system with its assets, ordered by name.
func (s *Store) ListSystems() ([]System, error) {
	rows, err := s.db.Query(`SELECT ` + systemCols + ` FROM systems ORDER BY lower(name), id`)
	if err != nil {
		return nil, err
	}
	var out []System
	byID := map[int64]int{}
	for rows.Next() {
		sys, err := scanSystem(rows)
		if err != nil {
			_ = rows.Close()
			return nil, err
		}
		byID[sys.ID] = len(out)
		out = append(out, sys)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, err
	}
	_ = rows.Close()
	if err := s.attachAssets(out, byID); err != nil {
		return nil, err
	}
	if out == nil {
		out = []System{}
	}
	return out, nil
}

func (s *Store) attachAssets(out []System, byID map[int64]int) error {
	rows, err := s.db.Query(`SELECT system_id, id, kind, name, host, port FROM assets WHERE system_id IS NOT NULL ORDER BY id`)
	if err != nil {
		return err
	}
	defer rows.Close() //nolint:errcheck // read-only
	for rows.Next() {
		var sid int64
		var a Asset
		if err := rows.Scan(&sid, &a.ID, &a.Kind, &a.Name, &a.Host, &a.Port); err != nil {
			return err
		}
		if i, ok := byID[sid]; ok {
			out[i].Assets = append(out[i].Assets, SystemAsset{ID: a.ID, Kind: a.Kind, Name: a.Name, Address: a.Address()})
		}
	}
	return rows.Err()
}

// GetSystem returns one system with its assets.
func (s *Store) GetSystem(id int64) (System, error) {
	sys, err := scanSystem(s.db.QueryRow(`SELECT `+systemCols+` FROM systems WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return System{}, ErrNotFound
	}
	if err != nil {
		return System{}, err
	}
	out := []System{sys}
	if err := s.attachAssets(out, map[int64]int{id: 0}); err != nil {
		return System{}, err
	}
	return out[0], nil
}

// UpdateSystem applies a validated patch and records who changed what, in the same
// transaction (SR-11). A patch that changes nothing writes nothing.
func (s *Store) UpdateSystem(id int64, patch SystemPatch, actor, reason string) (System, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return System{}, err
	}
	defer func() { _ = tx.Rollback() }()
	if err := s.applyPatchTx(tx, id, patch, actor, reason); err != nil {
		return System{}, err
	}
	if err := tx.Commit(); err != nil {
		return System{}, err
	}
	return s.GetSystem(id)
}

// SystemPatchByID is one row of a bulk update.
type SystemPatchByID struct {
	ID    int64
	Patch SystemPatch
}

// UpdateSystems applies several patches atomically: all of them, or none.
func (s *Store) UpdateSystems(patches []SystemPatchByID, actor, reason string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	for _, p := range patches {
		if err := s.applyPatchTx(tx, p.ID, p.Patch, actor, reason); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) applyPatchTx(tx *sql.Tx, id int64, patch SystemPatch, actor, reason string) error {
	before, err := scanSystem(tx.QueryRow(`SELECT `+systemCols+` FROM systems WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	beforeMap := before.fieldMap()
	fields := make([]string, 0, len(patch))
	for f := range patch {
		fields = append(fields, f)
	}
	sort.Strings(fields)

	var sets []string
	var args []any
	oldVals, newVals := map[string]any{}, map[string]any{}
	for _, f := range fields {
		norm, err := normalizeField(f, patch[f])
		if err != nil {
			return err
		}
		newVal := norm
		if p, ok := norm.(*int); ok {
			if p == nil {
				newVal = nil
			} else {
				newVal = *p
			}
		}
		if fmt.Sprint(beforeMap[f]) == fmt.Sprint(newVal) && (beforeMap[f] == nil) == (newVal == nil) {
			continue
		}
		oldVals[f], newVals[f] = beforeMap[f], newVal
		sets = append(sets, systemColumns[f]+" = ?")
		args = append(args, newVal)
	}
	if len(sets) == 0 {
		return nil
	}
	now := ts(s.now())
	sets = append(sets, "updated_at = ?")
	args = append(args, now, id)
	// The column names come from the fixed systemColumns table, never from input; values are bound.
	if _, err := tx.Exec(`UPDATE systems SET `+strings.Join(sets, ", ")+` WHERE id = ?`, args...); err != nil { //nolint:gosec // G202: allow-listed column names
		return err
	}
	return audit(tx, now, actor, id, "update", oldVals, newVals, reason)
}

// ---- audit -----------------------------------------------------------------------------------

// AuditEntry is one recorded change.
type AuditEntry struct {
	ID         int64           `json:"id"`
	At         time.Time       `json:"at"`
	Actor      string          `json:"actor"`
	ObjectKind string          `json:"objectKind"`
	ObjectID   int64           `json:"objectId"`
	Action     string          `json:"action"`
	Before     json.RawMessage `json:"before"`
	After      json.RawMessage `json:"after"`
	Reason     string          `json:"reason,omitempty"`
}

func audit(tx *sql.Tx, at, actor string, id int64, action string, before, after any, reason string) error {
	const kind = "system" // the only object kind audited so far
	b, err := json.Marshal(before)
	if err != nil {
		return err
	}
	a, err := json.Marshal(after)
	if err != nil {
		return err
	}
	if actor == "" {
		actor = "unknown"
	}
	_, err = tx.Exec(`INSERT INTO audit_log (at, actor, object_kind, object_id, action, before_json, after_json, reason) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		at, actor, kind, id, action, string(b), string(a), reason)
	return err
}

// Audit returns the recorded changes to one object, newest first.
func (s *Store) Audit(kind string, id int64, limit int) ([]AuditEntry, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := s.db.Query(`SELECT id, at, actor, object_kind, object_id, action, before_json, after_json, reason FROM audit_log
		WHERE object_kind = ? AND object_id = ? ORDER BY id DESC LIMIT ?`, kind, id, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck // read-only
	out := []AuditEntry{}
	for rows.Next() {
		var e AuditEntry
		var at, before, after string
		if err := rows.Scan(&e.ID, &at, &e.Actor, &e.ObjectKind, &e.ObjectID, &e.Action, &before, &after, &e.Reason); err != nil {
			return nil, err
		}
		if t := parseTS(sql.NullString{String: at, Valid: true}); t != nil {
			e.At = *t
		}
		e.Before, e.After = json.RawMessage(before), json.RawMessage(after)
		out = append(out, e)
	}
	return out, rows.Err()
}

// ---- merging and splitting -------------------------------------------------------------------

// mergeSystemsTx moves everything in system from into system to and deletes from. It
// refuses if both have a different, non-empty value for a field a person set (never a
// silent overwrite of operator data); a field empty on to is filled from from.
func (s *Store) mergeSystemsTx(tx *sql.Tx, fromID, toID int64, actor, reason string) error {
	if fromID == toID {
		return nil
	}
	from, err := scanSystem(tx.QueryRow(`SELECT `+systemCols+` FROM systems WHERE id = ?`, fromID))
	if err != nil {
		return notFound(err)
	}
	to, err := scanSystem(tx.QueryRow(`SELECT `+systemCols+` FROM systems WHERE id = ?`, toID))
	if err != nil {
		return notFound(err)
	}
	fm, tm := from.fieldMap(), to.fieldMap()
	var conflicts []string
	filled := map[string]any{}
	for _, f := range SystemFields[1:] {
		fv, tv := fm[f], tm[f]
		fEmpty, tEmpty := fv == nil || fv == "", tv == nil || tv == ""
		switch {
		case fEmpty:
		case tEmpty:
			filled[f] = fv
		case fmt.Sprint(fv) != fmt.Sprint(tv):
			conflicts = append(conflicts, f)
		}
	}
	if len(conflicts) > 0 {
		return &ConflictError{Fields: conflicts}
	}
	rows, err := tx.Query(`SELECT id FROM assets WHERE system_id = ? ORDER BY id`, fromID)
	if err != nil {
		return err
	}
	var moved []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			_ = rows.Close()
			return err
		}
		moved = append(moved, id)
	}
	_ = rows.Close()
	now := ts(s.now())
	if _, err := tx.Exec(`UPDATE assets SET system_id = ? WHERE system_id = ?`, toID, fromID); err != nil {
		return err
	}
	if _, err := tx.Exec(`UPDATE sources SET system_id = ? WHERE system_id = ?`, toID, fromID); err != nil {
		return err
	}
	// Trust anchors follow their system; one the target already holds is kept once.
	if _, err := tx.Exec(`UPDATE OR IGNORE trust_anchors SET system_id = ? WHERE system_id = ?`, toID, fromID); err != nil {
		return err
	}
	if len(filled) > 0 {
		var sets []string
		var args []any
		for f, v := range filled {
			sets = append(sets, systemColumns[f]+" = ?")
			args = append(args, v)
		}
		sort.Strings(sets)
		args = append(args, now, toID)
		if _, err := tx.Exec(`UPDATE systems SET `+strings.Join(sets, ", ")+`, updated_at = ? WHERE id = ?`, args...); err != nil { //nolint:gosec // G202: allow-listed column names
			return err
		}
	}
	if _, err := tx.Exec(`DELETE FROM systems WHERE id = ?`, fromID); err != nil {
		return err
	}
	// The merged-away system is recorded whole, so the merge can be understood and undone by hand.
	return audit(tx, now, actor, toID, "merge",
		map[string]any{"mergedSystemId": fromID, "mergedSystem": fm, "movedAssetIds": moved},
		map[string]any{"filled": filled}, reason)
}

func notFound(err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	return err
}

// splitAssetTx moves an asset (and the assets linked to it) into a new system of its own.
func (s *Store) splitAssetTx(tx *sql.Tx, assetIDs []int64, name, actor, reason string, fromSystem int64) error {
	now := ts(s.now())
	res, err := tx.Exec(`INSERT INTO systems (name, created_at, updated_at) VALUES (?, ?, ?)`, name, now, now)
	if err != nil {
		return err
	}
	newID, _ := res.LastInsertId()
	for _, id := range assetIDs {
		if _, err := tx.Exec(`UPDATE assets SET system_id = ? WHERE id = ?`, newID, id); err != nil {
			return err
		}
	}
	if err := audit(tx, now, actor, fromSystem, "split", map[string]any{"movedAssetIds": assetIDs},
		map[string]any{"newSystemId": newID}, reason); err != nil {
		return err
	}
	return nil
}

// pruneSystemIfEmpty deletes a system that nothing refers to and that holds no operator
// input: no asset, no source, and no field a person filled in.
func pruneSystemIfEmpty(tx *sql.Tx, id int64) error {
	var assets, sources int
	if err := tx.QueryRow(`SELECT (SELECT COUNT(*) FROM assets WHERE system_id = ?), (SELECT COUNT(*) FROM sources WHERE system_id = ?)`, id, id).Scan(&assets, &sources); err != nil {
		return err
	}
	if assets > 0 || sources > 0 {
		return nil
	}
	sys, err := scanSystem(tx.QueryRow(`SELECT `+systemCols+` FROM systems WHERE id = ?`, id))
	if err != nil {
		return notFound(err)
	}
	if len(sys.Provided()) > 0 {
		return nil
	}
	_, err = tx.Exec(`DELETE FROM systems WHERE id = ?`, id)
	return err
}

// backfillSystems gives every existing asset a system, one each, joining the assets a
// person had already linked by hand into one system (migration 4).
func backfillSystems(tx *sql.Tx, now time.Time) error {
	type asset struct {
		id   int64
		kind string
		name string
	}
	rows, err := tx.Query(`SELECT id, kind, name FROM assets ORDER BY id`)
	if err != nil {
		return err
	}
	var assets []asset
	for rows.Next() {
		var a asset
		if err := rows.Scan(&a.id, &a.kind, &a.name); err != nil {
			_ = rows.Close()
			return err
		}
		assets = append(assets, a)
	}
	_ = rows.Close()

	parent := map[int64]int64{}
	var find func(int64) int64
	find = func(x int64) int64 {
		if parent[x] == x {
			return x
		}
		parent[x] = find(parent[x])
		return parent[x]
	}
	for _, a := range assets {
		parent[a.id] = a.id
	}
	lrows, err := tx.Query(`SELECT asset_id, linked_asset_id FROM asset_links`)
	if err != nil {
		return err
	}
	for lrows.Next() {
		var a, b int64
		if err := lrows.Scan(&a, &b); err != nil {
			_ = lrows.Close()
			return err
		}
		if _, ok := parent[a]; ok {
			if _, ok := parent[b]; ok {
				parent[find(a)] = find(b)
			}
		}
	}
	_ = lrows.Close()

	// A snapshot recorded as made by this product's collector keeps that class; anything else
	// stays imported, because nothing in the database can prove more.
	srows, err := tx.Query(`SELECT id, summary_json FROM host_snapshots`)
	if err != nil {
		return err
	}
	var ours []int64
	for srows.Next() {
		var id int64
		var sum []byte
		if err := srows.Scan(&id, &sum); err != nil {
			_ = srows.Close()
			return err
		}
		var v struct {
			Producer string `json:"producer"`
		}
		if json.Unmarshal(sum, &v) == nil && strings.HasPrefix(strings.ToLower(v.Producer), "cipherhorizon") {
			ours = append(ours, id)
		}
	}
	_ = srows.Close()
	for _, id := range ours {
		if _, err := tx.Exec(`UPDATE host_snapshots SET source_class = 'collector' WHERE id = ?`, id); err != nil {
			return err
		}
	}

	// One system per component; a host's name wins, otherwise the lowest-numbered asset's.
	name := map[int64]string{}
	hostNamed := map[int64]bool{}
	for _, a := range assets {
		root := find(a.id)
		if _, ok := name[root]; !ok {
			name[root] = a.name
		}
		if a.kind == KindHost && !hostNamed[root] {
			name[root], hostNamed[root] = a.name, true
		}
	}
	made := map[int64]int64{}
	stamp := ts(now)
	for _, a := range assets {
		root := find(a.id)
		sid, ok := made[root]
		if !ok {
			res, err := tx.Exec(`INSERT INTO systems (name, created_at, updated_at) VALUES (?, ?, ?)`, name[root], stamp, stamp)
			if err != nil {
				return err
			}
			sid, _ = res.LastInsertId()
			made[root] = sid
		}
		if _, err := tx.Exec(`UPDATE assets SET system_id = ? WHERE id = ?`, sid, a.id); err != nil {
			return err
		}
	}
	return nil
}

// backup writes a consistent copy of the database next to it before a migration.
func (s *Store) backup(version int) error {
	if s.path == "" || s.path == ":memory:" || strings.HasPrefix(s.path, "file:") {
		return nil
	}
	base := fmt.Sprintf("%s.bak-v%d-%s", s.path, version, s.now().UTC().Format("20060102T150405Z"))
	dst := base
	for n := 2; ; n++ { // a retry within the same second must not be refused for want of a name
		if _, err := os.Stat(dst); err != nil {
			break
		}
		if n > 99 {
			return fmt.Errorf("%s and its numbered variants already exist", base)
		}
		dst = fmt.Sprintf("%s-%d", base, n)
	}
	if err := restrictFile(dst); err != nil {
		return err
	}
	if _, err := s.db.Exec(`VACUUM INTO ?`, dst); err != nil {
		_ = os.Remove(dst)
		return err
	}
	return restrictFile(dst)
}
