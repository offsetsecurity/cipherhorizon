package store

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/example/cipherhorizon/internal/estate"
)

// ImportInput is a third-party document that passed the importer, with the operator's
// decision about which system it describes. The subject is the operator's: SubjectClaim is
// what the document says about itself and is only recorded (SECARCH-001 SR-04).
type ImportInput struct {
	Raw           []byte
	SHA256        string
	SpecVersion   string
	Profile       string
	Kind          estate.ImportKind
	ToolName      string
	ToolVersion   string
	SubjectClaim  string
	SubmittedBy   string
	SystemID      int64  // an existing system, or
	NewSystemName string // the name of one to create
}

// ImportRecord is an import as listed: its provenance and what became of it.
type ImportRecord struct {
	ID             int64          `json:"id"`
	SHA256         string         `json:"sha256"`
	SpecVersion    string         `json:"specVersion"`
	Profile        string         `json:"profile"`
	Kind           string         `json:"kind"`
	ToolName       string         `json:"toolName"`
	ToolVersion    string         `json:"toolVersion"`
	SubjectClaim   string         `json:"subjectClaim"`
	SubmittedBy    string         `json:"submittedBy"`
	Size           int            `json:"size"`
	ReceivedAt     time.Time      `json:"receivedAt"`
	SystemID       int64          `json:"systemId"`
	SystemName     string         `json:"systemName"`
	Status         string         `json:"status"`
	Observations   int            `json:"observations"`
	NotInterpreted map[string]int `json:"notInterpreted"`
}

// ErrAlreadyImported means the same document is active on another system.
var ErrAlreadyImported = errors.New("this document is already imported for another system")

// AddImport stores a document and projects it. Importing the same bytes again for the same
// system changes nothing and returns the existing record (duplicate); for another system it is
// refused. A withdrawn import is reactivated. Every import is audited.
func (s *Store) AddImport(in ImportInput) (rec ImportRecord, duplicate bool, err error) {
	if in.SystemID == 0 && strings.TrimSpace(in.NewSystemName) == "" {
		return ImportRecord{}, false, fmt.Errorf("%w: an import needs a system: pass an existing one or the name of a new one", ErrInvalid)
	}
	tx, err := s.db.Begin()
	if err != nil {
		return ImportRecord{}, false, err
	}
	defer func() { _ = tx.Rollback() }()

	var existing, existingSystem int64
	var status string
	qerr := tx.QueryRow(`SELECT i.id, COALESCE(s.system_id, 0), COALESCE(s.status, 'active') FROM imports i
		LEFT JOIN sources s ON s.ref_kind = 'import' AND s.ref_id = i.id WHERE i.sha256 = ?`, in.SHA256).Scan(&existing, &existingSystem, &status)
	switch {
	case qerr == nil && status == "active":
		if in.SystemID != 0 && in.SystemID != existingSystem {
			return ImportRecord{}, false, ErrAlreadyImported
		}
		if in.SystemID == 0 && existingSystem != 0 {
			return ImportRecord{}, false, ErrAlreadyImported // a new system was asked for; the document already has one
		}
		if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
			return ImportRecord{}, false, err
		}
		r, err := s.GetImport(existing)
		return r, true, err
	case qerr != nil && !errors.Is(qerr, sql.ErrNoRows):
		return ImportRecord{}, false, qerr
	}

	now := ts(s.now())
	systemID := in.SystemID
	if systemID != 0 {
		var n int
		if err := tx.QueryRow(`SELECT COUNT(*) FROM systems WHERE id = ?`, systemID).Scan(&n); err != nil {
			return ImportRecord{}, false, err
		}
		if n == 0 {
			return ImportRecord{}, false, ErrNotFound
		}
	} else {
		name, nerr := normalizeField("name", in.NewSystemName)
		if nerr != nil {
			return ImportRecord{}, false, nerr
		}
		res, err := tx.Exec(`INSERT INTO systems (name, created_at, updated_at) VALUES (?, ?, ?)`, name, now, now)
		if err != nil {
			return ImportRecord{}, false, err
		}
		systemID, _ = res.LastInsertId()
		if err := audit(tx, now, in.SubmittedBy, systemID, "create", map[string]any{}, map[string]any{"name": name, "reason": "created for an import"}, ""); err != nil {
			return ImportRecord{}, false, err
		}
	}

	var importID int64
	if qerr == nil { // the same bytes were imported before and withdrawn: reactivate them for this system
		importID = existing
	} else {
		res, err := tx.Exec(`INSERT INTO imports (sha256, spec_version, profile, kind, cbom_json, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
			in.SHA256, in.SpecVersion, in.Profile, string(in.Kind), in.Raw, now)
		if err != nil {
			return ImportRecord{}, false, err
		}
		importID, _ = res.LastInsertId()
	}
	bom := new(cdx.BOM)
	if err := cdx.NewBOMDecoder(bytes.NewReader(in.Raw), cdx.BOMFileFormatJSON).Decode(bom); err != nil {
		return ImportRecord{}, false, fmt.Errorf("%w: the document could not be read", ErrInvalid)
	}
	pr := estate.FromImportedCBOM(bom, in.Kind)
	if err := s.writeSourceTx(tx, sourceInput{
		Class: estate.ClassImported, Stream: estate.StreamImported, RefKind: "import", RefID: importID, SystemID: systemID,
		ToolName: in.ToolName, ToolVersion: in.ToolVersion, SHA256: in.SHA256, Size: len(in.Raw), ObservedAt: s.now(),
		SubmittedBy: in.SubmittedBy, SubjectClaim: in.SubjectClaim, Uninterp: pr.Uninterpreted,
	}, pr.Observations); err != nil {
		return ImportRecord{}, false, err
	}
	if err := audit(tx, now, in.SubmittedBy, systemID, "import", map[string]any{},
		map[string]any{"importId": importID, "sha256": in.SHA256, "profile": in.Profile, "tool": in.ToolName, "subjectClaim": in.SubjectClaim}, ""); err != nil {
		return ImportRecord{}, false, err
	}
	if err := tx.Commit(); err != nil {
		return ImportRecord{}, false, err
	}
	s.correlateQuietly()
	r, err := s.GetImport(importID)
	return r, false, err
}

const importCols = `i.id, i.sha256, i.spec_version, i.profile, i.kind, s.tool_name, s.tool_version, s.subject_claim, s.submitted_by, s.size,
	s.received_at, COALESCE(s.system_id, 0), COALESCE(sy.name, ''), s.status, s.not_interpreted_json,
	(SELECT COUNT(*) FROM observations o WHERE o.source_id = s.id)`

func scanImport(r scanner) (ImportRecord, error) {
	var rec ImportRecord
	var at, ni string
	if err := r.Scan(&rec.ID, &rec.SHA256, &rec.SpecVersion, &rec.Profile, &rec.Kind, &rec.ToolName, &rec.ToolVersion, &rec.SubjectClaim,
		&rec.SubmittedBy, &rec.Size, &at, &rec.SystemID, &rec.SystemName, &rec.Status, &ni, &rec.Observations); err != nil {
		return ImportRecord{}, err
	}
	if t := parseTS(sql.NullString{String: at, Valid: true}); t != nil {
		rec.ReceivedAt = *t
	}
	_ = json.Unmarshal([]byte(ni), &rec.NotInterpreted)
	if rec.NotInterpreted == nil {
		rec.NotInterpreted = map[string]int{}
	}
	return rec, nil
}

const importFrom = ` FROM imports i JOIN sources s ON s.ref_kind = 'import' AND s.ref_id = i.id LEFT JOIN systems sy ON sy.id = s.system_id`

// GetImport returns one import.
func (s *Store) GetImport(id int64) (ImportRecord, error) {
	rec, err := scanImport(s.db.QueryRow(`SELECT `+importCols+importFrom+` WHERE i.id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return ImportRecord{}, ErrNotFound
	}
	return rec, err
}

// Imports lists every import, newest first.
func (s *Store) Imports() ([]ImportRecord, error) {
	rows, err := s.db.Query(`SELECT ` + importCols + importFrom + ` ORDER BY i.id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck // read-only
	out := []ImportRecord{}
	for rows.Next() {
		rec, err := scanImport(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

// WithdrawImport removes an import's observations from the graph. The raw document and the
// record of the import are kept for audit (they are how a withdrawn import is explained), and
// the withdrawal is audited.
func (s *Store) WithdrawImport(id int64, actor, reason string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var sourceID, systemID int64
	var status string
	if err := tx.QueryRow(`SELECT id, COALESCE(system_id, 0), status FROM sources WHERE ref_kind = 'import' AND ref_id = ?`, id).Scan(&sourceID, &systemID, &status); errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	} else if err != nil {
		return err
	}
	if status == "withdrawn" {
		return nil
	}
	if _, err := tx.Exec(`DELETE FROM observations WHERE source_id = ?`, sourceID); err != nil {
		return err
	}
	if _, err := tx.Exec(`UPDATE sources SET status = 'withdrawn' WHERE id = ?`, sourceID); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM entities WHERE id NOT IN (SELECT entity_id FROM observations)`); err != nil {
		return err
	}
	if err := audit(tx, ts(s.now()), actor, systemID, "withdraw-import", map[string]any{"importId": id}, map[string]any{}, reason); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	s.correlateQuietly()
	return nil
}

// reprojectImportsTx rebuilds the observations of every active import from its stored document.
func (s *Store) reprojectImportsTx(tx *sql.Tx) error {
	rows, err := tx.Query(`SELECT s.id, i.kind, i.cbom_json, s.observed_at FROM sources s JOIN imports i ON i.id = s.ref_id
		WHERE s.ref_kind = 'import' AND s.status = 'active' ORDER BY s.id`)
	if err != nil {
		return err
	}
	type job struct {
		sourceID int64
		kind     string
		raw      []byte
		at       string
	}
	var jobs []job
	for rows.Next() {
		var j job
		if err := rows.Scan(&j.sourceID, &j.kind, &j.raw, &j.at); err != nil {
			_ = rows.Close()
			return err
		}
		jobs = append(jobs, j)
	}
	_ = rows.Close()
	for _, j := range jobs {
		bom := new(cdx.BOM)
		if err := cdx.NewBOMDecoder(bytes.NewReader(j.raw), cdx.BOMFileFormatJSON).Decode(bom); err != nil {
			continue // a stored document that no longer decodes projects nothing; the raw bytes remain
		}
		at := s.now()
		if t := parseTS(sql.NullString{String: j.at, Valid: true}); t != nil {
			at = *t
		}
		pr := estate.FromImportedCBOM(bom, estate.ImportKind(j.kind))
		if err := s.insertObservations(tx, j.sourceID, estate.ClassImported, estate.StreamImported, at, pr.Uninterpreted, pr.Observations); err != nil {
			return err
		}
	}
	return nil
}
