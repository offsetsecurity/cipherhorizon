package refdata

import (
	"crypto/sha256"
	_ "embed" // the distrust list
	"encoding/hex"
	"encoding/json"
	"sync"

	"github.com/offsetsecurity/cipherhorizon/internal/pki"
)

// distrustJSON is the hand-curated list of distrusted keys and certificates.
// Unlike the generated lists it has no single upstream: each incident cites
// the root-program bug and announcements it comes from.
//
//go:embed distrust.json
var distrustJSON []byte

// DistrustFile is the schema of distrust.json.
type DistrustFile struct {
	Version   string             `json:"version"` // YYYY-MM-DD of the last edit
	About     string             `json:"about"`
	Incidents []DistrustIncident `json:"incidents"`
}

// DistrustIncident is one event that put keys on the list.
type DistrustIncident struct {
	ID      string          `json:"id"`
	Title   string          `json:"title"`
	Kind    string          `json:"kind"` // pki.KindKeyCompromise | pki.KindCADistrust
	Since   string          `json:"since"`
	Summary string          `json:"summary"`
	Sources []string        `json:"sources"`
	Entries []DistrustEntry `json:"entries"`
}

// DistrustEntry is one key, with the certificates known to carry it.
type DistrustEntry struct {
	Name       string   `json:"name"`
	SPKISHA256 string   `json:"spkiSha256,omitempty"`
	CertSHA256 []string `json:"certSha256,omitempty"`
}

const licenceDistrust = "Published identifiers (certificate and key SHA-256) from root-program incident reports; factual values"

var (
	distrustOnce sync.Once
	distrustFile DistrustFile
	distrust     *pki.Distrust
)

func loadDistrust() {
	distrustOnce.Do(func() {
		if err := json.Unmarshal(distrustJSON, &distrustFile); err != nil {
			panic("refdata: distrust.json: " + err.Error())
		}
		distrust = pki.NewDistrust()
		for _, in := range distrustFile.Incidents {
			for _, e := range in.Entries {
				distrust.Add(e.SPKISHA256, e.CertSHA256, pki.Listed{Name: e.Name, Kind: in.Kind, Incident: in.ID,
					Title: in.Title, Since: in.Since, Summary: in.Summary, Sources: in.Sources})
			}
		}
	})
}

// Distrust returns the bundled distrust list. The value is shared and read-only.
func Distrust() *pki.Distrust {
	loadDistrust()
	return distrust
}

// DistrustData returns the parsed list, for the reference-data page and tests.
func DistrustData() DistrustFile {
	loadDistrust()
	return distrustFile
}

func distrustSource() Source {
	loadDistrust()
	sum := sha256.Sum256(distrustJSON)
	n := 0
	for _, in := range distrustFile.Incidents {
		n += len(in.Entries)
	}
	return Source{Name: "Distrusted CA keys", URL: "internal/refdata/distrust.json (each incident cites its sources)",
		Retrieved: distrustFile.Version, SHA256: hex.EncodeToString(sum[:]), Licence: licenceDistrust, Count: n}
}
