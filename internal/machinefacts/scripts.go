package machinefacts

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"strings"

	"github.com/offsetsecurity/cipherhorizon/internal/signatures"
)

//go:embed scripts/cipherhorizon-inventory.sh scripts/cipherhorizon-inventory.ps1
var scriptFS embed.FS

const (
	markBegin = "#@@SIGNATURES-BEGIN@@"
	markEnd   = "#@@SIGNATURES-END@@"
)

// Script is one inventory script as the server hands it out: the engine from this
// repository with the current signature database for its platform written in between
// its markers, so what a person reads is what runs.
type Script struct {
	Name       string `json:"name"`
	Platform   string `json:"platform"`
	Run        string `json:"run"`    // the command that runs it
	SHA256     string `json:"sha256"` // of the bytes served
	Size       int    `json:"size"`
	Signatures int    `json:"signatures"` // how many signatures it carries
	DBVersion  string `json:"signatureDb"`
	body       []byte
}

// Body is the script's text.
func (s Script) Body() []byte { return s.body }

// Engine returns an engine's text without signatures (as kept in the repository).
func Engine(name string) ([]byte, error) { return scriptFS.ReadFile("scripts/" + name) }

// embedSignatures writes the platform's signatures into the engine between its markers.
func embedSignatures(engine, name, sigLines string) string {
	var block string
	if strings.HasSuffix(name, ".ps1") {
		block = "$Signatures = @'\n" + sigLines + "'@\n"
	} else {
		block = "SIGNATURES=$(cat <<'CH_SIGNATURES_EOF'\n" + sigLines + "CH_SIGNATURES_EOF\n)\n"
	}
	i := strings.Index(engine, markBegin)
	j := strings.Index(engine, markEnd)
	if i < 0 || j < i {
		return engine
	}
	return engine[:i] + markBegin + "\n" + block + engine[j:]
}

// Scripts lists the inventory scripts with the current signatures embedded.
func Scripts() []Script {
	db := signatures.MustLoad()
	defs := []Script{
		{Name: "cipherhorizon-inventory.ps1", Platform: "Windows · PowerShell",
			Run: `Unblock-File .\cipherhorizon-inventory.ps1; powershell -NoProfile -ExecutionPolicy RemoteSigned -File .\cipherhorizon-inventory.ps1`},
		{Name: "cipherhorizon-inventory.sh", Platform: "Linux · shell",
			Run: "sudo sh ./cipherhorizon-inventory.sh"},
	}
	out := make([]Script, 0, len(defs))
	for _, d := range defs {
		e, err := Engine(d.Name)
		if err != nil {
			continue
		}
		platform := "linux"
		if strings.HasSuffix(d.Name, ".ps1") {
			platform = "windows"
		}
		b := []byte(embedSignatures(string(e), d.Name, db.Engine(platform)))
		sum := sha256.Sum256(b)
		d.SHA256, d.Size, d.body = hex.EncodeToString(sum[:]), len(b), b
		d.Signatures, d.DBVersion = len(db.For(platform)), db.Version
		out = append(out, d)
	}
	return out
}
