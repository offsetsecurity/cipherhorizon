package signatures

import (
	"strings"
	"testing"
)

func TestTheDatabaseIsValid(t *testing.T) {
	db, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(db.For("windows")) < 5 || len(db.For("linux")) < 5 {
		t.Errorf("signatures: %d windows, %d linux", len(db.For("windows")), len(db.For("linux")))
	}
	for _, s := range db.Signatures {
		if s.How == "" {
			t.Errorf("%s: no How", s.ID)
		}
	}
	e := db.Engine("linux")
	if !strings.HasPrefix(e, "signatures\t"+db.Version+"\n") || !strings.Contains(e, "sig\tlinux.packages\tpackage\tmatch=") || strings.Contains(e, "win.") {
		t.Errorf("engine lines:\n%s", e)
	}
}

func TestValidationRefusesWhatAnEngineMustNotDo(t *testing.T) {
	base := `{"version":"1","signatures":[{"id":"linux.x","platform":"linux","title":"t","why":"w","capability":%s,"params":%s,"interpret":%s}]}`
	bad := map[string][3]string{
		"a command":        {`"command"`, `{"match":"x"}`, `"config"`},
		"wrong platform":   {`"registry"`, `{"key":"HKLM:\x","values":"a"}`, `"config"`},
		"unknown meaning":  {`"package"`, `{"match":"x"}`, `"anything"`},
		"missing param":    {`"lines"`, `{"paths":"/etc/x"}`, `"config"`},
		"extra param":      {`"package"`, `{"match":"x","exec":"rm"}`, `"package"`},
		"bad regex":        {`"package"`, `{"match":"("}`, `"package"`},
		"a key file":       {`"lines"`, `{"paths":"/etc/ssl/private/server.key","match":"."}`, `"config"`},
		"a key directory":  {`"certfiles"`, `{"dirs":"/etc/ssl/private"}`, `"certificate"`},
		"a tab in a value": {`"package"`, `{"match":"a\tb"}`, `"package"`},
	}
	for name, v := range bad {
		doc := strings.Replace(strings.Replace(strings.Replace(base, "%s", v[0], 1), "%s", v[1], 1), "%s", v[2], 1)
		if _, err := Parse([]byte(doc)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	ok := strings.Replace(strings.Replace(strings.Replace(base, "%s", `"lines"`, 1), "%s", `{"paths":"/etc/ssh/ssh_host_*_key.pub","match":"^ssh-"}`, 1), "%s", `"ssh-host-key"`, 1)
	if _, err := Parse([]byte(ok)); err != nil {
		t.Errorf("a public host key file is allowed: %v", err)
	}
}
