package datadir

import (
	"path/filepath"
	"testing"
)

func TestResolveOrder(t *testing.T) {
	env := map[string]string{}
	getenv := func(k string) string { return env[k] }
	inWD := false
	exists := func(string) bool { return inWD }
	home := filepath.Join("/", "home", "ana")

	check := func(name, flag, wantPath string, wantSrc Source) {
		t.Helper()
		p, src, err := resolve(flag, getenv, "linux", home, exists)
		if err != nil || p != wantPath || src != wantSrc {
			t.Errorf("%s: got %q %v %v, want %q %v", name, p, src, err, wantPath, wantSrc)
		}
	}
	def := filepath.Join(home, ".local", "share", "cipherhorizon", File)
	check("nothing set", "", def, FromDefault)
	inWD = true
	check("an old database in the working directory wins over the default", "", File, FromWorkingDir)
	env[EnvVar] = "/srv/ch.db"
	check("the environment wins over the working directory", "", "/srv/ch.db", FromEnv)
	check("--db wins over everything", "x.db", "x.db", FromFlag)
}

func TestDefaultPathPerOS(t *testing.T) {
	cases := []struct {
		goos, home string
		env        map[string]string
		want       string
	}{
		{"windows", `C:\Users\ana`, map[string]string{"LOCALAPPDATA": `C:\Users\ana\AppData\Local`},
			filepath.Join(`C:\Users\ana\AppData\Local`, "CipherHorizon", File)},
		{"windows", `C:\Users\ana`, nil, filepath.Join(`C:\Users\ana`, "AppData", "Local", "CipherHorizon", File)},
		{"darwin", "/Users/ana", nil, filepath.Join("/Users/ana", "Library", "Application Support", "CipherHorizon", File)},
		{"linux", "/home/ana", map[string]string{"XDG_DATA_HOME": "/data/ana"}, filepath.Join("/data/ana", "cipherhorizon", File)},
		{"linux", "/home/ana", map[string]string{"XDG_DATA_HOME": "relative"}, filepath.Join("/home/ana", ".local", "share", "cipherhorizon", File)},
	}
	for _, c := range cases {
		got, err := defaultPath(func(k string) string { return c.env[k] }, c.goos, c.home)
		if err != nil || got != c.want {
			t.Errorf("%s %v: got %q %v, want %q", c.goos, c.env, got, err, c.want)
		}
	}
	if _, err := defaultPath(func(string) string { return "" }, "linux", ""); err == nil {
		t.Error("no home and no XDG_DATA_HOME: want an error naming --db")
	}
}
