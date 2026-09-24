package config_test

import (
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/example/cipherhorizon/internal/config"
)

func TestEmptyInputYieldsDefaults(t *testing.T) {
	for name, in := range map[string]string{"empty": "", "comments only": "# nothing\n"} {
		cfg, err := config.Parse(strings.NewReader(in))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !reflect.DeepEqual(cfg, config.Default()) {
			t.Errorf("%s: got %+v, want defaults", name, cfg)
		}
	}
	d := config.Default()
	if d.Host.Root != config.DefaultRoot() || !d.PQC.Enabled || !d.Output.Pretty || d.Plugins.Timeout != time.Minute {
		t.Errorf("unexpected defaults: %+v", d)
	}
}

func TestPartialConfigKeepsOtherDefaults(t *testing.T) {
	cfg, err := config.Parse(strings.NewReader("host:\n  root: /host\nplugins:\n  timeout: 5s\n  disabled: [apt]\n"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Host.Root != "/host" || cfg.Plugins.Timeout != 5*time.Second || !reflect.DeepEqual(cfg.Plugins.Disabled, []string{"apt"}) {
		t.Errorf("got %+v", cfg)
	}
	if !cfg.PQC.Enabled || !cfg.Output.Pretty {
		t.Errorf("untouched sections lost their defaults: %+v", cfg)
	}
}

func TestBooleansCanBeSwitchedOff(t *testing.T) {
	cfg, err := config.Parse(strings.NewReader("pqc:\n  enabled: false\noutput:\n  pretty: false\n"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.PQC.Enabled || cfg.Output.Pretty {
		t.Errorf("explicit false ignored: %+v", cfg)
	}
}

func TestRejectsBadConfig(t *testing.T) {
	for name, in := range map[string]string{
		"unknown key (typo)": "plugins:\n  disable: [apt]\n",
		"unknown section":    "telemetry: {}\n",
		"empty root":         "host:\n  root: \"\"\n",
		"negative timeout":   "plugins:\n  timeout: -1s\n",
		"bad duration":       "plugins:\n  timeout: soon\n",
		"wrong type":         "plugins:\n  enabled: apt\n",
	} {
		if _, err := config.Parse(strings.NewReader(in)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestLoad(t *testing.T) {
	if cfg, err := config.Load(""); err != nil || !reflect.DeepEqual(cfg, config.Default()) {
		t.Errorf("Load(\"\") = %+v, %v", cfg, err)
	}
	if _, err := config.Load(filepath.Join(t.TempDir(), "missing.yaml")); err == nil {
		t.Error("missing file accepted")
	}
	p := filepath.Join(t.TempDir(), "c.yaml")
	if err := os.WriteFile(p, []byte("host:\n  name: box1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(p)
	if err != nil || cfg.Host.Name != "box1" {
		t.Errorf("Load = %+v, %v", cfg, err)
	}
}

// The documented example must stay loadable (strict mode rejects unknown keys)
// and must describe the defaults it claims to.
func TestExampleConfigIsValidAndMatchesDefaults(t *testing.T) {
	cfg, err := config.Load(filepath.Join("..", "..", "docs", "config.example.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	// `enabled: []` decodes to an empty slice, Default has a nil one: same meaning.
	if len(cfg.Plugins.Enabled) == 0 {
		cfg.Plugins.Enabled = nil
	}
	if len(cfg.Plugins.Disabled) == 0 {
		cfg.Plugins.Disabled = nil
	}
	// The example documents the Unix default root; on Windows the default is the system drive.
	want := config.Default()
	want.Host.Root = "/"
	if !reflect.DeepEqual(cfg, want) {
		t.Errorf("docs/config.example.yaml = %+v, differs from Default() = %+v", cfg, want)
	}
}

func TestDefaultRoot(t *testing.T) {
	got := config.DefaultRoot()
	if runtime.GOOS == "windows" {
		if len(got) < 3 || got[1] != ':' || got[2] != '\\' {
			t.Errorf("DefaultRoot() = %q, want a drive root such as C:\\", got)
		}
		return
	}
	if got != "/" {
		t.Errorf("DefaultRoot() = %q, want /", got)
	}
}
