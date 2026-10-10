// Package config loads the YAML configuration file.
//
// Every key is optional: an empty or absent file yields Default. Unknown keys
// are an error, so that a typo such as `disable:` for `disabled:` is caught
// instead of silently running the plugin the operator meant to switch off.
package config

import (
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"time"

	"go.yaml.in/yaml/v3"
)

// Config is the whole configuration.
type Config struct {
	Output  Output  `yaml:"output"`
	Host    Host    `yaml:"host"`
	Plugins Plugins `yaml:"plugins"`
	PQC     PQC     `yaml:"pqc"`
}

// Output controls where the CBOM goes.
type Output struct {
	// Path is the file to write, atomically. Empty means standard output.
	Path string `yaml:"path"`
	// Pretty indents the JSON.
	Pretty bool `yaml:"pretty"`
	// Spec is the CycloneDX version written: "1.7" (the default) or "1.6" for consumers that have
	// not moved to 1.7.
	Spec string `yaml:"spec"`
}

// DefaultSpec is the CycloneDX version written unless configured otherwise.
const DefaultSpec = "1.7"

// Host describes the machine being scanned.
type Host struct {
	// Root is the directory the host's filesystem is visible under: "/" natively,
	// "/host" in a container with the host mounted.
	Root string `yaml:"root"`
	// Name overrides the hostname recorded as the CBOM's subject.
	Name string `yaml:"name"`
	// Redact replaces the host name with a stable label derived from the machine
	// id, so the CBOM does not carry the name. See docs/decisions/ADR-0009.
	Redact bool `yaml:"redact"`
}

// Plugins selects and bounds sensors. (The section keeps its historical name so
// existing configuration files keep working.)
type Plugins struct {
	// Enabled restricts the run to these sensors; empty means every registered one.
	Enabled []string `yaml:"enabled"`
	// Disabled removes sensors from the run.
	Disabled []string `yaml:"disabled"`
	// Timeout bounds each sensor (Detect plus Collect); 0 disables the bound.
	Timeout time.Duration `yaml:"timeout"`
}

// PQC controls post-quantum risk annotation.
type PQC struct {
	Enabled bool `yaml:"enabled"`
}

// DefaultRoot is where the host's filesystem is visible by default: "/" on Unix,
// and the system drive on Windows (a bare "/" there would mean whichever drive the
// working directory happens to be on).
func DefaultRoot() string {
	if runtime.GOOS == "windows" {
		if d := os.Getenv("SystemDrive"); d != "" {
			return d + `\`
		}
		return `C:\`
	}
	return "/"
}

// Default returns the configuration used when nothing is specified.
func Default() Config {
	return Config{
		Output:  Output{Pretty: true, Spec: DefaultSpec},
		Host:    Host{Root: DefaultRoot()},
		Plugins: Plugins{Timeout: 60 * time.Second},
		PQC:     PQC{Enabled: true},
	}
}

// Load reads path. An empty path returns Default.
func Load(path string) (Config, error) {
	if path == "" {
		return Default(), nil
	}
	f, err := os.Open(path)
	if err != nil {
		return Config{}, fmt.Errorf("config: %w", err)
	}
	defer f.Close() //nolint:errcheck // read-only
	return Parse(f)
}

// Parse reads a configuration from r, layering it over Default.
func Parse(r io.Reader) (Config, error) {
	cfg := Default()
	dec := yaml.NewDecoder(r)
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil && !errors.Is(err, io.EOF) { // io.EOF: empty file
		return Config{}, fmt.Errorf("config: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// Validate rejects configurations that cannot work.
func (c Config) Validate() error {
	if c.Host.Root == "" {
		return errors.New("config: host.root must not be empty")
	}
	if c.Output.Spec != "" && c.Output.Spec != "1.6" && c.Output.Spec != "1.7" {
		return errors.New("config: output.spec must be 1.6 or 1.7")
	}
	if c.Plugins.Timeout < 0 {
		return errors.New("config: plugins.timeout must not be negative")
	}
	return nil
}
