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
}

// Host describes the machine being scanned.
type Host struct {
	// Root is the directory the host's filesystem is visible under: "/" natively,
	// "/host" in a container with the host mounted.
	Root string `yaml:"root"`
	// Name overrides the hostname recorded as the CBOM's subject.
	Name string `yaml:"name"`
}

// Plugins selects and bounds collectors.
type Plugins struct {
	// Enabled restricts the run to these plugins; empty means every registered one.
	Enabled []string `yaml:"enabled"`
	// Disabled removes plugins from the run.
	Disabled []string `yaml:"disabled"`
	// Timeout bounds each plugin (Detect plus Collect); 0 disables the bound.
	Timeout time.Duration `yaml:"timeout"`
}

// PQC controls post-quantum risk annotation.
type PQC struct {
	Enabled bool `yaml:"enabled"`
}

// Default returns the configuration used when nothing is specified.
func Default() Config {
	return Config{
		Output:  Output{Pretty: true},
		Host:    Host{Root: "/"},
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
	if c.Plugins.Timeout < 0 {
		return errors.New("config: plugins.timeout must not be negative")
	}
	return nil
}
