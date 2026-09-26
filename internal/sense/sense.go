// Package sense defines the contract every host sensor implements, the registry
// sensors register into, and the runner that drives them.
//
// A sensor looks at one kind of thing on the host (a package database, a file
// tree, a certificate store) and returns only what it saw, as evidence.Batch:
// observations and coverage. It never builds a CBOM, never asserts what software
// can do, and never says a fact is stronger than the method that found it.
// Capability is decided later, from cited knowledge (internal/knowledge and
// internal/derive); the CBOM is a projection of the result (internal/cbom).
//
// Import rules, enforced by test (arch_test.go): sensors do not import cbom,
// derive, os/exec or net. That is what keeps operating-system code at the edge.
package sense

import (
	"context"
	"fmt"
	"io/fs"
	"regexp"
	"sort"
	"sync"

	"github.com/example/cipherhorizon/internal/evidence"
)

// Env is what a sensor may use to look at the host. Everything a sensor reads
// comes through it, so a sensor is testable with a fake filesystem and the
// platform layer is the only place that touches the operating system.
type Env struct {
	// FS is the host's root filesystem, addressed with unrooted slash-separated
	// paths ("var/lib/dpkg/status"). Natively it is os.DirFS of the root; in a
	// container with the host mounted at /host it is os.DirFS("/host"); in tests
	// it is an fstest.MapFS. A sensor must read the host only through it.
	FS fs.FS
	// OS is the host's operating system family: "linux" or "windows".
	OS string
	// Tier is the privilege tier this run has: "user" or "admin". It is recorded on
	// every observation; a sensor never escalates.
	Tier string
	// Live is true only when FS is the running machine's own root, so the operating
	// system itself may be asked about it. It is false for a mounted disk, a container
	// image, a `--root` override or a test fixture. A sensor that asks the OS (native
	// APIs) must run only when Live: otherwise it would describe the wrong machine.
	Live bool
}

// Info describes a sensor.
type Info struct {
	// Name is the registry key and the name used in configuration: lowercase
	// kebab-case, e.g. "apt".
	Name string
	// Version is the sensor's own version (semver).
	Version string
	// Methods lists the method IDs the sensor uses (see evidence.Methods).
	Methods []string
}

var nameRE = regexp.MustCompile(`^[a-z][a-z0-9]*(-[a-z0-9]+)*$`)

// Validate reports whether the info is well formed and its methods are declared.
func (i Info) Validate() error {
	if !nameRE.MatchString(i.Name) {
		return fmt.Errorf("sensor name %q must be lowercase kebab-case", i.Name)
	}
	if i.Version == "" {
		return fmt.Errorf("sensor %q: version is empty", i.Name)
	}
	if len(i.Methods) == 0 {
		return fmt.Errorf("sensor %q declares no methods", i.Name)
	}
	for _, m := range i.Methods {
		if _, ok := evidence.LookupMethod(m); !ok {
			return fmt.Errorf("sensor %q uses undeclared method %q", i.Name, m)
		}
	}
	return nil
}

// Sensor inventories one kind of thing on the local host.
//
// One-shot and (later) daemon modes drive sensors through the same calls. A
// sensor must:
//
//   - be read-only: never modify the host;
//   - honour ctx cancellation;
//   - be repeatable: Detect and Collect may be called many times on one value;
//   - not assume concurrent use: the runner calls a sensor sequentially;
//   - report what it could not see as Coverage, never as silence.
type Sensor interface {
	// Info identifies the sensor. Cheap, side-effect free, the same every time.
	Info() Info

	// Detect reports whether this kind of thing is present on the host.
	//
	//	(true,  nil)  present: Collect will be called.
	//	(false, nil)  absent: the sensor is skipped. The normal outcome of, say, the
	//	              dpkg sensor on a Windows host.
	//	(false, err)  presence could not be determined; recorded as a failure.
	Detect(ctx context.Context) (bool, error)

	// Collect returns what the sensor saw. A non-nil error means the result is
	// INCOMPLETE; the Batch returned alongside is still valid and kept, because a
	// partial inventory beats none.
	Collect(ctx context.Context) (evidence.Batch, error)
}

// Factory constructs a Sensor for a host. Constructors must be cheap and
// side-effect free: all I/O belongs in Detect and Collect.
type Factory func(Env) (Sensor, error)

// Registry maps sensor names to factories.
type Registry struct {
	mu        sync.RWMutex
	factories map[string]Factory
}

// NewRegistry returns an empty registry. Tests use their own; production code
// uses Default, filled by sensor packages' init functions.
func NewRegistry() *Registry { return &Registry{factories: make(map[string]Factory)} }

// Register adds a factory under name. It fails on an invalid or duplicate name or
// a nil factory.
func (r *Registry) Register(name string, f Factory) error {
	if !nameRE.MatchString(name) {
		return fmt.Errorf("sense: invalid sensor name %q (want lowercase kebab-case)", name)
	}
	if f == nil {
		return fmt.Errorf("sense: nil factory for sensor %q", name)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, dup := r.factories[name]; dup {
		return fmt.Errorf("sense: sensor %q registered twice", name)
	}
	r.factories[name] = f
	return nil
}

// Names returns the registered sensor names, sorted.
func (r *Registry) Names() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	names := make([]string, 0, len(r.factories))
	for n := range r.factories {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// New builds the named sensor for env. It verifies that the sensor's Info is
// valid and carries the name it was registered under, which catches
// copy-paste registration mistakes at start-up.
func (r *Registry) New(name string, env Env) (Sensor, error) {
	r.mu.RLock()
	f, ok := r.factories[name]
	r.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("sense: unknown sensor %q (registered: %v)", name, r.Names())
	}
	s, err := f(env)
	if err != nil {
		return nil, fmt.Errorf("sense: constructing sensor %q: %w", name, err)
	}
	if s == nil {
		return nil, fmt.Errorf("sense: factory for %q returned nil", name)
	}
	info := s.Info()
	if err := info.Validate(); err != nil {
		return nil, fmt.Errorf("sense: %w", err)
	}
	if info.Name != name {
		return nil, fmt.Errorf("sense: sensor registered as %q reports name %q", name, info.Name)
	}
	return s, nil
}

// Default is the process-wide registry that sensors register into from init.
var Default = NewRegistry()

// Register adds a factory to Default. It panics on error: a bad registration is a
// programming mistake and must fail loudly at start-up (as with database/sql.Register).
func Register(name string, f Factory) {
	if err := Default.Register(name, f); err != nil {
		panic(err)
	}
}
