package collector

import (
	"fmt"
	"sort"
	"sync"
)

// Registry maps plugin names to factories.
type Registry struct {
	mu        sync.RWMutex
	factories map[string]Factory
}

// NewRegistry returns an empty registry. Tests use their own; production code
// uses Default via Register, populated by plugin packages' init functions.
func NewRegistry() *Registry {
	return &Registry{factories: make(map[string]Factory)}
}

// Register adds a factory under name. It fails on an invalid or duplicate name
// or a nil factory.
func (r *Registry) Register(name string, f Factory) error {
	if !nameRE.MatchString(name) {
		return fmt.Errorf("collector: invalid plugin name %q (want lowercase kebab-case)", name)
	}
	if f == nil {
		return fmt.Errorf("collector: nil factory for plugin %q", name)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, dup := r.factories[name]; dup {
		return fmt.Errorf("collector: plugin %q registered twice", name)
	}
	r.factories[name] = f
	return nil
}

// Names returns the registered plugin names, sorted.
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

// New builds the named plugin for host. It verifies that the constructed
// collector's Metadata is valid and carries the name it was registered under,
// which catches copy-paste registration mistakes at start-up.
func (r *Registry) New(name string, host Host) (Collector, error) {
	r.mu.RLock()
	f, ok := r.factories[name]
	r.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("collector: unknown plugin %q (registered: %v)", name, r.Names())
	}
	c, err := f(host)
	if err != nil {
		return nil, fmt.Errorf("collector: constructing plugin %q: %w", name, err)
	}
	if c == nil {
		return nil, fmt.Errorf("collector: factory for %q returned nil", name)
	}
	info := c.Metadata()
	if err := info.Validate(); err != nil {
		return nil, fmt.Errorf("collector: %w", err)
	}
	if info.Name != name {
		return nil, fmt.Errorf("collector: plugin registered as %q reports name %q", name, info.Name)
	}
	return c, nil
}

// Default is the process-wide registry that plugins register into from init.
var Default = NewRegistry()

// Register adds a factory to Default. It panics on error: a bad registration
// is a programming mistake and must fail loudly at start-up (as with
// database/sql.Register).
func Register(name string, f Factory) {
	if err := Default.Register(name, f); err != nil {
		panic(err)
	}
}
